// Package config holds linter settings and loads them from YAML.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/prometheus/common/model"
	"gopkg.in/yaml.v3"
)

// DefaultFile is the config file name picked up from the working directory
// when --config is not given.
const DefaultFile = ".alert-linter.yaml"

// Config is the effective linter configuration.
type Config struct {
	// ScrapeInterval is used by rate-window-too-short: range selectors in
	// rate()/increase()/... must cover at least RateWindowFactor scrapes.
	ScrapeInterval   time.Duration
	RateWindowFactor int

	// MinFor is the shortest `for:` that short-for accepts.
	MinFor time.Duration

	// PagingSeverities are the severity label values that wake a human.
	PagingSeverities []string
	// AllowedSeverities are all severity values your routing understands.
	AllowedSeverities []string
	// SeverityLabel is the label that carries severity (default "severity").
	SeverityLabel string

	// OwnerLabels: at least one must be present on every alert.
	OwnerLabels []string

	// HighCardinalityLabels must not appear in by(...) on paging alerts.
	HighCardinalityLabels []string

	// CauseMetrics are regular expressions matched against metric names
	// to recognise resource (cause) metrics such as CPU, memory and disk.
	CauseMetrics []*regexp.Regexp

	// Rules maps a rule ID to "off" or a severity override.
	Rules map[string]string

	// FailOn is the lowest finding severity that makes the exit code non-zero.
	FailOn string
}

// Default returns the built-in configuration.
func Default() *Config {
	return &Config{
		ScrapeInterval:    time.Minute,
		RateWindowFactor:  4,
		MinFor:            time.Minute,
		PagingSeverities:  []string{"critical", "page"},
		AllowedSeverities: []string{"critical", "page", "warning", "info", "none"},
		SeverityLabel:     "severity",
		OwnerLabels:       []string{"team", "owner"},
		HighCardinalityLabels: []string{
			"pod", "pod_name", "container", "container_id", "instance",
			"id", "uid", "path", "url", "user", "user_id", "request_id",
			"trace_id", "ip", "client_ip",
		},
		CauseMetrics: mustCompile([]string{
			`^node_cpu_`, `node_cpu_utili[sz]ation`, `^node_load(1|5|15)$`,
			`^node_memory_`, `node_memory_utili[sz]ation`,
			`^node_filesystem_`, `^node_disk_`,
			`^container_cpu_`, `^container_memory_`, `^container_fs_`,
			`^process_cpu_seconds_total$`, `^process_resident_memory_bytes$`,
			`^kube_pod_container_resource_`, `^jvm_memory_`, `^go_memstats_`,
		}),
		Rules:  map[string]string{},
		FailOn: "error",
	}
}

// file mirrors the YAML layout. Durations are strings so we can accept
// Prometheus-style values such as "1m" or "1d".
type file struct {
	ScrapeInterval        string            `yaml:"scrape_interval"`
	RateWindowFactor      int               `yaml:"rate_window_factor"`
	MinFor                string            `yaml:"min_for"`
	PagingSeverities      []string          `yaml:"paging_severities"`
	AllowedSeverities     []string          `yaml:"allowed_severities"`
	SeverityLabel         string            `yaml:"severity_label"`
	OwnerLabels           []string          `yaml:"owner_labels"`
	HighCardinalityLabels []string          `yaml:"high_cardinality_labels"`
	CauseMetrics          []string          `yaml:"cause_metrics"`
	Rules                 map[string]string `yaml:"rules"`
	FailOn                string            `yaml:"fail_on"`
}

// Load reads a config file and overlays it on the defaults. Unknown keys
// are rejected so a typo cannot silently disable a check.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return cfg, nil
}

// Parse overlays YAML config on the defaults.
func Parse(data []byte) (*Config, error) {
	var f file
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("invalid config: %s", strings.TrimPrefix(err.Error(), "yaml: "))
	}
	cfg := Default()
	var err error
	if f.ScrapeInterval != "" {
		if cfg.ScrapeInterval, err = duration("scrape_interval", f.ScrapeInterval); err != nil {
			return nil, err
		}
	}
	if f.MinFor != "" {
		if cfg.MinFor, err = duration("min_for", f.MinFor); err != nil {
			return nil, err
		}
	}
	if f.RateWindowFactor < 0 {
		return nil, errors.New("rate_window_factor must be positive")
	}
	if f.RateWindowFactor > 0 {
		cfg.RateWindowFactor = f.RateWindowFactor
	}
	if f.PagingSeverities != nil {
		cfg.PagingSeverities = f.PagingSeverities
	}
	if f.AllowedSeverities != nil {
		cfg.AllowedSeverities = f.AllowedSeverities
	}
	if f.SeverityLabel != "" {
		cfg.SeverityLabel = f.SeverityLabel
	}
	if f.OwnerLabels != nil {
		cfg.OwnerLabels = f.OwnerLabels
	}
	if f.HighCardinalityLabels != nil {
		cfg.HighCardinalityLabels = f.HighCardinalityLabels
	}
	if f.CauseMetrics != nil {
		res := make([]*regexp.Regexp, 0, len(f.CauseMetrics))
		for _, p := range f.CauseMetrics {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("cause_metrics: %q: %w", p, err)
			}
			res = append(res, re)
		}
		cfg.CauseMetrics = res
	}
	for id, v := range f.Rules {
		switch v {
		case "off", "error", "warning", "info":
			cfg.Rules[id] = v
		default:
			return nil, fmt.Errorf("rules.%s: %q is not one of off, error, warning, info", id, v)
		}
	}
	if f.FailOn != "" {
		if err := ValidateFailOn(f.FailOn); err != nil {
			return nil, err
		}
		cfg.FailOn = f.FailOn
	}
	// Paging severities must be allowed, otherwise unknown-severity and the
	// paging checks would contradict each other.
	for _, p := range cfg.PagingSeverities {
		if !contains(cfg.AllowedSeverities, p) {
			cfg.AllowedSeverities = append(cfg.AllowedSeverities, p)
		}
	}
	return cfg, nil
}

// ValidateFailOn checks a --fail-on / fail_on value.
func ValidateFailOn(v string) error {
	switch v {
	case "error", "warning", "info", "never":
		return nil
	}
	return fmt.Errorf("fail_on: %q is not one of error, warning, info, never", v)
}

// IsPaging reports whether a severity value pages someone.
func (c *Config) IsPaging(severity string) bool { return contains(c.PagingSeverities, severity) }

// IsAllowedSeverity reports whether a severity value is known.
func (c *Config) IsAllowedSeverity(severity string) bool {
	return contains(c.AllowedSeverities, severity)
}

func duration(key, v string) (time.Duration, error) {
	d, err := model.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return time.Duration(d), nil
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func mustCompile(patterns []string) []*regexp.Regexp {
	out := make([]*regexp.Regexp, len(patterns))
	for i, p := range patterns {
		out[i] = regexp.MustCompile(p)
	}
	return out
}
