package config

import (
	"strings"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	c := Default()
	if c.ScrapeInterval != time.Minute || c.RateWindowFactor != 4 || c.MinFor != time.Minute {
		t.Errorf("unexpected defaults: %+v", c)
	}
	if !c.IsPaging("critical") || c.IsPaging("warning") {
		t.Error("paging severities wrong")
	}
	if c.FailOn != "error" {
		t.Errorf("fail_on default = %q", c.FailOn)
	}
}

func TestParseOverlaysDefaults(t *testing.T) {
	c, err := Parse([]byte(`
scrape_interval: 15s
min_for: 5m
paging_severities: [sev1]
owner_labels: [squad]
cause_metrics: ['^my_cpu_']
rules:
  cause-based-paging: "off"
  short-for: error
fail_on: warning
`))
	if err != nil {
		t.Fatal(err)
	}
	if c.ScrapeInterval != 15*time.Second || c.MinFor != 5*time.Minute {
		t.Errorf("durations not applied: %v %v", c.ScrapeInterval, c.MinFor)
	}
	if c.RateWindowFactor != 4 {
		t.Errorf("unset factor should keep default, got %d", c.RateWindowFactor)
	}
	if !c.IsPaging("sev1") || !c.IsAllowedSeverity("sev1") {
		t.Error("paging severity must be implicitly allowed")
	}
	if len(c.CauseMetrics) != 1 || !c.CauseMetrics[0].MatchString("my_cpu_seconds") {
		t.Error("cause_metrics not compiled")
	}
	if c.Rules["cause-based-paging"] != "off" || c.Rules["short-for"] != "error" || c.FailOn != "warning" {
		t.Errorf("rules/fail_on not applied: %v %q", c.Rules, c.FailOn)
	}
}

func TestParseRejectsMistakes(t *testing.T) {
	cases := map[string]string{
		"unknown key":      "scrape_intervall: 1m",
		"bad duration":     "min_for: soon",
		"bad rule setting": "rules: {short-for: maybe}",
		"bad regex":        "cause_metrics: ['(']",
		"bad fail_on":      "fail_on: sometimes",
	}
	for name, src := range cases {
		if _, err := Parse([]byte(src)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestEmptyConfigIsDefaults(t *testing.T) {
	c, err := Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.OwnerLabels, ",") != "team,owner" {
		t.Errorf("owner labels = %v", c.OwnerLabels)
	}
}
