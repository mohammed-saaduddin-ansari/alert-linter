// Package cli wires flags, config, loading, linting and reporting together.
// It is separate from package main so golden tests can run it in-process.
package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/mohammed-saaduddin-ansari/alert-linter/internal/config"
	"github.com/mohammed-saaduddin-ansari/alert-linter/internal/lint"
	"github.com/mohammed-saaduddin-ansari/alert-linter/internal/loader"
	"github.com/mohammed-saaduddin-ansari/alert-linter/internal/report"
)

// Version is set at build time with -ldflags "-X .../internal/cli.Version=v1.2.3".
var Version = "dev"

// HelpURI is where each rule is documented (README anchors).
const HelpURI = "https://github.com/mohammed-saaduddin-ansari/alert-linter"

// Exit codes.
const (
	ExitOK       = 0 // no findings at or above --fail-on
	ExitFindings = 1 // findings at or above --fail-on
	ExitUsage    = 2 // bad flags, unreadable files or invalid config
)

const usage = `alert-linter lints Prometheus alerting rules for on-call anti-patterns.

Usage:
  alert-linter [flags] <file-or-directory>...

Directories are searched recursively for *.yml and *.yaml files that
contain rule groups (plain rule files or PrometheusRule manifests).

Flags:
`

// Run executes the CLI and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("alert-linter", flag.ContinueOnError)
	fl.SetOutput(stderr)
	configPath := fl.String("config", "", "config file (default: "+config.DefaultFile+" in the working directory, if present)")
	format := fl.String("format", "text", "output format: "+strings.Join(report.Formats, ", "))
	output := fl.String("output", "", "write the report to this file instead of stdout")
	failOn := fl.String("fail-on", "", "lowest severity that fails the run: error, warning, info or never (default from config, else error)")
	listRules := fl.Bool("list-rules", false, "list all rules and exit")
	showVersion := fl.Bool("version", false, "print the version and exit")
	fl.Usage = func() {
		fmt.Fprint(stderr, usage)
		fl.PrintDefaults()
	}
	if err := fl.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitOK
		}
		return ExitUsage
	}

	switch {
	case *showVersion:
		fmt.Fprintln(stdout, "alert-linter", version())
		return ExitOK
	case *listRules:
		printRules(stdout)
		return ExitOK
	case fl.NArg() == 0:
		fl.Usage()
		return ExitUsage
	}

	cfg, err := loadConfig(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "alert-linter:", err)
		return ExitUsage
	}
	if *failOn != "" {
		if err := config.ValidateFailOn(*failOn); err != nil {
			fmt.Fprintln(stderr, "alert-linter: --"+err.Error())
			return ExitUsage
		}
		cfg.FailOn = *failOn
	}
	linter, err := lint.New(cfg)
	if err != nil {
		fmt.Fprintln(stderr, "alert-linter:", err)
		return ExitUsage
	}

	files, err := collect(fl.Args(), stderr)
	if err != nil {
		fmt.Fprintln(stderr, "alert-linter:", err)
		return ExitUsage
	}
	res := linter.Lint(files)

	var buf bytes.Buffer
	if err := report.Write(&buf, *format, res, report.Meta{Version: version(), HelpURI: HelpURI}); err != nil {
		fmt.Fprintln(stderr, "alert-linter:", err)
		return ExitUsage
	}
	if *output != "" {
		if err := os.WriteFile(*output, buf.Bytes(), 0o644); err != nil {
			fmt.Fprintln(stderr, "alert-linter:", err)
			return ExitUsage
		}
		// Keep CI logs useful when the report itself goes to a file.
		if *format != "text" {
			fmt.Fprintf(stderr, "alert-linter: %d errors, %d warnings; report written to %s\n",
				res.Count(lint.Error), res.Count(lint.Warning), *output)
		}
	} else if _, err := stdout.Write(buf.Bytes()); err != nil {
		return ExitUsage
	}

	if failed(res, cfg.FailOn) {
		return ExitFindings
	}
	return ExitOK
}

func failed(res lint.Result, failOn string) bool {
	if failOn == "never" {
		return false
	}
	threshold, _ := lint.ParseSeverity(failOn)
	return res.Max() >= threshold && res.Max() != lint.Unset
}

func loadConfig(path string) (*config.Config, error) {
	if path != "" {
		return config.Load(path)
	}
	if _, err := os.Stat(config.DefaultFile); err == nil {
		return config.Load(config.DefaultFile)
	}
	return config.Default(), nil
}

// collect loads every named file, and every rule file found under named
// directories. Files named explicitly are always linted; files discovered
// in directories are linted only if they look like rule files, so a
// kustomization.yaml or Helm values file next to your rules is not an error.
func collect(paths []string, stderr io.Writer) ([]*loader.File, error) {
	var files []*loader.File
	seen := map[string]bool{}
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			f, err := loader.LoadFile(p)
			if err != nil {
				return nil, err
			}
			if f.Groups == 0 && len(f.Problems) == 0 {
				fmt.Fprintf(stderr, "alert-linter: note: %s contains no rule groups\n", p)
			}
			if !seen[p] {
				seen[p] = true
				files = append(files, f)
			}
			continue
		}
		var found []string
		err = filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && path != p && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			if ext := filepath.Ext(path); !d.IsDir() && (ext == ".yml" || ext == ".yaml") {
				found = append(found, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		sort.Strings(found)
		for _, path := range found {
			if seen[path] {
				continue
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			f := loader.Parse(path, data)
			// A rule file with a syntax error has no parsed groups, so fall
			// back to a textual check rather than silently skipping it.
			if f.Groups > 0 || (len(f.Problems) > 0 && bytes.Contains(data, []byte("groups:"))) {
				seen[path] = true
				files = append(files, f)
			}
		}
	}
	return files, nil
}

func printRules(w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RULE\tDEFAULT\tSUMMARY")
	for _, c := range lint.Checks {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", c.ID, c.Default, strings.ReplaceAll(c.Summary, "`", ""))
	}
	_ = tw.Flush()
	fmt.Fprintf(w, "\nmissing-runbook-url and missing-summary are errors on paging alerts and warnings otherwise.\nDocs: %s#rules\n", HelpURI)
}

func version() string {
	if Version != "dev" {
		return Version
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		return bi.Main.Version
	}
	return Version
}
