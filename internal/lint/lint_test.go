package lint

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/mohammed-saaduddin-ansari/alert-linter/internal/config"
	"github.com/mohammed-saaduddin-ansari/alert-linter/internal/loader"
)

// clean is a rule body that passes every check; cases mutate it.
const cleanLabels = `
        labels:
          severity: critical
          team: payments
        annotations:
          summary: s
          description: d
          runbook_url: https://runbooks.example.com/x`

func rule(name, expr, extra string) string {
	return fmt.Sprintf(`groups:
  - name: g
    rules:
      - alert: %s
        expr: %s
%s`, name, expr, extra)
}

func lintSrc(t *testing.T, cfg *config.Config, srcs ...string) Result {
	t.Helper()
	if cfg == nil {
		cfg = config.Default()
	}
	l, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var files []*loader.File
	for i, s := range srcs {
		files = append(files, loader.Parse(fmt.Sprintf("f%d.yaml", i), []byte(s)))
	}
	return l.Lint(files)
}

// ids returns "rule:severity" strings, sorted, for compact assertions.
func ids(r Result) string {
	var out []string
	for _, f := range r.Findings {
		out = append(out, f.RuleID+":"+f.Severity.String())
	}
	sort.Strings(out)
	return strings.Join(out, " ")
}

func TestChecks(t *testing.T) {
	good := "sum(rate(http_requests_total{code=~\"5..\"}[5m])) / sum(rate(http_requests_total[5m])) > 0.05"
	cases := []struct {
		name string
		src  string
		want string
	}{
		{"clean", rule("A", good, "        for: 5m"+cleanLabels), ""},
		{"paging without for", rule("A", good, cleanLabels), "paging-missing-for:error"},
		{"paging with for 0s", rule("A", good, "        for: 0s"+cleanLabels), "paging-missing-for:error"},
		{"warning without for is fine", rule("A", good, strings.Replace(cleanLabels, "critical", "warning", 1)), ""},
		{"short for", rule("A", good, "        for: 30s"+cleanLabels), "short-for:warning"},
		{"no annotations on paging", rule("A", good, `        for: 5m
        labels: {severity: page, team: x}`),
			"missing-description:warning missing-runbook-url:error missing-summary:error"},
		{"no annotations on warning", rule("A", good, `        labels: {severity: warning, team: x}`),
			"missing-description:warning missing-runbook-url:warning missing-summary:warning"},
		{"relative runbook", rule("A", good, "        for: 5m"+strings.Replace(cleanLabels, "https://runbooks.example.com/x", "wiki/x", 1)),
			"missing-runbook-url:warning"},
		{"templated runbook ok", rule("A", good, "        for: 5m"+strings.Replace(cleanLabels, "https://runbooks.example.com/x", "'{{ $externalURL }}/x'", 1)), ""},
		{"no labels at all", rule("A", good, `        annotations: {summary: s, description: d, runbook_url: "https://x"}`),
			"missing-owner-label:warning missing-severity:error"},
		{"unknown severity", rule("A", good, "        for: 5m"+strings.Replace(cleanLabels, "critical", "P1", 1)), "unknown-severity:error"},
		{"owner via group labels", `groups:
  - name: g
    labels: {team: payments}
    rules:
      - alert: A
        expr: up == 0
        labels: {severity: warning}
        annotations: {summary: s, description: d, runbook_url: "https://x"}`, ""},
		{"cpu page", rule("A", "avg(rate(node_cpu_seconds_total{mode!=\"idle\"}[5m])) > 0.9", "        for: 5m"+cleanLabels),
			"cause-based-paging:warning"},
		{"cpu via __name__ matcher", rule("A", "'{__name__=\"container_memory_working_set_bytes\"} > 1e9'", "        for: 5m"+cleanLabels),
			"cause-based-paging:warning"},
		{"cpu warning is fine", rule("A", "avg(rate(node_cpu_seconds_total[5m])) > 0.9", strings.Replace(cleanLabels, "critical", "warning", 1)), ""},
		{"disk prediction is a fair page", rule("A", "predict_linear(node_filesystem_avail_bytes[6h], 4*3600) < 0", "        for: 5m"+cleanLabels), ""},
		{"short rate window", rule("A", "sum(rate(http_requests_total[1m])) > 1", "        for: 5m"+cleanLabels), "rate-window-too-short:error"},
		{"several short windows are one finding", rule("A", "irate(x[2m]) + increase(y[30s]) + irate(x[2m])", "        for: 5m"+cleanLabels),
			"rate-window-too-short:error"},
		{"rate window exactly 4x is fine", rule("A", "rate(x[4m]) > 1", "        for: 5m"+cleanLabels), ""},
		{"subquery with too few steps", rule("A", "rate(x[1m:30s]) > 1", "        for: 5m"+cleanLabels), "rate-window-too-short:error"},
		{"by pod on page", rule("A", "sum by (namespace, pod) (rate(x[5m])) > 1", "        for: 5m"+cleanLabels), "high-cardinality-grouping:warning"},
		{"without pod is not flagged", rule("A", "sum without (pod) (rate(x[5m])) > 1", "        for: 5m"+cleanLabels), ""},
		{"by pod on warning is fine", rule("A", "sum by (pod) (rate(x[5m])) > 1", strings.Replace(cleanLabels, "critical", "warning", 1)), ""},
		{"bad promql", rule("A", "sum(rate(x[5m])", "        for: 5m"+cleanLabels), "invalid-rule:error"},
		{"recording rule short window", `groups:
  - name: g
    rules:
      - record: job:x:rate1m
        expr: sum by (job) (rate(x[1m]))`, "rate-window-too-short:error"},
		{"duplicate with same labels", rule("A", good, "        for: 5m"+cleanLabels) + "\n      - alert: A\n        expr: up == 0\n        for: 5m" + cleanLabels,
			"duplicate-alert:error"},
		{"same name, different severity tiers", rule("A", good, "        for: 5m"+cleanLabels) + "\n      - alert: A\n        expr: up == 0\n" + strings.Replace(cleanLabels, "critical", "warning", 1),
			""},
		{"unknown directive", "# alert-linter: disable=short-fro\n" + rule("A", good, "        for: 30s"+cleanLabels),
			"short-for:warning unknown-directive:warning"},
		{"directive disables", "# alert-linter: disable=short-for\n" + rule("A", good, "        for: 30s"+cleanLabels), ""},
		{"disable all", "# alert-linter: disable-file=all\n" + rule("A", "sum(rate(x[1m]))", ""), ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := ids(lintSrc(t, nil, c.src)); got != c.want {
				t.Errorf("got  %q\nwant %q", got, c.want)
			}
		})
	}
}

func TestConfigOverrides(t *testing.T) {
	src := rule("A", "sum by (pod) (rate(node_cpu_seconds_total[1m]))", cleanLabels)
	cfg, err := config.Parse([]byte(`
scrape_interval: 15s
rules:
  cause-based-paging: "off"
  high-cardinality-grouping: error
  paging-missing-for: warning
`))
	if err != nil {
		t.Fatal(err)
	}
	got := ids(lintSrc(t, cfg, src))
	want := "high-cardinality-grouping:error paging-missing-for:warning"
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}

func TestUnknownRuleInConfigIsRejected(t *testing.T) {
	cfg := config.Default()
	cfg.Rules["no-such-rule"] = "off"
	if _, err := New(cfg); err == nil {
		t.Fatal("expected an error for an unknown rule id")
	}
}

func TestDuplicateAcrossFiles(t *testing.T) {
	a := rule("A", "up == 0", "        for: 5m"+cleanLabels)
	r := lintSrc(t, nil, a, a)
	if ids(r) != "duplicate-alert:error" {
		t.Fatalf("got %q", ids(r))
	}
	f := r.Findings[0]
	if f.File != "f1.yaml" || !strings.Contains(f.Message, "first at f0.yaml:4") {
		t.Errorf("finding should point at the second file and cite the first: %+v", f)
	}
}

func TestResultCounts(t *testing.T) {
	r := lintSrc(t, nil, rule("A", "sum(rate(x[1m]))", ""))
	if r.Files != 1 || r.Groups != 1 || r.Alerts != 1 || r.Records != 0 {
		t.Errorf("counts: %+v", r)
	}
	if r.Max() != Error || r.Count(Error) == 0 {
		t.Errorf("max=%v errors=%d", r.Max(), r.Count(Error))
	}
}

func TestEveryCheckIsDocumented(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range Checks {
		if c.ID == "" || c.Summary == "" || c.Why == "" || c.Default == Unset {
			t.Errorf("check %q is missing metadata", c.ID)
		}
		if seen[c.ID] {
			t.Errorf("duplicate check id %q", c.ID)
		}
		seen[c.ID] = true
	}
}
