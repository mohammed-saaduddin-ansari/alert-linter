package loader

import (
	"strings"
	"testing"
	"time"
)

func TestParsePlainRuleFile(t *testing.T) {
	src := `groups:
  - name: api
    labels:
      team: payments
    rules:
      - alert: HighErrorRate
        expr: sum(rate(http_requests_total{code=~"5.."}[5m])) > 1
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: errors
      - record: job:http_requests:rate5m
        expr: sum by (job) (rate(http_requests_total[5m]))
`
	f := Parse("rules.yaml", []byte(src))
	if len(f.Problems) != 0 {
		t.Fatalf("unexpected problems: %+v", f.Problems)
	}
	if f.Groups != 1 || len(f.Rules) != 2 {
		t.Fatalf("got %d groups, %d rules", f.Groups, len(f.Rules))
	}
	a := f.Rules[0]
	if a.Kind != Alert || a.Name != "HighErrorRate" || a.Group != "api" {
		t.Errorf("alert parsed wrongly: %+v", a)
	}
	if !a.HasFor || a.For != 10*time.Minute || a.ForPos.Line != 8 {
		t.Errorf("for = %v (has=%v) at %v", a.For, a.HasFor, a.ForPos)
	}
	if a.Labels["team"] != "payments" || a.Labels["severity"] != "critical" {
		t.Errorf("labels not merged with group labels: %v", a.Labels)
	}
	if a.LabelPos["severity"].Line != 10 || a.LabelPos["team"].Line != 4 {
		t.Errorf("label positions: %v", a.LabelPos)
	}
	if a.Pos.Line != 6 || a.NamePos != (Pos{Line: 6, Col: 16}) {
		t.Errorf("positions: rule %v name %v", a.Pos, a.NamePos)
	}
	if r := f.Rules[1]; r.Kind != Record || r.Labels["team"] != "payments" {
		t.Errorf("record parsed wrongly: %+v", r)
	}
}

func TestParsePrometheusRuleManifest(t *testing.T) {
	src := `apiVersion: v1
kind: ConfigMap
metadata: {name: not-rules}
---
apiVersion: monitoring.coreos.com/v1
kind: PrometheusRule
metadata:
  name: api
spec:
  groups:
    - name: api
      rules:
        - alert: Down
          expr: up == 0
`
	f := Parse("manifest.yaml", []byte(src))
	if len(f.Problems) != 0 || len(f.Rules) != 1 || f.Rules[0].Name != "Down" {
		t.Fatalf("problems=%v rules=%d", f.Problems, len(f.Rules))
	}
	if f.Rules[0].Pos.Line != 13 {
		t.Errorf("line numbers must be file-relative across documents, got %d", f.Rules[0].Pos.Line)
	}
}

func TestParseProblems(t *testing.T) {
	src := `groups:
  - name: g
    rules:
      - alert: NoExpr
      - alert: BadFor
        expr: up == 0
        for: five minutes
      - alert: Both
        record: x
        expr: up
      - expr: up
      - alert: Typo
        expr: up
        anotations: {}
`
	f := Parse("p.yaml", []byte(src))
	want := []string{
		`rule "NoExpr" has no ` + "`expr`",
		`invalid ` + "`for`" + ` duration "five minutes"`,
		"both `alert` and `record`",
		"neither `alert` nor `record`",
		`unknown rule field "anotations"`,
	}
	if len(f.Problems) != len(want) {
		t.Fatalf("got %d problems: %+v", len(f.Problems), f.Problems)
	}
	for i, w := range want {
		if !strings.Contains(f.Problems[i].Msg, w) {
			t.Errorf("problem %d = %q, want it to contain %q", i, f.Problems[i].Msg, w)
		}
	}
	if f.Problems[1].Pos.Line != 7 {
		t.Errorf("bad `for` reported at line %d, want 7", f.Problems[1].Pos.Line)
	}
}

func TestInvalidYAMLReportsLine(t *testing.T) {
	f := Parse("bad.yaml", []byte("groups:\n  - name: g\n    rules: [\n"))
	if len(f.Problems) != 1 || !strings.HasPrefix(f.Problems[0].Msg, "invalid YAML") {
		t.Fatalf("problems: %+v", f.Problems)
	}
	if f.Problems[0].Pos.Line < 2 {
		t.Errorf("expected a line number from the YAML error, got %v", f.Problems[0].Pos)
	}
}

func TestDirectives(t *testing.T) {
	src := `# alert-linter: disable-file=missing-owner-label
groups:
  - name: g
    rules:
      # alert-linter: disable=short-for -- deliberately fast, see ADR-12
      - alert: Above
        expr: up == 0
      - alert: Trailing # alert-linter: disable=missing-summary,missing-description
        expr: up == 0
      - alert: Inside
        expr: |
          up == 0
        for: 30s # alert-linter: disable=short-for
      - alert: Untouched
        expr: up == 0
`
	f := Parse("d.yaml", []byte(src))
	if !f.FileDisabled["missing-owner-label"] {
		t.Error("file-wide directive not applied")
	}
	got := map[string][]string{}
	for _, r := range f.Rules {
		for id := range r.Disabled {
			got[r.Name] = append(got[r.Name], id)
		}
	}
	check := func(name string, ids ...string) {
		t.Helper()
		r := map[string]bool{}
		for _, id := range got[name] {
			r[id] = true
		}
		if len(r) != len(ids) {
			t.Errorf("%s: disabled %v, want %v", name, got[name], ids)
			return
		}
		for _, id := range ids {
			if !r[id] {
				t.Errorf("%s: %s not disabled (got %v)", name, id, got[name])
			}
		}
	}
	check("Above", "short-for")
	check("Trailing", "missing-summary", "missing-description")
	check("Inside", "short-for")
	check("Untouched")
	if len(f.Directives) != 4 {
		t.Errorf("got %d directives, want 4", len(f.Directives))
	}
}

func TestNonRuleYAMLIsIgnored(t *testing.T) {
	f := Parse("kustomization.yaml", []byte("resources:\n  - a.yaml\n"))
	if f.Groups != 0 || len(f.Problems) != 0 {
		t.Fatalf("groups=%d problems=%v", f.Groups, f.Problems)
	}
}
