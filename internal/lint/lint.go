// Package lint runs on-call hygiene checks over loaded Prometheus rules.
package lint

import (
	"fmt"
	"sort"
	"strings"

	"github.com/prometheus/prometheus/promql/parser"

	"github.com/mohammed-saaduddin-ansari/alert-linter/internal/config"
	"github.com/mohammed-saaduddin-ansari/alert-linter/internal/loader"
)

// Severity of a finding. The zero value means "use the check's default".
type Severity int

// Severities, ordered so that comparisons work (Error > Warning > Info).
const (
	Unset Severity = iota
	Info
	Warning
	Error
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "info"
	case Warning:
		return "warning"
	case Error:
		return "error"
	}
	return "unset"
}

// MarshalText makes severities render as words in JSON.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// ParseSeverity converts "error", "warning" or "info".
func ParseSeverity(v string) (Severity, error) {
	switch v {
	case "error":
		return Error, nil
	case "warning":
		return Warning, nil
	case "info":
		return Info, nil
	}
	return Unset, fmt.Errorf("unknown severity %q", v)
}

// Finding is one reported problem.
type Finding struct {
	RuleID   string   `json:"rule"`
	Severity Severity `json:"severity"`
	File     string   `json:"file"`
	Line     int      `json:"line"`
	Column   int      `json:"column"`
	Name     string   `json:"name,omitempty"` // alert or record name
	Message  string   `json:"message"`
	Hint     string   `json:"hint,omitempty"`
}

// Result is the outcome of a lint run.
type Result struct {
	Findings []Finding
	Files    int
	Groups   int
	Alerts   int
	Records  int
}

// Count returns the number of findings at exactly the given severity.
func (r Result) Count(s Severity) int {
	n := 0
	for _, f := range r.Findings {
		if f.Severity == s {
			n++
		}
	}
	return n
}

// Max returns the highest severity among the findings (Unset if none).
func (r Result) Max() Severity {
	m := Unset
	for _, f := range r.Findings {
		if f.Severity > m {
			m = f.Severity
		}
	}
	return m
}

// Linter applies the registered checks with a given configuration.
type Linter struct {
	cfg    *config.Config
	parser parser.Parser
}

// New validates the configuration against the check registry.
func New(cfg *config.Config) (*Linter, error) {
	for id := range cfg.Rules {
		if CheckByID(id) == nil {
			return nil, fmt.Errorf("config: unknown rule %q (run --list-rules)", id)
		}
	}
	return &Linter{
		cfg: cfg,
		// Experimental functions are accepted: this is a hygiene linter, not
		// a validator, and promtool already rejects what your server won't run.
		parser: parser.NewParser(parser.Options{EnableExperimentalFunctions: true}),
	}, nil
}

// Lint checks all files together, so duplicates are found across files.
func (l *Linter) Lint(files []*loader.File) Result {
	res := Result{Files: len(files)}
	var raw []Finding
	seen := map[string]*loader.Rule{}

	for _, f := range files {
		res.Groups += f.Groups
		for _, p := range f.Problems {
			raw = append(raw, l.finding(f, nil, checkInvalidRule, issue{pos: p.Pos, msg: p.Msg}))
		}
		for _, d := range f.Directives {
			for _, id := range d.IDs {
				if id != "all" && CheckByID(id) == nil {
					raw = append(raw, l.finding(f, nil, checkUnknownDirective, issue{
						pos:  d.Pos,
						msg:  fmt.Sprintf("directive disables unknown rule %q, so it has no effect", id),
						hint: "check the spelling against `alert-linter --list-rules`",
					}))
				}
			}
		}
		for _, r := range f.Rules {
			if r.Kind == loader.Alert {
				res.Alerts++
			} else {
				res.Records++
			}
			t := l.target(r)
			if t.parseErr != nil {
				raw = append(raw, l.finding(f, r, checkInvalidRule, issue{
					pos: r.ExprPos,
					msg: fmt.Sprintf("%q has an expression that does not parse: %v", r.Name, t.parseErr),
				}))
			}
			for _, c := range Checks {
				if c.run == nil || (r.Kind == loader.Record && !c.Records) {
					continue
				}
				for _, is := range c.run(t) {
					raw = append(raw, l.finding(f, r, c, is))
				}
			}
			if r.Kind == loader.Alert {
				if is, ok := duplicate(seen, r); ok {
					raw = append(raw, l.finding(f, r, checkDuplicate, is))
				}
			}
		}
	}

	for _, fd := range raw {
		if fd.Severity != Unset {
			res.Findings = append(res.Findings, fd)
		}
	}
	sort.SliceStable(res.Findings, func(i, j int) bool {
		a, b := res.Findings[i], res.Findings[j]
		if a.File != b.File {
			return a.File < b.File
		}
		if a.Line != b.Line {
			return a.Line < b.Line
		}
		if a.Column != b.Column {
			return a.Column < b.Column
		}
		return a.RuleID < b.RuleID
	})
	return res
}

// finding turns an issue into a Finding, applying config overrides and
// inline directives. A suppressed finding comes back with Severity Unset.
func (l *Linter) finding(f *loader.File, r *loader.Rule, c *Check, is issue) Finding {
	fd := Finding{
		RuleID:  c.ID,
		File:    f.Path,
		Line:    is.pos.Line,
		Column:  is.pos.Col,
		Message: is.msg,
		Hint:    is.hint,
	}
	if r != nil {
		fd.Name = r.Name
	}
	fd.Severity = is.sev
	if fd.Severity == Unset {
		fd.Severity = c.Default
	}
	if setting, ok := l.cfg.Rules[c.ID]; ok {
		if setting == "off" {
			fd.Severity = Unset
			return fd
		}
		fd.Severity, _ = ParseSeverity(setting)
	}
	if f.FileDisabled[c.ID] || f.FileDisabled["all"] {
		fd.Severity = Unset
	}
	if r != nil && (r.Disabled[c.ID] || r.Disabled["all"]) {
		fd.Severity = Unset
	}
	return fd
}

func (l *Linter) target(r *loader.Rule) *target {
	t := &target{Rule: r, cfg: l.cfg}
	t.expr, t.parseErr = l.parser.ParseExpr(r.Expr)
	if t.parseErr != nil {
		t.expr = nil
	}
	t.severity, t.hasSeverity = r.Labels[l.cfg.SeverityLabel]
	t.paging = r.Kind == loader.Alert && t.hasSeverity && l.cfg.IsPaging(t.severity)
	return t
}

// duplicate flags an alert whose name and static labels exactly match an
// earlier one. The same name with different labels (for example a warning
// tier and a critical tier) is a deliberate, common pattern and is allowed.
func duplicate(seen map[string]*loader.Rule, r *loader.Rule) (issue, bool) {
	keys := make([]string, 0, len(r.Labels))
	for k, v := range r.Labels {
		keys = append(keys, k+"="+v)
	}
	sort.Strings(keys)
	key := r.Name + "{" + strings.Join(keys, ",") + "}"
	first, ok := seen[key]
	if !ok {
		seen[key] = r
		return issue{}, false
	}
	return issue{
		pos: r.NamePos,
		msg: fmt.Sprintf("alert %q is defined again with identical labels (first at %s:%d)", r.Name, first.File, first.Pos.Line),
		hint: "Alertmanager cannot tell the two apart, so silences, inhibitions and grouping act on both; " +
			"delete one or give them distinct labels such as different severity tiers",
	}, true
}
