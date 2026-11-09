// Package loader reads Prometheus rule files into a position-aware model.
//
// It deliberately parses YAML into yaml.v3 nodes rather than unmarshalling
// straight into structs, so every finding can point at the exact line and
// column of the offending field, and so inline "alert-linter:" directives can
// be attached to the rule they sit next to.
package loader

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/common/model"
	"gopkg.in/yaml.v3"
)

// Kind distinguishes alerting rules from recording rules.
type Kind int

const (
	// Alert is an alerting rule (has an `alert:` key).
	Alert Kind = iota
	// Record is a recording rule (has a `record:` key).
	Record
)

// Pos is a 1-based line and column in a source file.
type Pos struct {
	Line, Col int
}

// Problem is a structural defect found while loading: bad YAML, a duration
// that does not parse, a rule with neither alert nor record, and so on.
type Problem struct {
	Pos Pos
	Msg string
}

// Directive is one inline `# alert-linter: disable=...` comment.
type Directive struct {
	Pos      Pos
	FileWide bool
	IDs      []string
}

// Rule is a single alerting or recording rule with source positions.
type Rule struct {
	File  string
	Group string
	Kind  Kind
	Name  string

	Pos     Pos // start of the rule's mapping (the `- ` line)
	NamePos Pos
	EndLine int // last line that belongs to the rule

	Expr    string
	ExprPos Pos

	For    time.Duration
	HasFor bool
	ForPos Pos

	// Labels are the effective static labels: group-level labels overlaid by
	// rule-level labels, which is how Prometheus applies them.
	Labels    map[string]string
	LabelPos  map[string]Pos // where each effective label was defined
	LabelsPos Pos            // the `labels:` key, or the rule start if absent

	Annotations    map[string]string
	AnnotationPos  map[string]Pos
	AnnotationsPos Pos

	// Disabled holds rule IDs switched off by inline directives for this rule.
	Disabled map[string]bool
}

// File is one loaded rule file.
type File struct {
	Path       string
	Rules      []*Rule
	Problems   []Problem
	Directives []Directive
	// FileDisabled holds rule IDs switched off for the whole file.
	FileDisabled map[string]bool
	// Groups is the number of rule groups found across all YAML documents.
	Groups int
}

// LoadFile reads and parses one file from disk.
func LoadFile(path string) (*File, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(path, data), nil
}

// Parse parses rule-file content. It never fails outright: syntax and
// structural errors are recorded as Problems so the linter can report them
// alongside other findings.
func Parse(path string, data []byte) *File {
	f := &File{Path: path, FileDisabled: map[string]bool{}}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			f.Problems = append(f.Problems, Problem{Pos: yamlErrorPos(err), Msg: "invalid YAML: " + cleanYAMLError(err)})
			break
		}
		f.loadDocument(&doc)
	}
	f.applyDirectives(data)
	return f
}

func (f *File) loadDocument(doc *yaml.Node) {
	if len(doc.Content) == 0 {
		return
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return
	}
	groups := mapGet(root, "groups")
	// Kubernetes PrometheusRule manifests (prometheus-operator) nest the
	// groups under spec.groups.
	if groups == nil {
		if kind := mapGet(root, "kind"); kind != nil && kind.Value == "PrometheusRule" {
			if spec := mapGet(root, "spec"); spec != nil {
				groups = mapGet(spec, "groups")
			}
		}
	}
	if groups == nil {
		return
	}
	if groups.Kind != yaml.SequenceNode {
		f.problem(groups, "`groups` must be a list")
		return
	}
	for _, g := range groups.Content {
		f.loadGroup(g)
	}
}

func (f *File) loadGroup(g *yaml.Node) {
	if g.Kind != yaml.MappingNode {
		f.problem(g, "each rule group must be a mapping")
		return
	}
	f.Groups++
	name := ""
	if n := mapGet(g, "name"); n != nil {
		name = n.Value
	} else {
		f.problem(g, "rule group has no `name`")
	}
	groupLabels, groupLabelPos := f.stringMap(mapGet(g, "labels"), "labels")
	if iv := mapGet(g, "interval"); iv != nil {
		if _, err := model.ParseDuration(iv.Value); err != nil {
			f.problem(iv, fmt.Sprintf("group %q has an invalid interval %q", name, iv.Value))
		}
	}
	rules := mapGet(g, "rules")
	if rules == nil {
		return
	}
	if rules.Kind != yaml.SequenceNode {
		f.problem(rules, fmt.Sprintf("group %q: `rules` must be a list", name))
		return
	}
	for _, rn := range rules.Content {
		if r := f.loadRule(rn, name, groupLabels, groupLabelPos); r != nil {
			f.Rules = append(f.Rules, r)
		}
	}
}

var knownRuleKeys = map[string]bool{
	"alert": true, "record": true, "expr": true, "for": true,
	"keep_firing_for": true, "labels": true, "annotations": true,
}

func (f *File) loadRule(n *yaml.Node, group string, groupLabels map[string]string, groupLabelPos map[string]Pos) *Rule {
	if n.Kind != yaml.MappingNode {
		f.problem(n, fmt.Sprintf("group %q: each rule must be a mapping", group))
		return nil
	}
	r := &Rule{
		File:     f.Path,
		Group:    group,
		Pos:      pos(n),
		EndLine:  lastLine(n),
		Disabled: map[string]bool{},
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if k := n.Content[i]; !knownRuleKeys[k.Value] {
			f.problem(k, fmt.Sprintf("unknown rule field %q", k.Value))
		}
	}

	alert, record := mapGet(n, "alert"), mapGet(n, "record")
	switch {
	case alert != nil && record != nil:
		f.problem(n, "rule has both `alert` and `record`")
		return nil
	case alert != nil:
		r.Kind, r.Name, r.NamePos = Alert, alert.Value, pos(alert)
	case record != nil:
		r.Kind, r.Name, r.NamePos = Record, record.Value, pos(record)
	default:
		f.problem(n, "rule has neither `alert` nor `record`")
		return nil
	}

	if e := mapGet(n, "expr"); e != nil && strings.TrimSpace(e.Value) != "" {
		r.Expr, r.ExprPos = e.Value, pos(e)
	} else {
		f.problem(n, fmt.Sprintf("rule %q has no `expr`", r.Name))
		return nil
	}

	if fr := mapGet(n, "for"); fr != nil {
		d, err := model.ParseDuration(fr.Value)
		if err != nil {
			f.problem(fr, fmt.Sprintf("rule %q has an invalid `for` duration %q", r.Name, fr.Value))
		} else {
			r.For, r.HasFor, r.ForPos = time.Duration(d), true, pos(fr)
		}
	}
	if kf := mapGet(n, "keep_firing_for"); kf != nil {
		if _, err := model.ParseDuration(kf.Value); err != nil {
			f.problem(kf, fmt.Sprintf("rule %q has an invalid `keep_firing_for` duration %q", r.Name, kf.Value))
		}
	}

	r.Labels, r.LabelPos = map[string]string{}, map[string]Pos{}
	for k, v := range groupLabels {
		r.Labels[k], r.LabelPos[k] = v, groupLabelPos[k]
	}
	r.LabelsPos = r.Pos
	if ln := mapGet(n, "labels"); ln != nil {
		r.LabelsPos = keyPos(n, "labels")
		labels, lpos := f.stringMap(ln, "labels")
		for k, v := range labels {
			r.Labels[k], r.LabelPos[k] = v, lpos[k]
		}
	}

	r.AnnotationsPos = r.Pos
	r.Annotations, r.AnnotationPos = map[string]string{}, map[string]Pos{}
	if an := mapGet(n, "annotations"); an != nil {
		r.AnnotationsPos = keyPos(n, "annotations")
		r.Annotations, r.AnnotationPos = f.stringMap(an, "annotations")
	}
	return r
}

// stringMap reads a mapping of scalar values, recording each value's position.
func (f *File) stringMap(n *yaml.Node, what string) (map[string]string, map[string]Pos) {
	out, out2 := map[string]string{}, map[string]Pos{}
	if n == nil {
		return out, out2
	}
	if n.Kind != yaml.MappingNode {
		f.problem(n, fmt.Sprintf("`%s` must be a mapping", what))
		return out, out2
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if v.Kind != yaml.ScalarNode {
			f.problem(v, fmt.Sprintf("%s value for %q must be a string", what, k.Value))
			continue
		}
		out[k.Value], out2[k.Value] = v.Value, pos(v)
	}
	return out, out2
}

func (f *File) problem(n *yaml.Node, msg string) {
	f.Problems = append(f.Problems, Problem{Pos: pos(n), Msg: msg})
}

// directiveRe matches `alert-linter: disable=a,b` and
// `alert-linter: disable-file=a,b`. Anything after the ID list (for example
// `-- reason`) is ignored, which encourages writing down why.
var directiveRe = regexp.MustCompile(`#\s*alert-linter:\s*(disable|disable-file)=([A-Za-z0-9_,-]+)`)

// applyDirectives scans raw lines for directives. A rule-level directive
// applies to the rule whose lines contain it (for example a trailing comment
// on `for: 30s`), or, if it sits between rules, to the next rule below it.
func (f *File) applyDirectives(data []byte) {
	lines := strings.Split(string(data), "\n")
	for i, line := range lines {
		m := directiveRe.FindStringSubmatchIndex(line)
		if m == nil {
			continue
		}
		ids := strings.Split(strings.Trim(line[m[4]:m[5]], ","), ",")
		d := Directive{
			Pos:      Pos{Line: i + 1, Col: m[0] + 1},
			FileWide: line[m[2]:m[3]] == "disable-file",
			IDs:      ids,
		}
		f.Directives = append(f.Directives, d)
		if d.FileWide {
			for _, id := range ids {
				f.FileDisabled[id] = true
			}
			continue
		}
		if r := f.ruleForLine(d.Pos.Line); r != nil {
			for _, id := range ids {
				r.Disabled[id] = true
			}
		}
	}
}

func (f *File) ruleForLine(line int) *Rule {
	for _, r := range f.Rules {
		if line >= r.Pos.Line && line <= r.EndLine {
			return r
		}
	}
	var next *Rule
	for _, r := range f.Rules {
		if r.Pos.Line > line && (next == nil || r.Pos.Line < next.Pos.Line) {
			next = r
		}
	}
	return next
}

func mapGet(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func keyPos(m *yaml.Node, key string) Pos {
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return pos(m.Content[i])
		}
	}
	return pos(m)
}

func pos(n *yaml.Node) Pos { return Pos{Line: n.Line, Col: n.Column} }

// lastLine returns the last source line spanned by a node, including the
// body of literal block scalars such as a multi-line `expr: |`.
func lastLine(n *yaml.Node) int {
	end := n.Line
	if n.Kind == yaml.ScalarNode && n.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		end += strings.Count(strings.TrimRight(n.Value, "\n"), "\n") + 1
	}
	for _, c := range n.Content {
		if l := lastLine(c); l > end {
			end = l
		}
	}
	return end
}

var yamlLineRe = regexp.MustCompile(`line (\d+)`)

func yamlErrorPos(err error) Pos {
	if m := yamlLineRe.FindStringSubmatch(err.Error()); m != nil {
		if n, convErr := strconv.Atoi(m[1]); convErr == nil {
			return Pos{Line: n, Col: 1}
		}
	}
	return Pos{Line: 1, Col: 1}
}

func cleanYAMLError(err error) string {
	return strings.TrimPrefix(err.Error(), "yaml: ")
}
