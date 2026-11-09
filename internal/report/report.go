// Package report renders lint results as text, JSON or SARIF 2.1.0.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"strings"

	"github.com/mohammed-saaduddin-ansari/alert-linter/internal/lint"
)

// Formats lists the supported output formats.
var Formats = []string{"text", "json", "sarif"}

// Meta describes the tool for formats that record it.
type Meta struct {
	Version string
	HelpURI string // base URL; "#<rule-id>" is appended per rule
}

// Write renders res in the given format.
func Write(w io.Writer, format string, res lint.Result, meta Meta) error {
	switch format {
	case "text":
		return Text(w, res)
	case "json":
		return JSON(w, res, meta)
	case "sarif":
		return SARIF(w, res, meta)
	}
	return fmt.Errorf("unknown format %q (want one of %s)", format, strings.Join(Formats, ", "))
}

// Text writes one compiler-style line per finding (clickable in most
// editors and terminals), an indented hint, and a one-line summary.
func Text(w io.Writer, res lint.Result) error {
	var b strings.Builder
	for _, f := range res.Findings {
		fmt.Fprintf(&b, "%s:%d:%d: %s: %s [%s]\n", f.File, f.Line, f.Column, f.Severity, f.Message, f.RuleID)
		if f.Hint != "" {
			fmt.Fprintf(&b, "    hint: %s\n", f.Hint)
		}
	}
	if len(res.Findings) > 0 {
		b.WriteString("\n")
	}
	counts := plural(res.Count(lint.Error), "error") + ", " + plural(res.Count(lint.Warning), "warning")
	if n := res.Count(lint.Info); n > 0 {
		counts += ", " + plural(n, "info")
	}
	fmt.Fprintf(&b, "%s (%s) in %s; checked %s and %s\n",
		plural(len(res.Findings), "finding"),
		counts,
		plural(res.Files, "file"),
		plural(res.Alerts, "alert"),
		plural(res.Records, "recording rule"))
	_, err := io.WriteString(w, b.String())
	return err
}

func plural(n int, word string) string {
	if n == 1 || word == "info" {
		return fmt.Sprintf("%d %s", n, word)
	}
	return fmt.Sprintf("%d %ss", n, word)
}

type jsonSummary struct {
	Files    int `json:"files"`
	Groups   int `json:"groups"`
	Alerts   int `json:"alerts"`
	Records  int `json:"recording_rules"`
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
	Infos    int `json:"infos"`
}

type jsonDoc struct {
	Tool     string         `json:"tool"`
	Version  string         `json:"version"`
	Summary  jsonSummary    `json:"summary"`
	Findings []lint.Finding `json:"findings"`
}

// JSON writes a stable machine-readable document.
func JSON(w io.Writer, res lint.Result, meta Meta) error {
	doc := jsonDoc{
		Tool:    "alert-linter",
		Version: meta.Version,
		Summary: jsonSummary{
			Files: res.Files, Groups: res.Groups, Alerts: res.Alerts, Records: res.Records,
			Errors: res.Count(lint.Error), Warnings: res.Count(lint.Warning), Infos: res.Count(lint.Info),
		},
		Findings: res.Findings,
	}
	if doc.Findings == nil {
		doc.Findings = []lint.Finding{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// SARIF 2.1.0 subset accepted by GitHub code scanning.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifText struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown,omitempty"`
}

type sarifRule struct {
	ID                   string        `json:"id"`
	Name                 string        `json:"name"`
	ShortDescription     sarifText     `json:"shortDescription"`
	FullDescription      sarifText     `json:"fullDescription"`
	Help                 sarifText     `json:"help"`
	HelpURI              string        `json:"helpUri,omitempty"`
	DefaultConfiguration sarifRuleConf `json:"defaultConfiguration"`
	Properties           sarifProps    `json:"properties"`
}

type sarifRuleConf struct {
	Level string `json:"level"`
}

type sarifProps struct {
	Tags []string `json:"tags"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	RuleIndex int             `json:"ruleIndex"`
	Level     string          `json:"level"`
	Message   sarifText       `json:"message"`
	Locations []sarifLocation `json:"locations"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
	Region           sarifRegion   `json:"region"`
}

type sarifArtifact struct {
	URI       string `json:"uri"`
	URIBaseID string `json:"uriBaseId,omitempty"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

func sarifLevel(s lint.Severity) string {
	switch s {
	case lint.Error:
		return "error"
	case lint.Warning:
		return "warning"
	}
	return "note"
}

// SARIF writes a SARIF 2.1.0 log. Every check is listed as a rule (not only
// those with findings) so code scanning can show help text and close
// alerts that have been fixed.
func SARIF(w io.Writer, res lint.Result, meta Meta) error {
	driver := sarifDriver{Name: "alert-linter", Version: meta.Version, InformationURI: meta.HelpURI}
	index := map[string]int{}
	for i, c := range lint.Checks {
		index[c.ID] = i
		helpURI := ""
		if meta.HelpURI != "" {
			helpURI = meta.HelpURI + "#" + c.ID
		}
		driver.Rules = append(driver.Rules, sarifRule{
			ID:                   c.ID,
			Name:                 ruleName(c.ID),
			ShortDescription:     sarifText{Text: c.Summary},
			FullDescription:      sarifText{Text: c.Why},
			Help:                 sarifText{Text: c.Why, Markdown: "**" + c.Summary + "**\n\n" + c.Why},
			HelpURI:              helpURI,
			DefaultConfiguration: sarifRuleConf{Level: sarifLevel(c.Default)},
			Properties:           sarifProps{Tags: []string{"prometheus", "alerting", "on-call"}},
		})
	}
	results := make([]sarifResult, 0, len(res.Findings))
	for _, f := range res.Findings {
		msg := f.Message
		if f.Hint != "" {
			msg += ". Suggestion: " + f.Hint
		}
		results = append(results, sarifResult{
			RuleID:    f.RuleID,
			RuleIndex: index[f.RuleID],
			Level:     sarifLevel(f.Severity),
			Message:   sarifText{Text: msg},
			Locations: []sarifLocation{{PhysicalLocation: sarifPhysical{
				ArtifactLocation: sarifLocationFor(f.File),
				Region:           sarifRegion{StartLine: max(f.Line, 1), StartColumn: f.Column},
			}}},
		})
	}
	log := sarifLog{
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Version: "2.1.0",
		Runs:    []sarifRun{{Tool: sarifTool{Driver: driver}, Results: results}},
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

// sarifLocationFor makes a repository-relative URI, which is what code
// scanning needs to attach a result to a file in the pull request diff.
// Absolute paths fall back to a file:// URI.
func sarifLocationFor(path string) sarifArtifact {
	if filepath.IsAbs(path) {
		return sarifArtifact{URI: (&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}).String()}
	}
	return sarifArtifact{URI: filepath.ToSlash(filepath.Clean(path)), URIBaseID: "%SRCROOT%"}
}

// ruleName turns "paging-missing-for" into "PagingMissingFor".
func ruleName(id string) string {
	parts := strings.Split(id, "-")
	for i, p := range parts {
		if p != "" {
			parts[i] = strings.ToUpper(p[:1]) + p[1:]
		}
	}
	return strings.Join(parts, "")
}
