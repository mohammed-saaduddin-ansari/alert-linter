package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/mohammed-saaduddin-ansari/alert-linter/internal/lint"
)

func sample() lint.Result {
	return lint.Result{
		Files: 1, Groups: 1, Alerts: 2,
		Findings: []lint.Finding{
			{RuleID: "short-for", Severity: lint.Warning, File: "./rules/a.yaml", Line: 7, Column: 14, Name: "A", Message: "m1", Hint: "h1"},
			{RuleID: "missing-severity", Severity: lint.Error, File: "/abs/b.yaml", Line: 3, Column: 9, Name: "B", Message: "m2"},
		},
	}
}

func TestText(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, "text", sample(), Meta{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"./rules/a.yaml:7:14: warning: m1 [short-for]\n    hint: h1\n",
		"/abs/b.yaml:3:9: error: m2 [missing-severity]\n",
		"2 findings (1 error, 1 warning) in 1 file; checked 2 alerts and 0 recording rules\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("text output missing %q:\n%s", want, out)
		}
	}
}

func TestSARIFShape(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, "sarif", sample(), Meta{Version: "1.2.3", HelpURI: "https://example.com/r"}); err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID      string `json:"id"`
						HelpURI string `json:"helpUri"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI       string `json:"uri"`
							URIBaseID string `json:"uriBaseId"`
						} `json:"artifactLocation"`
						Region struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b.Bytes(), &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("bad envelope: %+v", log)
	}
	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != len(lint.Checks) {
		t.Errorf("every check should be listed as a SARIF rule")
	}
	for _, r := range run.Results {
		if run.Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
			t.Errorf("ruleIndex %d does not point at %s", r.RuleIndex, r.RuleID)
		}
	}
	loc0 := run.Results[0].Locations[0].PhysicalLocation
	if loc0.ArtifactLocation.URI != "rules/a.yaml" || loc0.ArtifactLocation.URIBaseID != "%SRCROOT%" || loc0.Region.StartLine != 7 {
		t.Errorf("relative location wrong: %+v", loc0)
	}
	if u := run.Results[1].Locations[0].PhysicalLocation.ArtifactLocation; u.URI != "file:///abs/b.yaml" || u.URIBaseID != "" {
		t.Errorf("absolute location wrong: %+v", u)
	}
	if run.Results[1].Level != "error" || run.Results[0].Level != "warning" {
		t.Errorf("levels wrong")
	}
	if !strings.HasSuffix(run.Tool.Driver.Rules[0].HelpURI, "#"+run.Tool.Driver.Rules[0].ID) {
		t.Errorf("helpUri should anchor to the rule: %s", run.Tool.Driver.Rules[0].HelpURI)
	}
}

func TestJSONEmptyFindingsIsArray(t *testing.T) {
	var b bytes.Buffer
	if err := Write(&b, "json", lint.Result{Files: 1}, Meta{Version: "x"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"findings": []`) {
		t.Errorf("empty findings should encode as []: %s", b.String())
	}
}

func TestUnknownFormat(t *testing.T) {
	if err := Write(&bytes.Buffer{}, "xml", lint.Result{}, Meta{}); err == nil {
		t.Fatal("expected error")
	}
}
