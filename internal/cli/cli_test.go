package cli

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files in testdata/golden")

// Golden tests run the real CLI in-process from the repository root, so the
// paths in the output match what a user would see. Regenerate with:
//
//	go test ./internal/cli -update
func TestGolden(t *testing.T) {
	cases := []struct {
		name string
		args []string
		exit int
	}{
		{"bad.txt", []string{"examples/bad-rules.yaml"}, ExitFindings},
		{"bad.json", []string{"--format", "json", "examples/bad-rules.yaml"}, ExitFindings},
		{"bad.sarif", []string{"--format", "sarif", "examples/bad-rules.yaml"}, ExitFindings},
		{"bad-with-config.txt", []string{"--config", "examples/alert-linter.yaml", "examples/bad-rules.yaml"}, ExitFindings},
		{"good.txt", []string{"examples/good-rules.yaml"}, ExitOK},
		{"prometheusrule.txt", []string{"examples/prometheusrule.yaml"}, ExitOK},
		{"prometheusrule-fail-on-warning.txt", []string{"--fail-on", "warning", "examples/prometheusrule.yaml"}, ExitFindings},
		{"list-rules.txt", []string{"--list-rules"}, ExitOK},
	}
	t.Chdir("../..")
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(c.args, &stdout, &stderr); code != c.exit {
				t.Fatalf("exit code %d, want %d; stderr: %s", code, c.exit, stderr.String())
			}
			golden := filepath.Join("testdata", "golden", c.name+".golden")
			if *update {
				if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, stdout.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run `go test ./internal/cli -update`)", err)
			}
			if got := stdout.String(); got != string(want) {
				t.Errorf("output differs from %s (run `go test ./internal/cli -update` if intended)\n--- got ---\n%s", golden, got)
			}
		})
	}
}

func TestDirectoryInputSkipsNonRuleYAML(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("kustomization.yaml", "resources: [a.yaml]\n")
	write("values.yaml", "image: {{ .Values.image }}\n") // not valid YAML, not a rule file
	write("rules/broken.yaml", "groups:\n  - name: g\n    rules: [\n")
	write("rules/ok.yml", "groups:\n  - name: g\n    rules:\n      - alert: A\n        expr: up == 0\n")
	write(".git/ignored.yaml", "groups: [")

	var stdout, stderr bytes.Buffer
	code := Run([]string{"--format", "json", dir}, &stdout, &stderr)
	if code != ExitFindings {
		t.Fatalf("exit %d, stderr %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, `"files": 2`) {
		t.Errorf("expected exactly the two rule files to be linted:\n%s", out)
	}
	if !strings.Contains(out, "broken.yaml") || strings.Contains(out, "values.yaml") || strings.Contains(out, "ignored.yaml") {
		t.Errorf("wrong files linted:\n%s", out)
	}
}

func TestUsageErrors(t *testing.T) {
	for name, args := range map[string][]string{
		"no paths":       {},
		"missing file":   {"does-not-exist.yaml"},
		"bad format":     {"--format", "xml", "../../examples/good-rules.yaml"},
		"bad fail-on":    {"--fail-on", "sometimes", "../../examples/good-rules.yaml"},
		"missing config": {"--config", "nope.yaml", "../../examples/good-rules.yaml"},
		"unknown flag":   {"--frobnicate"},
	} {
		var stdout, stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr); code != ExitUsage {
			t.Errorf("%s: exit %d, want %d", name, code, ExitUsage)
		}
	}
}

func TestOutputFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report.sarif")
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--format", "sarif", "--output", out, "../../examples/bad-rules.yaml"}, &stdout, &stderr)
	if code != ExitFindings {
		t.Fatalf("exit %d", code)
	}
	if stdout.Len() != 0 {
		t.Error("nothing should go to stdout when --output is set")
	}
	data, err := os.ReadFile(out)
	if err != nil || !bytes.Contains(data, []byte(`"version": "2.1.0"`)) {
		t.Fatalf("report not written: %v", err)
	}
	if !strings.Contains(stderr.String(), "8 errors, 10 warnings") {
		t.Errorf("expected a one-line summary on stderr, got %q", stderr.String())
	}
}

func TestFailOnNever(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--fail-on", "never", "../../examples/bad-rules.yaml"}, &stdout, &stderr); code != ExitOK {
		t.Fatalf("exit %d, want 0", code)
	}
}
