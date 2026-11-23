package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rtulke/checkmate/internal/engine"
	"github.com/rtulke/checkmate/internal/facts"
)

func sampleReport() *engine.Report {
	rc := 0
	return &engine.Report{
		Policy:      "Test",
		PolicyFiles: []string{"/etc/checkmate/test.yml"},
		Facts:       facts.Facts{OS: "linux", Distro: "debian", Version: "12"},
		Results: []engine.Result{
			{ID: "A-1", Name: "first check", Status: engine.StatusPass, Severity: "medium",
				Command: "echo ok", RC: &rc, Stdout: "ok\n", Shell: "bash"},
			{ID: "B-22", Name: "second check", Status: engine.StatusFail, Severity: "critical",
				Message: "expected stdout == \"no\",\ngot \"yes\"", Command: "echo yes", RC: &rc, Rationale: "why it matters", Remediation: "fix it",
				When: []string{"facts.os == \"linux\""}},
			{ID: "C-333", Name: "third", Status: engine.StatusSkip, Message: "when: x is false"},
		},
		Summary: engine.Summary{Total: 3, Passed: 1, Failed: 1, Skipped: 1, Evaluated: 2, FailOn: "low", Score: 20},
	}
}

func render(t *testing.T, opts TextOptions) string {
	t.Helper()
	var b bytes.Buffer
	if err := Text(&b, sampleReport(), opts); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func resultLines(out string) []string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "PASS") || strings.HasPrefix(l, "FAIL") || strings.HasPrefix(l, "SKIP") {
			lines = append(lines, l)
		}
	}
	return lines
}

func TestVerbosity0ShowsThreeColumns(t *testing.T) {
	out := render(t, TextOptions{})
	lines := resultLines(out)
	if len(lines) != 3 {
		t.Fatalf("want 3 result lines, got %d:\n%s", len(lines), out)
	}
	if strings.Contains(out, "[critical]") || strings.Contains(out, "expected stdout") {
		t.Errorf("default output must not show severity or reason:\n%s", out)
	}
	if !strings.HasSuffix(lines[1], "second check") {
		t.Errorf("line should end with the name: %q", lines[1])
	}
	if !strings.Contains(out, "Run with -v") {
		t.Error("expected a hint about -v")
	}
}

func TestVerbosity1ShowsSeverityAndReason(t *testing.T) {
	out := render(t, TextOptions{Verbosity: 1})
	lines := resultLines(out)
	if !strings.Contains(lines[1], `[critical]  expected stdout == "no", got "yes"`) {
		t.Errorf("reason must be on the result line, newlines collapsed: %q", lines[1])
	}
	if strings.Contains(out, "fix it") || strings.Contains(out, "command:") {
		t.Error("details belong to -vv")
	}
	if strings.Index(lines[1], "expected") != strings.Index(lines[2], "when:") {
		t.Errorf("reasons are not aligned:\n%s\n%s", lines[1], lines[2])
	}
}

func TestVerbosity1TruncatesToWidth(t *testing.T) {
	out := render(t, TextOptions{Verbosity: 1, Width: 50})
	for _, l := range resultLines(out) {
		if strings.HasPrefix(l, "PASS") {
			continue
		}
		if n := len([]rune(l)); n > 50 {
			t.Errorf("line has %d runes, want <= 50: %q", n, l)
		}
		if !strings.HasSuffix(l, "…") {
			t.Errorf("shortened line should end with an ellipsis: %q", l)
		}
	}
}

func TestVerbosity2ShowsDetailsOfProblems(t *testing.T) {
	out := render(t, TextOptions{Verbosity: 2})
	for _, want := range []string{"command: echo yes", "exit code: 0", "why: why it matters", "fix: fix it"} {
		if !strings.Contains(out, want) {
			t.Errorf("-vv output lacks %q", want)
		}
	}
	if strings.Contains(out, "command: echo ok") {
		t.Error("-vv must not show details of passed checks")
	}
}

func TestVerbosity3ShowsDebugForEveryCheck(t *testing.T) {
	out := render(t, TextOptions{Verbosity: 3})
	for _, want := range []string{
		"command: echo ok", "shell: bash", "duration:", // passed check
		`when: facts.os == "linux"`, "platform keys:", "/etc/checkmate/test.yml",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("-vvv output lacks %q", want)
		}
	}
}

func TestNothingEvaluated(t *testing.T) {
	r := sampleReport()
	r.Results = r.Results[2:]
	r.Summary = engine.Summary{Total: 1, Skipped: 1, Score: -1}
	var b bytes.Buffer
	if err := Text(&b, r, TextOptions{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "NOTHING EVALUATED") || strings.Contains(out, "COMPLIANT") {
		t.Errorf("a run without evaluated checks must not look compliant:\n%s", out)
	}
}
