package report

import (
	"bytes"
	"strings"
	"testing"

	"github.com/rtulke/checkmate/internal/engine"
)

func sampleReport() *engine.Report {
	rc := 0
	return &engine.Report{
		Policy: "Test",
		Results: []engine.Result{
			{ID: "A-1", Name: "first check", Status: engine.StatusPass, Severity: "medium"},
			{ID: "B-22", Name: "second check", Status: engine.StatusFail, Severity: "critical",
				Message: "expected stdout == \"no\",\ngot \"yes\"", Command: "echo yes", RC: &rc, Remediation: "fix it"},
			{ID: "C-333", Name: "third", Status: engine.StatusSkip, Message: "when: x is false"},
		},
		Summary: engine.Summary{Total: 3, Passed: 1, Failed: 1, Skipped: 1, FailOn: "low", Score: 20},
	}
}

func TestTextOneLinePerResult(t *testing.T) {
	var b bytes.Buffer
	if err := Text(&b, sampleReport(), TextOptions{Version: "test"}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	lines := strings.Split(out, "\n")
	var resultLines []string
	for _, l := range lines {
		if strings.HasPrefix(l, "PASS") || strings.HasPrefix(l, "FAIL") || strings.HasPrefix(l, "SKIP") {
			resultLines = append(resultLines, l)
		}
	}
	if len(resultLines) != 3 {
		t.Fatalf("want 3 result lines, got %d:\n%s", len(resultLines), out)
	}
	if !strings.Contains(resultLines[1], `[critical]  expected stdout == "no", got "yes"`) {
		t.Errorf("reason must be on the result line, newlines collapsed: %q", resultLines[1])
	}
	if strings.Contains(out, "fix it") {
		t.Error("remediation belongs to verbose output")
	}
	if !strings.Contains(out, "Run with -v") {
		t.Error("expected a hint about -v")
	}
	// Reasons of FAIL and SKIP rows start in the same column.
	if strings.Index(resultLines[1], "expected") != strings.Index(resultLines[2], "when:") {
		t.Errorf("reasons are not aligned:\n%s\n%s", resultLines[1], resultLines[2])
	}
}

func TestTextTruncatesToWidth(t *testing.T) {
	var b bytes.Buffer
	if err := Text(&b, sampleReport(), TextOptions{Width: 50}); err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(b.String(), "\n") {
		if strings.HasPrefix(l, "FAIL") || strings.HasPrefix(l, "SKIP") {
			if n := len([]rune(l)); n > 50 {
				t.Errorf("line has %d runes, want <= 50: %q", n, l)
			}
			if !strings.HasSuffix(l, "…") {
				t.Errorf("shortened line should end with an ellipsis: %q", l)
			}
		}
	}
}

func TestTextVerboseShowsDetails(t *testing.T) {
	var b bytes.Buffer
	if err := Text(&b, sampleReport(), TextOptions{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"command: echo yes", "exit code: 0", "fix: fix it"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("verbose output lacks %q", want)
		}
	}
}
