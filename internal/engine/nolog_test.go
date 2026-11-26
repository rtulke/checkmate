//go:build !windows

package engine

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rtulke/checkmate/internal/facts"
	"github.com/rtulke/checkmate/internal/policy"
)

func TestNoLogKeepsSecretsOutOfResults(t *testing.T) {
	const secret = "s3cr3t-token"
	file := filepath.Join(t.TempDir(), "p.yml")
	content := `
name: no_log
waivers:
  - { id: WAIVED, reason: accepted }
checks:
  - { id: PASS, no_log: true, run: "echo ` + secret + `", expect: "` + secret + `" }
  - { id: FAIL, no_log: true, run: "echo ` + secret + ` x", expect: "== ` + secret + `" }
  - { id: WAIVED, no_log: true, run: "echo ` + secret + ` x", expect: "== ` + secret + `" }
  - { id: ERROR, no_log: true, run: "echo ` + secret + ` >&2; exit 3", expect: "~ x" }
  - { id: MISSING, no_log: true, run: "` + secret + `-command", expect: true }
  - { id: TIMEOUT, no_log: true, timeout: 200ms, run: "sleep 5 # ` + secret + `", expect: true }
  - { id: GUARD, no_log: true, only_if: "test ` + secret + ` = x", run: "echo x", expect: x }
  - { id: REGEX, no_log: true, run: "echo x", expect: "> ` + secret + `" }
  - { id: "LOOP-{{ item }}", no_log: true, loop_run: "echo ` + secret + ` >&2; exit 9", run: "echo x", expect: x }
  - { id: "ITEM-{{ item }}", no_log: true, loop_run: "echo one", run: "echo ` + secret + `; exit 1", expect: x }
  - { id: OPEN, run: "echo visible", expect: hidden }
`
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(file, policy.LoadOptions{AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	r := Run(context.Background(), p, Options{Facts: facts.Gather(), Jobs: 4})

	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), secret) {
		t.Errorf("the secret is in the report:\n%s", data)
	}

	want := map[string]struct {
		status  Status
		message string
	}{
		"PASS":        {StatusPass, ""},
		"FAIL":        {StatusFail, "the expectation does not hold"},
		"WAIVED":      {StatusWaived, "the expectation does not hold"},
		"ERROR":       {StatusError, "command failed with exit code 3"},
		"MISSING":     {StatusError, "command not found or not executable"},
		"TIMEOUT":     {StatusError, "command timed out"},
		"GUARD":       {StatusSkip, "only_if: the command did not succeed"},
		"REGEX":       {StatusError, "the check could not be evaluated"},
		"LOOP-{item}": {StatusError, "command failed"},
		"ITEM-one":    {StatusError, "command failed with exit code 1"},
		"OPEN":        {StatusFail, `got "visible"`},
	}
	if len(r.Results) != len(want) {
		t.Errorf("%d results, want %d", len(r.Results), len(want))
	}
	for _, res := range r.Results {
		w, ok := want[res.ID]
		if !ok || res.Status != w.status || !strings.Contains(res.Message, w.message) {
			t.Errorf("%s: %s %q, want %s %q", res.ID, res.Status, res.Message, w.status, w.message)
		}
		if res.ID == "OPEN" {
			if res.NoLog || res.Command == "" || res.Stdout == "" {
				t.Errorf("a check without no_log lost its details: %+v", res)
			}
			continue
		}
		if !res.NoLog || res.Command != "" || res.OnlyIf != "" || res.Stdout != "" || res.Stderr != "" || res.Expected != HiddenByNoLog {
			t.Errorf("%s keeps details: %+v", res.ID, res)
		}
		if res.Status != StatusPass && res.Status != StatusSkip && !strings.Contains(res.Message, HiddenByNoLog) {
			t.Errorf("%s: the message does not say that details are hidden: %q", res.ID, res.Message)
		}
	}
}
