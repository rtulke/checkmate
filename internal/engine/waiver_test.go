package engine

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rtulke/checkmate/internal/facts"
	"github.com/rtulke/checkmate/internal/policy"
)

const waiverPolicy = `name: waivers
checks:
  - id: W-FAIL
    name: fails
    run: echo no
    expect: "== yes"
  - id: W-PASS
    name: passes
    run: echo yes
    expect: "== yes"
  - id: W-ERROR
    name: errors
    run: exit 3
    expect: "== yes"
  - id: W-OTHER
    name: fails, not waived
    run: echo no
    expect: "== yes"
  - id: W-SKIP
    name: must not run
    run:
      windows: New-Item -ItemType File -Path $env:MARKER | Out-Null
      default: touch "$MARKER"
    expect: true
  - id: W-EXPIRED
    name: waiver expired
    run: echo no
    expect: "== yes"
  - id: W-HOST
    name: waiver for another host
    run: echo no
    expect: "== yes"
waivers:
  - id: [W-FAIL, W-PASS, W-ERROR]
    reason: accepted by the security team
  - id: W-SKIP
    reason: not relevant here
    skip: true
  - id: W-EXP*
    reason: was accepted
    until: 2026-01-31
  - id: W-HOST
    reason: only on another host
    when: facts.hostname == "no-such-host"
`

func runWaivers(t *testing.T, opts Options) (*Report, map[string]Result, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yml")
	if err := os.WriteFile(path, []byte(waiverPolicy), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "marker")
	t.Setenv("MARKER", marker)
	p, err := policy.Load(path, policy.LoadOptions{AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	opts.Facts = facts.Gather()
	if opts.Now.IsZero() {
		opts.Now = time.Date(2026, 2, 1, 0, 0, 0, 0, time.Local)
	}
	r := Run(context.Background(), p, opts)
	byID := map[string]Result{}
	for _, res := range r.Results {
		byID[res.ID] = res
	}
	return r, byID, marker
}

func TestWaivers(t *testing.T) {
	r, res, marker := runWaivers(t, Options{})
	want := map[string]Status{
		"W-FAIL":    StatusWaived,
		"W-PASS":    StatusPass,
		"W-ERROR":   StatusWaived,
		"W-OTHER":   StatusFail,
		"W-SKIP":    StatusWaived,
		"W-EXPIRED": StatusFail,
		"W-HOST":    StatusFail,
	}
	for id, status := range want {
		if res[id].Status != status {
			t.Errorf("%s: status %s, want %s (%s)", id, res[id].Status, status, res[id].Message)
		}
	}
	if w := res["W-FAIL"].Waiver; w == nil || w.Status != StatusFail || w.Reason != "accepted by the security team" {
		t.Errorf("W-FAIL: waiver info %+v", w)
	}
	if w := res["W-ERROR"].Waiver; w == nil || w.Status != StatusError {
		t.Errorf("W-ERROR: waiver must keep the original status: %+v", w)
	}
	if res["W-PASS"].Waiver != nil {
		t.Error("a passing check must not be marked as waived")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("a waiver with skip: true must not run the check")
	}
	if !strings.Contains(res["W-FAIL"].Message, "accepted by the security team") {
		t.Errorf("message must name the reason: %q", res["W-FAIL"].Message)
	}
	if len(r.Notices) != 1 || !strings.Contains(r.Notices[0], "expired on 2026-01-31") {
		t.Errorf("expected one notice about the expired waiver, got %q", r.Notices)
	}
	if r.Summary.Waived != 3 || r.Summary.Failed != 3 {
		t.Errorf("summary: %+v", r.Summary)
	}
}

func TestWaiverValidOnItsLastDay(t *testing.T) {
	_, res, _ := runWaivers(t, Options{Now: time.Date(2026, 1, 31, 23, 59, 0, 0, time.Local)})
	if res["W-EXPIRED"].Status != StatusWaived {
		t.Errorf("a waiver applies through the day given in until, got %s", res["W-EXPIRED"].Status)
	}
}

func TestIgnoreWaivers(t *testing.T) {
	r, res, _ := runWaivers(t, Options{IgnoreWaivers: true})
	if res["W-FAIL"].Status != StatusFail || res["W-SKIP"].Status != StatusPass || r.Summary.Waived != 0 {
		t.Errorf("--ignore-waivers must report raw results: %+v", r.Summary)
	}
}

func TestOnlyWaivedFailuresAreCompliant(t *testing.T) {
	r, _, _ := runWaivers(t, Options{Filter: Filter{IDs: []string{"W-FAIL", "W-PASS", "W-SKIP"}}})
	if !r.Summary.Compliant {
		t.Errorf("waived failures must not make the run non-compliant: %+v", r.Summary)
	}
}

func TestWaiverFileErrors(t *testing.T) {
	cases := map[string]string{
		"missing reason": "waivers:\n  - id: X\n",
		"missing id":     "waivers:\n  - reason: r\n",
		"bad date":       "waivers:\n  - id: X\n    reason: r\n    until: 31.03.2027\n",
		"unknown key":    "waivers:\n  - id: X\n    reason: r\n    expires: 2027-01-01\n",
		"bad pattern":    "waivers:\n  - id: \"[\"\n    reason: r\n",
	}
	for name, data := range cases {
		path := filepath.Join(t.TempDir(), "w.yml")
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := policy.LoadWaivers(path, policy.LoadOptions{AllowInsecure: true}); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
