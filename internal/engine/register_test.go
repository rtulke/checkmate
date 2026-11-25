//go:build !windows

package engine

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/rtulke/checkmate/internal/facts"
	"github.com/rtulke/checkmate/internal/policy"
)

const registerPolicy = `
name: register
waivers:
  - id: WAIVED
    reason: not run here
    skip: true
checks:
  - id: PRESENT
    register: present
    tags: [probe]
    run: command -v sh
    expect: true
  - id: ABSENT
    register: absent
    severity: info
    run: exit 3
    expect: true
  - id: SKIPPED
    register: skipped
    when: facts.os == 'plan9'
    run: echo x
    expect: x
  - id: WAIVED
    register: waived
    run: echo x
    expect: x
  - id: BROKEN
    register: broken
    run: no-such-command-here
    expect: x
  - id: ON-PRESENT
    when: present.passed and present.rc == 0
    register: chained
    run: echo x
    expect: x
  - id: ON-ABSENT
    when: absent.passed
    run: echo x
    expect: x
  - id: ON-FAILED
    tags: [leaf]
    when: [absent.failed, absent.rc == 3, "skipped.status == 'skip'", not skipped.ran,
           "waived.status == 'waived'", "broken.status == 'error'", chained.passed]
    run: echo x
    expect: x
`

func runRegister(t *testing.T, opts Options) map[string]Status {
	t.Helper()
	file := filepath.Join(t.TempDir(), "p.yml")
	if err := os.WriteFile(file, []byte(registerPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(file, policy.LoadOptions{AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	opts.Facts = facts.Gather()
	got := map[string]Status{}
	for _, res := range Run(context.Background(), p, opts).Results {
		got[res.ID] = res.Status
		if res.Status == StatusError && res.ID != "BROKEN" {
			t.Errorf("%s: %s", res.ID, res.Message)
		}
	}
	return got
}

func TestRegisterSteersLaterChecks(t *testing.T) {
	// One job: a check must never wait for one that cannot start.
	for _, jobs := range []int{1, 8} {
		got := runRegister(t, Options{Jobs: jobs})
		want := map[string]Status{
			"PRESENT": StatusPass, "ABSENT": StatusWarn, "SKIPPED": StatusSkip, "WAIVED": StatusWaived,
			"BROKEN": StatusError, "ON-PRESENT": StatusPass, "ON-ABSENT": StatusSkip, "ON-FAILED": StatusPass,
		}
		for id, status := range want {
			if got[id] != status {
				t.Errorf("jobs %d: %s is %q, want %s", jobs, id, got[id], status)
			}
		}
	}
}

func TestRegisterSelectsNeededChecks(t *testing.T) {
	got := runRegister(t, Options{Jobs: 2, Filter: Filter{Tags: ParseTagExpr("leaf")}})
	for _, id := range []string{"ON-FAILED", "ABSENT", "SKIPPED", "WAIVED", "BROKEN", "ON-PRESENT", "PRESENT"} {
		if _, ok := got[id]; !ok {
			t.Errorf("%s was not selected", id)
		}
	}
	if _, ok := got["ON-ABSENT"]; ok || got["ON-FAILED"] != StatusPass {
		t.Errorf("results: %v", got)
	}
	if got := runRegister(t, Options{Jobs: 2, Filter: Filter{Tags: ParseTagExpr("probe")}}); len(got) != 1 {
		t.Errorf("results: %v", got)
	}
}
