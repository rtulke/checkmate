//go:build !windows

package engine

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
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

const registerLoopPolicy = `
name: register and loop_run
checks:
  - id: PRESENT
    register: present
    run: command -v sh
    expect: true
  - id: ABSENT
    register: absent
    severity: info
    run: exit 3
    expect: true
  - id: TAKEN
    run: echo x
    expect: x
  - id: "VHOST-{{ item }}"
    tags: [vhost]
    when: [present.passed, item != 'c']
    loop_run: printf 'a\nb\nc\n'
    run: printf %s "$CHECKMATE_ITEM"
    expect: "{{ item }}"
  - id: "NONE-{{ item }}"
    when: absent.passed
    loop_run: exit 7
    run: echo x
    expect: x
  - id: "EMPTY-{{ item }}"
    when: absent.failed
    loop_run: "true"
    run: echo x
    expect: x
  - id: "{{ item }}"
    when: present.passed
    loop_run: printf 'TAKEN\nFREE\n'
    run: echo x
    expect: x
  - id: LAST
    run: echo x
    expect: x
`

func TestRegisterSteersLoopRun(t *testing.T) {
	file := filepath.Join(t.TempDir(), "p.yml")
	if err := os.WriteFile(file, []byte(registerLoopPolicy), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(file, policy.LoadOptions{AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	run := func(opts Options) []string {
		opts.Facts = facts.Gather()
		var got []string
		for _, res := range Run(context.Background(), p, opts).Results {
			got = append(got, res.ID+" "+string(res.Status))
		}
		return got
	}

	all := []string{"PRESENT PASS", "ABSENT WARN", "TAKEN PASS", "VHOST-a PASS", "VHOST-b PASS", "VHOST-c SKIP",
		"NONE-{item} SKIP", "EMPTY-{item} N/A", "TAKEN ERROR", "FREE PASS", "LAST PASS"}
	// One job: neither the waiting check nor its items may block the run.
	for _, jobs := range []int{1, 2, 16} {
		if got := run(Options{Jobs: jobs}); !reflect.DeepEqual(got, all) {
			t.Errorf("jobs %d:\n got %v\nwant %v", jobs, got, all)
		}
	}

	filters := map[string]struct {
		filter Filter
		want   []string
	}{
		"one item":  {Filter{IDs: ParseIDs("VHOST-b")}, []string{"PRESENT PASS", "VHOST-b PASS"}},
		"by tag":    {Filter{Tags: ParseTagExpr("vhost")}, []string{"PRESENT PASS", "VHOST-a PASS", "VHOST-b PASS", "VHOST-c SKIP"}},
		"unrelated": {Filter{IDs: ParseIDs("LAST")}, []string{"PRESENT PASS", "LAST PASS"}},
		// The check with the id "{{ item }}" could create any id, so it is
		// expanded, and it needs PRESENT for that.
		"other check": {Filter{IDs: ParseIDs("ABSENT")}, []string{"PRESENT PASS", "ABSENT WARN"}},
	}
	for name, c := range filters {
		if got := run(Options{Jobs: 4, Filter: c.filter}); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s:\n got %v\nwant %v", name, got, c.want)
		}
	}
}
