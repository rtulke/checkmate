//go:build !windows

package policy

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func expandRun(t *testing.T, checks string) ([]*Check, []*CheckError) {
	t.Helper()
	p := load(t, writePolicy(t, map[string]string{"p.yml": "name: t\nvars:\n  users: 'alice\\nbob smith\\nalice'\nsnippets:\n  two: printf 'x\\ny\\n'\nchecks:" + checks + "\n"}, "p.yml"))
	return ExpandRun(context.Background(), p, linuxFacts, nil, 4, nil)
}

func TestLoopRunCreatesOneCheckPerItem(t *testing.T) {
	checks, errs := expandRun(t, `
  - id: U-{{ item }}
    name: "user {{ item | upper }}"
    tags: ["{{ item }}"]
    loop_run: printf '{{ users }}\n'
    run: printf %s "$CHECKMATE_ITEM"
    expect: "{{ item }}"
  - id: S-{{ item }}
    loop_run: { use: two }
    run: echo x
    expect: x
  - id: V-{{ item }}
    loop_run:
      linux: echo on-linux
      darwin: echo on-darwin
    run: echo x
    expect: x`)
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	var ids []string
	for _, c := range checks {
		ids = append(ids, c.ID)
	}
	want := []string{"U-alice", "U-bob_smith", "S-x", "S-y", "V-on-linux"}
	if !reflect.DeepEqual(ids, want) {
		t.Fatalf("ids = %v, want %v", ids, want)
	}
	bob := checks[1]
	if bob.Name != "user BOB SMITH" || bob.Env[ItemEnv] != "bob smith" || !reflect.DeepEqual(bob.Tags, []string{"bob smith"}) {
		t.Errorf("check = name %q, env %v, tags %v", bob.Name, bob.Env, bob.Tags)
	}
	if cmd, _, _ := bob.Command(bob.Run, linuxFacts.PlatformKeys()); strings.Contains(cmd, "bob") {
		t.Errorf("item leaked into the command: %q", cmd)
	}
}

func TestLoopRunWithoutChecks(t *testing.T) {
	cases := map[string]struct{ check, status, message string }{
		"no items": {`
  - id: A-{{ item }}
    loop_run: "true"
    run: echo x
    expect: x`, FixedNA, "printed no items"},
		"command fails": {`
  - id: A-{{ item }}
    loop_run: echo a; echo broken >&2; exit 3
    run: echo x
    expect: x`, FixedError, "exit code 3: broken"},
		"command missing": {`
  - id: A-{{ item }}
    loop_run: no-such-command-here
    run: echo x
    expect: x`, FixedError, "exit code 127"},
		"timeout": {`
  - id: A-{{ item }}
    timeout: 100ms
    loop_run: sleep 5
    run: echo x
    expect: x`, FixedError, "timed out"},
		"when is false": {`
  - id: A-{{ item }}
    when: facts.os == 'plan9'
    loop_run: exit 9
    run: echo x
    expect: x`, FixedSkip, "when: facts.os == 'plan9' is false"},
		"when is broken": {`
  - id: A-{{ item }}
    when: nothing.defined == 1
    loop_run: exit 9
    run: echo x
    expect: x`, FixedError, "when:"},
		"other platform": {`
  - id: A-{{ item }}
    loop_run: { windows: echo a }
    run: echo x
    expect: x`, FixedNA, "no command for this platform"},
		"too much output": {`
  - id: A-{{ item }}
    loop_run: head -c 5000000 /dev/zero | tr '\0' 'a'
    run: echo x
    expect: x`, FixedError, "too large"},
	}
	for name, c := range cases {
		checks, errs := expandRun(t, c.check)
		if len(errs) != 0 || len(checks) != 1 {
			t.Errorf("%s: %d checks, errors %v", name, len(checks), errs)
			continue
		}
		f := checks[0].Fixed
		if checks[0].ID != "A-{item}" || f == nil || f.Status != c.status || !strings.Contains(f.Message, c.message) {
			t.Errorf("%s: id %s, outcome %+v, want %s %q", name, checks[0].ID, f, c.status, c.message)
		}
	}
}

func TestLoopRunItemConditionsAreLeftToTheCheck(t *testing.T) {
	checks, errs := expandRun(t, `
  - id: A-{{ item }}
    when: item != 'b'
    loop_run: printf 'a\nb\n'
    run: echo x
    expect: x`)
	if len(errs) != 0 || len(checks) != 2 {
		t.Fatalf("%d checks, errors %v", len(checks), errs)
	}
	for i, want := range []bool{true, false} {
		if ok, _, err := checks[i].Applies(); err != nil || ok != want {
			t.Errorf("%s applies = %v, %v; want %v", checks[i].ID, ok, err, want)
		}
	}
}

func TestLoopRunBrokenItemFailsTheCheck(t *testing.T) {
	checks, errs := expandRun(t, `
  - id: A-{{ item.split(':')[1] }}
    loop_run: printf 'a:1\nb\n'
    run: echo x
    expect: x
  - id: DUP-{{ item | first }}
    loop_run: printf 'ab\nac\n'
    run: echo x
    expect: x`)
	if len(errs) != 2 {
		t.Fatalf("errors: %v", errs)
	}
	if len(checks) != 1 || checks[0].ID != "DUP-a" {
		t.Errorf("checks: %v", checks)
	}
	if !strings.Contains(errs[1].Error(), "duplicate check id") {
		t.Errorf("error = %v", errs[1])
	}
}

func TestLoopRunWaitsForRegisteredChecks(t *testing.T) {
	checks, errs := expandRun(t, `
  - id: PROBE
    register: probe
    run: echo x
    expect: x
  - id: NOW-{{ item }}
    loop_run: echo a
    run: echo x
    expect: x
  - id: LATER-{{ item }}
    when: [probe.passed, item != 'b']
    loop_run: test "{{ users }}" && printf 'a\nb\n'
    run: echo x
    expect: x`)
	if len(errs) != 0 || len(checks) != 3 {
		t.Fatalf("%d checks, errors %v", len(checks), errs)
	}
	later := checks[2]
	if checks[1].ID != "NOW-a" || checks[1].Deferred() || later.ID != "LATER-{item}" || !later.Deferred() ||
		!reflect.DeepEqual(later.Needs, []string{"probe"}) {
		t.Fatalf("checks: %s deferred %v, %s deferred %v needs %v",
			checks[1].ID, checks[1].Deferred(), later.ID, later.Deferred(), later.Needs)
	}

	// Expanded twice: the result must not depend on an earlier expansion.
	for _, status := range []string{"pass", "pass"} {
		items, err := later.ExpandDeferred(context.Background(), linuxFacts.PlatformKeys(), map[string]Outcome{"probe": {Status: status}})
		if err != nil || len(items) != 2 || items[0].ID != "LATER-a" || items[1].ID != "LATER-b" {
			t.Fatalf("items %v, error %v", items, err)
		}
		for n, want := range []bool{true, false} {
			if ok, _, err := items[n].Applies(); err != nil || ok != want {
				t.Errorf("%s applies = %v, %v; want %v", items[n].ID, ok, err, want)
			}
		}
	}
	items, err := later.ExpandDeferred(context.Background(), linuxFacts.PlatformKeys(), map[string]Outcome{"probe": {Status: "fail"}})
	if err != nil || len(items) != 1 || items[0].Fixed == nil || items[0].Fixed.Status != FixedSkip {
		t.Fatalf("items %v, error %v", items, err)
	}
}
