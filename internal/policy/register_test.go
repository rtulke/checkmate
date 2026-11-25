package policy

import (
	"reflect"
	"strings"
	"testing"
)

func TestRegisterLinksLaterChecks(t *testing.T) {
	p := load(t, writePolicy(t, map[string]string{"p.yml": `
name: t
vars:
  installed: yes
checks:
  - id: NGINX
    register: nginx
    run: command -v nginx
    expect: true
  - id: "SVC-{{ item }}"
    register: "svc_{{ item }}"
    loop: [a, b]
    run: echo x
    expect: x
  - id: TLS
    when: [nginx.passed, "svc_a.status == 'pass'"]
    run: echo x
    expect: x
  - id: OTHER
    when: facts.os == "linux" and vars.installed and "nginx.conf" != my_nginx
    run: echo x
    expect: x
`}, "p.yml"))
	checks, errs := Expand(p, linuxFacts, map[string]any{"my_nginx": "x"})
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	needs := map[string][]string{}
	for _, c := range checks {
		needs[c.ID] = c.Needs
	}
	want := map[string][]string{"NGINX": nil, "SVC-a": nil, "SVC-b": nil, "TLS": {"nginx", "svc_a"}, "OTHER": nil}
	if !reflect.DeepEqual(needs, want) {
		t.Errorf("needs = %v, want %v", needs, want)
	}

	one := 1
	tls := checks[3].WithOutcomes(map[string]Outcome{
		"nginx": {Status: "pass", RC: new(int)},
		"svc_a": {Status: "fail", RC: &one},
	})
	if ok, cond, err := tls.Applies(); err != nil || ok || cond != "svc_a.status == 'pass'" {
		t.Errorf("Applies() = %v, %q, %v", ok, cond, err)
	}
	// The original check is untouched: the outcome belongs to one run.
	if _, _, err := checks[3].Applies(); err == nil {
		t.Error("the shared check sees a registered outcome")
	}
}

func TestOutcomeValues(t *testing.T) {
	two := 2
	got := Outcome{Status: "fail", RC: &two}.Values()
	want := map[string]any{"status": "fail", "passed": false, "failed": true, "ran": true, "rc": 2}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("values = %v, want %v", got, want)
	}
	got = Outcome{Status: "skip"}.Values()
	want = map[string]any{"status": "skip", "passed": false, "failed": false, "ran": false, "rc": -1}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("values = %v, want %v", got, want)
	}
}

func TestRegisterErrors(t *testing.T) {
	cases := map[string]struct{ checks, want string }{
		"bad name": {`
  - {id: A, register: "my-name", run: echo, expect: true}`, "not a valid name"},
		"reserved": {`
  - {id: A, register: facts, run: echo, expect: true}`, "reserved name"},
		"variable": {`
  - {id: A, register: port, run: echo, expect: true}`, "already a variable"},
		"twice": {`
  - {id: A, register: x, run: echo, expect: true}
  - {id: B, register: x, run: echo, expect: true}`, "already registered by A"},
		"itself": {`
  - {id: A, register: x, when: x.passed, run: echo, expect: true}`, "registers itself"},
		"later": {`
  - {id: A, when: x.passed, run: echo, expect: true}
  - {id: B, register: x, run: echo, expect: true}`, "defined later"},
		"loop_run registers": {`
  - {id: "A-{{ item }}", register: x, loop_run: echo a, run: echo, expect: true}`, "cannot be combined with loop_run"},
		"loop_run refers": {`
  - {id: A, register: x, run: echo, expect: true}
  - {id: "B-{{ item }}", when: x.passed, loop_run: echo a, run: echo, expect: true}`, "loop_run cannot refer"},
	}
	for name, c := range cases {
		p := load(t, writePolicy(t, map[string]string{"p.yml": "name: t\nvars:\n  port: 22\nchecks:" + c.checks + "\n"}, "p.yml"))
		_, errs := Expand(p, linuxFacts, nil)
		if len(errs) != 1 || !strings.Contains(errs[0].Error(), c.want) {
			t.Errorf("%s: errors %v, want one mentioning %q", name, errs, c.want)
		}
	}
}
