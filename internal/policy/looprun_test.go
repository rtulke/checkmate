package policy

import (
	"reflect"
	"strings"
	"testing"
)

func TestLoopRunIsNotExecutedByExpand(t *testing.T) {
	p := load(t, writePolicy(t, map[string]string{"p.yml": `
name: t
checks:
  - id: HOME-{{ item }}
    name: "home of {{ item }}"
    loop_run: exit 1
    run: echo "$CHECKMATE_ITEM"
    expect: "!empty"
  - id: FIELD-{{ item.split(':')[1] }}
    loop_run: exit 1
    run: echo x
    expect: x
`}, "p.yml"))
	checks, errs := Expand(p, linuxFacts, nil)
	if len(errs) != 0 {
		t.Fatalf("errors: %v", errs)
	}
	var ids []string
	for _, c := range checks {
		ids = append(ids, c.ID)
		if c.LoopRun.IsZero() || c.Fixed != nil || c.Env != nil {
			t.Errorf("%s: LoopRun %v, Fixed %v, Env %v", c.ID, c.LoopRun, c.Fixed, c.Env)
		}
	}
	if want := []string{"HOME-{item}", "FIELD-{item}"}; !reflect.DeepEqual(ids, want) {
		t.Errorf("ids = %v, want %v", ids, want)
	}
	if checks[0].Name != "home of {item}" {
		t.Errorf("name = %q", checks[0].Name)
	}
}

func TestLoopRunDefinitionErrors(t *testing.T) {
	cases := map[string]struct{ check, want string }{
		"item in run": {`
  - id: A-{{ item }}
    loop_run: echo a
    run: ls {{ item }}
    expect: x`, "CHECKMATE_ITEM"},
		"item in only_if": {`
  - id: A-{{ item }}
    loop_run: echo a
    only_if: test -e {{ item }}
    run: echo x
    expect: x`, "only_if: {{ item }}"},
		"item in snippet argument": {`
  - id: A-{{ item }}
    loop_run: echo a
    run: { use: show, arg: "{{ item }}" }
    expect: x`, "CHECKMATE_ITEM"},
		"other error in run": {`
  - id: A-{{ item }}
    loop_run: echo a
    run: ls {{ undefined_variable }}
    expect: x`, "undefined_variable"},
		"with loop": {`
  - id: A-{{ item }}
    loop: [a]
    loop_run: echo a
    run: echo x
    expect: x`, "cannot be combined"},
		"empty": {`
  - id: A-{{ item }}
    loop_run: ""
    run: echo x
    expect: x`, "loop_run: command is empty"},
		"cmd shell": {`
  - id: A-{{ item }}
    loop_run: echo a
    shell: cmd
    run: echo x
    expect: x`, "shell: cmd"},
		"item in loop_run": {`
  - id: A-{{ item }}
    loop_run: echo {{ item }}
    run: echo x
    expect: x`, "loop_run:"},
	}
	for name, c := range cases {
		p := load(t, writePolicy(t, map[string]string{"p.yml": "name: t\nsnippets:\n  show: echo {{ arg }}\nchecks:" + c.check + "\n"}, "p.yml"))
		checks, errs := Expand(p, linuxFacts, nil)
		if len(errs) != 1 || len(checks) != 0 {
			t.Errorf("%s: %d checks, errors %v", name, len(checks), errs)
			continue
		}
		if !strings.Contains(errs[0].Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", name, errs[0], c.want)
		}
	}
}

func TestLoopRunItems(t *testing.T) {
	got, err := loopRunItems("  a b \r\n\nroot\na b\n\tz\n")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a b", "root", "z"}; !reflect.DeepEqual(got, want) {
		t.Errorf("items = %q, want %q", got, want)
	}
	if _, err := loopRunItems("a\x00b\n"); err == nil {
		t.Error("NUL byte accepted")
	}
	if _, err := loopRunItems(strings.Repeat("x\n", 3)); err != nil {
		t.Errorf("repeated lines: %v", err)
	}
	var many strings.Builder
	for i := 0; i <= maxLoopItems; i++ {
		many.WriteString(strings.Repeat("i", 1+i%7))
		many.WriteString(string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + string(rune('a'+i/676%26)) + "\n")
	}
	if _, err := loopRunItems(many.String()); err == nil {
		t.Error("too many items accepted")
	}
}
