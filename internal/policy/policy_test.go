package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rtulke/checkmate/internal/facts"
)

// writePolicy writes files into a temporary directory and returns the
// path of the first one.
func writePolicy(t *testing.T, files map[string]string, main string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return filepath.Join(dir, main)
}

func load(t *testing.T, path string) *Policy {
	t.Helper()
	p, err := Load(path, LoadOptions{AllowInsecure: true})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	return p
}

var linuxFacts = facts.Facts{OS: "linux", Distro: "rocky", DistroLike: []string{"rhel", "centos", "fedora"}}

func TestExpandLoopsVarsAndSnippets(t *testing.T) {
	path := writePolicy(t, map[string]string{
		"main.yml": `
vars_files: [vars.yml]
vars:
  pkgs: [openssh, sudo]
snippets:
  installed:
    rhel: rpm -q {{ arg }}
    debian: dpkg -s {{ arg }}
checks:
  - id: "PKG-{{ item }}"
    loop: "{{ pkgs }}"
    run: { use: installed, arg: "{{ item }}" }
    expect: true
  - id: "SYS-{{ item.key }}"
    loop: "{{ sysctl }}"
    run: sysctl -n {{ item.key }}
    expect: "== {{ item.value }}"
`,
		"vars.yml": "sysctl:\n  net.ipv4.ip_forward: 0\n  kernel.randomize_va_space: 2\n",
	}, "main.yml")

	p := load(t, path)
	checks, errs := Expand(p, linuxFacts, nil)
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %v", errs)
	}
	var ids []string
	for _, c := range checks {
		ids = append(ids, c.ID)
	}
	want := "PKG-openssh PKG-sudo SYS-kernel.randomize_va_space SYS-net.ipv4.ip_forward"
	if got := strings.Join(ids, " "); got != want {
		t.Errorf("ids = %s, want %s", got, want)
	}

	cmd, ok, err := checks[0].Command(checks[0].Run, linuxFacts.PlatformKeys())
	if err != nil || !ok || cmd != "rpm -q openssh" {
		t.Errorf("rocky should use the rhel variant, got %q ok=%v err=%v", cmd, ok, err)
	}
	ubuntu := facts.Facts{OS: "linux", Distro: "ubuntu", DistroLike: []string{"debian"}}
	cmd, _, _ = checks[0].Command(checks[0].Run, ubuntu.PlatformKeys())
	if cmd != "dpkg -s openssh" {
		t.Errorf("ubuntu should use the debian variant, got %q", cmd)
	}
	macos := facts.Facts{OS: "darwin", Distro: "macos"}
	if _, ok, _ := checks[0].Command(checks[0].Run, macos.PlatformKeys()); ok {
		t.Error("macos has no variant and must not be applicable")
	}
}

func TestExtraVarsOverridePolicyVars(t *testing.T) {
	path := writePolicy(t, map[string]string{"p.yml": `
vars: {limit: 10}
checks:
  - id: X
    run: echo 1
    expect: "<= {{ limit }}"
`}, "p.yml")
	checks, errs := Expand(load(t, path), linuxFacts, map[string]any{"limit": 0})
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if got := checks[0].Expect.String(); got != `stdout <= "0"` {
		t.Errorf("expect = %s", got)
	}
}

func TestExpandErrors(t *testing.T) {
	cases := map[string]string{
		"missing id":      "checks:\n  - run: echo\n    expect: true\n",
		"missing run":     "checks:\n  - id: A\n    expect: true\n",
		"missing expect":  "checks:\n  - id: A\n    run: echo\n",
		"unknown key":     "checks:\n  - id: A\n    run: echo\n    expect: true\n    comand: x\n",
		"unknown snippet": "checks:\n  - id: A\n    run: {use: nope}\n    expect: true\n",
		"bad severity":    "checks:\n  - id: A\n    run: echo\n    expect: true\n    severity: urgent\n",
		"bad timeout":     "checks:\n  - id: A\n    run: echo\n    expect: true\n    timeout: soon\n",
		"bad shell":       "checks:\n  - id: A\n    run: echo\n    expect: true\n    shell: fish\n",
		"duplicate id":    "checks:\n  - id: A\n    run: echo\n    expect: true\n  - id: A\n    run: echo\n    expect: true\n",
		"undefined var":   "checks:\n  - id: A\n    run: echo {{ nope }}\n    expect: true\n",
		"bad expect":      "checks:\n  - id: A\n    run: echo\n    expect: \"~ (\"\n",
		"undefined loop":  "checks:\n  - id: A\n    loop: \"{{ nope }}\"\n    run: echo\n    expect: true\n",
		"id with spaces":  "checks:\n  - id: A B\n    run: echo\n    expect: true\n",
		"unknown as":      "checks:\n  - id: A\n    run: echo\n    expect: true\n    as: float\n",
	}
	for name, src := range cases {
		path := writePolicy(t, map[string]string{"p.yml": src}, "p.yml")
		_, errs := Expand(load(t, path), linuxFacts, nil)
		if len(errs) == 0 {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	cases := map[string]map[string]string{
		"unknown top-level key": {"p.yml": "chekcs: []\n"},
		"include cycle":         {"p.yml": "include: [q.yml]\n", "q.yml": "include: [p.yml]\n"},
		"missing include":       {"p.yml": "include: [missing.yml]\n"},
		"duplicate snippet":     {"p.yml": "include: [q.yml]\nsnippets: {s: echo}\n", "q.yml": "snippets: {s: echo}\n"},
		"bad default timeout":   {"p.yml": "defaults: {timeout: x}\n"},
	}
	for name, files := range cases {
		path := writePolicy(t, files, "p.yml")
		if _, err := Load(path, LoadOptions{AllowInsecure: true}); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestShellCodeSurvivesTemplating(t *testing.T) {
	path := writePolicy(t, map[string]string{"p.yml": `
vars: {x: 1}
checks:
  - id: A
    run: |
      arr=(a b); echo "${#arr[@]} {{ x }}" | awk '{print $1}'
    expect: true
`}, "p.yml")
	checks, errs := Expand(load(t, path), linuxFacts, nil)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	want := "arr=(a b); echo \"${#arr[@]} 1\" | awk '{print $1}'\n"
	if checks[0].Run.Command != want {
		t.Errorf("command = %q, want %q", checks[0].Run.Command, want)
	}
}

func TestDefaultsWhenAppliesToEveryCheck(t *testing.T) {
	path := writePolicy(t, map[string]string{"p.yml": `
defaults:
  when: facts.os == "linux"
checks:
  - id: A
    run: echo
    expect: true
  - id: B
    when: facts.is_root
    run: echo
    expect: true
`}, "p.yml")
	checks, errs := Expand(load(t, path), linuxFacts, nil)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	if len(checks[0].When) != 1 || len(checks[1].When) != 2 {
		t.Fatalf("when = %v / %v", checks[0].When, checks[1].When)
	}
	ok, _, err := checks[1].Applies()
	if err != nil || ok {
		t.Errorf("B must not apply to a non-root linux host (ok=%v err=%v)", ok, err)
	}
	macChecks, _ := Expand(load(t, path), facts.Facts{OS: "darwin"}, nil)
	if ok, _, _ := macChecks[0].Applies(); ok {
		t.Error("defaults.when must exclude macOS")
	}
}

func TestLoopExpression(t *testing.T) {
	path := writePolicy(t, map[string]string{"p.yml": `
vars:
  files:
    - { path: /a, contains: x }
    - { path: /b }
checks:
  - id: "C-{{ item.path | replace('/', '') }}"
    loop: "{{ files | selectattr('contains', 'defined') | list }}"
    run: grep {{ item.contains }} {{ item.path }}
    expect: true
  - id: "R-{{ item }}"
    loop: "{{ range(1, 4) | list }}"
    run: echo {{ item }}
    expect: true
`}, "p.yml")
	checks, errs := Expand(load(t, path), linuxFacts, nil)
	if len(errs) > 0 {
		t.Fatal(errs)
	}
	var ids []string
	for _, c := range checks {
		ids = append(ids, c.ID)
	}
	if got := strings.Join(ids, " "); got != "C-a R-1 R-2 R-3" {
		t.Errorf("ids = %s", got)
	}
}
