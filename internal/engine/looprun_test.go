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

func TestLoopRun(t *testing.T) {
	dir := t.TempDir()
	// "$(touch pwned)" would create a file if an item ever became part of
	// a command line.
	for name, mode := range map[string]os.FileMode{"private": 0o700, "open dir": 0o755, "$(touch pwned)": 0o700} {
		path := filepath.Join(dir, "homes", name)
		if err := os.Mkdir(filepath.Dir(path), 0o755); err != nil && !os.IsExist(err) {
			t.Fatal(err)
		}
		if err := os.Mkdir(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	file := filepath.Join(dir, "p.yml")
	content := `
name: loop_run
env:
  HOMES: ` + filepath.Join(dir, "homes") + `
checks:
  - id: HOME-{{ item }}
    name: "{{ item }} is private"
    loop_run: ls "$HOMES"
    run: cd "$HOMES" && ls -ld "$CHECKMATE_ITEM" | cut -c1-10
    expect: "drwx------"
  - id: NONE-{{ item }}
    loop_run: ls "$HOMES/private"
    run: echo x
    expect: x
  - id: FAILED-{{ item }}
    severity: info
    loop_run: ls "$HOMES/missing"
    run: echo x
    expect: x
  - id: OTHER-{{ item }}
    when: facts.os == 'plan9'
    loop_run: exit 1
    run: echo x
    expect: x
`
	if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(file, policy.LoadOptions{AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	r := Run(context.Background(), p, Options{Facts: facts.Gather(), Jobs: 4})

	want := map[string]Status{
		"HOME-private":        StatusPass,
		"HOME-open_dir":       StatusFail,
		"HOME-$(touch_pwned)": StatusPass,
		"NONE-{item}":         StatusNA,
		"FAILED-{item}":       StatusError,
		"OTHER-{item}":        StatusSkip,
	}
	got := map[string]Result{}
	for _, res := range r.Results {
		got[res.ID] = res
	}
	for id, status := range want {
		if res, ok := got[id]; !ok || res.Status != status {
			t.Errorf("%s: status %q, want %s (message: %s)", id, res.Status, status, res.Message)
		}
	}
	if len(r.Results) != len(want) {
		t.Errorf("%d results, want %d: %v", len(r.Results), len(want), got)
	}
	if got["FAILED-{item}"].Command == "" {
		t.Error("the failed loop_run command is not reported")
	}
	if _, err := os.Stat(filepath.Join(dir, "homes", "pwned")); err == nil {
		t.Error("an item was executed as a command")
	}
}
