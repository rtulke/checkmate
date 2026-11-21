package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFiles(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, data := range files {
		path := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func reasons(ws []Waiver) []string {
	var out []string
	for _, w := range ws {
		out = append(out, w.Reason)
	}
	return out
}

func TestWaiverFileIncludes(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"host.yml":   "include: [common.yml, roles/web.yml]\nwaivers:\n  - id: X\n    reason: host\n",
		"common.yml": "waivers:\n  - id: X\n    reason: common\n  - id: Y\n    reason: common-y\n",
		// paths are relative to the including file
		"roles/web.yml":  "include: [base.yml]\nwaivers:\n  - id: Z\n    reason: web\n",
		"roles/base.yml": "waivers:\n  - id: Z\n    reason: base\n",
	})
	ws, err := LoadWaivers(filepath.Join(dir, "host.yml"), LoadOptions{AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(reasons(ws), ",")
	if want := "host,common,common-y,web,base"; got != want {
		t.Errorf("order %q, want %q (a file before the files it includes)", got, want)
	}
}

func TestWaiverIncludeCycle(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"a.yml": "include: [b.yml]\n",
		"b.yml": "include: [a.yml]\n",
	})
	_, err := LoadWaivers(filepath.Join(dir, "a.yml"), LoadOptions{AllowInsecure: true})
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Errorf("expected an include cycle error, got %v", err)
	}
}

func TestWaiverFileOnlyIncludes(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"all.yml": "include: [a.yml]\n",
		"a.yml":   "waivers:\n  - id: X\n    reason: a\n",
	})
	ws, err := LoadWaivers(filepath.Join(dir, "all.yml"), LoadOptions{AllowInsecure: true})
	if err != nil || len(ws) != 1 {
		t.Fatalf("got %v, %v", ws, err)
	}
}

func TestPolicyWaiverPrecedence(t *testing.T) {
	dir := writeFiles(t, map[string]string{
		"site.yml":  "name: site\ninclude: [a.yml, b.yml]\nwaivers:\n  - id: X\n    reason: site\n",
		"a.yml":     "waivers:\n  - id: X\n    reason: a\n",
		"b.yml":     "include: [sub/c.yml]\nwaivers:\n  - id: X\n    reason: b\n",
		"sub/c.yml": "waivers:\n  - id: X\n    reason: c\n",
	})
	p, err := Load(filepath.Join(dir, "site.yml"), LoadOptions{AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Join(reasons(p.Waivers), ",")
	if want := "site,a,b,c"; got != want {
		t.Errorf("order %q, want %q", got, want)
	}
}
