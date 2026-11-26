//go:build windows

package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func icacls(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("icacls", args...).CombinedOutput(); err != nil {
		t.Fatalf("icacls %v: %v\n%s", args, err, out)
	}
}

func TestFileSecurityElevated(t *testing.T) {
	old := elevated
	defer func() { elevated = old }()

	dir := filepath.Join(t.TempDir(), "policies")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "p.yml")
	if err := os.WriteFile(path, []byte("checks: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Start from a list that names administrators and SYSTEM only.
	icacls(t, dir, "/inheritance:r", "/grant", "*S-1-5-32-544:(OI)(CI)F", "/grant", "*S-1-5-18:(OI)(CI)F")
	icacls(t, path, "/reset")

	elevated = func() bool { return true }
	if err := checkFileSecurity(path); err != nil {
		t.Fatalf("a file only administrators can write: %v", err)
	}

	// Users may write to the file.
	icacls(t, path, "/grant", "*S-1-5-32-545:M")
	if err := checkFileSecurity(path); err == nil || !strings.Contains(err.Error(), "Users may write to") {
		t.Errorf("a file users can modify was accepted: %v", err)
	}
	icacls(t, path, "/remove", "*S-1-5-32-545")
	// Reading is fine.
	icacls(t, path, "/grant", "*S-1-5-32-545:R")
	if err := checkFileSecurity(path); err != nil {
		t.Errorf("a file users can read was refused: %v", err)
	}

	// Authenticated users may write to the directory: the file can be replaced.
	icacls(t, dir, "/grant", "*S-1-5-11:(OI)(CI)M")
	icacls(t, path, "/inheritance:r", "/grant", "*S-1-5-32-544:F")
	if err := checkFileSecurity(path); err == nil || !strings.Contains(err.Error(), "Authenticated Users may write to") {
		t.Errorf("a directory users can write to was accepted: %v", err)
	}

	// Without administrator rights nothing is checked.
	elevated = func() bool { return false }
	if err := checkFileSecurity(path); err != nil {
		t.Errorf("a run without administrator rights checked files: %v", err)
	}
}
