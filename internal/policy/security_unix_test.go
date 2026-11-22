//go:build !windows

package policy

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestFileSecurityAsRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yml")
	if err := os.WriteFile(path, []byte("checks: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	fileOwner := info.Sys().(*syscall.Stat_t).Uid

	oldEuid, oldOwner := geteuid, ownerOfSelf
	defer func() { geteuid, ownerOfSelf = oldEuid, oldOwner }()
	geteuid = func() int { return 0 }

	// The file belongs to the owner of the binary (Homebrew): accepted.
	ownerOfSelf = func() (uint32, bool) { return fileOwner, true }
	if fileOwner != 0 {
		if err := checkFileSecurity(path); err != nil {
			t.Errorf("file of the binary's owner refused: %v", err)
		}
	}

	// The binary belongs to root (package install), the file to a user: refused.
	ownerOfSelf = func() (uint32, bool) { return 0, true }
	if fileOwner != 0 {
		if err := checkFileSecurity(path); err == nil || !strings.Contains(err.Error(), "owned neither by root") {
			t.Errorf("file of another user accepted: %v", err)
		}
	}

	// The binary belongs to someone else: refused.
	ownerOfSelf = func() (uint32, bool) { return fileOwner + 1, true }
	if fileOwner != 0 {
		if err := checkFileSecurity(path); err == nil {
			t.Error("file of a third user accepted")
		}
	}

	// Group-writable files are refused even for the binary's owner.
	ownerOfSelf = func() (uint32, bool) { return fileOwner, true }
	os.Chmod(path, 0o664)
	if err := checkFileSecurity(path); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Errorf("group-writable file accepted: %v", err)
	}

	// Not root: no checks.
	geteuid = func() int { return 1000 }
	if err := checkFileSecurity(path); err != nil {
		t.Errorf("non-root run checked files: %v", err)
	}
}
