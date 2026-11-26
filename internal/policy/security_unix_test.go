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

func TestDirectoriesAboveAPolicyAsRoot(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, "policies")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "p.yml")
	if err := os.WriteFile(path, []byte("checks: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	owner := info.Sys().(*syscall.Stat_t).Uid
	if owner == 0 {
		t.Skip("needs a non-root user")
	}
	oldEuid, oldOwner := geteuid, ownerOfSelf
	defer func() { geteuid, ownerOfSelf = oldEuid, oldOwner }()
	geteuid = func() int { return 0 }
	ownerOfSelf = func() (uint32, bool) { return owner, true }

	if err := checkFileSecurity(path); err != nil {
		t.Fatalf("a plain directory of the binary's owner: %v", err)
	}
	// Reached through a symlink, the real directories count.
	link := filepath.Join(base, "link.yml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if err := checkFileSecurity(link); err != nil {
		t.Errorf("symlink to a safe file: %v", err)
	}

	// Everyone may write to the directory: the file can be replaced.
	os.Chmod(dir, 0o777)
	if err := checkFileSecurity(path); err == nil || !strings.Contains(err.Error(), "world-writable directory") || !strings.HasSuffix(strings.SplitN(err.Error(), " (fix", 2)[0], "policies") {
		t.Errorf("world-writable directory accepted: %v", err)
	}
	if err := checkFileSecurity(link); err == nil {
		t.Error("world-writable directory accepted through a symlink")
	}
	// With the sticky bit only the owner of a file can replace it.
	os.Chmod(dir, 0o777|os.ModeSticky)
	if err := checkFileSecurity(path); err != nil {
		t.Errorf("sticky directory refused: %v", err)
	}
	// A directory further up counts as well.
	os.Chmod(dir, 0o755)
	os.Chmod(base, 0o777)
	if err := checkFileSecurity(path); err == nil || !strings.Contains(err.Error(), filepath.Base(base)+" (fix") {
		t.Errorf("world-writable directory further up accepted: %v", err)
	}
	os.Chmod(base, 0o755)
	// Group-writable is what Homebrew does.
	os.Chmod(dir, 0o775)
	if err := checkFileSecurity(path); err != nil {
		t.Errorf("group-writable directory refused: %v", err)
	}

	// The directories belong to a user who is not trusted with the file.
	ownerOfSelf = func() (uint32, bool) { return 0, true }
	os.Chown(path, 0, 0) // fails without root; then the file itself is refused first
	if err := checkFileSecurity(path); err == nil {
		t.Error("a file in the directory of another user was accepted")
	}
}
