//go:build !windows

package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Replaced in tests.
var (
	geteuid     = os.Geteuid
	ownerOfSelf = executableOwner
)

// checkFileSecurity refuses policy and waiver files that a non-root user
// could have modified when checkmate runs as root: policies are code
// executed as root.
//
// A file must not be group- or world-writable and must be owned by root or
// by the owner of the checkmate executable. The latter covers Homebrew,
// where the binary and the policies it installs belong to the admin user:
// whoever owns the binary can change what runs as root anyway, so trusting
// that user's files adds no risk.
func checkFileSecurity(path string) error {
	if geteuid() != 0 {
		return nil
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: refusing to load a group- or world-writable policy file as root "+
			"(fix with: chmod go-w %s, or pass --allow-insecure-policy)", path, path)
	}
	if st, ok := info.Sys().(*syscall.Stat_t); ok && !trustedOwner(st.Uid) {
		return fmt.Errorf("%s: refusing to load a policy file as root that is owned neither by root nor by "+
			"the owner of the checkmate executable (fix with: chown root %s, or pass --allow-insecure-policy)", path, path)
	}
	return checkDirectories(path)
}

func trustedOwner(uid uint32) bool {
	if uid == 0 {
		return true
	}
	self, ok := ownerOfSelf()
	return ok && self != 0 && uid == self
}

// checkDirectories looks at the directories above a policy file. Whoever
// can write to one of them can replace the file, however well the file
// itself is protected. A directory is refused if it belongs to a user who
// is not trusted with the file either, or if everyone can write to it and
// it does not have the sticky bit (as /tmp has), which lets only the owner
// of a file rename or remove it.
//
// Group-writable directories are accepted: Homebrew keeps its whole tree,
// the checkmate binary included, writable for the admin group.
func checkDirectories(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		abs = resolved
	}
	for dir := filepath.Dir(abs); ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && !trustedOwner(st.Uid) {
			return fmt.Errorf("%s: refusing to load a policy file as root from the directory %s, which belongs to "+
				"another user who could replace the file (move the policy, or pass --allow-insecure-policy)", path, dir)
		}
		if info.Mode().Perm()&0o002 != 0 && info.Mode()&os.ModeSticky == 0 {
			return fmt.Errorf("%s: refusing to load a policy file as root from the world-writable directory %s "+
				"(fix with: chmod o-w %s, or pass --allow-insecure-policy)", path, dir, dir)
		}
		if dir == filepath.Dir(dir) {
			return nil
		}
	}
}

// executableOwner returns the owner of the running checkmate binary, with
// symlinks resolved (Homebrew links bin/checkmate into the Cellar).
func executableOwner() (uint32, bool) {
	exe, err := os.Executable()
	if err != nil {
		return 0, false
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	info, err := os.Stat(exe)
	if err != nil {
		return 0, false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}
