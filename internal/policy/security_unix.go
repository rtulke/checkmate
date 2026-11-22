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
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || st.Uid == 0 {
		return nil
	}
	if self, ok := ownerOfSelf(); ok && self != 0 && st.Uid == self {
		return nil
	}
	return fmt.Errorf("%s: refusing to load a policy file as root that is owned neither by root nor by "+
		"the owner of the checkmate executable (fix with: chown root %s, or pass --allow-insecure-policy)", path, path)
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
