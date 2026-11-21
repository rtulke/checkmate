//go:build !windows

package policy

import (
	"fmt"
	"os"
	"syscall"
)

// checkFileSecurity refuses policy files that a non-root user could have
// modified when checkmate runs as root: policies are code executed as root.
func checkFileSecurity(path string) error {
	if os.Geteuid() != 0 {
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
	if st, ok := info.Sys().(*syscall.Stat_t); ok && st.Uid != 0 {
		return fmt.Errorf("%s: refusing to load a policy file not owned by root as root "+
			"(fix with: chown root %s, or pass --allow-insecure-policy)", path, path)
	}
	return nil
}
