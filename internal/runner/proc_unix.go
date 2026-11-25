//go:build !windows

package runner

import (
	"os/exec"
	"syscall"
)

// isolate runs the command in its own process group so that a timeout
// kills the whole pipeline, not just the shell.
func isolate(cmd *exec.Cmd) *processTree {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	return &processTree{}
}

// processTree needs no bookkeeping on POSIX systems: the process group
// is the tree.
type processTree struct{}

func (*processTree) started(*exec.Cmd) {}
func (*processTree) release()          {}
