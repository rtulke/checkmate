//go:build windows

package runner

import "os/exec"

// setProcessGroup is a no-op on Windows; exec.CommandContext kills the
// process on cancellation.
func setProcessGroup(_ *exec.Cmd) {}
