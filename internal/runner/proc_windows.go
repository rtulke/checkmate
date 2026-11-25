//go:build windows

package runner

import (
	"os/exec"
	"sync"

	"golang.org/x/sys/windows"
)

// isolate prepares the command so that a timeout ends the shell together
// with everything it started. Windows has no process groups to signal;
// killing the shell alone leaves its children running, and they keep the
// output pipes open. A job object collects the whole tree instead.
func isolate(cmd *exec.Cmd) *processTree {
	tree := &processTree{}
	cmd.Cancel = func() error {
		tree.terminate()
		if cmd.Process == nil {
			return nil
		}
		return cmd.Process.Kill()
	}
	return tree
}

type processTree struct {
	mu  sync.Mutex
	job windows.Handle
}

// started puts the running command into a job object. Processes it
// creates from now on belong to the job as well. Without a job (it cannot
// be created, or the process may not be assigned) a timeout still kills
// the shell itself.
func (t *processTree) started(cmd *exec.Cmd) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return
	}
	proc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		windows.CloseHandle(job)
		return
	}
	defer windows.CloseHandle(proc)
	if err := windows.AssignProcessToJobObject(job, proc); err != nil {
		windows.CloseHandle(job)
		return
	}
	t.mu.Lock()
	t.job = job
	t.mu.Unlock()
}

func (t *processTree) terminate() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.job != 0 {
		windows.TerminateJobObject(t.job, 1)
	}
}

// release closes the job. Processes that are still running keep running,
// as a background process does on POSIX systems.
func (t *processTree) release() {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.job != 0 {
		windows.CloseHandle(t.job)
		t.job = 0
	}
}
