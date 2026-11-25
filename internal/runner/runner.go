// Package runner executes check commands through a shell.
package runner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// maxOutput caps the captured stdout/stderr per command.
const maxOutput = 4 << 20

// Shells understood by checkmate.
var knownShells = map[string]bool{"bash": true, "sh": true, "zsh": true, "pwsh": true, "powershell": true, "cmd": true}

// ValidShell reports whether name is a supported shell ("" means default).
func ValidShell(name string) bool {
	return name == "" || knownShells[name]
}

// Request describes a command to run.
type Request struct {
	Command string
	Shell   string            // "" selects the platform default
	Dir     string            // working directory
	Env     map[string]string // extra environment variables
	Timeout time.Duration
}

// Result is the outcome of a command.
type Result struct {
	RC       int
	Stdout   string
	Stderr   string
	Duration time.Duration
	Shell    string
	// Truncated reports that stdout exceeded the output cap and was cut.
	Truncated bool
}

// ErrTimeout is returned when a command exceeds its timeout.
var ErrTimeout = errors.New("command timed out")

// Run executes the request. An error is returned only if the command could
// not be run to completion (shell missing, timeout); a non-zero exit code
// is reported in the result.
func Run(ctx context.Context, req Request) (Result, error) {
	shell := req.Shell
	if shell == "" {
		shell = DefaultShell()
	}
	argv, err := shellArgv(shell, req.Command)
	if err != nil {
		return Result{Shell: shell}, err
	}

	if req.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, req.Timeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = req.Dir
	cmd.Env = buildEnv(req.Env)
	cmd.Stdin = nil
	stdout := &limitedBuffer{limit: maxOutput}
	stderr := &limitedBuffer{limit: maxOutput}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	setProcessGroup(cmd)
	cmd.WaitDelay = 2 * time.Second

	start := time.Now()
	runErr := cmd.Run()
	res := Result{
		Stdout:   normalizeNewlines(stdout.String()),
		Stderr:   normalizeNewlines(stderr.String()),
		Duration: time.Since(start),
		Shell:    shell,
	}
	res.Truncated = stdout.truncated

	if ctx.Err() == context.DeadlineExceeded {
		return res, fmt.Errorf("%w after %s", ErrTimeout, req.Timeout)
	}
	// The command succeeded, but a process it left behind kept stdout or
	// stderr open beyond WaitDelay. The command itself has completed.
	if errors.Is(runErr, exec.ErrWaitDelay) {
		return res, nil
	}
	if runErr != nil {
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			res.RC = exitErr.ExitCode()
			if res.RC < 0 {
				return res, fmt.Errorf("command terminated by signal: %v", runErr)
			}
			return res, nil
		}
		return res, fmt.Errorf("cannot run shell %q: %w", shell, runErr)
	}
	return res, nil
}

// DefaultShell returns the shell used when a check does not specify one.
func DefaultShell() string {
	if runtime.GOOS == "windows" {
		if _, err := exec.LookPath("pwsh"); err == nil {
			return "pwsh"
		}
		return "powershell"
	}
	if _, err := exec.LookPath("bash"); err == nil {
		return "bash"
	}
	return "sh"
}

// IsPOSIXShell reports whether exit codes 126/127 mean "not executable" and
// "not found" for the given shell.
func IsPOSIXShell(shell string) bool {
	if shell == "" {
		shell = DefaultShell()
	}
	switch shell {
	case "bash", "sh", "zsh":
		return true
	}
	return false
}

func shellArgv(shell, command string) ([]string, error) {
	switch shell {
	case "bash":
		return []string{"bash", "--noprofile", "--norc", "-o", "pipefail", "-c", command}, nil
	case "zsh":
		return []string{"zsh", "-f", "-o", "pipefail", "-c", command}, nil
	case "sh":
		return []string{"sh", "-c", command}, nil
	case "pwsh", "powershell":
		// The command runs in a script block, so that a return in it still
		// reaches the exit handling. A script that completes exits 0, even if
		// a silenced error left $? false; terminating errors exit 1 and the
		// exit code of a failed native command is passed on.
		script := "$ErrorActionPreference = 'Stop'\n& {\n" + command +
			"\n}\nif ($LASTEXITCODE) { exit $LASTEXITCODE }\nexit 0"
		return []string{shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script}, nil
	case "cmd":
		return []string{"cmd", "/D", "/S", "/C", command}, nil
	}
	return nil, fmt.Errorf("unsupported shell %q", shell)
}

// buildEnv inherits the environment, forces a stable locale on POSIX
// systems and applies extra variables.
func buildEnv(extra map[string]string) []string {
	env := map[string]string{}
	var order []string
	set := func(k, v string) {
		if _, ok := env[k]; !ok {
			order = append(order, k)
		}
		env[k] = v
	}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			set(k, v)
		}
	}
	if runtime.GOOS != "windows" {
		set("LC_ALL", "C")
		set("LANG", "C")
	}
	for k, v := range extra {
		set(k, v)
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		out = append(out, k+"="+env[k])
	}
	return out
}

func normalizeNewlines(s string) string {
	return strings.ReplaceAll(s, "\r\n", "\n")
}

// limitedBuffer keeps at most limit bytes and silently drops the rest.
type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	remaining := b.limit - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if len(p) > remaining {
		b.buf.Write(p[:remaining])
		b.truncated = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *limitedBuffer) String() string {
	if b.truncated {
		return b.buf.String() + "\n[output truncated]"
	}
	return b.buf.String()
}
