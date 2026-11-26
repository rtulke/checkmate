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
	// Target runs the command on another host over SSH; nil runs it here.
	// Dir does not apply then: the command starts in the home directory.
	Target *Target
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

// ErrUnreachable is returned when the host of a remote command does not
// answer.
var ErrUnreachable = errors.New("host is not reachable over SSH")

// Run executes the request. An error is returned only if the command could
// not be run to completion (shell missing, timeout); a non-zero exit code
// is reported in the result.
func Run(ctx context.Context, req Request) (Result, error) {
	shell := req.Shell
	remote := req.Target != nil
	var argv []string
	var stdin string
	var err error
	localTimeout := req.Timeout
	if remote {
		if shell == "" || req.Target.Device != "" {
			shell = req.Target.defaultShell()
		}
		argv, stdin, err = req.Target.argv(shell, req.Command, req.Env, req.Timeout)
		if req.Timeout > 0 && req.Target.HasTimeout {
			// The host ends the command and its children itself; ending
			// ssh first would leave them running.
			localTimeout += 5 * time.Second
		}
	} else {
		if shell == "" {
			shell = DefaultShell()
		}
		argv, err = shellArgv(shell, req.Command)
	}
	if err != nil {
		return Result{Shell: shell}, err
	}

	if localTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, localTimeout)
		defer cancel()
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	if remote {
		// ssh needs the environment of the user (agent, configuration);
		// the variables of the check are part of the remote command.
		cmd.Env = os.Environ()
	} else {
		cmd.Dir = req.Dir
		cmd.Env = buildEnv(shell, req.Env)
	}
	cmd.Stdin = nil
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	stdout := &limitedBuffer{limit: maxOutput}
	stderr := &limitedBuffer{limit: maxOutput}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	tree := isolate(cmd)
	cmd.WaitDelay = 2 * time.Second

	start := time.Now()
	runErr := cmd.Start()
	if runErr == nil {
		tree.started(cmd)
		runErr = cmd.Wait()
		tree.release()
	}
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
	if remote {
		rc := 0
		var exitErr *exec.ExitError
		if errors.As(runErr, &exitErr) {
			rc = exitErr.ExitCode()
		}
		// timeout(1) reports 124 when it ended the command, 137 when it
		// had to kill it.
		if (rc == 124 || rc == 137) && req.Timeout > 0 && req.Target.HasTimeout && res.Duration >= req.Timeout {
			return res, fmt.Errorf("%w after %s", ErrTimeout, req.Timeout)
		}
		if rc == 255 && (req.Target.Device == "" || sshFailed(res.Stderr)) && !req.Target.reachable(ctx) {
			return res, fmt.Errorf("%w: %s%s", ErrUnreachable, req.Target.Host, firstLineSuffix(res.Stderr))
		}
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
		//
		// Output is UTF-8 whatever the code page of the console is, also
		// for the programs the script starts. Without a console the setting
		// cannot be changed and stays as it is.
		script := "try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; " +
			"$OutputEncoding = [Console]::OutputEncoding } catch {}\n" +
			"$ErrorActionPreference = 'Stop'\n& {\n" + command +
			"\n}\nif ($LASTEXITCODE) { exit $LASTEXITCODE }\nexit 0"
		return []string{shell, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script}, nil
	case "cmd":
		return []string{"cmd", "/D", "/S", "/C", command}, nil
	}
	return nil, fmt.Errorf("unsupported shell %q", shell)
}

// buildEnv inherits the environment, forces a stable locale on POSIX
// systems and applies extra variables.
func buildEnv(shell string, extra map[string]string) []string {
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
	if shell == "powershell" {
		for _, k := range order {
			if strings.EqualFold(k, "PSModulePath") {
				env[k] = windowsPowerShellModulePath(env[k])
			}
		}
	}
	out := make([]string, 0, len(order))
	for _, k := range order {
		out = append(out, k+"="+env[k])
	}
	return out
}

// windowsPowerShellModulePath removes the module directories of PowerShell
// 7 from a PSModulePath. When checkmate is started from PowerShell 7, the
// variable lists them first, and Windows PowerShell 5.1 then tries to load
// modules it cannot use: built-in commands such as Get-Acl fail with "the
// module could not be loaded".
func windowsPowerShellModulePath(value string) string {
	var kept []string
	for _, dir := range strings.Split(value, ";") {
		foreign := false
		for _, part := range strings.FieldsFunc(dir, func(r rune) bool { return r == '\\' || r == '/' }) {
			if strings.EqualFold(part, "PowerShell") {
				foreign = true
			}
		}
		if !foreign {
			kept = append(kept, dir)
		}
	}
	return strings.Join(kept, ";")
}

// sshFailed reports whether stderr is a message of the ssh client itself,
// for hosts that cannot be asked whether they are still there.
func sshFailed(stderr string) bool {
	for _, mark := range []string{"ssh: ", "Connection closed", "Connection reset", "Connection timed out",
		"Permission denied", "Host key verification failed", "kex_exchange_identification"} {
		if strings.Contains(stderr, mark) {
			return true
		}
	}
	return false
}

func firstLineSuffix(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return ""
	}
	return ": " + strings.TrimSpace(s)
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
