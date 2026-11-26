package runner

import (
	"context"
	"fmt"
	"math"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/rtulke/checkmate/internal/facts"
)

// Target is a host whose commands run over SSH instead of locally.
//
// checkmate drives the ssh program rather than speaking the protocol
// itself, so ~/.ssh/config, agents, jump hosts and known_hosts apply as
// they do on the command line. One connection per host is kept open and
// shared by all commands (ControlMaster).
type Target struct {
	Host   string // destination as for ssh: host or user@host
	Port   int    // 0 leaves the port to ssh
	Become bool   // run every command through `sudo -n`

	// Shell is the default shell of the host, "bash" or "sh". HasTimeout
	// says that the host has a timeout program that ends a command and its
	// children. Both are set from the facts of the host.
	Shell      string
	HasTimeout bool

	// SSH is the ssh program, "ssh" if empty.
	SSH string

	controlDir string
}

// MaxRemoteJobs is the most commands that may run on one host at a time.
// They share one connection, and sshd accepts 10 sessions per connection
// by default (MaxSessions); two are left for the checks of the connection
// itself.
const MaxRemoteJobs = 8

var (
	validHost   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@:%\[\]-]*$`)
	validEnvKey = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// NewTarget checks the destination. It must not look like an option of
// ssh, wherever it comes from.
func NewTarget(host string, port int, become bool) (*Target, error) {
	if !validHost.MatchString(host) {
		return nil, fmt.Errorf("invalid host %q", host)
	}
	if port < 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port %d", port)
	}
	// CHECKMATE_SSH names another ssh program, as GIT_SSH does for git.
	return &Target{Host: host, Port: port, Become: become, SSH: os.Getenv("CHECKMATE_SSH")}, nil
}

// Open prepares the shared connection. The connection itself is made by
// the first command.
func (t *Target) Open() error {
	if runtime.GOOS == "windows" {
		return nil // OpenSSH for Windows cannot share connections
	}
	// Unix socket paths are short (104 bytes on macOS); ssh adds a 40
	// character hash, so the directory has to stay close to the root.
	base := os.TempDir()
	if len(base) > 40 {
		base = "/tmp"
	}
	dir, err := os.MkdirTemp(base, "cm-")
	if err != nil {
		return err
	}
	t.controlDir = dir
	return nil
}

// Close ends the shared connection.
func (t *Target) Close() {
	if t.controlDir == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	args := append(t.sshOptions(), "-O", "exit", t.Host)
	_ = exec.CommandContext(ctx, t.program(), args...).Run()
	_ = os.RemoveAll(t.controlDir)
	t.controlDir = ""
}

func (t *Target) program() string {
	if t.SSH != "" {
		return t.SSH
	}
	return "ssh"
}

func (t *Target) sshOptions() []string {
	// BatchMode: never ask for a password or passphrase, fail instead.
	opts := []string{"-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10"}
	if t.controlDir != "" {
		opts = append(opts,
			"-o", "ControlMaster=auto",
			"-o", "ControlPath="+t.controlDir+"/%C",
			"-o", "ControlPersist=120")
	}
	if t.Port != 0 {
		opts = append(opts, "-p", strconv.Itoa(t.Port))
	}
	return opts
}

// argv is the local command that runs command on the host.
func (t *Target) argv(shell, command string, env map[string]string, timeout time.Duration) ([]string, error) {
	remote, err := t.remoteCommand(shell, command, env, timeout)
	if err != nil {
		return nil, err
	}
	return append(append([]string{t.program()}, t.sshOptions()...), t.Host, remote), nil
}

// remoteCommand is the command line handed to the login shell of the host.
// sshd runs it as `$SHELL -c <line>`, so every word is quoted for a POSIX
// shell. The command itself travels as one argument and is never
// interpreted on the way.
//
//	exec [sudo -n] env LC_ALL=C LANG=C PATH=... K=V... [timeout -k 2 N] bash ... -c '<command>' </dev/null
func (t *Target) remoteCommand(shell, command string, env map[string]string, timeout time.Duration) (string, error) {
	switch shell {
	case "bash", "sh", "zsh":
	default:
		return "", fmt.Errorf("shell %q is not available over SSH (use bash, sh or zsh)", shell)
	}
	inner, err := shellArgv(shell, command)
	if err != nil {
		return "", err
	}

	words := []string{"exec"}
	if t.Become {
		words = append(words, "sudo", "-n")
	}
	words = append(words, "env", "LC_ALL=C", "LANG=C")
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !validEnvKey.MatchString(k) {
			return "", fmt.Errorf("environment variable %q cannot be passed to the host", k)
		}
		words = append(words, k+"="+env[k])
	}
	if timeout > 0 && t.HasTimeout {
		words = append(words, "timeout", "-k", "2", strconv.Itoa(int(math.Ceil(timeout.Seconds()))))
	}
	words = append(words, inner...)

	quoted := make([]string, 0, len(words)+1)
	for _, w := range words {
		quoted = append(quoted, posixQuote(w))
		if w == "LANG=C" {
			// A non-interactive SSH session often has no sbin directories
			// in PATH, where many of the tools a check needs live. This
			// word is expanded by the login shell of the host.
			quoted = append(quoted, `"PATH=$PATH:/usr/local/sbin:/usr/sbin:/sbin"`)
		}
	}
	// Like locally, commands have no input: one that reads stdin must not
	// wait for the connection.
	return strings.Join(quoted, " ") + " </dev/null", nil
}

// posixQuote quotes a word for a POSIX shell.
func posixQuote(s string) string {
	if s != "" && safeWord.MatchString(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

var safeWord = regexp.MustCompile(`^[A-Za-z0-9_./=:@%+,-]+$`)

// reachable reports whether the host still answers. ssh exits with 255
// both when the connection fails and when the command does; this tells
// the two apart.
func (t *Target) reachable(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	args := append(t.sshOptions(), t.Host, "exit 0")
	return exec.CommandContext(ctx, t.program(), args...).Run() == nil
}

// Facts runs the facts script on the host and takes the default shell and
// the timeout program from its answer. It is the first command of a run,
// so it also proves that the host is reachable and, with Become, that
// sudo works without a password.
func (t *Target) Facts(ctx context.Context) (facts.Facts, error) {
	res, err := Run(ctx, Request{Command: facts.RemoteScript, Shell: "sh", Timeout: 30 * time.Second, Target: t})
	if err != nil {
		return facts.Facts{}, err
	}
	if res.RC != 0 {
		reason := "exit code " + strconv.Itoa(res.RC)
		if t.Become {
			reason += " (sudo -n must work without a password)"
		}
		return facts.Facts{}, fmt.Errorf("cannot gather facts on %s: %s%s", t.Host, reason, firstLineSuffix(res.Stderr))
	}
	f, host, err := facts.Remote(res.Stdout)
	if err != nil {
		return facts.Facts{}, fmt.Errorf("%s: %w", t.Host, err)
	}
	t.Shell = "sh"
	if host.HasBash {
		t.Shell = "bash"
	}
	t.HasTimeout = host.HasTimeout
	return f, nil
}
