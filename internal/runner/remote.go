package runner

import (
	"context"
	"encoding/base64"
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
	"unicode/utf16"

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

	// Shell is the default shell of the host: "bash" or "sh", on Windows
	// "pwsh" or "powershell". HasTimeout says that the host has a timeout
	// program that ends a command and its children. Windows says that the
	// host runs Windows. All three are set from the facts of the host.
	Shell      string
	HasTimeout bool
	Windows    bool

	// Device marks a host without a shell, such as a switch or a firewall,
	// and names its platform (ios, junos, ...). Commands are sent as they
	// are, one at a time, and nothing is asked of the host beforehand.
	Device string

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
	// OpenSSH for Windows cannot share connections, and many devices accept
	// only one session per connection.
	if runtime.GOOS == "windows" || t.Device != "" {
		return nil
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

// MaxJobs is the most commands that may run on the host at a time.
func (t *Target) MaxJobs() int {
	if t.Device != "" {
		return 1
	}
	return MaxRemoteJobs
}

// defaultShell is the shell of a command that does not name one.
func (t *Target) defaultShell() string {
	switch {
	case t.Device != "":
		return "device"
	case t.Shell != "":
		return t.Shell
	case t.Windows:
		return "powershell"
	}
	return "sh"
}

// argv is the local command that runs command on the host, and what it
// reads from its standard input, if anything.
func (t *Target) argv(shell, command string, env map[string]string, timeout time.Duration) (argv []string, stdin string, err error) {
	var remote string
	switch {
	case t.Device != "":
		// No shell on the other side: nothing can carry variables, and
		// the command is all there is.
		if len(env) > 0 {
			return nil, "", fmt.Errorf("a device without a shell cannot receive variables (env, loop_run items)")
		}
		remote = command
	case t.Windows:
		remote, stdin, err = t.windowsCommand(shell, command, env)
	default:
		remote, err = t.remoteCommand(shell, command, env, timeout)
	}
	if err != nil {
		return nil, "", err
	}
	return append(append([]string{t.program()}, t.sshOptions()...), t.Host, remote), stdin, nil
}

// windowsBootstrap reads a script from standard input and runs it. It is
// all that travels on the command line, encoded, so that neither cmd.exe
// nor PowerShell as the login shell of the host interprets anything and
// the 8191 characters cmd.exe accepts are never a limit for a check.
// Input and output are UTF-8 whatever the code page of the host is.
const windowsBootstrap = `try { [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding $false; $OutputEncoding = [Console]::OutputEncoding } catch {}
$in = [Console]::OpenStandardInput(); $buf = New-Object System.IO.MemoryStream; $in.CopyTo($buf)
$script = [scriptblock]::Create([System.Text.Encoding]::UTF8.GetString($buf.ToArray()))
$ErrorActionPreference = 'Stop'
& $script
if ($LASTEXITCODE) { exit $LASTEXITCODE }
exit 0`

// windowsCommand is the command line for a Windows host and the script it
// reads. Variables are set at the top of the script, as quoted strings.
func (t *Target) windowsCommand(shell, command string, env map[string]string) (line, script string, err error) {
	switch shell {
	case "pwsh", "powershell":
	default:
		return "", "", fmt.Errorf("shell %q is not available on a Windows host over SSH (use powershell or pwsh)", shell)
	}
	if t.Become {
		return "", "", fmt.Errorf("become is not available on Windows; connect as a user with administrator rights")
	}
	var b strings.Builder
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if !validEnvKey.MatchString(k) {
			return "", "", fmt.Errorf("environment variable %q cannot be passed to the host", k)
		}
		fmt.Fprintf(&b, "$env:%s = '%s'\n", k, strings.ReplaceAll(env[k], "'", "''"))
	}
	b.WriteString(command)
	return shell + " -NoLogo -NoProfile -NonInteractive -EncodedCommand " + encodePowerShell(windowsBootstrap), b.String(), nil
}

// encodePowerShell encodes a script for -EncodedCommand: UTF-16LE in
// base64.
func encodePowerShell(script string) string {
	units := utf16.Encode([]rune(script))
	raw := make([]byte, 2*len(units))
	for i, u := range units {
		raw[2*i], raw[2*i+1] = byte(u), byte(u>>8)
	}
	return base64.StdEncoding.EncodeToString(raw)
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
	if t.Device != "" {
		// "exit 0" means something else on every device; ask ssh itself.
		return false
	}
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
	if t.Device != "" {
		return facts.Device(t.Host, t.Device), nil
	}
	res, err := Run(ctx, Request{Command: facts.RemoteScript, Shell: "sh", Timeout: 30 * time.Second, Target: t})
	if err != nil {
		return facts.Facts{}, err
	}
	// A Windows host has no sh: cmd.exe or PowerShell answer the script
	// with an error or with its text. Ask again in PowerShell.
	if _, _, posixErr := facts.Remote(res.Stdout); res.RC != 0 || posixErr != nil {
		windows := *t
		windows.Windows = true
		if wres, werr := Run(ctx, Request{Command: facts.RemoteWindowsScript, Shell: "powershell", Timeout: 60 * time.Second, Target: &windows}); werr == nil && wres.RC == 0 {
			if f, hasPwsh, ferr := facts.RemoteWindows(wres.Stdout); ferr == nil {
				if t.Become {
					return facts.Facts{}, fmt.Errorf("%s: become is not available on Windows; connect as a user with administrator rights", t.Host)
				}
				t.Windows = true
				t.Shell = "powershell"
				if hasPwsh {
					t.Shell = "pwsh"
				}
				return f, nil
			}
		}
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
