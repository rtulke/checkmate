//go:build !windows

package runner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSSH writes a stand-in for ssh that does what sshd does with a
// command: hand it to a shell as one string. The quoting on the way is
// therefore the real thing; only the network is missing. Its arguments are
// appended to the returned log file.
func fakeSSH(t *testing.T, behaviour string) (program, log string) {
	t.Helper()
	dir := t.TempDir()
	program, log = filepath.Join(dir, "ssh"), filepath.Join(dir, "log")
	script := `#!/bin/sh
printf '%s\n' "$*" >> '` + log + `'
while [ $# -gt 0 ]; do
  case "$1" in
    -o|-p) shift 2 ;;
    -O) exit 0 ;;
    -*) shift ;;
    *) break ;;
  esac
done
host=$1; shift
` + behaviour + `
exec sh -c "$*"
`
	if err := os.WriteFile(program, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return program, log
}

func target(t *testing.T, behaviour string) *Target {
	t.Helper()
	tgt, err := NewTarget("audit@web01.example.net", 0, false)
	if err != nil {
		t.Fatal(err)
	}
	tgt.SSH, _ = fakeSSH(t, behaviour)
	tgt.Shell = "sh"
	return tgt
}

func TestRemoteCommandReachesTheHostUnchanged(t *testing.T) {
	tgt := target(t, "")
	commands := map[string]string{
		`echo "a  b" 'c d' $HOME-x`:                                "a  b c d " + os.Getenv("HOME") + "-x",
		`printf '%s\n' "it's" 'say "hi"' '$(id)' '` + "`id`" + `'`: "it's\nsay \"hi\"\n$(id)\n`id`",
		"echo one\necho two | tr a-z A-Z":                          "one\nTWO",
		`awk 'BEGIN { print "x" "\\" "y" }'`:                       `x\y`,
		`printf %s "$CHECKMATE_ITEM"`:                              "$(touch pwned); `id` 'q' \"d\" \\ *",
		`printf %s "$LC_ALL"`:                                      "C",
		`cat; echo done`:                                           "done",
		`cd / && pwd`:                                              "/",
		`case ":$PATH:" in *:/usr/sbin:*) echo sbin;; esac`:        "sbin",
	}
	for command, want := range commands {
		res, err := Run(context.Background(), Request{Command: command, Target: tgt, Timeout: 10 * time.Second,
			Env: map[string]string{"CHECKMATE_ITEM": "$(touch pwned); `id` 'q' \"d\" \\ *"}})
		if err != nil {
			t.Errorf("%q: %v", command, err)
			continue
		}
		if got := strings.TrimSpace(res.Stdout); res.RC != 0 || got != want {
			t.Errorf("%q: rc %d, stdout %q, want %q (stderr %q)", command, res.RC, got, want, res.Stderr)
		}
	}
	if _, err := os.Stat("pwned"); err == nil {
		os.Remove("pwned")
		t.Error("a value was executed on the way to the host")
	}
}

func TestRemoteExitCodesAndShell(t *testing.T) {
	tgt := target(t, "")
	res, err := Run(context.Background(), Request{Command: "echo out; echo err >&2; exit 3", Target: tgt})
	if err != nil || res.RC != 3 || res.Stdout != "out\n" || res.Stderr != "err\n" || res.Shell != "sh" {
		t.Errorf("got %+v, %v", res, err)
	}
	// pipefail belongs to bash also on the host.
	if _, lookErr := exec.LookPath("bash"); lookErr == nil {
		res, err = Run(context.Background(), Request{Command: "false | true", Shell: "bash", Target: tgt})
		if err != nil || res.RC != 1 || res.Shell != "bash" {
			t.Errorf("bash: got %+v, %v", res, err)
		}
	}
	if _, err := Run(context.Background(), Request{Command: "Get-Item .", Shell: "pwsh", Target: tgt}); err == nil ||
		!strings.Contains(err.Error(), "not available over SSH") {
		t.Errorf("pwsh: %v", err)
	}
	if _, err := Run(context.Background(), Request{Command: "true", Target: tgt, Env: map[string]string{"A B": "x"}}); err == nil {
		t.Error("an invalid variable name was accepted")
	}
}

func TestRemoteBecomeAndOptions(t *testing.T) {
	tgt := target(t, "")
	tgt.Become, tgt.Port, tgt.HasTimeout = true, 2222, true
	line, err := tgt.remoteCommand("sh", "id -u", map[string]string{"B": "2", "A": "it's"}, 1500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	want := `exec sudo -n env LC_ALL=C LANG=C "PATH=$PATH:/usr/local/sbin:/usr/sbin:/sbin" 'A=it'\''s' B=2 timeout -k 2 2 sh -c 'id -u' </dev/null`
	if line != want {
		t.Errorf("got  %s\nwant %s", line, want)
	}
	argv, err := tgt.argv("sh", "true", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(argv[1:], " ")
	for _, part := range []string{"-T", "BatchMode=yes", "-p 2222", "audit@web01.example.net exec sudo -n env"} {
		if !strings.Contains(joined, part) {
			t.Errorf("ssh arguments %q lack %q", joined, part)
		}
	}
}

func TestRemoteRejectsDestinationsThatLookLikeOptions(t *testing.T) {
	for _, host := range []string{"", "-oProxyCommand=id", "web01 -oProxyCommand=id", "web01;id", "a\nb"} {
		if _, err := NewTarget(host, 0, false); err == nil {
			t.Errorf("%q was accepted", host)
		}
	}
	for _, host := range []string{"web01", "audit@web01.example.net", "10.0.0.5", "fe80::1%eth0", "audit@[2001:db8::1]"} {
		if _, err := NewTarget(host, 22, false); err != nil {
			t.Errorf("%q: %v", host, err)
		}
	}
}

func TestRemoteUnreachableHostIsNotAnExitCode(t *testing.T) {
	// ssh exits with 255 when it cannot connect.
	down := target(t, `echo "ssh: connect to host $host port 22: Connection refused" >&2; exit 255`)
	_, err := Run(context.Background(), Request{Command: "true", Target: down})
	if !errors.Is(err, ErrUnreachable) || !strings.Contains(err.Error(), "Connection refused") {
		t.Errorf("unreachable host: %v", err)
	}
	// A command may exit with 255 as well; the host still answers then.
	up := target(t, "")
	res, err := Run(context.Background(), Request{Command: "exit 255", Target: up})
	if err != nil || res.RC != 255 {
		t.Errorf("exit 255: %+v, %v", res, err)
	}
}

func TestRemoteTimeout(t *testing.T) {
	tgt := target(t, "")
	start := time.Now()
	_, err := Run(context.Background(), Request{Command: "sleep 30", Target: tgt, Timeout: 300 * time.Millisecond})
	if !errors.Is(err, ErrTimeout) || time.Since(start) > 5*time.Second {
		t.Errorf("without timeout(1): %v after %s", err, time.Since(start))
	}
	if exec.Command("timeout", "-k", "1", "5", "true").Run() != nil {
		t.Skip("no timeout(1) on this machine")
	}
	tgt.HasTimeout = true
	marker := filepath.Join(t.TempDir(), "marker")
	start = time.Now()
	_, err = Run(context.Background(), Request{Target: tgt, Timeout: time.Second,
		Command: "(sleep 3; echo alive > '" + marker + "') | cat"})
	if !errors.Is(err, ErrTimeout) || time.Since(start) > 5*time.Second {
		t.Errorf("with timeout(1): %v after %s", err, time.Since(start))
	}
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(marker); err == nil {
		t.Error("the command kept running on the host after the timeout")
	}
	// A command that ends in time with 124 is not a timeout.
	res, err := Run(context.Background(), Request{Command: "exit 124", Target: tgt, Timeout: 10 * time.Second})
	if err != nil || res.RC != 124 {
		t.Errorf("exit 124: %+v, %v", res, err)
	}
}

func TestRemoteFacts(t *testing.T) {
	tgt := target(t, "")
	f, err := tgt.Facts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if f.OS == "" || f.Hostname == "" || f.Kernel == "" || f.Distro == "" || len(f.PlatformKeys()) < 2 {
		t.Errorf("facts: %+v", f)
	}
	if _, err := exec.LookPath("bash"); err == nil && tgt.Shell != "bash" {
		t.Errorf("default shell %q although bash exists", tgt.Shell)
	}

	banner := target(t, `echo "Welcome to $host"; exit 0`)
	if _, err := banner.Facts(context.Background()); err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Errorf("foreign output: %v", err)
	}
	down := target(t, "exit 255")
	if _, err := down.Facts(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Errorf("unreachable: %v", err)
	}
	nosudo := target(t, "")
	nosudo.Become = true
	t.Setenv("PATH", t.TempDir()+":/usr/bin:/bin")
	if err := os.WriteFile(filepath.Join(strings.Split(os.Getenv("PATH"), ":")[0], "sudo"),
		[]byte("#!/bin/sh\necho 'sudo: a password is required' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := nosudo.Facts(context.Background()); err == nil || !strings.Contains(err.Error(), "a password is required") {
		t.Errorf("sudo with password: %v", err)
	}
}
