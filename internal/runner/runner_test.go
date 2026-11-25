//go:build !windows

package runner

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestRunReportsExitCodeAndOutput(t *testing.T) {
	res, err := Run(context.Background(), Request{Command: "echo out; echo err >&2; exit 3", Shell: "sh"})
	if err != nil {
		t.Fatal(err)
	}
	if res.RC != 3 || res.Stdout != "out\n" || res.Stderr != "err\n" {
		t.Errorf("got rc=%d stdout=%q stderr=%q", res.RC, res.Stdout, res.Stderr)
	}
}

func TestRunAppliesEnvAndStableLocale(t *testing.T) {
	res, err := Run(context.Background(), Request{
		Command: `echo "$LC_ALL $CHECKMATE_TEST"`, Shell: "sh", Env: map[string]string{"CHECKMATE_TEST": "x"},
	})
	if err != nil || strings.TrimSpace(res.Stdout) != "C x" {
		t.Errorf("got %q, %v", res.Stdout, err)
	}
}

// A timeout must end the whole pipeline, not only the shell, and must not
// wait for the children to finish on their own.
func TestRunTimeoutKillsProcessGroup(t *testing.T) {
	start := time.Now()
	_, err := Run(context.Background(), Request{Command: "sleep 31 | sleep 31", Shell: "sh", Timeout: 200 * time.Millisecond})
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("expected a timeout, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("timeout took %s", elapsed)
	}
	time.Sleep(100 * time.Millisecond)
	if out, _ := exec.Command("pgrep", "-f", "sleep 31").Output(); len(out) > 0 {
		t.Errorf("processes survived the timeout: %s", out)
	}
}

// A command that leaves a background process holding stdout has completed
// all the same; its exit code and output count.
func TestRunBackgroundProcessIsNotAnError(t *testing.T) {
	res, err := Run(context.Background(), Request{Command: "(sleep 4 &); echo done", Shell: "sh"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.RC != 0 || strings.TrimSpace(res.Stdout) != "done" {
		t.Errorf("got rc=%d stdout=%q", res.RC, res.Stdout)
	}
}

func TestRunRejectsUnknownShell(t *testing.T) {
	if _, err := Run(context.Background(), Request{Command: "true", Shell: "fish"}); err == nil {
		t.Error("an unsupported shell must be an error")
	}
}

func TestOutputIsCapped(t *testing.T) {
	b := &limitedBuffer{limit: 4}
	b.Write([]byte("abcdef"))
	b.Write([]byte("gh"))
	if got := b.String(); got != "abcd\n[output truncated]" {
		t.Errorf("got %q", got)
	}
}
