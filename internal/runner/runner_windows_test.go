//go:build windows

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

// powershells are the PowerShell variants found on this machine. Servers
// usually have only Windows PowerShell 5.1 ("powershell"), so both count.
func powershells(t *testing.T) []string {
	t.Helper()
	var found []string
	for _, shell := range []string{"powershell", "pwsh"} {
		if _, err := exec.LookPath(shell); err == nil {
			found = append(found, shell)
		}
	}
	if len(found) == 0 {
		t.Fatal("no PowerShell found")
	}
	return found
}

func TestPowerShellExitCodes(t *testing.T) {
	cases := map[string]int{
		"Write-Output ok":             0,
		"cmd /c exit 3":               3,
		"exit 5":                      5,
		"throw 'broken'":              1,
		"Get-Item C:\\no\\such\\path": 1,
		"$null = Get-Item C:\\nope -ErrorAction SilentlyContinue": 0,
	}
	for _, shell := range powershells(t) {
		for command, want := range cases {
			res, err := Run(context.Background(), Request{Command: command, Shell: shell})
			if err != nil {
				t.Errorf("%s: %q: %v", shell, command, err)
				continue
			}
			if res.RC != want {
				t.Errorf("%s: %q: exit code %d, want %d (stderr: %s)", shell, command, res.RC, want, res.Stderr)
			}
		}
	}
}

func TestPowerShellOutputIsUTF8(t *testing.T) {
	// The characters are built from code points so that the test does not
	// depend on how the command line itself is encoded.
	const want = "\u00e4\u20ac\u4e2d"
	commands := map[string]string{
		"pipeline": "Write-Output ([string][char]0xE4 + [char]0x20AC + [char]0x4E2D)",
		"console":  "[Console]::Out.Write([string][char]0xE4 + [char]0x20AC + [char]0x4E2D)",
		"env":      "Write-Output $env:CHECKMATE_TEXT",
	}
	for _, shell := range powershells(t) {
		for name, command := range commands {
			res, err := Run(context.Background(), Request{Command: command, Shell: shell,
				Env: map[string]string{"CHECKMATE_TEXT": want}})
			if err != nil {
				t.Errorf("%s: %s: %v", shell, name, err)
				continue
			}
			if got := strings.TrimSpace(res.Stdout); got != want {
				t.Errorf("%s: %s: stdout %q, want %q (stderr: %s)", shell, name, got, want, res.Stderr)
			}
		}
	}
}

func TestTimeoutEndsChildProcesses(t *testing.T) {
	for _, shell := range append(powershells(t), "cmd") {
		// The child would create the marker a few seconds after the timeout
		// if it survived the shell. The timeout leaves the shell enough time
		// to start it.
		marker := filepath.Join(t.TempDir(), "marker")
		command := `cmd /c "ping -n 12 127.0.0.1 >nul & echo alive > ""` + marker + `"""`
		if shell == "cmd" {
			command = `ping -n 12 127.0.0.1 >nul & echo alive > "` + marker + `"`
		}
		start := time.Now()
		_, err := Run(context.Background(), Request{Command: command, Shell: shell, Timeout: 4 * time.Second})
		if !errors.Is(err, ErrTimeout) {
			t.Errorf("%s: expected a timeout, got %v", shell, err)
			continue
		}
		if elapsed := time.Since(start); elapsed > 6500*time.Millisecond {
			t.Errorf("%s: the timeout took %s", shell, elapsed)
		}
		time.Sleep(9 * time.Second)
		if _, err := os.Stat(marker); err == nil {
			t.Errorf("%s: a child process survived the timeout", shell)
		}
	}
}

// Without a timeout the marker must appear: the test above would also pass
// if the command never worked.
func TestChildProcessCommandWorks(t *testing.T) {
	for _, shell := range powershells(t) {
		marker := filepath.Join(t.TempDir(), "marker")
		command := `cmd /c "ping -n 2 127.0.0.1 >nul & echo alive > ""` + marker + `"""`
		if _, err := Run(context.Background(), Request{Command: command, Shell: shell, Timeout: 20 * time.Second}); err != nil {
			t.Errorf("%s: %v", shell, err)
			continue
		}
		if _, err := os.Stat(marker); err != nil {
			t.Errorf("%s: the marker was not written: %v", shell, err)
		}
	}
}

// Started from PowerShell 7, PSModulePath lists its module directories.
// Windows PowerShell must still find its own built-in modules.
func TestWindowsPowerShellLoadsItsOwnModules(t *testing.T) {
	if _, err := exec.LookPath("powershell"); err != nil {
		t.Skip("no Windows PowerShell")
	}
	pwsh7 := `C:\Program Files\PowerShell\7\Modules`
	if _, err := os.Stat(pwsh7); err != nil {
		t.Skip("no PowerShell 7 modules to get in the way")
	}
	t.Setenv("PSModulePath", pwsh7+";"+os.Getenv("PSModulePath"))
	res, err := Run(context.Background(), Request{Shell: "powershell",
		Command: "(Get-Acl -LiteralPath $env:SystemRoot).Owner.Length -gt 0"})
	if err != nil || res.RC != 0 || strings.TrimSpace(res.Stdout) != "True" {
		t.Errorf("rc %d, stdout %q, stderr %q, error %v", res.RC, res.Stdout, res.Stderr, err)
	}
}

// cmd.exe reads its command line in its own way; quotes and its special
// characters must arrive as they were written.
func TestCmdGetsTheCommandAsWritten(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a b.txt")
	if err := os.WriteFile(file, []byte("found\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		`echo "a b"`:                   `"a b"`,
		`type "` + file + `"`:          "found",
		`echo one& echo two`:           "one\ntwo",
		`echo a^&b`:                    "a&b",
		`echo "x" | findstr /C:"x"`:    `"x"`,
		`if "a b"=="a b" (echo same)`:  "same",
		`for %i in (1 2) do @echo n%i`: "n1\nn2",
		`echo %CHECKMATE_TEXT%`:        `say "hi" \ there`,
	}
	for command, want := range cases {
		res, err := Run(context.Background(), Request{Command: command, Shell: "cmd", Dir: dir,
			Env: map[string]string{"CHECKMATE_TEXT": `say "hi" \ there`}})
		if err != nil {
			t.Errorf("%q: %v", command, err)
			continue
		}
		got := strings.TrimSpace(strings.ReplaceAll(strings.ReplaceAll(res.Stdout, " \n", "\n"), "\n\n", "\n"))
		if res.RC != 0 || got != want {
			t.Errorf("%q: rc %d, stdout %q, want %q (stderr %q)", command, res.RC, got, want, res.Stderr)
		}
	}
	res, err := Run(context.Background(), Request{Command: `exit /b 7`, Shell: "cmd"})
	if err != nil || res.RC != 7 {
		t.Errorf("exit code: %+v, %v", res, err)
	}
}
