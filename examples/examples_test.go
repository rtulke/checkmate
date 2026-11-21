//go:build !windows

// Package examples verifies that every example policy is valid and that
// every command it renders is syntactically valid shell code on every
// platform it targets.
package examples

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/rtulke/checkmate/internal/facts"
	"github.com/rtulke/checkmate/internal/policy"
)

// platforms simulates the hosts the examples are written for.
var platforms = map[string]facts.Facts{
	"rocky9":     {OS: "linux", Distro: "rocky", DistroLike: []string{"rhel", "centos", "fedora"}, Version: "9.4", VersionMajor: 9, IsRoot: true},
	"rhel8":      {OS: "linux", Distro: "rhel", DistroLike: []string{"fedora"}, Version: "8.10", VersionMajor: 8, IsRoot: true},
	"debian12":   {OS: "linux", Distro: "debian", Version: "12", VersionMajor: 12, IsRoot: true},
	"ubuntu24":   {OS: "linux", Distro: "ubuntu", DistroLike: []string{"debian"}, Version: "24.04", VersionMajor: 24, IsRoot: true},
	"ubuntu26":   {OS: "linux", Distro: "ubuntu", DistroLike: []string{"debian"}, Version: "26.04", VersionMajor: 26, IsRoot: true},
	"sles15":     {OS: "linux", Distro: "sles", DistroLike: []string{"suse"}, Version: "15.6", VersionMajor: 15, IsRoot: true},
	"alpine":     {OS: "linux", Distro: "alpine", Version: "3.20.0", VersionMajor: 3, IsRoot: true},
	"macos":      {OS: "darwin", Distro: "macos", Version: "15.1", VersionMajor: 15},
	"windows":    {OS: "windows", Distro: "windows", Version: "10.0.22631", VersionMajor: 10},
	"linux-user": {OS: "linux", Distro: "debian", Version: "12", VersionMajor: 12, IsRoot: false},
	// Targets of the CIS benchmarks in ../cis.
	"centos7":  {OS: "linux", Distro: "centos", DistroLike: []string{"rhel", "fedora"}, Version: "7", VersionMajor: 7, IsRoot: true},
	"rocky10":  {OS: "linux", Distro: "rocky", DistroLike: []string{"rhel", "centos", "fedora"}, Version: "10.0", VersionMajor: 10, IsRoot: true},
	"debian11": {OS: "linux", Distro: "debian", Version: "11", VersionMajor: 11, IsRoot: true},
	"debian13": {OS: "linux", Distro: "debian", Version: "13", VersionMajor: 13, IsRoot: true},
	"ubuntu20": {OS: "linux", Distro: "ubuntu", DistroLike: []string{"debian"}, Version: "20.04", VersionMajor: 20, IsRoot: true},
	"ubuntu22": {OS: "linux", Distro: "ubuntu", DistroLike: []string{"debian"}, Version: "22.04", VersionMajor: 22, IsRoot: true},
	"sles16":   {OS: "linux", Distro: "sles", DistroLike: []string{"suse"}, Version: "16.0", VersionMajor: 16, IsRoot: true},
	"amzn2":    {OS: "linux", Distro: "amzn", DistroLike: []string{"centos", "rhel", "fedora"}, Version: "2", VersionMajor: 2, IsRoot: true},
	"amzn2023": {OS: "linux", Distro: "amzn", DistroLike: []string{"fedora"}, Version: "2023", VersionMajor: 2023, IsRoot: true},
	"amzn2027": {OS: "linux", Distro: "amzn", DistroLike: []string{"fedora"}, Version: "2027", VersionMajor: 2027, IsRoot: true},
	"ubuntu18": {OS: "linux", Distro: "ubuntu", DistroLike: []string{"debian"}, Version: "18.04", VersionMajor: 18, IsRoot: true},
	// Targets of the Windows CIS benchmarks.
	"win11":   {OS: "windows", Distro: "windows", DistroName: "Windows 11", Version: "10.0.26100", VersionMajor: 10, IsRoot: true},
	"win2019": {OS: "windows", Distro: "windows", DistroName: "Windows Server 2019", Version: "10.0.17763", VersionMajor: 10, IsRoot: true},
	"win2022": {OS: "windows", Distro: "windows", DistroName: "Windows Server 2022", Version: "10.0.20348", VersionMajor: 10, IsRoot: true},
	"win2025": {OS: "windows", Distro: "windows", DistroName: "Windows Server 2025", Version: "10.0.26100", VersionMajor: 10, IsRoot: true},
}

func policyFiles(t *testing.T) []string {
	t.Helper()
	var files []string
	err := filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(path, ".yml") && !strings.Contains(path, "vars/") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no example policies found")
	}
	// The policy of the terminal demo (docs/demo.tape) and the generated CIS
	// benchmarks are checked as well.
	files = append(files, "../docs/demo/demo.yml")
	cis, _ := filepath.Glob("../cis/*.yml")
	stig, _ := filepath.Glob("../stig/*.yml")
	return append(append(files, cis...), stig...)
}

// colonSpace finds single-line commands containing ": ", which YAML reads
// as a mapping (a frequent mistake with awk -F: and cut -d:).
var colonSpace = regexp.MustCompile(`^\s+(run|only_if|[a-z,]+): [^|>"'{\[#].*(: |:$)`)

func TestNoUnquotedColonSpace(t *testing.T) {
	for _, file := range policyFiles(t) {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(data), "\n") {
			if colonSpace.MatchString(line) {
				t.Errorf("%s:%d: command contains \": \"; use a block scalar (run: |): %s", file, i+1, strings.TrimSpace(line))
			}
		}
	}
}

func TestExamplesAreValid(t *testing.T) {
	for _, file := range policyFiles(t) {
		p, err := policy.Load(file, policy.LoadOptions{AllowInsecure: true})
		if err != nil {
			t.Errorf("%s: %v", file, err)
			continue
		}
		// The demo policy is deliberately minimal and the CIS policies are
		// generated; style rules apply to hand-written examples only.
		styleRules := !strings.HasPrefix(file, "../")
		if styleRules && (p.Name == "" || p.Description == "") {
			t.Errorf("%s: every example needs a name and a description", file)
		}
		for name, f := range platforms {
			checks, errs := policy.Expand(p, f, nil)
			for _, e := range errs {
				t.Errorf("[%s] %v", name, e)
			}
			if len(checks) == 0 && len(errs) == 0 {
				t.Errorf("[%s] %s: no checks", name, file)
			}
			for _, c := range checks {
				if !styleRules {
					continue
				}
				if c.Name == c.ID {
					t.Errorf("%s: check %s needs a descriptive name", file, c.ID)
				}
				if len(c.Tags) == 0 {
					t.Errorf("%s: check %s needs tags", file, c.ID)
				}
			}
		}
	}
}

// TestExampleCommandsParse renders every command for every platform and
// checks the result with `bash -n` (or `pwsh` parsing is skipped).
func TestExampleCommandsParse(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	checked := 0
	for _, file := range policyFiles(t) {
		p, err := policy.Load(file, policy.LoadOptions{AllowInsecure: true})
		if err != nil {
			t.Errorf("%s: %v", file, err)
			continue
		}
		for name, f := range platforms {
			if f.OS == "windows" {
				continue // PowerShell syntax is not checked here
			}
			checks, _ := policy.Expand(p, f, nil)
			for _, c := range checks {
				if c.Shell != "" && c.Shell != "bash" && c.Shell != "sh" {
					continue
				}
				applies, _, err := c.Applies()
				if err != nil {
					t.Errorf("[%s] %s %s: %v", name, file, c.ID, err)
					continue
				}
				if !applies {
					continue
				}
				for label, spec := range map[string]policy.CommandSpec{"run": c.Run, "only_if": c.OnlyIf} {
					if spec.IsZero() {
						continue
					}
					cmd, ok, err := c.Command(spec, f.PlatformKeys())
					if err != nil {
						t.Errorf("[%s] %s %s %s: %v", name, file, c.ID, label, err)
						continue
					}
					if !ok {
						continue
					}
					out, err := exec.Command("bash", "-n", "-c", cmd).CombinedOutput()
					if err != nil {
						t.Errorf("[%s] %s %s %s: bash syntax error: %s\n%s", name, file, c.ID, label, strings.TrimSpace(string(out)), cmd)
					}
					checked++
				}
			}
		}
	}
	t.Logf("checked %d rendered commands", checked)
}

// TestPowerShellCommandsParse parses every rendered Windows command with the
// PowerShell parser. It needs pwsh or powershell; without one, setting
// CHECKMATE_PS_DUMP=<dir> writes the commands to files for parsing elsewhere
// (e.g. in a PowerShell container).
func TestPowerShellCommandsParse(t *testing.T) {
	shell := ""
	for _, s := range []string{"pwsh", "powershell"} {
		if _, err := exec.LookPath(s); err == nil {
			shell = s
			break
		}
	}
	dump := os.Getenv("CHECKMATE_PS_DUMP")
	if shell == "" && dump == "" {
		t.Skip("neither pwsh nor powershell available")
	}
	dir := dump
	if dir == "" {
		dir = t.TempDir()
	}
	seen := map[string]bool{}
	n := 0
	for _, file := range policyFiles(t) {
		p, err := policy.Load(file, policy.LoadOptions{AllowInsecure: true})
		if err != nil {
			t.Errorf("%s: %v", file, err)
			continue
		}
		for _, f := range platforms {
			if f.OS != "windows" {
				continue
			}
			// Role-specific checks of the Windows benchmarks apply only with
			// the matching variables.
			for _, vars := range []map[string]any{
				nil,
				{"cis_windows_role": "standalone", "cis_windows_domain_joined": true},
				{"cis_windows_role": "dc"},
			} {
				checks, _ := policy.Expand(p, f, vars)
				for _, c := range checks {
					if applies, _, err := c.Applies(); err != nil || !applies {
						continue
					}
					for _, spec := range []policy.CommandSpec{c.Run, c.OnlyIf} {
						if spec.IsZero() {
							continue
						}
						cmd, ok, err := c.Command(spec, f.PlatformKeys())
						if err != nil || !ok || seen[cmd] {
							continue
						}
						seen[cmd] = true
						n++
						name := filepath.Join(dir, fmt.Sprintf("%05d.ps1", n))
						if err := os.WriteFile(name, []byte("# "+file+" "+c.ID+"\n"+cmd+"\n"), 0o644); err != nil {
							t.Fatal(err)
						}
					}
				}
			}
		}
	}
	t.Logf("%d distinct PowerShell commands", n)
	if shell == "" {
		return
	}
	script := `$bad = 0
foreach ($f in Get-ChildItem -LiteralPath $args[0] -Filter *.ps1) {
  $tokens = $null; $errors = $null
  [System.Management.Automation.Language.Parser]::ParseFile($f.FullName, [ref]$tokens, [ref]$errors) | Out-Null
  foreach ($e in $errors) { $bad++; Write-Output ("{0}: {1} (line {2})" -f (Get-Content -LiteralPath $f.FullName -TotalCount 1), $e.Message, $e.Extent.StartLineNumber) }
}
exit [int]($bad -gt 0)`
	out, err := exec.Command(shell, "-NoProfile", "-NonInteractive", "-Command", script, dir).CombinedOutput()
	if err != nil {
		t.Errorf("PowerShell syntax errors:\n%s", out)
	}
}
