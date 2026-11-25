package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTestPolicy writes a small policy that runs on every platform.
func writeTestPolicy(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "p.yml")
	body := `name: Export test
checks:
  - { id: OK-1, run: "echo ok", expect: "== ok", severity: high }
  - { id: BAD-2, run: "echo no", expect: "== yes", severity: low }
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestRunExportAndConvert(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeTestPolicy(t, dir)
	var out, errOut bytes.Buffer
	base := filepath.Join(dir, "run")
	code := run([]string{"run", "--allow-insecure-policy", "-q", "--export", "json,html,csv,prom", "-o", base + ".json", policyPath}, &out, &errOut)
	if code != exitNotCompliant {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	for _, ext := range []string{".json", ".html", ".csv", ".prom"} {
		if _, err := os.Stat(base + ext); err != nil {
			t.Errorf("missing %s (stderr: %s)", ext, errOut.String())
		}
	}
	if !strings.Contains(out.String(), "BAD-2") {
		t.Error("text output must still go to stdout")
	}
	leftovers, _ := filepath.Glob(filepath.Join(dir, ".*.tmp"))
	if len(leftovers) > 0 {
		t.Errorf("temporary files left: %v", leftovers)
	}

	// A single format without -o goes to stdout.
	out.Reset()
	if code := run([]string{"export", "-f", "csv", base + ".json"}, &out, &errOut); code != 0 {
		t.Fatalf("export: %d %s", code, errOut.String())
	}
	if !strings.HasPrefix(out.String(), "host,os,") {
		t.Errorf("csv not on stdout: %q", out.String())
	}

	// Several formats are written next to the report, merged from two files.
	second := filepath.Join(dir, "second.json")
	data, _ := os.ReadFile(base + ".json")
	os.WriteFile(second, data, 0o600)
	errOut.Reset()
	if code := run([]string{"export", "--format", "html,xccdf", "-o", dir + "/", base + ".json", second}, &out, &errOut); code != 0 {
		t.Fatalf("merge: %d %s", code, errOut.String())
	}
	for _, f := range []string{"checkmate-report.html", "checkmate-report.xccdf.xml"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("missing %s: %s", f, errOut.String())
		}
	}

	// attack needs exactly one report.
	if code := run([]string{"export", "-f", "attack", base + ".json", second}, &out, &errOut); code != exitUsage {
		t.Errorf("attack with two reports: exit %d", code)
	}
}

func TestDiffDetectsKinds(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeTestPolicy(t, dir)
	var out, errOut bytes.Buffer
	report := filepath.Join(dir, "r.json")
	run([]string{"run", "--allow-insecure-policy", "--export", "json", "-o", report, policyPath}, &out, &errOut)

	out.Reset()
	if code := run([]string{"diff", report, report}, &out, &errOut); code != 0 {
		t.Errorf("same report: exit %d\n%s", code, out.String())
	}
	if code := run([]string{"diff", "--allow-insecure-policy", policyPath, policyPath}, &out, &errOut); code != 0 {
		t.Errorf("same policy: exit %d", code)
	}
	changed := filepath.Join(dir, "q.yaml")
	data, _ := os.ReadFile(policyPath)
	os.WriteFile(changed, bytes.Replace(data, []byte("severity: low"), []byte("severity: critical"), 1), 0o600)
	out.Reset()
	if code := run([]string{"diff", "--allow-insecure-policy", policyPath, changed}, &out, &errOut); code != exitNotCompliant {
		t.Errorf("changed policy: exit %d", code)
	}
	if !strings.Contains(out.String(), "severity: low -> critical") {
		t.Errorf("unexpected diff:\n%s", out.String())
	}
	errOut.Reset()
	if code := run([]string{"diff", report, policyPath}, &out, &errOut); code != exitUsage || !strings.Contains(errOut.String(), "cannot compare") {
		t.Errorf("mixed kinds: exit %d, %s", code, errOut.String())
	}
}

func TestParseExports(t *testing.T) {
	p, err := parseExports("html, pdf,html,syslog,syslog:udp://h:514")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.formats) != 2 || len(p.syslog) != 2 || p.syslog[0] != "" || p.syslog[1] != "udp://h:514" {
		t.Errorf("unexpected plan %+v", p)
	}
	if _, err := parseExports("html,docx"); err == nil {
		t.Error("unknown format must fail")
	}
}

func TestResolveBase(t *testing.T) {
	dir := t.TempDir()
	if got := resolveBase("", "def"); got != "def" {
		t.Errorf("got %s", got)
	}
	if got := resolveBase(dir, "x/def"); got != filepath.Join(dir, "def") {
		t.Errorf("got %s", got)
	}
	if got := stripFormatExt("a/report.xccdf.xml"); got != "a/report" {
		t.Errorf("got %s", got)
	}
}

// Exports into a directory that does not exist yet create it; a target that
// cannot be written is reported before the checks run.
func TestRunExportCreatesDirectoryAndChecksItFirst(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeTestPolicy(t, dir)
	var out, errOut bytes.Buffer
	target := filepath.Join(dir, "new", "reports") + string(os.PathSeparator)
	code := run([]string{"run", "--allow-insecure-policy", "-q", "--export", "json", "-o", target, policyPath}, &out, &errOut)
	if code != exitNotCompliant {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	if files, _ := filepath.Glob(filepath.Join(dir, "new", "reports", "*.json")); len(files) != 1 {
		t.Errorf("expected one report, got %v (stderr: %s)", files, errOut.String())
	}

	blocker := filepath.Join(dir, "file")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errOut.Reset()
	code = run([]string{"run", "--allow-insecure-policy", "--export", "json", "-o", filepath.Join(blocker, "x"), policyPath}, &out, &errOut)
	if code != exitUsage || !strings.Contains(errOut.String(), "cannot write exports") || out.Len() != 0 {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out.String(), errOut.String())
	}
}
