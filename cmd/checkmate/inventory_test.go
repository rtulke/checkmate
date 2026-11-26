//go:build !windows

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rtulke/checkmate/internal/engine"
)

// standInSSH replaces ssh by a script that runs the command in a local
// shell, as sshd would on the host, and that cannot reach hosts whose name
// contains "down".
func standInSSH(t *testing.T, dir string) {
	t.Helper()
	script := `#!/bin/sh
while [ $# -gt 0 ]; do
  case "$1" in
    -o|-p) shift 2 ;;
    -O) exit 0 ;;
    -*) shift ;;
    *) break ;;
  esac
done
host=$1; shift
case "$host" in
  *down*) echo "ssh: connect to host $host port 22: Connection timed out" >&2; exit 255 ;;
esac
exec sh -c "$*"
`
	path := filepath.Join(dir, "ssh")
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CHECKMATE_SSH", path)
}

func TestRunInventory(t *testing.T) {
	dir := t.TempDir()
	standInSSH(t, dir)
	writeFiles(t, dir, map[string]string{
		"hosts.yml": `
defaults:
  user: audit
  vars: { want: a }
groups:
  web:
    vars: { role: web }
    hosts: [web01.example.net, web02.example.net]
  db:
    vars: { role: db, want: b }
    hosts: [db01.example.net, down01.example.net]
`,
		"p.yml": `
name: Inventory test
vars: { role: none, want: z }
checks:
  - id: ROLE
    run: echo "{{ inventory_hostname }} {{ role }} {{ group_names | join(',') }}"
    expect: "~ ^(web0[12].example.net web web|db01.example.net db db)$"
  - id: WANT
    run: echo a
    expect: "{{ want }}"
`,
	})
	policyPath, inv := filepath.Join(dir, "p.yml"), filepath.Join(dir, "hosts.yml")
	args := func(extra ...string) []string {
		return append([]string{"run", "--allow-insecure-policy", "-i", inv, policyPath}, extra...)
	}

	// A finding outranks a host that could not be checked.
	var out, errOut bytes.Buffer
	if code := run(args("--format", "json"), &out, &errOut); code != exitNotCompliant {
		t.Fatalf("exit %d: %s", code, errOut.String())
	}
	var doc struct {
		Reports []engine.Report `json:"reports"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("json: %v\n%s", err, out.String())
	}
	reports := doc.Reports
	var got []string
	for _, r := range reports {
		state := "compliant"
		switch {
		case r.Unreachable:
			state = "unreachable"
		case !r.Summary.Compliant:
			state = "not compliant"
		}
		got = append(got, r.Host+" ["+strings.Join(r.Groups, ",")+"] "+state)
	}
	want := []string{"web01.example.net [web] compliant", "web02.example.net [web] compliant",
		"db01.example.net [db] not compliant", "down01.example.net [db] unreachable"}
	if strings.Join(got, "; ") != strings.Join(want, "; ") {
		t.Errorf("reports:\n got %v\nwant %v", got, want)
	}
	down := reports[3]
	if len(down.Results) != 0 || down.Summary.Total != 0 || !strings.Contains(down.Error, "Connection timed out") {
		t.Errorf("unreachable host: %d results, error %q", len(down.Results), down.Error)
	}

	// Nothing is known about an unreachable host: it is neither compliant
	// (0) nor non-compliant (1).
	for limit, code := range map[string]int{
		"web":         exitCompliant,
		"web,down*":   exitUnchecked,
		"down01*":     exitUnchecked,
		"db01*":       exitNotCompliant,
		"web01*,db":   exitNotCompliant,
		"nosuchgroup": exitUsage,
	} {
		out.Reset()
		errOut.Reset()
		if got := run(args("--limit", limit), &out, &errOut); got != code {
			t.Errorf("--limit %s: exit %d, want %d (%s)", limit, got, code, errOut.String())
		}
	}

	out.Reset()
	if got := run(args("-l", "web"), &out, &errOut); got != exitCompliant || !strings.Contains(out.String(), "2 hosts") {
		t.Errorf("-l web: exit %d\n%s", got, out.String())
	}

	// The overview names the state and gives no numbers for the host.
	out.Reset()
	run(args(), &out, &errOut)
	text := out.String()
	for _, part := range []string{"4 reports", "unreachable: ", "1 of 4 hosts could not be checked"} {
		if !strings.Contains(text, part) {
			t.Errorf("overview lacks %q:\n%s", part, text)
		}
	}
	out.Reset()
	run(args("--limit", "down*"), &out, &errOut)
	if strings.Contains(out.String(), "NOTHING EVALUATED") || !strings.Contains(out.String(), "unreachable") {
		t.Errorf("a single unreachable host:\n%s", out.String())
	}

	// -e overrides the inventory, which overrides the policy.
	out.Reset()
	errOut.Reset()
	if code := run(args("--limit", "db01*", "-e", "want=a"), &out, &errOut); code != exitCompliant {
		t.Errorf("-e want=a: exit %d\n%s", code, out.String())
	}
}

func TestInventoryOptionsNeedEachOther(t *testing.T) {
	dir := t.TempDir()
	policyPath := writeTestPolicy(t, dir)
	writeFiles(t, dir, map[string]string{"hosts.yml": "hosts: [a]\n", "bad.yml": "hosts: [{nam: a}]\n"})
	inv := filepath.Join(dir, "hosts.yml")
	for name, c := range map[string]struct {
		args []string
		want string
	}{
		"limit alone":  {[]string{"--limit", "web"}, "--limit needs --inventory"},
		"with host":    {[]string{"-i", inv, "--host", "a"}, "cannot be combined"},
		"with become":  {[]string{"-i", inv, "--become"}, "cannot be combined"},
		"missing file": {[]string{"-i", filepath.Join(dir, "none.yml")}, "none.yml"},
		"broken file":  {[]string{"-i", filepath.Join(dir, "bad.yml")}, "nam"},
	} {
		var out, errOut bytes.Buffer
		code := run(append([]string{"run", "--allow-insecure-policy", policyPath}, c.args...), &out, &errOut)
		if code != exitUsage || !strings.Contains(errOut.String(), c.want) {
			t.Errorf("%s: exit %d, stderr %q", name, code, errOut.String())
		}
	}
}
