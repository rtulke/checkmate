package compare

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rtulke/checkmate/internal/engine"
	"github.com/rtulke/checkmate/internal/facts"
	"github.com/rtulke/checkmate/internal/policy"
)

func rep(host string, score float64, results ...engine.Result) *engine.Report {
	return &engine.Report{Policy: "P", Facts: facts.Facts{Hostname: host}, Results: results,
		Summary: engine.Summary{Score: score}}
}

func res(id string, s engine.Status) engine.Result {
	return engine.Result{ID: id, Name: id, Status: s, Severity: "medium"}
}

func TestReportDiffClassifies(t *testing.T) {
	old := rep("a", 80, res("same", engine.StatusPass), res("broke", engine.StatusPass),
		res("fixed", engine.StatusFail), res("other", engine.StatusFail), res("gone", engine.StatusPass))
	old.Results = append(old.Results, res("accepted", engine.StatusFail))
	cur := rep("a", 70, res("same", engine.StatusPass), res("broke", engine.StatusError),
		res("fixed", engine.StatusPass), res("other", engine.StatusWarn), res("new", engine.StatusFail),
		res("accepted", engine.StatusWaived))
	d := Reports([]*engine.Report{old}, []*engine.Report{cur})
	h := d.Hosts[0]
	ids := func(list []StatusChange) string {
		var s []string
		for _, c := range list {
			s = append(s, c.ID)
		}
		return strings.Join(s, ",")
	}
	if ids(h.Regressions) != "broke" || ids(h.Fixed) != "fixed" || ids(h.Waived) != "accepted" || ids(h.Changed) != "other" ||
		ids(h.Added) != "new" || ids(h.Removed) != "gone" {
		t.Errorf("unexpected classification: %+v", h)
	}
	if d.Empty() || d.Regressions() != 1 {
		t.Error("diff must not be empty")
	}
	var b bytes.Buffer
	WriteReportText(&b, d, func(_, s string) string { return s })
	for _, want := range []string{"score 80.0% -> 70.0% (-10.0)", "New problems (1)", "PASS -> ERROR", "Removed checks (1)"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in\n%s", want, b.String())
		}
	}
}

func TestReportDiffPairsHosts(t *testing.T) {
	old := []*engine.Report{rep("a", 90), rep("b", 90)}
	cur := []*engine.Report{rep("b", 90), rep("c", 90)}
	d := Reports(old, cur)
	if len(d.Hosts) != 1 || len(d.OnlyOld) != 1 || len(d.OnlyNew) != 1 {
		t.Fatalf("unexpected pairing: %+v", d)
	}
	if !strings.HasPrefix(d.OnlyOld[0], "a ") || !strings.HasPrefix(d.OnlyNew[0], "c ") {
		t.Errorf("wrong hosts: %v %v", d.OnlyOld, d.OnlyNew)
	}
	same := Reports([]*engine.Report{rep("x", 50, res("a", engine.StatusPass))}, []*engine.Report{rep("x", 50, res("a", engine.StatusPass))})
	if !same.Empty() {
		t.Error("identical reports must have an empty diff")
	}
}

func writePolicy(t *testing.T, dir, name, body string) *policy.Policy {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := policy.Load(path, policy.LoadOptions{AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestPolicyDiff(t *testing.T) {
	dir := t.TempDir()
	old := writePolicy(t, dir, "old.yml", `
name: P
version: "1"
snippets:
  pkg: { rhel: "rpm -q {{ arg }}", debian: "dpkg -s {{ arg }}" }
checks:
  - { id: KEEP, run: "echo a", expect: "== a" }
  - { id: CHANGE, severity: low, run: "echo a", expect: "== a" }
  - { id: SNIP, run: { use: pkg, arg: sshd }, expect: "rc == 0" }
  - { id: GONE, run: "true", expect: "rc == 0" }
  - id: "L-{{ item }}"
    loop: [x, y]
    run: "echo {{ item }}"
    expect: "== {{ item }}"
`)
	cur := writePolicy(t, dir, "new.yml", `
name: P
version: "2"
snippets:
  pkg: { rhel: "rpm -q --quiet {{ arg }}", debian: "dpkg -s {{ arg }}" }
checks:
  - { id: KEEP, run: "echo a", expect: "== a" }
  - { id: CHANGE, severity: high, run: "echo b", expect: "== b" }
  - { id: SNIP, run: { use: pkg, arg: sshd }, expect: "rc == 0" }
  - { id: ADDED, run: "true", expect: "rc == 0" }
  - id: "L-{{ item }}"
    loop: [x, z]
    run: "echo {{ item }}"
    expect: "== {{ item }}"
`)
	d := Policies(old, cur, facts.Facts{OS: "linux"}, nil)
	if len(d.Policy) != 1 || d.Policy[0].Field != "version" {
		t.Errorf("policy fields: %+v", d.Policy)
	}
	refs := func(list []CheckRef) string {
		var s []string
		for _, c := range list {
			s = append(s, c.ID)
		}
		return strings.Join(s, ",")
	}
	if refs(d.Added) != "ADDED,L-z" || refs(d.Removed) != "GONE,L-y" {
		t.Errorf("added %s, removed %s", refs(d.Added), refs(d.Removed))
	}
	changed := map[string][]string{}
	for _, c := range d.Changed {
		for _, f := range c.Fields {
			changed[c.ID] = append(changed[c.ID], f.Field)
		}
	}
	if strings.Join(changed["CHANGE"], ",") != "severity,run,expect" {
		t.Errorf("CHANGE fields: %v", changed["CHANGE"])
	}
	if strings.Join(changed["SNIP"], ",") != "run" {
		t.Errorf("a changed snippet must show up in the check: %v", changed)
	}
	if _, ok := changed["KEEP"]; ok {
		t.Error("KEEP did not change")
	}
	var b bytes.Buffer
	WritePolicyText(&b, d, func(_, s string) string { return s })
	if !strings.Contains(b.String(), "- rpm -q sshd") || !strings.Contains(b.String(), "+ rpm -q --quiet sshd") {
		t.Errorf("line diff missing:\n%s", b.String())
	}
	if !Policies(old, old, facts.Facts{}, nil).Empty() {
		t.Error("a policy compared with itself must be empty")
	}
}

func TestLineDiff(t *testing.T) {
	got := lineDiff([]string{"a", "b", "c"}, []string{"a", "x", "c", "d"})
	var s []string
	for _, l := range got {
		s = append(s, string(l.op)+l.text)
	}
	if strings.Join(s, " ") != " a -b +x  c +d" {
		t.Errorf("got %q", strings.Join(s, " "))
	}
}
