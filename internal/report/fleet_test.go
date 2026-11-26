package report

import (
	"strings"
	"testing"
	"time"

	"github.com/rtulke/checkmate/internal/engine"
	"github.com/rtulke/checkmate/internal/facts"
)

// fleet is what a run with an inventory returns: two checked hosts in
// groups and one that did not answer.
func fleet() []*engine.Report {
	good := hostileReport("ip-10-0-0-1")
	good.Host, good.Groups = "web01.example.net", []string{"web", "eu"}
	clean := sampleReport()
	clean.Results = clean.Results[:1]
	clean.Results[0].Status = engine.StatusPass
	clean.Summary = engine.Summarize(clean.Results)
	clean.Host, clean.Groups = "db01.example.net", []string{"db", "eu"}
	down := &engine.Report{
		Tool: "checkmate", Policy: good.Policy, Facts: facts.Facts{Hostname: "db02.example.net"},
		Started: time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC), Summary: engine.Summary{Score: -1},
		Results: []engine.Result{}, Host: "db02.example.net", Groups: []string{"db"},
		Error: "host is not reachable over SSH: connection <timed> out", Unreachable: true,
	}
	return []*engine.Report{good, clean, down}
}

func TestEveryFormatRendersAFleet(t *testing.T) {
	for _, f := range Formats {
		if !f.Multi {
			continue
		}
		if out := renderFormat(t, f.Name, fleet()...); out == "" {
			t.Errorf("%s: empty output", f.Name)
		}
		// Only hosts that could not be checked.
		renderFormat(t, f.Name, fleet()[2])
		renderFormat(t, f.Name, fleet()[2], fleet()[2])
	}
}

func TestUncheckedHostsSayNothingAboutCompliance(t *testing.T) {
	rs := fleet()
	checked := []*engine.Report{rs[0], rs[1]}
	if got, want := aggregate(rs), aggregate(checked); got != want {
		t.Errorf("totals change with an unchecked host:\n got %+v\nwant %+v", got, want)
	}
	if s := aggregate([]*engine.Report{rs[1], rs[2]}); !s.Compliant {
		t.Error("an unchecked host makes the checked ones non-compliant")
	}
	if s := aggregate([]*engine.Report{rs[2], rs[2]}); s.Compliant {
		t.Error("hosts nobody checked are reported as compliant")
	}

	text := renderFormat(t, "text", rs...)
	for _, want := range []string{"db02.example.net", "unreachable: host is not reachable", "1 of 3 hosts could not be checked",
		"GROUP", "web01.example.net"} {
		if !strings.Contains(text, want) {
			t.Errorf("text lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "ip-10-0-0-1") {
		t.Errorf("text uses the reported host name instead of the inventory name:\n%s", text)
	}

	prom := renderFormat(t, "prom", rs...)
	for _, want := range []string{
		`checkmate_host_checked{policy="Sample",host="web01.example.net"} 1`,
		`checkmate_host_checked{policy="Sample",host="db02.example.net"} 0`,
		`checkmate_compliant{policy="Sample",host="db01.example.net"} 1`,
	} {
		if !strings.Contains(prom, strings.ReplaceAll(want, "Sample", policyTitle(rs[0]))) {
			t.Errorf("prom lacks %s", want)
		}
	}
	for _, line := range strings.Split(prom, "\n") {
		if strings.Contains(line, `host="db02.example.net"`) && !strings.HasPrefix(line, "checkmate_host_checked") {
			t.Errorf("prom claims to know something about an unchecked host: %s", line)
		}
	}

	csv := renderFormat(t, "csv", rs...)
	if !strings.Contains(csv, "db02.example.net,,,") || !strings.Contains(csv, ",UNREACHABLE,") {
		t.Errorf("csv has no row for the unchecked host:\n%s", csv)
	}
	if n := strings.Count(csv, "db02.example.net"); n != 1 {
		t.Errorf("csv: %d rows for the unchecked host", n)
	}

	jsonl := renderFormat(t, "jsonl", rs...)
	if !strings.Contains(jsonl, `"event":"unchecked"`) || !strings.Contains(jsonl, `"groups":["db","eu"]`) {
		t.Errorf("jsonl:\n%s", jsonl)
	}
	for _, line := range strings.Split(jsonl, "\n") {
		if strings.Contains(line, `"host":"db02.example.net"`) && strings.Contains(line, `"summary"`) {
			t.Errorf("jsonl has a summary for an unchecked host: %s", line)
		}
	}
	for _, m := range SyslogMessages(rs[2:], "1.2.3") {
		if m.Severity != 3 {
			t.Errorf("syslog severity %d for an unchecked host", m.Severity)
		}
	}

	junit := renderFormat(t, "junit", rs...)
	if !strings.Contains(junit, `hostname="db02.example.net" tests="1" failures="0" errors="1"`) ||
		!strings.Contains(junit, `<error message="unreachable">`) {
		t.Errorf("junit:\n%s", junit)
	}

	// SCAP documents hold test results; a host without any is left out.
	for _, name := range []string{"xccdf", "arf"} {
		if out := renderFormat(t, name, rs...); strings.Contains(out, "db02.example.net") || !strings.Contains(out, "db01.example.net") {
			t.Errorf("%s: unchecked host listed, or checked host missing", name)
		}
	}

	html := renderFormat(t, "html", rs...)
	for _, want := range []string{"UNREACHABLE", "connection &lt;timed&gt; out", "1 of 3 hosts could not be checked",
		"<h2>Groups</h2>", "web, eu"} {
		if !strings.Contains(html, want) {
			t.Errorf("html lacks %q", want)
		}
	}
	if strings.Contains(html, "<timed>") {
		t.Error("html does not escape the error text")
	}
	if strings.Count(html, `<th title="`) != 2 {
		t.Errorf("html: the check table has %d host columns, want one per checked host", strings.Count(html, `<th title="`))
	}
}

func TestGroupRows(t *testing.T) {
	rows := groupRows(fleet())
	type row struct {
		name                                      string
		hosts, compliant, notCompliant, unchecked int
	}
	var got []row
	for _, g := range rows {
		got = append(got, row{g.Name, g.Hosts, g.Compliant, g.NotCompliant, g.Unchecked})
	}
	want := []row{{"web", 1, 0, 1, 0}, {"eu", 2, 1, 1, 0}, {"db", 2, 1, 0, 1}}
	if len(got) != len(want) {
		t.Fatalf("groups %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("group %d: %+v, want %+v", i, got[i], want[i])
		}
	}
	if rows[2].Summary.Score != 100 {
		t.Errorf("score of db counts the unchecked host: %v", rows[2].Summary.Score)
	}
	if len(groupRows([]*engine.Report{hostileReport("a"), hostileReport("b")})) != 0 {
		t.Error("groups without an inventory")
	}
}
