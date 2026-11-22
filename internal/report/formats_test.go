package report

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rtulke/checkmate/internal/engine"
	"github.com/rtulke/checkmate/internal/facts"
)

// hostileReport has a waived check and output with markup, formulas and
// non-Latin text, as a check on a compromised host could produce.
func hostileReport(host string) *engine.Report {
	r := sampleReport()
	r.Facts.Hostname = host
	r.Started = time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)
	r.RunID = "0123456789abcdef"
	r.Results = append(r.Results,
		engine.Result{ID: "D-4", Name: "waived check", Status: engine.StatusWaived, Severity: "high",
			Message: "waived: accepted", Waiver: &engine.WaiverInfo{Reason: "accepted risk", Until: "2027-01-01",
				Source: "waivers.yml:3", Status: engine.StatusFail}},
		engine.Result{ID: "E/5 x", Name: "hostile <b>name</b>", Status: engine.StatusError, Severity: "low",
			Message: "=HYPERLINK(\"http://evil\")", Stdout: "<script>alert(1)</script> 日本語 €",
			Description: "STIG V-123456, CCI-000366."},
	)
	r.Summary = engine.Summarize(r.Results)
	r.Summary.FailOn = "low"
	return r
}

func renderFormat(t *testing.T, name string, rs ...*engine.Report) string {
	t.Helper()
	f, ok := LookupFormat(name)
	if !ok {
		t.Fatalf("no format %s", name)
	}
	var b bytes.Buffer
	if err := f.Write(&b, rs, Options{Version: "1.2.3", Now: time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)}); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return b.String()
}

func TestEveryFormatRendersOneAndSeveralReports(t *testing.T) {
	for _, f := range Formats {
		renderFormat(t, f.Name, hostileReport("a"))
		if f.Multi {
			out := renderFormat(t, f.Name, hostileReport("a"), hostileReport("b"))
			if out == "" {
				t.Errorf("%s: empty output", f.Name)
			}
		}
	}
}

func TestHTMLEscapesCheckOutput(t *testing.T) {
	out := renderFormat(t, "html", hostileReport("a"))
	for _, bad := range []string{"<script>alert(1)", "<b>name</b>"} {
		if strings.Contains(out, bad) {
			t.Errorf("HTML contains unescaped %q", bad)
		}
	}
	if !strings.Contains(out, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("escaped output missing")
	}
	if strings.Contains(out, "ZgotmplZ") {
		t.Error("template produced an unsafe-value placeholder")
	}
	if !strings.Contains(out, "accepted risk") {
		t.Error("waiver reason missing")
	}
}

func TestCSVNeutralizesFormulas(t *testing.T) {
	out := renderFormat(t, "csv", hostileReport("a"))
	rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 6 || rows[0][0] != "host" {
		t.Fatalf("unexpected rows: %v", rows)
	}
	for _, row := range rows {
		for _, cell := range row {
			if cell != "" && strings.ContainsRune("=+-@", rune(cell[0])) {
				t.Errorf("cell starts with a formula character: %q", cell)
			}
		}
	}
}

func TestPromMetrics(t *testing.T) {
	out := renderFormat(t, "prom", hostileReport("web\"1"))
	for _, want := range []string{
		`checkmate_compliant{policy="Test",host="web\"1"} 0`,
		`checkmate_checks{policy="Test",host="web\"1",status="waived"} 1`,
		`checkmate_failed_checks{policy="Test",host="web\"1",severity="critical"} 1`,
		`checkmate_check_problem{policy="Test",host="web\"1",id="B-22",severity="critical",status="fail"} 1`,
		`checkmate_last_run_timestamp_seconds{policy="Test",host="web\"1"} 1795341600`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s in\n%s", want, out)
		}
	}
	if strings.Contains(out, `id="A-1"`) {
		t.Error("passed checks must not get a per-check series")
	}
}

func TestJSONLAndSyslogMessages(t *testing.T) {
	out := renderFormat(t, "jsonl", hostileReport("a"))
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 6 {
		t.Fatalf("want 5 results and a summary, got %d lines", len(lines))
	}
	var last Event
	if err := json.Unmarshal([]byte(lines[5]), &last); err != nil || last.Event != "summary" || last.Summary == nil {
		t.Fatalf("last line is not a summary: %s", lines[5])
	}
	msgs := SyslogMessages([]*engine.Report{hostileReport("a")}, "1.2.3")
	if len(msgs) != 5 { // the skipped check is left out
		t.Fatalf("want 5 syslog messages, got %d", len(msgs))
	}
	sev := map[string]int{}
	for _, m := range msgs {
		var e Event
		json.Unmarshal([]byte(m.Text), &e)
		sev[e.ID+string(e.Event)] = m.Severity
	}
	if sev["B-22result"] != 2 || sev["A-1result"] != 6 || sev["summary"] != 4 {
		t.Errorf("unexpected severities: %v", sev)
	}
}

func TestXCCDF(t *testing.T) {
	out := renderFormat(t, "xccdf", hostileReport("a"), hostileReport("b"))
	var doc struct {
		Rules []struct {
			ID     string `xml:"id,attr"`
			Idents []struct {
				System string `xml:"system,attr"`
				Value  string `xml:",chardata"`
			} `xml:"ident"`
		} `xml:"Rule"`
		TestResults []struct {
			ID          string `xml:"id,attr"`
			RuleResults []struct {
				IDRef    string `xml:"idref,attr"`
				Result   string `xml:"result"`
				Override *struct {
					Old    string `xml:"old-result"`
					Remark string `xml:"remark"`
				} `xml:"override"`
			} `xml:"rule-result"`
		} `xml:"TestResult"`
	}
	if err := xml.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Rules) != 5 || len(doc.TestResults) != 2 {
		t.Fatalf("want 5 rules and 2 test results, got %d and %d", len(doc.Rules), len(doc.TestResults))
	}
	if got := doc.Rules[4].ID; got != "xccdf_io.github.rtulke.checkmate_rule_E_5_x" {
		t.Errorf("rule id not sanitized: %s", got)
	}
	if len(doc.Rules[4].Idents) != 2 {
		t.Errorf("want CCI and V- idents, got %v", doc.Rules[4].Idents)
	}
	results := map[string]string{}
	for _, rr := range doc.TestResults[0].RuleResults {
		results[rr.IDRef] = rr.Result
		if strings.HasSuffix(rr.IDRef, "D-4") && (rr.Override == nil || rr.Override.Old != "fail" || rr.Override.Remark != "accepted risk") {
			t.Errorf("waiver not recorded as override: %+v", rr.Override)
		}
	}
	want := map[string]string{"A-1": "pass", "B-22": "fail", "C-333": "notselected", "D-4": "pass", "E_5_x": "error"}
	for id, res := range want {
		if got := results["xccdf_io.github.rtulke.checkmate_rule_"+id]; got != res {
			t.Errorf("%s: want %s, got %s", id, res, got)
		}
	}
}

func TestARF(t *testing.T) {
	out := renderFormat(t, "arf", hostileReport("a"), hostileReport("b.example.org"))
	for _, want := range []string{
		`<arf:asset-report-collection xmlns:arf="http://scap.nist.gov/schema/asset-reporting-format/1.1"`,
		`<core:relationship type="arfvocab:isAbout" subject="xccdf2">`,
		`<ai:fqdn>b.example.org</ai:fqdn>`,
		`<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"`,
		`<TestResult xmlns="http://checklists.nist.gov/xccdf/1.2"`,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %s", want)
		}
	}
	if err := xml.Unmarshal([]byte(out), new(struct{})); err != nil {
		t.Errorf("not well-formed: %v", err)
	}
}

func TestJUnitSuitePerReport(t *testing.T) {
	out := renderFormat(t, "junit", hostileReport("a"), hostileReport("b"))
	if strings.Count(out, "<testsuite ") != 2 || !strings.Contains(out, `name="a: Test"`) {
		t.Errorf("want one suite per host:\n%s", out)
	}
}

func TestPDFIsWellFormed(t *testing.T) {
	out := renderFormat(t, "pdf", hostileReport("a"), hostileReport("b"))
	if !strings.HasPrefix(out, "%PDF-1.4") || !strings.HasSuffix(out, "%%EOF\n") {
		t.Fatal("missing PDF header or trailer")
	}
}

func TestReadReportsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	single := filepath.Join(dir, "a.json")
	multi := filepath.Join(dir, "all.json")
	os.WriteFile(single, []byte(renderFormat(t, "json", hostileReport("a"))), 0o600)
	os.WriteFile(multi, []byte(renderFormat(t, "json", hostileReport("a"), hostileReport("b"))), 0o600)

	rs, err := ReadReports(single)
	if err != nil || len(rs) != 1 || rs[0].Facts.Hostname != "a" || len(rs[0].Results) != 5 {
		t.Fatalf("single: %v %v", rs, err)
	}
	if rs[0].Results[3].Waiver == nil || rs[0].Version != "1.2.3" {
		t.Error("waiver or version lost")
	}
	rs, err = ReadReports(multi)
	if err != nil || len(rs) != 2 || rs[1].Facts.Hostname != "b" {
		t.Fatalf("multi: %v %v", rs, err)
	}
	bad := filepath.Join(dir, "bad.json")
	os.WriteFile(bad, []byte(`{"foo": 1}`), 0o600)
	if _, err := ReadReports(bad); err == nil {
		t.Error("a foreign JSON file must be rejected")
	}
}

func TestHostLabelsDisambiguate(t *testing.T) {
	a, b := hostileReport("web"), hostileReport("web")
	b.Policy = "Other"
	c := hostileReport("db")
	got := hostLabels([]*engine.Report{a, b, c})
	if got[0] != "web · Test" || got[1] != "web · Other" || got[2] != "db" {
		t.Errorf("unexpected labels %v", got)
	}
	_ = facts.Facts{}
}

func TestScope(t *testing.T) {
	a, b := hostileReport("web"), hostileReport("web")
	if got := scope([]*engine.Report{a, b}); got != "2 reports from 1 host" {
		t.Errorf("got %q", got)
	}
	if got := scope([]*engine.Report{a, hostileReport("db")}); got != "2 hosts" {
		t.Errorf("got %q", got)
	}
}
