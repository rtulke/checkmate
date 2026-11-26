package report

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/rtulke/checkmate/internal/engine"
	"github.com/rtulke/checkmate/internal/policy"
)

// Options apply to every output format; each format uses what it needs.
type Options struct {
	Version   string    // checkmate version
	Color     bool      // text: ANSI colors
	Verbosity int       // text: 0-3
	Quiet     bool      // text: only problems
	Width     int       // text: terminal width
	Now       time.Time // time the output is made (default: now)
}

func (o Options) now() time.Time {
	if o.Now.IsZero() {
		return time.Now()
	}
	return o.Now
}

// Format is an output format. Every format can render one report; Multi
// formats also render several reports (hosts or runs) as one document.
type Format struct {
	Name        string
	Ext         string // file extension used by exports, with the dot
	Multi       bool
	Binary      bool // not meant for a terminal
	Description string
	Write       func(w io.Writer, rs []*engine.Report, o Options) error
}

// Formats lists every output format in the order shown in help texts.
var Formats = []Format{
	{"text", ".txt", true, false, "human-readable report", writeText},
	{"json", ".json", true, false, "complete results; input for export and diff", writeJSON},
	{"jsonl", ".jsonl", true, false, "one JSON event per check, for log pipelines and SIEMs", writeJSONL},
	{"csv", ".csv", true, false, "one row per check and host, for spreadsheets", writeCSV},
	{"html", ".html", true, false, "self-contained, filterable report", writeHTML},
	{"pdf", ".pdf", true, true, "printable report", writePDF},
	{"junit", ".junit.xml", true, false, "JUnit XML for CI systems", writeJUnit},
	{"xccdf", ".xccdf.xml", true, false, "SCAP XCCDF 1.2 benchmark with test results", writeXCCDF},
	{"arf", ".arf.xml", true, false, "SCAP Asset Reporting Format 1.1", writeARF},
	{"prom", ".prom", true, false, "Prometheus metrics for the node_exporter textfile collector", writeProm},
	{"attack", ".attack.json", false, false, "MITRE ATT&CK Navigator layer of the attack-t* tagged checks", writeAttack},
}

// LookupFormat returns the format with the given name.
func LookupFormat(name string) (Format, bool) {
	for _, f := range Formats {
		if f.Name == name {
			return f, true
		}
	}
	return Format{}, false
}

// FormatNames returns the names of all formats, comma-separated.
func FormatNames() string {
	names := make([]string, len(Formats))
	for i, f := range Formats {
		names[i] = f.Name
	}
	return strings.Join(names, ", ")
}

func writeText(w io.Writer, rs []*engine.Report, o Options) error {
	// A single host that could not be checked has no results to list; the
	// overview says why.
	if len(rs) == 1 && rs[0].Error == "" {
		return Text(w, rs[0], TextOptions{Color: o.Color, Verbosity: o.Verbosity, Quiet: o.Quiet, Version: o.Version, Width: o.Width})
	}
	return TextOverview(w, rs, TextOptions{Color: o.Color, Version: o.Version})
}

func writeJSON(w io.Writer, rs []*engine.Report, o Options) error {
	if len(rs) == 1 {
		return JSON(w, rs[0], o.Version)
	}
	doc := struct {
		Tool    string           `json:"tool"`
		Version string           `json:"version"`
		Reports []*engine.Report `json:"reports"`
	}{"checkmate", o.Version, rs}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

func writeJUnit(w io.Writer, rs []*engine.Report, _ Options) error { return JUnit(w, rs...) }

func writeAttack(w io.Writer, rs []*engine.Report, o Options) error {
	if len(rs) != 1 {
		return fmt.Errorf("the attack format needs exactly one report")
	}
	return AttackLayer(w, rs[0], o.Version)
}

// ReadReports reads a JSON report written by checkmate: a single report or
// several reports written together (`"reports": [...]`).
func ReadReports(path string) ([]*engine.Report, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	return DecodeReports(fh, path)
}

// DecodeReports reads a JSON report from r; name is used in errors.
func DecodeReports(rd io.Reader, path string) ([]*engine.Report, error) {
	data, err := io.ReadAll(rd)
	if err != nil {
		return nil, err
	}
	var probe struct {
		Tool    string            `json:"tool"`
		Reports []json.RawMessage `json:"reports"`
		Results json.RawMessage   `json:"results"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, fmt.Errorf("%s: not a checkmate JSON report: %v", path, err)
	}
	if probe.Tool != "checkmate" && probe.Results == nil && probe.Reports == nil {
		return nil, fmt.Errorf("%s: not a checkmate JSON report", path)
	}
	if probe.Reports != nil {
		var rs []*engine.Report
		for i, raw := range probe.Reports {
			r, err := decodeReport(raw)
			if err != nil {
				return nil, fmt.Errorf("%s: report %d: %v", path, i+1, err)
			}
			rs = append(rs, r)
		}
		return rs, nil
	}
	r, err := decodeReport(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	return []*engine.Report{r}, nil
}

func decodeReport(data []byte) (*engine.Report, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	var r engine.Report
	if err := dec.Decode(&r); err != nil {
		return nil, err
	}
	if r.Results == nil {
		return nil, fmt.Errorf("no results")
	}
	return &r, nil
}

// --- helpers shared by the formats ---

// policyTitle returns the policy name, or its path if it has none.
func policyTitle(r *engine.Report) string {
	if r.Policy != "" {
		return r.Policy
	}
	return r.PolicyPath
}

// hostLabels returns a label per report: the hostname, extended by the
// policy where a host appears more than once.
// HostName is the name of the host of a report: its name in the inventory
// if the run had one, since that is how the user knows it, otherwise the
// host name the host reports.
func HostName(r *engine.Report) string {
	if r.Host != "" {
		return r.Host
	}
	return r.Facts.Hostname
}

func hostLabels(rs []*engine.Report) []string {
	count := map[string]int{}
	for _, r := range rs {
		count[HostName(r)]++
	}
	labels := make([]string, len(rs))
	seen := map[string]int{}
	for i, r := range rs {
		l := HostName(r)
		if l == "" {
			l = "unknown host"
		}
		if count[HostName(r)] > 1 {
			l += " · " + policyTitle(r)
		}
		seen[l]++
		if seen[l] > 1 {
			l += fmt.Sprintf(" (%d)", seen[l])
		}
		labels[i] = l
	}
	return labels
}

// documentTitle names a set of reports, e.g. for an HTML or PDF title.
func documentTitle(rs []*engine.Report) string {
	titles := map[string]bool{}
	var order []string
	for _, r := range rs {
		t := policyTitle(r)
		if r.PolicyVersion != "" {
			t += " v" + r.PolicyVersion
		}
		if !titles[t] {
			titles[t] = true
			order = append(order, t)
		}
	}
	if len(order) == 1 {
		return order[0]
	}
	return fmt.Sprintf("%d policies", len(order))
}

// scope describes a set of reports, e.g. "3 hosts" or "2 reports from 1 host".
func scope(rs []*engine.Report) string {
	hosts := map[string]bool{}
	for _, r := range rs {
		hosts[HostName(r)] = true
	}
	plural := func(n int, word string) string {
		if n == 1 {
			return fmt.Sprintf("1 %s", word)
		}
		return fmt.Sprintf("%d %ss", n, word)
	}
	if len(hosts) == len(rs) {
		return plural(len(hosts), "host")
	}
	return plural(len(rs), "report") + " from " + plural(len(hosts), "host")
}

// checkRow is one check across several reports.
type checkRow struct {
	ID       string
	Name     string
	Severity string
	Tags     []string
	Results  []*engine.Result // per report; nil where the check is missing
}

// worst returns the most important status of the row.
func (c checkRow) worst() engine.Status {
	best := engine.Status("")
	for _, r := range c.Results {
		if r != nil && statusRank(r.Status) > statusRank(best) {
			best = r.Status
		}
	}
	return best
}

// statusRank orders statuses by how much attention they need.
func statusRank(s engine.Status) int {
	switch s {
	case engine.StatusError:
		return 7
	case engine.StatusFail:
		return 6
	case engine.StatusWarn:
		return 5
	case engine.StatusWaived:
		return 4
	case engine.StatusPass:
		return 3
	case engine.StatusSkip:
		return 2
	case engine.StatusNA:
		return 1
	}
	return 0
}

// checkRows merges the results of several reports by check ID, in the
// order the checks first appear.
func checkRows(rs []*engine.Report) []checkRow {
	index := map[string]int{}
	var rows []checkRow
	for i, r := range rs {
		for j := range r.Results {
			res := &r.Results[j]
			k, ok := index[res.ID]
			if !ok {
				k = len(rows)
				index[res.ID] = k
				rows = append(rows, checkRow{ID: res.ID, Name: res.Name, Severity: res.Severity, Tags: res.Tags,
					Results: make([]*engine.Result, len(rs))})
			}
			rows[k].Results[i] = res
		}
	}
	return rows
}

// problemRows returns the rows with a problem on at least one host, most
// severe first.
func problemRows(rows []checkRow) []checkRow {
	var out []checkRow
	for _, row := range rows {
		if isProblem(row.worst()) {
			out = append(out, row)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := policy.SeverityRank(out[i].Severity), policy.SeverityRank(out[j].Severity)
		if si != sj {
			return si > sj
		}
		return statusRank(out[i].worst()) > statusRank(out[j].worst())
	})
	return out
}

// aggregate sums the results of several reports.
// unchecked counts the hosts that could not be checked.
func unchecked(rs []*engine.Report) int {
	n := 0
	for _, r := range rs {
		if r.Error != "" {
			n++
		}
	}
	return n
}

// aggregate sums up the hosts that were checked. Hosts that could not be
// checked say nothing about compliance in either direction and are left
// out; see unchecked.
func aggregate(rs []*engine.Report) engine.Summary {
	if len(rs) == 1 {
		return rs[0].Summary
	}
	var all []engine.Result
	compliant := len(rs) > unchecked(rs)
	for _, r := range rs {
		if r.Error != "" {
			continue
		}
		all = append(all, r.Results...)
		compliant = compliant && r.Summary.Compliant
	}
	s := engine.Summarize(all)
	s.Compliant = compliant
	return s
}

// clip shortens s to at most n bytes at a rune boundary and says so.
func clip(s string, n int) string {
	s = strings.TrimRight(s, "\n")
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + fmt.Sprintf("\n… (%d more bytes)", len(s)-cut)
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

// scoreText formats a score; -1 means nothing was evaluated.
func scoreText(score float64) string {
	if score < 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", score)
}

// waiverOrigin is the status a waived check would have had.
func waiverOrigin(res *engine.Result) string {
	if res.Waiver == nil {
		return ""
	}
	if res.Waiver.Status == "" {
		return "not run"
	}
	return string(res.Waiver.Status)
}
