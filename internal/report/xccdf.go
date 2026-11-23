package report

import (
	"encoding/xml"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/rtulke/checkmate/internal/engine"
	"github.com/rtulke/checkmate/internal/policy"
)

// XCCDF 1.2 and ARF 1.1 output. checkmate has no SCAP source content, so the
// XCCDF document is generated from the results: a Benchmark with one Rule
// per check and one TestResult per report. ARF wraps the same Benchmark (as
// the report request) and the TestResults (as reports about each asset).

const (
	xccdfNS      = "http://checklists.nist.gov/xccdf/1.2"
	xccdfIDSpace = "io.github.rtulke.checkmate"
	cciSystem    = "http://cyber.mil/cci"
	stigSystem   = "http://cyber.mil/legacy"
	dcNS         = "http://purl.org/dc/elements/1.1/"
	checkSystem  = "urn:checkmate:command"
)

type xccdfBenchmark struct {
	XMLName     xml.Name           `xml:"Benchmark"`
	Xmlns       string             `xml:"xmlns,attr,omitempty"`
	ID          string             `xml:"id,attr"`
	Resolved    string             `xml:"resolved,attr"`
	Lang        string             `xml:"xml:lang,attr"`
	Status      xccdfStatus        `xml:"status"`
	Title       string             `xml:"title"`
	Description string             `xml:"description,omitempty"`
	Version     string             `xml:"version"`
	Metadata    xccdfMetadata      `xml:"metadata"`
	Rules       []xccdfRule        `xml:"Rule"`
	TestResults []*xccdfTestResult `xml:"TestResult"`
}

type xccdfMetadata struct {
	Creator   dcElement `xml:"dc:creator"`
	Publisher dcElement `xml:"dc:publisher"`
	Source    dcElement `xml:"dc:source"`
}

type dcElement struct {
	Xmlns string `xml:"xmlns:dc,attr"`
	Value string `xml:",chardata"`
}

type xccdfStatus struct {
	Date  string `xml:"date,attr"`
	Value string `xml:",chardata"`
}

type xccdfRule struct {
	ID          string          `xml:"id,attr"`
	Selected    bool            `xml:"selected,attr"`
	Severity    string          `xml:"severity,attr"`
	Weight      string          `xml:"weight,attr"`
	Title       string          `xml:"title"`
	Description string          `xml:"description,omitempty"`
	Reference   []string        `xml:"reference,omitempty"`
	Rationale   string          `xml:"rationale,omitempty"`
	Idents      []xccdfIdent    `xml:"ident"`
	Fixtext     string          `xml:"fixtext,omitempty"`
	Check       *xccdfCheckLink `xml:"check,omitempty"`
}

type xccdfIdent struct {
	System string `xml:"system,attr"`
	Value  string `xml:",chardata"`
}

type xccdfTestResult struct {
	XMLName     xml.Name          `xml:"TestResult"`
	Xmlns       string            `xml:"xmlns,attr,omitempty"`
	ID          string            `xml:"id,attr"`
	StartTime   string            `xml:"start-time,attr"`
	EndTime     string            `xml:"end-time,attr"`
	TestSystem  string            `xml:"test-system,attr"`
	Version     string            `xml:"version,attr"`
	Benchmark   *xccdfBenchRef    `xml:"benchmark,omitempty"`
	Title       string            `xml:"title"`
	Identity    *xccdfIdentity    `xml:"identity,omitempty"`
	Target      string            `xml:"target"`
	TargetFacts []xccdfFact       `xml:"target-facts>fact"`
	RuleResults []xccdfRuleResult `xml:"rule-result"`
	Scores      []xccdfScore      `xml:"score"`
}

type xccdfBenchRef struct {
	Href string `xml:"href,attr"`
	ID   string `xml:"id,attr"`
}

type xccdfIdentity struct {
	Authenticated bool   `xml:"authenticated,attr"`
	Privileged    bool   `xml:"privileged,attr"`
	Value         string `xml:",chardata"`
}

type xccdfFact struct {
	Name  string `xml:"name,attr"`
	Type  string `xml:"type,attr"`
	Value string `xml:",chardata"`
}

type xccdfRuleResult struct {
	IDRef    string          `xml:"idref,attr"`
	Role     string          `xml:"role,attr"`
	Time     string          `xml:"time,attr"`
	Severity string          `xml:"severity,attr"`
	Weight   string          `xml:"weight,attr"`
	Result   string          `xml:"result"`
	Override *xccdfOverride  `xml:"override,omitempty"`
	Idents   []xccdfIdent    `xml:"ident"`
	Messages []xccdfMessage  `xml:"message"`
	Check    *xccdfCheckLink `xml:"check,omitempty"`
}

type xccdfOverride struct {
	Time      string `xml:"time,attr"`
	Authority string `xml:"authority,attr"`
	OldResult string `xml:"old-result"`
	NewResult string `xml:"new-result"`
	Remark    string `xml:"remark"`
}

type xccdfMessage struct {
	Severity string `xml:"severity,attr"`
	Value    string `xml:",chardata"`
}

type xccdfCheckLink struct {
	System  string `xml:"system,attr"`
	Content string `xml:"check-content"`
}

type xccdfScore struct {
	System  string `xml:"system,attr"`
	Maximum string `xml:"maximum,attr"`
	Value   string `xml:",chardata"`
}

var (
	cciRe     = regexp.MustCompile(`\bCCI-\d{6}\b`)
	vulnIDRe  = regexp.MustCompile(`\bV-\d{4,}\b`)
	idCleanRe = regexp.MustCompile(`[^A-Za-z0-9._-]`)
)

// xccdfID builds an XCCDF 1.2 identifier, e.g. xccdf_io.github.rtulke.checkmate_rule_SSH-001.
func xccdfID(kind, name string) string {
	name = idCleanRe.ReplaceAllString(name, "_")
	if name == "" {
		name = "unnamed"
	}
	return fmt.Sprintf("xccdf_%s_%s_%s", xccdfIDSpace, kind, name)
}

// xccdfSeverity maps checkmate severities; XCCDF has no "critical".
func xccdfSeverity(s string) string {
	switch s {
	case "info", "low", "medium", "high":
		return s
	case "critical":
		return "high"
	}
	return "unknown"
}

// xccdfResult maps a checkmate status. Warnings are failures below the
// fail_on threshold, so they are failures in XCCDF.
func xccdfResult(s engine.Status) string {
	switch s {
	case engine.StatusPass:
		return "pass"
	case engine.StatusFail, engine.StatusWarn:
		return "fail"
	case engine.StatusError:
		return "error"
	case engine.StatusSkip:
		return "notselected"
	case engine.StatusNA:
		return "notapplicable"
	}
	return "unknown"
}

func idents(res *engine.Result) []xccdfIdent {
	var out []xccdfIdent
	seen := map[string]bool{}
	add := func(system, v string) {
		if !seen[v] {
			seen[v] = true
			out = append(out, xccdfIdent{system, v})
		}
	}
	for _, v := range cciRe.FindAllString(res.Description, -1) {
		add(cciSystem, v)
	}
	for _, v := range vulnIDRe.FindAllString(res.Description, -1) {
		add(stigSystem, v)
	}
	return out
}

func xccdfDocument(rs []*engine.Report, o Options) *xccdfBenchmark {
	title := documentTitle(rs)
	version := "1"
	if len(rs) == 1 && rs[0].PolicyVersion != "" {
		version = rs[0].PolicyVersion
	}
	b := &xccdfBenchmark{
		Xmlns:    xccdfNS,
		ID:       xccdfID("benchmark", title),
		Resolved: "1",
		Lang:     "en",
		Status:   xccdfStatus{Date: o.now().Format("2006-01-02"), Value: "accepted"},
		Title:    title,
		Version:  version,
		Metadata: xccdfMetadata{
			Creator:   dcElement{dcNS, "checkmate " + o.Version},
			Publisher: dcElement{dcNS, "checkmate"},
			Source:    dcElement{dcNS, "https://github.com/rtulke/checkmate"},
		},
	}
	if len(rs) == 1 {
		b.Description = "Generated by checkmate from the results of " + rs[0].PolicyPath
	}
	for _, row := range checkRows(rs) {
		var res *engine.Result
		for _, r := range row.Results {
			if r != nil {
				res = r
				break
			}
		}
		rule := xccdfRule{
			ID:          xccdfID("rule", row.ID),
			Selected:    true,
			Severity:    xccdfSeverity(res.Severity),
			Weight:      fmt.Sprint(policy.SeverityWeight(res.Severity)),
			Title:       res.Name,
			Description: res.Description,
			Idents:      idents(res),
			Rationale:   res.Rationale,
			Fixtext:     res.Remediation,
		}
		if res.Reference != "" {
			rule.Reference = []string{res.Reference}
		}
		for _, r := range row.Results {
			if r != nil && r.Command != "" {
				rule.Check = &xccdfCheckLink{System: checkSystem, Content: r.Command}
				break
			}
		}
		b.Rules = append(b.Rules, rule)
	}
	labels := hostLabels(rs)
	for i, r := range rs {
		b.TestResults = append(b.TestResults, xccdfTestResultFor(r, labels[i], o))
	}
	return b
}

func xccdfTestResultFor(r *engine.Report, label string, o Options) *xccdfTestResult {
	start := r.Started.UTC()
	end := start.Add(time.Duration(r.DurationMS) * time.Millisecond)
	stamp := func(t time.Time) string { return t.Format("2006-01-02T15:04:05") }
	name := label
	if r.RunID != "" {
		name += "_" + r.RunID
	}
	tr := &xccdfTestResult{
		ID:         xccdfID("testresult", name),
		StartTime:  stamp(start),
		EndTime:    stamp(end),
		TestSystem: "cpe:/a:rtulke:checkmate:" + firstNonEmpty(r.Version, o.Version),
		Version:    firstNonEmpty(r.PolicyVersion, "1"),
		Title:      "checkmate: " + policyTitle(r) + " on " + r.Facts.Hostname,
		Target:     firstNonEmpty(r.Facts.Hostname, "unknown"),
	}
	if r.Facts.IsRoot {
		account := "root"
		if r.Facts.OS == "windows" {
			account = "Administrators"
		}
		tr.Identity = &xccdfIdentity{Authenticated: true, Privileged: true, Value: account}
	}
	fact := func(name, value string) {
		if value != "" {
			tr.TargetFacts = append(tr.TargetFacts, xccdfFact{"urn:xccdf:fact:" + name, "string", value})
		}
	}
	fact("asset:identifier:host_name", r.Facts.Hostname)
	fact("asset:identifier:os_name", r.Facts.DistroName)
	fact("asset:identifier:os_version", r.Facts.Version)
	fact("ethernet:kernel", r.Facts.Kernel)

	var earned, maximum float64
	for i := range r.Results {
		res := &r.Results[i]
		rr := xccdfRuleResult{
			IDRef:    xccdfID("rule", res.ID),
			Role:     "full",
			Time:     stamp(start),
			Severity: xccdfSeverity(res.Severity),
			Weight:   fmt.Sprint(policy.SeverityWeight(res.Severity)),
			Result:   xccdfResult(res.Status),
			Idents:   idents(res),
		}
		if res.Status == engine.StatusWaived && res.Waiver != nil {
			// A waiver is an XCCDF override: the result is accepted, the
			// original result and the reason are kept.
			old := "notchecked"
			if res.Waiver.Status != "" {
				old = xccdfResult(res.Waiver.Status)
			}
			if res.Waiver.Status == "" {
				rr.Result = "notchecked"
			} else {
				rr.Result = "pass"
				rr.Override = &xccdfOverride{Time: stamp(start), Authority: res.Waiver.Source,
					OldResult: old, NewResult: "pass", Remark: res.Waiver.Reason}
			}
		}
		if res.Message != "" {
			sev := "info"
			if isProblem(res.Status) {
				sev = "warning"
			}
			if res.Status == engine.StatusError {
				sev = "error"
			}
			rr.Messages = append(rr.Messages, xccdfMessage{sev, res.Message})
		}
		if res.Command != "" {
			rr.Check = &xccdfCheckLink{System: checkSystem, Content: res.Command}
		}
		// Flat scoring as defined by XCCDF: passed weight out of the weight
		// of all rules that passed, failed or errored.
		w := float64(policy.SeverityWeight(res.Severity))
		switch rr.Result {
		case "pass":
			earned += w
			maximum += w
		case "fail", "error", "unknown":
			maximum += w
		}
		tr.RuleResults = append(tr.RuleResults, rr)
	}
	tr.Scores = []xccdfScore{
		{System: "urn:xccdf:scoring:flat", Maximum: fmt.Sprintf("%g", maximum), Value: fmt.Sprintf("%g", earned)},
	}
	if r.Summary.Score >= 0 {
		tr.Scores = append(tr.Scores, xccdfScore{System: "urn:checkmate:scoring:weighted", Maximum: "100",
			Value: fmt.Sprintf("%g", r.Summary.Score)})
	}
	return tr
}

func writeXMLDoc(w io.Writer, doc any) error {
	if _, err := io.WriteString(w, xml.Header); err != nil {
		return err
	}
	enc := xml.NewEncoder(w)
	enc.Indent("", "  ")
	if err := enc.Encode(doc); err != nil {
		return err
	}
	_, err := io.WriteString(w, "\n")
	return err
}

func writeXCCDF(w io.Writer, rs []*engine.Report, o Options) error {
	return writeXMLDoc(w, xccdfDocument(rs, o))
}

// --- ARF 1.1 ---

type arfCollection struct {
	XMLName       xml.Name         `xml:"arf:asset-report-collection"`
	XmlnsARF      string           `xml:"xmlns:arf,attr"`
	XmlnsCore     string           `xml:"xmlns:core,attr"`
	XmlnsAI       string           `xml:"xmlns:ai,attr"`
	Relationships arfRelationships `xml:"core:relationships"`
	Requests      []arfRequest     `xml:"arf:report-requests>arf:report-request"`
	Assets        []arfAsset       `xml:"arf:assets>arf:asset"`
	Reports       []arfReport      `xml:"arf:reports>arf:report"`
}

type arfRelationships struct {
	XmlnsVocab    string            `xml:"xmlns:arfvocab,attr"`
	Relationships []arfRelationship `xml:"core:relationship"`
}

type arfRelationship struct {
	Type    string `xml:"type,attr"`
	Subject string `xml:"subject,attr"`
	Ref     string `xml:"core:ref"`
}

type arfRequest struct {
	ID      string          `xml:"id,attr"`
	Content *xccdfBenchmark `xml:"arf:content>Benchmark"`
}

type arfAsset struct {
	ID     string    `xml:"id,attr"`
	Device arfDevice `xml:"ai:computing-device"`
}

type arfDevice struct {
	FQDN     string `xml:"ai:fqdn,omitempty"`
	Hostname string `xml:"ai:hostname,omitempty"`
}

type arfReport struct {
	ID      string           `xml:"id,attr"`
	Content *xccdfTestResult `xml:"arf:content>TestResult"`
}

func writeARF(w io.Writer, rs []*engine.Report, o Options) error {
	bench := xccdfDocument(rs, o)
	results := bench.TestResults
	bench.TestResults = nil
	doc := arfCollection{
		XmlnsARF:      "http://scap.nist.gov/schema/asset-reporting-format/1.1",
		XmlnsCore:     "http://scap.nist.gov/schema/reporting-core/1.1",
		XmlnsAI:       "http://scap.nist.gov/schema/asset-identification/1.1",
		Relationships: arfRelationships{XmlnsVocab: "http://scap.nist.gov/specifications/arf/vocabulary/relationships/1.0#"},
		Requests:      []arfRequest{{ID: "collection1", Content: bench}},
	}
	for i, tr := range results {
		tr.Xmlns = xccdfNS
		tr.Benchmark = &xccdfBenchRef{Href: "#collection1", ID: bench.ID}
		asset := fmt.Sprintf("asset%d", i+1)
		report := fmt.Sprintf("xccdf%d", i+1)
		host := rs[i].Facts.Hostname
		dev := arfDevice{Hostname: host}
		if strings.Contains(host, ".") {
			dev.FQDN = host
		}
		doc.Assets = append(doc.Assets, arfAsset{ID: asset, Device: dev})
		doc.Reports = append(doc.Reports, arfReport{ID: report, Content: tr})
		doc.Relationships.Relationships = append(doc.Relationships.Relationships,
			arfRelationship{Type: "arfvocab:createdFor", Subject: report, Ref: "collection1"},
			arfRelationship{Type: "arfvocab:isAbout", Subject: report, Ref: asset})
	}
	return writeXMLDoc(w, doc)
}
