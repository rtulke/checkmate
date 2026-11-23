package main

// DISA STIG texts. The goss audits of ansible-lockdown carry the STIG IDs
// but not the texts of the rules. The rationale (VulnDiscussion) and the
// fix text of every rule are read from the manual XCCDF benchmark that DISA
// publishes for each STIG.

import (
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// disaRule holds the texts of one STIG rule.
type disaRule struct {
	VulID     string // V-257784
	RuleID    string // SV-257784r1262100_rule
	StigID    string // RHEL-09-211045
	Rationale string
	Fix       string
}

// disaBenchmark is a parsed DISA XCCDF benchmark.
type disaBenchmark struct {
	Release string // V2R10
	Date    string // 30 Sep 2026
	byVulID map[string]*disaRule
	byStig  map[string]*disaRule
}

type xccdfBenchmark struct {
	Version   string `xml:"version"`
	PlainText []struct {
		ID   string `xml:"id,attr"`
		Text string `xml:",chardata"`
	} `xml:"plain-text"`
	Groups []struct {
		ID   string `xml:"id,attr"`
		Rule struct {
			ID          string `xml:"id,attr"`
			Version     string `xml:"version"`
			Description string `xml:"description"`
			Fixtext     string `xml:"fixtext"`
		} `xml:"Rule"`
	} `xml:"Group"`
}

var (
	vulnDiscussion = regexp.MustCompile(`(?s)<VulnDiscussion>(.*?)</VulnDiscussion>`)
	releaseInfo    = regexp.MustCompile(`Release:\s*(\d+)\s+Benchmark Date:\s*(.+)`)
	satisfies      = regexp.MustCompile(`(?s)\n\s*Satisfies:[^\n]*\s*$`)
)

// loadDISA reads a DISA manual XCCDF benchmark (U_*_Manual-xccdf.xml).
func loadDISA(path string) (*disaBenchmark, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var x xccdfBenchmark
	if err := xml.Unmarshal(data, &x); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	b := &disaBenchmark{byVulID: map[string]*disaRule{}, byStig: map[string]*disaRule{}}
	for _, p := range x.PlainText {
		if p.ID != "release-info" {
			continue
		}
		if m := releaseInfo.FindStringSubmatch(p.Text); m != nil {
			b.Release = fmt.Sprintf("V%sR%s", strings.TrimSpace(x.Version), m[1])
			b.Date = strings.TrimSpace(m[2])
		}
	}
	if b.Release == "" {
		return nil, fmt.Errorf("%s: no release information, not a DISA STIG benchmark", path)
	}
	for _, g := range x.Groups {
		r := &disaRule{
			VulID:  strings.TrimSpace(g.ID),
			RuleID: strings.TrimSpace(g.Rule.ID),
			StigID: strings.TrimSpace(g.Rule.Version),
			Fix:    cleanText(g.Rule.Fixtext),
		}
		if m := vulnDiscussion.FindStringSubmatch(g.Rule.Description); m != nil {
			// The trailing "Satisfies: SRG-..." list names related SRG
			// requirements; it explains nothing and is left out.
			r.Rationale = cleanText(satisfies.ReplaceAllString(m[1], ""))
		}
		if r.VulID == "" || (r.Rationale == "" && r.Fix == "") {
			continue
		}
		b.byVulID[r.VulID] = r
		if r.StigID != "" {
			b.byStig[r.StigID] = r
		}
	}
	if len(b.byVulID) == 0 {
		return nil, fmt.Errorf("%s: no STIG rules found", path)
	}
	return b, nil
}

// lookup finds the texts of a rule by its STIG ID, the key of the audit
// content, and by the vulnerability ID if the STIG ID is unknown. conflict
// is set if the vulnerability ID names a different rule (a typo upstream).
// exact reports whether the rule revision is the same as in the audit.
func (b *disaBenchmark) lookup(m ruleMeta) (r *disaRule, exact bool, conflict string) {
	byStig := b.byStig[strings.TrimSpace(m.CISID)]
	byVul := b.byVulID[strings.TrimSpace(m.VulID)]
	r = byStig
	if r == nil {
		r = byVul
	} else if byVul != nil && byVul != r {
		conflict = fmt.Sprintf("%s names %s, but %s is %s", m.VulID, byVul.StigID, m.CISID, r.VulID)
	}
	if r == nil {
		return nil, false, conflict
	}
	return r, strings.TrimSpace(m.RuleID) == r.RuleID, conflict
}

// cleanText normalizes line endings and whitespace of a text block.
func cleanText(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\r", "\n")
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t")
	}
	s = strings.Join(lines, "\n")
	for strings.Contains(s, "\n\n\n") {
		s = strings.ReplaceAll(s, "\n\n\n", "\n\n")
	}
	return strings.TrimSpace(s)
}
