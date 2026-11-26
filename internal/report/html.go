package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"strings"
	"time"

	"github.com/rtulke/checkmate/internal/engine"
	"github.com/rtulke/checkmate/internal/policy"
)

//go:embed html.tmpl
var htmlTemplate string

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"lower": strings.ToLower,
}).Parse(htmlTemplate))

// Output of commands is shortened in HTML and PDF reports; JSON keeps it all.
const detailLimit = 4000

type htmlView struct {
	Title     string
	Subtitle  string
	Generated string
	Version   string
	Multi     bool
	Score     string
	ScoreNum  float64
	ScoreCls  string
	Verdict   string
	VerdictCl string
	Counts    []htmlCount
	BySev     []htmlSev
	Hosts     []htmlHost
	Groups    []htmlGroup
	Unchecked int
	Labels    []string
	Rows      []htmlRow
	Waivers   []htmlWaiver
	Notices   []string
	Total     int
	Scope     string
}

type htmlCount struct {
	Label, Status, Class string
	N                    int
}

type htmlSev struct {
	Severity string
	N        int
	Pct      int
}

type htmlGroup struct {
	Name                                      string
	Hosts, Compliant, NotCompliant, Unchecked int
	Score, ScoreCls                           string
}

type htmlHost struct {
	Groups, Error                                          string // inventory groups; why the host was not checked
	Unchecked                                              bool
	Label, Distro, Kernel, Arch, Policy, Started, Duration string
	Score, ScoreCls, Verdict, VerdictCl                    string
	Summary                                                engine.Summary
}

type htmlRow struct {
	ID, Name, Severity, Tags string
	Worst, WorstCls          string
	Statuses, Search         string
	Cells                    []htmlCell
	Details                  []htmlDetail
}

type htmlCell struct{ Status, Class string }

type htmlDetail struct {
	Host, Status, Class                   string
	Description, Rationale                string
	Message, Expected                     string
	Command, OnlyIf, Shell, RC            string
	Stdout, Stderr, Remediation           string
	Reference, Location, Duration, Origin string
	RefLink                               bool
	Waiver                                *engine.WaiverInfo
}

type htmlWaiver struct {
	Host, ID, Name, Reason, Until, Source, Origin string
}

func statusClass(s engine.Status) string {
	if s == engine.StatusNA {
		return "na"
	}
	return strings.ToLower(string(s))
}

func scoreClass(score float64) string {
	switch {
	case score < 0:
		return "none"
	case score >= 90:
		return "good"
	case score >= 70:
		return "fair"
	}
	return "poor"
}

func verdict(s engine.Summary) (string, string) {
	switch {
	case s.Evaluated == 0:
		return "NOTHING EVALUATED", "warn"
	case s.Compliant:
		return "COMPLIANT", "pass"
	}
	return "NOT COMPLIANT", "fail"
}

func htmlData(all []*engine.Report, o Options) htmlView {
	// Totals, the columns of the check table and the details cover the
	// hosts that were checked; the host table lists every host.
	rs := checkedReports(all)
	allLabels := hostLabels(all)
	labels := make([]string, 0, len(rs))
	for i, r := range all {
		if !r.Unchecked() {
			labels = append(labels, allLabels[i])
		}
	}
	s := aggregate(all)
	v := htmlView{
		Title:     documentTitle(rs),
		Generated: o.now().Format("2006-01-02 15:04:05 MST"),
		Version:   o.Version,
		Multi:     len(all) > 1,
		Unchecked: len(all) - len(rs),
		Score:     scoreText(s.Score),
		ScoreNum:  s.Score,
		ScoreCls:  scoreClass(s.Score),
		Labels:    labels,
		Total:     s.Total,
		Scope:     scope(all),
	}
	v.Verdict, v.VerdictCl = verdict(s)
	if len(rs) == 0 {
		v.Verdict, v.VerdictCl = "NOT CHECKED", "warn"
	}
	for _, g := range groupRows(all) {
		v.Groups = append(v.Groups, htmlGroup{g.Name, g.Hosts, g.Compliant, g.NotCompliant, g.Unchecked,
			scoreText(g.Summary.Score), scoreClass(g.Summary.Score)})
	}
	if len(all) == 1 && len(rs) == 1 {
		r := rs[0]
		v.Subtitle = r.HostName()
		if r.Facts.DistroName != "" {
			v.Subtitle += " · " + r.Facts.DistroName
		}
		v.Subtitle += " · " + r.Started.Format("2006-01-02 15:04")
	} else {
		v.Subtitle = scope(all)
	}
	v.Counts = []htmlCount{
		{"passed", "PASS", "pass", s.Passed}, {"failed", "FAIL", "fail", s.Failed},
		{"warnings", "WARN", "warn", s.Warnings}, {"errors", "ERROR", "error", s.Errors},
		{"waived", "WAIVED", "waived", s.Waived}, {"skipped", "SKIP", "skip", s.Skipped},
		{"n/a", "N/A", "na", s.NotApplicable},
	}

	sevCount := map[string]int{}
	maxSev := 0
	for _, r := range rs {
		for _, res := range r.Results {
			if res.Status == engine.StatusFail || res.Status == engine.StatusError {
				sevCount[res.Severity]++
				maxSev = maxInt(maxSev, sevCount[res.Severity])
			}
		}
	}
	for i := len(policy.Severities) - 1; i >= 0; i-- {
		sev := policy.Severities[i]
		pct := 0
		if maxSev > 0 {
			pct = sevCount[sev] * 100 / maxSev
		}
		v.BySev = append(v.BySev, htmlSev{sev, sevCount[sev], pct})
	}

	for i, r := range all {
		if r.Unchecked() {
			v.Hosts = append(v.Hosts, htmlHost{Label: allLabels[i], Groups: strings.Join(r.Groups, ", "), Policy: policyTitle(r),
				Started: r.Started.Format("2006-01-02 15:04:05"), Unchecked: true, Error: r.Error,
				Verdict: strings.ToUpper(r.State()), VerdictCl: "warn"})
			continue
		}
		h := htmlHost{
			Label:    allLabels[i],
			Groups:   strings.Join(r.Groups, ", "),
			Distro:   r.Facts.DistroName,
			Kernel:   r.Facts.Kernel,
			Arch:     r.Facts.Arch,
			Policy:   policyTitle(r),
			Started:  r.Started.Format("2006-01-02 15:04:05"),
			Duration: (time.Duration(r.DurationMS) * time.Millisecond).Round(100 * time.Millisecond).String(),
			Score:    scoreText(r.Summary.Score),
			ScoreCls: scoreClass(r.Summary.Score),
			Summary:  r.Summary,
		}
		if r.PolicyVersion != "" {
			h.Policy += " v" + r.PolicyVersion
		}
		h.Verdict, h.VerdictCl = verdict(r.Summary)
		v.Hosts = append(v.Hosts, h)
		for _, n := range r.Notices {
			if len(all) > 1 {
				n = allLabels[i] + ": " + n
			}
			v.Notices = append(v.Notices, n)
		}
	}

	for _, row := range checkRows(rs) {
		hr := htmlRow{
			ID:       row.ID,
			Name:     row.Name,
			Severity: row.Severity,
			Tags:     strings.Join(row.Tags, " "),
			Worst:    string(row.worst()),
			WorstCls: statusClass(row.worst()),
		}
		statuses := map[string]bool{}
		for i, res := range row.Results {
			if res == nil {
				hr.Cells = append(hr.Cells, htmlCell{"–", "none"})
				continue
			}
			statuses[string(res.Status)] = true
			if isProblem(res.Status) {
				statuses["PROBLEM"] = true
			}
			hr.Cells = append(hr.Cells, htmlCell{string(res.Status), statusClass(res.Status)})
			d := htmlDetail{
				Host:        labels[i],
				Status:      string(res.Status),
				Class:       statusClass(res.Status),
				Description: res.Description,
				Rationale:   res.Rationale,
				Message:     res.Message,
				Expected:    res.Expected,
				Command:     clip(res.Command, detailLimit),
				OnlyIf:      clip(res.OnlyIf, detailLimit),
				Shell:       res.Shell,
				Stdout:      clip(res.Stdout, detailLimit),
				Stderr:      clip(res.Stderr, detailLimit),
				Remediation: res.Remediation,
				Reference:   res.Reference,
				RefLink:     strings.HasPrefix(res.Reference, "https://") || strings.HasPrefix(res.Reference, "http://"),
				Location:    res.Location,
				Duration:    fmt.Sprintf("%d ms", res.DurationMS),
				Waiver:      res.Waiver,
				Origin:      waiverOrigin(res),
			}
			if res.RC != nil {
				d.RC = fmt.Sprint(*res.RC)
			}
			hr.Details = append(hr.Details, d)
			if res.Waiver != nil {
				v.Waivers = append(v.Waivers, htmlWaiver{labels[i], res.ID, res.Name, res.Waiver.Reason,
					res.Waiver.Until, res.Waiver.Source, waiverOrigin(res)})
			}
		}
		for st := range statuses {
			hr.Statuses += st + " "
		}
		hr.Search = strings.ToLower(row.ID + " " + row.Name + " " + hr.Tags)
		v.Rows = append(v.Rows, hr)
	}
	return v
}

func writeHTML(w io.Writer, rs []*engine.Report, o Options) error {
	return htmlTmpl.Execute(w, htmlData(rs, o))
}
