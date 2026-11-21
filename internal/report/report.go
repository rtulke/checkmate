// Package report renders run results as text, JSON or JUnit XML.
package report

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/rtulke/checkmate/internal/engine"
)

// TextOptions control the text output.
type TextOptions struct {
	Color   bool
	Verbose bool // show command and output for failed and errored checks
	Quiet   bool // show only failed and errored checks
	Version string
	Width   int // terminal width; reasons are shortened to fit (0 = no limit)
}

const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorDim     = "\033[2m"
	colorBold    = "\033[1m"
)

// Text writes a human-readable report.
func Text(w io.Writer, r *engine.Report, opts TextOptions) error {
	paint := func(color, s string) string {
		if !opts.Color || color == "" {
			return s
		}
		return color + s + colorReset
	}

	host := r.Facts.Hostname
	if r.Facts.DistroName != "" {
		host += " (" + r.Facts.DistroName + ")"
	}
	title := r.Policy
	if title == "" {
		title = r.PolicyPath
	}
	if r.PolicyVersion != "" {
		title += " v" + r.PolicyVersion
	}
	fmt.Fprintf(w, "%s %s · %s · %s\n\n", paint(colorBold, "checkmate"), opts.Version, title, host)

	idWidth, nameWidth, sevWidth := 0, 0, 0
	for _, res := range r.Results {
		if !opts.Quiet || isProblem(res.Status) {
			idWidth = maxInt(idWidth, minInt(len(res.ID), 32))
			nameWidth = maxInt(nameWidth, minInt(runeLen(res.Name), 48))
		}
		if isProblem(res.Status) && res.Severity != "" {
			sevWidth = maxInt(sevWidth, len(res.Severity)+2)
		}
	}

	hasDetails := false
	for _, res := range r.Results {
		problem := isProblem(res.Status)
		if opts.Quiet && !problem {
			continue
		}
		color, _ := statusColor(res.Status)

		// Build the line twice: plain to measure it, colored to print it.
		plain := fmt.Sprintf("%-5s  %-*s  ", res.Status, idWidth, res.ID)
		colored := paint(color, fmt.Sprintf("%-5s", res.Status)) + fmt.Sprintf("  %-*s  ", idWidth, res.ID)
		name := res.Name
		reason := oneLine(res.Message)
		if reason == "" {
			plain += name
			colored += name
		} else {
			plain += padRight(name, nameWidth) + "  "
			colored += padRight(name, nameWidth) + "  "
			if sevWidth > 0 {
				sev := ""
				if problem && res.Severity != "" {
					sev = "[" + res.Severity + "]"
				}
				plain += padRight(sev, sevWidth) + "  "
				colored += paint(severityColor(res.Severity), sev) + strings.Repeat(" ", sevWidth-len(sev)) + "  "
			}
			// Keep every result on one line: shorten the reason to the
			// terminal width instead of letting the terminal wrap it.
			if opts.Width > 0 {
				if room := opts.Width - runeLen(plain); room < runeLen(reason) {
					reason = truncate(reason, room)
				}
			}
			reasonColor := colorDim
			if problem {
				reasonColor = ""
			}
			colored += paint(reasonColor, reason)
		}
		fmt.Fprintln(w, strings.TrimRight(colored, " "))

		if !problem {
			continue
		}
		if res.Remediation != "" || res.Command != "" {
			hasDetails = true
		}
		if !opts.Verbose {
			continue
		}
		indent := strings.Repeat(" ", 7)
		if res.Message != "" && oneLine(res.Message) != reason {
			fmt.Fprintf(w, "%s%s %s\n", indent, paint(colorDim, "message:"), indentBlock(res.Message, indent+"  "))
		}
		if res.Command != "" {
			fmt.Fprintf(w, "%s%s %s\n", indent, paint(colorDim, "command:"), indentBlock(res.Command, indent+"  "))
		}
		if res.RC != nil {
			fmt.Fprintf(w, "%s%s %d\n", indent, paint(colorDim, "exit code:"), *res.RC)
		}
		if s := strings.TrimSpace(res.Stdout); s != "" {
			fmt.Fprintf(w, "%s%s %s\n", indent, paint(colorDim, "stdout:"), indentBlock(s, indent+"  "))
		}
		if s := strings.TrimSpace(res.Stderr); s != "" {
			fmt.Fprintf(w, "%s%s %s\n", indent, paint(colorDim, "stderr:"), indentBlock(s, indent+"  "))
		}
		if res.Remediation != "" {
			fmt.Fprintf(w, "%s%s %s\n", indent, paint(colorBlue, "fix:"), indentBlock(res.Remediation, indent+"     "))
		}
		if res.Reference != "" {
			fmt.Fprintf(w, "%s%s %s\n", indent, paint(colorBlue, "see:"), res.Reference)
		}
		fmt.Fprintf(w, "%s%s %s\n", indent, paint(colorDim, "defined at:"), res.Location)
	}

	s := r.Summary
	count := func(n int, label, color string) string {
		text := fmt.Sprintf("%d %s", n, label)
		if n == 0 {
			return paint(colorDim, text)
		}
		return paint(color, text)
	}
	checksLabel := "checks"
	if s.Total == 1 {
		checksLabel = "check"
	}
	fmt.Fprintf(w, "\n%d %s · %s · %s · %s · %s · %s · %s · %s\n",
		s.Total, checksLabel,
		count(s.Passed, "passed", colorGreen),
		count(s.Failed, "failed", colorRed),
		count(s.Warnings, "warnings", colorYellow),
		count(s.Errors, "errors", colorMagenta),
		count(s.Skipped, "skipped", colorDim),
		count(s.NotApplicable, "n/a", colorDim),
		(time.Duration(r.DurationMS) * time.Millisecond).String())

	scoreColor := colorRed
	switch {
	case s.Score >= 90:
		scoreColor = colorGreen
	case s.Score >= 70:
		scoreColor = colorYellow
	}
	fmt.Fprintf(w, "Score  %s %s\n", paint(scoreColor, scoreBar(s.Score, 30)), paint(colorBold+scoreColor, fmt.Sprintf("%.1f%%", s.Score)))

	verdict := paint(colorBold+colorGreen, "COMPLIANT")
	if !s.Compliant {
		verdict = paint(colorBold+colorRed, "NOT COMPLIANT")
	}
	fmt.Fprintf(w, "Result %s %s\n", verdict, paint(colorDim, fmt.Sprintf("(failures of severity %s and above count; errors always count)", s.FailOn)))
	if hasDetails && !opts.Verbose {
		fmt.Fprintln(w, paint(colorDim, "Run with -v to see commands, output and remediation."))
	}
	return nil
}

func isProblem(s engine.Status) bool {
	return s == engine.StatusFail || s == engine.StatusError || s == engine.StatusWarn
}

// oneLine collapses whitespace, including newlines, into single spaces.
func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func runeLen(s string) int { return len([]rune(s)) }

func padRight(s string, width int) string {
	if n := runeLen(s); n < width {
		return s + strings.Repeat(" ", width-n)
	}
	return s
}

// truncate shortens s to at most n runes, ending with an ellipsis.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	if n <= 1 {
		return "…"
	}
	return string(r[:n-1]) + "…"
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// scoreBar draws a horizontal bar of the given width for a 0-100 score.
func scoreBar(score float64, width int) string {
	filled := int(score / 100 * float64(width))
	if filled < 0 {
		filled = 0
	}
	if filled > width {
		filled = width
	}
	return strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
}

func severityColor(s string) string {
	switch s {
	case "critical":
		return colorBold + colorRed
	case "high":
		return colorRed
	case "medium":
		return colorYellow
	case "low":
		return colorCyan
	}
	return colorDim
}

func statusColor(s engine.Status) (color string, dim bool) {
	switch s {
	case engine.StatusPass:
		return colorGreen, false
	case engine.StatusFail:
		return colorBold + colorRed, false
	case engine.StatusWarn:
		return colorYellow, false
	case engine.StatusError:
		return colorBold + colorMagenta, false
	}
	return colorDim, true
}

func indentBlock(s, indent string) string {
	return strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n"+indent)
}

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r *engine.Report, version string) error {
	doc := struct {
		Tool    string `json:"tool"`
		Version string `json:"version"`
		*engine.Report
	}{"checkmate", version, r}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

type junitSuites struct {
	XMLName  xml.Name     `xml:"testsuites"`
	Name     string       `xml:"name,attr"`
	Tests    int          `xml:"tests,attr"`
	Failures int          `xml:"failures,attr"`
	Errors   int          `xml:"errors,attr"`
	Skipped  int          `xml:"skipped,attr"`
	Time     string       `xml:"time,attr"`
	Suites   []junitSuite `xml:"testsuite"`
}

type junitSuite struct {
	Name      string      `xml:"name,attr"`
	Hostname  string      `xml:"hostname,attr"`
	Tests     int         `xml:"tests,attr"`
	Failures  int         `xml:"failures,attr"`
	Errors    int         `xml:"errors,attr"`
	Skipped   int         `xml:"skipped,attr"`
	Time      string      `xml:"time,attr"`
	Timestamp string      `xml:"timestamp,attr"`
	Cases     []junitCase `xml:"testcase"`
}

type junitCase struct {
	Classname string        `xml:"classname,attr"`
	Name      string        `xml:"name,attr"`
	Time      string        `xml:"time,attr"`
	Failure   *junitMessage `xml:"failure,omitempty"`
	Error     *junitMessage `xml:"error,omitempty"`
	Skipped   *junitMessage `xml:"skipped,omitempty"`
	SystemOut string        `xml:"system-out,omitempty"`
	SystemErr string        `xml:"system-err,omitempty"`
}

type junitMessage struct {
	Message string `xml:"message,attr"`
	Body    string `xml:",chardata"`
}

// JUnit writes the report as JUnit XML for CI systems.
func JUnit(w io.Writer, r *engine.Report) error {
	s := r.Summary
	seconds := func(ms int64) string { return fmt.Sprintf("%.3f", float64(ms)/1000) }
	suiteName := r.Policy
	if suiteName == "" {
		suiteName = r.PolicyPath
	}
	suite := junitSuite{
		Name:      suiteName,
		Hostname:  r.Facts.Hostname,
		Tests:     s.Total,
		Failures:  s.Failed,
		Errors:    s.Errors,
		Skipped:   s.Skipped + s.NotApplicable,
		Time:      seconds(r.DurationMS),
		Timestamp: r.Started.Format(time.RFC3339),
	}
	for _, res := range r.Results {
		c := junitCase{
			Classname: suiteName,
			Name:      res.ID + ": " + res.Name,
			Time:      seconds(res.DurationMS),
			SystemOut: res.Stdout,
			SystemErr: res.Stderr,
		}
		details := res.Message
		if res.Remediation != "" {
			details += "\nfix: " + res.Remediation
		}
		switch res.Status {
		case engine.StatusFail:
			c.Failure = &junitMessage{Message: res.Message, Body: details}
		case engine.StatusError:
			c.Error = &junitMessage{Message: res.Message, Body: details}
		case engine.StatusSkip, engine.StatusNA:
			c.Skipped = &junitMessage{Message: res.Message}
		case engine.StatusWarn:
			// Warnings do not fail a CI build but stay visible in the log.
			c.SystemErr = strings.TrimSpace("WARNING: " + details + "\n" + c.SystemErr)
		}
		suite.Cases = append(suite.Cases, c)
	}
	doc := junitSuites{
		Name: "checkmate", Tests: s.Total, Failures: s.Failed, Errors: s.Errors,
		Skipped: suite.Skipped, Time: suite.Time, Suites: []junitSuite{suite},
	}
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
