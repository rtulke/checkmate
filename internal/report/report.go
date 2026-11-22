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
	Color bool
	// Verbosity: 0 = status, ID and name; 1 = plus severity and reason;
	// 2 = plus details of problems; 3 = debug details of every check.
	Verbosity int
	Quiet     bool // show only failed and errored checks
	Version   string
	Width     int // terminal width; reasons are shortened to fit (0 = no limit)
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

	if opts.Verbosity >= 3 {
		writeDebugHeader(w, r, paint)
	}

	// WAIVED is the only six-letter status; widen the column only if needed.
	idWidth, nameWidth, sevWidth, statusWidth := 0, 0, 0, 5
	for _, res := range r.Results {
		if res.Status == engine.StatusWaived && (!opts.Quiet || isProblem(res.Status)) {
			statusWidth = 6
		}
		if !opts.Quiet || isProblem(res.Status) {
			idWidth = maxInt(idWidth, minInt(len(res.ID), 32))
			nameWidth = maxInt(nameWidth, minInt(runeLen(res.Name), 48))
		}
		if isProblem(res.Status) && res.Severity != "" {
			sevWidth = maxInt(sevWidth, len(res.Severity)+2)
		}
	}

	problems := false
	for _, res := range r.Results {
		problem := isProblem(res.Status)
		problems = problems || problem
		if opts.Quiet && !problem {
			continue
		}
		color, _ := statusColor(res.Status)

		// Build the line twice: plain to measure it, colored to print it.
		plain := fmt.Sprintf("%-*s  %-*s  ", statusWidth, res.Status, idWidth, res.ID)
		colored := paint(color, fmt.Sprintf("%-*s", statusWidth, res.Status)) + fmt.Sprintf("  %-*s  ", idWidth, res.ID)
		reason := oneLine(res.Message)
		if opts.Verbosity == 0 || reason == "" {
			plain += res.Name
			colored += res.Name
		} else {
			plain += padRight(res.Name, nameWidth) + "  "
			colored += padRight(res.Name, nameWidth) + "  "
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
			if opts.Width > 0 && opts.Verbosity < 3 {
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

		switch {
		case opts.Verbosity >= 3:
			writeDetails(w, res, paint, true)
		case opts.Verbosity == 2 && problem:
			writeDetails(w, res, paint, false)
		}
	}

	if len(r.Notices) > 0 {
		fmt.Fprintln(w)
		for _, n := range r.Notices {
			fmt.Fprintln(w, paint(colorYellow, "notice: ")+n)
		}
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
	waived := ""
	if s.Waived > 0 {
		waived = " · " + count(s.Waived, "waived", colorCyan)
	}
	fmt.Fprintf(w, "\n%d %s · %s · %s · %s · %s%s · %s · %s · %s\n",
		s.Total, checksLabel,
		count(s.Passed, "passed", colorGreen),
		count(s.Failed, "failed", colorRed),
		count(s.Warnings, "warnings", colorYellow),
		count(s.Errors, "errors", colorMagenta),
		waived,
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
	if s.Evaluated == 0 {
		fmt.Fprintf(w, "Score  %s %s\n", paint(colorDim, scoreBar(0, 30)), paint(colorDim, "n/a"))
		fmt.Fprintf(w, "Result %s %s\n", paint(colorBold+colorYellow, "NOTHING EVALUATED"),
			paint(colorDim, "(every check was skipped or not applicable on this host)"))
		return nil
	}
	fmt.Fprintf(w, "Score  %s %s\n", paint(scoreColor, scoreBar(s.Score, 30)), paint(colorBold+scoreColor, fmt.Sprintf("%.1f%%", s.Score)))

	verdict := paint(colorBold+colorGreen, "COMPLIANT")
	if !s.Compliant {
		verdict = paint(colorBold+colorRed, "NOT COMPLIANT")
	}
	fmt.Fprintf(w, "Result %s %s\n", verdict, paint(colorDim, fmt.Sprintf("(failures of severity %s and above count; errors always count)", s.FailOn)))
	if problems {
		switch opts.Verbosity {
		case 0:
			fmt.Fprintln(w, paint(colorDim, "Run with -v for reasons, -vv for commands and remediation."))
		case 1:
			fmt.Fprintln(w, paint(colorDim, "Run with -vv for commands, output and remediation."))
		}
	}
	return nil
}

// writeDetails prints the indented detail block below a result line. With
// debug set, it also shows conditions, shell and timing.
func writeDetails(w io.Writer, res engine.Result, paint func(string, string) string, debug bool) {
	indent := strings.Repeat(" ", 7)
	field := func(label, value string) {
		if strings.TrimSpace(value) == "" {
			return
		}
		fmt.Fprintf(w, "%s%s %s\n", indent, paint(colorDim, label+":"), indentBlock(strings.TrimRight(value, "\n"), indent+strings.Repeat(" ", len(label)+2)))
	}
	if debug {
		field("severity", res.Severity)
		field("tags", strings.Join(res.Tags, ", "))
		if len(res.When) > 0 {
			field("when", strings.Join(res.When, " and "))
		}
		field("only_if", res.OnlyIf)
		field("expected", res.Expected)
	}
	if res.Message != "" && (debug || runeLen(oneLine(res.Message)) > 60 || strings.Contains(res.Message, "\n")) {
		field("message", res.Message)
	}
	if res.Waiver != nil {
		waiver := res.Waiver.Reason + " (" + res.Waiver.Source
		if res.Waiver.Until != "" {
			waiver += ", until " + res.Waiver.Until
		}
		field("waiver", waiver+")")
	}
	field("command", res.Command)
	if res.RC != nil {
		field("exit code", fmt.Sprint(*res.RC))
	}
	if debug {
		field("shell", res.Shell)
		field("duration", (time.Duration(res.DurationMS) * time.Millisecond).String())
	}
	field("stdout", strings.TrimSpace(res.Stdout))
	field("stderr", strings.TrimSpace(res.Stderr))
	if res.Remediation != "" {
		fmt.Fprintf(w, "%s%s %s\n", indent, paint(colorBlue, "fix:"), indentBlock(res.Remediation, indent+"     "))
	}
	if res.Reference != "" {
		fmt.Fprintf(w, "%s%s %s\n", indent, paint(colorBlue, "see:"), res.Reference)
	}
	field("defined at", res.Location)
}

// writeDebugHeader prints facts and the loaded files (-vvv).
func writeDebugHeader(w io.Writer, r *engine.Report, paint func(string, string) string) {
	f := r.Facts
	line := func(label, value string) {
		fmt.Fprintf(w, "%s %s\n", paint(colorDim, fmt.Sprintf("%-14s", label+":")), value)
	}
	line("os", fmt.Sprintf("%s/%s", f.OS, f.Arch))
	distro := strings.TrimSpace(f.Distro + " " + f.Version)
	if len(f.DistroLike) > 0 {
		distro += " (like " + strings.Join(f.DistroLike, ", ") + ")"
	}
	line("distro", distro)
	line("kernel", f.Kernel)
	line("root", fmt.Sprint(f.IsRoot))
	line("platform keys", strings.Join(f.PlatformKeys(), " > "))
	line("fail on", r.Summary.FailOn)
	for i, file := range r.PolicyFiles {
		label := ""
		if i == 0 {
			label = "files"
		}
		fmt.Fprintf(w, "%s %s\n", paint(colorDim, fmt.Sprintf("%-14s", label+map[bool]string{true: ":", false: " "}[i == 0])), file)
	}
	fmt.Fprintln(w)
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
	case engine.StatusWaived:
		return colorCyan, false
	}
	return colorDim, true
}

func indentBlock(s, indent string) string {
	return strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n"+indent)
}

// JSON writes the report as indented JSON.
func JSON(w io.Writer, r *engine.Report, version string) error {
	doc := *r
	doc.Tool = "checkmate"
	if doc.Version == "" {
		doc.Version = version
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(&doc)
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

// JUnit writes reports as JUnit XML for CI systems, one test suite per
// report.
func JUnit(w io.Writer, rs ...*engine.Report) error {
	seconds := func(ms int64) string { return fmt.Sprintf("%.3f", float64(ms)/1000) }
	doc := junitSuites{Name: "checkmate"}
	var total int64
	labels := hostLabels(rs)
	for i, r := range rs {
		suite := junitSuiteFor(r, seconds)
		if len(rs) > 1 {
			suite.Name = labels[i] + ": " + suite.Name
		}
		doc.Suites = append(doc.Suites, suite)
		doc.Tests += suite.Tests
		doc.Failures += suite.Failures
		doc.Errors += suite.Errors
		doc.Skipped += suite.Skipped
		total += r.DurationMS
	}
	doc.Time = seconds(total)
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

func junitSuiteFor(r *engine.Report, seconds func(int64) string) junitSuite {
	s := r.Summary
	suiteName := policyTitle(r)
	suite := junitSuite{
		Name:      suiteName,
		Hostname:  r.Facts.Hostname,
		Tests:     s.Total,
		Failures:  s.Failed,
		Errors:    s.Errors,
		Skipped:   s.Skipped + s.NotApplicable + s.Waived,
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
		case engine.StatusSkip, engine.StatusNA, engine.StatusWaived:
			c.Skipped = &junitMessage{Message: res.Message}
		case engine.StatusWarn:
			// Warnings do not fail a CI build but stay visible in the log.
			c.SystemErr = strings.TrimSpace("WARNING: " + details + "\n" + c.SystemErr)
		}
		suite.Cases = append(suite.Cases, c)
	}
	return suite
}

// TextOverview writes a summary of several reports: one line per host and
// the checks that have problems anywhere.
func TextOverview(w io.Writer, rs []*engine.Report, opts TextOptions) error {
	paint := func(color, s string) string {
		if !opts.Color || color == "" {
			return s
		}
		return color + s + colorReset
	}
	fmt.Fprintf(w, "%s %s · %s · %d reports\n\n", paint(colorBold, "checkmate"), opts.Version, documentTitle(rs), len(rs))
	labels := hostLabels(rs)
	hostWidth := 4
	for _, l := range labels {
		hostWidth = maxInt(hostWidth, minInt(runeLen(l), 40))
	}
	fmt.Fprintf(w, "%-*s  %7s  %5s  %5s  %5s  %5s  %6s  %s\n", hostWidth, "HOST", "SCORE", "PASS", "FAIL", "WARN", "ERROR", "WAIVED", "RESULT")
	for i, r := range rs {
		s := r.Summary
		verdict := paint(colorGreen, "compliant")
		switch {
		case s.Evaluated == 0:
			verdict = paint(colorYellow, "nothing evaluated")
		case !s.Compliant:
			verdict = paint(colorRed, "not compliant")
		}
		fmt.Fprintf(w, "%s  %7s  %5d  %5d  %5d  %5d  %6d  %s\n", padRight(truncate(labels[i], 40), hostWidth),
			scoreText(s.Score), s.Passed, s.Failed, s.Warnings, s.Errors, s.Waived, verdict)
	}

	problems := problemRows(checkRows(rs))
	if len(problems) > 0 {
		fmt.Fprintf(w, "\n%s\n", paint(colorBold, "Problems"))
		for _, row := range problems {
			var where []string
			for i, res := range row.Results {
				if res != nil && isProblem(res.Status) {
					where = append(where, labels[i]+" "+string(res.Status))
				}
			}
			color, _ := statusColor(row.worst())
			fmt.Fprintf(w, "%s  %s  %s %s\n", paint(color, fmt.Sprintf("%-5s", row.worst())), row.ID,
				paint(severityColor(row.Severity), "["+row.Severity+"]"), row.Name)
			fmt.Fprintf(w, "       %s\n", paint(colorDim, strings.Join(where, ", ")))
		}
	}
	s := aggregate(rs)
	fmt.Fprintf(w, "\n%s · %d checks · %d passed · %d failed · %d warnings · %d errors · %d waived · score %s\n",
		scope(rs), s.Total, s.Passed, s.Failed, s.Warnings, s.Errors, s.Waived, scoreText(s.Score))
	return nil
}
