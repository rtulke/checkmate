package report

import (
	"fmt"
	"io"
	"strings"

	"github.com/rtulke/checkmate/internal/engine"
	"github.com/rtulke/checkmate/internal/pdf"
)

// The PDF report has the content of the HTML report in print form: summary,
// hosts, findings with details, waivers and a table of all results.

var (
	pdfText    = pdf.Color{R: 29, G: 35, B: 43}
	pdfMuted   = pdf.Color{R: 95, G: 107, B: 122}
	pdfLine    = pdf.Color{R: 225, G: 229, B: 234}
	pdfPanel   = pdf.Color{R: 246, G: 247, B: 249}
	pdfAccent  = pdf.Color{R: 57, G: 73, B: 171}
	pdfWhite   = pdf.Color{R: 255, G: 255, B: 255}
	pdfDark    = pdf.Color{R: 34, G: 34, B: 34}
	pdfStatusC = map[string]pdf.Color{
		"pass": {R: 46, G: 125, B: 50}, "fail": {R: 198, G: 40, B: 40}, "warn": {R: 183, G: 121, B: 31},
		"error": {R: 173, G: 20, B: 87}, "waived": {R: 0, G: 131, B: 143}, "skip": {R: 120, G: 144, B: 156},
		"na": {R: 120, G: 144, B: 156}, "none": {R: 120, G: 144, B: 156},
	}
	pdfSevC = map[string]pdf.Color{
		"info": {R: 120, G: 144, B: 156}, "low": {R: 0, G: 151, B: 167}, "medium": {R: 249, G: 168, B: 37},
		"high": {R: 229, G: 57, B: 53}, "critical": {R: 142, G: 0, B: 0},
	}
)

const (
	pdfMargin = 42.0
	pdfTop    = 50.0
	pdfBottom = 56.0 // room for the footer
)

// pdfLayout keeps the cursor and breaks pages.
type pdfLayout struct {
	d     *pdf.Doc
	y     float64
	width float64 // usable width
	// header is redrawn after a page break inside a table.
	header func()
}

func (l *pdfLayout) newPage() {
	l.d.AddPage()
	l.y = pdfTop
	if l.header != nil {
		l.header()
	}
}

// need breaks the page unless h points fit below the cursor.
func (l *pdfLayout) need(h float64) {
	if l.y+h > l.d.Height-pdfBottom {
		l.newPage()
	}
}

// paragraph writes wrapped text and advances the cursor.
func (l *pdfLayout) paragraph(x, width float64, f pdf.Font, size float64, c pdf.Color, s string) {
	lh := size * 1.35
	for _, line := range pdf.Wrap(f, size, s, width) {
		l.need(lh)
		l.d.Text(x, l.y+size, f, size, c, line)
		l.y += lh
	}
}

func (l *pdfLayout) heading(s string) {
	l.need(40)
	l.y += 14
	l.d.Text(pdfMargin, l.y+13, pdf.HelveticaBold, 13, pdfText, s)
	l.y += 20
	l.d.Line(pdfMargin, l.y, pdfMargin+l.width, l.y, 0.6, pdfLine)
	l.y += 8
}

// badge draws a colored label and returns its width.
func (l *pdfLayout) badge(x, y float64, text string, bg pdf.Color, fg pdf.Color) float64 {
	w := pdf.Width(pdf.HelveticaBold, 7, text) + 8
	l.d.Rect(x, y, w, 11, &bg, nil)
	l.d.Text(x+4, y+8, pdf.HelveticaBold, 7, fg, text)
	return w
}

func sevBadgeColors(sev string) (pdf.Color, pdf.Color) {
	bg, ok := pdfSevC[sev]
	if !ok {
		bg = pdfSevC["info"]
	}
	if sev == "medium" {
		return bg, pdfDark
	}
	return bg, pdfWhite
}

func writePDF(w io.Writer, reports []*engine.Report, o Options) error {
	// Totals and findings cover the hosts that were checked; the host table
	// lists every host.
	rs := checkedReports(reports)
	d := pdf.New()
	d.Created = o.now()
	title := documentTitle(reports)
	d.Title = title + " - checkmate compliance report"
	d.Author = "checkmate " + o.Version
	l := &pdfLayout{d: d, width: d.Width - 2*pdfMargin}
	l.newPage()

	allLabels := hostLabels(reports)
	labels := make([]string, 0, len(rs))
	for i, r := range reports {
		if !r.Unchecked() {
			labels = append(labels, allLabels[i])
		}
	}
	s := aggregate(reports)
	multi := len(reports) > 1

	// Title block.
	d.Text(pdfMargin, l.y+10, pdf.HelveticaBold, 9, pdfAccent, "CHECKMATE COMPLIANCE REPORT")
	l.y += 18
	l.paragraph(pdfMargin, l.width, pdf.HelveticaBold, 20, pdfText, title)
	sub := scope(reports)
	if !multi && len(rs) == 1 {
		r := rs[0]
		sub = strings.TrimSpace(r.HostName() + " · " + r.Facts.DistroName)
		sub = strings.TrimSuffix(sub, " ·") + " · " + r.Started.Format("2006-01-02 15:04")
	}
	l.paragraph(pdfMargin, l.width, pdf.Helvetica, 10, pdfMuted, sub)
	l.y += 12

	// Summary panel: score, verdict and counts.
	panelH := 92.0
	d.Rect(pdfMargin, l.y, l.width, panelH, &pdfPanel, &pdfLine)
	scoreCls := scoreClass(s.Score)
	scoreColor := map[string]pdf.Color{"good": pdfStatusC["pass"], "fair": pdfStatusC["warn"], "poor": pdfStatusC["fail"], "none": pdfStatusC["skip"]}[scoreCls]
	d.Text(pdfMargin+14, l.y+20, pdf.Helvetica, 8, pdfMuted, "COMPLIANCE SCORE")
	d.Text(pdfMargin+14, l.y+50, pdf.HelveticaBold, 28, scoreColor, scoreText(s.Score))
	barW := 130.0
	d.Rect(pdfMargin+14, l.y+58, barW, 5, &pdfLine, nil)
	if s.Score > 0 {
		d.Rect(pdfMargin+14, l.y+58, barW*s.Score/100, 5, &scoreColor, nil)
	}
	v, vc := verdict(s)
	if len(rs) == 0 {
		v, vc = "NOT CHECKED", "warn"
	}
	d.Text(pdfMargin+14, l.y+78, pdf.HelveticaBold, 10, pdfStatusC[vc], v)

	counts := []struct {
		label, cls string
		n          int
	}{{"passed", "pass", s.Passed}, {"failed", "fail", s.Failed}, {"warnings", "warn", s.Warnings},
		{"errors", "error", s.Errors}, {"waived", "waived", s.Waived}, {"skipped", "skip", s.Skipped}, {"n/a", "na", s.NotApplicable}}
	cx := pdfMargin + 180
	cw := (l.width - 180 - 10) / 4
	for i, c := range counts {
		x := cx + float64(i%4)*cw
		y := l.y + 14 + float64(i/4)*38
		d.Text(x, y+16, pdf.HelveticaBold, 16, pdfStatusC[c.cls], fmt.Sprint(c.n))
		d.Text(x, y+28, pdf.Helvetica, 8, pdfMuted, c.label)
	}
	l.y += panelH + 6
	l.paragraph(pdfMargin, l.width, pdf.Helvetica, 8, pdfMuted, fmt.Sprintf("%d checks%s. Failures of severity %s and above make a host non-compliant; errors always do.",
		s.Total, map[bool]string{true: " · " + scope(reports), false: ""}[multi], firstNonEmpty(s.FailOn, reports[0].Summary.FailOn, "low")))
	if n := len(reports) - len(rs); n > 0 {
		l.paragraph(pdfMargin, l.width, pdf.HelveticaBold, 8, pdfStatusC["warn"], fmt.Sprintf(
			"%d of %d hosts could not be checked. Nothing is known about them: they count neither in the totals nor in the score.", n, len(reports)))
	}

	// Hosts.
	l.heading(map[bool]string{true: "Hosts", false: "Host"}[multi])
	hostCols := []pdfCol{{"Host", 0.22}, {"System", 0.22}, {"Policy", 0.22}, {"Score", 0.09}, {"Pass", 0.06}, {"Fail", 0.06}, {"Error", 0.06}, {"Waived", 0.07}}
	var hostRows [][]pdfCell
	for i, r := range reports {
		name := allLabels[i]
		if len(r.Groups) > 0 {
			name += "\n" + strings.Join(r.Groups, ", ")
		}
		if r.Unchecked() {
			hostRows = append(hostRows, []pdfCell{
				{Text: name, Font: pdf.HelveticaBold},
				{Text: strings.ToUpper(r.State()), Font: pdf.HelveticaBold, Color: pdfStatusC["warn"]},
				{Text: clipLines(r.Error, 3)},
				{Text: "-"}, {Text: "-"}, {Text: "-"}, {Text: "-"}, {Text: "-"},
			})
			continue
		}
		hs := r.Summary
		hostRows = append(hostRows, []pdfCell{
			{Text: name, Font: pdf.HelveticaBold},
			{Text: strings.TrimSpace(r.Facts.DistroName + "\n" + r.Facts.Kernel + " " + r.Facts.Arch)},
			{Text: policyTitle(r) + map[bool]string{true: " v" + r.PolicyVersion, false: ""}[r.PolicyVersion != ""] + "\n" + r.Started.Format("2006-01-02 15:04")},
			{Text: scoreText(hs.Score), Font: pdf.HelveticaBold},
			{Text: fmt.Sprint(hs.Passed)}, {Text: fmt.Sprint(hs.Failed)}, {Text: fmt.Sprint(hs.Errors)}, {Text: fmt.Sprint(hs.Waived)},
		})
	}
	l.table(hostCols, hostRows)

	if groups := groupRows(reports); len(groups) > 1 {
		l.need(80) // keep the heading with its table
		l.heading("Groups")
		var groupCells [][]pdfCell
		for _, g := range groups {
			groupCells = append(groupCells, []pdfCell{
				{Text: g.Name, Font: pdf.HelveticaBold}, {Text: fmt.Sprint(g.Hosts)},
				{Text: fmt.Sprint(g.Compliant), Color: pdfStatusC["pass"]},
				{Text: fmt.Sprint(g.NotCompliant), Color: pdfStatusC["fail"]},
				{Text: fmt.Sprint(g.Unchecked), Color: pdfStatusC["warn"]},
				{Text: scoreText(g.Summary.Score), Font: pdf.HelveticaBold},
			})
		}
		l.table([]pdfCol{{"Group", 0.34}, {"Hosts", 0.12}, {"Compliant", 0.14}, {"Not compliant", 0.14}, {"Not checked", 0.14}, {"Score", 0.12}}, groupCells)
	}

	var notices []string
	for i, r := range rs {
		for _, n := range r.Notices {
			if multi {
				n = labels[i] + ": " + n
			}
			notices = append(notices, n)
		}
	}
	if len(notices) > 0 {
		l.heading("Notices")
		for _, n := range notices {
			l.paragraph(pdfMargin, l.width, pdf.Helvetica, 9, pdfText, "• "+n)
		}
	}

	// Findings with details.
	rows := checkRows(rs)
	problems := problemRows(rows)
	if len(rs) > 1 && len(problems) > 0 {
		l.problemMatrix(problems, labels)
	}
	l.heading(fmt.Sprintf("Findings (%d)", len(problems)))
	if len(problems) == 0 {
		l.paragraph(pdfMargin, l.width, pdf.Helvetica, 10, pdfMuted, "No check failed, warned or errored.")
	}
	for _, row := range problems {
		l.finding(row, labels, len(rs) > 1)
	}

	// Waivers.
	var waiverRows [][]pdfCell
	for _, row := range rows {
		for i, res := range row.Results {
			if res == nil || res.Waiver == nil {
				continue
			}
			cells := []pdfCell{{Text: res.ID, Font: pdf.Courier, Size: 7}, {Text: res.Waiver.Reason + map[bool]string{true: "\nuntil " + res.Waiver.Until, false: ""}[res.Waiver.Until != ""]},
				{Text: waiverOrigin(res)}, {Text: res.Waiver.Source, Size: 7}}
			if len(rs) > 1 {
				cells = append([]pdfCell{{Text: labels[i]}}, cells...)
			}
			waiverRows = append(waiverRows, cells)
		}
	}
	if len(waiverRows) > 0 {
		l.heading(fmt.Sprintf("Waivers (%d)", len(waiverRows)))
		cols := []pdfCol{{"ID", 0.28}, {"Reason", 0.38}, {"Without waiver", 0.12}, {"Source", 0.22}}
		if len(rs) > 1 {
			cols = []pdfCol{{"Host", 0.16}, {"ID", 0.24}, {"Reason", 0.32}, {"Without waiver", 0.1}, {"Source", 0.18}}
		}
		l.table(cols, waiverRows)
	}

	// All results.
	l.heading(fmt.Sprintf("All results (%d checks)", len(rows)))
	cols := []pdfCol{{"Status", 0.1}, {"Severity", 0.1}, {"ID", 0.32}, {"Check", 0.48}}
	var all [][]pdfCell
	for _, row := range rows {
		status := string(row.worst())
		if len(rs) > 1 {
			n, of := 0, 0
			for _, res := range row.Results {
				if res != nil {
					of++
					if res.Status == row.worst() {
						n++
					}
				}
			}
			status = fmt.Sprintf("%s %d/%d", status, n, of)
		}
		all = append(all, []pdfCell{
			{Text: status, Font: pdf.HelveticaBold, Color: pdfStatusC[statusClass(row.worst())]},
			{Text: row.Severity, Badge: true},
			{Text: row.ID, Font: pdf.Courier, Size: 7},
			{Text: row.Name},
		})
	}
	l.table(cols, all)

	// Footer on every page.
	total := d.Pages()
	for p := 1; p <= total; p++ {
		d.SetPage(p)
		y := d.Height - 30
		d.Line(pdfMargin, y-10, d.Width-pdfMargin, y-10, 0.5, pdfLine)
		d.Text(pdfMargin, y, pdf.Helvetica, 7, pdfMuted, "checkmate "+o.Version+" · "+title+" · generated "+o.now().Format("2006-01-02 15:04"))
		pg := fmt.Sprintf("page %d of %d", p, total)
		d.Text(d.Width-pdfMargin-pdf.Width(pdf.Helvetica, 7, pg), y, pdf.Helvetica, 7, pdfMuted, pg)
	}
	return d.Write(w)
}

// finding writes one problem with its details for every affected host.
func (l *pdfLayout) finding(row checkRow, labels []string, multi bool) {
	d := l.d
	l.need(60)
	l.y += 4
	x := pdfMargin
	worst := row.worst()
	x += l.badge(x, l.y, string(worst), pdfStatusC[statusClass(worst)], pdfWhite) + 4
	bg, fg := sevBadgeColors(row.Severity)
	x += l.badge(x, l.y, row.Severity, bg, fg) + 6
	idLines := pdf.Wrap(pdf.Courier, 8, row.ID, pdfMargin+l.width-x)
	for i, line := range idLines {
		d.Text(x, l.y+8.5+float64(i)*10, pdf.Courier, 8, pdfMuted, line)
	}
	l.y += 5 + 10*float64(len(idLines))
	l.paragraph(pdfMargin, l.width, pdf.HelveticaBold, 10, pdfText, row.Name)

	field := func(label, value string, mono bool) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		l.need(22)
		d.Text(pdfMargin+10, l.y+8, pdf.Helvetica, 7.5, pdfMuted, label)
		if mono {
			lines := pdf.Wrap(pdf.Courier, 7, clipLines(value, 14), l.width-100)
			for _, line := range lines {
				l.need(9)
				d.Rect(pdfMargin+88, l.y-1, l.width-88, 9.5, &pdfPanel, nil)
				d.Text(pdfMargin+92, l.y+6.5, pdf.Courier, 7, pdfText, line)
				l.y += 9
			}
			l.y += 3
		} else {
			l.paragraph(pdfMargin+88, l.width-88, pdf.Helvetica, 8.5, pdfText, value)
		}
	}
	described := false
	for i, res := range row.Results {
		if res == nil || !isProblem(res.Status) {
			continue
		}
		if multi {
			l.need(20)
			l.y += 2
			d.Text(pdfMargin+10, l.y+9, pdf.HelveticaBold, 8.5, pdfText, labels[i])
			d.Text(pdfMargin+14+pdf.Width(pdf.HelveticaBold, 8.5, labels[i]), l.y+9, pdf.HelveticaBold, 8, pdfStatusC[statusClass(res.Status)], string(res.Status))
			l.y += 13
		}
		if !described {
			field("Description", res.Description, false)
			field("Rationale", res.Rationale, false)
			described = true
		}
		field("Reason", res.Message, false)
		field("Expected", res.Expected, false)
		field("Command", res.Command, true)
		field("Output", res.Stdout, true)
		field("Errors", res.Stderr, true)
		field("Remediation", res.Remediation, false)
		field("Reference", res.Reference, false)
		field("Defined in", res.Location, false)
	}
	l.y += 4
	l.need(6)
	d.Line(pdfMargin, l.y, pdfMargin+l.width, l.y, 0.4, pdfLine)
	l.y += 4
}

// clipLines keeps at most n lines of s.
func clipLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) <= n {
		return s
	}
	return strings.Join(lines[:n], "\n") + fmt.Sprintf("\n… (%d more lines)", len(lines)-n)
}

type pdfCol struct {
	Title string
	Share float64 // share of the usable width
}

type pdfCell struct {
	Text  string
	Font  pdf.Font
	Size  float64
	Color pdf.Color
	Badge bool // draw as severity badge
}

// problemMatrix shows at a glance which check has a problem on which host:
// one row per check, one column per host. With more hosts than fit on the
// page, the matrix continues with the next hosts.
func (l *pdfLayout) problemMatrix(problems []checkRow, labels []string) {
	const perTable = 6
	short := shortLabels(labels)
	l.need(80) // keep the heading with its table
	l.heading("Problems by host")
	for start := 0; start < len(labels); start += perTable {
		end := minInt(start+perTable, len(labels))
		cols := []pdfCol{{"Check", 0.34}}
		share := 0.66 / float64(perTable)
		for _, label := range short[start:end] {
			// The header is a single line: shorten what does not fit.
			for pdf.Width(pdf.HelveticaBold, 7.5, label) > share*l.width-8 && len(label) > 1 {
				r := []rune(strings.TrimSuffix(label, "…"))
				label = string(r[:len(r)-1]) + "…"
			}
			cols = append(cols, pdfCol{label, share})
		}
		var cells [][]pdfCell
		for _, row := range problems {
			line := []pdfCell{{Text: row.ID, Font: pdf.Courier, Size: 7}}
			found := false
			for _, res := range row.Results[start:end] {
				switch {
				case res == nil:
					line = append(line, pdfCell{Text: "-", Color: pdfMuted})
				case isProblem(res.Status):
					found = true
					line = append(line, pdfCell{Text: string(res.Status), Font: pdf.HelveticaBold, Size: 7, Color: pdfStatusC[statusClass(res.Status)]})
				default:
					line = append(line, pdfCell{Text: strings.ToLower(string(res.Status)), Size: 7, Color: pdfMuted})
				}
			}
			// Checks without a problem on these hosts would only add noise.
			if found {
				cells = append(cells, line)
			}
		}
		if len(cells) > 0 {
			l.table(cols, cells)
		}
	}
}

// shortLabels drops the domain that all host names share, which only costs
// room in a narrow column: web01.example.net and db01.example.net become
// web01 and db01.
func shortLabels(labels []string) []string {
	if len(labels) < 2 {
		return labels
	}
	suffix := labels[0]
	for _, l := range labels[1:] {
		for suffix != "" && !strings.HasSuffix(l, suffix) {
			if i := strings.IndexByte(suffix[1:], '.'); i >= 0 {
				suffix = suffix[i+1:]
			} else {
				suffix = ""
			}
		}
	}
	// A shared tail of digits belongs to IP addresses, not to a domain.
	if !strings.HasPrefix(suffix, ".") || !strings.ContainsAny(suffix, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ") {
		return labels
	}
	out := make([]string, len(labels))
	for i, l := range labels {
		out[i] = strings.TrimSuffix(l, suffix)
		if out[i] == "" {
			return labels
		}
	}
	return out
}

// table draws rows with wrapped cells, repeating the header after page
// breaks.
func (l *pdfLayout) table(cols []pdfCol, rows [][]pdfCell) {
	d := l.d
	widths := make([]float64, len(cols))
	for i, c := range cols {
		widths[i] = c.Share * l.width
	}
	drawHeader := func() {
		d.Rect(pdfMargin, l.y, l.width, 14, &pdfPanel, nil)
		x := pdfMargin
		for i, c := range cols {
			d.Text(x+4, l.y+9.5, pdf.HelveticaBold, 7.5, pdfMuted, c.Title)
			x += widths[i]
		}
		l.y += 16
	}
	l.need(34)
	drawHeader()
	l.header = drawHeader
	defer func() { l.header = nil }()
	for _, row := range rows {
		lines := make([][]string, len(row))
		h := 0.0
		for i, cell := range row {
			size := cell.Size
			if size == 0 {
				size = 8
			}
			if cell.Badge {
				lines[i] = []string{cell.Text}
			} else {
				lines[i] = pdf.Wrap(cell.Font, size, cell.Text, widths[i]-8)
			}
			if lh := float64(len(lines[i])) * size * 1.3; lh > h {
				h = lh
			}
		}
		h += 6
		l.need(h)
		x := pdfMargin
		for i, cell := range row {
			size := cell.Size
			if size == 0 {
				size = 8
			}
			color := cell.Color
			if color == (pdf.Color{}) {
				color = pdfText
			}
			if cell.Badge && cell.Text != "" {
				bg, fg := sevBadgeColors(cell.Text)
				l.badge(x+4, l.y+2, cell.Text, bg, fg)
			} else {
				for j, line := range lines[i] {
					d.Text(x+4, l.y+3+size+float64(j)*size*1.3, cell.Font, size, color, line)
				}
			}
			x += widths[i]
		}
		l.y += h
		d.Line(pdfMargin, l.y, pdfMargin+l.width, l.y, 0.4, pdfLine)
	}
	l.y += 6
}
