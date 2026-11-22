package compare

import (
	"fmt"
	"io"
	"strings"
)

// Painter colors text for terminals; it returns s unchanged without color.
type Painter func(color, s string) string

const (
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
	cyan   = "\033[36m"
	dim    = "\033[2m"
	bold   = "\033[1m"
)

func scoreString(s float64) string {
	if s < 0 {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", s)
}

// WriteReportText writes a report diff for humans.
func WriteReportText(w io.Writer, d ReportDiff, paint Painter) {
	for i, h := range d.Hosts {
		if i > 0 {
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "%s %s\n%s %s\n", paint(red, "---"), h.Old, paint(green, "+++"), h.New)
		delta := h.NewScore - h.OldScore
		color := dim
		switch {
		case delta > 0:
			color = green
		case delta < 0:
			color = red
		}
		fmt.Fprintf(w, "score %s -> %s %s\n", scoreString(h.OldScore), scoreString(h.NewScore),
			paint(color, fmt.Sprintf("(%+.1f)", delta)))
		if h.Empty() {
			fmt.Fprintln(w, paint(dim, "no changes"))
			continue
		}
		section := func(title, color, marker string, list []StatusChange, transition bool) {
			if len(list) == 0 {
				return
			}
			fmt.Fprintf(w, "\n%s (%d)\n", paint(bold, title), len(list))
			for _, c := range list {
				status := string(c.New)
				if transition {
					status = string(c.Old) + " -> " + string(c.New)
				} else if c.New == "" {
					status = string(c.Old)
				}
				fmt.Fprintf(w, "  %s %-16s %s  %s %s\n", paint(color, marker), status, c.ID,
					paint(dim, "["+c.Severity+"]"), c.Name)
				if c.Reason != "" && marker == "+" {
					fmt.Fprintf(w, "      %s\n", paint(dim, oneLine(c.Reason)))
				}
			}
		}
		section("New problems", red, "+", h.Regressions, true)
		section("Fixed", green, "-", h.Fixed, true)
		section("Changed", yellow, "~", h.Changed, true)
		section("Added checks", cyan, ">", h.Added, false)
		section("Removed checks", cyan, "<", h.Removed, false)
	}
	for _, l := range d.OnlyOld {
		fmt.Fprintf(w, "\n%s %s\n", paint(red, "only in old:"), l)
	}
	for _, l := range d.OnlyNew {
		fmt.Fprintf(w, "\n%s %s\n", paint(green, "only in new:"), l)
	}
}

// WritePolicyText writes a policy diff for humans.
func WritePolicyText(w io.Writer, d PolicyDiff, paint Painter) {
	fmt.Fprintf(w, "%s %s (%d checks)\n%s %s (%d checks)\n", paint(red, "---"), d.Old, d.OldCount,
		paint(green, "+++"), d.New, d.NewCount)
	for _, e := range d.Errors {
		fmt.Fprintf(w, "%s %s\n", paint(yellow, "warning:"), e)
	}
	if d.Empty() {
		fmt.Fprintln(w, paint(dim, "no changes"))
		return
	}
	if len(d.Policy) > 0 {
		fmt.Fprintf(w, "\n%s\n", paint(bold, "Policy"))
		for _, f := range d.Policy {
			writeField(w, f, "  ", paint)
		}
	}
	if len(d.Added) > 0 {
		fmt.Fprintf(w, "\n%s (%d)\n", paint(bold, "Added checks"), len(d.Added))
		for _, c := range d.Added {
			fmt.Fprintf(w, "  %s %s  %s %s\n", paint(green, "+"), c.ID, paint(dim, "["+c.Severity+"]"), c.Name)
		}
	}
	if len(d.Removed) > 0 {
		fmt.Fprintf(w, "\n%s (%d)\n", paint(bold, "Removed checks"), len(d.Removed))
		for _, c := range d.Removed {
			fmt.Fprintf(w, "  %s %s  %s %s\n", paint(red, "-"), c.ID, paint(dim, "["+c.Severity+"]"), c.Name)
		}
	}
	if len(d.Changed) > 0 {
		fmt.Fprintf(w, "\n%s (%d)\n", paint(bold, "Changed checks"), len(d.Changed))
		for _, c := range d.Changed {
			fmt.Fprintf(w, "  %s %s  %s\n", paint(yellow, "~"), c.ID, c.Name)
			for _, f := range c.Fields {
				writeField(w, f, "      ", paint)
			}
		}
	}
}

// writeField shows a changed value: inline if both sides are one line,
// otherwise as a line diff.
func writeField(w io.Writer, f FieldChange, indent string, paint Painter) {
	if !strings.Contains(f.Old, "\n") && !strings.Contains(f.New, "\n") && len(f.Old)+len(f.New) < 100 {
		fmt.Fprintf(w, "%s%s: %s -> %s\n", indent, f.Field, quoteEmpty(f.Old), quoteEmpty(f.New))
		return
	}
	fmt.Fprintf(w, "%s%s:\n", indent, f.Field)
	for _, l := range lineDiff(splitLines(f.Old), splitLines(f.New)) {
		switch l.op {
		case '-':
			fmt.Fprintf(w, "%s  %s\n", indent, paint(red, "- "+l.text))
		case '+':
			fmt.Fprintf(w, "%s  %s\n", indent, paint(green, "+ "+l.text))
		default:
			fmt.Fprintf(w, "%s  %s\n", indent, paint(dim, "  "+l.text))
		}
	}
}

func quoteEmpty(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

func oneLine(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}

type diffLine struct {
	op   byte // ' ', '-' or '+'
	text string
}

// lineDiff computes a minimal line diff (longest common subsequence).
// Commands and descriptions are short, so the quadratic table is fine.
func lineDiff(a, b []string) []diffLine {
	n, m := len(a), len(b)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else {
				lcs[i][j] = max(lcs[i+1][j], lcs[i][j+1])
			}
		}
	}
	var out []diffLine
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			out = append(out, diffLine{' ', a[i]})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, diffLine{'-', a[i]})
			i++
		default:
			out = append(out, diffLine{'+', b[j]})
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, diffLine{'-', a[i]})
	}
	for ; j < m; j++ {
		out = append(out, diffLine{'+', b[j]})
	}
	return out
}
