package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rtulke/checkmate/internal/compare"
	"github.com/rtulke/checkmate/internal/facts"
	"github.com/rtulke/checkmate/internal/report"
)

// fileKind tells reports from policies: by extension, and by the first
// character for other names (a JSON report starts with "{").
func fileKind(path string) (string, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		return "report", nil
	case ".yml", ".yaml":
		return "policy", nil
	}
	fh, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	r := bufio.NewReader(fh)
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "policy", nil
		}
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '{':
			return "report", nil
		}
		return "policy", nil
	}
}

func cmdDiff(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs, false)
	format := fs.String("format", "text", "output format: text or json")
	color := fs.String("color", "auto", "colored output: auto, always or never")
	fs.Usage = func() {
		fmt.Fprintln(stderr, `Usage: checkmate diff [flags] <old> <new>

Compares two JSON reports (new problems, fixed checks, newly waived checks, other status
changes, added and removed checks, score) or two policies (added, removed
and changed checks, field by field). The kind is taken from the file
extension: .json for reports, .yml/.yaml for policies.

Exit codes: 0 no differences, 1 differences, 2 error.

Flags:`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitCompliant
		}
		return exitUsage
	}
	if fs.NArg() != 2 {
		fs.Usage()
		return exitUsage
	}
	if *format != "text" && *format != "json" {
		fmt.Fprintf(stderr, "checkmate: unknown format %q (use text or json)\n", *format)
		return exitUsage
	}
	oldPath, newPath := fs.Arg(0), fs.Arg(1)
	oldKind, err := fileKind(oldPath)
	if err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	newKind, err := fileKind(newPath)
	if err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	if oldKind != newKind {
		fmt.Fprintf(stderr, "checkmate: cannot compare a %s (%s) with a %s (%s)\n", oldKind, oldPath, newKind, newPath)
		return exitUsage
	}

	paint := func(c, s string) string { return s }
	if *format == "text" && (*color == "always" || (*color == "auto" && useColor(stdout))) {
		paint = func(c, s string) string { return c + s + "\033[0m" }
	}
	// emit writes the diff and returns the exit code.
	emit := func(v any, empty bool, text func()) int {
		if *format == "json" {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(v); err != nil {
				fmt.Fprintln(stderr, "checkmate:", err)
				return exitUsage
			}
		} else {
			text()
		}
		if empty {
			return exitCompliant
		}
		return exitNotCompliant
	}

	if oldKind == "report" {
		old, err := report.ReadReports(oldPath)
		if err != nil {
			fmt.Fprintln(stderr, "checkmate:", err)
			return exitUsage
		}
		cur, err := report.ReadReports(newPath)
		if err != nil {
			fmt.Fprintln(stderr, "checkmate:", err)
			return exitUsage
		}
		d := compare.Reports(old, cur)
		return emit(d, d.Empty(), func() { compare.WriteReportText(stdout, d, paint) })
	}

	vars, err := common.vars()
	if err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	old, err := common.load(oldPath)
	if err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	cur, err := common.load(newPath)
	if err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	d := compare.Policies(old, cur, facts.Gather(), vars)
	return emit(d, d.Empty(), func() { compare.WritePolicyText(stdout, d, paint) })
}
