package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/rtulke/checkmate/internal/engine"
	"github.com/rtulke/checkmate/internal/report"
	"github.com/rtulke/checkmate/internal/syslog"
)

// exportPlan is a parsed list of formats, e.g. "html,pdf,syslog:udp://siem".
type exportPlan struct {
	formats []report.Format
	syslog  []string // syslog targets
}

func (p exportPlan) empty() bool { return len(p.formats) == 0 && len(p.syslog) == 0 }

// parseExports parses a comma-separated list of formats. "syslog" sends to
// the local syslog daemon, "syslog:<url>" to a remote collector.
func parseExports(list string) (exportPlan, error) {
	var p exportPlan
	seen := map[string]bool{}
	for _, item := range strings.Split(list, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if item == "syslog" || strings.HasPrefix(item, "syslog:") {
			p.syslog = append(p.syslog, strings.TrimPrefix(strings.TrimPrefix(item, "syslog"), ":"))
			continue
		}
		f, ok := report.LookupFormat(item)
		if !ok {
			return p, fmt.Errorf("unknown format %q (use %s, syslog or syslog:<udp|tcp|tls>://host)", item, report.FormatNames())
		}
		if !seen[f.Name] {
			seen[f.Name] = true
			p.formats = append(p.formats, f)
		}
	}
	return p, nil
}

var unsafeName = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

// defaultBase names the exports of a run: checkmate-<host>-<time>.
func defaultBase(r *engine.Report) string {
	host := unsafeName.ReplaceAllString(r.Facts.Hostname, "_")
	if host == "" {
		host = "host"
	}
	return "checkmate-" + host + "-" + r.Started.Format("20060102-150405")
}

// resolveBase applies -o: empty means def; a directory (existing, or
// ending in a path separator) gets def as file name inside it.
func resolveBase(output, def string) string {
	if output == "" {
		return def
	}
	if strings.HasSuffix(output, "/") || strings.HasSuffix(output, string(os.PathSeparator)) {
		return filepath.Join(output, filepath.Base(def))
	}
	if info, err := os.Stat(output); err == nil && info.IsDir() {
		return filepath.Join(output, filepath.Base(def))
	}
	return output
}

// stripFormatExt removes a known export extension, so that "-o x.html"
// and "-o x" both write x.html.
func stripFormatExt(base string) string {
	longest := ""
	for _, f := range report.Formats {
		if strings.HasSuffix(base, f.Ext) && len(base) > len(f.Ext) && len(f.Ext) > len(longest) {
			longest = f.Ext
		}
	}
	return strings.TrimSuffix(base, longest)
}

// export writes every format to base+extension and sends syslog messages.
// It reports each file written on stderr.
func export(rs []*engine.Report, plan exportPlan, base string, opts report.Options, stderr io.Writer) error {
	base = stripFormatExt(base)
	for _, f := range plan.formats {
		if !f.Multi && len(rs) > 1 {
			return fmt.Errorf("format %s needs a single report, got %d", f.Name, len(rs))
		}
		path := base + f.Ext
		if err := writeFile(path, func(w io.Writer) error { return f.Write(w, rs, opts) }); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		fmt.Fprintf(stderr, "checkmate: wrote %s\n", path)
	}
	for _, target := range plan.syslog {
		if err := sendSyslog(rs, target, opts.Version); err != nil {
			return err
		}
		fmt.Fprintf(stderr, "checkmate: sent results to syslog %s\n", firstNonEmpty(target, "local"))
	}
	return nil
}

func sendSyslog(rs []*engine.Report, target, version string) error {
	w, err := syslog.Dial(target, "checkmate")
	if err != nil {
		return err
	}
	defer w.Close()
	for _, m := range report.SyslogMessages(rs, version) {
		if err := w.Send(m.Severity, m.MsgID, m.Text); err != nil {
			return fmt.Errorf("syslog: %w", err)
		}
	}
	return nil
}

func cmdExport(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	formats := fs.String("format", "text", "comma-separated formats: "+report.FormatNames()+", syslog[:<url>]")
	fs.StringVar(formats, "f", "text", "shorthand for --format")
	output := fs.String("output", "", "base name (or directory) of the files to write; \"-\" for stdout")
	fs.StringVar(output, "o", "", "shorthand for --output")
	color := fs.String("color", "auto", "colored text output: auto, always or never")
	fs.Usage = func() {
		fmt.Fprintln(stderr, `Usage: checkmate export [flags] <report.json>...

Converts JSON reports of "checkmate run --format json" into other formats.
Several reports (hosts or runs) are merged into one document. A single
format without -o is written to stdout; otherwise each format is written
to <base>.<ext>, where <base> defaults to the name of the report.
"-" reads a report from stdin.

Flags:`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return exitCompliant
		}
		return exitUsage
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return exitUsage
	}
	plan, err := parseExports(*formats)
	if err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	if plan.empty() {
		fmt.Fprintln(stderr, "checkmate: no format given")
		return exitUsage
	}
	var rs []*engine.Report
	for _, path := range fs.Args() {
		var got []*engine.Report
		if path == "-" {
			got, err = report.DecodeReports(stdin, "stdin")
		} else {
			got, err = report.ReadReports(path)
		}
		if err != nil {
			fmt.Fprintln(stderr, "checkmate:", err)
			return exitUsage
		}
		rs = append(rs, got...)
	}
	opts := report.Options{
		Version: version,
		Color:   *color == "always" || (*color == "auto" && useColor(stdout)),
		Width:   terminalWidth(stdout),
	}

	toStdout := *output == "-" || (*output == "" && len(plan.formats) == 1)
	if toStdout {
		if len(plan.formats) != 1 {
			fmt.Fprintln(stderr, "checkmate: -o - needs exactly one format")
			return exitUsage
		}
		f := plan.formats[0]
		if f.Binary && isTerminal(stdout) {
			fmt.Fprintf(stderr, "checkmate: not writing %s to a terminal; use -o <file> or redirect stdout\n", f.Name)
			return exitUsage
		}
		if !f.Multi && len(rs) > 1 {
			fmt.Fprintf(stderr, "checkmate: format %s needs a single report, got %d\n", f.Name, len(rs))
			return exitUsage
		}
		if err := f.Write(stdout, rs, opts); err != nil {
			fmt.Fprintln(stderr, "checkmate:", err)
			return exitUsage
		}
		plan.formats = nil
	}

	def := "checkmate-report"
	if fs.NArg() == 1 && fs.Arg(0) != "-" {
		def = strings.TrimSuffix(fs.Arg(0), filepath.Ext(fs.Arg(0)))
	}
	opts.Color = false
	if err := export(rs, plan, resolveBase(*output, def), opts, stderr); err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	return exitCompliant
}

// writeFile writes a file atomically: into a temporary file in the same
// directory that replaces the target only when complete, so that readers
// such as the node_exporter never see a half-written file.
func writeFile(path string, write func(io.Writer) error) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o640); err != nil && !isWindows() {
		tmp.Close()
		return err
	}
	if err := write(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// checkWritableDir creates dir if needed and reports whether files can be
// created in it.
func checkWritableDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	probe, err := os.CreateTemp(dir, ".checkmate-*.tmp")
	if err != nil {
		return err
	}
	probe.Close()
	return os.Remove(probe.Name())
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	return err == nil && info.Mode()&os.ModeCharDevice != 0
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func isWindows() bool { return runtime.GOOS == "windows" }
