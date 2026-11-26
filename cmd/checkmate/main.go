// Command checkmate runs command-based compliance checks defined in YAML.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/rtulke/checkmate/internal/engine"
	"github.com/rtulke/checkmate/internal/facts"
	"github.com/rtulke/checkmate/internal/policy"
	"github.com/rtulke/checkmate/internal/report"
	"github.com/rtulke/checkmate/internal/runner"

	"golang.org/x/term"
	"gopkg.in/yaml.v3"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

// Exit codes.
const (
	exitCompliant    = 0
	exitNotCompliant = 1
	exitUsage        = 2
)

const usage = `checkmate - command-based compliance checks

Usage:
  checkmate run      [flags] <policy.yml>   run checks and report results
  checkmate validate [flags] <policy.yml>   check a policy for errors without running it
  checkmate list     [flags] <policy.yml>   list checks and the commands they would run
  checkmate export   [flags] <report.json>...  convert or merge JSON reports (html, pdf, csv, ...)
  checkmate diff     [flags] <old> <new>    compare two reports (.json) or two policies (.yml)
  checkmate facts                           print the facts gathered for this host
  checkmate version                         print the version

Run "checkmate <command> -h" for the flags of a command.

Exit codes:
  0  all selected checks passed (compliant)
  1  at least one check failed or could not be evaluated
  2  usage error or invalid policy
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "run":
		return cmdRun(rest, stdout, stderr)
	case "validate":
		return cmdValidate(rest, stdout, stderr)
	case "list":
		return cmdList(rest, stdout, stderr)
	case "export":
		return cmdExport(rest, os.Stdin, stdout, stderr)
	case "diff":
		return cmdDiff(rest, stdout, stderr)
	case "facts":
		return cmdFacts(stdout)
	case "version", "--version":
		fmt.Fprintf(stdout, "checkmate %s\n", version)
		return exitCompliant
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		return exitCompliant
	}
	fmt.Fprintf(stderr, "checkmate: unknown command %q\n\n%s", cmd, usage)
	return exitUsage
}

// commonFlags are shared by run, validate and list.
type commonFlags struct {
	tags          string
	skipTags      string
	ids           string
	extraVars     multiFlag
	allowInsecure bool
}

func (c *commonFlags) register(fs *flag.FlagSet, withFilter bool) {
	if withFilter {
		fs.StringVar(&c.tags, "tags", "", "select checks by tags: \",\" = or, \"+\" = and (e.g. compliance+full,quality)")
		fs.StringVar(&c.tags, "t", "", "shorthand for --tags")
		fs.StringVar(&c.skipTags, "skip-tags", "", "exclude checks by tags (same syntax as --tags)")
		fs.StringVar(&c.ids, "id", "", "select checks by ID, comma-separated glob patterns (e.g. SSH-*)")
	}
	fs.Var(&c.extraVars, "extra-var", "set a variable, key=value (repeatable, overrides policy vars)")
	fs.Var(&c.extraVars, "e", "shorthand for --extra-var")
	fs.BoolVar(&c.allowInsecure, "allow-insecure-policy", false,
		"load policy files even if they are writable by non-root users while running as root")
}

// splitHostPort separates a trailing port from an ssh destination. A bare
// IPv6 address has several colons and no port; with a port it is written
// [addr]:port.
func splitHostPort(dest string) (string, int) {
	i := strings.LastIndexByte(dest, ':')
	if i < 0 {
		return dest, 0
	}
	name, digits := dest[:i], dest[i+1:]
	if strings.Contains(name, ":") && !strings.HasSuffix(name, "]") {
		return dest, 0
	}
	port, err := strconv.Atoi(digits)
	if err != nil || port <= 0 {
		return dest, 0
	}
	return strings.Trim(name, "[]"), port
}

func (c *commonFlags) filter() engine.Filter {
	return engine.Filter{
		Tags:     engine.ParseTagExpr(c.tags),
		SkipTags: engine.ParseTagExpr(c.skipTags),
		IDs:      engine.ParseIDs(c.ids),
	}
}

func (c *commonFlags) vars() (map[string]any, error) {
	vars := map[string]any{}
	for _, kv := range c.extraVars {
		key, raw, ok := strings.Cut(kv, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, fmt.Errorf("invalid --extra-var %q, expected key=value", kv)
		}
		vars[strings.TrimSpace(key)] = extraVarValue(raw)
	}
	return vars, nil
}

// extraVarValue reads the value of an --extra-var as YAML, so that lists,
// mappings, booleans and plain numbers arrive typed. A number is only kept
// when it reads back exactly as typed: 1.10 is a version, 0644 a file mode
// and 1e3 a string, not 1.1, 420 and 1000.
func extraVarValue(raw string) any {
	var value any
	if err := yaml.Unmarshal([]byte(raw), &value); err != nil {
		return raw
	}
	switch value.(type) {
	case []any, map[string]any, bool:
		return value
	case int, int64, uint64, float64:
		if fmt.Sprint(value) == strings.TrimSpace(raw) {
			return value
		}
	}
	return raw
}

func (c *commonFlags) load(path string) (*policy.Policy, error) {
	return policy.Load(path, policy.LoadOptions{AllowInsecure: c.allowInsecure})
}

func cmdRun(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs, true)
	format := fs.String("format", "text", "output format on stdout: "+report.FormatNames())
	exports := fs.String("export", "", "also write these formats to files, comma-separated, e.g. html,pdf,json; syslog[:<url>] sends to syslog")
	output := fs.String("output", "", "base name or directory of the --export files (default: checkmate-<host>-<time>)")
	fs.StringVar(output, "o", "", "shorthand for --output")
	// Deprecated since 2.1, replaced by --export; kept working, not shown.
	jsonOut := fs.String("json-out", "", "")
	junitOut := fs.String("junit-out", "", "")
	attackOut := fs.String("attack-layer", "", "")
	jobs := fs.Int("jobs", 0, "number of checks to run in parallel (default: number of CPUs)")
	fs.IntVar(jobs, "j", 0, "shorthand for --jobs")
	verbosity := 0
	fs.Var(countFlag{&verbosity, 1}, "v", "more output, repeatable: -v reasons and severity, -vv details of problems, -vvv debug")
	fs.Var(countFlag{&verbosity, 1}, "verbose", "same as -v")
	fs.Var(countFlag{&verbosity, 2}, "vv", "same as -v -v: commands, output, rationale and remediation of problems")
	fs.Var(countFlag{&verbosity, 3}, "vvv", "same as -v -v -v: debug details of every check, facts and loaded files")
	fs.Var(countFlag{&verbosity, 3}, "debug", "same as -vvv")
	quiet := fs.Bool("quiet", false, "show only failed checks and the summary")
	fs.BoolVar(quiet, "q", false, "shorthand for --quiet")
	color := fs.String("color", "auto", "colored output: auto, always or never")
	noColor := fs.Bool("no-color", false, "shorthand for --color never")
	failOn := fs.String("fail-on", "", "lowest severity whose failures count as non-compliant: info, low, medium, high, critical (default: policy defaults.fail_on or low)")
	var waiverFiles multiFlag
	fs.Var(&waiverFiles, "waivers", "file with accepted deviations (repeatable), see the waivers reference")
	ignoreWaivers := fs.Bool("ignore-waivers", false, "report every result as if no waiver existed")
	host := fs.String("host", "", "run the checks on another host over SSH: [user@]host[:port]")
	become := fs.Bool("become", false, "with --host: run every command through sudo -n")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: checkmate run [flags] <policy.yml>")
		printDefaults(fs, "json-out", "junit-out", "attack-layer")
	}

	path, code := parseWithPolicy(fs, args)
	if path == "" {
		return code
	}
	if *failOn != "" && policy.SeverityRank(*failOn) < 0 {
		fmt.Fprintf(stderr, "checkmate: invalid --fail-on %q (use %s)\n", *failOn, strings.Join(policy.Severities, ", "))
		return exitUsage
	}
	if *color != "auto" && *color != "always" && *color != "never" {
		fmt.Fprintf(stderr, "checkmate: invalid --color %q (use auto, always or never)\n", *color)
		return exitUsage
	}
	stdoutFormat, ok := report.LookupFormat(*format)
	if !ok {
		fmt.Fprintf(stderr, "checkmate: unknown format %q (use %s)\n", *format, report.FormatNames())
		return exitUsage
	}
	if stdoutFormat.Binary && isTerminal(stdout) {
		fmt.Fprintf(stderr, "checkmate: not writing %s to a terminal; use --export %s or redirect stdout\n", *format, *format)
		return exitUsage
	}
	plan, err := parseExports(*exports)
	if err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	if *output != "" && plan.empty() {
		fmt.Fprintln(stderr, "checkmate: -o needs --export, e.g. --export html,pdf")
		return exitUsage
	}
	// A run can take minutes: find out now, not afterwards, that the export
	// files cannot be written.
	if len(plan.formats) > 0 {
		if err := checkWritableDir(filepath.Dir(resolveBase(*output, "checkmate"))); err != nil {
			fmt.Fprintln(stderr, "checkmate: cannot write exports:", err)
			return exitUsage
		}
	}
	vars, err := common.vars()
	if err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	p, err := common.load(path)
	if err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}

	var waivers []policy.Waiver
	for _, f := range waiverFiles {
		w, err := policy.LoadWaivers(f, policy.LoadOptions{AllowInsecure: common.allowInsecure})
		if err != nil {
			fmt.Fprintln(stderr, "checkmate:", err)
			return exitUsage
		}
		// Files named later are more specific and take precedence.
		waivers = append(w, waivers...)
	}

	// Checks run in their own process groups, so a signal that ends checkmate
	// does not reach them: cancel the run instead, which kills them.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	hostFacts := facts.Gather()
	var target *runner.Target
	if *host != "" {
		name, port := splitHostPort(*host)
		target, err = runner.NewTarget(name, port, *become)
		if err == nil {
			err = target.Open()
		}
		if err == nil {
			defer target.Close()
			// The facts of the host decide which commands run there, and
			// gathering them proves that it can be reached.
			hostFacts, err = target.Facts(ctx)
		}
		if err != nil {
			fmt.Fprintln(stderr, "checkmate:", err)
			return exitUsage
		}
	} else if *become {
		fmt.Fprintln(stderr, "checkmate: --become needs --host; run checkmate itself with sudo for local checks")
		return exitUsage
	}
	r := engine.Run(ctx, p, engine.Options{
		Facts:         hostFacts,
		Target:        target,
		Vars:          vars,
		Filter:        common.filter(),
		Jobs:          *jobs,
		FailOn:        *failOn,
		Waivers:       waivers,
		IgnoreWaivers: *ignoreWaivers,
	})

	r.Version = version
	opts := report.Options{
		Version:   version,
		Verbosity: minInt(verbosity, 3),
		Quiet:     *quiet,
	}
	// The result goes to stdout first, so that a failing export (a full disk,
	// an unreachable syslog server) does not cost the result of the run.
	stdoutOpts := opts
	stdoutOpts.Color = !*noColor && (*color == "always" || (*color == "auto" && useColor(stdout)))
	stdoutOpts.Width = terminalWidth(stdout)
	if err := stdoutFormat.Write(stdout, []*engine.Report{r}, stdoutOpts); err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	if err := export([]*engine.Report{r}, plan, resolveBase(*output, defaultBase(r)), opts, stderr); err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	for _, legacy := range []struct{ path, format string }{{*jsonOut, "json"}, {*junitOut, "junit"}, {*attackOut, "attack"}} {
		if legacy.path == "" {
			continue
		}
		f, _ := report.LookupFormat(legacy.format)
		if err := writeFile(legacy.path, func(w io.Writer) error { return f.Write(w, []*engine.Report{r}, opts) }); err != nil {
			fmt.Fprintln(stderr, "checkmate:", err)
			return exitUsage
		}
	}
	if r.Summary.Total == 0 {
		fmt.Fprintln(stderr, "checkmate: no checks selected")
		return exitUsage
	}
	if r.Summary.Evaluated == 0 {
		fmt.Fprintln(stderr, "checkmate: no check was evaluated (all skipped or not applicable)")
		return exitUsage
	}
	if r.Summary.Compliant {
		return exitCompliant
	}
	return exitNotCompliant
}

func cmdValidate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs, false)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: checkmate validate [flags] <policy.yml>")
		fs.PrintDefaults()
	}
	path, code := parseWithPolicy(fs, args)
	if path == "" {
		return code
	}
	vars, err := common.vars()
	if err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	p, err := common.load(path)
	if err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	checks, errs := policy.Expand(p, facts.Gather(), vars)
	for _, e := range errs {
		fmt.Fprintln(stderr, e.Error())
	}
	if len(errs) > 0 {
		fmt.Fprintf(stderr, "\n%d error(s) in %s\n", len(errs), path)
		return exitUsage
	}
	fmt.Fprintf(stdout, "%s: OK (%d checks from %d file(s), %d snippets)\n",
		path, len(checks), len(p.Files), len(p.Snippets))
	return exitCompliant
}

func cmdList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs, true)
	verbose := fs.Bool("verbose", false, "show the command each check runs on this platform")
	fs.BoolVar(verbose, "v", false, "shorthand for --verbose")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: checkmate list [flags] <policy.yml>")
		fs.PrintDefaults()
	}
	path, code := parseWithPolicy(fs, args)
	if path == "" {
		return code
	}
	vars, err := common.vars()
	if err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	p, err := common.load(path)
	if err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	f := facts.Gather()
	checks, errs := policy.Expand(p, f, vars)
	for _, e := range errs {
		fmt.Fprintln(stderr, e.Error())
	}

	filter := common.filter()
	keys := f.PlatformKeys()
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tSEVERITY\tTAGS\tNAME")
	for _, c := range checks {
		if !filter.Match(c.ID, c.Tags) {
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", c.ID, c.Severity, strings.Join(c.Tags, ","), c.Name)
		if *verbose {
			cmd, ok, err := c.Command(c.Run, keys)
			switch {
			case err != nil:
				cmd = "error: " + err.Error()
			case !ok:
				cmd = "(not applicable on this platform)"
			}
			fmt.Fprintf(tw, "\t\t\t  $ %s\n", strings.ReplaceAll(strings.TrimSpace(cmd), "\n", "\n\t\t\t    "))
			fmt.Fprintf(tw, "\t\t\t  expect: %s\n", c.Expect.String())
		}
	}
	tw.Flush()
	if len(errs) > 0 {
		return exitUsage
	}
	return exitCompliant
}

func cmdFacts(stdout io.Writer) int {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	f := facts.Gather()
	out := struct {
		facts.Facts
		PlatformKeys []string `json:"platform_keys"`
	}{f, f.PlatformKeys()}
	if err := enc.Encode(out); err != nil {
		return exitUsage
	}
	return exitCompliant
}

// parseWithPolicy parses flags (which may appear before or after the
// policy argument) and returns the single policy path.
func parseWithPolicy(fs *flag.FlagSet, args []string) (string, int) {
	if err := fs.Parse(reorderArgs(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return "", exitCompliant
		}
		return "", exitUsage
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return "", exitUsage
	}
	return fs.Arg(0), exitCompliant
}

// reorderArgs moves flags in front of positional arguments so that
// "checkmate run policy.yml --tags x" works like "checkmate run --tags x policy.yml".
func reorderArgs(fs *flag.FlagSet, args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			positional = append(positional, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			positional = append(positional, arg)
			continue
		}
		flags = append(flags, arg)
		name := strings.TrimLeft(arg, "-")
		if strings.Contains(name, "=") {
			continue
		}
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return append(flags, positional...)
}

// printDefaults prints the flags of fs except the hidden ones.
func printDefaults(fs *flag.FlagSet, hidden ...string) {
	skip := map[string]bool{}
	for _, h := range hidden {
		skip[h] = true
	}
	all := flag.NewFlagSet(fs.Name(), flag.ContinueOnError)
	all.SetOutput(fs.Output())
	fs.VisitAll(func(f *flag.Flag) {
		if !skip[f.Name] {
			all.Var(f.Value, f.Name, f.Usage)
		}
	})
	all.PrintDefaults()
}

// terminalWidth returns the width of the terminal stdout is attached to, or
// 0 if it is not a terminal. COLUMNS overrides the detected width.
func terminalWidth(w io.Writer) int {
	if c, err := strconv.Atoi(os.Getenv("COLUMNS")); err == nil && c > 0 {
		return c
	}
	f, ok := w.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return 0
	}
	width, _, err := term.GetSize(int(f.Fd()))
	if err != nil {
		return 0
	}
	return width
}

func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" || os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }

func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// countFlag is a boolean flag that adds step to a counter each time it is
// given, so that -v -v equals -vv.
type countFlag struct {
	n    *int
	step int
}

func (c countFlag) String() string   { return "" }
func (c countFlag) IsBoolFlag() bool { return true }

func (c countFlag) Set(s string) error {
	switch s {
	case "", "true":
		*c.n += c.step
	case "false":
	default:
		v, err := strconv.Atoi(s)
		if err != nil {
			return fmt.Errorf("expected a number, got %q", s)
		}
		*c.n = v
	}
	return nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
