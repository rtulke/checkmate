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
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/rtulke/checkmate/internal/engine"
	"github.com/rtulke/checkmate/internal/facts"
	"github.com/rtulke/checkmate/internal/policy"
	"github.com/rtulke/checkmate/internal/report"

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
		var value any
		if err := yaml.Unmarshal([]byte(raw), &value); err != nil || value == nil {
			value = raw
		}
		vars[strings.TrimSpace(key)] = value
	}
	return vars, nil
}

func (c *commonFlags) load(path string) (*policy.Policy, error) {
	return policy.Load(path, policy.LoadOptions{AllowInsecure: c.allowInsecure})
}

func cmdRun(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs, true)
	format := fs.String("format", "text", "output format on stdout: text, json or junit")
	jsonOut := fs.String("json-out", "", "also write a JSON report to this file")
	junitOut := fs.String("junit-out", "", "also write a JUnit XML report to this file")
	jobs := fs.Int("jobs", 0, "number of checks to run in parallel (default: number of CPUs)")
	fs.IntVar(jobs, "j", 0, "shorthand for --jobs")
	verbose := fs.Bool("verbose", false, "show command and output of failed checks")
	fs.BoolVar(verbose, "v", false, "shorthand for --verbose")
	quiet := fs.Bool("quiet", false, "show only failed checks and the summary")
	fs.BoolVar(quiet, "q", false, "shorthand for --quiet")
	color := fs.String("color", "auto", "colored output: auto, always or never")
	noColor := fs.Bool("no-color", false, "shorthand for --color never")
	failOn := fs.String("fail-on", "", "lowest severity whose failures count as non-compliant: info, low, medium, high, critical (default: policy defaults.fail_on or low)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: checkmate run [flags] <policy.yml>")
		fs.PrintDefaults()
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
	if *format != "text" && *format != "json" && *format != "junit" {
		fmt.Fprintf(stderr, "checkmate: unknown format %q (use text, json or junit)\n", *format)
		return exitUsage
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	r := engine.Run(ctx, p, engine.Options{
		Facts:  facts.Gather(),
		Vars:   vars,
		Filter: common.filter(),
		Jobs:   *jobs,
		FailOn: *failOn,
	})

	if *jsonOut != "" {
		if err := writeFile(*jsonOut, func(w io.Writer) error { return report.JSON(w, r, version) }); err != nil {
			fmt.Fprintln(stderr, "checkmate:", err)
			return exitUsage
		}
	}
	if *junitOut != "" {
		if err := writeFile(*junitOut, func(w io.Writer) error { return report.JUnit(w, r) }); err != nil {
			fmt.Fprintln(stderr, "checkmate:", err)
			return exitUsage
		}
	}

	switch *format {
	case "json":
		err = report.JSON(stdout, r, version)
	case "junit":
		err = report.JUnit(stdout, r)
	default:
		err = report.Text(stdout, r, report.TextOptions{
			Color:   !*noColor && (*color == "always" || (*color == "auto" && useColor(stdout))),
			Verbose: *verbose,
			Quiet:   *quiet,
			Version: version,
			Width:   terminalWidth(stdout),
		})
	}
	if err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	if r.Summary.Total == 0 {
		fmt.Fprintln(stderr, "checkmate: no checks selected")
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

func writeFile(path string, write func(io.Writer) error) error {
	fh, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	if err := write(fh); err != nil {
		fh.Close()
		return err
	}
	return fh.Close()
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
