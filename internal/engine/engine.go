// Package engine runs the checks of a policy and collects the results.
package engine

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/rtulke/checkmate/internal/expect"
	"github.com/rtulke/checkmate/internal/facts"
	"github.com/rtulke/checkmate/internal/policy"
	"github.com/rtulke/checkmate/internal/runner"
)

// Status is the outcome of a single check.
type Status string

const (
	StatusPass  Status = "PASS"  // the expectation holds
	StatusFail  Status = "FAIL"  // the expectation does not hold
	StatusWarn  Status = "WARN"  // failed, but below the fail_on severity threshold
	StatusError Status = "ERROR" // the check could not be evaluated; counts as non-compliant
	StatusSkip  Status = "SKIP"  // `when` or `only_if` excluded the check
	StatusNA    Status = "N/A"   // no command variant for this platform
)

// Result is the outcome of one check.
type Result struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Tags        []string `json:"tags,omitempty"`
	Severity    string   `json:"severity,omitempty"`
	Status      Status   `json:"status"`
	Message     string   `json:"message,omitempty"`
	Expected    string   `json:"expected,omitempty"`
	When        []string `json:"when,omitempty"`
	OnlyIf      string   `json:"only_if,omitempty"`
	Command     string   `json:"command,omitempty"`
	Shell       string   `json:"shell,omitempty"`
	RC          *int     `json:"rc,omitempty"`
	Stdout      string   `json:"stdout,omitempty"`
	Stderr      string   `json:"stderr,omitempty"`
	DurationMS  int64    `json:"duration_ms"`
	Remediation string   `json:"remediation,omitempty"`
	Reference   string   `json:"reference,omitempty"`
	Location    string   `json:"location"`
}

// Summary counts results by status.
type Summary struct {
	Total         int     `json:"total"`
	Passed        int     `json:"passed"`
	Failed        int     `json:"failed"`
	Warnings      int     `json:"warnings"`
	Errors        int     `json:"errors"`
	Skipped       int     `json:"skipped"`
	NotApplicable int     `json:"not_applicable"`
	FailOn        string  `json:"fail_on"`
	Score         float64 `json:"score"` // weighted share of passed checks, 0-100
	Compliant     bool    `json:"compliant"`
}

// Report is the outcome of a policy run.
type Report struct {
	Policy        string      `json:"policy"`
	PolicyVersion string      `json:"policy_version,omitempty"`
	PolicyPath    string      `json:"policy_path"`
	PolicyFiles   []string    `json:"policy_files,omitempty"`
	Facts         facts.Facts `json:"facts"`
	Started       time.Time   `json:"started"`
	DurationMS    int64       `json:"duration_ms"`
	Summary       Summary     `json:"summary"`
	Results       []Result    `json:"results"`
}

// Options configure a run.
type Options struct {
	Facts  facts.Facts
	Vars   map[string]any // extra variables, override policy variables
	Filter Filter
	Jobs   int // parallel checks, <= 0 means number of CPUs
	// FailOn is the lowest severity whose failures make the run
	// non-compliant; failures below it are reported as warnings. Empty
	// means the policy default (defaults.fail_on, "low" if unset).
	FailOn string
}

// Run expands and executes all selected checks of a policy.
func Run(ctx context.Context, p *policy.Policy, opts Options) *Report {
	started := time.Now()
	checks, expandErrs := policy.Expand(p, opts.Facts, opts.Vars)

	// Broken checks are always reported, regardless of filters: a policy
	// that cannot be evaluated must never look compliant.
	var results []Result
	for _, e := range expandErrs {
		id := e.ID
		if id == "" {
			id = e.Source.Location()
		}
		results = append(results, Result{
			ID:       id,
			Name:     "invalid check definition",
			Status:   StatusError,
			Message:  e.Err.Error(),
			Location: e.Source.Location(),
		})
	}

	var selected []*policy.Check
	for _, c := range checks {
		if opts.Filter.Match(c.ID, c.Tags) {
			selected = append(selected, c)
		}
	}

	jobs := opts.Jobs
	if jobs <= 0 {
		jobs = runtime.NumCPU()
	}
	checkResults := make([]Result, len(selected))
	sem := make(chan struct{}, jobs)
	var wg sync.WaitGroup
	platformKeys := opts.Facts.PlatformKeys()
	failOn := opts.FailOn
	if failOn == "" {
		failOn = p.Defaults.FailOn
	}
	threshold := policy.SeverityRank(failOn)
	for i, c := range selected {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, c *policy.Check) {
			defer wg.Done()
			defer func() { <-sem }()
			res := runCheck(ctx, p, c, platformKeys)
			// Failures below the threshold (always including "info") are
			// warnings. Errors are never downgraded: a check that cannot be
			// evaluated must not look harmless.
			if res.Status == StatusFail && (policy.SeverityRank(res.Severity) < threshold || res.Severity == "info") {
				res.Status = StatusWarn
			}
			checkResults[i] = res
		}(i, c)
	}
	wg.Wait()
	results = append(results, checkResults...)

	report := &Report{
		Policy:        p.Name,
		PolicyVersion: p.Version,
		PolicyPath:    p.Path,
		PolicyFiles:   p.Files,
		Facts:         opts.Facts,
		Started:       started,
		DurationMS:    time.Since(started).Milliseconds(),
		Results:       results,
	}
	report.Summary = summarize(results)
	report.Summary.FailOn = failOn
	return report
}

func runCheck(ctx context.Context, p *policy.Policy, c *policy.Check, platformKeys []string) (res Result) {
	start := time.Now()
	res = Result{
		ID:          c.ID,
		Name:        c.Name,
		Description: c.Description,
		Tags:        c.Tags,
		Severity:    c.Severity,
		Expected:    c.Expect.String(),
		When:        c.When,
		Remediation: c.Remediation,
		Reference:   c.Reference,
		Location:    c.Source.Location(),
	}
	defer func() {
		res.DurationMS = time.Since(start).Milliseconds()
		// A panic in a single check must not hide the check or crash the
		// run; it becomes an error result instead.
		if r := recover(); r != nil {
			res.Status = StatusError
			res.Message = fmt.Sprintf("internal error: %v", r)
		}
	}()

	applies, cond, err := c.Applies()
	if err != nil {
		return withStatus(res, StatusError, err.Error())
	}
	if !applies {
		return withStatus(res, StatusSkip, fmt.Sprintf("when: %s is false", cond))
	}

	command, ok, err := c.Command(c.Run, platformKeys)
	if err != nil {
		return withStatus(res, StatusError, err.Error())
	}
	if !ok {
		return withStatus(res, StatusNA, notApplicableMessage(c, c.Run, platformKeys))
	}
	res.Command = command

	if !c.OnlyIf.IsZero() {
		guard, ok, err := c.Command(c.OnlyIf, platformKeys)
		if err != nil {
			return withStatus(res, StatusError, "only_if: "+err.Error())
		}
		if !ok {
			return withStatus(res, StatusNA, notApplicableMessage(c, c.OnlyIf, platformKeys))
		}
		res.OnlyIf = guard
		out, err := execute(ctx, p, c, guard)
		if err != nil {
			return withStatus(res, StatusError, "only_if: "+err.Error())
		}
		if out.RC != 0 {
			return withStatus(res, StatusSkip, fmt.Sprintf("only_if: %q returned exit code %d", oneLine(guard), out.RC))
		}
	}

	out, err := execute(ctx, p, c, command)
	res.Shell = out.Shell
	res.Stdout = out.Stdout
	res.Stderr = out.Stderr
	if err != nil {
		return withStatus(res, StatusError, err.Error())
	}
	rc := out.RC
	res.RC = &rc

	if runner.IsPOSIXShell(out.Shell) && (rc == 126 || rc == 127) {
		return withStatus(res, StatusError, fmt.Sprintf("command not found or not executable (exit code %d)%s",
			rc, stderrHint(out.Stderr)))
	}
	if c.Expect.NeedsOutput() && !containsInt(c.AllowRC, rc) {
		return withStatus(res, StatusError, fmt.Sprintf("command failed with exit code %d%s "+
			"(add allow_rc to accept it)", rc, stderrHint(out.Stderr)))
	}

	ok, msg, err := c.Expect.Eval(expect.Output{RC: rc, Stdout: out.Stdout, Stderr: out.Stderr}, c.Mode)
	if err != nil {
		return withStatus(res, StatusError, err.Error())
	}
	if ok {
		return withStatus(res, StatusPass, "")
	}
	return withStatus(res, StatusFail, msg)
}

func execute(ctx context.Context, p *policy.Policy, c *policy.Check, command string) (runner.Result, error) {
	return runner.Run(ctx, runner.Request{
		Command: command,
		Shell:   c.Shell,
		Dir:     c.Source.Dir,
		Env:     p.Env,
		Timeout: c.Timeout,
	})
}

func withStatus(res Result, status Status, msg string) Result {
	res.Status = status
	res.Message = msg
	return res
}

func notApplicableMessage(c *policy.Check, spec policy.CommandSpec, platformKeys []string) string {
	platforms := spec.Platforms()
	if spec.Use != "" {
		platforms = nil
		if s, ok := c.SnippetPlatforms(spec.Use); ok {
			platforms = s
		}
	}
	return fmt.Sprintf("no command for this platform (%s); defined for: %s",
		strings.Join(platformKeys[:len(platformKeys)-1], ", "), strings.Join(platforms, ", "))
}

func stderrHint(stderr string) string {
	line := oneLine(stderr)
	if line == "" {
		return ""
	}
	return ": " + line
}

func oneLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i] + " ..."
	}
	if len(s) > 160 {
		s = s[:157] + "..."
	}
	return s
}

func containsInt(list []int, v int) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func summarize(results []Result) Summary {
	s := Summary{Total: len(results)}
	for _, r := range results {
		switch r.Status {
		case StatusPass:
			s.Passed++
		case StatusFail:
			s.Failed++
		case StatusWarn:
			s.Warnings++
		case StatusError:
			s.Errors++
		case StatusSkip:
			s.Skipped++
		case StatusNA:
			s.NotApplicable++
		}
	}
	s.Compliant = s.Failed == 0 && s.Errors == 0

	// Score: passed weight / evaluated weight. Broken definitions without
	// a severity count as medium so they lower the score.
	var passed, total int
	for _, r := range results {
		sev := r.Severity
		if sev == "" {
			sev = "medium"
		}
		w := policy.SeverityWeight(sev)
		switch r.Status {
		case StatusPass:
			passed += w
			total += w
		case StatusFail, StatusWarn, StatusError:
			total += w
		}
	}
	s.Score = 100
	if total > 0 {
		s.Score = float64(int(float64(passed)*1000/float64(total))) / 10
	}
	return s
}
