// Package engine runs the checks of a policy and collects the results.
package engine

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"runtime"
	"sort"
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
	StatusPass   Status = "PASS"   // the expectation holds
	StatusFail   Status = "FAIL"   // the expectation does not hold
	StatusWarn   Status = "WARN"   // failed, but below the fail_on severity threshold
	StatusError  Status = "ERROR"  // the check could not be evaluated; counts as non-compliant
	StatusSkip   Status = "SKIP"   // `when` or `only_if` excluded the check
	StatusNA     Status = "N/A"    // no command variant for this platform
	StatusWaived Status = "WAIVED" // failed, warned or errored, but a waiver accepts it
)

// Result is the outcome of one check.
type Result struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description,omitempty"`
	Tags        []string    `json:"tags,omitempty"`
	Severity    string      `json:"severity,omitempty"`
	Status      Status      `json:"status"`
	Message     string      `json:"message,omitempty"`
	Expected    string      `json:"expected,omitempty"`
	When        []string    `json:"when,omitempty"`
	OnlyIf      string      `json:"only_if,omitempty"`
	Command     string      `json:"command,omitempty"`
	Shell       string      `json:"shell,omitempty"`
	RC          *int        `json:"rc,omitempty"`
	Stdout      string      `json:"stdout,omitempty"`
	Stderr      string      `json:"stderr,omitempty"`
	DurationMS  int64       `json:"duration_ms"`
	Rationale   string      `json:"rationale,omitempty"`
	Remediation string      `json:"remediation,omitempty"`
	Reference   string      `json:"reference,omitempty"`
	Location    string      `json:"location"`
	Waiver      *WaiverInfo `json:"waiver,omitempty"`
}

// WaiverInfo records the waiver applied to a result.
type WaiverInfo struct {
	Reason string `json:"reason"`
	Until  string `json:"until,omitempty"`
	Source string `json:"source"`
	// Status is what the check would have been without the waiver; empty if
	// the check was not run (skip: true).
	Status Status `json:"status,omitempty"`
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
	Waived        int     `json:"waived"`
	Evaluated     int     `json:"evaluated"` // checks that passed, failed, warned, errored or were waived
	FailOn        string  `json:"fail_on"`
	Score         float64 `json:"score"` // weighted share of passed checks, 0-100; -1 if nothing was evaluated
	Compliant     bool    `json:"compliant"`
}

// Report is the outcome of a policy run.
type Report struct {
	Tool          string      `json:"tool"`              // always "checkmate"
	Version       string      `json:"version,omitempty"` // checkmate version that made the report
	RunID         string      `json:"run_id,omitempty"`  // random ID that ties all outputs of one run together
	Policy        string      `json:"policy"`
	PolicyVersion string      `json:"policy_version,omitempty"`
	PolicyPath    string      `json:"policy_path"`
	PolicyFiles   []string    `json:"policy_files,omitempty"`
	Facts         facts.Facts `json:"facts"`
	Started       time.Time   `json:"started"`
	DurationMS    int64       `json:"duration_ms"`
	Summary       Summary     `json:"summary"`
	Results       []Result    `json:"results"`
	Notices       []string    `json:"notices,omitempty"` // e.g. expired waivers
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
	// Waivers are added to the waivers of the policy.
	Waivers []policy.Waiver
	// IgnoreWaivers reports every result as if no waiver existed.
	IgnoreWaivers bool
	// Now is the time waiver expiry is compared against (default: now).
	Now time.Time
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
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	var waivers []policy.Waiver
	if !opts.IgnoreWaivers {
		// Waivers given on the command line are more specific than those of
		// the policy; the first matching waiver wins.
		waivers = append(append(waivers, opts.Waivers...), p.Waivers...)
	}
	var noticeMu sync.Mutex
	notices := map[string]bool{}
	notice := func(s string) {
		noticeMu.Lock()
		notices[s] = true
		noticeMu.Unlock()
	}
	for i, c := range selected {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, c *policy.Check) {
			defer wg.Done()
			defer func() { <-sem }()
			w, err := findWaiver(c, waivers, now, notice)
			if err != nil {
				checkResults[i] = withStatus(baseResult(c), StatusError, err.Error())
				return
			}
			if w != nil && w.Skip {
				res := withStatus(baseResult(c), StatusWaived, "waived, not run: "+w.Reason)
				res.Waiver = &WaiverInfo{Reason: w.Reason, Until: w.UntilString(), Source: w.Source}
				checkResults[i] = res
				return
			}
			res := runCheck(ctx, p, c, platformKeys)
			// Failures below the threshold (always including "info") are
			// warnings. Errors are never downgraded: a check that cannot be
			// evaluated must not look harmless.
			if res.Status == StatusFail && (policy.SeverityRank(res.Severity) < threshold || res.Severity == "info") {
				res.Status = StatusWarn
			}
			if w != nil && (res.Status == StatusFail || res.Status == StatusWarn || res.Status == StatusError) {
				res.Waiver = &WaiverInfo{Reason: w.Reason, Until: w.UntilString(), Source: w.Source, Status: res.Status}
				msg := "waived: " + w.Reason
				if res.Message != "" {
					msg += " (" + string(res.Status) + ": " + res.Message + ")"
				}
				res.Status = StatusWaived
				res.Message = msg
			}
			checkResults[i] = res
		}(i, c)
	}
	wg.Wait()
	results = append(results, checkResults...)

	report := &Report{
		Tool:          "checkmate",
		RunID:         newRunID(),
		Policy:        p.Name,
		PolicyVersion: p.Version,
		PolicyPath:    p.Path,
		PolicyFiles:   p.Files,
		Facts:         opts.Facts,
		Started:       started,
		DurationMS:    time.Since(started).Milliseconds(),
		Results:       results,
	}
	report.Summary = Summarize(results)
	report.Summary.FailOn = failOn
	for n := range notices {
		report.Notices = append(report.Notices, n)
	}
	sort.Strings(report.Notices)
	return report
}

// findWaiver returns the first waiver that covers the check and whose
// conditions hold. Matching waivers that have expired are reported as
// notices and ignored, so the check counts again.
func findWaiver(c *policy.Check, waivers []policy.Waiver, now time.Time, notice func(string)) (*policy.Waiver, error) {
	for i := range waivers {
		w := &waivers[i]
		if !w.Matches(c.ID) {
			continue
		}
		applies := true
		for _, cond := range w.When {
			ok, err := c.Eval(cond)
			if err != nil {
				return nil, fmt.Errorf("waiver %s: when: %w", w.Source, err)
			}
			if !ok {
				applies = false
				break
			}
		}
		if !applies {
			continue
		}
		if w.Expired(now) {
			notice(fmt.Sprintf("waiver %s expired on %s and no longer applies to %s", w.Source, w.UntilString(), c.ID))
			continue
		}
		return w, nil
	}
	return nil, nil
}

// baseResult fills the fields of a result that describe the check itself.
func baseResult(c *policy.Check) Result {
	return Result{
		ID:          c.ID,
		Name:        c.Name,
		Description: c.Description,
		Tags:        c.Tags,
		Severity:    c.Severity,
		Expected:    c.Expect.String(),
		When:        c.When,
		Rationale:   c.Rationale,
		Remediation: c.Remediation,
		Reference:   c.Reference,
		Location:    c.Source.Location(),
	}
}

func runCheck(ctx context.Context, p *policy.Policy, c *policy.Check, platformKeys []string) (res Result) {
	start := time.Now()
	res = baseResult(c)
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
	if c.Expect.NeedsOutput() && !c.AllowsRC(rc) {
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

// newRunID returns a random 16 hex digit identifier.
func newRunID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("%016x", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}

// Summarize counts results by status and computes the compliance score.
// FailOn is left empty.
func Summarize(results []Result) Summary {
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
		case StatusWaived:
			s.Waived++
		}
	}
	s.Evaluated = s.Passed + s.Failed + s.Warnings + s.Errors + s.Waived
	// A run in which every check was skipped or not applicable has checked
	// nothing and must not look compliant.
	s.Compliant = s.Failed == 0 && s.Errors == 0 && s.Evaluated > 0

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
	s.Score = -1
	if s.Evaluated > 0 {
		s.Score = 100
	}
	if total > 0 {
		s.Score = float64(int(float64(passed)*1000/float64(total))) / 10
	}
	return s
}
