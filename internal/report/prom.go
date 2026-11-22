package report

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/rtulke/checkmate/internal/engine"
	"github.com/rtulke/checkmate/internal/policy"
)

// writeProm writes metrics in the Prometheus text format, for the
// textfile collector of the node_exporter. Every series is labelled with
// the policy and host, so several policies can share a directory. Per
// check, only problems are exported, which keeps the number of series
// small while still telling an alert which checks fail.
func writeProm(w io.Writer, rs []*engine.Report, _ Options) error {
	var b strings.Builder
	metric := func(name, help, typ string) {
		fmt.Fprintf(&b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
	}
	labels := func(r *engine.Report, extra ...string) string {
		pairs := []string{"policy", policyTitle(r), "host", r.Facts.Hostname}
		pairs = append(pairs, extra...)
		parts := make([]string, 0, len(pairs)/2)
		for i := 0; i+1 < len(pairs); i += 2 {
			parts = append(parts, fmt.Sprintf(`%s="%s"`, pairs[i], promEscape(pairs[i+1])))
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	each := func(f func(r *engine.Report)) {
		for _, r := range rs {
			f(r)
		}
	}

	metric("checkmate_score", "Weighted share of passed checks in percent (0-100); -1 if nothing was evaluated.", "gauge")
	each(func(r *engine.Report) { fmt.Fprintf(&b, "checkmate_score%s %g\n", labels(r), r.Summary.Score) })

	metric("checkmate_compliant", "1 if no check failed or errored, 0 otherwise.", "gauge")
	each(func(r *engine.Report) {
		fmt.Fprintf(&b, "checkmate_compliant%s %d\n", labels(r), boolInt(r.Summary.Compliant))
	})

	metric("checkmate_checks", "Number of checks by status.", "gauge")
	each(func(r *engine.Report) {
		s := r.Summary
		for _, c := range []struct {
			status string
			n      int
		}{{"pass", s.Passed}, {"fail", s.Failed}, {"warn", s.Warnings}, {"error", s.Errors},
			{"waived", s.Waived}, {"skip", s.Skipped}, {"not_applicable", s.NotApplicable}} {
			fmt.Fprintf(&b, "checkmate_checks%s %d\n", labels(r, "status", c.status), c.n)
		}
	})

	metric("checkmate_failed_checks", "Number of failed checks (FAIL and ERROR) by severity.", "gauge")
	each(func(r *engine.Report) {
		count := map[string]int{}
		for _, res := range r.Results {
			if res.Status == engine.StatusFail || res.Status == engine.StatusError {
				count[res.Severity]++
			}
		}
		for _, sev := range policy.Severities {
			fmt.Fprintf(&b, "checkmate_failed_checks%s %d\n", labels(r, "severity", sev), count[sev])
		}
	})

	metric("checkmate_check_problem", "Checks that failed, warned or errored; one series per problem.", "gauge")
	each(func(r *engine.Report) {
		var lines []string
		for _, res := range r.Results {
			if isProblem(res.Status) {
				lines = append(lines, fmt.Sprintf("checkmate_check_problem%s 1\n",
					labels(r, "id", res.ID, "severity", res.Severity, "status", strings.ToLower(string(res.Status)))))
			}
		}
		sort.Strings(lines)
		b.WriteString(strings.Join(lines, ""))
	})

	metric("checkmate_last_run_timestamp_seconds", "Start of the run as a Unix timestamp.", "gauge")
	each(func(r *engine.Report) {
		fmt.Fprintf(&b, "checkmate_last_run_timestamp_seconds%s %d\n", labels(r), r.Started.Unix())
	})

	metric("checkmate_run_duration_seconds", "Duration of the run.", "gauge")
	each(func(r *engine.Report) {
		fmt.Fprintf(&b, "checkmate_run_duration_seconds%s %g\n", labels(r), float64(r.DurationMS)/1000)
	})

	_, err := io.WriteString(w, b.String())
	return err
}

func promEscape(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(s)
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
