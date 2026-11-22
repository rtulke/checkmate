// Package compare finds the differences between two reports or two
// policies.
package compare

import (
	"fmt"
	"sort"
	"strings"

	"github.com/rtulke/checkmate/internal/engine"
	"github.com/rtulke/checkmate/internal/facts"
	"github.com/rtulke/checkmate/internal/policy"
)

// --- reports ---

// StatusChange is a check whose status differs between two reports.
type StatusChange struct {
	ID       string        `json:"id"`
	Name     string        `json:"name"`
	Severity string        `json:"severity,omitempty"`
	Old      engine.Status `json:"old,omitempty"`
	New      engine.Status `json:"new,omitempty"`
	Reason   string        `json:"reason,omitempty"` // reason of the new result
}

// HostDiff compares the results of one host (or one pair of reports).
type HostDiff struct {
	Old         string         `json:"old"` // label of the old report
	New         string         `json:"new"`
	OldScore    float64        `json:"old_score"`
	NewScore    float64        `json:"new_score"`
	Regressions []StatusChange `json:"regressions"` // new problems
	Fixed       []StatusChange `json:"fixed"`       // problems that are gone
	Changed     []StatusChange `json:"changed"`     // other status changes
	Added       []StatusChange `json:"added"`       // checks only in the new report
	Removed     []StatusChange `json:"removed"`     // checks only in the old report
}

// Empty reports whether nothing changed.
func (h HostDiff) Empty() bool {
	return len(h.Regressions)+len(h.Fixed)+len(h.Changed)+len(h.Added)+len(h.Removed) == 0 && h.OldScore == h.NewScore
}

// ReportDiff is the comparison of two sets of reports.
type ReportDiff struct {
	Hosts   []HostDiff `json:"hosts"`
	OnlyOld []string   `json:"only_old,omitempty"` // reports without a counterpart
	OnlyNew []string   `json:"only_new,omitempty"`
}

// Empty reports whether nothing changed.
func (d ReportDiff) Empty() bool {
	for _, h := range d.Hosts {
		if !h.Empty() {
			return false
		}
	}
	return len(d.OnlyOld) == 0 && len(d.OnlyNew) == 0
}

// Regressions counts the new problems over all hosts.
func (d ReportDiff) Regressions() int {
	n := 0
	for _, h := range d.Hosts {
		n += len(h.Regressions)
	}
	return n
}

func reportLabel(r *engine.Report) string {
	l := r.Facts.Hostname
	name := r.Policy
	if name == "" {
		name = r.PolicyPath
	}
	if name != "" {
		l += " · " + name
	}
	return l + " · " + r.Started.Format("2006-01-02 15:04")
}

// Reports compares old and new reports. Two single reports are compared
// directly, even if they come from different hosts; otherwise reports are
// paired by host and policy.
func Reports(old, new []*engine.Report) ReportDiff {
	var d ReportDiff
	if len(old) == 1 && len(new) == 1 {
		d.Hosts = append(d.Hosts, compareReports(old[0], new[0]))
		return d
	}
	key := func(r *engine.Report) string { return r.Facts.Hostname + "\x00" + r.Policy }
	newByKey := map[string]*engine.Report{}
	for _, r := range new {
		newByKey[key(r)] = r
	}
	matched := map[string]bool{}
	for _, o := range old {
		n, ok := newByKey[key(o)]
		if !ok {
			d.OnlyOld = append(d.OnlyOld, reportLabel(o))
			continue
		}
		matched[key(o)] = true
		d.Hosts = append(d.Hosts, compareReports(o, n))
	}
	for _, n := range new {
		if !matched[key(n)] {
			d.OnlyNew = append(d.OnlyNew, reportLabel(n))
		}
	}
	return d
}

func isProblem(s engine.Status) bool {
	return s == engine.StatusFail || s == engine.StatusError || s == engine.StatusWarn
}

func compareReports(old, new *engine.Report) HostDiff {
	h := HostDiff{Old: reportLabel(old), New: reportLabel(new), OldScore: old.Summary.Score, NewScore: new.Summary.Score}
	oldByID := map[string]*engine.Result{}
	for i := range old.Results {
		oldByID[old.Results[i].ID] = &old.Results[i]
	}
	seen := map[string]bool{}
	for i := range new.Results {
		n := &new.Results[i]
		seen[n.ID] = true
		c := StatusChange{ID: n.ID, Name: n.Name, Severity: n.Severity, New: n.Status, Reason: n.Message}
		o, ok := oldByID[n.ID]
		if !ok {
			h.Added = append(h.Added, c)
			continue
		}
		c.Old = o.Status
		switch {
		case o.Status == n.Status:
		case isProblem(n.Status) && !isProblem(o.Status):
			h.Regressions = append(h.Regressions, c)
		case isProblem(o.Status) && !isProblem(n.Status):
			h.Fixed = append(h.Fixed, c)
		default:
			h.Changed = append(h.Changed, c)
		}
	}
	for i := range old.Results {
		o := &old.Results[i]
		if !seen[o.ID] {
			h.Removed = append(h.Removed, StatusChange{ID: o.ID, Name: o.Name, Severity: o.Severity, Old: o.Status})
		}
	}
	bySeverity := func(list []StatusChange) {
		sort.SliceStable(list, func(i, j int) bool {
			return policy.SeverityRank(list[i].Severity) > policy.SeverityRank(list[j].Severity)
		})
	}
	bySeverity(h.Regressions)
	bySeverity(h.Fixed)
	return h
}

// --- policies ---

// FieldChange is a changed property of a check or policy.
type FieldChange struct {
	Field string `json:"field"`
	Old   string `json:"old"`
	New   string `json:"new"`
}

// CheckChange lists the changed fields of a check present in both policies.
type CheckChange struct {
	ID     string        `json:"id"`
	Name   string        `json:"name"`
	Fields []FieldChange `json:"fields"`
}

// CheckRef names a check.
type CheckRef struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
}

// PolicyDiff is the comparison of two policies.
type PolicyDiff struct {
	Old      string        `json:"old"`
	New      string        `json:"new"`
	Policy   []FieldChange `json:"policy"` // name, version, defaults, variables
	Added    []CheckRef    `json:"added"`
	Removed  []CheckRef    `json:"removed"`
	Changed  []CheckChange `json:"changed"`
	OldCount int           `json:"old_checks"`
	NewCount int           `json:"new_checks"`
	Errors   []string      `json:"errors,omitempty"` // checks that could not be expanded
}

// Empty reports whether the policies are equivalent.
func (d PolicyDiff) Empty() bool {
	return len(d.Policy)+len(d.Added)+len(d.Removed)+len(d.Changed) == 0
}

// Policies compares two loaded policies check by check. Checks are expanded
// (loops, templates, snippets) with the given facts and variables, so the
// comparison is about what would run, not how it is written.
func Policies(old, new *policy.Policy, f facts.Facts, vars map[string]any) PolicyDiff {
	d := PolicyDiff{Old: old.Path, New: new.Path}
	field := func(name, a, b string) {
		if a != b {
			d.Policy = append(d.Policy, FieldChange{name, a, b})
		}
	}
	field("name", old.Name, new.Name)
	field("version", old.Version, new.Version)
	field("description", strings.TrimSpace(old.Description), strings.TrimSpace(new.Description))
	field("defaults.timeout", old.Defaults.Timeout.String(), new.Defaults.Timeout.String())
	field("defaults.shell", old.Defaults.Shell, new.Defaults.Shell)
	field("defaults.severity", old.Defaults.Severity, new.Defaults.Severity)
	field("defaults.fail_on", old.Defaults.FailOn, new.Defaults.FailOn)
	for _, k := range unionKeys(old.Vars, new.Vars) {
		field("vars."+k, valueString(old.Vars, k), valueString(new.Vars, k))
	}
	for _, k := range unionKeys(old.Env, new.Env) {
		field("env."+k, old.Env[k], new.Env[k])
	}
	field("waivers", fmt.Sprint(len(old.Waivers)), fmt.Sprint(len(new.Waivers)))

	oldChecks, oldErrs := policy.Expand(old, f, vars)
	newChecks, newErrs := policy.Expand(new, f, vars)
	for _, e := range oldErrs {
		d.Errors = append(d.Errors, "old: "+e.Error())
	}
	for _, e := range newErrs {
		d.Errors = append(d.Errors, "new: "+e.Error())
	}
	d.OldCount, d.NewCount = len(oldChecks), len(newChecks)

	oldByID := map[string]*policy.Check{}
	for _, c := range oldChecks {
		oldByID[c.ID] = c
	}
	seen := map[string]bool{}
	for _, n := range newChecks {
		seen[n.ID] = true
		o, ok := oldByID[n.ID]
		if !ok {
			d.Added = append(d.Added, CheckRef{n.ID, n.Name, n.Severity})
			continue
		}
		a, b := describe(o), describe(n)
		var fields []FieldChange
		for _, k := range checkFields {
			if a[k] != b[k] {
				fields = append(fields, FieldChange{k, a[k], b[k]})
			}
		}
		if len(fields) > 0 {
			d.Changed = append(d.Changed, CheckChange{n.ID, n.Name, fields})
		}
	}
	for _, o := range oldChecks {
		if !seen[o.ID] {
			d.Removed = append(d.Removed, CheckRef{o.ID, o.Name, o.Severity})
		}
	}
	return d
}

var checkFields = []string{"name", "description", "severity", "tags", "when", "only_if", "run",
	"expect", "as", "shell", "timeout", "allow_rc", "remediation", "reference"}

// describe renders the comparable properties of a check as text.
func describe(c *policy.Check) map[string]string {
	tags := append([]string{}, c.Tags...)
	sort.Strings(tags)
	allow := "any"
	if !c.AnyRC {
		parts := make([]string, len(c.AllowRC))
		for i, rc := range c.AllowRC {
			parts[i] = fmt.Sprint(rc)
		}
		allow = strings.Join(parts, ", ")
	}
	return map[string]string{
		"name":        c.Name,
		"description": strings.TrimSpace(c.Description),
		"severity":    c.Severity,
		"tags":        strings.Join(tags, ", "),
		"when":        strings.Join(c.When, "\n"),
		"only_if":     commandText(c, c.OnlyIf),
		"run":         commandText(c, c.Run),
		"expect":      c.Expect.String(),
		"as":          string(c.Mode),
		"shell":       c.Shell,
		"timeout":     c.Timeout.String(),
		"allow_rc":    allow,
		"remediation": c.Remediation,
		"reference":   c.Reference,
	}
}

// commandText resolves a command for every platform it is defined for, so
// a change in a snippet shows up in every check that uses it.
func commandText(c *policy.Check, spec policy.CommandSpec) string {
	if spec.IsZero() {
		return ""
	}
	platforms := spec.Platforms()
	if spec.Use != "" {
		platforms, _ = c.SnippetPlatforms(spec.Use)
	}
	if len(platforms) == 0 || (len(platforms) == 1 && platforms[0] == "any") {
		cmd, _, err := c.Command(spec, []string{"default"})
		if err != nil {
			return "error: " + err.Error()
		}
		return strings.TrimSpace(cmd)
	}
	var b strings.Builder
	for _, p := range platforms {
		cmd, _, err := c.Command(spec, []string{p})
		if err != nil {
			cmd = "error: " + err.Error()
		}
		fmt.Fprintf(&b, "[%s]\n%s\n", p, strings.TrimSpace(cmd))
	}
	return strings.TrimSpace(b.String())
}

func unionKeys[V any](a, b map[string]V) []string {
	set := map[string]bool{}
	for k := range a {
		set[k] = true
	}
	for k := range b {
		set[k] = true
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func valueString(m map[string]any, k string) string {
	v, ok := m[k]
	if !ok {
		return ""
	}
	return fmt.Sprintf("%v", v)
}
