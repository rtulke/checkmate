//go:build !windows

package engine

import (
	"context"
	"strings"
	"testing"

	"github.com/rtulke/checkmate/internal/facts"
	"github.com/rtulke/checkmate/internal/policy"
)

func runPolicy(t *testing.T, filter Filter) map[string]Result {
	t.Helper()
	p, err := policy.Load("testdata/engine.yml", policy.LoadOptions{AllowInsecure: true})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	r := Run(context.Background(), p, Options{Facts: facts.Gather(), Filter: filter, Jobs: 4})
	byID := map[string]Result{}
	for _, res := range r.Results {
		byID[res.ID] = res
	}
	return byID
}

func TestRunStatuses(t *testing.T) {
	results := runPolicy(t, Filter{})
	want := map[string]Status{
		"T-INCLUDED":    StatusPass,
		"T-PASS":        StatusPass,
		"T-FAIL":        StatusFail,
		"T-RC-ERROR":    StatusError,
		"T-RC-ALLOWED":  StatusPass,
		"T-ANY-RC":      StatusFail,
		"T-NOTFOUND":    StatusError,
		"T-TIMEOUT":     StatusError,
		"T-PIPEFAIL":    StatusPass,
		"T-NA":          StatusNA,
		"T-NA-SNIPPET":  StatusNA,
		"T-SKIP-WHEN":   StatusSkip,
		"T-SKIP-ONLYIF": StatusSkip,
		"T-SNIPPET":     StatusPass,
		"T-LOOP-one":    StatusPass,
		"T-LOOP-two":    StatusPass,
		"T-POLICY-DIR":  StatusPass,
		"T-ENV-LOCALE":  StatusPass,
		"T-BAD-WHEN":    StatusError,
	}
	for id, status := range want {
		res, ok := results[id]
		if !ok {
			t.Errorf("%s: missing result", id)
			continue
		}
		if res.Status != status {
			t.Errorf("%s: status %s, want %s (message: %s)", id, res.Status, status, res.Message)
		}
	}
	if len(results) != len(want) {
		t.Errorf("got %d results, want %d", len(results), len(want))
	}
	if msg := results["T-FAIL"].Message; !strings.Contains(msg, `">= \"500\"`) && !strings.Contains(msg, "312") {
		t.Errorf("T-FAIL message should explain the mismatch, got %q", msg)
	}
	if msg := results["T-TIMEOUT"].Message; !strings.Contains(msg, "timed out") {
		t.Errorf("T-TIMEOUT message = %q", msg)
	}
}

func TestRunReportOrderAndSummary(t *testing.T) {
	p, err := policy.Load("testdata/engine.yml", policy.LoadOptions{AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	r := Run(context.Background(), p, Options{Facts: facts.Gather(), Jobs: 8})
	if r.Results[0].ID != "T-INCLUDED" || r.Results[1].ID != "T-PASS" {
		t.Errorf("results must keep policy order, got %s, %s", r.Results[0].ID, r.Results[1].ID)
	}
	if r.Summary.Compliant {
		t.Error("a run with failures and errors must not be compliant")
	}
	if r.Summary.Failed != 2 || r.Summary.Errors != 4 {
		t.Errorf("summary = %+v", r.Summary)
	}
}

func TestRunFilter(t *testing.T) {
	results := runPolicy(t, Filter{Tags: ParseTagExpr("a+b,included")})
	if len(results) != 2 {
		t.Fatalf("tag filter selected %d checks, want 2: %v", len(results), keys(results))
	}
	for _, id := range []string{"T-PASS", "T-INCLUDED"} {
		if _, ok := results[id]; !ok {
			t.Errorf("%s should be selected", id)
		}
	}

	results = runPolicy(t, Filter{IDs: ParseIDs("T-LOOP-*"), SkipTags: ParseTagExpr("nothing")})
	if len(results) != 2 {
		t.Errorf("id filter selected %v", keys(results))
	}
}

func TestFilterMatch(t *testing.T) {
	f := Filter{Tags: ParseTagExpr("compliance+full,quality"), SkipTags: ParseTagExpr("slow")}
	cases := []struct {
		tags []string
		want bool
	}{
		{[]string{"compliance", "full"}, true},
		{[]string{"compliance"}, false},
		{[]string{"quality"}, true},
		{[]string{"quality", "slow"}, false},
	}
	for _, c := range cases {
		if got := f.Match("X", c.tags); got != c.want {
			t.Errorf("Match(%v) = %v, want %v", c.tags, got, c.want)
		}
	}
}

func keys(m map[string]Result) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestEscapes runs a policy full of quoting and escaping edge cases; every
// check must pass.
func TestEscapes(t *testing.T) {
	p, err := policy.Load("testdata/escapes.yml", policy.LoadOptions{AllowInsecure: true})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	r := Run(context.Background(), p, Options{Facts: facts.Gather(), Jobs: 8})
	for _, res := range r.Results {
		if res.Status != StatusPass {
			t.Errorf("%s (%s): %s: %s\n  command: %q\n  stdout: %q\n  stderr: %q",
				res.ID, res.Name, res.Status, res.Message, res.Command, res.Stdout, res.Stderr)
		}
	}
	if r.Summary.Total < 30 {
		t.Errorf("expected all escape checks to run, got %d", r.Summary.Total)
	}
}

func TestFailOnThresholdAndScore(t *testing.T) {
	p, err := policy.Load("testdata/engine.yml", policy.LoadOptions{AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	r := Run(context.Background(), p, Options{Facts: facts.Gather(), FailOn: "high", Jobs: 8})
	byID := map[string]Result{}
	for _, res := range r.Results {
		byID[res.ID] = res
	}
	if got := byID["T-FAIL"].Status; got != StatusWarn {
		t.Errorf("medium failure with fail_on=high must be a warning, got %s", got)
	}
	if got := byID["T-TIMEOUT"].Status; got != StatusError {
		t.Errorf("errors must never be downgraded, got %s", got)
	}
	if r.Summary.Failed != 0 || r.Summary.Warnings != 2 {
		t.Errorf("summary = %+v", r.Summary)
	}
	if r.Summary.Compliant {
		t.Error("errors still make the run non-compliant")
	}
	if r.Summary.FailOn != "high" {
		t.Errorf("FailOn = %q", r.Summary.FailOn)
	}
}

func TestScore(t *testing.T) {
	results := []Result{
		{Status: StatusPass, Severity: "critical"}, // 10 of 10
		{Status: StatusFail, Severity: "low"},      // 0 of 1
		{Status: StatusWarn, Severity: "medium"},   // 0 of 3
		{Status: StatusPass, Severity: "info"},     // does not count
		{Status: StatusSkip, Severity: "high"},     // does not count
	}
	s := summarize(results)
	if s.Score != 71.4 {
		t.Errorf("score = %v, want 71.4", s.Score)
	}
	empty := summarize([]Result{{Status: StatusSkip}, {Status: StatusNA}})
	if empty.Score != -1 || empty.Compliant || empty.Evaluated != 0 {
		t.Errorf("a run without evaluated checks must not be compliant: %+v", empty)
	}
}
