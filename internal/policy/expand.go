package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rtulke/checkmate/internal/expect"
	"github.com/rtulke/checkmate/internal/facts"
	"github.com/rtulke/checkmate/internal/runner"
	"github.com/rtulke/checkmate/internal/tmpl"

	"gopkg.in/yaml.v3"
)

// Severities accepted in a check, from least to most severe.
var Severities = []string{"info", "low", "medium", "high", "critical"}

// Check is a fully expanded and rendered check, ready to run.
type Check struct {
	ID          string
	Name        string
	Description string
	Tags        []string
	Severity    string
	When        []string
	OnlyIf      CommandSpec
	Run         CommandSpec
	Expect      expect.Expectation
	Mode        expect.Mode
	Shell       string
	Timeout     time.Duration
	AllowRC     []int // nil together with AnyRC means every exit code
	AnyRC       bool  // allow_rc: any
	Rationale   string
	Remediation string
	Reference   string
	Source      CheckSource

	// Register is the name under which later checks see the outcome of
	// this check in their `when` conditions; Needs lists the registered
	// names this check refers to. See register.go.
	Register string
	Needs    []string

	// LoopRun is the item command of a check written with loop_run.
	LoopRun CommandSpec
	// Env holds extra environment variables for the commands of the check
	// (CHECKMATE_ITEM for loop_run checks).
	Env map[string]string
	// Fixed is set when the outcome is known without running the check,
	// e.g. because its loop_run command printed no items.
	Fixed *FixedOutcome

	context  map[string]any
	snippets map[string]CommandSpec

	// A loop_run check that is expanded during the run, see ExpandDeferred.
	deferred    bool
	target      *runner.Target
	expandItems func(exec *loopExec, outcomes map[string]any) ([]*Check, error)
}

// CheckError is a problem with a single check found during expansion.
type CheckError struct {
	ID     string // best-effort ID, may be empty or unrendered
	Source CheckSource
	Err    error
}

func (e *CheckError) Error() string {
	if e.ID != "" {
		return fmt.Sprintf("%s: check %s: %v", e.Source.Location(), e.ID, e.Err)
	}
	return fmt.Sprintf("%s: %v", e.Source.Location(), e.Err)
}

// rawCheck mirrors the on-disk format of a check after rendering.
type rawCheck struct {
	ID          string      `yaml:"id"`
	Name        string      `yaml:"name"`
	Description string      `yaml:"description"`
	Tags        []string    `yaml:"tags"`
	Severity    string      `yaml:"severity"`
	When        StringList  `yaml:"when"`
	OnlyIf      CommandSpec `yaml:"only_if"`
	Run         CommandSpec `yaml:"run"`
	Expect      yaml.Node   `yaml:"expect"`
	As          string      `yaml:"as"`
	Shell       string      `yaml:"shell"`
	Timeout     string      `yaml:"timeout"`
	AllowRC     ExitCodes   `yaml:"allow_rc"`
	Rationale   string      `yaml:"rationale"`
	Remediation string      `yaml:"remediation"`
	Reference   string      `yaml:"reference"`
	Register    string      `yaml:"register"`
}

// checkKeys are the keys allowed in a check ("loop" and "loop_run" are
// removed before).
var checkKeys = []string{"id", "name", "description", "tags", "severity", "when", "only_if",
	"run", "expect", "as", "shell", "timeout", "allow_rc", "rationale", "remediation", "reference", "register"}

func checkKnownKeys(n *yaml.Node, allowed []string) error {
	for i := 0; i+1 < len(n.Content); i += 2 {
		key := n.Content[i]
		known := false
		for _, a := range allowed {
			if key.Value == a {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("line %d: unknown key %q (allowed: loop, loop_run, %s)", key.Line, key.Value, strings.Join(allowed, ", "))
		}
	}
	return nil
}

// ExitCodes is a list of exit codes or the word "any".
type ExitCodes struct {
	Codes []int
	Any   bool
}

// UnmarshalYAML implements yaml.Unmarshaler.
func (e *ExitCodes) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.ScalarNode && node.Value == "any" {
		e.Any = true
		return nil
	}
	if node.Kind == yaml.ScalarNode {
		var code int
		if err := node.Decode(&code); err != nil {
			return fmt.Errorf("line %d: allow_rc must be a list of exit codes or \"any\"", node.Line)
		}
		e.Codes = []int{code}
		return nil
	}
	if err := node.Decode(&e.Codes); err != nil {
		return fmt.Errorf("line %d: allow_rc must be a list of exit codes or \"any\"", node.Line)
	}
	return nil
}

// AllowsRC reports whether an exit code is acceptable for output checks.
func (c *Check) AllowsRC(rc int) bool {
	if c.AnyRC {
		return true
	}
	for _, x := range c.AllowRC {
		if x == rc {
			return true
		}
	}
	return false
}

// StringList accepts a single string or a list of strings.
type StringList []string

// UnmarshalYAML implements yaml.Unmarshaler.
func (s *StringList) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Value != "" {
			*s = []string{node.Value}
		}
		return nil
	case yaml.SequenceNode:
		var list []string
		if err := node.Decode(&list); err != nil {
			return err
		}
		*s = list
		return nil
	}
	return fmt.Errorf("line %d: expected a string or a list of strings", node.Line)
}

// Context builds the template context shared by all checks.
func Context(p *Policy, f facts.Facts, extraVars map[string]any) map[string]any {
	vars := map[string]any{}
	mergeInto(vars, p.Vars)
	mergeInto(vars, extraVars)

	ctx := map[string]any{}
	mergeInto(ctx, vars) // variables are available at top level, like Ansible
	ctx["vars"] = vars
	ctx["facts"] = f.Map()
	return ctx
}

// Expand expands loops, renders templates and validates every check.
// Checks that fail to expand are returned as errors; the others are
// returned in policy order. Nothing is executed: a loop_run check is
// returned once, with the placeholder ItemPlaceholder as its item.
func Expand(p *Policy, f facts.Facts, extraVars map[string]any) ([]*Check, []*CheckError) {
	return expand(p, f, extraVars, nil)
}

// ExpandRun is Expand for a run: it executes the loop_run commands, at most
// jobs of them at a time, and returns one check per item.
//
// With a target the commands run on that host; f must be its facts.
func ExpandRun(ctx context.Context, p *Policy, f facts.Facts, extraVars map[string]any, jobs int, target *runner.Target) ([]*Check, []*CheckError) {
	if jobs < 1 {
		jobs = 1
	}
	return expand(p, f, extraVars, &loopExec{ctx: ctx, platformKeys: f.PlatformKeys(), jobs: jobs, target: target})
}

func expand(p *Policy, f facts.Facts, extraVars map[string]any, exec *loopExec) ([]*Check, []*CheckError) {
	base := Context(p, f, extraVars)

	type expansion struct {
		checks []*Check
		err    *CheckError
	}
	expanded := make([]expansion, len(p.Checks))
	for i, src := range p.Checks {
		expanded[i].checks, expanded[i].err = expandSource(p, src, base, nil)
	}
	if exec != nil {
		// A loop_run check whose conditions refer to a registered check has
		// to wait for that check; it stays unexpanded and the run expands
		// it (ExpandDeferred). All others get their items now. Item
		// commands are independent of each other, so they may run side by
		// side; the results keep the order of the policy.
		var names []*regexp.Regexp
		for _, e := range expanded {
			for _, c := range e.checks {
				if c.Register != "" {
					names = append(names, referencePattern(c.Register))
				}
			}
		}
		sem := make(chan struct{}, exec.jobs)
		var wg sync.WaitGroup
		for i, src := range p.Checks {
			if expanded[i].err != nil || !hasKey(src.Node, "loop_run") {
				continue
			}
			proto := expanded[i].checks[0]
			if refersToAny(proto.When, names) {
				proto.deferred = true
				proto.target = exec.target
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(i int, src CheckSource) {
				defer wg.Done()
				defer func() { <-sem }()
				defer func() {
					if r := recover(); r != nil {
						expanded[i] = expansion{err: &CheckError{ID: scalarValue(src.Node, "id"), Source: src,
							Err: fmt.Errorf("loop_run: internal error: %v", r)}}
					}
				}()
				expanded[i].checks, expanded[i].err = expandSource(p, src, base, exec)
			}(i, src)
		}
		wg.Wait()
	}

	var checks []*Check
	var errs []*CheckError
	seen := map[string]string{}
	for i, src := range p.Checks {
		if expanded[i].err != nil {
			errs = append(errs, expanded[i].err)
			continue
		}
		for _, c := range expanded[i].checks {
			if prev, dup := seen[c.ID]; dup {
				errs = append(errs, &CheckError{ID: c.ID, Source: src,
					Err: fmt.Errorf("duplicate check id (first defined at %s)", prev)})
				continue
			}
			seen[c.ID] = src.Location()
			checks = append(checks, c)
		}
	}
	checks, regErrs := linkRegistered(checks)
	return checks, append(errs, regErrs...)
}

func expandSource(p *Policy, src CheckSource, base map[string]any, exec *loopExec) ([]*Check, *CheckError) {
	rawID := scalarValue(src.Node, "id")
	fail := func(err error) *CheckError {
		return &CheckError{ID: rawID, Source: src, Err: err}
	}

	node := cloneNode(src.Node)
	loopNode := removeKey(node, "loop")
	loopRunNode := removeKey(node, "loop_run")

	ctx := copyMap(base)
	ctx["policy_dir"] = src.Dir

	if loopRunNode != nil {
		if loopNode != nil {
			return nil, fail(fmt.Errorf("loop and loop_run cannot be combined"))
		}
		checks, err := expandLoopRun(p, src, node, loopRunNode, ctx, exec)
		if err == nil && exec == nil {
			// Kept for ExpandDeferred, see expand.
			checks[0].expandItems = func(exec *loopExec, outcomes map[string]any) ([]*Check, error) {
				withOutcomes := copyMap(ctx)
				mergeInto(withOutcomes, outcomes)
				return expandLoopRun(p, src, node, loopRunNode, withOutcomes, exec)
			}
		}
		if err != nil {
			var ce *CheckError
			if errors.As(err, &ce) {
				return nil, ce
			}
			return nil, fail(err)
		}
		return checks, nil
	}

	items := []any{nil}
	if loopNode != nil {
		var err error
		items, err = loopItems(loopNode, ctx)
		if err != nil {
			return nil, fail(fmt.Errorf("loop: %w", err))
		}
	}

	var checks []*Check
	for _, item := range items {
		itemCtx := ctx
		if loopNode != nil {
			itemCtx = copyMap(ctx)
			itemCtx["item"] = item
		}
		n := cloneNode(node)
		if err := renderNode(n, itemCtx); err != nil {
			return nil, fail(err)
		}
		c, err := decodeCheck(p, src, n, itemCtx)
		if err != nil {
			return nil, err
		}
		checks = append(checks, c)
	}
	return checks, nil
}

// decodeCheck turns a rendered check node into a check.
func decodeCheck(p *Policy, src CheckSource, n *yaml.Node, ctx map[string]any) (*Check, *CheckError) {
	rawID := scalarValue(src.Node, "id")
	if err := checkKnownKeys(n, checkKeys); err != nil {
		return nil, &CheckError{ID: rawID, Source: src, Err: err}
	}
	var raw rawCheck
	if err := n.Decode(&raw); err != nil {
		return nil, &CheckError{ID: rawID, Source: src, Err: err}
	}
	c, err := build(p, src, raw, ctx)
	if err != nil {
		id := raw.ID
		if id == "" {
			id = rawID
		}
		return nil, &CheckError{ID: id, Source: src, Err: err}
	}
	return c, nil
}

func build(p *Policy, src CheckSource, raw rawCheck, ctx map[string]any) (*Check, error) {
	c := &Check{
		ID:          strings.TrimSpace(raw.ID),
		Name:        strings.TrimSpace(raw.Name),
		Description: raw.Description,
		Tags:        raw.Tags,
		Severity:    raw.Severity,
		When:        append(append([]string{}, src.When...), raw.When...),
		OnlyIf:      raw.OnlyIf,
		Run:         raw.Run,
		Shell:       raw.Shell,
		Timeout:     p.Defaults.Timeout,
		AllowRC:     raw.AllowRC.Codes,
		AnyRC:       raw.AllowRC.Any,
		Rationale:   strings.TrimSpace(raw.Rationale),
		Remediation: strings.TrimSpace(raw.Remediation),
		Reference:   raw.Reference,
		Register:    strings.TrimSpace(raw.Register),
		Source:      src,
		context:     ctx,
		snippets:    p.Snippets,
	}
	if c.ID == "" {
		return nil, fmt.Errorf("id is required")
	}
	if strings.ContainsAny(c.ID, " \t\n") {
		return nil, fmt.Errorf("id %q must not contain whitespace", c.ID)
	}
	if c.Name == "" {
		c.Name = c.ID
	}
	if err := validRegisterName(c.Register, ctx); err != nil {
		return nil, err
	}
	if c.Severity == "" {
		c.Severity = p.Defaults.Severity
	}
	if !validSeverity(c.Severity) {
		return nil, fmt.Errorf("invalid severity %q (use %s)", c.Severity, strings.Join(Severities, ", "))
	}
	if c.Shell == "" {
		c.Shell = p.Defaults.Shell
	}
	if !runner.ValidShell(c.Shell) {
		return nil, fmt.Errorf("unsupported shell %q", c.Shell)
	}
	if raw.Timeout != "" {
		t, err := time.ParseDuration(raw.Timeout)
		if err != nil || t <= 0 {
			return nil, fmt.Errorf("invalid timeout %q (e.g. 30s, 2m)", raw.Timeout)
		}
		c.Timeout = t
	}
	if len(c.AllowRC) == 0 && !c.AnyRC {
		c.AllowRC = []int{0}
	}
	mode, err := expect.ParseMode(raw.As)
	if err != nil {
		return nil, err
	}
	c.Mode = mode

	if c.Run.IsZero() {
		return nil, fmt.Errorf("run is required")
	}
	for _, spec := range []CommandSpec{c.Run, c.OnlyIf} {
		if spec.Use != "" {
			if _, ok := p.Snippets[spec.Use]; !ok {
				return nil, fmt.Errorf("unknown snippet %q", spec.Use)
			}
		}
	}
	if raw.Expect.Kind == 0 {
		return nil, fmt.Errorf("expect is required")
	}
	exp, err := expect.Parse(&raw.Expect)
	if err != nil {
		return nil, fmt.Errorf("expect: %w", err)
	}
	c.Expect = exp
	return c, nil
}

// Applies evaluates the `when` conditions of the check.
func (c *Check) Applies() (bool, string, error) {
	for _, cond := range c.When {
		ok, err := tmpl.Eval(cond, c.context)
		if err != nil {
			return false, cond, fmt.Errorf("when: %w", err)
		}
		if !ok {
			return false, cond, nil
		}
	}
	return true, "", nil
}

// Command resolves a command spec (run or only_if) for the given platform.
// ok is false if the command has no variant for this platform.
func (c *Check) Command(spec CommandSpec, platformKeys []string) (cmd string, ok bool, err error) {
	if spec.Use == "" {
		cmd, ok = spec.Select(platformKeys)
		return cmd, ok, nil
	}
	snippet, found := c.snippets[spec.Use]
	if !found {
		return "", false, fmt.Errorf("unknown snippet %q", spec.Use)
	}
	body, ok := snippet.Select(platformKeys)
	if !ok {
		return "", false, nil
	}
	ctx := copyMap(c.context)
	if !c.LoopRun.IsZero() {
		// The item is data from the host and reaches commands only through
		// the environment, see renderLoopRunCheck.
		delete(ctx, "item")
	}
	ctx["arg"] = spec.Arg
	args := map[string]any{}
	mergeInto(args, spec.Args)
	ctx["args"] = args
	rendered, err := tmpl.Render(body, ctx)
	if err != nil {
		return "", false, fmt.Errorf("snippet %s: %w", spec.Use, err)
	}
	return rendered, true, nil
}

func validSeverity(s string) bool { return SeverityRank(s) >= 0 }

// SeverityRank returns the position of s in Severities (info = 0,
// critical = 4), or -1 for an unknown severity.
func SeverityRank(s string) int {
	for i, v := range Severities {
		if s == v {
			return i
		}
	}
	return -1
}

// SeverityWeight is the weight of a severity in the compliance score.
// Informational checks do not count.
func SeverityWeight(s string) int {
	switch s {
	case "low":
		return 1
	case "medium":
		return 3
	case "high":
		return 7
	case "critical":
		return 10
	}
	return 0
}

// loopItems turns a loop node into a list of items. A mapping yields
// {key, value} items in file order; a sequence yields its elements; a
// scalar "{{ name }}" refers to a list or mapping variable.
func loopItems(node *yaml.Node, ctx map[string]any) ([]any, error) {
	switch node.Kind {
	case yaml.MappingNode:
		var items []any
		for i := 0; i+1 < len(node.Content); i += 2 {
			var value any
			if err := node.Content[i+1].Decode(&value); err != nil {
				return nil, err
			}
			items = append(items, map[string]any{"key": node.Content[i].Value, "value": value})
		}
		return items, nil
	case yaml.SequenceNode:
		var items []any
		if err := node.Decode(&items); err != nil {
			return nil, err
		}
		return items, nil
	case yaml.ScalarNode:
		var value any
		if path, ok := variableReference(node.Value); ok {
			v, found := lookupPath(ctx, path)
			if !found {
				return nil, fmt.Errorf("variable %q is not defined", path)
			}
			value = v
		} else {
			// Any other Jinja2 expression, e.g. a filtered list: render it as
			// JSON and decode the result.
			expr, ok := templateExpression(node.Value)
			if !ok {
				return nil, fmt.Errorf("expected a list, a mapping or a Jinja2 expression like \"{{ my_list }}\"")
			}
			out, err := tmpl.Render("{{ ("+expr+") | tojson }}", ctx)
			if err != nil {
				return nil, err
			}
			if err := json.Unmarshal([]byte(out), &value); err != nil {
				return nil, fmt.Errorf("expression %q does not produce a list or mapping", expr)
			}
			value = integralNumbers(value)
		}
		switch v := value.(type) {
		case []any:
			return v, nil
		case map[string]any:
			items := make([]any, 0, len(v))
			for _, k := range sortedKeys(v) {
				items = append(items, map[string]any{"key": k, "value": v[k]})
			}
			return items, nil
		}
		return nil, fmt.Errorf("%q is neither a list nor a mapping", node.Value)
	}
	return nil, fmt.Errorf("unsupported loop value")
}

// integralNumbers turns whole float64 values from JSON back into ints, so
// that 1 renders as "1" and not as "1.0".
func integralNumbers(v any) any {
	switch x := v.(type) {
	case float64:
		if x == float64(int64(x)) {
			return int(x)
		}
	case []any:
		for i := range x {
			x[i] = integralNumbers(x[i])
		}
	case map[string]any:
		for k := range x {
			x[k] = integralNumbers(x[k])
		}
	}
	return v
}

// templateExpression extracts the expression from "{{ expr }}".
func templateExpression(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{{") || !strings.HasSuffix(s, "}}") {
		return "", false
	}
	expr := strings.TrimSpace(s[2 : len(s)-2])
	return expr, expr != ""
}

// variableReference extracts "a.b" from "{{ a.b }}".
func variableReference(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{{") || !strings.HasSuffix(s, "}}") {
		return "", false
	}
	path := strings.TrimSpace(s[2 : len(s)-2])
	if path == "" || strings.ContainsAny(path, " |()[]'\"") {
		return "", false
	}
	return path, true
}

func lookupPath(ctx map[string]any, path string) (any, bool) {
	var current any = ctx
	for _, part := range strings.Split(path, ".") {
		m, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = m[part]
		if !ok {
			return nil, false
		}
	}
	return current, true
}

// renderNode renders all scalar values (not mapping keys) in place.
func renderNode(n *yaml.Node, ctx map[string]any) error {
	return renderNodeWith(n, ctx, nil)
}

// renderNodeWith is renderNode with a fallback: if recover is set, it
// supplies the value of a scalar that cannot be rendered.
func renderNodeWith(n *yaml.Node, ctx map[string]any, recover func(src string) string) error {
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range n.Content {
			if err := renderNodeWith(child, ctx, recover); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if err := renderNodeWith(n.Content[i+1], ctx, recover); err != nil {
				return fmt.Errorf("%s: %w", n.Content[i].Value, err)
			}
		}
	case yaml.ScalarNode:
		if !tmpl.HasTemplate(n.Value) {
			return nil
		}
		out, err := tmpl.Render(n.Value, ctx)
		if err != nil {
			if recover == nil {
				return err
			}
			out = recover(n.Value)
		}
		if out != n.Value && n.Tag != "!!str" {
			n.Tag = "" // let YAML resolve the rendered value's type
		}
		n.Value = out
	}
	return nil
}

func cloneNode(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.AliasNode && n.Alias != nil {
		// Inline the anchored node so that templates in it are rendered for
		// every use, not only where the anchor is defined.
		c := cloneNode(n.Alias)
		c.Anchor = ""
		return c
	}
	c := *n
	if n.Content != nil {
		c.Content = make([]*yaml.Node, len(n.Content))
		for i, child := range n.Content {
			c.Content[i] = cloneNode(child)
		}
	}
	return &c
}

func removeKey(n *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			value := n.Content[i+1]
			n.Content = append(n.Content[:i], n.Content[i+2:]...)
			return value
		}
	}
	return nil
}

func scalarValue(n *yaml.Node, key string) string {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key && n.Content[i+1].Kind == yaml.ScalarNode {
			return n.Content[i+1].Value
		}
	}
	return ""
}

func copyMap(m map[string]any) map[string]any {
	c := make(map[string]any, len(m)+2)
	for k, v := range m {
		c[k] = v
	}
	return c
}

// SnippetPlatforms lists the platform keys a snippet is defined for. A
// snippet without variants applies everywhere and returns ["any"].
func (c *Check) SnippetPlatforms(name string) ([]string, bool) {
	s, ok := c.snippets[name]
	if !ok {
		return nil, false
	}
	if len(s.Variants) == 0 {
		return []string{"any"}, true
	}
	return s.Platforms(), true
}
