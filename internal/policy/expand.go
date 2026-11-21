package policy

import (
	"fmt"
	"strings"
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
	AllowRC     []int
	Remediation string
	Reference   string
	Source      CheckSource

	context  map[string]any
	snippets map[string]CommandSpec
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
	AllowRC     []int       `yaml:"allow_rc"`
	Remediation string      `yaml:"remediation"`
	Reference   string      `yaml:"reference"`
}

// checkKeys are the keys allowed in a check ("loop" is removed before).
var checkKeys = []string{"id", "name", "description", "tags", "severity", "when", "only_if",
	"run", "expect", "as", "shell", "timeout", "allow_rc", "remediation", "reference"}

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
			return fmt.Errorf("line %d: unknown key %q (allowed: loop, %s)", key.Line, key.Value, strings.Join(allowed, ", "))
		}
	}
	return nil
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
// returned in policy order.
func Expand(p *Policy, f facts.Facts, extraVars map[string]any) ([]*Check, []*CheckError) {
	base := Context(p, f, extraVars)
	var checks []*Check
	var errs []*CheckError
	seen := map[string]string{}

	for _, src := range p.Checks {
		expanded, err := expandSource(p, src, base)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		for _, c := range expanded {
			if prev, dup := seen[c.ID]; dup {
				errs = append(errs, &CheckError{ID: c.ID, Source: src,
					Err: fmt.Errorf("duplicate check id (first defined at %s)", prev)})
				continue
			}
			seen[c.ID] = src.Location()
			checks = append(checks, c)
		}
	}
	return checks, errs
}

func expandSource(p *Policy, src CheckSource, base map[string]any) ([]*Check, *CheckError) {
	rawID := scalarValue(src.Node, "id")
	fail := func(err error) *CheckError {
		return &CheckError{ID: rawID, Source: src, Err: err}
	}

	node := cloneNode(src.Node)
	loopNode := removeKey(node, "loop")

	ctx := copyMap(base)
	ctx["policy_dir"] = src.Dir

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
		if err := checkKnownKeys(n, checkKeys); err != nil {
			return nil, fail(err)
		}
		var raw rawCheck
		if err := n.Decode(&raw); err != nil {
			return nil, fail(err)
		}
		c, err := build(p, src, raw, itemCtx)
		if err != nil {
			id := raw.ID
			if id == "" {
				id = rawID
			}
			return nil, &CheckError{ID: id, Source: src, Err: err}
		}
		checks = append(checks, c)
	}
	return checks, nil
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
		AllowRC:     raw.AllowRC,
		Remediation: strings.TrimSpace(raw.Remediation),
		Reference:   raw.Reference,
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
	if len(c.AllowRC) == 0 {
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
		path, ok := variableReference(node.Value)
		if !ok {
			return nil, fmt.Errorf("expected a list, a mapping or a variable reference like \"{{ my_list }}\"")
		}
		value, ok := lookupPath(ctx, path)
		if !ok {
			return nil, fmt.Errorf("variable %q is not defined", path)
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
		return nil, fmt.Errorf("variable %q is neither a list nor a mapping", path)
	}
	return nil, fmt.Errorf("unsupported loop value")
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
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, child := range n.Content {
			if err := renderNode(child, ctx); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			if err := renderNode(n.Content[i+1], ctx); err != nil {
				return fmt.Errorf("%s: %w", n.Content[i].Value, err)
			}
		}
	case yaml.ScalarNode:
		if !tmpl.HasTemplate(n.Value) {
			return nil
		}
		out, err := tmpl.Render(n.Value, ctx)
		if err != nil {
			return err
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
