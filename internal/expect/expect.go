// Package expect parses and evaluates the `expect` clause of a check.
//
// An expectation is evaluated against the result of a command: its exit
// code, its standard output and its standard error. Supported forms:
//
//	expect: true                 # exit code is 0
//	expect: false                # exit code is not 0
//	expect: "== active"          # trimmed stdout compared with an operator
//	expect: active               # shorthand for "== active"
//	expect: empty                # stdout is empty ("!empty" for the opposite)
//	expect: { lines: "<= 1" }    # number of non-empty stdout lines
//	expect: { rc: "== 3" }       # explicit exit code comparison
//	expect: { stderr: empty }    # stderr instead of stdout
//	expect: ["!empty", "!~ x"]   # all conditions must hold
//	expect: { any: [a, b] }      # at least one condition must hold
package expect

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// Output is the observable result of a command.
type Output struct {
	RC     int
	Stdout string
	Stderr string
}

// Mode controls how values are compared.
type Mode string

const (
	ModeAuto    Mode = "auto"    // numeric if both sides are numbers, string otherwise
	ModeNumber  Mode = "number"  // both sides must be numbers
	ModeVersion Mode = "version" // version-aware comparison, 8.10 > 8.9
	ModeString  Mode = "string"  // plain (lexicographic) string comparison
)

// ParseMode validates a mode name. An empty name means ModeAuto.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case "", ModeAuto:
		return ModeAuto, nil
	case ModeNumber, ModeVersion, ModeString:
		return Mode(s), nil
	}
	return "", fmt.Errorf("unknown comparison mode %q (use auto, number, version or string)", s)
}

// Expectation is a parsed `expect` clause.
type Expectation interface {
	// Eval returns whether the expectation holds. The message explains a
	// mismatch. An error means the expectation could not be evaluated.
	Eval(out Output, mode Mode) (ok bool, message string, err error)
	// NeedsOutput reports whether the expectation inspects command output.
	// For those, a failing command is an error rather than a test result.
	NeedsOutput() bool
	String() string
}

// Parse parses an `expect` YAML node.
func Parse(node *yaml.Node) (Expectation, error) {
	if node == nil || node.Kind == 0 {
		return nil, fmt.Errorf("expect is missing")
	}
	switch node.Kind {
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!null":
			return nil, fmt.Errorf("expect is empty")
		case "!!bool":
			var b bool
			if err := node.Decode(&b); err != nil {
				return nil, err
			}
			return exitCode{want: b}, nil
		}
		return ParseCondition("stdout", node.Value)
	case yaml.SequenceNode:
		return parseGroup(node, true)
	case yaml.MappingNode:
		var items []Expectation
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i].Value, node.Content[i+1]
			switch key {
			case "all", "any":
				g, err := parseGroup(value, key == "all")
				if err != nil {
					return nil, err
				}
				items = append(items, g)
			case "stdout", "stderr", "lines", "rc":
				e, err := parseTarget(key, value)
				if err != nil {
					return nil, err
				}
				items = append(items, e)
			default:
				return nil, fmt.Errorf("unknown expect key %q (use stdout, stderr, lines, rc, all or any)", key)
			}
		}
		if len(items) == 0 {
			return nil, fmt.Errorf("expect is empty")
		}
		if len(items) == 1 {
			return items[0], nil
		}
		return group{all: true, items: items}, nil
	}
	return nil, fmt.Errorf("unsupported expect value")
}

func parseGroup(node *yaml.Node, all bool) (Expectation, error) {
	if node.Kind != yaml.SequenceNode {
		e, err := Parse(node)
		if err != nil {
			return nil, err
		}
		return group{all: all, items: []Expectation{e}}, nil
	}
	if len(node.Content) == 0 {
		return nil, fmt.Errorf("expect list is empty")
	}
	g := group{all: all}
	for _, child := range node.Content {
		e, err := Parse(child)
		if err != nil {
			return nil, err
		}
		g.items = append(g.items, e)
	}
	return g, nil
}

func parseTarget(target string, node *yaml.Node) (Expectation, error) {
	switch node.Kind {
	case yaml.ScalarNode:
		return ParseCondition(target, node.Value)
	case yaml.SequenceNode:
		g := group{all: true}
		for _, child := range node.Content {
			if child.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("%s: expected a condition string", target)
			}
			c, err := ParseCondition(target, child.Value)
			if err != nil {
				return nil, err
			}
			g.items = append(g.items, c)
		}
		return g, nil
	}
	return nil, fmt.Errorf("%s: expected a condition string or a list of them", target)
}

// exitCode checks whether the command succeeded (rc 0) or not.
type exitCode struct{ want bool }

func (e exitCode) Eval(out Output, _ Mode) (bool, string, error) {
	ok := (out.RC == 0) == e.want
	if ok {
		return true, "", nil
	}
	if e.want {
		return false, fmt.Sprintf("expected exit code 0, got %d", out.RC), nil
	}
	return false, "expected a non-zero exit code, got 0", nil
}

func (e exitCode) NeedsOutput() bool { return false }

func (e exitCode) String() string {
	if e.want {
		return "exit code 0"
	}
	return "non-zero exit code"
}

// group combines expectations with AND (all) or OR (any).
type group struct {
	all   bool
	items []Expectation
}

func (g group) Eval(out Output, mode Mode) (bool, string, error) {
	var messages []string
	for _, item := range g.items {
		ok, msg, err := item.Eval(out, mode)
		if err != nil {
			return false, "", err
		}
		if g.all && !ok {
			return false, msg, nil
		}
		if !g.all && ok {
			return true, "", nil
		}
		if !ok {
			messages = append(messages, msg)
		}
	}
	if g.all {
		return true, "", nil
	}
	return false, "none matched: " + strings.Join(messages, "; "), nil
}

func (g group) NeedsOutput() bool {
	for _, item := range g.items {
		if item.NeedsOutput() {
			return true
		}
	}
	return false
}

func (g group) String() string {
	parts := make([]string, len(g.items))
	for i, item := range g.items {
		parts[i] = item.String()
	}
	sep := " and "
	if !g.all {
		sep = " or "
	}
	return strings.Join(parts, sep)
}

// Operators, longest first so that ">=" wins over ">".
var operators = []string{"!in ", "in ", "==", "!=", ">=", "<=", "!>", "!<", "!~", "~", ">", "<"}

// condition compares one aspect of the output with an operand.
type condition struct {
	target  string // stdout, stderr, lines, rc
	op      string // ==, !=, >, >=, <, <=, ~, !~, in, !in, empty, !empty
	operand string
	list    []string
	re      *regexp.Regexp
}

// ParseCondition parses a condition string such as ">= 500" for a target.
func ParseCondition(target, s string) (Expectation, error) {
	s = strings.TrimSpace(s)
	c := &condition{target: target}
	switch s {
	case "empty", "!empty":
		c.op = s
		return c, nil
	}

	c.op = "=="
	c.operand = s
	for _, op := range operators {
		if strings.HasPrefix(s, op) {
			c.op = strings.TrimSpace(op)
			c.operand = strings.TrimSpace(s[len(op):])
			break
		}
	}
	// Normalize the negated ordering operators.
	switch c.op {
	case "!>":
		c.op = "<="
	case "!<":
		c.op = ">="
	}
	c.operand = unquote(c.operand)

	switch c.op {
	case "~", "!~":
		re, err := regexp.Compile("(?m)" + c.operand)
		if err != nil {
			return nil, fmt.Errorf("invalid regular expression %q: %w", c.operand, err)
		}
		c.re = re
	case "in", "!in":
		list, err := parseList(c.operand)
		if err != nil {
			return nil, err
		}
		c.list = list
	}
	if (target == "lines" || target == "rc") && c.op != "empty" && c.op != "!empty" &&
		c.op != "~" && c.op != "!~" && c.op != "in" && c.op != "!in" {
		if _, err := strconv.ParseFloat(c.operand, 64); err != nil {
			return nil, fmt.Errorf("%s: operand %q is not a number", target, c.operand)
		}
	}
	return c, nil
}

func (c *condition) value(out Output) string {
	switch c.target {
	case "stderr":
		return strings.TrimSpace(out.Stderr)
	case "lines":
		return strconv.Itoa(countLines(out.Stdout))
	case "rc":
		return strconv.Itoa(out.RC)
	}
	return strings.TrimSpace(out.Stdout)
}

func (c *condition) Eval(out Output, mode Mode) (bool, string, error) {
	got := c.value(out)
	if c.target == "lines" || c.target == "rc" {
		mode = ModeNumber
	}

	var ok bool
	switch c.op {
	case "empty":
		ok = got == ""
	case "!empty":
		ok = got != ""
	case "~":
		ok = c.re.MatchString(got)
	case "!~":
		ok = !c.re.MatchString(got)
	case "in", "!in":
		found := false
		for _, candidate := range c.list {
			eq, err := equal(got, candidate, mode)
			if err != nil {
				return false, "", err
			}
			if eq {
				found = true
				break
			}
		}
		ok = found == (c.op == "in")
	case "==", "!=":
		eq, err := equal(got, c.operand, mode)
		if err != nil {
			return false, "", err
		}
		ok = eq == (c.op == "==")
	default:
		cmp, err := compare(got, c.operand, mode)
		if err != nil {
			return false, "", err
		}
		switch c.op {
		case ">":
			ok = cmp > 0
		case ">=":
			ok = cmp >= 0
		case "<":
			ok = cmp < 0
		case "<=":
			ok = cmp <= 0
		}
	}
	if ok {
		return true, "", nil
	}
	return false, fmt.Sprintf("expected %s, got %s", c.String(), describe(got)), nil
}

func (c *condition) NeedsOutput() bool { return c.target != "rc" }

func (c *condition) String() string {
	switch c.op {
	case "empty":
		return c.target + " to be empty"
	case "!empty":
		return c.target + " not to be empty"
	case "in", "!in":
		return fmt.Sprintf("%s %s [%s]", c.target, c.op, strings.Join(c.list, ", "))
	}
	return fmt.Sprintf("%s %s %q", c.target, c.op, c.operand)
}

func describe(s string) string {
	if s == "" {
		return "empty output"
	}
	if len(s) > 200 {
		s = s[:197] + "..."
	}
	return strconv.Quote(s)
}

func countLines(s string) int {
	n := 0
	for _, line := range strings.Split(s, "\n") {
		if strings.TrimSpace(line) != "" {
			n++
		}
	}
	return n
}

func unquote(s string) string {
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' || first == '\'') && first == last {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func parseList(s string) ([]string, error) {
	var raw []any
	if strings.HasPrefix(s, "[") {
		if err := yaml.Unmarshal([]byte(s), &raw); err != nil {
			return nil, fmt.Errorf("invalid list %q: %w", s, err)
		}
	} else {
		for _, part := range strings.Split(s, ",") {
			raw = append(raw, strings.TrimSpace(part))
		}
	}
	list := make([]string, 0, len(raw))
	for _, item := range raw {
		list = append(list, fmt.Sprint(item))
	}
	if len(list) == 0 {
		return nil, fmt.Errorf("list %q is empty", s)
	}
	return list, nil
}

func equal(a, b string, mode Mode) (bool, error) {
	switch mode {
	case ModeString:
		return a == b, nil
	case ModeVersion:
		return CompareVersions(a, b) == 0, nil
	case ModeNumber:
		fa, fb, err := numbers(a, b)
		if err != nil {
			return false, err
		}
		return fa == fb, nil
	}
	if fa, fb, err := numbers(a, b); err == nil {
		return fa == fb, nil
	}
	return a == b, nil
}

func compare(a, b string, mode Mode) (int, error) {
	switch mode {
	case ModeString:
		return strings.Compare(a, b), nil
	case ModeVersion:
		return CompareVersions(a, b), nil
	}
	fa, fb, err := numbers(a, b)
	if err != nil {
		if mode == ModeAuto {
			return 0, fmt.Errorf("%w (use `as: version` or `as: string` for non-numeric comparisons)", err)
		}
		return 0, err
	}
	switch {
	case fa < fb:
		return -1, nil
	case fa > fb:
		return 1, nil
	}
	return 0, nil
}

func numbers(a, b string) (float64, float64, error) {
	fa, errA := strconv.ParseFloat(a, 64)
	fb, errB := strconv.ParseFloat(b, 64)
	if errA != nil || errB != nil {
		return 0, 0, fmt.Errorf("cannot compare %s and %s as numbers", describe(a), describe(b))
	}
	return fa, fb, nil
}

// CompareVersions compares two version strings segment by segment.
// Numeric segments are compared as numbers, others as strings; missing
// segments count as zero. It returns -1, 0 or 1.
func CompareVersions(a, b string) int {
	pa, pb := versionParts(a), versionParts(b)
	for i := 0; i < len(pa) || i < len(pb); i++ {
		sa, sb := "0", "0"
		if i < len(pa) {
			sa = pa[i]
		}
		if i < len(pb) {
			sb = pb[i]
		}
		na, errA := strconv.ParseUint(sa, 10, 64)
		nb, errB := strconv.ParseUint(sb, 10, 64)
		var c int
		if errA == nil && errB == nil {
			switch {
			case na < nb:
				c = -1
			case na > nb:
				c = 1
			}
		} else {
			c = strings.Compare(sa, sb)
		}
		if c != 0 {
			return c
		}
	}
	return 0
}

// versionParts splits "1.2.3-4.el9" into [1 2 3 4 el 9].
func versionParts(v string) []string {
	var parts []string
	var current strings.Builder
	var currentIsDigit bool
	flush := func() {
		if current.Len() > 0 {
			parts = append(parts, current.String())
			current.Reset()
		}
	}
	for _, r := range strings.TrimSpace(v) {
		switch {
		case unicode.IsDigit(r):
			if current.Len() > 0 && !currentIsDigit {
				flush()
			}
			currentIsDigit = true
			current.WriteRune(r)
		case unicode.IsLetter(r):
			if current.Len() > 0 && currentIsDigit {
				flush()
			}
			currentIsDigit = false
			current.WriteRune(r)
		default:
			flush()
		}
	}
	flush()
	return parts
}
