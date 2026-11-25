package policy

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/rtulke/checkmate/internal/runner"
	"github.com/rtulke/checkmate/internal/tmpl"

	"gopkg.in/yaml.v3"
)

// A check with loop_run runs a command first and becomes one check per
// line of its output:
//
//	- id: HOME-{{ item }}
//	  name: "Home directory of {{ item }} is private"
//	  loop_run: awk -F: '$3 >= 1000 { print $1 }' /etc/passwd
//	  run: stat -c %a "$(getent passwd "$CHECKMATE_ITEM" | cut -d: -f6)"
//	  expect: "in [700, 750]"
//
// The lines come from the host, not from the policy author. They are
// therefore never pasted into a command: `run` and `only_if` cannot use
// {{ item }} and read the item from the environment instead.

const (
	// ItemEnv is the environment variable that carries the item of a
	// loop_run check into its commands.
	ItemEnv = "CHECKMATE_ITEM"
	// ItemPlaceholder stands for the item where loop_run is not executed
	// (validate, list, diff).
	ItemPlaceholder = "{item}"
	// maxLoopItems bounds the number of checks one loop_run may create.
	maxLoopItems = 10000
)

// Outcomes of a check that is not run, see Check.Fixed.
const (
	FixedSkip  = "skip"
	FixedNA    = "na"
	FixedError = "error"
)

// FixedOutcome is the result of a check whose loop_run did not produce
// checks to run.
type FixedOutcome struct {
	Status  string // FixedSkip, FixedNA or FixedError
	Message string
	Command string // the loop_run command, if it was resolved
}

// loopExec carries what is needed to execute loop_run commands.
type loopExec struct {
	ctx          context.Context
	platformKeys []string
	jobs         int
}

var (
	templateTag   = regexp.MustCompile(`(?s)\{\{.*?\}\}|\{%.*?%\}`)
	itemReference = regexp.MustCompile(`\bitem\b`)
	whitespaceRun = regexp.MustCompile(`\s+`)
)

// expandLoopRun expands a check with loop_run. Without exec it returns the
// check once, rendered with ItemPlaceholder.
func expandLoopRun(p *Policy, src CheckSource, node, loopRunNode *yaml.Node, ctx map[string]any, exec *loopExec) ([]*Check, error) {
	loopRunNode = cloneNode(loopRunNode) // rendered below, and expanded twice if deferred
	if err := renderNode(loopRunNode, ctx); err != nil {
		return nil, fmt.Errorf("loop_run: %w", err)
	}
	var spec CommandSpec
	if err := loopRunNode.Decode(&spec); err != nil {
		return nil, fmt.Errorf("loop_run: %w", err)
	}
	if spec.IsZero() {
		return nil, fmt.Errorf("loop_run: command is empty")
	}

	// The placeholder check validates the definition and supplies shell,
	// timeout and conditions before any item is known.
	proto, err := loopRunCheck(p, src, node, ctx, spec, ItemPlaceholder, true)
	if err != nil {
		return nil, err
	}
	if exec == nil {
		return []*Check{proto}, nil
	}
	fixed := func(status, msg, command string) ([]*Check, error) {
		proto.Fixed = &FixedOutcome{Status: status, Message: msg, Command: command}
		return []*Check{proto}, nil
	}

	// Conditions that do not depend on the item decide whether the item
	// command may run at all (it may not exist on this platform).
	for _, cond := range proto.When {
		if itemReference.MatchString(cond) {
			continue
		}
		ok, err := tmpl.Eval(cond, ctx)
		if err != nil {
			return fixed(FixedError, fmt.Sprintf("when: %v", err), "")
		}
		if !ok {
			return fixed(FixedSkip, fmt.Sprintf("when: %s is false", cond), "")
		}
	}

	command, ok, err := proto.Command(spec, exec.platformKeys)
	if err != nil {
		return fixed(FixedError, "loop_run: "+err.Error(), "")
	}
	if !ok {
		return fixed(FixedNA, "loop_run: no command for this platform", "")
	}
	out, err := runner.Run(exec.ctx, runner.Request{
		Command: command,
		Shell:   proto.Shell,
		Dir:     src.Dir,
		Env:     p.Env,
		Timeout: proto.Timeout,
	})
	if err != nil {
		return fixed(FixedError, "loop_run: "+err.Error(), command)
	}
	if out.RC != 0 {
		msg := fmt.Sprintf("loop_run: command failed with exit code %d", out.RC)
		if line := firstLine(out.Stderr); line != "" {
			msg += ": " + line
		}
		return fixed(FixedError, msg, command)
	}
	if out.Truncated {
		return fixed(FixedError, "loop_run: the output is too large, items would be missing", command)
	}
	items, err := loopRunItems(out.Stdout)
	if err != nil {
		return fixed(FixedError, "loop_run: "+err.Error(), command)
	}
	if len(items) == 0 {
		return fixed(FixedNA, "loop_run: the command printed no items", command)
	}

	checks := make([]*Check, 0, len(items))
	for _, item := range items {
		c, err := loopRunCheck(p, src, node, ctx, spec, item, false)
		if err != nil {
			return nil, err
		}
		checks = append(checks, c)
	}
	return checks, nil
}

// loopRunItems splits the output of a loop_run command into items: one per
// line, without surrounding whitespace, empty lines and repetitions.
func loopRunItems(stdout string) ([]string, error) {
	var items []string
	seen := map[string]bool{}
	for _, line := range strings.Split(stdout, "\n") {
		item := strings.TrimSpace(line)
		if item == "" || seen[item] {
			continue
		}
		if strings.ContainsRune(item, 0) {
			return nil, fmt.Errorf("an item contains a NUL byte; print one item per line")
		}
		seen[item] = true
		items = append(items, item)
		if len(items) > maxLoopItems {
			return nil, fmt.Errorf("more than %d items", maxLoopItems)
		}
	}
	return items, nil
}

// loopRunCheck builds the check for one item. With placeholder set,
// templates that cannot cope with the placeholder (say, a field of a
// split item) are replaced by it instead of failing.
func loopRunCheck(p *Policy, src CheckSource, node *yaml.Node, ctx map[string]any, spec CommandSpec, item string, placeholder bool) (*Check, error) {
	itemCtx := copyMap(ctx)
	itemCtx["item"] = item
	var fallback func(string) string
	if placeholder {
		fallback = func(src string) string { return templateTag.ReplaceAllString(src, ItemPlaceholder) }
	}

	n := cloneNode(node)
	for i := 0; i+1 < len(n.Content); i += 2 {
		key, value := n.Content[i].Value, n.Content[i+1]
		switch key {
		case "run", "only_if":
			// Rendered without the item: it is data from the host and
			// must not become part of a command line.
			if err := renderNode(value, ctx); err != nil {
				if usesItem(value) {
					return nil, fmt.Errorf("%s: {{ item }} of a loop_run cannot be used in a command, "+
						"read the environment variable %s instead (\"$%s\", in PowerShell $env:%s)",
						key, ItemEnv, ItemEnv, ItemEnv)
				}
				return nil, fmt.Errorf("%s: %w", key, err)
			}
		default:
			if err := renderNodeWith(value, itemCtx, fallback); err != nil {
				return nil, fmt.Errorf("%s: %w", key, err)
			}
			if key == "id" && !placeholder && value.Kind == yaml.ScalarNode {
				// Items may contain blanks, IDs may not.
				value.Value = whitespaceRun.ReplaceAllString(strings.TrimSpace(value.Value), "_")
			}
		}
	}

	c, cerr := decodeCheck(p, src, n, itemCtx)
	if cerr != nil {
		return nil, cerr
	}
	if c.Shell == "cmd" {
		return nil, &CheckError{ID: c.ID, Source: src, Err: fmt.Errorf(
			"loop_run is not available with shell: cmd, which expands %%%s%% as command text; use powershell", ItemEnv)}
	}
	if c.Register != "" {
		return nil, &CheckError{ID: c.ID, Source: src, Err: fmt.Errorf("register cannot be combined with loop_run")}
	}
	c.LoopRun = spec
	if !placeholder {
		c.Env = map[string]string{ItemEnv: item}
	}
	return c, nil
}

// usesItem reports whether a template below n refers to the item.
func usesItem(n *yaml.Node) bool {
	if n.Kind == yaml.ScalarNode {
		for _, tag := range templateTag.FindAllString(n.Value, -1) {
			if itemReference.MatchString(tag) {
				return true
			}
		}
		return false
	}
	for _, child := range n.Content {
		if usesItem(child) {
			return true
		}
	}
	return false
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// Deferred reports whether the check is a loop_run check that still has to
// be expanded, because its conditions refer to registered checks.
func (c *Check) Deferred() bool { return c.deferred }

// ExpandDeferred expands a deferred loop_run check once the outcomes of the
// checks it refers to are known. Like ExpandRun it returns one check per
// item, or the check itself with a fixed outcome.
func (c *Check) ExpandDeferred(ctx context.Context, platformKeys []string, outcomes map[string]Outcome) ([]*Check, *CheckError) {
	values := map[string]any{}
	for name, o := range outcomes {
		values[name] = o.Values()
	}
	checks, err := c.expandItems(&loopExec{ctx: ctx, platformKeys: platformKeys, jobs: 1}, values)
	if err != nil {
		var ce *CheckError
		if errors.As(err, &ce) {
			return nil, ce
		}
		return nil, &CheckError{ID: c.ID, Source: c.Source, Err: err}
	}
	return checks, nil
}
