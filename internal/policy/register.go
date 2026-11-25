package policy

import (
	"fmt"
	"regexp"
)

// A check with `register: name` publishes its outcome, and later checks may
// refer to it in `when`:
//
//	- id: NGINX-INSTALLED
//	  register: nginx
//	  run: command -v nginx
//	  expect: true
//
//	- id: NGINX-TLS
//	  when: nginx.passed
//	  run: nginx -T | grep ssl_protocols
//	  expect: "!~ TLSv1(\\.1)?[ ;]"
//
// Only the outcome is published (status, exit code), never the output:
// registered checks steer other checks, they do not collect data for them.

var registerName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// reservedNames cannot be registered: they have a meaning in templates.
var reservedNames = map[string]bool{
	"vars": true, "facts": true, "item": true, "arg": true, "args": true, "policy_dir": true,
	"true": true, "false": true, "none": true, "and": true, "or": true, "not": true, "in": true, "is": true,
}

func validRegisterName(name string, ctx map[string]any) error {
	if name == "" {
		return nil
	}
	if !registerName.MatchString(name) {
		return fmt.Errorf("register: %q is not a valid name (letters, digits and _)", name)
	}
	if reservedNames[name] {
		return fmt.Errorf("register: %q is a reserved name", name)
	}
	if _, taken := ctx[name]; taken {
		return fmt.Errorf("register: %q is already a variable", name)
	}
	return nil
}

// linkRegistered fills Check.Needs. A check may only refer to checks that
// are defined before it, which also rules out cycles. Checks that break
// the rules are removed and reported.
func linkRegistered(checks []*Check) ([]*Check, []*CheckError) {
	owner := map[string]int{} // registered name -> index of its check
	var errs []*CheckError
	bad := map[int]bool{}
	for i, c := range checks {
		if c.Register == "" {
			continue
		}
		if prev, dup := owner[c.Register]; dup {
			errs = append(errs, &CheckError{ID: c.ID, Source: c.Source,
				Err: fmt.Errorf("register: %q is already registered by %s", c.Register, checks[prev].ID)})
			bad[i] = true
			continue
		}
		owner[c.Register] = i
	}
	if len(owner) == 0 {
		return checks, nil
	}

	names := sortedKeys(owner)
	patterns := make([]*regexp.Regexp, len(names))
	for n, name := range names {
		patterns[n] = regexp.MustCompile(`(^|[^A-Za-z0-9_.])` + name + `\b`)
	}
	for i, c := range checks {
		if bad[i] {
			continue
		}
		for n, name := range names {
			if !refersTo(c.When, patterns[n]) {
				continue
			}
			var err error
			switch at := owner[name]; {
			case at == i:
				err = fmt.Errorf("when: the check refers to %q, which it registers itself", name)
			case at > i:
				err = fmt.Errorf("when: %q is registered by %s, which is defined later; move that check up", name, checks[at].ID)
			case !c.LoopRun.IsZero():
				err = fmt.Errorf("when: a check with loop_run cannot refer to the registered %q", name)
			}
			if err != nil {
				errs = append(errs, &CheckError{ID: c.ID, Source: c.Source, Err: err})
				bad[i] = true
				break
			}
			c.Needs = append(c.Needs, name)
		}
	}
	if len(bad) == 0 {
		return checks, errs
	}
	kept := checks[:0:0]
	for i, c := range checks {
		if !bad[i] {
			kept = append(kept, c)
		}
	}
	return kept, errs
}

// stringLiteral matches quoted text in a condition; a name inside it is
// not a reference.
var stringLiteral = regexp.MustCompile(`"(\\.|[^"\\])*"|'(\\.|[^'\\])*'`)

func refersTo(conds []string, pattern *regexp.Regexp) bool {
	for _, cond := range conds {
		if pattern.MatchString(stringLiteral.ReplaceAllString(cond, `""`)) {
			return true
		}
	}
	return false
}

// Outcome is what a registered check publishes.
type Outcome struct {
	Status string // pass, fail, error, skip, na or waived
	RC     *int   // exit code of the command, nil if it did not run
}

// Values is the mapping a `when` condition sees under the registered name.
func (o Outcome) Values() map[string]any {
	rc := -1
	if o.RC != nil {
		rc = *o.RC
	}
	return map[string]any{
		"status": o.Status,
		"passed": o.Status == "pass",
		"failed": o.Status == "fail",
		"ran":    o.RC != nil,
		"rc":     rc,
	}
}

// WithOutcomes returns a copy of the check whose conditions see the given
// registered outcomes.
func (c *Check) WithOutcomes(outcomes map[string]Outcome) *Check {
	clone := *c
	clone.context = copyMap(c.context)
	for name, o := range outcomes {
		clone.context[name] = o.Values()
	}
	return &clone
}
