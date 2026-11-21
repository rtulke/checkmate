package policy

import (
	"bytes"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rtulke/checkmate/internal/tmpl"
)

// Waiver accepts the failure of checks for a documented reason. A waived
// check that fails, warns or errors is reported as WAIVED and does not make
// the run non-compliant.
type Waiver struct {
	IDs    []string  // glob patterns matched against check IDs
	Reason string    // why the deviation is accepted; required
	Until  time.Time // last day the waiver applies; zero means no expiry
	When   []string  // Jinja2 conditions; all must hold
	Skip   bool      // do not run the check at all
	Source string    // file:line of the definition
}

var waiverKeys = []string{"id", "reason", "until", "when", "skip"}

// Matches reports whether the waiver covers a check ID.
func (w Waiver) Matches(id string) bool {
	for _, pattern := range w.IDs {
		if ok, _ := path.Match(pattern, id); ok {
			return true
		}
	}
	return false
}

// Expired reports whether the waiver no longer applies at time now. A
// waiver is valid through the whole day given in until.
func (w Waiver) Expired(now time.Time) bool {
	return !w.Until.IsZero() && !now.Before(w.Until.AddDate(0, 0, 1))
}

// UntilString formats the expiry date, empty without one.
func (w Waiver) UntilString() string {
	if w.Until.IsZero() {
		return ""
	}
	return w.Until.Format("2006-01-02")
}

// parseWaivers decodes the waivers list of a file.
func parseWaivers(nodes []yaml.Node, file string) ([]Waiver, error) {
	var out []Waiver
	for i := range nodes {
		n := &nodes[i]
		loc := fmt.Sprintf("%s:%d", file, n.Line)
		if n.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("%s: a waiver must be a mapping", loc)
		}
		if err := checkKnownKeys(n, waiverKeys); err != nil {
			return nil, fmt.Errorf("%s: waiver: %w", loc, err)
		}
		var raw struct {
			ID     StringList `yaml:"id"`
			Reason string     `yaml:"reason"`
			Until  string     `yaml:"until"`
			When   StringList `yaml:"when"`
			Skip   bool       `yaml:"skip"`
		}
		if err := n.Decode(&raw); err != nil {
			return nil, fmt.Errorf("%s: waiver: %w", loc, err)
		}
		w := Waiver{Reason: strings.TrimSpace(raw.Reason), When: raw.When, Skip: raw.Skip, Source: loc}
		for _, id := range raw.ID {
			id = strings.TrimSpace(id)
			if id == "" {
				continue
			}
			if _, err := path.Match(id, ""); err != nil {
				return nil, fmt.Errorf("%s: waiver: invalid id pattern %q", loc, id)
			}
			w.IDs = append(w.IDs, id)
		}
		if len(w.IDs) == 0 {
			return nil, fmt.Errorf("%s: waiver: id is required", loc)
		}
		if w.Reason == "" {
			return nil, fmt.Errorf("%s: waiver: reason is required", loc)
		}
		if raw.Until != "" {
			t, err := time.ParseInLocation("2006-01-02", strings.TrimSpace(raw.Until), time.Local)
			if err != nil {
				return nil, fmt.Errorf("%s: waiver: until must be a date like 2027-03-31, got %q", loc, raw.Until)
			}
			w.Until = t
		}
		out = append(out, w)
	}
	return out, nil
}

// LoadWaivers reads a waiver file, e.g. a host-specific exception file
// passed with --waivers. Besides waivers it may list other waiver files
// under include (relative to the including file). The first matching waiver
// wins, so the waivers of a file come before those it includes: a specific
// file overrides the common files it builds on.
func LoadWaivers(file string, opts LoadOptions) ([]Waiver, error) {
	abs, err := filepath.Abs(file)
	if err != nil {
		return nil, err
	}
	l := &loader{opts: opts, visiting: map[string]bool{}}
	return l.loadWaivers(abs)
}

func (l *loader) loadWaivers(path string) ([]Waiver, error) {
	if l.visiting[path] {
		return nil, fmt.Errorf("include cycle detected at %s", path)
	}
	l.visiting[path] = true
	defer delete(l.visiting, path)

	data, err := l.readFile(path)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Include []string    `yaml:"include"`
		Waivers []yaml.Node `yaml:"waivers"`
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil && err != io.EOF {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	out, err := parseWaivers(doc.Waivers, path)
	if err != nil {
		return nil, err
	}
	for _, inc := range doc.Include {
		w, err := l.loadWaivers(resolve(filepath.Dir(path), inc))
		if err != nil {
			return nil, err
		}
		out = append(out, w...)
	}
	return out, nil
}

// Eval evaluates a Jinja2 condition with the facts and variables of the
// check.
func (c *Check) Eval(cond string) (bool, error) {
	return tmpl.Eval(cond, c.context)
}
