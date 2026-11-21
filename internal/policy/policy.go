// Package policy loads checkmate policy files.
//
// A policy is a YAML document with metadata, variables, reusable command
// snippets and a list of checks. Policies can include other policies.
package policy

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Policy is a loaded policy including everything it includes.
type Policy struct {
	Name        string
	Version     string
	Description string
	Path        string            // path of the top-level policy file
	Vars        map[string]any    // merged variables
	Env         map[string]string // extra environment for all commands
	Defaults    Defaults
	Snippets    map[string]CommandSpec
	Checks      []CheckSource
	Waivers     []Waiver // accepted deviations from all files
	Files       []string // all files read, for diagnostics
}

// Defaults apply to every check that does not override them.
type Defaults struct {
	Timeout  time.Duration
	Shell    string
	Severity string
	FailOn   string // lowest severity whose failures are fatal
}

// CheckSource is an unexpanded check as written in a policy file.
type CheckSource struct {
	Node *yaml.Node // the raw check mapping
	File string     // file the check was defined in
	Dir  string     // directory of that file, used as working directory
	When []string   // defaults.when of that file, added to the check's conditions
}

// Line returns the line of the check in its file.
func (c CheckSource) Line() int { return c.Node.Line }

// Location returns "file:line" for diagnostics.
func (c CheckSource) Location() string { return fmt.Sprintf("%s:%d", c.File, c.Node.Line) }

// fileDoc mirrors the on-disk format of a policy file.
type fileDoc struct {
	Name        string                 `yaml:"name"`
	Version     string                 `yaml:"version"`
	Description string                 `yaml:"description"`
	Include     []string               `yaml:"include"`
	Vars        map[string]any         `yaml:"vars"`
	VarsFiles   []string               `yaml:"vars_files"`
	Env         map[string]string      `yaml:"env"`
	Defaults    fileDefaults           `yaml:"defaults"`
	Snippets    map[string]CommandSpec `yaml:"snippets"`
	Checks      []yaml.Node            `yaml:"checks"`
	Waivers     []yaml.Node            `yaml:"waivers"`
}

type fileDefaults struct {
	Timeout  string     `yaml:"timeout"`
	Shell    string     `yaml:"shell"`
	Severity string     `yaml:"severity"`
	FailOn   string     `yaml:"fail_on"`
	When     StringList `yaml:"when"`
}

// LoadOptions influence how policy files are loaded.
type LoadOptions struct {
	// AllowInsecure skips the ownership/permission check of policy files.
	AllowInsecure bool
}

// DefaultTimeout applies when neither the policy nor the check sets one.
const DefaultTimeout = 30 * time.Second

// Load reads a policy file and everything it includes.
func Load(path string, opts LoadOptions) (*Policy, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	p := &Policy{
		Path:     abs,
		Vars:     map[string]any{},
		Env:      map[string]string{},
		Snippets: map[string]CommandSpec{},
		Defaults: Defaults{Timeout: DefaultTimeout, Severity: "medium", FailOn: "low"},
	}
	l := &loader{opts: opts, policy: p, visiting: map[string]bool{}}
	if err := l.load(abs, true); err != nil {
		return nil, err
	}
	return p, nil
}

type loader struct {
	opts     LoadOptions
	policy   *Policy
	visiting map[string]bool
}

func (l *loader) load(path string, top bool) error {
	if l.visiting[path] {
		return fmt.Errorf("include cycle detected at %s", path)
	}
	l.visiting[path] = true
	defer delete(l.visiting, path)

	doc, err := l.readDoc(path)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)

	// Included files first: their checks run before ours and our values
	// override theirs. Our waivers go before theirs, because the first
	// matching waiver wins.
	waiverStart := len(l.policy.Waivers)
	for _, inc := range doc.Include {
		if err := l.load(resolve(dir, inc), false); err != nil {
			return err
		}
	}

	p := l.policy
	for _, vf := range doc.VarsFiles {
		vars, err := l.readVarsFile(resolve(dir, vf))
		if err != nil {
			return err
		}
		mergeInto(p.Vars, vars)
	}
	mergeInto(p.Vars, doc.Vars)
	for k, v := range doc.Env {
		p.Env[k] = v
	}

	for _, name := range sortedKeys(doc.Snippets) {
		if _, exists := p.Snippets[name]; exists {
			return fmt.Errorf("%s: snippet %q is already defined in an included file", path, name)
		}
		spec := doc.Snippets[name]
		if spec.Use != "" {
			return fmt.Errorf("%s: snippet %q must not reference another snippet", path, name)
		}
		p.Snippets[name] = spec
	}

	if top {
		p.Name = doc.Name
		p.Version = doc.Version
		p.Description = doc.Description
	}
	if err := applyDefaults(&p.Defaults, doc.Defaults, path); err != nil {
		return err
	}

	waivers, err := parseWaivers(doc.Waivers, path)
	if err != nil {
		return err
	}
	p.Waivers = append(p.Waivers[:waiverStart], append(waivers, p.Waivers[waiverStart:]...)...)

	for i := range doc.Checks {
		node := &doc.Checks[i]
		if node.Kind != yaml.MappingNode {
			return fmt.Errorf("%s:%d: a check must be a mapping", path, node.Line)
		}
		p.Checks = append(p.Checks, CheckSource{Node: node, File: path, Dir: dir, When: doc.Defaults.When})
	}
	return nil
}

// applyDefaults merges file defaults. Includes load first, so values of
// the including (outer) file win.
func applyDefaults(d *Defaults, fd fileDefaults, path string) error {
	if fd.Timeout != "" {
		t, err := time.ParseDuration(fd.Timeout)
		if err != nil || t <= 0 {
			return fmt.Errorf("%s: invalid defaults.timeout %q", path, fd.Timeout)
		}
		d.Timeout = t
	}
	if fd.Shell != "" {
		d.Shell = fd.Shell
	}
	if fd.Severity != "" {
		if SeverityRank(fd.Severity) < 0 {
			return fmt.Errorf("%s: invalid defaults.severity %q", path, fd.Severity)
		}
		d.Severity = fd.Severity
	}
	if fd.FailOn != "" {
		if SeverityRank(fd.FailOn) < 0 {
			return fmt.Errorf("%s: invalid defaults.fail_on %q (use %s)", path, fd.FailOn, strings.Join(Severities, ", "))
		}
		d.FailOn = fd.FailOn
	}

	return nil
}

func (l *loader) readDoc(path string) (*fileDoc, error) {
	data, err := l.readFile(path)
	if err != nil {
		return nil, err
	}
	var doc fileDoc
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	l.policy.Files = append(l.policy.Files, path)
	return &doc, nil
}

func (l *loader) readVarsFile(path string) (map[string]any, error) {
	data, err := l.readFile(path)
	if err != nil {
		return nil, err
	}
	vars := map[string]any{}
	if err := yaml.Unmarshal(data, &vars); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	l.policy.Files = append(l.policy.Files, path)
	return vars, nil
}

func (l *loader) readFile(path string) ([]byte, error) {
	if !l.opts.AllowInsecure {
		if err := checkFileSecurity(path); err != nil {
			return nil, err
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func resolve(dir, p string) string {
	if filepath.IsAbs(p) {
		return filepath.Clean(p)
	}
	return filepath.Join(dir, p)
}

func mergeInto(dst, src map[string]any) {
	for k, v := range src {
		dst[k] = v
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
