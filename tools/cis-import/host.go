package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

// Upstream reads a few facts of the audited host while it renders a rule
// file. A policy is generated once for every host, so these are replaced by
// markers that the converters turn into shell code.
const (
	auditdConf     = "/etc/audit/auditd.conf"
	auditLogDirVar = "AUDIT_LOG_DIR="
	globCountVar   = "GLOB_COUNT="
)

var (
	// {{ len (glob "/sys/class/net/*/wireless") }}
	globCount = regexp.MustCompile(`\{\{-? *len \(glob "([^"]+)"\) *-?\}\}`)
	// ... | get "dir")) "/var/log/audit": the directory upstream assumes
	// when auditd.conf does not name a log file.
	auditLogDirDefault = regexp.MustCompile(`\| *get "dir"\)\) "([^"]+)"`)
	auditLogDirRef     = regexp.MustCompile(`"?` + auditLogDirVar + `([^\s"]+)"?`)
)

// auditLogDirShell sets d to the directory of log_file in auditd.conf, or to
// the directory upstream assumes when there is none.
func auditLogDirShell(fallback string) string {
	return `d=$(sed -nE 's|^[[:space:]]*log_file[[:space:]]*=[[:space:]]*([^[:space:]]*)/[^/[:space:]]*[[:space:]]*$|\1|p' ` + auditdConf + ` 2>/dev/null | head -n 1)
[ -n "$d" ] || d=` + shellQuote(fallback)
}

// hostFuncs are the template functions that read the audited host.
func hostFuncs(data []byte) template.FuncMap {
	logDir := "/var/log/audit"
	if m := auditLogDirDefault.FindSubmatch(data); m != nil {
		logDir = string(m[1])
	}
	return template.FuncMap{
		"glob": func(pattern string) []string {
			if pattern == auditdConf {
				return []string{pattern}
			}
			return nil
		},
		"readFile": func(path string) string {
			if path == auditdConf {
				return "log_file = " + auditLogDirVar + logDir + "/audit.log\n"
			}
			return ""
		},
		"findStringSubmatch": func(expr, s string) map[string]string {
			out := map[string]string{}
			re, err := regexp.Compile(expr)
			if err != nil {
				return out
			}
			m := re.FindStringSubmatch(s)
			for i, n := range re.SubexpNames() {
				if m != nil && n != "" {
					out[n] = m[i]
				}
			}
			return out
		},
		"get": func(key string, m map[string]string) string { return m[key] },
	}
}

// loadDiscovery reads the discovery block of goss.yml or syver.yml: facts of
// the host that decide whether a test applies. It returns a shell command
// per fact that succeeds when the fact holds.
func loadDiscovery(src string, b benchmark, vars map[string]any) (map[string]string, error) {
	out := map[string]string{}
	for _, name := range []string{"syver.yml", "goss.yml"} {
		path := filepath.Join(src, name)
		if _, err := os.Stat(path); err != nil {
			continue
		}
		rendered, err := render(path, vars, "")
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		var doc struct {
			Discovery map[string]map[string]map[string]any `yaml:"discovery"`
		}
		if err := yaml.Unmarshal(rendered, &doc); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		for kind, resources := range doc.Discovery {
			for name, attrs := range resources {
				fact := str(attrs["register"])
				if fact == "" {
					continue
				}
				switch kind {
				case "mount":
					out[fact] = "findmnt -n " + shellQuote(name)
				case "package":
					out[fact] = packageQuery(b, name)
				case "file":
					out[fact] = "test -e " + shellQuote(name)
				default:
					fmt.Fprintf(os.Stderr, "  discovery %s: unsupported kind %s\n", fact, kind)
				}
			}
		}
	}
	return out, nil
}

// discoveryConditions finds the resources of a rule file that upstream skips
// when a discovered fact is absent. It returns the commands that test these
// facts, by resource kind and name (see resourceKey).
func discoveryConditions(path string, vars map[string]any, discovery map[string]string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(discovery) == 0 {
		return out, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	facts := map[string]bool{}
	for _, m := range discoveredRe.FindAllStringSubmatch(string(data), -1) {
		facts[m[1]] = true
	}
	for _, fact := range sortedKeys(facts) {
		test, ok := discovery[fact]
		if !ok {
			continue
		}
		rendered, err := render(path, vars, fact)
		if err != nil {
			return nil, err
		}
		doc, err := decodeResources(rendered)
		if err != nil {
			return nil, err
		}
		for kind, resources := range doc {
			for name, attrs := range resources {
				if truthy(attrs["skip"]) {
					key := resourceKey(kind, name)
					out[key] = append(out[key], test)
				}
			}
		}
	}
	return out, nil
}

func resourceKey(kind, name string) string { return kind + "\x00" + name }

// dependsOn returns the commands for the depends-on list of a resource: the
// test only applies if these resources pass.
func dependsOn(b benchmark, attrs map[string]any) []string {
	var out []string
	for _, d := range stringList(attrs["depends-on"]) {
		kind, name, _ := strings.Cut(d, ":")
		if kind == "package" && name != "" {
			out = append(out, packageQuery(b, name))
			continue
		}
		fmt.Fprintf(os.Stderr, "  unsupported depends-on %q\n", d)
	}
	return out
}

// addOnlyIf makes the checks apply only if every command succeeds.
func addOnlyIf(checks []check, conds ...[]string) []check {
	for i := range checks {
		have := strings.Split(checks[i].OnlyIf, " && ")
		for _, list := range conds {
			for _, cond := range list {
				if slices.Contains(have, cond) {
					continue
				}
				have = append(have, cond)
				if checks[i].OnlyIf != "" {
					checks[i].OnlyIf += " && "
				}
				checks[i].OnlyIf += cond
			}
		}
	}
	return checks
}

// packageQuery is a command that succeeds if the package is installed.
func packageQuery(b benchmark, pkg string) string {
	if b.Package == "dpkg" {
		return fmt.Sprintf("dpkg-query -W -f='${Status}' %s 2>/dev/null | grep -q 'install ok installed'", pkg)
	}
	return fmt.Sprintf("rpm -q --quiet %s", pkg)
}

// matchingCheck translates a matching resource, which compares a value the
// template computes on the host. Only "no path matches a glob" is supported.
func matchingCheck(c check, name string, attrs map[string]any) []check {
	pattern, ok := strings.CutPrefix(str(attrs["content"]), globCountVar)
	want, isInt := attrs["matches"].(int)
	if !ok || !isInt || want != 0 || !safeGlob.MatchString(pattern) {
		fmt.Fprintf(os.Stderr, "  skipped %s: unsupported matching resource\n", c.ID)
		return nil
	}
	c.Name = fmt.Sprintf("%s: no %s exists", humanize(name), pattern)
	c.Run = fmt.Sprintf("ls -d %s 2>/dev/null", pattern)
	c.AllowAnyRC = true
	c.Expect = []string{"empty"}
	return []check{c}
}

var safeGlob = regexp.MustCompile(`^[A-Za-z0-9_./*?-]+$`)

// hostVars are upstream variables that say what a host is used for, by
// benchmark. The rules they switch on are generated for every host and
// apply only if the package is installed.
var hostVars = map[string]map[string]string{
	"ubuntu24": {"ubtu24cis_desktop_required": "gdm3"},
	"rhel10":   {"desktop_required": "gdm"},
}

// hostVarConditions compares a rule file rendered with a host variable set
// and unset. A resource that only one of the two includes gets a command
// that tests the package behind the variable (by resourceKey). Resources
// that upstream skips when the variable is set are returned in unskip.
func hostVarConditions(path string, b benchmark, vars map[string]any) (conds map[string][]string, unskip map[string]bool, err error) {
	conds, unskip = map[string][]string{}, map[string]bool{}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	active := func(vars map[string]any) (map[string]bool, map[string]bool, error) {
		rendered, err := render(path, vars, "")
		if err != nil {
			return nil, nil, err
		}
		doc, err := decodeResources(rendered)
		if err != nil {
			return nil, nil, err
		}
		on, all := map[string]bool{}, map[string]bool{}
		for kind, resources := range doc {
			for name, attrs := range resources {
				all[resourceKey(kind, name)] = true
				on[resourceKey(kind, name)] = !truthy(attrs["skip"])
			}
		}
		return on, all, nil
	}
	for _, name := range sortedKeys(hostVars[b.Key]) {
		if !strings.Contains(string(data), ".Vars."+name) {
			continue
		}
		installed := packageQuery(b, hostVars[b.Key][name])
		with, all, err := active(vars)
		if err != nil {
			return nil, nil, err
		}
		unset := map[string]any{}
		for k, v := range vars {
			unset[k] = v
		}
		unset[name] = false
		without, _, err := active(unset)
		if err != nil {
			return nil, nil, err
		}
		for key := range all {
			switch {
			case with[key] && !without[key]:
				conds[key] = append(conds[key], installed)
			case !with[key] && without[key]:
				conds[key] = append(conds[key], "! "+installed)
				unskip[key] = true
			}
		}
	}
	return conds, unskip, nil
}

var (
	// modprobe --showconfig | grep -P '\b(install|blacklist)\h+dccp\b'
	showconfigGrep = regexp.MustCompile(`^modprobe --showconfig \| grep -P '\\b\(install\|blacklist\)\\h\+([A-Za-z0-9_-]+)\\b'$`)
	// /^blacklist firewire[-_]core$/, /^install overlay(fs)? /bin/...
	modprobeLine = regexp.MustCompile(`^/\^(?:blacklist|install) ([A-Za-z0-9_()\[\]?-]+)`)
	moduleName   = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
)

// moduleCondition returns a command that succeeds if the kernel module a
// resource is about exists for the running kernel. A module the kernel does
// not ship cannot be loaded, so there is nothing to disable.
func moduleCondition(kind string, attrs map[string]any) []string {
	module := ""
	switch kind {
	case "command":
		if m := showconfigGrep.FindStringSubmatch(strings.TrimSpace(str(attrs["exec"]))); m != nil {
			module = m[1]
		}
	case "file":
		contents, _ := attrs["contents"].([]any)
		for _, p := range contents {
			m := modprobeLine.FindStringSubmatch(fmt.Sprint(p))
			if m == nil {
				return nil
			}
			name := strings.NewReplacer("(fs)?", "", "[-_]", "_").Replace(m[1])
			if module != "" && module != name {
				return nil
			}
			module = name
		}
	}
	if !moduleName.MatchString(module) {
		return nil
	}
	return []string{"modinfo " + module + " >/dev/null 2>&1"}
}
