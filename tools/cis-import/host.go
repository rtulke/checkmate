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
