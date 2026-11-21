// Command cis-import converts the goss-based CIS audit content of the
// ansible-lockdown project (https://github.com/ansible-lockdown, MIT
// license) into checkmate policies.
//
//	go run ./tools/cis-import -src <checkout of RHEL9-CIS-Audit> -bench rhel9 -out cis/rhel9.yml
//
// Every goss resource becomes one or more checkmate checks. Check names are
// generated from what a check verifies; CIS recommendation titles are not
// copied. Rule numbers, profile levels and NIST references are kept as
// tags and descriptions.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"gopkg.in/yaml.v3"
)

// benchmark describes one supported CIS benchmark or DISA STIG.
type benchmark struct {
	Key     string // rhel9, or rhel9-stig for a STIG
	Name    string // Red Hat Enterprise Linux 9
	Repo    string // RHEL9-CIS-Audit
	When    string // Jinja2 condition limiting the policy to the platform
	Package string // rpm or dpkg
}

// stig reports whether the benchmark is a DISA STIG.
func (b benchmark) stig() bool { return strings.HasSuffix(b.Key, "-stig") }

// platform is the key without the -stig suffix.
func (b benchmark) platform() string { return strings.TrimSuffix(b.Key, "-stig") }

var benchmarks = map[string]benchmark{
	"rhel7":      {"rhel7", "Red Hat Enterprise Linux 7", "RHEL7-CIS-Audit", rhelWhen(7), "rpm"},
	"rhel8":      {"rhel8", "Red Hat Enterprise Linux 8", "RHEL8-CIS-Audit", rhelWhen(8), "rpm"},
	"rhel9":      {"rhel9", "Red Hat Enterprise Linux 9", "RHEL9-CIS-Audit", rhelWhen(9), "rpm"},
	"rhel10":     {"rhel10", "Red Hat Enterprise Linux 10", "RHEL10-CIS-Audit", rhelWhen(10), "rpm"},
	"debian11":   {"debian11", "Debian 11", "DEBIAN11-CIS-Audit", `facts.distro == "debian" and facts.version_major == 11`, "dpkg"},
	"debian12":   {"debian12", "Debian 12", "DEBIAN12-CIS-Audit", `facts.distro == "debian" and facts.version_major == 12`, "dpkg"},
	"debian13":   {"debian13", "Debian 13", "DEBIAN13-CIS-Audit", `facts.distro == "debian" and facts.version_major == 13`, "dpkg"},
	"ubuntu20":   {"ubuntu20", "Ubuntu 20.04 LTS", "UBUNTU20-CIS-Audit", `facts.distro == "ubuntu" and facts.version_major == 20`, "dpkg"},
	"ubuntu22":   {"ubuntu22", "Ubuntu 22.04 LTS", "UBUNTU22-CIS-Audit", `facts.distro == "ubuntu" and facts.version_major == 22`, "dpkg"},
	"ubuntu24":   {"ubuntu24", "Ubuntu 24.04 LTS", "UBUNTU24-CIS-Audit", `facts.distro == "ubuntu" and facts.version_major == 24`, "dpkg"},
	"ubuntu26":   {"ubuntu26", "Ubuntu 26.04 LTS", "UBUNTU26-CIS-Audit", `facts.distro == "ubuntu" and facts.version_major == 26`, "dpkg"},
	"suse15":     {"suse15", "SUSE Linux Enterprise 15", "SUSE15-CIS-Audit", suseWhen(15), "rpm"},
	"suse16":     {"suse16", "SUSE Linux Enterprise 16", "SUSE16-CIS-Audit", suseWhen(16), "rpm"},
	"amazon2":    {"amazon2", "Amazon Linux 2", "AMAZON2-CIS-Audit", `facts.distro == "amzn" and facts.version_major == 2`, "rpm"},
	"amazon2023": {"amazon2023", "Amazon Linux 2023", "AMAZON2023-CIS-Audit", `facts.distro == "amzn" and facts.version_major == 2023`, "rpm"},
	"amazon2027": {"amazon2027", "Amazon Linux 2027", "AMAZON2027-CIS-Audit", `facts.distro == "amzn" and facts.version_major == 2027`, "rpm"},
	"ubuntu18":   {"ubuntu18", "Ubuntu 18.04 LTS", "UBUNTU18-CIS-Audit", `facts.distro == "ubuntu" and facts.version_major == 18`, "dpkg"},

	"rhel7-stig":      {"rhel7-stig", "Red Hat Enterprise Linux 7", "RHEL7-STIG-Audit", rhelWhen(7), "rpm"},
	"rhel8-stig":      {"rhel8-stig", "Red Hat Enterprise Linux 8", "RHEL8-STIG-Audit", rhelWhen(8), "rpm"},
	"rhel9-stig":      {"rhel9-stig", "Red Hat Enterprise Linux 9", "RHEL9-STIG-Audit", rhelWhen(9), "rpm"},
	"rhel10-stig":     {"rhel10-stig", "Red Hat Enterprise Linux 10", "RHEL10-STIG-Audit", rhelWhen(10), "rpm"},
	"ubuntu22-stig":   {"ubuntu22-stig", "Ubuntu 22.04 LTS", "UBUNTU22-STIG-Audit", `facts.distro == "ubuntu" and facts.version_major == 22`, "dpkg"},
	"ubuntu24-stig":   {"ubuntu24-stig", "Ubuntu 24.04 LTS", "UBUNTU24-STIG-Audit", `facts.distro == "ubuntu" and facts.version_major == 24`, "dpkg"},
	"amazon2023-stig": {"amazon2023-stig", "Amazon Linux 2023", "AMAZON2023-STIG-Audit", `facts.distro == "amzn" and facts.version_major == 2023`, "rpm"},
}

func rhelWhen(v int) string {
	return fmt.Sprintf(`(facts.distro == "rhel" or "rhel" in facts.distro_like) and facts.version_major == %d`, v)
}

func suseWhen(v int) string {
	return fmt.Sprintf(`(facts.distro in ["sles", "sled", "opensuse-leap"] or "suse" in facts.distro_like) and facts.version_major == %d`, v)
}

// check is one generated checkmate check.
type check struct {
	ID          string
	Name        string
	Description string
	Tags        []string
	Severity    string
	Run         string
	AllowAnyRC  bool
	Expect      []string // YAML fragments, combined with "all"
	Timeout     string
	As          string
	OnlyIf      string
}

// ruleMeta is the meta block of a goss resource.
type ruleMeta struct {
	CISID       string // CIS recommendation number, or the STIG ID
	Server      int
	Workstation int
	NIST        []string
	Controls    []string
	// STIG only
	Cat     int
	VulID   string
	RuleID  string
	CCI     []string
	NISTR4  []string
	Title   string
	Qualify string
}

func main() {
	src := flag.String("src", "", "checkout of an ansible-lockdown *-CIS-Audit repository")
	key := flag.String("bench", "", "benchmark key, e.g. rhel9")
	out := flag.String("out", "", "output policy file")
	flag.Parse()

	b, ok := benchmarks[*key]
	if !ok || *src == "" || *out == "" {
		keys := make([]string, 0, len(benchmarks))
		for k := range benchmarks {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(os.Stderr, "usage: cis-import -src DIR -bench KEY -out FILE\nbenchmarks: %s\n", strings.Join(keys, ", "))
		os.Exit(2)
	}
	stats, err := convert(*src, b, *out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "cis-import:", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "%s: %d rule files, %d rules, %d checks, %d resources skipped\n",
		b.Key, stats.files, stats.rules, stats.checks, stats.skipped)
}

type stats struct{ files, rules, checks, skipped int }

func convert(src string, b benchmark, out string) (stats, error) {
	var st stats
	vars, version, err := loadVars(src)
	if err != nil {
		return st, err
	}
	var files []string
	err = filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := strings.ToLower(strings.TrimPrefix(path, src))
		if !d.IsDir() && strings.HasSuffix(path, ".yml") && (strings.Contains(rel, "section_") || strings.Contains(rel, "/cat_")) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return st, err
	}
	sort.Slice(files, func(i, j int) bool { return naturalLess(files[i], files[j]) })

	var checks []check
	rules := map[string]bool{}
	seen := map[string]int{}
	for _, f := range files {
		st.files++
		rendered, err := render(f, vars)
		if err != nil {
			return st, fmt.Errorf("%s: %w", f, err)
		}
		doc, err := decodeResources(rendered)
		if err != nil {
			return st, fmt.Errorf("%s: %w", f, err)
		}
		for _, kind := range []string{"kernel-param", "mount", "package", "service", "file", "command", "user", "group"} {
			resources := doc[kind]
			for _, name := range sortedKeys(resources) {
				attrs := resources[name]
				if truthy(attrs["skip"]) {
					st.skipped++
					continue
				}
				meta := parseMeta(attrs["meta"])
				if meta.CISID == "" {
					meta.CISID = cisIDFromPath(f)
				}
				if b.stig() {
					meta.Title, meta.Qualify = stigTitle(str(attrs["title"]))
					if meta.Cat == 0 {
						meta.Cat = catFromPath(f)
					}
				}
				generated := convertResource(b, kind, name, attrs, meta)
				if len(generated) == 0 {
					st.skipped++
					continue
				}
				// Commands that are not valid shell code upstream are left out
				// and reported, instead of producing a check that always errors.
				valid := generated[:0]
				for _, c := range generated {
					if err := shellSyntax(c.Run); err != nil {
						fmt.Fprintf(os.Stderr, "  skipped %s (%s): invalid shell syntax: %v\n", c.ID, filepath.Base(f), err)
						st.skipped++
						continue
					}
					valid = append(valid, c)
				}
				generated = valid
				if len(generated) == 0 {
					continue
				}
				rules[meta.CISID] = true
				for _, c := range generated {
					c.ID = uniqueID(seen, c.ID)
					checks = append(checks, c)
				}
			}
		}
	}
	st.rules = len(rules)
	st.checks = len(checks)
	return st, writePolicy(out, b, version, checks, len(rules))
}

func loadVars(src string) (map[string]any, string, error) {
	vars := map[string]any{}
	matches, _ := filepath.Glob(filepath.Join(src, "vars", "*.yml"))
	for _, m := range matches {
		data, err := os.ReadFile(m)
		if err != nil {
			return nil, "", err
		}
		var v map[string]any
		if err := yaml.Unmarshal(data, &v); err != nil {
			return nil, "", fmt.Errorf("%s: %w", m, err)
		}
		for k, val := range v {
			vars[k] = val
		}
	}
	// Generate every rule and every level; selection happens with tags.
	for k := range vars {
		if strings.Contains(k, "_rule_") || strings.HasSuffix(k, "_level_1") || strings.HasSuffix(k, "_level_2") ||
			regexp.MustCompile(`_section[0-9]+$`).MatchString(k) {
			vars[k] = true
		}
	}
	vars["run_heavy_tests"] = true
	version := strings.TrimPrefix(fmt.Sprint(vars["benchmark_version"]), "v")
	return vars, version, nil
}

// decodeResources reads a rendered goss file. Unlike a plain Unmarshal it
// tolerates duplicate resource keys (the later one gets a suffix) and
// ignores resources that are not mappings.
func decodeResources(data []byte) (map[string]map[string]map[string]any, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	out := map[string]map[string]map[string]any{}
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return out, nil
	}
	top := root.Content[0]
	for i := 0; i+1 < len(top.Content); i += 2 {
		kind, resources := top.Content[i].Value, top.Content[i+1]
		if resources.Kind != yaml.MappingNode {
			continue
		}
		if out[kind] == nil {
			out[kind] = map[string]map[string]any{}
		}
		for j := 0; j+1 < len(resources.Content); j += 2 {
			name, body := resources.Content[j].Value, resources.Content[j+1]
			if body.Kind != yaml.MappingNode {
				continue
			}
			attrs, err := decodeAttrs(body)
			if err != nil {
				return nil, err
			}
			key := name
			for n := 2; out[kind][key] != nil; n++ {
				key = fmt.Sprintf("%s#%d", name, n)
			}
			if _, has := attrs["path"]; !has && kind == "file" {
				attrs["path"] = name
			}
			if _, has := attrs["mountpoint"]; !has && kind == "mount" {
				attrs["mountpoint"] = name
			}
			out[kind][key] = attrs
		}
	}
	return out, nil
}

// decodeAttrs decodes a resource body. Duplicate keys are merged: lists
// are concatenated, other values are overwritten by the later one.
func decodeAttrs(body *yaml.Node) (map[string]any, error) {
	attrs := map[string]any{}
	for i := 0; i+1 < len(body.Content); i += 2 {
		key := body.Content[i].Value
		v := nodeValue(body.Content[i+1])
		if prev, ok := attrs[key].([]any); ok {
			if cur, ok := v.([]any); ok {
				attrs[key] = append(prev, cur...)
				continue
			}
		}
		attrs[key] = v
	}
	return attrs, nil
}

// nodeValue converts a YAML node like Decode, but a duplicate key in a
// nested mapping keeps the later value instead of failing.
func nodeValue(n *yaml.Node) any {
	switch n.Kind {
	case yaml.MappingNode:
		m := map[string]any{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			m[n.Content[i].Value] = nodeValue(n.Content[i+1])
		}
		return m
	case yaml.SequenceNode:
		l := make([]any, 0, len(n.Content))
		for _, c := range n.Content {
			l = append(l, nodeValue(c))
		}
		return l
	case yaml.AliasNode:
		return nodeValue(n.Alias)
	case yaml.DocumentNode:
		if len(n.Content) > 0 {
			return nodeValue(n.Content[0])
		}
		return nil
	}
	var v any
	if err := n.Decode(&v); err != nil {
		return n.Value
	}
	return v
}

var funcs = template.FuncMap{
	"upper":     strings.ToUpper,
	"lower":     strings.ToLower,
	"mkSlice":   func(args ...any) []any { return args },
	"splitList": func(sep, s string) []string { return strings.Split(s, sep) },
	"split":     func(sep, s string) []string { return strings.Split(s, sep) },
	"join": func(sep string, v any) string {
		var parts []string
		for _, e := range stringList(v) {
			parts = append(parts, e)
		}
		return strings.Join(parts, sep)
	},
	"contains":  func(sub, s string) bool { return strings.Contains(s, sub) },
	"hasPrefix": func(p, s string) bool { return strings.HasPrefix(s, p) },
	"hasSuffix": func(p, s string) bool { return strings.HasSuffix(s, p) },
	"replace":   func(old, new, s string) string { return strings.ReplaceAll(s, old, new) },
	"default": func(def, v any) any {
		if v == nil || fmt.Sprint(v) == "" {
			return def
		}
		return v
	},
	"list":    func(args ...any) []any { return args },
	"trim":    strings.TrimSpace,
	"toLower": strings.ToLower,
	"toUpper": strings.ToUpper,
	"toJson": func(v any) string {
		data, _ := json.Marshal(v)
		return string(data)
	},
}

func render(path string, vars map[string]any) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	tpl, err := template.New(filepath.Base(path)).Funcs(funcs).Option("missingkey=zero").Parse(string(data))
	if err != nil {
		return nil, err
	}
	// .Discovered holds facts goss collects at run time (installed packages,
	// separate mounts). Rules are generated as if they were present; mount
	// option rules get an only_if instead (see mountChecks).
	discovered := map[string]any{}
	for _, m := range discoveredRe.FindAllStringSubmatch(string(data), -1) {
		discovered[m[1]] = true
	}
	var buf bytes.Buffer
	if err := tpl.Execute(&buf, map[string]any{"Vars": vars, "Env": map[string]string{}, "Discovered": discovered}); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// convertResource translates one goss resource.
func convertResource(b benchmark, kind, name string, attrs map[string]any, m ruleMeta) []check {
	id := fmt.Sprintf("CIS-%s-%s-%s", strings.ToUpper(b.Key), m.CISID, sanitize(name))
	if b.stig() {
		id = fmt.Sprintf("STIG-%s-%s", m.CISID, sanitize(name))
	}
	base := check{
		ID:          id,
		Description: description(b, m),
		Tags:        tags(b, m),
		Severity:    severity(m),
	}
	if t, ok := attrs["timeout"]; ok {
		base.Timeout = fmt.Sprintf("%vms", t)
	}
	generated := convertKind(b, kind, name, attrs, base)
	if b.stig() && m.Title != "" {
		for i := range generated {
			what := generated[i].Name
			generated[i].Name = m.Title
			if len(generated) > 1 || m.Qualify != "" {
				q := m.Qualify
				if q == "" || len(generated) > 1 {
					q = what
				}
				generated[i].Name += " (" + firstLine(q, 70) + ")"
			}
		}
	}
	return generated
}

func convertKind(b benchmark, kind, name string, attrs map[string]any, base check) []check {
	switch kind {
	case "command":
		return commandCheck(base, name, attrs)
	case "file":
		return fileChecks(base, name, attrs)
	case "package":
		return packageChecks(base, b, name, attrs)
	case "service":
		return serviceChecks(base, name, attrs)
	case "mount":
		return mountChecks(base, name, attrs)
	case "kernel-param":
		return kernelParamCheck(base, name, attrs)
	case "user", "group":
		return accountCheck(base, kind, name, attrs)
	}
	return nil
}

func commandCheck(c check, name string, attrs map[string]any) []check {
	exec := strings.TrimSpace(str(attrs["exec"]))
	if exec == "" {
		return nil
	}
	for _, f := range commandFixes {
		if f.match(name, exec) {
			c.Run = f.run
			c.Name = f.name
			c.Expect = f.expect
			c.AllowAnyRC = false
			return []check{c}
		}
	}
	c.Run = exec
	c.Name = fmt.Sprintf("%s: %s", humanize(name), firstLine(exec, 90))
	codes := exitCodes(attrs["exit-status"])
	patterns := patternConditions(attrs["stdout"])
	patterns = append(patterns, stderrConditions(attrs["stderr"])...)
	if len(patterns) == 0 {
		c.Expect = []string{rcCondition(codes)}
		return []check{c}
	}
	c.AllowAnyRC = true
	c.Expect = append([]string{rcCondition(codes)}, patterns...)
	return []check{c}
}

func fileChecks(base check, name string, attrs map[string]any) []check {
	path := str(attrs["path"])
	if path == "" {
		path = name
	}
	var out []check
	var lines []string
	var parts []string
	q := shellQuote(path)

	exists, hasExists := attrs["exists"].(bool)
	if hasExists && !exists {
		c := base
		c.ID += "-absent"
		c.Name = path + " does not exist"
		c.Run = fmt.Sprintf("test -e %s || test -L %s", q, q)
		c.Expect = []string{"false"}
		return []check{c}
	}
	lines = append(lines, fmt.Sprintf("f=%s", q))
	lines = append(lines, `if [ ! -e "$f" ] && [ ! -L "$f" ]; then echo "$f does not exist"; exit 0; fi`)
	if hasExists {
		parts = append(parts, "exists")
	}
	switch str(attrs["filetype"]) {
	case "symlink":
		lines = append(lines, `[ -L "$f" ] || echo "$f is not a symbolic link"`)
		parts = append(parts, "is a symbolic link")
	case "directory":
		lines = append(lines, `[ -d "$f" ] || echo "$f is not a directory"`)
		parts = append(parts, "is a directory")
	case "file":
		lines = append(lines, `[ -f "$f" ] || echo "$f is not a regular file"`)
		parts = append(parts, "is a regular file")
	}
	if target := str(attrs["linked-to"]); target != "" {
		lines = append(lines, fmt.Sprintf(`[ "$(readlink "$f")" = %s ] || echo "$f links to $(readlink "$f")"`, shellQuote(target)))
		parts = append(parts, "links to "+target)
	}
	if modes := stringList(attrs["mode"]); len(modes) > 0 {
		var allowed int64
		for _, m := range modes {
			v, err := strconv.ParseInt(m, 8, 32)
			if err == nil {
				allowed |= v
			}
		}
		mask := ^allowed & 0o7777
		lines = append(lines, fmt.Sprintf(`if [ -n "$(find -H "$f" -maxdepth 0 -perm /%04o)" ]; then echo "$f has mode $(stat -L -c %%a "$f")"; fi`, mask))
		parts = append(parts, fmt.Sprintf("mode %04o or stricter", allowed))
	}
	if owners := stringList(attrs["owner"]); len(owners) > 0 {
		lines = append(lines, fmt.Sprintf(`case "$(stat -L -c %%U "$f")" in %s) ;; *) echo "$f is owned by $(stat -L -c %%U "$f")" ;; esac`, strings.Join(quoteAll(owners), "|")))
		parts = append(parts, "owner "+strings.Join(owners, " or "))
	}
	if groups := stringList(attrs["group"]); len(groups) > 0 {
		lines = append(lines, fmt.Sprintf(`case "$(stat -L -c %%G "$f")" in %s) ;; *) echo "$f has group $(stat -L -c %%G "$f")" ;; esac`, strings.Join(quoteAll(groups), "|")))
		parts = append(parts, "group "+strings.Join(groups, " or "))
	}
	if len(parts) > 0 {
		c := base
		c.ID += "-attrs"
		c.Name = path + ": " + strings.Join(parts, ", ")
		c.Run = strings.Join(lines, "\n")
		c.Expect = []string{"empty"}
		out = append(out, c)
	}

	contents := attrs["contents"]
	if contents == nil {
		contents = attrs["contains"]
	}
	if conds := patternConditions(contents); len(conds) > 0 {
		c := base
		c.ID += "-content"
		c.Name = fmt.Sprintf("%s has the expected content (%d rule%s)", path, len(conds), plural(len(conds)))
		c.Run = fmt.Sprintf("cat %s", q)
		// sshd reads drop-in files, which hold the effective settings on
		// current distributions (Include /etc/ssh/sshd_config.d/*.conf).
		if path == "/etc/ssh/sshd_config" {
			c.Run = "cat /etc/ssh/sshd_config.d/*.conf /etc/ssh/sshd_config 2>/dev/null"
		}
		c.AllowAnyRC = true
		c.Expect = conds
		out = append(out, c)
	}
	return out
}

func packageChecks(c check, b benchmark, name string, attrs map[string]any) []check {
	pkg := str(attrs["name"])
	if pkg == "" {
		pkg = name
	}
	installed, ok := attrs["installed"].(bool)
	if !ok {
		installed = true
	}
	query := fmt.Sprintf("rpm -q --quiet %s", pkg)
	if b.Package == "dpkg" {
		query = fmt.Sprintf("dpkg-query -W -f='${Status}' %s 2>/dev/null | grep -q 'install ok installed'", pkg)
	}
	c.Run = query
	if installed {
		c.Name = "Package " + pkg + " is installed"
		c.Expect = []string{"true"}
	} else {
		c.Name = "Package " + pkg + " is not installed"
		c.Expect = []string{"false"}
	}
	out := []check{c}
	if v, ok := attrs["versions"].(map[string]any); ok && installed {
		if constraint := str(v["semver-constraint"]); constraint != "" {
			op, ver := splitConstraint(constraint)
			vc := c
			vc.ID += "-version"
			vc.Name = fmt.Sprintf("Package %s version %s %s", pkg, op, ver)
			if b.Package == "dpkg" {
				vc.Run = fmt.Sprintf("dpkg-query -W -f='${Version}' %s", pkg)
			} else {
				vc.Run = fmt.Sprintf("rpm -q --qf '%%{VERSION}-%%{RELEASE}' %s", pkg)
			}
			vc.As = "version"
			vc.AllowAnyRC = true
			vc.Expect = []string{`{ rc: "== 0" }`, yamlString(op + " " + ver)}
			out = append(out, vc)
		}
	}
	return out
}

func serviceChecks(base check, name string, attrs map[string]any) []check {
	if n := str(attrs["name"]); n != "" {
		name = n // the resource key is only a label when name is set
	}
	var out []check
	if v, ok := attrs["enabled"].(bool); ok {
		c := base
		c.ID += "-enabled"
		c.Run = fmt.Sprintf("systemctl show -p UnitFileState %s | cut -d= -f2", name)
		if v {
			c.Name = "Service " + name + " is enabled"
			c.Expect = []string{yamlString("~ ^enabled")}
		} else {
			c.Name = "Service " + name + " is not enabled"
			c.Expect = []string{yamlString("!~ ^enabled")}
		}
		out = append(out, c)
	}
	if v, ok := attrs["running"].(bool); ok {
		c := base
		c.ID += "-running"
		c.Run = fmt.Sprintf("systemctl show -p ActiveState %s | cut -d= -f2", name)
		if v {
			c.Name = "Service " + name + " is running"
			c.Expect = []string{yamlString("== active")}
		} else {
			c.Name = "Service " + name + " is not running"
			c.Expect = []string{yamlString("!= active")}
		}
		out = append(out, c)
	}
	return out
}

func mountChecks(c check, name string, attrs map[string]any) []check {
	mp := str(attrs["mountpoint"])
	if mp == "" {
		mp = name
	}
	if exists, ok := attrs["exists"].(bool); ok && !exists {
		c.Name = mp + " is not a separate mount"
		c.Run = "findmnt -n " + shellQuote(mp)
		c.Expect = []string{"false"}
		return []check{c}
	}
	opts := stringList(attrs["opts"])
	fs := stringList(attrs["filesystem"])
	if _, conditional := attrs["skip"]; len(opts) > 0 && conditional {
		// Option rules apply only if the mount point is a separate mount;
		// whether it must be one is a rule of its own.
		c.OnlyIf = "findmnt -n " + shellQuote(mp)
	}
	c.Run = "findmnt -n -o FSTYPE,OPTIONS " + shellQuote(mp)
	c.AllowAnyRC = true
	c.Expect = []string{`{ rc: "== 0" }`}
	desc := mp + " is a separate mount"
	for _, o := range opts {
		c.Expect = append(c.Expect, yamlString("~ [ ,]"+regexp.QuoteMeta(o)+"(,|$)"))
	}
	if len(opts) > 0 {
		desc += " with " + strings.Join(opts, ", ")
	}
	if len(fs) > 0 {
		c.Expect = append(c.Expect, yamlString("~ ^("+strings.Join(fs, "|")+") "))
	}
	c.Name = desc
	return []check{c}
}

func kernelParamCheck(c check, name string, attrs map[string]any) []check {
	if n := str(attrs["name"]); n != "" {
		name = n
	}
	value := str(attrs["value"])
	if value == "" {
		return nil
	}
	c.Name = fmt.Sprintf("Kernel parameter %s is %s", name, value)
	c.Run = "sysctl -n " + name
	c.AllowAnyRC = true
	c.Expect = []string{`{ rc: "== 0" }`, yamlString("== " + value)}
	return []check{c}
}

func accountCheck(c check, kind, name string, attrs map[string]any) []check {
	if n := str(attrs["name"]); n != "" {
		name = n
	}
	db := "passwd"
	if kind == "group" {
		db = "group"
	}
	exists, ok := attrs["exists"].(bool)
	if !ok {
		exists = true
	}
	c.Run = fmt.Sprintf("getent %s %s", db, name)
	if exists {
		c.Name = fmt.Sprintf("%s %s exists", strings.Title(kind), name)
		c.Expect = []string{"true"}
	} else {
		c.Name = fmt.Sprintf("%s %s does not exist", strings.Title(kind), name)
		c.Expect = []string{"false"}
	}
	return []check{c}
}

// patternConditions translates goss matchers (have-patterns semantics) into
// per-line expectations.
func patternConditions(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		var out []string
		for _, p := range x {
			if s := patternCondition(fmt.Sprint(p)); s != "" {
				out = append(out, s)
			}
		}
		return out
	case map[string]any:
		if alt, ok := x["or"].([]any); ok {
			var inner []string
			for _, p := range alt {
				if s := patternCondition(fmt.Sprint(p)); s != "" {
					inner = append(inner, s)
				}
			}
			if len(inner) > 0 {
				return []string{"{ any: [" + strings.Join(inner, ", ") + "] }"}
			}
		}
		for _, k := range []string{"contains", "contain-element", "have-patterns"} {
			if list, ok := x[k]; ok {
				return patternConditions(list)
			}
		}
		if re, ok := x["match-regexp"]; ok {
			return patternConditions([]any{re})
		}
		if n, ok := x["not"]; ok {
			inner := patternConditions(n)
			if len(inner) > 0 {
				return []string{"{ not: { all: [" + strings.Join(inner, ", ") + "] } }"}
			}
		}
	case string:
		if s := patternCondition(x); s != "" {
			return []string{s}
		}
	}
	return nil
}

func patternCondition(p string) string {
	if p == "" {
		return ""
	}
	neg := false
	if strings.HasPrefix(p, "!") {
		neg = true
		p = p[1:]
	}
	var re string
	if len(p) >= 2 && strings.HasPrefix(p, "/") && strings.HasSuffix(p, "/") {
		re = p[1 : len(p)-1]
	} else {
		re = regexp.QuoteMeta(p)
	}
	// A disabled module may point to /bin/true or /bin/false; both are fine.
	re = strings.ReplaceAll(re, "install /bin/true", "install /(usr/)?bin/(true|false)")
	if _, err := regexp.Compile(re); err != nil {
		return ""
	}
	key := "some"
	if neg {
		key = "none"
	}
	return fmt.Sprintf("{ %s: %s }", key, yamlString("~ "+re))
}

func stderrConditions(v any) []string {
	var out []string
	for _, p := range stringList(v) {
		op := "~"
		if strings.HasPrefix(p, "!") {
			op, p = "!~", p[1:]
		}
		re := regexp.QuoteMeta(p)
		if len(p) >= 2 && strings.HasPrefix(p, "/") && strings.HasSuffix(p, "/") {
			re = p[1 : len(p)-1]
		}
		out = append(out, fmt.Sprintf("{ stderr: %s }", yamlString(op+" "+re)))
	}
	return out
}

func exitCodes(v any) []int {
	switch x := v.(type) {
	case nil:
		return []int{0}
	case int:
		return []int{x}
	case map[string]any:
		var out []int
		for _, c := range anyList(x["or"]) {
			if n, err := strconv.Atoi(fmt.Sprint(c)); err == nil {
				out = append(out, n)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	if n, err := strconv.Atoi(fmt.Sprint(v)); err == nil {
		return []int{n}
	}
	return []int{0}
}

func rcCondition(codes []int) string {
	if len(codes) == 1 {
		return fmt.Sprintf(`{ rc: "== %d" }`, codes[0])
	}
	parts := make([]string, len(codes))
	for i, c := range codes {
		parts[i] = strconv.Itoa(c)
	}
	return fmt.Sprintf(`{ rc: "in [%s]" }`, strings.Join(parts, ", "))
}

func parseMeta(v any) ruleMeta {
	m := ruleMeta{}
	meta, _ := v.(map[string]any)
	if meta == nil {
		return m
	}
	if ids := stringList(meta["CIS_ID"]); len(ids) > 0 {
		m.CISID = ids[0]
	}
	if ids := stringList(meta["STIG_ID"]); len(ids) > 0 && strings.TrimSpace(ids[0]) != "" {
		m.CISID = strings.TrimSpace(ids[0])
	}
	m.Cat = intValue(meta["Cat"])
	if v := meta["Vul_ID"]; v != nil {
		m.VulID = fmt.Sprint(v)
	}
	if v := meta["Rule_ID"]; v != nil {
		m.RuleID = fmt.Sprint(v)
	}
	m.CCI = stringList(meta["CCI"])
	m.NISTR4 = stringList(meta["NIST800-53R4"])
	m.Server = intValue(meta["server"])
	m.Workstation = intValue(meta["workstation"])
	m.NIST = stringList(meta["NIST800-53R5"])
	m.Controls = stringList(meta["CISv8"])
	return m
}

func tags(b benchmark, m ruleMeta) []string {
	if b.stig() {
		t := []string{"stig", "stig-" + b.platform()}
		if m.Cat >= 1 && m.Cat <= 3 {
			t = append(t, fmt.Sprintf("stig-cat-%d", m.Cat))
		}
		return t
	}
	t := []string{"cis", "cis-" + b.Key}
	if section := strings.SplitN(m.CISID, ".", 2)[0]; section != "" {
		t = append(t, "cis-section-"+section)
	}
	level := m.Server
	if level == 0 || (m.Workstation != 0 && m.Workstation < level) {
		level = m.Workstation
	}
	if level == 1 {
		t = append(t, "cis-level-1")
	}
	if level == 1 || level == 2 {
		t = append(t, "cis-level-2")
	}
	if m.Server != 0 {
		t = append(t, "cis-server")
		if m.Server == 1 {
			t = append(t, "cis-level1-server")
		}
		t = append(t, "cis-level2-server")
	}
	if m.Workstation != 0 {
		t = append(t, "cis-workstation")
		if m.Workstation == 1 {
			t = append(t, "cis-level1-workstation")
		}
		t = append(t, "cis-level2-workstation")
	}
	return t
}

func severity(m ruleMeta) string {
	switch m.Cat {
	case 1:
		return "high"
	case 2:
		return "medium"
	case 3:
		return "low"
	}
	if m.Server == 1 || m.Workstation == 1 {
		return "medium"
	}
	return "low"
}

func description(b benchmark, m ruleMeta) string {
	if b.stig() {
		ids := []string{m.CISID}
		if m.VulID != "" {
			ids = append(ids, m.VulID)
		}
		if m.RuleID != "" {
			ids = append(ids, m.RuleID)
		}
		parts := []string{fmt.Sprintf("DISA STIG for %s, %s", b.Name, strings.Join(ids, ", "))}
		if m.Cat > 0 {
			parts[0] += fmt.Sprintf(", CAT %s", strings.Repeat("I", m.Cat))
		}
		if len(m.CCI) > 0 {
			parts = append(parts, strings.Join(m.CCI, ", "))
		}
		if len(m.NISTR4) > 0 {
			parts = append(parts, "NIST SP 800-53 Rev. 4: "+strings.Join(m.NISTR4, ", "))
		}
		return strings.Join(parts, ". ") + "."
	}
	parts := []string{fmt.Sprintf("CIS %s benchmark recommendation %s", b.Name, m.CISID)}
	if len(m.NIST) > 0 {
		parts = append(parts, "NIST SP 800-53 Rev. 5: "+strings.Join(m.NIST, ", "))
	}
	if len(m.Controls) > 0 {
		parts = append(parts, "CIS Controls v8: "+strings.Join(m.Controls, ", "))
	}
	return strings.Join(parts, ". ") + "."
}

// patch fixes a known problem in the upstream content.
type patch struct {
	why      string
	old, new string
}

// patches are applied to every generated expectation. Keep this list short
// and report the problems upstream.
var patches = []patch{
	{"MaxSessions 10 is allowed; only values above 10 fail", "MaxSessions (1|1[1-9]|", "MaxSessions (1[1-9]|"},
	{`APT accepts "false" as well as "0"`, `APT::Install-Recommends \"0\";`, `APT::Install-Recommends \"(0|false)\";`},
	{`APT accepts "false" as well as "0"`, `APT::Install-Suggests \"0\";`, `APT::Install-Suggests \"(0|false)\";`},
}

// commandFix replaces an upstream command that gives wrong results.
type commandFix struct {
	why    string
	match  func(name, exec string) bool
	name   string
	run    string
	expect []string
}

var commandFixes = []commandFix{
	{
		why: "broken quoting made awk fail with exit code 1, which upstream accepts as a pass",
		match: func(name, exec string) bool {
			return strings.Contains(name, "minpasswd") && strings.Contains(exec, "print $1 ' ' $4")
		},
		name:   "Accounts with a password have a minimum password lifetime of at least one day",
		run:    `awk -F: '$2 ~ /^\$/ && $4 < 1 {print $1 " " $4}' /etc/shadow`,
		expect: []string{"empty"},
	},
	{
		why: "upstream runs the /etc/shadow command of another rule instead of looking for NOPASSWD",
		match: func(name, exec string) bool {
			return strings.Contains(name, "sudoers_nopasswd") && strings.Contains(exec, "/etc/shadow")
		},
		name:   "sudo requires a password: no NOPASSWD rules",
		run:    `grep -rhiE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null || true`,
		expect: []string{"empty"},
	},
	{
		why: "stat fails without interactive users, and comparing modes as decimal numbers misses e.g. 705",
		match: func(name, exec string) bool {
			return strings.Contains(exec, `stat -c "%a %n" $(awk -F: '($3>=1000)`)
		},
		name: "Home directories of interactive users have mode 0750 or stricter",
		run: `awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd | while read -r d; do
  if [ -d "$d" ]; then find "$d" -maxdepth 0 -perm /027 -printf '%m %p\n'; fi
done`,
		expect: []string{"empty"},
	},
	{
		why: "upstream variants compare dates as strings, or turn 'never' into an error that passes",
		match: func(name, exec string) bool {
			return strings.Contains(name, "passwd_chg_past") && strings.Contains(exec, "chage")
		},
		name: "No user has a last password change date in the future",
		run: `now=$(date +%s)
for usr in $(cut -d: -f1 /etc/shadow); do
  d=$(chage --list "$usr" 2>/dev/null | awk -F': ' '/^Last password change/ {print $2}')
  case "$d" in ""|never|*"must be changed"*) continue ;; esac
  t=$(date -d "$d" +%s 2>/dev/null) || { echo "$usr: cannot parse last password change '$d'"; continue; }
  if [ "$t" -gt "$now" ]; then echo "$usr: last password change $d is in the future"; fi
done`,
		expect: []string{"empty"},
	},
	{
		why: "stat fails without an operand when no banner is configured",
		match: func(name, exec string) bool {
			return strings.Contains(exec, "stat -Lc '%a %U %G' $(sshd -T")
		},
		name: "The SSH banner file is owned by root and not writable by others",
		run: `b=$(sshd -T 2>/dev/null | awk 'tolower($1)=="banner" {print $2}')
if [ -z "$b" ] || [ "$b" = none ]; then echo "no banner configured"; exit 0; fi
stat -Lc '%a %U %G' "$b"`,
		expect: []string{`{ any: [ { some: "~ ^no banner configured$" }, { some: "~ ^[0-6][04][04] root root$" } ] }`},
	},
}

func applyPatches(s string) string {
	for _, p := range patches {
		s = strings.ReplaceAll(s, p.old, p.new)
	}
	return s
}

func writePolicy(path string, b benchmark, version string, checks []check, rules int) error {
	var w bytes.Buffer
	fmt.Fprintf(&w, "# Generated by tools/cis-import from ansible-lockdown/%s (MIT license).\n", b.Repo)
	if b.stig() {
		fmt.Fprintf(&w, "# Do not edit by hand; regenerate with `make stig-import`. See stig/NOTICE.\n")
		fmt.Fprintf(&w, "name: DISA STIG %s\n", b.Name)
		fmt.Fprintf(&w, "version: %s\n", yamlString(version))
		fmt.Fprintf(&w, "description: >\n")
		fmt.Fprintf(&w, "  Automated checks for %d rules of the DISA Security Technical\n", rules)
		fmt.Fprintf(&w, "  Implementation Guide for %s (version %s), converted from the goss\n", b.Name, version)
		fmt.Fprintf(&w, "  audit content of the ansible-lockdown project. Severity follows the STIG\n")
		fmt.Fprintf(&w, "  category: CAT I high, CAT II medium, CAT III low. Select categories with\n")
		fmt.Fprintf(&w, "  tags, e.g. `--tags stig-cat-1`.\n\n")
		return writeChecks(&w, path, b, checks)
	}
	fmt.Fprintf(&w, "# Do not edit by hand; regenerate with `make cis-import`. See cis/NOTICE.\n")
	fmt.Fprintf(&w, "name: CIS %s\n", b.Name)
	fmt.Fprintf(&w, "version: %s\n", yamlString(version))
	fmt.Fprintf(&w, "description: >\n")
	fmt.Fprintf(&w, "  Automated checks for %d recommendations of the CIS %s benchmark\n", rules, b.Name)
	fmt.Fprintf(&w, "  (version %s), converted from the goss audit content of the\n", version)
	fmt.Fprintf(&w, "  ansible-lockdown project. Check names describe what is verified; the\n")
	fmt.Fprintf(&w, "  recommendation number is in the ID and the description. Select profiles\n")
	fmt.Fprintf(&w, "  with tags, e.g. `--tags cis-level-1+cis-server`.\n\n")
	return writeChecks(&w, path, b, checks)
}

func writeChecks(w *bytes.Buffer, path string, b benchmark, checks []check) error {
	fmt.Fprintf(w, "defaults:\n  when: %s\n  timeout: 120s\n\nchecks:\n", yamlString(b.When))
	for _, c := range checks {
		fmt.Fprintf(w, "  - id: %s\n", yamlString(c.ID))
		fmt.Fprintf(w, "    name: %s\n", yamlString(c.Name))
		fmt.Fprintf(w, "    description: %s\n", yamlString(c.Description))
		fmt.Fprintf(w, "    tags: [%s]\n", strings.Join(c.Tags, ", "))
		fmt.Fprintf(w, "    severity: %s\n", c.Severity)
		if c.Timeout != "" {
			fmt.Fprintf(w, "    timeout: %s\n", c.Timeout)
		}
		if c.OnlyIf != "" {
			fmt.Fprintf(w, "    only_if: %s\n", yamlString(c.OnlyIf))
		}
		w.WriteString("    run: |\n")
		for _, line := range strings.Split(protectTemplates(c.Run), "\n") {
			w.WriteString("      " + line + "\n")
		}
		if c.AllowAnyRC {
			w.WriteString("    allow_rc: any\n")
		}
		if c.As != "" {
			fmt.Fprintf(w, "    as: %s\n", c.As)
		}
		switch len(c.Expect) {
		case 1:
			fmt.Fprintf(w, "    expect: %s\n", protectTemplates(applyPatches(c.Expect[0])))
		default:
			w.WriteString("    expect:\n")
			for _, e := range c.Expect {
				fmt.Fprintf(w, "      - %s\n", protectTemplates(applyPatches(e)))
			}
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, w.Bytes(), 0o644)
}

// protectTemplates keeps Jinja2 from interpreting {{ and {% in commands.
func protectTemplates(s string) string {
	if strings.Contains(s, "{{") || strings.Contains(s, "{%") {
		return "{% raw %}" + s + "{% endraw %}"
	}
	return s
}

// shellSyntax checks a command with `bash -n`.
func shellSyntax(cmd string) error {
	out, err := exec.Command("bash", "-n", "-c", cmd).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if i := strings.LastIndex(msg, "\n"); i >= 0 {
			msg = msg[i+1:]
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// --- helpers ------------------------------------------------------------------

func yamlString(s string) string {
	data, _ := json.Marshal(s)
	return string(data)
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func quoteAll(list []string) []string {
	out := make([]string, len(list))
	for i, s := range list {
		out[i] = shellQuote(s)
	}
	return out
}

func str(v any) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(v))
}

func anyList(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}

func stringList(v any) []string {
	switch x := v.(type) {
	case nil:
		return nil
	case []any:
		var out []string
		for _, e := range x {
			out = append(out, fmt.Sprint(e))
		}
		return out
	case map[string]any:
		return stringList(x["or"])
	}
	return []string{fmt.Sprint(v)}
}

func intValue(v any) int {
	n, _ := strconv.Atoi(fmt.Sprint(v))
	return n
}

func truthy(v any) bool {
	b, ok := v.(bool)
	return ok && b
}

var unsafeID = regexp.MustCompile(`[^A-Za-z0-9_.-]+`)

func sanitize(s string) string {
	s = strings.Trim(unsafeID.ReplaceAllString(s, "_"), "_")
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

func uniqueID(seen map[string]int, id string) string {
	seen[id]++
	if seen[id] == 1 {
		return id
	}
	return fmt.Sprintf("%s-%d", id, seen[id])
}

func humanize(s string) string {
	s = strings.NewReplacer("_", " ", "-", " ").Replace(s)
	return strings.Join(strings.Fields(s), " ")
}

func firstLine(s string, n int) string {
	line := strings.TrimSpace(strings.SplitN(s, "\n", 2)[0])
	if len([]rune(line)) > n {
		return string([]rune(line)[:n-1]) + "…"
	}
	return line
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func splitConstraint(c string) (string, string) {
	c = strings.TrimSpace(c)
	for _, op := range []string{">=", "<=", "==", "!=", ">", "<", "="} {
		if strings.HasPrefix(c, op) {
			if op == "=" {
				op = "=="
			}
			return op, strings.TrimSpace(c[len(op):])
		}
	}
	return ">=", c
}

var cisIDRe = regexp.MustCompile(`cis_([0-9.]+[0-9])\.yml$`)

func cisIDFromPath(p string) string {
	if m := cisIDRe.FindStringSubmatch(p); m != nil {
		return m[1]
	}
	return strings.TrimSuffix(filepath.Base(p), ".yml")
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// naturalLess orders cis_1.1.2.10 after cis_1.1.2.9.
func naturalLess(a, b string) bool {
	ra, rb := regexp.MustCompile(`\d+|\D+`).FindAllString(a, -1), regexp.MustCompile(`\d+|\D+`).FindAllString(b, -1)
	for i := 0; i < len(ra) && i < len(rb); i++ {
		if ra[i] == rb[i] {
			continue
		}
		na, ea := strconv.Atoi(ra[i])
		nb, eb := strconv.Atoi(rb[i])
		if ea == nil && eb == nil {
			return na < nb
		}
		return ra[i] < rb[i]
	}
	return len(ra) < len(rb)
}

// stigTitle splits a goss title "RHEL-09-212015 | Text | qualifier".
func stigTitle(t string) (title, qualifier string) {
	parts := strings.Split(t, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	switch {
	case len(parts) >= 3:
		return parts[1], strings.Join(parts[2:], " ")
	case len(parts) == 2:
		return parts[1], ""
	}
	return "", ""
}

var discoveredRe = regexp.MustCompile(`\.Discovered\.([A-Za-z0-9_]+)`)

var catRe = regexp.MustCompile(`(?i)/cat_([123])/`)

func catFromPath(p string) int {
	if m := catRe.FindStringSubmatch(p); m != nil {
		n, _ := strconv.Atoi(m[1])
		return n
	}
	return 0
}
