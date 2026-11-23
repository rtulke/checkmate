// Command gendocs generates the example pages of the documentation site
// from the policies in examples/ and updates the examples navigation in
// mkdocs.yml. Run it from the repository root:
//
//	go run ./tools/gendocs
package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/rtulke/checkmate/internal/facts"
	"github.com/rtulke/checkmate/internal/policy"

	"gopkg.in/yaml.v3"
)

// docFacts is a neutral host used to render names in the check tables.
var docFacts = facts.Facts{OS: "linux", Distro: "linux", Version: "1", VersionMajor: 1, IsRoot: true}

const (
	examplesDir = "examples"
	docsDir     = "docs/examples"
	mkdocsFile  = "mkdocs.yml"
	repoURL     = "https://github.com/rtulke/checkmate"
	navBegin    = "  # BEGIN generated examples navigation"
	navEnd      = "  # END generated examples navigation"
)

// category describes one directory of examples.
type category struct {
	Dir         string
	Title       string
	Description string
}

// categories in navigation order. Unknown directories are appended.
var categories = []category{
	{"platforms", "Platforms", "Operating-system specific baselines: generic Linux, the RHEL, Debian and SUSE families, macOS and Windows."},
	{"system", "System", "Users, sudo, SSH, PAM, services, kernel, boot, time, logging, packages, cron and mandatory access control."},
	{"files", "Files", "Permissions, content, integrity, file-system searches, mounts and disk space."},
	{"network", "Network", "Interfaces and routing, listening ports, host firewalls, DNS and TLS."},
	{"hardware", "Hardware", "CPU and memory, disks and RAID, virtualization and IPMI sensors."},
	{"network-devices", "Network devices", "Switches, routers and firewalls over SSH, eAPI and SNMP: Cisco, Juniper, Arista and any SNMP device."},
	{"remote", "Remote hosts", "Checking servers from a management host over SSH without installing anything."},
	{"applications", "Applications", "Docker, Kubernetes, nginx, Apache, PHP and web content, PostgreSQL, MySQL, MongoDB, Redis and web endpoints."},
	{"cloud", "Cloud", "Cloud instances on AWS, Azure and Google Cloud: metadata service, agents and stored credentials."},
	{"services", "Linux services", "Common Linux network services: Postfix, NFS, FTP (vsftpd, ProFTPD), BIND, DHCP (Kea, ISC dhcpd), Dovecot, Samba and OpenLDAP. Checks of a service are skipped when it is not installed."},
	{"validation", "Server validation", "Describe the expected state of a server role and validate it, in the style of goss and serverspec."},
	{"compliance", "Compliance baselines", "Complete baselines: BSI IT-Grundschutz, Si001 of the Swiss Federal Administration, a broad Linux hardening baseline modelled on OpenSCAP and CIS, and a managed-RHEL baseline."},
	{"attack", "MITRE ATT&CK", "Traces and mitigations of MITRE ATT&CK techniques, tagged with technique and tactic IDs. `--export attack` turns the results into an ATT&CK Navigator layer."},
}

type policyDoc struct {
	Name        string      `yaml:"name"`
	Version     string      `yaml:"version"`
	Description string      `yaml:"description"`
	Checks      []checkDoc  `yaml:"checks"`
	Snippets    yaml.Node   `yaml:"snippets"`
	Vars        yaml.Node   `yaml:"vars"`
	VarsFiles   []string    `yaml:"vars_files"`
	Include     []string    `yaml:"include"`
	Defaults    interface{} `yaml:"defaults"`
}

type checkDoc struct {
	ID       string    `yaml:"id"`
	Name     string    `yaml:"name"`
	Severity string    `yaml:"severity"`
	Tags     []string  `yaml:"tags"`
	Loop     yaml.Node `yaml:"loop"`
	Run      yaml.Node `yaml:"run"`
	When     yaml.Node `yaml:"when"`
}

type page struct {
	Category string
	Source   string // e.g. examples/system/ssh.yml
	Target   string // e.g. docs/examples/system/ssh.md
	Doc      policyDoc
	Raw      string
	Checks   []*policy.Check // expanded checks, loops resolved
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gendocs:", err)
		os.Exit(1)
	}
}

func run() error {
	pages, err := collect()
	if err != nil {
		return err
	}
	if err := os.RemoveAll(docsDir); err != nil {
		return err
	}
	byCategory := map[string][]page{}
	for _, p := range pages {
		byCategory[p.Category] = append(byCategory[p.Category], p)
		if err := writePage(p); err != nil {
			return err
		}
	}
	cats := orderedCategories(byCategory)
	for _, c := range cats {
		if c.Dir == "" {
			continue
		}
		if err := writeCategoryIndex(c, byCategory[c.Dir]); err != nil {
			return err
		}
	}
	if err := writeExamplesIndex(cats, byCategory); err != nil {
		return err
	}
	cisPages, err := writeCISPages()
	if err != nil {
		return err
	}
	stigPages, err := writeSTIGPages()
	if err != nil {
		return err
	}
	return updateNav(cats, byCategory, cisPages, stigPages)
}

// cisPage is a generated page for one CIS benchmark policy.
type cisPage struct {
	Key, Title, Target string
	Rules, Checks      int
	Levels             map[string]int
}

// writeCISPages documents the generated CIS policies in cis/.
func writeCISPages() ([]cisPage, error) {
	files, _ := filepath.Glob("cis/*.yml")
	sort.Slice(files, func(i, j int) bool { return naturalLess(files[i], files[j]) })
	dir := "docs/cis"
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var pages []cisPage
	for _, f := range files {
		p, err := policy.Load(f, policy.LoadOptions{AllowInsecure: true})
		if err != nil {
			return nil, err
		}
		checks, errs := policy.Expand(p, docFacts, nil)
		if len(errs) > 0 {
			return nil, errs[0]
		}
		key := strings.TrimSuffix(filepath.Base(f), ".yml")
		cp := cisPage{Key: key, Title: p.Name, Target: filepath.Join(dir, key+".md"), Checks: len(checks), Levels: map[string]int{}}
		rules := map[string]map[string]bool{}
		var b bytes.Buffer
		fmt.Fprintf(&b, "# %s\n\n%s\n\n", p.Name, strings.TrimSpace(p.Description))
		fmt.Fprintf(&b, "**Policy:** [`%s`](%s/blob/main/%s) · **Benchmark version:** %s\n\n", f, repoURL, f, p.Version)
		if strings.HasPrefix(key, "win") {
			fmt.Fprintf(&b, "Run in an elevated PowerShell (as administrator). Every check collects its own value:\n\n")
			if key == "win11" {
				fmt.Fprintf(&b, "```powershell\ncheckmate run %s --tags cis-level1-workstation\ncheckmate run %s --tags cis-level-2 -e cis_windows_domain_joined=true\n```\n\n", f, f)
			} else {
				fmt.Fprintf(&b, "```powershell\ncheckmate run %s --tags cis-level1-member-server\ncheckmate run %s --tags cis-level1-domain-controller -e cis_windows_role=dc\ncheckmate run %s -e cis_windows_role=standalone\n```\n\n", f, f, f)
			}
		} else if key == "apache" {
			fmt.Fprintf(&b, "Runs as root and reads the configuration the way httpd sees it (`httpd -t -D DUMP_INCLUDES`, `-S`, `-M`):\n\n")
			fmt.Fprintf(&b, "```bash\nsudo checkmate run %s --tags cis-level-1\nsudo checkmate run %s --tags cis-level-2 -v\n```\n\n", f, f)
		} else if key == "postgresql" {
			fmt.Fprintf(&b, "Runs as root and queries the server as the postgres user over the local socket:\n\n")
			fmt.Fprintf(&b, "```bash\nsudo checkmate run %s\nsudo checkmate run %s --tags cis-postgresql-db -v\n```\n\n", f, f)
		} else if strings.HasPrefix(key, "macos") {
			fmt.Fprintf(&b, "The checks read system settings and configuration profiles and need root:\n\n")
			fmt.Fprintf(&b, "```bash\nsudo checkmate run %s --tags cis-level-1\nsudo checkmate run %s --tags cis-level-2 -v\n```\n\n", f, f)
		} else {
			fmt.Fprintf(&b, "```bash\ncheckmate run %s --tags cis-level1-server\ncheckmate run %s --tags cis-level-2 -v\n```\n\n", f, f)
		}
		fmt.Fprintf(&b, "| ID | Check | Profiles | Severity |\n|---|---|---|---|\n")
		for _, c := range checks {
			id := c.ID
			rule := cisRule(id, key)
			if rules[rule] == nil {
				rules[rule] = map[string]bool{}
			}
			var profiles []string
			for _, t := range c.Tags {
				switch t {
				case "cis-level1-server", "cis-level1-workstation":
					profiles = append(profiles, "L1 "+strings.TrimPrefix(t, "cis-level1-"))
					rules[rule]["l1"] = true
				case "cis-level2-server", "cis-level2-workstation":
					if !contains(c.Tags, strings.Replace(t, "level2", "level1", 1)) {
						profiles = append(profiles, "L2 "+strings.TrimPrefix(t, "cis-level2-"))
						rules[rule]["l2"] = true
					}
				}
			}
			if len(profiles) == 0 {
				// Benchmarks without server/workstation profiles (macOS).
				if contains(c.Tags, "cis-level-1") {
					profiles = append(profiles, "L1")
					rules[rule]["l1"] = true
				} else if contains(c.Tags, "cis-level-2") {
					profiles = append(profiles, "L2")
					rules[rule]["l2"] = true
				}
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", id, escapeTable(c.Name), strings.Join(profiles, ", "), severityBadge(c.Severity))
		}
		cp.Rules = len(rules)
		for _, r := range rules {
			if r["l1"] {
				cp.Levels["l1"]++
			} else if r["l2"] {
				cp.Levels["l2"]++
			}
		}
		if err := os.WriteFile(cp.Target, b.Bytes(), 0o644); err != nil {
			return nil, err
		}
		pages = append(pages, cp)
	}

	var idx bytes.Buffer
	idx.WriteString("# CIS benchmarks\n\n")
	idx.WriteString("Automated checks for the CIS benchmarks of 17 Linux platforms, Windows 11 and Windows Server 2019/2022/2025, macOS, PostgreSQL and Apache httpd. The Linux policies are generated\n")
	idx.WriteString("from the goss audit content of [Ansible Lockdown](https://github.com/ansible-lockdown) (MIT license), the macOS\n")
	idx.WriteString("policies from the [macOS Security Compliance Project](https://github.com/usnistgov/macos_security) (CC BY 4.0).\n")
	idx.WriteString("The recommendation number is part of the ID. The policies contain no benchmark text.\n\n")
	idx.WriteString("| Benchmark | Recommendations | Level 1 | Level 2 only | Checks |\n|---|---|---|---|---|\n")
	tr, tc := 0, 0
	for _, p := range pages {
		fmt.Fprintf(&idx, "| [%s](%s.md) | %d | %d | %d | %d |\n", p.Title, p.Key, p.Rules, p.Levels["l1"], p.Levels["l2"], p.Checks)
		tr += p.Rules
		tc += p.Checks
	}
	fmt.Fprintf(&idx, "| **Total** | **%d** | | | **%d** |\n\n", tr, tc)
	idx.WriteString("## Selecting profiles\n\n")
	idx.WriteString("| Tag | Selects |\n|---|---|\n")
	idx.WriteString("| `cis-level1-server`, `cis-level2-server`, `cis-level1-workstation`, `cis-level2-workstation` | one of the four CIS profiles |\n")
	idx.WriteString("| `cis-level-1`, `cis-level-2` | a level (Level 2 includes Level 1) |\n")
	idx.WriteString("| `cis-server`, `cis-workstation` | recommendations of a profile type |\n")
	idx.WriteString("| `cis-section-1` … | one chapter |\n")
	idx.WriteString("| `cis-rhel9`, `cis-debian12`, `cis-macos15`, … | one benchmark |\n")
	idx.WriteString("| `nist-800-53r5-moderate`, `nist-800-171`, `disa-stig`, `cmmc-level-2`, … | macOS checks that are also part of these baselines |\n\n")
	idx.WriteString("macOS has no server/workstation split; use `cis-level-1` or `cis-level-2`. The PostgreSQL and Apache policies are written by hand;\n")
	idx.WriteString("PostgreSQL has the profiles `cis-postgresql-db` and `cis-postgresql-linux`, Apache uses `cis-level-1` and `cis-level-2`.\n\n")
	idx.WriteString("```bash\ncheckmate run cis/rhel9.yml --tags cis-level1-server\n")
	idx.WriteString("checkmate run cis/debian12.yml --tags cis-level-2+cis-server --fail-on high\n")
	idx.WriteString("checkmate run cis/ubuntu24.yml --id 'CIS-UBUNTU24-5.*' -vv\n```\n\n")
	idx.WriteString("See [cis/README.md](https://github.com/rtulke/checkmate/blob/main/cis/README.md) for how the conversion works and the\n")
	idx.WriteString("few deliberate deviations from the upstream content.\n")
	return pages, os.WriteFile(filepath.Join(dir, "index.md"), idx.Bytes(), 0o644)
}

// cisRule extracts the recommendation number from a check ID.
func cisRule(id, key string) string {
	// IDs look like CIS-<BENCHMARK>-<number>-<name>.
	parts := strings.SplitN(id, "-", 4)
	if len(parts) < 3 {
		return id
	}
	return parts[2]
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

var naturalSplit = regexp.MustCompile(`\d+|\D+`)

func naturalLess(a, b string) bool {
	ra, rb := naturalSplit.FindAllString(a, -1), naturalSplit.FindAllString(b, -1)
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

func collect() ([]page, error) {
	var pages []page
	err := filepath.WalkDir(examplesDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".yml") || strings.Contains(path, "/vars/") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var doc policyDoc
		if err := yaml.Unmarshal(raw, &doc); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		p, err := policy.Load(path, policy.LoadOptions{AllowInsecure: true})
		if err != nil {
			return err
		}
		checks, errs := policy.Expand(p, docFacts, nil)
		if len(errs) > 0 {
			return errs[0]
		}
		rel := strings.TrimPrefix(path, examplesDir+"/")
		cat := ""
		if i := strings.IndexByte(rel, '/'); i >= 0 {
			cat = rel[:i]
		}
		pages = append(pages, page{
			Category: cat,
			Source:   path,
			Target:   filepath.Join(docsDir, strings.TrimSuffix(rel, ".yml")+".md"),
			Doc:      doc,
			Raw:      string(raw),
			Checks:   checks,
		})
		return nil
	})
	sort.Slice(pages, func(i, j int) bool { return pages[i].Source < pages[j].Source })
	return pages, err
}

func orderedCategories(byCategory map[string][]page) []category {
	var out []category
	seen := map[string]bool{}
	if _, ok := byCategory[""]; ok {
		out = append(out, category{Dir: "", Title: "Getting started"})
		seen[""] = true
	}
	for _, c := range categories {
		if _, ok := byCategory[c.Dir]; ok {
			out = append(out, c)
			seen[c.Dir] = true
		}
	}
	var extra []string
	for dir := range byCategory {
		if !seen[dir] {
			extra = append(extra, dir)
		}
	}
	sort.Strings(extra)
	for _, dir := range extra {
		out = append(out, category{Dir: dir, Title: strings.Title(strings.ReplaceAll(dir, "-", " "))})
	}
	return out
}

func writePage(p page) error {
	var b bytes.Buffer
	d := p.Doc
	fmt.Fprintf(&b, "# %s\n\n", d.Name)
	fmt.Fprintf(&b, "%s\n\n", strings.TrimSpace(d.Description))

	fmt.Fprintf(&b, "<div class=\"grid cards\" markdown>\n\n")
	fmt.Fprintf(&b, "- :material-file-code: **Policy file**  \n  [`%s`](%s/blob/main/%s)\n", p.Source, repoURL, p.Source)
	fmt.Fprintf(&b, "- :material-format-list-checks: **Checks**  \n  %d from %d definitions%s\n", len(p.Checks), len(d.Checks), loopNote(d.Checks))
	fmt.Fprintf(&b, "- :material-monitor: **Platforms**  \n  %s\n", platformsOf(d))
	fmt.Fprintf(&b, "\n</div>\n\n")

	fmt.Fprintf(&b, "## Run it\n\n```bash\n")
	fmt.Fprintf(&b, "# Show what would run on this host\ncheckmate list -v %s\n\n", p.Source)
	fmt.Fprintf(&b, "# Run the checks\ncheckmate run %s\n", p.Source)
	if len(d.VarsFiles) > 0 || d.Vars.Kind != 0 {
		fmt.Fprintf(&b, "\n# Override a variable from the command line\ncheckmate run %s -e name=value\n", p.Source)
	}
	fmt.Fprintf(&b, "```\n\n")

	fmt.Fprintf(&b, "## Checks\n\n| ID | Check | Severity | Tags |\n|---|---|---|---|\n")
	for _, c := range p.Checks {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", c.ID, escapeTable(c.Name), severityBadge(c.Severity), escapeTable(strings.Join(c.Tags, ", ")))
	}

	if len(d.VarsFiles) > 0 {
		dir := filepath.Dir(p.Source)
		for _, vf := range d.VarsFiles {
			path := filepath.Join(dir, vf)
			raw, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("%s: %w", p.Source, err)
			}
			fmt.Fprintf(&b, "\n## Variables: `%s`\n\n```yaml\n%s```\n", vf, ensureNewline(string(raw)))
		}
	}

	fmt.Fprintf(&b, "\n## Policy\n\n```yaml title=\"%s\" linenums=\"1\"\n%s```\n", p.Source, ensureNewline(p.Raw))

	if err := os.MkdirAll(filepath.Dir(p.Target), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p.Target, b.Bytes(), 0o644)
}

func writeCategoryIndex(c category, pages []page) error {
	var b bytes.Buffer
	fmt.Fprintf(&b, "# %s\n\n%s\n\n", c.Title, c.Description)
	fmt.Fprintf(&b, "| Example | Description | Checks |\n|---|---|---|\n")
	for _, p := range pages {
		link := strings.TrimPrefix(p.Target, filepath.Join(docsDir, c.Dir)+"/")
		fmt.Fprintf(&b, "| [%s](%s) | %s | %d |\n", p.Doc.Name, link, escapeTable(firstSentence(p.Doc.Description)), len(p.Checks))
	}
	path := filepath.Join(docsDir, c.Dir, "index.md")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b.Bytes(), 0o644)
}

func writeExamplesIndex(cats []category, byCategory map[string][]page) error {
	var b bytes.Buffer
	total := 0
	for _, ps := range byCategory {
		for _, p := range ps {
			total += len(p.Checks)
		}
	}
	fmt.Fprintf(&b, "# Examples\n\n")
	fmt.Fprintf(&b, "%d ready-to-use policies with %d checks. Every example is validated, syntax-checked for each\n", countPages(byCategory), total)
	fmt.Fprintf(&b, "platform and executed on RHEL, Debian, Ubuntu, openSUSE and Alpine in the test suite, so you can copy them as a\n")
	fmt.Fprintf(&b, "starting point.\n\n")
	fmt.Fprintf(&b, "<div class=\"grid cards\" markdown>\n\n")
	for _, c := range cats {
		if c.Dir == "" {
			for _, p := range byCategory[""] {
				fmt.Fprintf(&b, "- :material-rocket-launch: **[%s](%s)**\n\n    ---\n\n    %s\n\n", p.Doc.Name,
					strings.TrimPrefix(p.Target, docsDir+"/"), firstSentence(p.Doc.Description))
			}
			continue
		}
		fmt.Fprintf(&b, "- %s **[%s](%s/index.md)**\n\n    ---\n\n    %s\n\n", categoryIcon(c.Dir), c.Title, c.Dir, c.Description)
		var links []string
		for _, p := range byCategory[c.Dir] {
			rel := strings.TrimPrefix(p.Target, docsDir+"/")
			links = append(links, fmt.Sprintf("[%s](%s)", shortTitle(p), rel))
		}
		fmt.Fprintf(&b, "    %s\n\n", strings.Join(links, " · "))
	}
	fmt.Fprintf(&b, "</div>\n")
	return os.WriteFile(filepath.Join(docsDir, "index.md"), b.Bytes(), 0o644)
}

func updateNav(cats []category, byCategory map[string][]page, cisPages, stigPages []cisPage) error {
	raw, err := os.ReadFile(mkdocsFile)
	if err != nil {
		return err
	}
	content := string(raw)
	start := strings.Index(content, navBegin)
	end := strings.Index(content, navEnd)
	if start < 0 || end < start {
		return fmt.Errorf("%s: navigation markers not found", mkdocsFile)
	}
	var b strings.Builder
	b.WriteString(navBegin + "\n")
	b.WriteString("  - Examples:\n")
	b.WriteString("      - examples/index.md\n")
	for _, c := range cats {
		if c.Dir == "" {
			for _, p := range byCategory[""] {
				fmt.Fprintf(&b, "      - %s: %s\n", quote(p.Doc.Name), strings.TrimPrefix(p.Target, "docs/"))
			}
			continue
		}
		fmt.Fprintf(&b, "      - %s:\n", quote(c.Title))
		fmt.Fprintf(&b, "          - examples/%s/index.md\n", c.Dir)
		for _, p := range byCategory[c.Dir] {
			fmt.Fprintf(&b, "          - %s: %s\n", quote(shortTitle(p)), strings.TrimPrefix(p.Target, "docs/"))
		}
	}
	if len(cisPages) > 0 {
		b.WriteString("  - CIS benchmarks:\n")
		b.WriteString("      - cis/index.md\n")
		for _, p := range cisPages {
			fmt.Fprintf(&b, "      - %s: %s\n", quote(strings.TrimPrefix(p.Title, "CIS ")), strings.TrimPrefix(p.Target, "docs/"))
		}
	}
	if len(stigPages) > 0 {
		b.WriteString("  - DISA STIG:\n")
		b.WriteString("      - stig/index.md\n")
		for _, p := range stigPages {
			fmt.Fprintf(&b, "      - %s: %s\n", quote(strings.TrimPrefix(p.Title, "DISA STIG ")), strings.TrimPrefix(p.Target, "docs/"))
		}
	}
	content = content[:start] + b.String() + content[end:]
	return os.WriteFile(mkdocsFile, []byte(content), 0o644)
}

// shortTitle is the page title used in navigation lists.
func shortTitle(p page) string {
	return p.Doc.Name
}

func loopNote(checks []checkDoc) string {
	n := 0
	for _, c := range checks {
		if c.Loop.Kind != 0 {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	return fmt.Sprintf(", %d with loops", n)
}

// platformsOf derives the targeted platforms from variant keys and `when`.
func platformsOf(d policyDoc) string {
	set := map[string]bool{}
	var visit func(n *yaml.Node)
	visit = func(n *yaml.Node) {
		if n.Kind == yaml.MappingNode && !hasKey(n, "use") {
			for i := 0; i+1 < len(n.Content); i += 2 {
				for _, k := range strings.Split(n.Content[i].Value, ",") {
					set[strings.TrimSpace(k)] = true
				}
			}
		}
	}
	for _, c := range d.Checks {
		visit(&c.Run)
		w := c.When.Value
		for _, kw := range []string{"linux", "darwin", "windows", "rhel", "debian", "ubuntu", "suse", "sles"} {
			if strings.Contains(w, `"`+kw+`"`) {
				set[kw] = true
			}
		}
	}
	if d.Snippets.Kind == yaml.MappingNode {
		for i := 1; i < len(d.Snippets.Content); i += 2 {
			visit(d.Snippets.Content[i])
		}
	}
	if set["darwin"] {
		set["macos"] = true
		delete(set, "darwin")
	}
	delete(set, "default")
	delete(set, "unix")
	if len(set) == 0 {
		return "any (POSIX shell)"
	}
	var keys []string
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

func hasKey(n *yaml.Node, key string) bool {
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return true
		}
	}
	return false
}

func severityBadge(s string) string {
	return fmt.Sprintf(`<span class="sev sev-%s">%s</span>`, s, s)
}

func categoryIcon(dir string) string {
	icons := map[string]string{
		"platforms":       ":material-penguin:",
		"system":          ":material-cog:",
		"files":           ":material-folder-lock:",
		"network":         ":material-lan:",
		"hardware":        ":material-chip:",
		"network-devices": ":material-router-network:",
		"remote":          ":material-remote-desktop:",
		"applications":    ":material-application-cog:",
		"compliance":      ":material-shield-check:",
		"services":        ":material-server-network:",
		"attack":          ":material-target-account:",
		"cloud":           ":material-cloud-check:",
		"validation":      ":material-clipboard-check:",
	}
	if i, ok := icons[dir]; ok {
		return i
	}
	return ":material-file-document:"
}

func firstSentence(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if i := strings.Index(s, ". "); i >= 0 {
		return s[:i+1]
	}
	return s
}

func escapeTable(s string) string {
	return strings.ReplaceAll(s, "|", `\|`)
}

func ensureNewline(s string) string {
	if strings.HasSuffix(s, "\n") {
		return s
	}
	return s + "\n"
}

func quote(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

func countPages(byCategory map[string][]page) int {
	n := 0
	for _, ps := range byCategory {
		n += len(ps)
	}
	return n
}

// writeSTIGPages documents the generated DISA STIG policies in stig/.
func writeSTIGPages() ([]cisPage, error) {
	files, _ := filepath.Glob("stig/*.yml")
	sort.Slice(files, func(i, j int) bool { return naturalLess(files[i], files[j]) })
	dir := "docs/stig"
	if err := os.RemoveAll(dir); err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	var pages []cisPage
	for _, f := range files {
		p, err := policy.Load(f, policy.LoadOptions{AllowInsecure: true})
		if err != nil {
			return nil, err
		}
		checks, errs := policy.Expand(p, docFacts, nil)
		if len(errs) > 0 {
			return nil, errs[0]
		}
		key := strings.TrimSuffix(filepath.Base(f), ".yml")
		sp := cisPage{Key: key, Title: p.Name, Target: filepath.Join(dir, key+".md"), Checks: len(checks), Levels: map[string]int{}}
		rules := map[string]string{}
		var b bytes.Buffer
		fmt.Fprintf(&b, "# %s\n\n%s\n\n", p.Name, strings.TrimSpace(p.Description))
		fmt.Fprintf(&b, "**Policy:** [`%s`](%s/blob/main/%s) · **STIG version:** %s\n\n", f, repoURL, f, p.Version)
		fmt.Fprintf(&b, "```bash\nsudo checkmate run %s --tags stig-cat-1\nsudo checkmate run %s -v\n```\n\n", f, f)
		fmt.Fprintf(&b, "| ID | Rule | CAT | Severity |\n|---|---|---|---|\n")
		for _, c := range checks {
			cat := ""
			for _, t := range c.Tags {
				if strings.HasPrefix(t, "stig-cat-") {
					cat = strings.Repeat("I", int(t[len(t)-1]-'0'))
				}
			}
			rules[stigRule(c.ID)] = cat
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", c.ID, escapeTable(c.Name), cat, severityBadge(c.Severity))
		}
		sp.Rules = len(rules)
		for _, cat := range rules {
			sp.Levels[cat]++
		}
		if err := os.WriteFile(sp.Target, b.Bytes(), 0o644); err != nil {
			return nil, err
		}
		pages = append(pages, sp)
	}
	var idx bytes.Buffer
	idx.WriteString("# DISA STIG\n\n")
	idx.WriteString("Automated checks for the Security Technical Implementation Guides of the US Defense Information Systems\n")
	idx.WriteString("Agency, generated from the goss audit content of [Ansible Lockdown](https://github.com/ansible-lockdown)\n")
	idx.WriteString("(MIT license). STIGs implement NIST SP 800-53 controls; each check names its STIG ID, vulnerability ID, CCI\n")
	idx.WriteString("and NIST control in the description. Rule titles are taken from the STIG, and every check carries the\n")
	idx.WriteString("rationale and the fix text of its rule from the DISA XCCDF benchmark (shown with `-vv` and in the reports).\n\n")
	idx.WriteString("| STIG | Rules | CAT I | CAT II | CAT III | Checks |\n|---|---|---|---|---|---|\n")
	tr, tc := 0, 0
	for _, p := range pages {
		fmt.Fprintf(&idx, "| [%s](%s.md) | %d | %d | %d | %d | %d |\n", strings.TrimPrefix(p.Title, "DISA STIG "), p.Key, p.Rules, p.Levels["I"], p.Levels["II"], p.Levels["III"], p.Checks)
		tr += p.Rules
		tc += p.Checks
	}
	fmt.Fprintf(&idx, "| **Total** | **%d** | | | | **%d** |\n\n", tr, tc)
	idx.WriteString("## Selecting categories\n\n| Tag | Selects | Severity |\n|---|---|---|\n")
	idx.WriteString("| `stig-cat-1` | CAT I: direct loss of confidentiality, integrity or availability | high |\n")
	idx.WriteString("| `stig-cat-2` | CAT II: potential for loss | medium |\n")
	idx.WriteString("| `stig-cat-3` | CAT III: degrades measures | low |\n")
	idx.WriteString("| `stig-rhel9`, `stig-ubuntu24`, … | one STIG | |\n\n")
	idx.WriteString("```bash\nsudo checkmate run stig/rhel9.yml --tags stig-cat-1\nsudo checkmate run stig/ubuntu24.yml --fail-on high -v\n```\n")
	return pages, os.WriteFile(filepath.Join(dir, "index.md"), idx.Bytes(), 0o644)
}

// stigRule extracts the STIG ID (e.g. RHEL-09-212015) from a check ID.
func stigRule(id string) string {
	parts := strings.SplitN(strings.TrimPrefix(id, "STIG-"), "-", 4)
	if len(parts) < 3 {
		return id
	}
	return strings.Join(parts[:3], "-")
}
