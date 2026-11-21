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
	"sort"
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
	{"validation", "Server validation", "Describe the expected state of a server role and validate it, in the style of goss and serverspec."},
	{"compliance", "Compliance baselines", "Complete baselines: a broad Linux hardening baseline modelled on OpenSCAP and CIS, and a managed-RHEL baseline with a tag-based selection model."},
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
	return updateNav(cats, byCategory)
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

func updateNav(cats []category, byCategory map[string][]page) error {
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
