package main

// Rationale and remediation texts written for checkmate. CIS benchmark text
// cannot be used, so every concept (one setting or control, usually shared
// by several benchmarks) has its own texts in texts/linux.yml and
// texts/windows.yml. A Linux concept is the ID suffix of a check without the
// part suffixes the converter adds (-attrs, -content, ...); a Windows
// concept is the registry value, security setting, user right, audit
// subcategory, service or firewall setting the check reads.

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// familyText is a text for all platforms, or one per platform family.
type familyText map[string]string

// UnmarshalYAML accepts a string or a mapping of family to string.
func (t *familyText) UnmarshalYAML(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		*t = familyText{"all": n.Value}
		return nil
	}
	var m map[string]string
	if err := n.Decode(&m); err != nil {
		return err
	}
	for k := range m {
		switch k {
		case "all", "rhel", "debian", "suse":
		default:
			return fmt.Errorf("line %d: unknown platform family %q (use all, rhel, debian or suse)", n.Line, k)
		}
	}
	*t = m
	return nil
}

// forFamily returns the text of a family, or the text for all.
func (t familyText) forFamily(family string) string {
	if s, ok := t[family]; ok {
		return strings.TrimSpace(s)
	}
	return strings.TrimSpace(t["all"])
}

type conceptText struct {
	Rationale   familyText `yaml:"rationale"`
	Remediation familyText `yaml:"remediation"`
}

// textBase holds the texts while a CIS benchmark is converted.
var textBase map[string]conceptText

func loadTexts(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	textBase = map[string]conceptText{}
	if err := yaml.Unmarshal(data, &textBase); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// family is the platform family of a Linux benchmark.
func (b benchmark) family() string {
	switch p := b.platform(); {
	case strings.HasPrefix(p, "debian"), strings.HasPrefix(p, "ubuntu"):
		return "debian"
	case strings.HasPrefix(p, "suse"):
		return "suse"
	}
	return "rhel"
}

var (
	cisIDSuffix = regexp.MustCompile(`^CIS-[A-Z0-9]+-[0-9.]+-(.*)$`)
	checkPart   = regexp.MustCompile(`-(attrs|content|absent|enabled|running|version|[0-9]+)$`)
)

// linuxConcept is the concept of a Linux check, from its ID.
func linuxConcept(id string) string {
	m := cisIDSuffix.FindStringSubmatch(id)
	if m == nil {
		return ""
	}
	base := m[1]
	for checkPart.MatchString(base) {
		base = checkPart.ReplaceAllString(base, "")
	}
	return base
}

// applyTexts adds the rationale, and the remediation where the converter
// could not generate one, to the checks of a CIS benchmark. It returns the
// IDs of checks that lack a text.
func applyTexts(b benchmark, checks []check) (missing []string) {
	used := map[string]bool{}
	for i := range checks {
		c := &checks[i]
		key := c.TextKey
		family := "all"
		if !b.windows() {
			key = linuxConcept(c.ID)
			family = b.family()
		}
		t, ok := textBase[key]
		if !ok {
			missing = append(missing, fmt.Sprintf("%s (concept %q has no texts)", c.ID, key))
			continue
		}
		used[key] = true
		if c.Rationale == "" {
			c.Rationale = t.Rationale.forFamily(family)
		}
		if c.Remediation == "" {
			c.Remediation = t.Remediation.forFamily(family)
		}
		switch {
		case c.Rationale == "":
			missing = append(missing, fmt.Sprintf("%s (concept %q has no rationale for %s)", c.ID, key, family))
		case c.Remediation == "":
			missing = append(missing, fmt.Sprintf("%s (concept %q has no remediation for %s)", c.ID, key, family))
		}
	}
	sort.Strings(missing)
	return missing
}
