package main

// Texts of mSCP rules. discussion becomes the rationale of a check and fix
// its remediation. Both are written in AsciiDoc; they are converted to
// plain text, which every report format can show. Rules that are fixed by
// a configuration profile get the profile settings from mobileconfig_info
// and ddm_info, since their fix text only says that a profile is needed.

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const profileFix = "This is implemented by a Configuration Profile."

var (
	admonitionLabel = regexp.MustCompile(`^\[(NOTE|IMPORTANT|WARNING|CAUTION|TIP)\]$`)
	sourceAttr      = regexp.MustCompile(`^\[source(,[^\]]*)?\]$`)
	orderedItem     = regexp.MustCompile(`^\.\s+(.*)$`)
	bulletItem      = regexp.MustCompile(`^\*\s+(.*)$`)
	linkMacro       = regexp.MustCompile(`link:(\S+?)\[([^\]]*)\]`)
	crossRef        = regexp.MustCompile(`<<([^,>]+)(?:,\s*([^>]+))?>>`)
	monospace       = regexp.MustCompile("`([^`\n]+)`")
	emphasis        = regexp.MustCompile(`(^|[^\w_])_([^_\s][^_\n]*?)_([^\w_]|$)`)
	strong          = regexp.MustCompile(`(^|[^\w*])\*([^*\s][^*\n]*?)\*([^\w*]|$)`)
)

// asciidocText converts the AsciiDoc of an mSCP text to plain text. Code
// blocks are kept verbatim; inline markup is removed, links keep their URL.
func asciidocText(s, odv string) string {
	// The value is inserted after the markup is removed, so a value such as
	// a regular expression is not mistaken for markup.
	s = strings.ReplaceAll(s, "$ODV", odvMarker)
	var out []string
	inCode := false
	label := ""  // admonition waiting for its first line
	ordered := 0 // number of the last ordered list item
	for _, line := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "----" {
			inCode = !inCode
			continue
		}
		if inCode {
			out = append(out, line)
			continue
		}
		switch {
		case sourceAttr.MatchString(trimmed), trimmed == "====", strings.HasPrefix(trimmed, "include::"):
			continue
		case admonitionLabel.MatchString(trimmed):
			label = admonitionLabel.FindStringSubmatch(trimmed)[1]
			continue
		}
		if m := orderedItem.FindStringSubmatch(trimmed); m != nil {
			ordered++
			trimmed = fmt.Sprintf("%d. %s", ordered, m[1])
		} else {
			if trimmed != "" {
				ordered = 0
			}
			if m := bulletItem.FindStringSubmatch(trimmed); m != nil {
				trimmed = "- " + m[1]
			}
		}
		trimmed = strings.TrimSuffix(trimmed, " +")
		trimmed = inlineText(trimmed)
		if label != "" && trimmed != "" {
			trimmed = label + ": " + trimmed
			label = ""
		}
		out = append(out, trimmed)
	}
	return cleanText(strings.ReplaceAll(strings.Join(out, "\n"), odvMarker, odv))
}

// odvMarker stands for the organization-defined value while markup is
// removed; it contains no markup characters.
const odvMarker = "\x00ODV\x00"

// inlineText removes AsciiDoc inline markup from one line of prose.
func inlineText(s string) string {
	s = linkMacro.ReplaceAllStringFunc(s, func(m string) string {
		p := linkMacro.FindStringSubmatch(m)
		if strings.TrimSpace(p[2]) == "" {
			return p[1]
		}
		return p[2] + " (" + p[1] + ")"
	})
	s = crossRef.ReplaceAllStringFunc(s, func(m string) string {
		p := crossRef.FindStringSubmatch(m)
		if p[2] != "" {
			return p[2]
		}
		return p[1]
	})
	s = monospace.ReplaceAllString(s, `"$1"`)
	// The patterns consume the character around the markup, so adjacent
	// markup needs a second pass.
	for i := 0; i < 2; i++ {
		s = emphasis.ReplaceAllString(s, "$1$2$3")
		s = strong.ReplaceAllString(s, "$1$2$3")
	}
	return s
}

// remediation builds the remediation of a rule from its fix text and, for
// rules fixed by a configuration profile, the settings of the profile.
func remediation(r rule, odv string) string {
	fix := asciidocText(r.Fix, odv)
	if !strings.HasPrefix(fix, profileFix) {
		return fix
	}
	var b strings.Builder
	b.WriteString(fix)
	if settings := profileSettings(&r.MobileconfigInfo, odv); len(settings) > 0 {
		b.WriteString("\n\nConfiguration profile settings (payload type: key = value):\n")
		b.WriteString(strings.Join(settings, "\n"))
	}
	if ddm := ddmSetting(&r.DDMInfo, odv); ddm != "" {
		b.WriteString("\n\nWith declarative device management instead: " + ddm)
	}
	return b.String()
}

// profileSettings lists the settings of mobileconfig_info in file order,
// one line per value; nested dictionaries are joined with " > ".
func profileSettings(n *yaml.Node, odv string) []string {
	if n.Kind != yaml.MappingNode {
		return nil
	}
	var out []string
	for i := 0; i+1 < len(n.Content); i += 2 {
		payload := n.Content[i].Value
		for _, s := range flatten(n.Content[i+1], "", odv) {
			out = append(out, payload+": "+s)
		}
	}
	return out
}

func flatten(n *yaml.Node, prefix, odv string) []string {
	switch n.Kind {
	case yaml.MappingNode:
		var out []string
		for i := 0; i+1 < len(n.Content); i += 2 {
			key := n.Content[i].Value
			if prefix != "" {
				key = prefix + " > " + key
			}
			out = append(out, flatten(n.Content[i+1], key, odv)...)
		}
		return out
	case yaml.SequenceNode:
		var items []string
		for _, c := range n.Content {
			items = append(items, scalarText(c, odv))
		}
		return []string{prefix + " = [" + strings.Join(items, ", ") + "]"}
	case yaml.ScalarNode:
		if prefix == "" {
			return nil
		}
		return []string{prefix + " = " + scalarText(n, odv)}
	}
	return nil
}

func scalarText(n *yaml.Node, odv string) string {
	if n.Kind != yaml.ScalarNode {
		return strings.Join(flatten(n, "", odv), ", ")
	}
	v := strings.ReplaceAll(n.Value, "$ODV", odv)
	if n.Tag == "!!str" && (v == "" || strings.TrimSpace(v) != v) {
		return fmt.Sprintf("%q", v)
	}
	return v
}

// ddmSetting describes the declaration of ddm_info.
func ddmSetting(n *yaml.Node, odv string) string {
	var d struct {
		Type  string    `yaml:"declarationtype"`
		Key   string    `yaml:"ddm_key"`
		Value yaml.Node `yaml:"ddm_value"`
	}
	if n.Kind == 0 || n.Decode(&d) != nil || d.Type == "" || d.Key == "" {
		return ""
	}
	values := flatten(&d.Value, d.Key, odv)
	if len(values) == 0 {
		return ""
	}
	return d.Type + ": " + strings.Join(values, ", ")
}

// cleanText removes trailing blanks and repeated empty lines.
func cleanText(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimRight(l, " \t")
	}
	s = strings.Join(lines, "\n")
	for strings.Contains(s, "\n\n\n") {
		s = strings.ReplaceAll(s, "\n\n\n", "\n\n")
	}
	return strings.TrimSpace(s)
}
