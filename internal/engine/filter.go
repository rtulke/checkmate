package engine

import (
	"path"
	"strings"
)

// Filter selects checks by tags and IDs.
//
// Tag expressions use "," for OR and "+" for AND:
// "compliance+full,quality" selects checks tagged both compliance and
// full, or tagged quality.
type Filter struct {
	Tags     [][]string // at least one group must match (empty: all checks)
	SkipTags [][]string // checks matching any group are excluded
	IDs      []string   // glob patterns; at least one must match (empty: all)
}

// ParseTagExpr parses a tag expression such as "a+b,c".
func ParseTagExpr(s string) [][]string {
	var groups [][]string
	for _, alt := range strings.Split(s, ",") {
		var group []string
		for _, tag := range strings.Split(alt, "+") {
			if tag = strings.TrimSpace(tag); tag != "" {
				group = append(group, tag)
			}
		}
		if len(group) > 0 {
			groups = append(groups, group)
		}
	}
	return groups
}

// ParseIDs parses a comma-separated list of ID glob patterns.
func ParseIDs(s string) []string {
	var ids []string
	for _, id := range strings.Split(s, ",") {
		if id = strings.TrimSpace(id); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// Match reports whether a check with the given ID and tags is selected.
func (f Filter) Match(id string, tags []string) bool {
	if len(f.IDs) > 0 {
		matched := false
		for _, pattern := range f.IDs {
			if ok, _ := path.Match(pattern, id); ok {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if len(f.Tags) > 0 && !matchAnyGroup(f.Tags, tags) {
		return false
	}
	return !matchAnyGroup(f.SkipTags, tags)
}

func matchAnyGroup(groups [][]string, tags []string) bool {
	have := make(map[string]bool, len(tags))
	for _, t := range tags {
		have[t] = true
	}
	for _, group := range groups {
		all := true
		for _, t := range group {
			if !have[t] {
				all = false
				break
			}
		}
		if all {
			return true
		}
	}
	return false
}
