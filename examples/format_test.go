package examples

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// inlineComment matches code followed by whitespace and a "# " comment.
var inlineComment = regexp.MustCompile(`^(.*?\S)([ \t]+)(#(?: |$).*)$`)

// commentColumn returns the column of an inline comment, or -1.
func commentColumn(line string) int {
	if strings.HasPrefix(strings.TrimSpace(line), "#") {
		return -1
	}
	m := inlineComment.FindStringSubmatch(line)
	if m == nil || strings.Count(m[1], `"`)%2 == 1 || strings.Count(m[1], "'")%2 == 1 {
		return -1
	}
	return len(m[1]) + len(m[2])
}

// misaligned returns the first line of every paragraph (run of non-blank
// lines) whose inline comments do not start in the same column.
func misaligned(lines []string, offset int) []int {
	var bad []int
	for i := 0; i < len(lines); {
		if strings.TrimSpace(lines[i]) == "" {
			i++
			continue
		}
		cols := map[int]bool{}
		first := -1
		for ; i < len(lines) && strings.TrimSpace(lines[i]) != ""; i++ {
			if c := commentColumn(lines[i]); c >= 0 {
				cols[c] = true
				if first < 0 {
					first = i
				}
			}
		}
		if len(cols) > 1 {
			bad = append(bad, offset+first+1)
		}
	}
	return bad
}

// TestCommentAlignment keeps inline comments of examples and code blocks in
// the documentation in one column per paragraph.
func TestCommentAlignment(t *testing.T) {
	var files []string
	for _, pattern := range []string{"../README*.md", "../cis/*.md", "../stig/*.md"} {
		m, _ := filepath.Glob(pattern)
		files = append(files, m...)
	}
	_ = filepath.WalkDir("../docs", func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".md") {
			files = append(files, path)
		}
		return nil
	})
	_ = filepath.WalkDir(".", func(path string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && strings.HasSuffix(path, ".yml") {
			files = append(files, path)
		}
		return nil
	})
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(data), "\n")
		var bad []int
		if strings.HasSuffix(f, ".md") {
			start, inCode := 0, false
			for i, l := range lines {
				if strings.HasPrefix(strings.TrimSpace(l), "```") {
					if inCode {
						bad = append(bad, misaligned(lines[start:i], start)...)
					}
					inCode, start = !inCode, i+1
				}
			}
		} else {
			bad = misaligned(lines, 0)
		}
		for _, line := range bad {
			t.Errorf("%s:%d: inline comments of this block do not start in the same column", f, line)
		}
	}
}
