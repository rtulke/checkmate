// Package pipes rewrites shell pipelines whose last command stops reading
// before its input ends.
//
// `producer | grep -q x` and `producer | head -1` close the pipe as soon as
// they have what they need. A producer that is still writing is killed by
// SIGPIPE, and under `set -o pipefail`, which checkmate uses, the pipeline
// then fails although the pattern was found: an `if` takes the wrong
// branch, an only_if skips the check. Upstream audit content is written for
// shells without pipefail and uses both forms freely.
package pipes

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
)

var (
	// A grep behind a pipe (not behind ||) with -q among its short options.
	quietGrep = regexp.MustCompile(`(^|[^|])\|(\s*)grep(\s+)-([A-Za-z]*)q([A-Za-z]*)`)
	// head behind a pipe with a line count, in the spellings found in audit
	// scripts.
	headLines = regexp.MustCompile(`(^|[^|])\|(\s*)head\s+(?:-n\s*|-)([0-9]+)\b`)
)

// Drain makes every `| grep -q` and `| head -N` in command read all of its
// input: grep without -q and with its output discarded, sed in place of
// head. The exit status and the output stay the same.
func Drain(command string) string {
	command = headLines.ReplaceAllStringFunc(command, func(m string) string {
		sub := headLines.FindStringSubmatch(m)
		if sub[3] == "1" {
			return sub[1] + "|" + sub[2] + "sed -n 1p"
		}
		return sub[1] + "|" + sub[2] + "sed -n 1," + sub[3] + "p"
	})

	var out strings.Builder
	rest := command
	for {
		loc := quietGrep.FindStringSubmatchIndex(rest)
		if loc == nil {
			out.WriteString(rest)
			return out.String()
		}
		sub := quietGrep.FindStringSubmatch(rest[loc[0]:loc[1]])
		out.WriteString(rest[:loc[0]])
		out.WriteString(sub[1] + "|" + sub[2] + "grep")
		if flags := sub[4] + sub[5]; flags != "" {
			out.WriteString(sub[3] + "-" + flags)
		}
		// The redirection goes to the end of the arguments of this grep.
		args := rest[loc[1]:]
		end := endOfCommand(args)
		trimmed := strings.TrimRight(args[:end], " \t")
		out.WriteString(trimmed + " >/dev/null" + args[len(trimmed):end])
		rest = args[end:]
	}
}

// endOfCommand returns the index in s at which the simple command that
// starts s ends: at an unquoted ; & | ) or newline, or at the end. A quote
// that is never closed belongs to the text around the command, as in
// sh -c '... | grep -q x', and ends it too.
func endOfCommand(s string) int {
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\':
			i++
		case '\'':
			j := strings.IndexByte(s[i+1:], '\'')
			if j < 0 {
				return i
			}
			i += j + 1
		case '"':
			j := closingDoubleQuote(s[i+1:])
			if j < 0 {
				return i
			}
			i += j + 1
		case '`':
			return i
		case ';', '|', ')', '\n':
			return i
		case '&':
			// 2>&1 is part of the command, && and & end it.
			if i > 0 && s[i-1] == '>' {
				continue
			}
			return i
		}
	}
	return len(s)
}

func closingDoubleQuote(s string) int {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			return i
		}
	}
	return -1
}

var (
	checkKey   = regexp.MustCompile(`^    ([a-z_]+):`)
	quotedLine = regexp.MustCompile(`^(\s*[A-Za-z0-9_,-]+: )(".*")$`)
)

// DrainFile applies Drain to the commands (run and only_if) of a generated
// policy file in place. It works on the text, so that nothing else in the
// file changes; values in double quotes are JSON strings, as the importers
// write them.
func DrainFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	key := ""
	for i, line := range lines {
		if m := checkKey.FindStringSubmatch(line); m != nil {
			key = m[1]
		} else if !strings.HasPrefix(line, "     ") && strings.TrimSpace(line) != "" {
			key = ""
		}
		if key != "run" && key != "only_if" {
			continue
		}
		if m := quotedLine.FindStringSubmatch(line); m != nil {
			var value string
			if err := json.Unmarshal([]byte(m[2]), &value); err != nil {
				continue
			}
			quoted, _ := json.Marshal(Drain(value))
			lines[i] = m[1] + string(quoted)
			continue
		}
		lines[i] = Drain(line)
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0o644)
}
