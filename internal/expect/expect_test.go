package expect

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func parseYAML(t *testing.T, src string) Expectation {
	t.Helper()
	var node yaml.Node
	if err := yaml.Unmarshal([]byte(src), &node); err != nil {
		t.Fatalf("yaml: %v", err)
	}
	e, err := Parse(node.Content[0])
	if err != nil {
		t.Fatalf("parse %q: %v", src, err)
	}
	return e
}

func TestEval(t *testing.T) {
	tests := []struct {
		expect string
		out    Output
		mode   Mode
		want   bool
	}{
		{"true", Output{RC: 0}, ModeAuto, true},
		{"true", Output{RC: 1}, ModeAuto, false},
		{"false", Output{RC: 3}, ModeAuto, true},
		{"false", Output{RC: 0}, ModeAuto, false},
		{`"== active"`, Output{Stdout: "active\n"}, ModeAuto, true},
		{`active`, Output{Stdout: "  active  "}, ModeAuto, true},
		{`"!= active"`, Output{Stdout: "inactive"}, ModeAuto, true},
		// Equality: whole numbers by value, everything else as written.
		{`"== 1"`, Output{Stdout: "1.0"}, ModeAuto, false},
		{`"== 1"`, Output{Stdout: "1.0"}, ModeNumber, true},
		{`"644"`, Output{Stdout: "0644"}, ModeAuto, true},
		{`"== 7"`, Output{Stdout: "+007"}, ModeAuto, true},
		{`"== 0"`, Output{Stdout: "-0"}, ModeAuto, true},
		{`"!= 644"`, Output{Stdout: "0644"}, ModeAuto, false},
		{`"== 12345678901234567890123"`, Output{Stdout: "012345678901234567890123"}, ModeAuto, true},
		{`"== 8.10"`, Output{Stdout: "8.1"}, ModeAuto, false},
		{`"== 8.10"`, Output{Stdout: "8.10"}, ModeAuto, true},
		{`"== 8.10"`, Output{Stdout: "8.1"}, ModeNumber, true},
		{`"100"`, Output{Stdout: "1e2"}, ModeAuto, false},
		{`"16"`, Output{Stdout: "0x10"}, ModeAuto, false},
		{`"infinity"`, Output{Stdout: "inf"}, ModeAuto, false},
		{`"nan"`, Output{Stdout: "nan"}, ModeAuto, true},
		{`"!= nan"`, Output{Stdout: "nan"}, ModeAuto, false},
		// Lists keep their items as written.
		{`"in [8.10, 9.0]"`, Output{Stdout: "8.1"}, ModeAuto, false},
		{`"in [8.10, 9.0]"`, Output{Stdout: "9.0"}, ModeAuto, true},
		{`"in [0644, 0600]"`, Output{Stdout: "644"}, ModeAuto, true},
		{`"in ['027', \"077\"]"`, Output{Stdout: "077"}, ModeString, true},
		{`"in [true, null]"`, Output{Stdout: "null"}, ModeAuto, true},
		{`"in [644 root root, 640 root shadow]"`, Output{Stdout: "640 root shadow"}, ModeAuto, true},
		// "in" is only an operator in front of a list.
		{`"in progress"`, Output{Stdout: "in progress"}, ModeAuto, true},
		{`"in progress"`, Output{Stdout: "progress"}, ModeAuto, false},
		{`"!in use"`, Output{Stdout: "!in use"}, ModeAuto, true},
		{`"in a, b"`, Output{Stdout: "b"}, ModeAuto, true},
		{`"in [a]"`, Output{Stdout: "a"}, ModeAuto, true},
		{`"== 1"`, Output{Stdout: "01"}, ModeAuto, true},
		{`"== 01"`, Output{Stdout: "1"}, ModeString, false},
		{`">= 500"`, Output{Stdout: "512"}, ModeAuto, true},
		{`">= 500"`, Output{Stdout: "312"}, ModeAuto, false},
		{`"> 2"`, Output{Stdout: "10"}, ModeAuto, true}, // numeric, not lexicographic
		{`"< 2"`, Output{Stdout: "1"}, ModeAuto, true},
		{`"!> 90"`, Output{Stdout: "90"}, ModeAuto, true},
		{`"!> 90"`, Output{Stdout: "91"}, ModeAuto, false},
		{`"!< 5"`, Output{Stdout: "5"}, ModeAuto, true},
		{`"~ ^PermitRootLogin no$"`, Output{Stdout: "Port 22\nPermitRootLogin no\n"}, ModeAuto, true},
		{`"!~ nosuid"`, Output{Stdout: "rw,nodev"}, ModeAuto, true},
		{`"in [xfs, ext4]"`, Output{Stdout: "xfs"}, ModeAuto, true},
		{`"in xfs, ext4"`, Output{Stdout: "btrfs"}, ModeAuto, false},
		{`"!in [0, 2]"`, Output{Stdout: "1"}, ModeAuto, true},
		{`empty`, Output{Stdout: " \n"}, ModeAuto, true},
		{`"!empty"`, Output{Stdout: ""}, ModeAuto, false},
		{`{lines: "== 2"}`, Output{Stdout: "a\n\nb\n"}, ModeAuto, true},
		{`{rc: "== 3"}`, Output{RC: 3}, ModeAuto, true},
		{`{stderr: empty}`, Output{Stdout: "x", Stderr: ""}, ModeAuto, true},
		{`{stdout: ["!empty", "~ ok"]}`, Output{Stdout: "all ok"}, ModeAuto, true},
		{`["!empty", "~ ok"]`, Output{Stdout: "fail"}, ModeAuto, false},
		{`{any: ["== a", "== b"]}`, Output{Stdout: "b"}, ModeAuto, true},
		{`{any: ["== a", "== b"]}`, Output{Stdout: "c"}, ModeAuto, false},
		{`{stdout: "== x", rc: "== 0"}`, Output{Stdout: "x", RC: 0}, ModeAuto, true},
		{`">= 8.10"`, Output{Stdout: "8.9"}, ModeVersion, false},
		{`">= 8.9"`, Output{Stdout: "8.10"}, ModeVersion, true},
		{`"== 1.2"`, Output{Stdout: "1.2.0"}, ModeVersion, true},
		{`"== ''"`, Output{Stdout: ""}, ModeAuto, true},
	}
	for _, tt := range tests {
		e := parseYAML(t, tt.expect)
		got, msg, err := e.Eval(tt.out, tt.mode)
		if err != nil {
			t.Errorf("%s on %+v: unexpected error %v", tt.expect, tt.out, err)
			continue
		}
		if got != tt.want {
			t.Errorf("%s on %+v (%s): got %v, want %v (%s)", tt.expect, tt.out, tt.mode, got, tt.want, msg)
		}
		if !got && msg == "" {
			t.Errorf("%s: a mismatch must explain itself", tt.expect)
		}
	}
}

func TestEvalErrors(t *testing.T) {
	// Ordering non-numeric values in auto mode is ambiguous and must be an
	// error, never a silent lexicographic comparison.
	e := parseYAML(t, `"> 5"`)
	if _, _, err := e.Eval(Output{Stdout: "abc"}, ModeAuto); err == nil {
		t.Error("expected an error comparing non-numeric output")
	}
	e = parseYAML(t, `"== 5"`)
	if _, _, err := e.Eval(Output{Stdout: "abc"}, ModeNumber); err == nil {
		t.Error("expected an error in number mode")
	}
}

func TestParseErrors(t *testing.T) {
	for _, src := range []string{
		`null`,
		`"~ ("`,
		`{lines: "== x"}`,
		`{unknown: x}`,
		`[]`,
		`{}`,
	} {
		var node yaml.Node
		if err := yaml.Unmarshal([]byte(src), &node); err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(node.Content[0]); err == nil {
			t.Errorf("%s: expected a parse error", src)
		}
	}
}

func TestNeedsOutput(t *testing.T) {
	cases := map[string]bool{
		`true`:                 false,
		`{rc: "!= 0"}`:         false,
		`"== x"`:               true,
		`{lines: "== 0"}`:      true,
		`[true, "== x"]`:       true,
		`{any: [true, false]}`: false,
	}
	for src, want := range cases {
		if got := parseYAML(t, src).NeedsOutput(); got != want {
			t.Errorf("%s: NeedsOutput = %v, want %v", src, got, want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"8.10", "8.9", 1},
		{"1.2.3", "1.2.3", 0},
		{"1.2", "1.2.0", 0},
		{"5.14.0-427.el9", "5.14.0-70.el9", 1},
		{"2.0", "10.0", -1},
		{"1.0a", "1.0b", -1},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestCombinators(t *testing.T) {
	tests := []struct {
		name   string
		expect string
		out    Output
		want   bool
	}{
		{"not regex", `{not: "~ telnet"}`, Output{Stdout: "ssh"}, true},
		{"not regex fails", `{not: "~ telnet"}`, Output{Stdout: "telnet ssh"}, false},
		{"not exit code", `{not: true}`, Output{RC: 1}, true},
		{"not group", `{not: {any: ["== a", "== b"]}}`, Output{Stdout: "b"}, false},

		{"if then", "{if: {stdout: \"~ ^Ubuntu\"}, then: \"~ 24\", else: \"~ 12\"}", Output{Stdout: "Ubuntu 24.04"}, true},
		{"if then fails", "{if: {stdout: \"~ ^Ubuntu\"}, then: \"~ 24\", else: \"~ 12\"}", Output{Stdout: "Ubuntu 22.04"}, false},
		{"else branch", "{if: {stdout: \"~ ^Ubuntu\"}, then: \"~ 24\", else: \"~ 12\"}", Output{Stdout: "Debian 12"}, true},
		{"if without else passes", `{if: {rc: "== 0"}, then: "== ok"}`, Output{RC: 1, Stdout: "x"}, true},
		{"if on exit code", `{if: true, then: "== active", else: {rc: "== 3"}}`, Output{RC: 3}, true},
		{"nested if", `{if: "~ a", then: {if: "~ b", then: "~ c"}}`, Output{Stdout: "a b"}, false},

		{"each", `{each: "< 90"}`, Output{Stdout: "10\n89\n"}, true},
		{"each fails", `{each: "< 90"}`, Output{Stdout: "10\n95\n"}, false},
		{"each empty output", `{each: "< 90"}`, Output{Stdout: ""}, true},
		{"each with list", `{each: ["~ ^/", "!~ tmp"]}`, Output{Stdout: "/a\n/b"}, true},
		{"some", `{some: "~ ^\\^\\*"}`, Output{Stdout: "^- a\n^* b"}, true},
		{"some fails", `{some: "== x"}`, Output{Stdout: "a\nb"}, false},
		{"none", `{none: "~ (?i)permitrootlogin yes"}`, Output{Stdout: "PermitRootLogin no\nPort 22"}, true},
		{"none fails", `{none: "~ (?i)permitrootlogin yes"}`, Output{Stdout: "permitrootlogin yes"}, false},
		{"each version", `{each: ">= 1.2"}`, Output{Stdout: "1.10\n1.2.1"}, true},

		{"combined", `{all: [{each: "< 90"}, {lines: ">= 2"}, {not: empty}]}`, Output{Stdout: "1\n2"}, true},
		{"regex sees leading space", `{some: "~ ^\\s+umask 027"}`, Output{Stdout: "x\n    umask 027\n"}, true},
		{"comparison trims", `{each: "< 90"}`, Output{Stdout: "  10  \n 20"}, true},
	}
	for _, tt := range tests {
		e := parseYAML(t, tt.expect)
		mode := ModeAuto
		if tt.name == "each version" {
			mode = ModeVersion
		}
		got, msg, err := e.Eval(tt.out, mode)
		if err != nil {
			t.Errorf("%s: unexpected error %v", tt.name, err)
			continue
		}
		if got != tt.want {
			t.Errorf("%s: got %v, want %v (%s)", tt.name, got, tt.want, msg)
		}
		if !got && msg == "" {
			t.Errorf("%s: a mismatch must explain itself", tt.name)
		}
	}
}

func TestCombinatorParseErrors(t *testing.T) {
	for _, src := range []string{
		`{if: "== a"}`,
		`{then: "== a"}`,
		`{not: {}}`,
		`{each: []}`,
		`{each: {a: b}}`,
		`{some: "~ ("}`,
	} {
		var node yaml.Node
		if err := yaml.Unmarshal([]byte(src), &node); err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(node.Content[0]); err == nil {
			t.Errorf("%s: expected a parse error", src)
		}
	}
}

func TestCombinatorMessages(t *testing.T) {
	e := parseYAML(t, `{each: "< 90"}`)
	_, msg, _ := e.Eval(Output{Stdout: "10\n95"}, ModeAuto)
	if !strings.Contains(msg, "line 2") {
		t.Errorf("message %q should name the failing line", msg)
	}
	// A non-numeric line is an error, not a failure.
	if _, _, err := e.Eval(Output{Stdout: "95 /var"}, ModeAuto); err == nil {
		t.Error("comparing a non-numeric line must be an error")
	}
	e = parseYAML(t, "{if: {stdout: \"~ ^Ubuntu\"}, then: \"~ 24\"}")
	_, msg, _ = e.Eval(Output{Stdout: "Ubuntu 22.04"}, ModeAuto)
	if want := "then branch"; !strings.Contains(msg, want) {
		t.Errorf("message %q should mention %q", msg, want)
	}
}

func TestCases(t *testing.T) {
	const withoutElse = `
cases:
  - { if: "~ ^ubuntu", then: "~ 24\\." }
  - { if: { any: ["~ ^debian", "~ ^raspbian"] }, then: "~ 1[2-9]" }
  - if: { rc: "== 3" }
    then: empty
`
	const withElse = withoutElse + `else: "~ ^alpine"` + "\n"
	cases := []struct {
		yaml, stdout string
		rc           int
		want         bool
		message      string
	}{
		{withoutElse, "ubuntu 24.04", 0, true, ""},
		{withoutElse, "ubuntu 22.04", 0, false, `(case 1, because stdout ~ "^ubuntu" holds)`},
		{withoutElse, "raspbian 12", 0, true, ""},
		{withoutElse, "debian 9", 0, false, "(case 2, because"},
		{withoutElse, "", 3, true, ""},
		{withoutElse, "x", 3, false, "(case 3, because"},
		// The first case that applies decides, later ones are not asked.
		{withoutElse, "ubuntu 24.04", 3, true, ""},
		{withoutElse, "rhel 9", 0, false, "no case matches the output"},
		{withElse, "alpine 3", 0, true, ""},
		{withElse, "rhel 9", 0, false, "(else, because no case matches)"},
		{withElse, "ubuntu 22.04", 0, false, "(case 1,"},
	}
	for _, c := range cases {
		var node yaml.Node
		if err := yaml.Unmarshal([]byte(c.yaml), &node); err != nil {
			t.Fatal(err)
		}
		e, err := Parse(node.Content[0])
		if err != nil {
			t.Fatalf("parse: %v", err)
		}
		if !e.NeedsOutput() {
			t.Error("NeedsOutput() = false")
		}
		ok, msg, err := e.Eval(Output{Stdout: c.stdout, RC: c.rc}, ModeAuto)
		if err != nil || ok != c.want || !strings.Contains(msg, c.message) {
			t.Errorf("%q rc %d: got %v, %q, %v; want %v with %q", c.stdout, c.rc, ok, msg, err, c.want, c.message)
		}
	}
}

func TestCasesErrors(t *testing.T) {
	for src, want := range map[string]string{
		`{cases: []}`:            "expected a list",
		`{cases: "~ x"}`:         "expected a list",
		`{cases: [{if: "~ x"}]}`: "case 1",
		`{cases: [{if: "~ x", then: y}, {then: y}]}`:          "case 2",
		`{cases: [{if: "~ x", then: y, else: z}]}`:            `unknown key "else"`,
		`{cases: [{if: "~ x", then: y}], if: "~ a", then: b}`: "cannot be combined",
		`{cases: [{if: "~ (", then: y}]}`:                     "case 1: if",
		`{cases: [{if: "~ x", then: y}], else: "~ ("}`:        "else:",
	} {
		var node yaml.Node
		if err := yaml.Unmarshal([]byte(src), &node); err != nil {
			t.Fatal(err)
		}
		if _, err := Parse(node.Content[0]); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %v, want one mentioning %q", src, err, want)
		}
	}
}
