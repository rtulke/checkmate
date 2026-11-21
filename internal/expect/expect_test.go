package expect

import (
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
		{`"== 1"`, Output{Stdout: "1.0"}, ModeAuto, true},
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
