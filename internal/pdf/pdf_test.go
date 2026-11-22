package pdf

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestWidth(t *testing.T) {
	if got := Width(Helvetica, 10, "A"); got != 6.67 {
		t.Errorf("Helvetica A at 10pt: got %v, want 6.67", got)
	}
	if got := Width(Courier, 10, "abc"); got != 18 {
		t.Errorf("Courier: got %v, want 18", got)
	}
	if Width(HelveticaBold, 10, "W") <= Width(Helvetica, 10, "i") {
		t.Error("W must be wider than i")
	}
}

func TestWrap(t *testing.T) {
	lines := Wrap(Helvetica, 10, "the quick brown fox jumps over the lazy dog", 60)
	if len(lines) < 3 {
		t.Fatalf("expected several lines, got %q", lines)
	}
	for _, l := range lines {
		if Width(Helvetica, 10, l) > 60 {
			t.Errorf("line too wide: %q", l)
		}
	}
	long := Wrap(Courier, 10, strings.Repeat("x", 50), 60)
	if len(long) != 5 || long[0] != strings.Repeat("x", 10) {
		t.Errorf("long word not split: %q", long)
	}
	if got := Wrap(Courier, 10, "a\n\nb", 100); len(got) != 3 || got[1] != "" {
		t.Errorf("newlines not kept: %q", got)
	}
	if got := Wrap(Courier, 10, "  indented", 200); got[0] != "  indented" {
		t.Errorf("leading spaces of preformatted text lost: %q", got)
	}
}

func TestEscapeAndEncode(t *testing.T) {
	if got := escape(`a(b)\c`); got != `a\(b\)\\c` {
		t.Errorf("got %s", got)
	}
	if got := escape("äé€✓"); got != `\344\351\200?` {
		t.Errorf("got %s", got)
	}
	if got := string(encode("a\x00b\x1b")); got != "ab" {
		t.Errorf("control characters not dropped: %q", got)
	}
}

// TestCrossReferences checks that every xref entry points at its object.
func TestCrossReferences(t *testing.T) {
	d := New()
	d.Title = "T (1)"
	d.AddPage()
	d.Text(10, 10, Helvetica, 12, Color{}, "hello")
	d.Link(10, 10, 50, 12, "https://example.org")
	d.AddPage()
	d.Rect(10, 10, 50, 50, &Color{R: 255}, &Color{})
	d.SetPage(1)
	d.Line(0, 0, 10, 10, 1, Color{})
	var b bytes.Buffer
	if err := d.Write(&b); err != nil {
		t.Fatal(err)
	}
	out := b.Bytes()
	m := regexp.MustCompile(`startxref\n(\d+)\n%%EOF\n$`).FindSubmatch(out)
	if m == nil {
		t.Fatal("no startxref")
	}
	xref, _ := strconv.Atoi(string(m[1]))
	if !bytes.HasPrefix(out[xref:], []byte("xref\n")) {
		t.Fatal("startxref does not point at the xref table")
	}
	entries := regexp.MustCompile(`(\d{10}) 00000 n `).FindAllSubmatch(out[xref:], -1)
	if len(entries) == 0 {
		t.Fatal("no xref entries")
	}
	for i, e := range entries {
		off, _ := strconv.Atoi(string(e[1]))
		want := fmt.Sprintf("%d 0 obj", i+1)
		if !bytes.HasPrefix(out[off:], []byte(want)) {
			t.Errorf("entry %d points at %q", i+1, out[off:off+12])
		}
	}
	if !bytes.Contains(out, []byte("/Count 2")) || !bytes.Contains(out, []byte("/URI (https://example.org)")) {
		t.Error("page tree or link missing")
	}
}
