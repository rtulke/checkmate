// Package pdf writes simple PDF documents: text in the standard Helvetica
// and Courier fonts, lines and filled rectangles. It needs no font files,
// since the standard fonts are built into every PDF viewer, and is just
// large enough for checkmate's reports.
//
// Coordinates are in points (1/72 inch) with the origin at the top-left
// corner of the page; y grows downwards.
package pdf

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
	"strings"
	"time"
)

// Font is one of the standard fonts.
type Font int

const (
	Helvetica Font = iota
	HelveticaBold
	Courier
)

var fontNames = [...]string{"Helvetica", "Helvetica-Bold", "Courier"}

// A4 page size in points.
const (
	A4Width  = 595.28
	A4Height = 841.89
)

// Color is an RGB color with components from 0 to 255.
type Color struct{ R, G, B uint8 }

func (c Color) op(stroke bool) string {
	op := "rg"
	if stroke {
		op = "RG"
	}
	return fmt.Sprintf("%s %s %s %s", num(float64(c.R)/255), num(float64(c.G)/255), num(float64(c.B)/255), op)
}

// Doc is a PDF document under construction.
type Doc struct {
	Width, Height float64
	Title         string
	Author        string
	Created       time.Time
	pages         []*bytes.Buffer
	links         map[int][]link
	current       int  // page drawing goes to if selected
	selected      bool // SetPage was called
}

// New returns an empty A4 portrait document.
func New() *Doc {
	return &Doc{Width: A4Width, Height: A4Height, Created: time.Now()}
}

// AddPage starts a new page; drawing goes to the newest page.
func (d *Doc) AddPage() {
	d.pages = append(d.pages, &bytes.Buffer{})
	d.selected = false
}

// Pages returns the number of pages.
func (d *Doc) Pages() int { return len(d.pages) }

// SetPage makes page n (1-based) the page drawing goes to, e.g. to add
// footers once the total page count is known.
func (d *Doc) SetPage(n int) {
	if n < 1 || n > len(d.pages) {
		return
	}
	d.current = n - 1
	d.selected = true
}

func (d *Doc) cur() *bytes.Buffer {
	if len(d.pages) == 0 {
		d.AddPage()
	}
	if d.selected {
		return d.pages[d.current]
	}
	return d.pages[len(d.pages)-1]
}

// Text draws s with its baseline at (x, y).
func (d *Doc) Text(x, y float64, f Font, size float64, c Color, s string) {
	fmt.Fprintf(d.cur(), "BT %s /F%d %s Tf %s %s Td (%s) Tj ET\n",
		c.op(false), int(f)+1, num(size), num(x), num(d.Height-y), escape(s))
}

// Rect draws a rectangle with its top-left corner at (x, y), filled with
// fill if fill is non-nil and outlined with stroke if stroke is non-nil.
func (d *Doc) Rect(x, y, w, h float64, fill, stroke *Color) {
	if fill == nil && stroke == nil {
		return
	}
	b := d.cur()
	op := "S"
	if fill != nil {
		b.WriteString(fill.op(false) + " ")
		op = "f"
	}
	if stroke != nil {
		b.WriteString(stroke.op(true) + " 0.5 w ")
		if fill != nil {
			op = "B"
		}
	}
	fmt.Fprintf(b, "%s %s %s %s re %s\n", num(x), num(d.Height-y-h), num(w), num(h), op)
}

// Line draws a line of the given width.
func (d *Doc) Line(x1, y1, x2, y2, width float64, c Color) {
	fmt.Fprintf(d.cur(), "%s %s w %s %s m %s %s l S\n",
		c.op(true), num(width), num(x1), num(d.Height-y1), num(x2), num(d.Height-y2))
}

// Link makes the rectangle with top-left corner (x, y) a link to uri.
func (d *Doc) Link(x, y, w, h float64, uri string) {
	if d.links == nil {
		d.links = map[int][]link{}
	}
	p := len(d.pages) - 1
	if d.selected {
		p = d.current
	}
	d.links[p] = append(d.links[p], link{x, d.Height - y - h, x + w, d.Height - y, uri})
}

type link struct {
	x1, y1, x2, y2 float64
	uri            string
}

// Width returns the width of s in font f at the given size.
func Width(f Font, size float64, s string) float64 {
	var units int
	for _, b := range encode(s) {
		switch f {
		case Courier:
			units += 600
		case HelveticaBold:
			units += int(helveticaBoldWidths[b])
		default:
			units += int(helveticaWidths[b])
		}
	}
	return float64(units) * size / 1000
}

// Wrap breaks s into lines no wider than width. Explicit newlines are
// kept; words longer than a line are split.
func Wrap(f Font, size float64, s string, width float64) []string {
	var lines []string
	for _, para := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		para = strings.ReplaceAll(para, "\t", "    ")
		if f != Courier {
			para = strings.Join(strings.Fields(para), " ")
		}
		if para == "" {
			lines = append(lines, "")
			continue
		}
		line := ""
		for _, word := range splitKeep(para, f == Courier) {
			candidate := line + word
			if Width(f, size, candidate) <= width {
				line = candidate
				continue
			}
			if strings.TrimSpace(line) != "" {
				lines = append(lines, strings.TrimRight(line, " "))
				line = ""
				word = strings.TrimLeft(word, " ")
				if f == Courier && strings.TrimSpace(word) == "" {
					continue
				}
			}
			// The word alone may still be too long: split it by runes.
			for Width(f, size, word) > width {
				cut := fitRunes(f, size, word, width)
				lines = append(lines, word[:cut])
				word = word[cut:]
			}
			line = word
		}
		lines = append(lines, strings.TrimRight(line, " "))
	}
	return lines
}

// splitKeep splits s into words that keep their trailing spaces. With
// keepSpaces, runs of spaces are preserved (for preformatted text).
func splitKeep(s string, keepSpaces bool) []string {
	var words []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' && (i+1 == len(s) || s[i+1] != ' ' || !keepSpaces) {
			words = append(words, s[start:i+1])
			start = i + 1
		}
	}
	if start < len(s) {
		words = append(words, s[start:])
	}
	return words
}

// fitRunes returns the byte length of the longest prefix of s (at least one
// rune) that fits into width.
func fitRunes(f Font, size float64, s string, width float64) int {
	cut := 0
	for i, r := range s {
		next := i + len(string(r))
		if cut > 0 && Width(f, size, s[:next]) > width {
			break
		}
		cut = next
	}
	return cut
}

// Write writes the finished document.
func (d *Doc) Write(w io.Writer) error {
	if len(d.pages) == 0 {
		d.AddPage()
	}
	var out bytes.Buffer
	var offsets []int
	obj := func(body string) int {
		offsets = append(offsets, out.Len())
		n := len(offsets)
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", n, body)
		return n
	}
	out.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")

	// Object 1 is the catalog, object 2 the page tree; the page tree is
	// written last, when its kids are known, and found via the xref table.
	catalog := obj("<< /Type /Catalog /Pages 2 0 R >>")
	offsets = append(offsets, 0)
	pageTree := len(offsets)

	var fonts []string
	for i, name := range fontNames {
		n := obj(fmt.Sprintf("<< /Type /Font /Subtype /Type1 /BaseFont /%s /Encoding /WinAnsiEncoding >>", name))
		fonts = append(fonts, fmt.Sprintf("/F%d %d 0 R", i+1, n))
	}
	resources := "<< /Font << " + strings.Join(fonts, " ") + " >> >>"

	var kids []string
	for i, page := range d.pages {
		var z bytes.Buffer
		zw := zlib.NewWriter(&z)
		zw.Write(page.Bytes())
		zw.Close()
		offsets = append(offsets, out.Len())
		content := len(offsets)
		fmt.Fprintf(&out, "%d 0 obj\n<< /Length %d /Filter /FlateDecode >>\nstream\n", content, z.Len())
		out.Write(z.Bytes())
		out.WriteString("\nendstream\nendobj\n")

		annots := ""
		var refs []string
		for _, l := range d.links[i] {
			n := obj(fmt.Sprintf("<< /Type /Annot /Subtype /Link /Rect [%s %s %s %s] /Border [0 0 0] /A << /S /URI /URI (%s) >> >>",
				num(l.x1), num(l.y1), num(l.x2), num(l.y2), escape(l.uri)))
			refs = append(refs, fmt.Sprintf("%d 0 R", n))
		}
		if len(refs) > 0 {
			annots = " /Annots [" + strings.Join(refs, " ") + "]"
		}
		n := obj(fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %s %s] /Resources %s /Contents %d 0 R%s >>",
			num(d.Width), num(d.Height), resources, content, annots))
		kids = append(kids, fmt.Sprintf("%d 0 R", n))
	}

	offsets[pageTree-1] = out.Len()
	fmt.Fprintf(&out, "%d 0 obj\n<< /Type /Pages /Kids [%s] /Count %d >>\nendobj\n",
		pageTree, strings.Join(kids, " "), len(kids))

	info := obj(fmt.Sprintf("<< /Title (%s) /Author (%s) /Producer (checkmate) /CreationDate (D:%s) >>",
		escape(d.Title), escape(d.Author), d.Created.UTC().Format("20060102150405Z")))

	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets)+1)
	for _, off := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root %d 0 R /Info %d 0 R >>\nstartxref\n%d\n%%%%EOF\n",
		len(offsets)+1, catalog, info, xref)
	_, err := w.Write(out.Bytes())
	return err
}

// num formats a number compactly with at most two decimals.
func num(f float64) string {
	s := fmt.Sprintf("%.2f", f)
	s = strings.TrimRight(strings.TrimRight(s, "0"), ".")
	if s == "-0" || s == "" {
		return "0"
	}
	return s
}

// winAnsi maps the runes of the 0x80-0x9F range of Windows-1252.
var winAnsi = map[rune]byte{
	'€': 0x80, '‚': 0x82, 'ƒ': 0x83, '„': 0x84, '…': 0x85, '†': 0x86, '‡': 0x87, 'ˆ': 0x88,
	'‰': 0x89, 'Š': 0x8a, '‹': 0x8b, 'Œ': 0x8c, 'Ž': 0x8e, '‘': 0x91, '’': 0x92, '“': 0x93,
	'”': 0x94, '•': 0x95, '–': 0x96, '—': 0x97, '˜': 0x98, '™': 0x99, 'š': 0x9a, '›': 0x9b,
	'œ': 0x9c, 'ž': 0x9e, 'Ÿ': 0x9f,
}

// encode converts s to WinAnsiEncoding; runes it cannot represent become
// "?" and control characters are dropped.
func encode(s string) []byte {
	out := make([]byte, 0, len(s))
	for _, r := range s {
		switch {
		case r == '\t':
			out = append(out, ' ')
		case r < 0x20 || r == 0x7f:
		case r < 0x80, r >= 0xa0 && r <= 0xff:
			out = append(out, byte(r))
		default:
			if b, ok := winAnsi[r]; ok {
				out = append(out, b)
			} else {
				out = append(out, '?')
			}
		}
	}
	return out
}

// escape encodes s as the body of a PDF literal string.
func escape(s string) string {
	var b strings.Builder
	for _, c := range encode(s) {
		switch {
		case c == '(' || c == ')' || c == '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		case c >= 0x80:
			fmt.Fprintf(&b, "\\%03o", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
