package tmpl

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestRender(t *testing.T) {
	ctx := map[string]any{
		"name":  "sshd",
		"port":  22,
		"ports": []any{22, 443},
		"facts": map[string]any{"os": "linux", "version_major": 9},
		"item":  map[string]any{"key": "a", "value": "b c"},
	}
	for src, want := range map[string]string{
		"plain text":                      "plain text",
		"{{ name }}":                      "sshd",
		"{{ name | upper }}-{{ port }}":   "SSHD-22",
		"{{ ports | join(',') }}":         "22,443",
		"{{ facts.os }}/{{ item.value }}": "linux/b c",
		"{% if facts.version_major >= 9 %}new{% else %}old{% endif %}": "new",
		"{% for p in ports %}-e {{ p }} {% endfor %}":                  "-e 22 -e 443 ",
		"{{ undefined_name | default('x') }}":                          "x",
		"{{ 'a:b'.split(':')[1] }}":                                    "b",
		"awk '{print $1}' # no template":                               "awk '{print $1}' # no template",
		"{% raw %}{{ .State }}{% endraw %}":                            "{{ .State }}",
		"line one\n{{ name }}\n":                                       "line one\nsshd\n",
	} {
		got, err := Render(src, ctx)
		if err != nil || got != want {
			t.Errorf("Render(%q) = %q, %v; want %q", src, got, err, want)
		}
	}
}

func TestRenderErrors(t *testing.T) {
	for src, want := range map[string]string{
		"{{ missing }}":         "missing",
		"{{ name.nope.deep }}":  "",
		"{{ name | nofilter }}": "nofilter",
		"{% if %}x{% endif %}":  "",
		"{{ unclosed":           "",
	} {
		_, err := Render(src, map[string]any{"name": "x"})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("Render(%q): error %v, want one mentioning %q", src, err, want)
		}
	}
	// Templates cannot read files.
	for _, src := range []string{`{% include "/etc/passwd" %}`, `{% extends "/etc/passwd" %}`, `{% import "/etc/passwd" as p %}`} {
		if out, err := Render(src, nil); err == nil {
			t.Errorf("Render(%q) = %q, want an error", src, out)
		}
	}
}

func TestEval(t *testing.T) {
	ctx := map[string]any{"facts": map[string]any{"os": "linux", "is_root": false, "distro_like": []any{"rhel", "fedora"}}, "n": 3}
	for expr, want := range map[string]bool{
		"":                            true,
		"  ":                          true,
		`facts.os == "linux"`:         true,
		`facts.os == "darwin"`:        false,
		`"rhel" in facts.distro_like`: true,
		"not facts.is_root":           true,
		"n > 2 and n < 4":             true,
		"n > 5 or facts.is_root":      false,
	} {
		got, err := Eval(expr, ctx)
		if err != nil || got != want {
			t.Errorf("Eval(%q) = %v, %v; want %v", expr, got, err, want)
		}
	}
	if _, err := Eval("nothing.here == 1", ctx); err == nil || !strings.Contains(err.Error(), `expression "nothing.here == 1"`) {
		t.Errorf("undefined name: %v", err)
	}
	if _, err := Eval("n >", ctx); err == nil {
		t.Error("a broken expression was accepted")
	}
}

func TestHasTemplate(t *testing.T) {
	for s, want := range map[string]bool{"{{ x }}": true, "{% if x %}": true, "awk '{print}'": false, "a { b } c": false, "": false} {
		if HasTemplate(s) != want {
			t.Errorf("HasTemplate(%q) = %v", s, !want)
		}
	}
}

func TestCutKeepsCharactersWhole(t *testing.T) {
	s := "aä€日本"
	for n := 0; n <= len(s)+1; n++ {
		got := Cut(s, n)
		if !utf8.ValidString(got) || len(got) > n || !strings.HasPrefix(s, got) {
			t.Errorf("Cut(%q, %d) = %q", s, n, got)
		}
	}
	if Cut("abc", 5) != "abc" || Cut("abc", 2) != "ab" {
		t.Error("ASCII is cut at the wrong place")
	}
	// The messages that quote a template are cut the same way.
	_, err := Render("{{ "+strings.Repeat("ä", 60)+" }}", nil)
	if err == nil || !utf8.ValidString(err.Error()) {
		t.Errorf("error is not valid UTF-8: %v", err)
	}
}
