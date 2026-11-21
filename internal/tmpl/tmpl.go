// Package tmpl renders Jinja2 templates and evaluates Jinja2 expressions.
//
// Two deliberate deviations from stock Jinja2 keep shell commands intact:
//   - comments use {## ... ##} instead of {# ... #}, so shell code such as
//     ${#array} is not mistaken for a comment;
//   - undefined variables are an error (strict mode), so typos fail loudly
//     instead of silently rendering an empty string.
package tmpl

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/nikolalohinski/gonja/v2"
	"github.com/nikolalohinski/gonja/v2/config"
	"github.com/nikolalohinski/gonja/v2/exec"
	"github.com/nikolalohinski/gonja/v2/loaders"
)

func init() {
	gonja.SetLoggerOutput(io.Discard)
}

func newConfig() *config.Config {
	cfg := config.New()
	cfg.StrictUndefined = true
	cfg.KeepTrailingNewline = true
	cfg.CommentStartString = "{##"
	cfg.CommentEndString = "##}"
	return cfg
}

// HasTemplate reports whether s contains template syntax.
func HasTemplate(s string) bool {
	return strings.Contains(s, "{{") || strings.Contains(s, "{%")
}

// Render renders src with the given context. Strings without template
// syntax are returned unchanged.
func Render(src string, ctx map[string]any) (string, error) {
	if !HasTemplate(src) {
		return src, nil
	}
	// A memory loader without entries disables {% include %} and friends,
	// so templates cannot read arbitrary files.
	mem, err := loaders.NewMemoryLoader(map[string]string{})
	if err != nil {
		return "", err
	}
	loader, err := loaders.NewShiftedLoader("template", bytes.NewReader([]byte(src)), mem)
	if err != nil {
		return "", err
	}
	tpl, err := exec.NewTemplate("template", newConfig(), loader, gonja.DefaultEnvironment)
	if err != nil {
		return "", fmt.Errorf("template %q: %w", abbreviate(src), err)
	}
	out, err := tpl.ExecuteToString(exec.NewContext(ctx))
	if err != nil {
		return "", fmt.Errorf("template %q: %w", abbreviate(src), err)
	}
	return out, nil
}

// Eval evaluates a Jinja2 expression (as used in `when`) to a boolean.
func Eval(expr string, ctx map[string]any) (bool, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return true, nil
	}
	out, err := Render("{% if "+expr+" %}1{% else %}0{% endif %}", ctx)
	if err != nil {
		return false, fmt.Errorf("expression %q: %w", expr, unwrapTemplateErr(err))
	}
	return out == "1", nil
}

// unwrapTemplateErr returns the innermost error, which carries the useful
// message without repeating the wrapped template source.
func unwrapTemplateErr(err error) error {
	for {
		inner := errors.Unwrap(err)
		if inner == nil {
			return err
		}
		err = inner
	}
}

func abbreviate(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 60 {
		return s[:57] + "..."
	}
	return s
}
