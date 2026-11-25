package main

import (
	"reflect"
	"testing"
)

func TestExtraVarValue(t *testing.T) {
	cases := []struct {
		raw  string
		want any
	}{
		{"8080", 8080},
		{"-1", -1},
		{"1.5", 1.5},
		{"true", true},
		{"false", false},
		{"[22, 443]", []any{22, 443}},
		{"{a: b}", map[string]any{"a": "b"}},
		{"hello world", "hello world"},
		{"", ""},
		// Values that YAML would silently change stay as typed.
		{"1.10", "1.10"},
		{"1.0", "1.0"},
		{"0644", "0644"},
		{"0o644", "0o644"},
		{"0x1F", "0x1F"},
		{"1e3", "1e3"},
		{"1_000", "1_000"},
		{"+5", "+5"},
		{".5", ".5"},
		{".inf", ".inf"},
		{".nan", ".nan"},
		{"null", "null"},
		{"~", "~"},
		{"2026-01-31", "2026-01-31"},
		{"12345678901234567890123", "12345678901234567890123"},
		{"a: b: c", "a: b: c"},
		{"*alias", "*alias"},
		{"'quoted'", "'quoted'"},
	}
	for _, c := range cases {
		if got := extraVarValue(c.raw); !reflect.DeepEqual(got, c.want) {
			t.Errorf("extraVarValue(%q) = %#v (%T), want %#v", c.raw, got, got, c.want)
		}
	}
}

func TestExtraVarsNeedKeyAndValue(t *testing.T) {
	for _, kv := range []string{"novalue", "=x", " =x"} {
		c := commonFlags{extraVars: []string{kv}}
		if _, err := c.vars(); err == nil {
			t.Errorf("vars() accepted %q", kv)
		}
	}
	c := commonFlags{extraVars: []string{"a=b=c", " k =1.10"}}
	got, err := c.vars()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{"a": "b=c", "k": "1.10"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("vars() = %#v, want %#v", got, want)
	}
}
