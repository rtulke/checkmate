package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignVerifyAndRequire(t *testing.T) {
	dir := t.TempDir()
	writeFiles(t, dir, map[string]string{
		"p.yml":    "name: Signed\ninclude: [inc.yml]\nvars_files: [vars.yml]\nchecks:\n  - {id: A, run: \"echo {{ word }}\", expect: ok}\n",
		"inc.yml":  "checks:\n  - {id: B, run: \"echo ok\", expect: ok}\n",
		"vars.yml": "word: ok\n",
	})
	p := func(name string) string { return filepath.Join(dir, name) }
	call := func(args ...string) (int, string) {
		var out, errOut bytes.Buffer
		code := run(args, &out, &errOut)
		return code, out.String() + errOut.String()
	}

	if code, out := call("keygen", "-o", p("ops"), "ops"); code != 0 {
		t.Fatalf("keygen: %d %s", code, out)
	}
	if info, err := os.Stat(p("ops.key")); err != nil || info.Mode().Perm()&0o077 != 0 && os.PathSeparator == '/' {
		t.Errorf("private key file: %v, %v", info, err)
	}
	// A key is never overwritten.
	if code, out := call("keygen", "-o", p("ops"), "ops"); code != exitUsage || !strings.Contains(out, "exist") {
		t.Errorf("second keygen: %d %s", code, out)
	}
	trust := []string{"--allow-insecure-policy", "--trusted-keys", p("ops.pub")}
	with := func(cmd string, extra ...string) []string {
		return append(append([]string{cmd}, trust...), extra...)
	}

	// Nothing is signed yet.
	if code, out := call(with("verify", p("p.yml"))...); code != exitNotCompliant || !strings.Contains(out, "3 of 3 files") {
		t.Errorf("verify unsigned: %d %s", code, out)
	}
	if code, out := call(with("run", "--require-signed", p("p.yml"))...); code != exitUsage || !strings.Contains(out, "it has no signature") {
		t.Errorf("run unsigned with --require-signed: %d %s", code, out)
	}
	// Without the requirement own policies run as always.
	if code, out := call(with("run", p("p.yml"))...); code != 0 || !strings.Contains(out, "3 files of your own") {
		t.Errorf("run unsigned: %d %s", code, out)
	}

	// The policy alone is not enough: included and variable files count.
	if code, out := call("sign", "--key", p("ops.key"), p("p.yml")); code != 0 || !strings.Contains(out, "signed ") {
		t.Fatalf("sign: %d %s", code, out)
	}
	if code, out := call(with("run", "--require-signed", p("p.yml"))...); code != exitUsage || !strings.Contains(out, "inc.yml") {
		t.Errorf("included file unsigned: %d %s", code, out)
	}
	if code, out := call("sign", "--key", p("ops.key"), p("inc.yml"), p("vars.yml")); code != 0 {
		t.Fatalf("sign: %d %s", code, out)
	}
	if code, out := call(with("verify", p("p.yml"))...); code != 0 || strings.Count(out, "signed by ops") != 3 {
		t.Errorf("verify signed: %d %s", code, out)
	}
	code, out := call(with("run", "--require-signed", "--format", "json", p("p.yml"))...)
	if code != 0 || strings.Count(out, `"signer": "ops"`) != 3 || !strings.Contains(out, `"origin": "local"`) {
		t.Errorf("run signed: %d %s", code, out)
	}
	t.Setenv("CHECKMATE_REQUIRE_SIGNED", "1")
	if code, out := call("run", "--allow-insecure-policy", p("p.yml")); code != exitUsage || !strings.Contains(out, "not usable (unknown key)") {
		t.Errorf("required by the environment, no trusted keys: %d %s", code, out)
	}
	t.Setenv("CHECKMATE_REQUIRE_SIGNED", "")

	// A file changed after signing is refused even when nothing is required.
	if err := os.WriteFile(p("vars.yml"), []byte("word: ok # edited\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range []string{"run", "validate", "list", "verify"} {
		if code, out := call(with(cmd, p("p.yml"))...); code != exitUsage || !strings.Contains(out, "changed after it was signed") {
			t.Errorf("%s with an edited file: %d %s", cmd, code, out)
		}
	}

	// Shipped policies need no signature.
	if code, out := call(with("run", "--require-signed", "--id", "GS-001", "../../examples/getting-started.yml")...); code == exitUsage && strings.Contains(out, "refusing") {
		t.Errorf("a shipped policy was refused: %s", out)
	}
	// A waiver file is held to the same rule.
	writeFiles(t, dir, map[string]string{"w.yml": "waivers:\n  - {id: A, reason: accepted}\n"})
	os.WriteFile(p("vars.yml"), []byte("word: ok\n"), 0o600)
	if code, out := call(with("run", "--require-signed", "--waivers", p("w.yml"), p("p.yml"))...); code != exitUsage || !strings.Contains(out, "w.yml") {
		t.Errorf("unsigned waiver file: %d %s", code, out)
	}

	if code, out := call("sign", p("p.yml")); code != exitUsage {
		t.Errorf("sign without a key: %d %s", code, out)
	}
	if code, out := call("sign", "--key", p("ops.pub"), p("p.yml")); code != exitUsage || !strings.Contains(out, "private key") {
		t.Errorf("sign with a public key: %d %s", code, out)
	}
	if code, out := call("run", "--allow-insecure-policy", "--trusted-keys", p("p.yml"), p("p.yml")); code != exitUsage || !strings.Contains(out, "line 1") {
		t.Errorf("a trust file that is none: %d %s", code, out)
	}
}
