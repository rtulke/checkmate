package provenance

import (
	"os"
	"strings"
	"testing"
)

func TestLookup(t *testing.T) {
	data, err := os.ReadFile("../../examples/getting-started.yml")
	if err != nil {
		t.Fatal(err)
	}
	// The checkout itself may have Windows line ends.
	data = []byte(strings.ReplaceAll(string(data), "\r\n", "\n"))
	// Known content is shipped wherever the file lies, also with the line
	// ends of a checkout on Windows.
	for _, path := range []string{"examples/getting-started.yml", "/tmp/copy.yml", `C:\policies\gs.yml`} {
		for _, content := range [][]byte{data, []byte(strings.ReplaceAll(string(data), "\n", "\r\n"))} {
			s := Lookup(path, content)
			if s.Origin != Shipped || s.Shipped != "examples/getting-started.yml" || !s.Trusted() || len(s.SHA256) != 64 {
				t.Errorf("%s: %+v", path, s)
			}
		}
	}
	changed := append([]byte("# edited\n"), data...)
	for path, want := range map[string]string{
		"/usr/share/checkmate/examples/getting-started.yml": Modified,
		"examples/getting-started.yml":                      Modified,
		"/srv/policies/getting-started.yml":                 Local,
		"/srv/my-examples/getting-started.yml":              Local,
		"/srv/xexamples/getting-started.yml":                Local,
	} {
		s := Lookup(path, changed)
		if s.Origin != want || s.Trusted() {
			t.Errorf("%s: origin %s, want %s", path, s.Origin, want)
		}
	}
}

func TestSummary(t *testing.T) {
	for want, sources := range map[string][]Source{
		"1 file shipped with checkmate, unchanged":                                               {{Origin: Shipped}},
		"2 files shipped with checkmate, unchanged, 1 shipped file modified, 1 file of your own": {{Origin: Shipped}, {Origin: Shipped}, {Origin: Modified}, {Origin: Local}},
		"3 files of your own (2 signed)":                                                         {{Origin: Local, Signer: "ops"}, {Origin: Local, Signer: "ops"}, {Origin: Local}},
		"":                                                                                       nil,
	} {
		if got := Summary(sources); got != want {
			t.Errorf("Summary = %q, want %q", got, want)
		}
	}
}

func TestManifestIsWellFormed(t *testing.T) {
	if len(paths) < 90 || len(byHash) < 90 {
		t.Fatalf("%d paths, %d hashes in the built-in manifest", len(paths), len(byHash))
	}
	for hash, path := range byHash {
		if len(hash) != 64 || strings.ContainsAny(path, `\ `) || !strings.HasSuffix(path, ".yml") {
			t.Errorf("entry %q %q", hash, path)
		}
	}
}
