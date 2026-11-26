// Package provenance says where a policy file comes from.
//
// A policy is code that runs as root, so it matters whether a file is one
// that was shipped with this checkmate, a changed copy of one, or a file
// of your own. The SHA-256 hashes of all shipped policies are built into
// the binary (shipped.sha256, written by tools/manifest); trust in them is
// trust in the binary, which is verified through its package or checksum.
package provenance

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"path/filepath"
	"strings"
)

//go:embed shipped.sha256
var manifest string

// Manifest returns the built-in list of shipped policies, with Unix line
// ends also where a checkout converted them.
func Manifest() string { return strings.ReplaceAll(manifest, "\r\n", "\n") }

// Origins of a file.
const (
	Shipped  = "shipped"  // shipped with this checkmate, unchanged
	Modified = "modified" // has the path of a shipped policy but other content
	Local    = "local"    // not shipped with this checkmate
)

// Source describes one file a policy was loaded from.
type Source struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Origin string `json:"origin"` // shipped, modified or local
	// Shipped is the path of the file in the checkmate sources, for shipped
	// and modified files.
	Shipped string `json:"shipped,omitempty"`
	// Signer is the name of the trusted key that signed the file; Signature
	// says why there is none: "", "invalid", "unknown key".
	Signer    string `json:"signer,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// Trusted reports whether the content of the file is vouched for: by this
// checkmate, or by a signature of a trusted key.
func (s Source) Trusted() bool { return s.Origin == Shipped || s.Signer != "" }

var (
	byHash = map[string]string{} // hash -> shipped path
	paths  []string              // shipped paths
)

func init() {
	for _, line := range strings.Split(manifest, "\n") {
		hash, path, ok := strings.Cut(strings.TrimSpace(line), "  ")
		if !ok || strings.HasPrefix(hash, "#") {
			continue
		}
		byHash[hash] = path
		paths = append(paths, path)
	}
}

// Hash returns the SHA-256 of a text file as shipped: with Unix line ends.
// A checkout on Windows may have converted them, which changes neither the
// policy nor where it comes from.
func Hash(data []byte) string {
	sum := sha256.Sum256(bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n")))
	return hex.EncodeToString(sum[:])
}

// Lookup classifies a file by its content and, if the content is not known,
// by its path.
func Lookup(path string, data []byte) Source {
	s := Source{Path: path, SHA256: Hash(data), Origin: Local}
	if shipped, ok := byHash[s.SHA256]; ok {
		s.Origin, s.Shipped = Shipped, shipped
		return s
	}
	// The same place as a shipped policy (cis/rhel9.yml), other content:
	// most likely an edited copy, and worth saying so.
	slashed := filepath.ToSlash(path)
	for _, shipped := range paths {
		if slashed == shipped || strings.HasSuffix(slashed, "/"+shipped) {
			s.Origin, s.Shipped = Modified, shipped
			return s
		}
	}
	return s
}

// Summary describes the files of a policy in one line.
func Summary(sources []Source) string {
	count := map[string]int{}
	signed := 0
	for _, s := range sources {
		count[s.Origin]++
		if s.Origin != Shipped && s.Signer != "" {
			signed++
		}
	}
	plural := func(n int, one, many string) string {
		if n == 1 {
			return "1 " + one
		}
		return itoa(n) + " " + many
	}
	var parts []string
	if n := count[Shipped]; n > 0 {
		parts = append(parts, plural(n, "file", "files")+" shipped with checkmate, unchanged")
	}
	if n := count[Modified]; n > 0 {
		parts = append(parts, plural(n, "shipped file", "shipped files")+" modified")
	}
	if n := count[Local]; n > 0 {
		parts = append(parts, plural(n, "file", "files")+" of your own")
	}
	out := strings.Join(parts, ", ")
	if signed > 0 {
		out += " (" + plural(signed, "signed", "signed") + ")"
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for ; n > 0; n /= 10 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
	}
	return string(digits)
}
