// Command manifest writes internal/provenance/shipped.sha256: the hashes
// of all policies shipped with checkmate, which the binary uses to tell a
// shipped policy from a changed or foreign one.
//
//	go run ./tools/manifest
package main

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rtulke/checkmate/internal/provenance"
)

// Roots are the directories whose policies are shipped.
var Roots = []string{"cis", "stig", "examples"}

// Build returns the manifest for the policies below dir.
func Build(dir string) (string, error) {
	var lines []string
	for _, root := range Roots {
		err := filepath.WalkDir(filepath.Join(dir, root), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".yml") {
				return err
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(dir, path)
			if err != nil {
				return err
			}
			lines = append(lines, provenance.Hash(data)+"  "+filepath.ToSlash(rel))
			return nil
		})
		if err != nil {
			return "", err
		}
	}
	sort.Slice(lines, func(i, j int) bool { return lines[i][66:] < lines[j][66:] })
	return "# SHA-256 of the policies shipped with checkmate, written by tools/manifest.\n" +
		strings.Join(lines, "\n") + "\n", nil
}

func main() {
	out, err := Build(".")
	if err == nil {
		err = os.WriteFile(filepath.Join("internal", "provenance", "shipped.sha256"), []byte(out), 0o644)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "manifest:", err)
		os.Exit(1)
	}
}
