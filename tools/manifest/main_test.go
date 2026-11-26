package main

import (
	"testing"

	"github.com/rtulke/checkmate/internal/provenance"
)

// The hashes built into the binary must be those of the policies in the
// tree, or a shipped policy would be reported as modified.
func TestManifestIsUpToDate(t *testing.T) {
	want, err := Build("../..")
	if err != nil {
		t.Fatal(err)
	}
	if provenance.Manifest() != want {
		t.Error("internal/provenance/shipped.sha256 is out of date; run: go run ./tools/manifest (or make manifest)")
	}
}
