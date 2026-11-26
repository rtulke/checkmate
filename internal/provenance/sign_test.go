package provenance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSignAndVerify(t *testing.T) {
	private, public, err := GenerateKey("release-team")
	if err != nil {
		t.Fatal(err)
	}
	other, otherPublic, _ := GenerateKey("someone-else")
	trusted, err := ParseTrustedKeys([]byte("# keys\n\n" + public))
	if err != nil || len(trusted) != 1 || trusted[0].Name != "release-team" {
		t.Fatalf("trusted keys: %v, %v", trusted, err)
	}
	content := []byte("name: Policy\nchecks: []\n")
	sig, err := Sign([]byte(private), content)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sig, "checkmate-signature ed25519 "+trusted[0].ID()+" ") || strings.Count(sig, "\n") != 1 {
		t.Errorf("signature file %q", sig)
	}

	if signer, state := Verify(content, []byte(sig), trusted); signer != "release-team" || state != "" {
		t.Errorf("valid signature: %q, %q", signer, state)
	}
	// Line ends of a checkout on Windows do not change what was signed.
	if signer, _ := Verify([]byte("name: Policy\r\nchecks: []\r\n"), []byte(sig), trusted); signer != "release-team" {
		t.Error("CRLF line ends invalidate the signature")
	}
	// One changed byte does.
	if signer, state := Verify([]byte("name: policy\nchecks: []\n"), []byte(sig), trusted); signer != "" || state != SignatureInvalid {
		t.Errorf("changed content: %q, %q", signer, state)
	}
	// A valid signature of a key nobody trusts says nothing.
	foreign, _ := Sign([]byte(other), content)
	if signer, state := Verify(content, []byte(foreign), trusted); signer != "" || state != SignatureUnknownKey {
		t.Errorf("foreign key: %q, %q", signer, state)
	}
	both, _ := ParseTrustedKeys([]byte(public + otherPublic))
	if signer, _ := Verify(content, []byte(foreign), both); signer != "someone-else" {
		t.Errorf("second trusted key: %q", signer)
	}
	// A signature of a trusted key cannot be relabelled to another key.
	relabelled := strings.Replace(foreign, both[1].ID(), both[0].ID(), 1)
	if signer, state := Verify(content, []byte(relabelled), both); signer != "" || state != SignatureInvalid {
		t.Errorf("relabelled signature: %q, %q", signer, state)
	}
	for _, bad := range []string{"", "garbage", "checkmate-signature ed25519 abc", "checkmate-signature rsa abc def",
		"checkmate-signature ed25519 " + trusted[0].ID() + " AAAA", strings.Replace(sig, "checkmate-signature", "checkmate-key", 1)} {
		if signer, state := Verify(content, []byte(bad), trusted); signer != "" || state != SignatureMalformed {
			t.Errorf("%q: %q, %q", bad, signer, state)
		}
	}
}

func TestKeyFiles(t *testing.T) {
	private, public, err := GenerateKey("ops@example.net")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(private, "checkmate-private-key ed25519 ") || !strings.HasPrefix(public, "checkmate-key ed25519 ") {
		t.Errorf("key files:\n%s%s", private, public)
	}
	// The private key file is not a public key, and the other way round.
	if _, err := ParseTrustedKeys([]byte(private)); err == nil {
		t.Error("a private key was accepted as a trusted key")
	}
	if _, err := Sign([]byte(public), []byte("x")); err == nil {
		t.Error("a public key was accepted for signing")
	}
	for _, name := range []string{"", "two words", "-dash", "semi;colon"} {
		if _, _, err := GenerateKey(name); err == nil {
			t.Errorf("key name %q accepted", name)
		}
	}
	if _, err := ParseTrustedKeys([]byte("checkmate-key ed25519 AAAA name\n")); err == nil || !strings.Contains(err.Error(), "line 1") {
		t.Errorf("short key: %v", err)
	}
}

func TestSourceWithSignature(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "p.yml")
	content := []byte("checks: []\n")
	private, public, _ := GenerateKey("ops")
	trusted, _ := ParseTrustedKeys([]byte(public))

	s := Lookup(path, content).WithSignature(content, trusted)
	if s.Signer != "" || s.Signature != "" || s.Trusted() {
		t.Errorf("without a signature file: %+v", s)
	}
	sig, _ := Sign([]byte(private), content)
	if err := os.WriteFile(path+SignatureSuffix, []byte(sig), 0o644); err != nil {
		t.Fatal(err)
	}
	s = Lookup(path, content).WithSignature(content, trusted)
	if s.Signer != "ops" || !s.Trusted() || s.Origin != Local {
		t.Errorf("signed: %+v", s)
	}
	s = Lookup(path, []byte("checks: [] # edited\n")).WithSignature([]byte("checks: [] # edited\n"), trusted)
	if s.Signature != SignatureInvalid || s.Trusted() {
		t.Errorf("edited after signing: %+v", s)
	}
	s = Lookup(path, content).WithSignature(content, nil)
	if s.Signature != SignatureUnknownKey || s.Trusted() {
		t.Errorf("no trusted keys: %+v", s)
	}
}
