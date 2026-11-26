package provenance

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// Signatures let an organization vouch for its own policies the way the
// built-in hashes vouch for the shipped ones. They are Ed25519 signatures
// over the hash of a file, kept next to it as <file>.sig. Keys and
// signatures are single lines of text:
//
//	checkmate-private-key ed25519 <base64> <name>
//	checkmate-key ed25519 <base64> <name>
//	checkmate-signature ed25519 <key id> <base64>
const (
	privatePrefix   = "checkmate-private-key"
	publicPrefix    = "checkmate-key"
	signaturePrefix = "checkmate-signature"
	algorithm       = "ed25519"
	// The signed message names its purpose, so that a signature over a
	// policy cannot be passed off as one over anything else.
	messagePrefix = "checkmate policy signature v1\n"

	// SignatureSuffix is appended to the name of a file for its signature.
	SignatureSuffix = ".sig"
)

// Key is a public key that is trusted to sign policies.
type Key struct {
	Name   string
	Public ed25519.PublicKey
}

// ID is a short name of the key that does not depend on what it is called.
func (k Key) ID() string {
	sum := sha256.Sum256(k.Public)
	return hex.EncodeToString(sum[:8])
}

// Line is the key as a line of a trust file.
func (k Key) Line() string {
	return fmt.Sprintf("%s %s %s %s", publicPrefix, algorithm, base64.StdEncoding.EncodeToString(k.Public), k.Name)
}

var keyName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@-]*$`)

// GenerateKey makes a new key pair and returns the private key file and the
// public key line.
func GenerateKey(name string) (private, public string, err error) {
	if !keyName.MatchString(name) {
		return "", "", fmt.Errorf("invalid key name %q (letters, digits, . _ @ -)", name)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	private = fmt.Sprintf("%s %s %s %s\n", privatePrefix, algorithm, base64.StdEncoding.EncodeToString(priv.Seed()), name)
	return private, Key{Name: name, Public: pub}.Line() + "\n", nil
}

func parseLine(line, prefix string, size int) (data []byte, rest string, err error) {
	fields := strings.Fields(line)
	if len(fields) < 3 || fields[0] != prefix {
		return nil, "", fmt.Errorf("expected a line starting with %q", prefix)
	}
	if fields[1] != algorithm {
		return nil, "", fmt.Errorf("unsupported algorithm %q", fields[1])
	}
	last := fields[len(fields)-1]
	if prefix == signaturePrefix {
		// checkmate-signature ed25519 <key id> <base64>
		if len(fields) != 4 {
			return nil, "", errors.New("malformed signature")
		}
		rest = fields[2]
	} else {
		// <prefix> ed25519 <base64> <name>
		if len(fields) != 4 {
			return nil, "", errors.New("malformed key")
		}
		rest, last = fields[3], fields[2]
	}
	data, err = base64.StdEncoding.DecodeString(last)
	if err != nil || len(data) != size {
		return nil, "", errors.New("malformed key or signature data")
	}
	return data, rest, nil
}

// ParseTrustedKeys reads a trust file: one public key per line; empty
// lines and lines starting with # are ignored.
func ParseTrustedKeys(data []byte) ([]Key, error) {
	var keys []Key
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		pub, name, err := parseLine(line, publicPrefix, ed25519.PublicKeySize)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", n+1, err)
		}
		keys = append(keys, Key{Name: name, Public: pub})
	}
	return keys, nil
}

func message(content []byte) []byte {
	return []byte(messagePrefix + Hash(content) + "\n")
}

// Sign returns the content of the signature file for a policy file.
func Sign(privateKeyFile, content []byte) (string, error) {
	seed, _, err := parseLine(strings.TrimSpace(string(privateKeyFile)), privatePrefix, ed25519.SeedSize)
	if err != nil {
		return "", fmt.Errorf("private key: %w", err)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	key := Key{Public: priv.Public().(ed25519.PublicKey)}
	sig := ed25519.Sign(priv, message(content))
	return fmt.Sprintf("%s %s %s %s\n", signaturePrefix, algorithm, key.ID(), base64.StdEncoding.EncodeToString(sig)), nil
}

// Signature states of a file, see Source.Signature.
const (
	SignatureInvalid    = "invalid"
	SignatureUnknownKey = "unknown key"
	SignatureMalformed  = "malformed"
)

// Verify checks the signature file of a policy file against the trusted
// keys. It returns the name of the key that signed the content, or the
// state of a signature that does not vouch for it.
func Verify(content, signatureFile []byte, trusted []Key) (signer, state string) {
	sig, id, err := parseLine(strings.TrimSpace(string(signatureFile)), signaturePrefix, ed25519.SignatureSize)
	if err != nil {
		return "", SignatureMalformed
	}
	for _, key := range trusted {
		if key.ID() != id {
			continue
		}
		if ed25519.Verify(key.Public, message(content), sig) {
			return key.Name, ""
		}
		// Made with a trusted key, but for other content: the file was
		// changed after it was signed.
		return "", SignatureInvalid
	}
	return "", SignatureUnknownKey
}

// WithSignature adds what the signature file next to the policy file says.
// A missing signature file leaves the source as it is.
func (s Source) WithSignature(content []byte, trusted []Key) Source {
	sig, err := os.ReadFile(s.Path + SignatureSuffix)
	if err != nil {
		return s
	}
	s.Signer, s.Signature = Verify(content, sig, trusted)
	return s
}
