package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/rtulke/checkmate/internal/policy"
	"github.com/rtulke/checkmate/internal/provenance"
)

// defaultTrustFile is read when no --trusted-keys is given and it exists.
func defaultTrustFile() string {
	if runtime.GOOS == "windows" {
		dir := os.Getenv("ProgramData")
		if dir == "" {
			dir = `C:\ProgramData`
		}
		return filepath.Join(dir, "checkmate", "trusted_keys")
	}
	return "/etc/checkmate/trusted_keys"
}

// trustedKeys reads the public keys that may sign policies. The files
// decide what runs as root, so they are held to the rules for policy files.
func trustedKeys(files []string, allowInsecure bool) ([]provenance.Key, error) {
	if len(files) == 0 {
		if _, err := os.Stat(defaultTrustFile()); err != nil {
			return nil, nil
		}
		files = []string{defaultTrustFile()}
	}
	var keys []provenance.Key
	for _, file := range files {
		if !allowInsecure {
			if err := policy.CheckFileSecurity(file); err != nil {
				return nil, err
			}
		}
		data, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		k, err := provenance.ParseTrustedKeys(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		keys = append(keys, k...)
	}
	return keys, nil
}

func cmdKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("o", "", "base name of the key files (default: the key name)")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: checkmate keygen [-o base] <name>\n\n"+
			"Writes <base>.key, the private key for `checkmate sign`, and <base>.pub,\n"+
			"the line for the file of trusted keys ("+defaultTrustFile()+").")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		if err == nil {
			fs.Usage()
		}
		return exitUsage
	}
	name := fs.Arg(0)
	base := *out
	if base == "" {
		base = name
	}
	private, public, err := provenance.GenerateKey(name)
	if err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	// Never overwrite a key: signatures made with it would become useless.
	for _, f := range []struct {
		path, content string
		mode          os.FileMode
	}{{base + ".key", private, 0o600}, {base + ".pub", public, 0o644}} {
		fh, err := os.OpenFile(f.path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, f.mode)
		if err == nil {
			_, err = fh.WriteString(f.content)
			if cerr := fh.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			fmt.Fprintln(stderr, "checkmate:", err)
			return exitUsage
		}
	}
	fmt.Fprintf(stdout, "%s.key  private key: keep it secret, sign with `checkmate sign --key %s.key <policy>`\n", base, base)
	fmt.Fprintf(stdout, "%s.pub  public key: add this line to %s where policies are run\n", base, defaultTrustFile())
	return exitCompliant
}

func cmdSign(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fs.SetOutput(stderr)
	keyFile := fs.String("key", "", "private key file written by checkmate keygen")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: checkmate sign --key <name.key> <file>...\n\n"+
			"Writes <file>.sig next to every file. A policy that includes other files\n"+
			"needs a signature for each of them, also for variable and waiver files.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil || fs.NArg() == 0 || *keyFile == "" {
		if err == nil {
			fs.Usage()
		}
		return exitUsage
	}
	key, err := os.ReadFile(*keyFile)
	if err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	for _, file := range fs.Args() {
		content, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintln(stderr, "checkmate:", err)
			return exitUsage
		}
		sig, err := provenance.Sign(key, content)
		if err != nil {
			fmt.Fprintf(stderr, "checkmate: %s: %v\n", *keyFile, err)
			return exitUsage
		}
		if err := os.WriteFile(file+provenance.SignatureSuffix, []byte(sig), 0o644); err != nil {
			fmt.Fprintln(stderr, "checkmate:", err)
			return exitUsage
		}
		fmt.Fprintf(stdout, "signed %s (sha256 %s)\n", file, provenance.Hash(content))
	}
	return exitCompliant
}

// describeSource says in words what checkmate knows about a file.
func describeSource(s provenance.Source) string {
	origin := "not shipped with checkmate"
	switch s.Origin {
	case provenance.Shipped:
		origin = "shipped with checkmate, unchanged"
	case provenance.Modified:
		origin = "differs from the shipped " + s.Shipped
	}
	switch {
	case s.Signer != "":
		origin += ", signed by " + s.Signer
	case s.Signature == provenance.SignatureUnknownKey:
		origin += ", signed by a key that is not trusted here"
	case s.Signature != "":
		origin += ", signature " + s.Signature
	case s.Origin != provenance.Shipped:
		origin += ", not signed"
	}
	return origin
}

func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var common commonFlags
	common.register(fs, false)
	fs.Usage = func() {
		fmt.Fprintln(stderr, "Usage: checkmate verify [flags] <policy.yml>\n\n"+
			"Lists every file the policy is loaded from, with its hash, where it comes\n"+
			"from and who signed it. Exit code 0 if every file is shipped with checkmate\n"+
			"or signed by a trusted key, 1 otherwise. Nothing is run.")
		fs.PrintDefaults()
	}
	path, code := parseWithPolicy(fs, args)
	if path == "" {
		return code
	}
	p, err := common.load(path)
	if err != nil {
		fmt.Fprintln(stderr, "checkmate:", err)
		return exitUsage
	}
	untrusted := 0
	for _, s := range p.Sources {
		mark := "ok"
		if !s.Trusted() {
			mark = "--"
			untrusted++
		}
		fmt.Fprintf(stdout, "%s  %s  %s  %s\n", mark, s.SHA256, s.Path, describeSource(s))
	}
	if untrusted > 0 {
		fmt.Fprintf(stdout, "\n%d of %d files are neither shipped with checkmate nor signed by a trusted key\n", untrusted, len(p.Sources))
		return exitNotCompliant
	}
	fmt.Fprintf(stdout, "\nall %d files are shipped with checkmate or signed by a trusted key\n", len(p.Sources))
	return exitCompliant
}
