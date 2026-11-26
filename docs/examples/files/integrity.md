# File integrity

Detect modified files: single files against known checksums, whole directories against an allowlist, package databases and AIDE.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/files/integrity.yml`](https://github.com/rtulke/checkmate/blob/main/examples/files/integrity.yml)
- :material-format-list-checks: **Checks**  
  9 from 6 definitions, 1 with loops
- :material-monitor: **Platforms**  
  debian, linux, macos, rhel, suse

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/files/integrity.yml

# Run the checks
checkmate run examples/files/integrity.yml

# Override a variable from the command line
checkmate run examples/files/integrity.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `INT-001` | sshd_config matches an approved version | <span class="sev sev-high">high</span> | files, integrity, ssh |
| `INT-002` | Every PAM file matches the allowlist | <span class="sev sev-high">high</span> | files, integrity, pam |
| `INT-003` | Package-owned binaries are unmodified | <span class="sev sev-critical">critical</span> | files, integrity, packages |
| `INT-004` | AIDE reports no changes | <span class="sev sev-high">high</span> | files, integrity |
| `INT-005` | /etc is unchanged since the last etckeeper commit | <span class="sev sev-low">low</span> | files, integrity |
| `INT-ELF-_usr_bin_sudo` | /usr/bin/sudo is a real binary, not a script | <span class="sev sev-high">high</span> | files, integrity |
| `INT-ELF-_usr_bin_su` | /usr/bin/su is a real binary, not a script | <span class="sev sev-high">high</span> | files, integrity |
| `INT-ELF-_usr_bin_passwd` | /usr/bin/passwd is a real binary, not a script | <span class="sev sev-high">high</span> | files, integrity |
| `INT-ELF-_usr_sbin_sshd` | /usr/sbin/sshd is a real binary, not a script | <span class="sev sev-high">high</span> | files, integrity |

## Policy

```yaml title="examples/files/integrity.yml" linenums="1"
name: File integrity
version: 1.0.0
description: >
  Detect modified files: single files against known checksums, whole
  directories against an allowlist, package databases and AIDE.

vars:
  trusted_sshd_config:
    - REPLACE_WITH_SHA256_OF_YOUR_SSHD_CONFIG

snippets:
  sha256:
    linux: sha256sum {{ arg }} | cut -d' ' -f1
    macos: shasum -a 256 {{ arg }} | cut -d' ' -f1

checks:
  - id: INT-001
    name: sshd_config matches an approved version
    tags: [files, integrity, ssh]
    severity: high
    only_if: test -f /etc/ssh/sshd_config
    run: { use: sha256, arg: /etc/ssh/sshd_config }
    expect: "in {{ trusted_sshd_config }}"
    rationale: A changed sshd_config can open the host, for example by allowing root or password logins.
    remediation: Compare the file with the approved version and restore it, or add the new checksum to trusted_sshd_config.

  - id: INT-002
    name: Every PAM file matches the allowlist
    tags: [files, integrity, pam]
    severity: high
    when: facts.os == "linux"
    # trusted-pam.sha256 holds lines as printed by `sha256sum /etc/pam.d/*`.
    only_if: test -f trusted-pam.sha256
    run: |
      sha256sum /etc/pam.d/* | grep -vxFf trusted-pam.sha256
    allow_rc: [0, 1]
    expect: empty
    rationale: A changed PAM file can skip authentication steps or load a module that records passwords.
    remediation: Review the listed files and restore them, or append their new `sha256sum` lines to trusted-pam.sha256.

  - id: INT-003
    name: Package-owned binaries are unmodified
    tags: [files, integrity, packages]
    severity: critical
    timeout: 20m
    run:
      # Field 1 of rpm -V: "5" in position 3 means the file digest changed.
      rhel,suse: rpm -Va --noconfig --nomtime 2>/dev/null | awk 'substr($1, 3, 1) == "5" {print $NF}'
      debian: debsums -s -c 2>/dev/null
    allow_rc: [0, 1, 2]
    expect: empty
    rationale: A binary whose digest differs from the package database was replaced after installation, as a rootkit does.
    remediation: Find out how the listed files were changed and reinstall the packages that own them.

  - id: INT-004
    name: AIDE reports no changes
    tags: [files, integrity]
    severity: high
    timeout: 30m
    when: facts.is_root
    only_if: command -v aide
    # aide --check exits 0 when the database matches the file system.
    run: aide --check >/dev/null 2>&1
    expect: true
    rationale: A difference to the AIDE database is a file change that nobody has approved yet.
    remediation: Review the report of `aide --check`. After approved changes create a new database with `aide --update` and put it in place.

  - id: INT-005
    name: /etc is unchanged since the last etckeeper commit
    tags: [files, integrity]
    severity: low
    only_if: test -d /etc/.git && command -v git
    run: git -C /etc status --porcelain
    expect: empty
    rationale: Uncommitted changes in /etc are changes that nobody recorded or reviewed.
    remediation: Review the changes with `git -C /etc diff`, then commit them with `etckeeper commit` or revert them.

  - id: "INT-ELF-{{ item | replace('/', '_') }}"
    name: "{{ item }} is a real binary, not a script"
    tags: [files, integrity]
    severity: high
    when: facts.os == "linux"
    loop: [/usr/bin/sudo, /usr/bin/su, /usr/bin/passwd, /usr/sbin/sshd]
    only_if: test -e {{ item }}
    # A wrapper script in place of a real binary is a classic backdoor.
    run: head -c 4 {{ item }} | od -An -c | tr -d ' '
    expect: "== 177ELF"
    rationale: "A script in place of {{ item }} is a classic backdoor that captures passwords before it calls the real program."
    remediation: "Treat the host as compromised and reinstall the package that owns {{ item }}."
```
