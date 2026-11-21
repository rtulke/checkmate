# sudo

sudo configuration: syntax, file permissions, dangerous rules, logging and an allowlist of approved sudoers files by SHA-256 checksum.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/system/sudo.yml`](https://github.com/rtulke/checkmate/blob/main/examples/system/sudo.yml)
- :material-format-list-checks: **Checks**  
  8 from 8 definitions
- :material-monitor: **Platforms**  
  linux, macos

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/system/sudo.yml

# Run the checks
checkmate run examples/system/sudo.yml
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `SUDO-001` | sudoers syntax is valid | <span class="sev sev-high">high</span> | system, sudo |
| `SUDO-002` | /etc/sudoers is read-only and owned by root | <span class="sev sev-high">high</span> | system, sudo, files |
| `SUDO-003` | Drop-in files are owned by root and not accessible by others | <span class="sev sev-high">high</span> | system, sudo, files |
| `SUDO-004` | No rule grants passwordless root for everything | <span class="sev sev-high">high</span> | system, sudo |
| `SUDO-005` | No rule disables authentication | <span class="sev sev-high">high</span> | system, sudo |
| `SUDO-006` | sudo runs commands in a pseudo terminal | <span class="sev sev-low">low</span> | system, sudo |
| `SUDO-007` | sudo writes its own log file | <span class="sev sev-low">low</span> | system, sudo, logging |
| `SUDO-008` | Only approved sudoers files are present | <span class="sev sev-critical">critical</span> | system, sudo, integrity |

## Policy

```yaml title="examples/system/sudo.yml" linenums="1"
name: sudo
version: 1.0.0
description: >
  sudo configuration: syntax, file permissions, dangerous rules, logging
  and an allowlist of approved sudoers files by SHA-256 checksum.

checks:
  - id: SUDO-001
    name: sudoers syntax is valid
    tags: [system, sudo]
    severity: high
    when: facts.is_root
    run: visudo -c -q
    expect: true

  - id: SUDO-002
    name: /etc/sudoers is read-only and owned by root
    tags: [system, sudo, files]
    severity: high
    run:
      linux: stat -c '%a %U' /etc/sudoers
      macos: stat -f '%Lp %Su' /etc/sudoers
    expect: "in [440 root, 400 root]"

  - id: SUDO-003
    name: Drop-in files are owned by root and not accessible by others
    tags: [system, sudo, files]
    severity: high
    run: |
      find /etc/sudoers.d -type f \( ! -user root -o -perm /o+rwx -o -perm /g+w \) 2>/dev/null
    allow_rc: [0, 1]
    expect: empty

  - id: SUDO-004
    name: No rule grants passwordless root for everything
    tags: [system, sudo]
    severity: high
    when: facts.is_root
    run: |
      grep -rhE '^[^#]*NOPASSWD:[[:space:]]*ALL[[:space:]]*$' /etc/sudoers /etc/sudoers.d 2>/dev/null
    allow_rc: [0, 1]
    expect: empty

  - id: SUDO-005
    name: No rule disables authentication
    tags: [system, sudo]
    severity: high
    when: facts.is_root
    run: |
      grep -rhE '^[^#]*!authenticate' /etc/sudoers /etc/sudoers.d 2>/dev/null
    allow_rc: [0, 1]
    expect: empty

  - id: SUDO-006
    name: sudo runs commands in a pseudo terminal
    tags: [system, sudo]
    severity: low
    when: facts.is_root
    run: |
      grep -rhE '^[[:space:]]*Defaults([[:space:]]+|.*[[:space:],])use_pty([[:space:],]|$)' /etc/sudoers /etc/sudoers.d 2>/dev/null
    allow_rc: [0, 1]
    expect: { lines: ">= 1" }

  - id: SUDO-007
    name: sudo writes its own log file
    tags: [system, sudo, logging]
    severity: low
    when: facts.is_root
    run: |
      grep -rhE '^[[:space:]]*Defaults[[:space:]].*logfile=' /etc/sudoers /etc/sudoers.d 2>/dev/null
    allow_rc: [0, 1]
    expect: { lines: ">= 1" }

  # Allowlist: every sudoers file must match a checksum in
  # trusted-sudoers.sha256 (lines as printed by `sha256sum <file>`).
  # Unlike comment-stripping approaches, this compares exact content, so
  # nothing can be hidden in lines that look like comments.
  - id: SUDO-008
    name: Only approved sudoers files are present
    tags: [system, sudo, integrity]
    severity: critical
    when: facts.os == "linux" and facts.is_root
    run: |
      sha256sum /etc/sudoers /etc/sudoers.d/* 2>/dev/null | grep -vxFf trusted-sudoers.sha256
    allow_rc: [0, 1]
    expect: empty
    remediation: >
      Review the listed files. To approve a file, append the output of
      `sha256sum <file>` to trusted-sudoers.sha256.
```
