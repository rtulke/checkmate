# File content

Patterns for checking what is inside files: a line is present or absent, a key has a value (key=value, INI, JSON, YAML), a file matches a checksum, and multi-line content.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/files/content.yml`](https://github.com/rtulke/checkmate/blob/main/examples/files/content.yml)
- :material-format-list-checks: **Checks**  
  10 from 10 definitions
- :material-monitor: **Platforms**  
  linux

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/files/content.yml

# Run the checks
checkmate run examples/files/content.yml

# Override a variable from the command line
checkmate run examples/files/content.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `CONTENT-001` | A line is present (exact match) | <span class="sev sev-medium">medium</span> | files, content |
| `CONTENT-002` | A pattern is absent | <span class="sev sev-medium">medium</span> | files, content |
| `CONTENT-003` | key=value setting (shell-style config) | <span class="sev sev-medium">medium</span> | files, content |
| `CONTENT-004` | key = value with spaces (login.defs style) | <span class="sev sev-medium">medium</span> | files, content |
| `CONTENT-005` | INI value via Python configparser | <span class="sev sev-medium">medium</span> | files, content |
| `CONTENT-006` | JSON value via jq | <span class="sev sev-medium">medium</span> | files, content |
| `CONTENT-007` | The login banner matches the approved text | <span class="sev sev-low">low</span> | files, content |
| `CONTENT-008` | The login banner does not reveal the operating system | <span class="sev sev-low">low</span> | files, content |
| `CONTENT-009` | A file is not empty | <span class="sev sev-medium">medium</span> | files, content |
| `CONTENT-010` | Multi-line content contains a block in order | <span class="sev sev-medium">medium</span> | files, content |

## Policy

```yaml title="examples/files/content.yml" linenums="1"
name: File content
version: 1.0.0
description: >
  Patterns for checking what is inside files: a line is present or absent,
  a key has a value (key=value, INI, JSON, YAML), a file matches a checksum,
  and multi-line content.

vars:
  login_banner_sha256: REPLACE_WITH_SHA256_OF_YOUR_BANNER

checks:
  - id: CONTENT-001
    name: A line is present (exact match)
    tags: [files, content]
    run: grep -qxF '127.0.0.1 localhost' /etc/hosts || grep -qE '^127\.0\.0\.1[[:space:]]+localhost' /etc/hosts
    expect: true

  - id: CONTENT-002
    name: A pattern is absent
    tags: [files, content]
    # grep exits 1 if nothing matches: expect false means "must not match".
    run: grep -qE '^[[:space:]]*PermitRootLogin[[:space:]]+yes' /etc/ssh/sshd_config
    expect: false

  - id: CONTENT-003
    name: key=value setting (shell-style config)
    tags: [files, content]
    only_if: test -f /etc/selinux/config
    run: |
      awk -F= '$1 == "SELINUX" {gsub(/["[:space:]]/, "", $2); print $2}' /etc/selinux/config
    expect: "== enforcing"

  - id: CONTENT-004
    name: "key = value with spaces (login.defs style)"
    tags: [files, content]
    when: facts.os == "linux"
    run: |
      cat /etc/login.defs 2>/dev/null | awk '$1 == "ENCRYPT_METHOD" {print $2}'
    allow_rc: [0, 1]
    expect: "in [SHA512, YESCRYPT]"

  - id: CONTENT-005
    name: INI value via Python configparser
    tags: [files, content]
    only_if: test -f /etc/dnf/dnf.conf && command -v python3
    run: |
      python3 -c 'import configparser; c = configparser.ConfigParser(); c.read("/etc/dnf/dnf.conf"); print(c.get("main", "gpgcheck", fallback=""))'
    expect: "in [1, True, true]"

  - id: CONTENT-006
    name: JSON value via jq
    tags: [files, content]
    only_if: test -f /etc/docker/daemon.json && command -v jq
    run: jq -r '.["live-restore"] // false' /etc/docker/daemon.json
    expect: "== true"

  - id: CONTENT-007
    name: The login banner matches the approved text
    tags: [files, content]
    severity: low
    only_if: test -f /etc/issue.net
    run: sha256sum /etc/issue.net | cut -d' ' -f1
    expect: "== {{ login_banner_sha256 }}"

  - id: CONTENT-008
    name: The login banner does not reveal the operating system
    tags: [files, content]
    severity: low
    when: facts.os == "linux"
    # \r, \s, \v and \m are getty escapes that print kernel and OS details.
    run: grep -iE '(\\[mrsv]|ubuntu|debian|red hat|rocky|suse)' /etc/issue /etc/issue.net 2>/dev/null
    allow_rc: [0, 1, 2]
    expect: empty

  - id: CONTENT-009
    name: A file is not empty
    tags: [files, content]
    run: test -s /etc/resolv.conf
    expect: true

  - id: CONTENT-010
    name: Multi-line content contains a block in order
    tags: [files, content]
    only_if: test -f /etc/dnf/dnf.conf
    # awk walks through the file and only prints "found" if gpgcheck=1
    # appears after the [main] section header.
    run: |
      awk '/^\[main\]/ {m = 1} m && /^gpgcheck=1/ {print "found"; exit}' /etc/dnf/dnf.conf
    expect: "== found"
```
