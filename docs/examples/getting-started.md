# Getting started

Demonstrates the building blocks of a checkmate policy.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/getting-started.yml`](https://github.com/rtulke/checkmate/blob/main/examples/getting-started.yml)
- :material-format-list-checks: **Checks**  
  11 from 9 definitions, 1 with loops
- :material-monitor: **Platforms**  
  linux, macos

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/getting-started.yml

# Run the checks
checkmate run examples/getting-started.yml

# Override a variable from the command line
checkmate run examples/getting-started.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `GS-001` | The root directory exists | <span class="sev sev-medium">medium</span> | demo |
| `GS-002` | /etc/hosts is owned by root | <span class="sev sev-medium">medium</span> | demo, files |
| `GS-003` | At least 100 MB free in /tmp | <span class="sev sev-medium">medium</span> | demo, disk |
| `GS-TOOL-LS` | Tool ls is installed | <span class="sev sev-medium">medium</span> | demo, packages |
| `GS-TOOL-GREP` | Tool grep is installed | <span class="sev sev-medium">medium</span> | demo, packages |
| `GS-TOOL-AWK` | Tool awk is installed | <span class="sev sev-medium">medium</span> | demo, packages |
| `GS-005` | The kernel reports a version number | <span class="sev sev-medium">medium</span> | demo |
| `GS-006` | No more than one account with UID 0 | <span class="sev sev-medium">medium</span> | demo, users |
| `GS-007` | systemd is the init system | <span class="sev sev-medium">medium</span> | demo |
| `GS-008` | Homebrew is healthy | <span class="sev sev-medium">medium</span> | demo |
| `GS-009` | Bash is version 3.2 or newer | <span class="sev sev-medium">medium</span> | demo |

## Policy

```yaml title="examples/getting-started.yml" linenums="1"
# A first policy that runs on any Linux or macOS machine without root.
#
#   checkmate run examples/getting-started.yml
#
name: Getting started
version: 1.0.0
description: Demonstrates the building blocks of a checkmate policy.

vars:
  min_free_mb: 100
  required_tools: [ls, grep, awk]

snippets:
  # A snippet is a reusable command; {{ arg }} is filled in by the check.
  tool_exists: command -v {{ arg }}

checks:
  # 1. The simplest check: the command must succeed (exit code 0).
  - id: GS-001
    name: The root directory exists
    tags: [demo]
    run: test -d /
    expect: true
    rationale: Every Unix system has a root directory, so this check shows what a passing result looks like.
    remediation: Nothing needs fixing on a working system. A failure points to a problem with the shell that runs the checks.

  # 2. Compare the output with a value.
  - id: GS-002
    name: /etc/hosts is owned by root
    tags: [demo, files]
    run:
      linux: stat -c %U /etc/hosts
      macos: stat -f %Su /etc/hosts
    expect: "== root"
    rationale: Whoever owns /etc/hosts can redirect host names to other addresses.
    remediation: sudo chown root /etc/hosts

  # 3. Numeric comparison with a variable.
  - id: GS-003
    name: "At least {{ min_free_mb }} MB free in /tmp"
    tags: [demo, disk]
    run:
      linux: df -Pm /tmp | awk 'NR==2 {print $4}'
      macos: df -m /tmp | awk 'NR==2 {print $4}'
    expect: ">= {{ min_free_mb }}"
    rationale: Many programs write temporary files to /tmp and fail when it is full.
    remediation: Delete files in /tmp that are no longer needed or enlarge the file system.

  # 4. One check definition, several checks: loop over a list variable.
  - id: "GS-TOOL-{{ item | upper }}"
    name: "Tool {{ item }} is installed"
    tags: [demo, packages]
    loop: "{{ required_tools }}"
    run: { use: tool_exists, arg: "{{ item }}" }
    expect: true
    rationale: "Scripts and checks on this machine call {{ item }} and fail without it."
    remediation: "Install the package that provides {{ item }}."

  # 5. Regular expressions and multiple conditions.
  - id: GS-005
    name: The kernel reports a version number
    tags: [demo]
    run: uname -r
    expect: ["!empty", "~ ^[0-9]+\\."]
    rationale: Checks that compare kernel versions need `uname -r` to print a release that starts with a number.
    remediation: Look at the output of `uname -r`. A custom kernel may need a different pattern in this check.

  # 6. Count lines instead of comparing text.
  - id: GS-006
    name: No more than one account with UID 0
    tags: [demo, users]
    # Commands containing ": " must be quoted or written as a block (|).
    run: |
      awk -F: '$3 == 0' /etc/passwd
    expect: { lines: "<= 1" }
    rationale: Every account with UID 0 has full root rights, so a second one is a second root.
    remediation: Delete the additional UID 0 accounts or give them an unprivileged UID.

  # 7. Conditional checks: `when` uses facts, `only_if` runs a command.
  - id: GS-007
    name: systemd is the init system
    tags: [demo]
    when: facts.os == "linux"
    run: cat /proc/1/comm
    expect: "== systemd"
    rationale: Checks that use systemctl only work where systemd is the init system.
    remediation: Leave systemd-based checks out on this host or use a policy written for its init system.

  - id: GS-008
    name: Homebrew is healthy
    tags: [demo]
    only_if: command -v brew
    run: brew --version
    expect: "~ ^Homebrew"
    timeout: 60s
    rationale: A Homebrew that no longer starts cannot install or update the software it manages.
    remediation: Run `brew doctor` and follow its advice, or reinstall Homebrew.

  # 8. Version-aware comparison: 10.10 is newer than 10.9.
  - id: GS-009
    name: Bash is version 3.2 or newer
    tags: [demo]
    run: bash -c 'echo "${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"'
    as: version
    expect: ">= 3.2"
    rationale: Shell scripts written for current bash versions fail on releases older than 3.2.
    remediation: Install a current bash from your package manager.
```
