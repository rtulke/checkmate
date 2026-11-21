# SUSE Linux Enterprise and openSUSE

Checks for SLES and openSUSE Leap/Tumbleweed. zypper reports pending patches through its exit code, which these checks assert with `rc`.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/platforms/suse.yml`](https://github.com/rtulke/checkmate/blob/main/examples/platforms/suse.yml)
- :material-format-list-checks: **Checks**  
  6 from 6 definitions
- :material-monitor: **Platforms**  
  sles, suse

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/platforms/suse.yml

# Run the checks
checkmate run examples/platforms/suse.yml
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `SUSE-001` | No security patches pending | <span class="sev sev-high">high</span> | platform, suse, updates |
| `SUSE-002` | No patches pending at all | <span class="sev sev-low">low</span> | platform, suse, updates |
| `SUSE-003` | The system is registered with SCC or RMT | <span class="sev sev-medium">medium</span> | platform, suse, subscription |
| `SUSE-004` | AppArmor is active | <span class="sev sev-medium">medium</span> | platform, suse, apparmor |
| `SUSE-005` | No repository disables GPG checks | <span class="sev sev-high">high</span> | platform, suse, packages |
| `SUSE-006` | No reboot needed | <span class="sev sev-medium">medium</span> | platform, suse, updates |

## Policy

```yaml title="examples/platforms/suse.yml" linenums="1"
name: SUSE Linux Enterprise and openSUSE
version: 1.0.0
description: >
  Checks for SLES and openSUSE Leap/Tumbleweed. zypper reports pending
  patches through its exit code, which these checks assert with `rc`.

checks:
  - id: SUSE-001
    name: No security patches pending
    tags: [platform, suse, updates]
    severity: high
    when: '"suse" in facts.distro_like or facts.distro == "sles"'
    # zypper patch-check exits 100 for pending patches, 101 for security patches.
    run: zypper --non-interactive --quiet patch-check
    timeout: 3m
    expect: { rc: "!= 101" }
    remediation: zypper patch --category security

  - id: SUSE-002
    name: No patches pending at all
    tags: [platform, suse, updates]
    severity: low
    when: '"suse" in facts.distro_like or facts.distro == "sles"'
    run: zypper --non-interactive --quiet patch-check
    timeout: 3m
    expect: { rc: "== 0" }

  - id: SUSE-003
    name: The system is registered with SCC or RMT
    tags: [platform, suse, subscription]
    when: facts.distro == "sles"
    only_if: command -v SUSEConnect
    run: SUSEConnect --status-text
    expect: "~ (?i)registered"

  - id: SUSE-004
    name: AppArmor is active
    tags: [platform, suse, apparmor]
    when: '"suse" in facts.distro_like or facts.distro == "sles"'
    run: systemctl is-active apparmor
    expect: "== active"

  - id: SUSE-005
    name: No repository disables GPG checks
    tags: [platform, suse, packages]
    severity: high
    when: '"suse" in facts.distro_like or facts.distro == "sles"'
    run: |
      grep -HEi '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*(0|off|no|false)' /etc/zypp/repos.d/*.repo
    allow_rc: [0, 1, 2]
    expect: empty

  - id: SUSE-006
    name: No reboot needed
    tags: [platform, suse, updates]
    when: '"suse" in facts.distro_like or facts.distro == "sles"'
    # Exit code 102 means a reboot is required.
    run: zypper needs-rebooting
    expect: { rc: "!= 102" }
```
