# SELinux and AppArmor

Mandatory access control: SELinux on the RHEL family, AppArmor on Debian, Ubuntu and SUSE.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/system/security-modules.yml`](https://github.com/rtulke/checkmate/blob/main/examples/system/security-modules.yml)
- :material-format-list-checks: **Checks**  
  7 from 7 definitions
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/system/security-modules.yml

# Run the checks
checkmate run examples/system/security-modules.yml
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `MAC-SEL-001` | SELinux is enforcing | <span class="sev sev-high">high</span> | system, selinux |
| `MAC-SEL-002` | SELinux stays enforcing after a reboot | <span class="sev sev-high">high</span> | system, selinux |
| `MAC-SEL-003` | SELinux uses the targeted policy | <span class="sev sev-medium">medium</span> | system, selinux |
| `MAC-SEL-004` | No unconfined services are running | <span class="sev sev-medium">medium</span> | system, selinux |
| `MAC-SEL-005` | SELinux is not disabled on the kernel command line | <span class="sev sev-high">high</span> | system, selinux |
| `MAC-AA-001` | AppArmor is enabled | <span class="sev sev-high">high</span> | system, apparmor |
| `MAC-AA-002` | No AppArmor profile is in complain mode | <span class="sev sev-medium">medium</span> | system, apparmor |

## Policy

```yaml title="examples/system/security-modules.yml" linenums="1"
name: SELinux and AppArmor
version: 1.0.0
description: >
  Mandatory access control: SELinux on the RHEL family, AppArmor on Debian,
  Ubuntu and SUSE.

checks:
  - id: MAC-SEL-001
    name: SELinux is enforcing
    tags: [system, selinux]
    severity: high
    only_if: command -v getenforce
    run: getenforce
    expect: "== Enforcing"
    rationale: In permissive mode SELinux only logs violations, so a compromised service is not confined.
    remediation: Set SELINUX=enforcing in /etc/selinux/config and run `setenforce 1`. Reboot if SELinux was disabled.

  - id: MAC-SEL-002
    name: SELinux stays enforcing after a reboot
    tags: [system, selinux]
    severity: high
    only_if: test -f /etc/selinux/config
    run: |
      awk -F= '$1 == "SELINUX" {print $2}' /etc/selinux/config
    expect: "== enforcing"
    rationale: A permissive or disabled setting in the configuration file takes effect at the next reboot.
    remediation: Set SELINUX=enforcing in /etc/selinux/config.

  - id: MAC-SEL-003
    name: SELinux uses the targeted policy
    tags: [system, selinux]
    only_if: test -f /etc/selinux/config
    run: |
      awk -F= '$1 == "SELINUXTYPE" {print $2}' /etc/selinux/config
    expect: "in [targeted, mls]"
    rationale: The minimum policy confines only a few services and leaves the rest unprotected.
    remediation: Set SELINUXTYPE=targeted in /etc/selinux/config and relabel the file system.

  - id: MAC-SEL-004
    name: No unconfined services are running
    tags: [system, selinux]
    only_if: command -v getenforce
    run: ps -eZ | grep -c unconfined_service_t
    allow_rc: [0, 1]
    expect: "== 0"
    rationale: A service in the unconfined_service_t domain runs without SELinux restrictions.
    remediation: Restore the file context of the service binaries with `restorecon` or write a policy module for the service.

  - id: MAC-SEL-005
    name: SELinux is not disabled on the kernel command line
    tags: [system, selinux]
    severity: high
    only_if: command -v getenforce
    run: cat /proc/cmdline
    expect: "!~ (selinux=0|enforcing=0)"
    rationale: selinux=0 or enforcing=0 on the kernel command line overrides /etc/selinux/config at every boot.
    remediation: Remove selinux=0 and enforcing=0 from the kernel command line in the bootloader configuration and reboot.

  - id: MAC-AA-001
    name: AppArmor is enabled
    tags: [system, apparmor]
    severity: high
    only_if: command -v aa-enabled
    run: aa-enabled --quiet
    expect: true
    rationale: Without AppArmor no profile confines a compromised service.
    remediation: Run `systemctl enable --now apparmor`. Add apparmor=1 security=apparmor to the kernel command line if the kernel starts without it.

  - id: MAC-AA-002
    name: No AppArmor profile is in complain mode
    tags: [system, apparmor]
    when: facts.is_root
    only_if: command -v aa-status && aa-enabled --quiet
    run: aa-status --complaining
    expect: "== 0"
    rationale: A profile in complain mode only logs violations and blocks nothing.
    remediation: Switch the profiles to enforce mode with `aa-enforce <profile>`.
```
