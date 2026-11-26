# Red Hat Enterprise Linux family

Checks for RHEL and its rebuilds (Rocky Linux, AlmaLinux, CentOS Stream, Oracle Linux). Every check is limited to the RHEL family with `when`, so the policy can safely run on mixed fleets.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/platforms/rhel.yml`](https://github.com/rtulke/checkmate/blob/main/examples/platforms/rhel.yml)
- :material-format-list-checks: **Checks**  
  9 from 9 definitions
- :material-monitor: **Platforms**  
  rhel

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/platforms/rhel.yml

# Run the checks
checkmate run examples/platforms/rhel.yml

# Override a variable from the command line
checkmate run examples/platforms/rhel.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `RHEL-001` | Major release is 8 or newer | <span class="sev sev-high">high</span> | platform, rhel |
| `RHEL-002` | SELinux is enforcing | <span class="sev sev-high">high</span> | platform, rhel, selinux |
| `RHEL-003` | System-wide crypto policy is not LEGACY | <span class="sev sev-medium">medium</span> | platform, rhel, crypto |
| `RHEL-004` | No repository disables GPG signature checks | <span class="sev sev-high">high</span> | platform, rhel, packages |
| `RHEL-005` | The system is registered | <span class="sev sev-medium">medium</span> | platform, rhel, subscription |
| `RHEL-006` | No security updates pending | <span class="sev sev-high">high</span> | platform, rhel, updates |
| `RHEL-007` | firewalld is running | <span class="sev sev-medium">medium</span> | platform, rhel, firewall |
| `RHEL-008` | Automatic updates are configured | <span class="sev sev-low">low</span> | platform, rhel, updates |
| `RHEL-009` | Running kernel is the newest installed kernel | <span class="sev sev-medium">medium</span> | platform, rhel, kernel |

## Policy

```yaml title="examples/platforms/rhel.yml" linenums="1"
name: Red Hat Enterprise Linux family
version: 1.0.0
description: >
  Checks for RHEL and its rebuilds (Rocky Linux, AlmaLinux, CentOS Stream,
  Oracle Linux). Every check is limited to the RHEL family with `when`, so
  the policy can safely run on mixed fleets.

vars:
  min_major_version: 8

checks:
  - id: RHEL-001
    name: "Major release is {{ min_major_version }} or newer"
    tags: [platform, rhel]
    severity: high
    when: facts.distro == "rhel" or "rhel" in facts.distro_like
    run: rpm -E %rhel
    expect: ">= {{ min_major_version }}"
    rationale: "A major release older than {{ min_major_version }} is below the minimum of this policy and may no longer receive security updates."
    remediation: "Upgrade or reinstall the system with release {{ min_major_version }} or newer."

  - id: RHEL-002
    name: SELinux is enforcing
    tags: [platform, rhel, selinux]
    severity: high
    when: facts.distro == "rhel" or "rhel" in facts.distro_like
    run: getenforce
    expect: "== Enforcing"
    rationale: Without SELinux in enforcing mode a compromised service can use every right of its user account.
    remediation: Set SELINUX=enforcing in /etc/selinux/config and reboot.

  - id: RHEL-003
    name: System-wide crypto policy is not LEGACY
    tags: [platform, rhel, crypto]
    when: facts.distro == "rhel" or "rhel" in facts.distro_like
    run: update-crypto-policies --show
    expect: "!~ ^LEGACY"
    rationale: The LEGACY policy allows old protocols and algorithms with known weaknesses for every application that follows the system-wide policy.
    remediation: update-crypto-policies --set DEFAULT

  - id: RHEL-004
    name: No repository disables GPG signature checks
    tags: [platform, rhel, packages]
    severity: high
    when: facts.distro == "rhel" or "rhel" in facts.distro_like
    # grep exits 1 when nothing matches, which is the good case here.
    run: |
      grep -HEi '^[[:space:]]*gpgcheck[[:space:]]*=[[:space:]]*(0|false|no)[[:space:]]*$' /etc/dnf/dnf.conf /etc/yum.repos.d/*.repo
    allow_rc: [0, 1]
    expect: empty
    rationale: With signature checks switched off a manipulated repository or mirror can deliver modified packages that are installed as root.
    remediation: Set gpgcheck=1 in the listed files.

  - id: RHEL-005
    name: The system is registered
    tags: [platform, rhel, subscription]
    when: facts.distro == "rhel"
    only_if: command -v subscription-manager
    run: subscription-manager identity >/dev/null
    expect: true
    rationale: An unregistered system gets no updates from the Red Hat repositories.
    remediation: subscription-manager register

  - id: RHEL-006
    name: No security updates pending
    tags: [platform, rhel, updates]
    severity: high
    when: facts.distro == "rhel" or "rhel" in facts.distro_like
    run: dnf -q updateinfo list --security --available 2>/dev/null
    timeout: 3m
    expect: { lines: "== 0" }
    rationale: Every pending security update is a published vulnerability that is still open on this system.
    remediation: dnf upgrade --security

  - id: RHEL-007
    name: firewalld is running
    tags: [platform, rhel, firewall]
    when: facts.distro == "rhel" or "rhel" in facts.distro_like
    run: systemctl is-active firewalld
    expect: "== active"
    rationale: Without a running firewalld every listening port is reachable from the whole network.
    remediation: systemctl enable --now firewalld

  - id: RHEL-008
    name: Automatic updates are configured
    tags: [platform, rhel, updates]
    severity: low
    when: facts.distro == "rhel" or "rhel" in facts.distro_like
    run: systemctl is-enabled dnf-automatic.timer dnf-automatic-install.timer 2>/dev/null
    allow_rc: [0, 1]
    expect: "~ ^enabled"
    rationale: Without an update timer updates wait until someone installs them by hand.
    remediation: dnf install dnf-automatic && systemctl enable --now dnf-automatic.timer

  - id: RHEL-009
    name: Running kernel is the newest installed kernel
    tags: [platform, rhel, kernel]
    when: facts.distro == "rhel" or "rhel" in facts.distro_like
    run: |
      newest=$(rpm -q --last kernel-core kernel 2>/dev/null | sed -n 1p | awk '{print $1}' | sed -E 's/^kernel(-core)?-//')
      [ "$newest" = "$(uname -r)" ]
    expect: true
    rationale: Until the reboot the system runs the old kernel with the vulnerabilities the update fixes.
    remediation: Reboot into the newest kernel.
```
