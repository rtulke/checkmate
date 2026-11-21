# Debian and Ubuntu

Checks for Debian, Ubuntu and their derivatives. All checks are limited to the Debian family with `when`.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/platforms/debian.yml`](https://github.com/rtulke/checkmate/blob/main/examples/platforms/debian.yml)
- :material-format-list-checks: **Checks**  
  9 from 9 definitions
- :material-monitor: **Platforms**  
  debian, ubuntu

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/platforms/debian.yml

# Run the checks
checkmate run examples/platforms/debian.yml

# Override a variable from the command line
checkmate run examples/platforms/debian.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `DEB-001` | Debian 12 or newer | <span class="sev sev-high">high</span> | platform, debian |
| `DEB-002` | Ubuntu 22.04 or newer | <span class="sev sev-high">high</span> | platform, debian, ubuntu |
| `DEB-003` | unattended-upgrades is installed | <span class="sev sev-medium">medium</span> | platform, debian, updates |
| `DEB-004` | Automatic security upgrades are enabled | <span class="sev sev-medium">medium</span> | platform, debian, updates |
| `DEB-005` | No security updates pending | <span class="sev sev-high">high</span> | platform, debian, updates |
| `DEB-006` | No APT source is marked as trusted without signature | <span class="sev sev-high">high</span> | platform, debian, packages |
| `DEB-007` | APT does not allow unauthenticated packages | <span class="sev sev-high">high</span> | platform, debian, packages |
| `DEB-008` | AppArmor is enabled | <span class="sev sev-medium">medium</span> | platform, debian, apparmor |
| `DEB-009` | No reboot required after updates | <span class="sev sev-medium">medium</span> | platform, debian, updates |

## Policy

```yaml title="examples/platforms/debian.yml" linenums="1"
name: Debian and Ubuntu
version: 1.0.0
description: >
  Checks for Debian, Ubuntu and their derivatives. All checks are limited
  to the Debian family with `when`.

vars:
  min_debian: 12
  min_ubuntu: 22

checks:
  - id: DEB-001
    name: "Debian {{ min_debian }} or newer"
    tags: [platform, debian]
    severity: high
    when: facts.distro == "debian"
    # Facts can be used inside commands, too.
    run: echo "{{ facts.version_major }}"
    expect: ">= {{ min_debian }}"

  - id: DEB-002
    name: "Ubuntu {{ min_ubuntu }}.04 or newer"
    tags: [platform, debian, ubuntu]
    severity: high
    when: facts.distro == "ubuntu"
    run: echo "{{ facts.version_major }}"
    expect: ">= {{ min_ubuntu }}"

  - id: DEB-003
    name: unattended-upgrades is installed
    tags: [platform, debian, updates]
    when: facts.distro == "debian" or "debian" in facts.distro_like
    run: |
      dpkg-query -W -f='${Status}' unattended-upgrades 2>/dev/null
    allow_rc: [0, 1]
    expect: "== install ok installed"

  - id: DEB-004
    name: Automatic security upgrades are enabled
    tags: [platform, debian, updates]
    when: facts.distro == "debian" or "debian" in facts.distro_like
    run: |
      apt-config dump APT::Periodic::Unattended-Upgrade | awk '{print $2}' | tr -d '";'
    # A number of days, a duration (e.g. 1d) or "always" (Debian 13) enables it.
    expect: "~ ^(always|[1-9][0-9]*[smhd]?)$"

  - id: DEB-005
    name: No security updates pending
    tags: [platform, debian, updates]
    severity: high
    when: facts.distro == "debian" or "debian" in facts.distro_like
    # grep -c prints 0 and exits 1 when nothing matches.
    run: |
      apt-get -s -o Debug::NoLocking=1 dist-upgrade | grep -c '^Inst .*[Ss]ecurity'
    allow_rc: [0, 1]
    expect: "== 0"
    remediation: apt-get update && apt-get upgrade

  - id: DEB-006
    name: No APT source is marked as trusted without signature
    tags: [platform, debian, packages]
    severity: high
    when: facts.distro == "debian" or "debian" in facts.distro_like
    run: |
      grep -rIl -e 'trusted=yes' -e '^Trusted:[[:space:]]*yes' /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null
    allow_rc: [0, 1, 2]
    expect: empty

  - id: DEB-007
    name: APT does not allow unauthenticated packages
    tags: [platform, debian, packages]
    severity: high
    when: facts.distro == "debian" or "debian" in facts.distro_like
    run: |
      apt-config dump | grep -iE 'AllowUnauthenticated|AllowInsecureRepositories' | grep -i '"true"'
    allow_rc: [0, 1]
    expect: empty

  - id: DEB-008
    name: AppArmor is enabled
    tags: [platform, debian, apparmor]
    when: facts.distro == "debian" or "debian" in facts.distro_like
    run: aa-enabled --quiet
    expect: true

  - id: DEB-009
    name: No reboot required after updates
    tags: [platform, debian, updates]
    when: facts.distro == "debian" or "debian" in facts.distro_like
    run: test ! -f /var/run/reboot-required
    expect: true
    remediation: Reboot the system. Affected packages are listed in /var/run/reboot-required.pkgs.
```
