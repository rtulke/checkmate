# Linux (generic)

Distribution-independent health and hygiene checks for any systemd-based Linux system. Platform variants pick the right command for RHEL, Debian and SUSE families where tools differ.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/platforms/linux.yml`](https://github.com/rtulke/checkmate/blob/main/examples/platforms/linux.yml)
- :material-format-list-checks: **Checks**  
  9 from 9 definitions
- :material-monitor: **Platforms**  
  debian, linux, rhel, suse

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/platforms/linux.yml

# Run the checks
checkmate run examples/platforms/linux.yml

# Override a variable from the command line
checkmate run examples/platforms/linux.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `LNX-OS-001` | /etc/os-release is present | <span class="sev sev-low">low</span> | platform, linux |
| `LNX-OS-002` | Kernel is 4.18 or newer | <span class="sev sev-medium">medium</span> | platform, linux, kernel |
| `LNX-OS-003` | systemd is the init system | <span class="sev sev-low">low</span> | platform, linux |
| `LNX-OS-004` | No failed systemd units | <span class="sev sev-medium">medium</span> | platform, linux, services |
| `LNX-OS-005` | No reboot pending | <span class="sev sev-medium">medium</span> | platform, linux, updates |
| `LNX-OS-006` | Uptime is below 180 days | <span class="sev sev-low">low</span> | platform, linux |
| `LNX-OS-007` | The FQDN resolves | <span class="sev sev-medium">medium</span> | platform, linux, dns |
| `LNX-OS-008` | Timezone is UTC | <span class="sev sev-low">low</span> | platform, linux, time |
| `LNX-OS-009` | Load average is below the number of CPUs | <span class="sev sev-low">low</span> | platform, linux, performance |

## Policy

```yaml title="examples/platforms/linux.yml" linenums="1"
name: Linux (generic)
version: 1.0.0
description: >
  Distribution-independent health and hygiene checks for any systemd-based
  Linux system. Platform variants pick the right command for RHEL, Debian
  and SUSE families where tools differ.

vars:
  max_uptime_days: 180
  expected_timezone: UTC
  min_kernel: "4.18"

checks:
  - id: LNX-OS-001
    name: /etc/os-release is present
    tags: [platform, linux]
    severity: low
    when: facts.os == "linux"
    run: test -r /etc/os-release
    expect: true

  - id: LNX-OS-002
    name: "Kernel is {{ min_kernel }} or newer"
    tags: [platform, linux, kernel]
    when: facts.os == "linux"
    run: uname -r | cut -d- -f1
    as: version
    expect: ">= {{ min_kernel }}"

  - id: LNX-OS-003
    name: systemd is the init system
    tags: [platform, linux]
    severity: low
    when: facts.os == "linux"
    run: cat /proc/1/comm
    expect: "== systemd"

  - id: LNX-OS-004
    name: No failed systemd units
    tags: [platform, linux, services]
    when: facts.os == "linux"
    run: systemctl list-units --state=failed --no-legend --plain
    expect: empty
    remediation: Inspect with `systemctl --failed` and `journalctl -u <unit>`.

  - id: LNX-OS-005
    name: No reboot pending
    tags: [platform, linux, updates]
    run:
      rhel: needs-restarting -r >/dev/null
      debian: test ! -f /var/run/reboot-required
      suse: zypper needs-rebooting >/dev/null
    expect: true
    remediation: Schedule a reboot to activate the updated kernel and libraries.

  - id: LNX-OS-006
    name: "Uptime is below {{ max_uptime_days }} days"
    tags: [platform, linux]
    severity: low
    when: facts.os == "linux"
    run: awk '{print int($1 / 86400)}' /proc/uptime
    expect: "< {{ max_uptime_days }}"
    remediation: Long uptimes usually mean missed kernel updates.

  - id: LNX-OS-007
    name: The FQDN resolves
    tags: [platform, linux, dns]
    when: facts.os == "linux"
    run: getent hosts "$(hostname -f)"
    expect: "!empty"

  - id: LNX-OS-008
    name: "Timezone is {{ expected_timezone }}"
    tags: [platform, linux, time]
    severity: low
    when: facts.os == "linux"
    run: timedatectl show -p Timezone --value
    expect: "== {{ expected_timezone }}"

  - id: LNX-OS-009
    name: Load average is below the number of CPUs
    tags: [platform, linux, performance]
    severity: low
    when: facts.os == "linux"
    run: |
      awk -v cpus="$(nproc)" '{print ($1 <= cpus) ? "ok" : "high: " $1}' /proc/loadavg
    expect: "== ok"
```
