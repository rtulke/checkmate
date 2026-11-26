# Virtualization and out-of-band management

Detect the hypervisor, make sure the matching guest tools run, and read hardware sensors through IPMI on physical servers.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/hardware/virtualization.yml`](https://github.com/rtulke/checkmate/blob/main/examples/hardware/virtualization.yml)
- :material-format-list-checks: **Checks**  
  6 from 6 definitions
- :material-monitor: **Platforms**  
  linux

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/hardware/virtualization.yml

# Run the checks
checkmate run examples/hardware/virtualization.yml

# Override a variable from the command line
checkmate run examples/hardware/virtualization.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `VIRT-001` | Runs on an approved platform | <span class="sev sev-info">info</span> | hardware, virtualization |
| `VIRT-002` | VMware Tools are running on VMware guests | <span class="sev sev-medium">medium</span> | hardware, virtualization |
| `VIRT-003` | The QEMU guest agent runs on KVM guests | <span class="sev sev-medium">medium</span> | hardware, virtualization |
| `VIRT-004` | Hyper-V daemons run on Hyper-V guests | <span class="sev sev-medium">medium</span> | hardware, virtualization |
| `VIRT-005` | All IPMI sensors are in a normal state | <span class="sev sev-high">high</span> | hardware, ipmi |
| `VIRT-006` | The IPMI system event log has no critical entries | <span class="sev sev-medium">medium</span> | hardware, ipmi |

## Policy

```yaml title="examples/hardware/virtualization.yml" linenums="1"
name: Virtualization and out-of-band management
version: 1.0.0
description: >
  Detect the hypervisor, make sure the matching guest tools run, and read
  hardware sensors through IPMI on physical servers.

vars:
  allowed_platforms: [vmware, kvm, qemu, microsoft, xen, amazon, none]

defaults:
  # Shell commands for Unix-like systems.
  when: facts.os != "windows"

checks:
  - id: VIRT-001
    name: Runs on an approved platform
    tags: [hardware, virtualization]
    severity: info
    when: facts.os == "linux"
    only_if: command -v systemd-detect-virt
    # systemd-detect-virt prints "none" and exits 1 on bare metal.
    run: systemd-detect-virt
    allow_rc: [0, 1]
    expect: "in {{ allowed_platforms }}"
    rationale: A host on an unexpected platform was deployed outside the standard process or moved to another environment.
    remediation: Move the host to an approved platform or add the platform to allowed_platforms.

  - id: VIRT-002
    name: VMware Tools are running on VMware guests
    tags: [hardware, virtualization]
    only_if: '[ "$(systemd-detect-virt 2>/dev/null)" = vmware ]'
    run: systemctl is-active vmtoolsd
    allow_rc: [0, 3]
    expect: "== active"
    rationale: Without VMware Tools the hypervisor cannot shut the guest down cleanly or quiesce it for snapshots.
    remediation: Install open-vm-tools and run `systemctl enable --now vmtoolsd`.

  - id: VIRT-003
    name: The QEMU guest agent runs on KVM guests
    tags: [hardware, virtualization]
    only_if: '[ "$(systemd-detect-virt 2>/dev/null)" = kvm ]'
    run: systemctl is-active qemu-guest-agent
    allow_rc: [0, 3]
    expect: "== active"
    rationale: Without the guest agent the hypervisor cannot freeze file systems for consistent snapshots or shut the guest down cleanly.
    remediation: Install qemu-guest-agent and run `systemctl enable --now qemu-guest-agent`.

  - id: VIRT-004
    name: Hyper-V daemons run on Hyper-V guests
    tags: [hardware, virtualization]
    only_if: '[ "$(systemd-detect-virt 2>/dev/null)" = microsoft ]'
    run: systemctl is-active hypervkvpd hv-kvp-daemon 2>/dev/null | grep -c '^active$'
    allow_rc: [0, 1, 3]
    expect: ">= 1"
    rationale: Without the Hyper-V daemons the host cannot exchange data with the guest, for example its IP addresses or backup requests.
    remediation: Install the Hyper-V daemons package of the distribution and start the KVP daemon.

  - id: VIRT-005
    name: All IPMI sensors are in a normal state
    tags: [hardware, ipmi]
    severity: high
    when: facts.is_root
    only_if: command -v ipmitool && test -e /dev/ipmi0
    # Status column 3 is "ok" or "ns" (no reading) for healthy sensors.
    run: |
      ipmitool sdr list 2>/dev/null | awk -F'|' '{gsub(/[[:space:]]/, "", $3)} $3 != "ok" && $3 != "ns" {print $1 "(" $3 ")"}'
    expect: empty
    rationale: A sensor outside its normal state reports a hardware problem such as a failed fan, a failed power supply or high temperature.
    remediation: Read the sensors with `ipmitool sdr list` and repair or replace the affected component.

  - id: VIRT-006
    name: The IPMI system event log has no critical entries
    tags: [hardware, ipmi]
    when: facts.is_root
    only_if: command -v ipmitool && test -e /dev/ipmi0
    run: ipmitool sel elist 2>/dev/null | grep -ciE 'critical|non-recoverable'
    allow_rc: [0, 1]
    expect: "== 0"
    rationale: Critical entries in the event log record hardware faults such as memory errors or power failures.
    remediation: Read the entries with `ipmitool sel elist`, fix the hardware fault and clear the log with `ipmitool sel clear`.
```
