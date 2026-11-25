# Disks and RAID

SMART health, software RAID state, NVMe wear, I/O errors in the kernel log and the macOS disk status.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/hardware/disks.yml`](https://github.com/rtulke/checkmate/blob/main/examples/hardware/disks.yml)
- :material-format-list-checks: **Checks**  
  6 from 6 definitions
- :material-monitor: **Platforms**  
  linux, macos, windows

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/hardware/disks.yml

# Run the checks
checkmate run examples/hardware/disks.yml

# Override a variable from the command line
checkmate run examples/hardware/disks.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `HW-DISK-001` | All disks report a healthy SMART status | <span class="sev sev-critical">critical</span> | hardware, disks |
| `HW-DISK-002` | Software RAID arrays are complete | <span class="sev sev-critical">critical</span> | hardware, disks, raid |
| `HW-DISK-003` | NVMe wear is below 80% | <span class="sev sev-medium">medium</span> | hardware, disks |
| `HW-DISK-004` | No disk I/O errors in the kernel log | <span class="sev sev-high">high</span> | hardware, disks |
| `HW-DISK-005` | The internal disk reports a verified SMART status | <span class="sev sev-high">high</span> | hardware, disks |
| `HW-DISK-006` | Physical disks are healthy (Windows) | <span class="sev sev-critical">critical</span> | hardware, disks |

## Policy

```yaml title="examples/hardware/disks.yml" linenums="1"
name: Disks and RAID
version: 1.0.0
description: >
  SMART health, software RAID state, NVMe wear, I/O errors in the kernel log
  and the macOS disk status.

vars:
  max_nvme_wear_percent: 80

checks:
  - id: HW-DISK-001
    name: All disks report a healthy SMART status
    tags: [hardware, disks]
    severity: critical
    when: facts.os == "linux" and facts.is_root
    only_if: command -v smartctl
    run: |
      lsblk -dn -o NAME,TYPE | awk '$2 == "disk" {print $1}' | while read -r disk; do
        smartctl -H "/dev/$disk" 2>/dev/null | grep -E 'PASSED|OK$' >/dev/null || echo "$disk"
      done
    expect: empty

  - id: HW-DISK-002
    name: Software RAID arrays are complete
    tags: [hardware, disks, raid]
    severity: critical
    only_if: test -r /proc/mdstat
    # A degraded array shows an underscore in its status, e.g. [U_].
    run: grep -E '\[U*_[U_]*\]' /proc/mdstat
    allow_rc: [0, 1]
    expect: empty

  - id: HW-DISK-003
    name: "NVMe wear is below {{ max_nvme_wear_percent }}%"
    tags: [hardware, disks]
    when: facts.is_root
    only_if: command -v nvme && test -e /dev/nvme0
    run: |
      nvme smart-log /dev/nvme0 | awk -F: '/percentage_used/ {gsub(/[[:space:]%]/, "", $2); print $2}'
    expect: ["!empty", "< {{ max_nvme_wear_percent }}"]

  - id: HW-DISK-004
    name: No disk I/O errors in the kernel log
    tags: [hardware, disks]
    severity: high
    when: facts.os == "linux" and facts.is_root
    run: |
      dmesg 2>/dev/null | grep -ciE 'I/O error|medium error|critical target error'
    allow_rc: [0, 1]
    expect: "== 0"

  - id: HW-DISK-005
    name: The internal disk reports a verified SMART status
    tags: [hardware, disks]
    severity: high
    when: facts.os == "darwin"
    run: |
      diskutil info disk0 | awk -F: '/SMART Status/ {gsub(/^[[:space:]]+/, "", $2); print $2}'
    expect: "in [Verified, Not Supported]"

  - id: HW-DISK-006
    name: Physical disks are healthy (Windows)
    tags: [hardware, disks]
    severity: critical
    when: facts.os == "windows"
    run: |
      Get-PhysicalDisk | Where-Object HealthStatus -ne 'Healthy' | Select-Object -ExpandProperty FriendlyName
    expect: empty
```
