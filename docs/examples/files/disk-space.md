# Disk space

Free space and inodes per mount point, oversized log files and space held by deleted files. `df -P` gives the same columns on Linux and macOS.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/files/disk-space.yml`](https://github.com/rtulke/checkmate/blob/main/examples/files/disk-space.yml)
- :material-format-list-checks: **Checks**  
  8 from 5 definitions, 1 with loops
- :material-monitor: **Platforms**  
  linux

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/files/disk-space.yml

# Run the checks
checkmate run examples/files/disk-space.yml

# Override a variable from the command line
checkmate run examples/files/disk-space.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `DISK-FREE-_` | / has at least 1024 MB free | <span class="sev sev-high">high</span> | files, disk |
| `DISK-FREE-_tmp` | /tmp has at least 500 MB free | <span class="sev sev-high">high</span> | files, disk |
| `DISK-FREE-_var` | /var has at least 1024 MB free | <span class="sev sev-high">high</span> | files, disk |
| `DISK-FREE-_var_log` | /var/log has at least 500 MB free | <span class="sev sev-high">high</span> | files, disk |
| `DISK-USED` | No local filesystem is more than 90% full | <span class="sev sev-high">high</span> | files, disk |
| `DISK-INODES` | No filesystem uses more than 90% of its inodes | <span class="sev sev-medium">medium</span> | files, disk |
| `DISK-LOGS` | No log file is larger than 1 GB | <span class="sev sev-low">low</span> | files, disk, logging |
| `DISK-DELETED` | Deleted but open files hold less than 1 GB | <span class="sev sev-low">low</span> | files, disk |

## Policy

```yaml title="examples/files/disk-space.yml" linenums="1"
name: Disk space
version: 1.0.0
description: >
  Free space and inodes per mount point, oversized log files and space held
  by deleted files. `df -P` gives the same columns on Linux and macOS.

vars:
  min_free_mb:
    /: 1024
    /tmp: 500
    /var: 1024
    /var/log: 500
  max_used_percent: 90

checks:
  - id: "DISK-FREE-{{ item.key | replace('/', '_') }}"
    name: "{{ item.key }} has at least {{ item.value }} MB free"
    tags: [files, disk]
    severity: high
    loop: "{{ min_free_mb }}"
    only_if: test -d {{ item.key }}
    run: |
      df -Pm {{ item.key }} | awk 'NR == 2 {print $4}'
    expect: ">= {{ item.value }}"

  - id: DISK-USED
    name: "No local filesystem is more than {{ max_used_percent }}% full"
    tags: [files, disk]
    severity: high
    when: facts.os == "linux"
    run: |
      df -P | awk -v max={{ max_used_percent }} 'NR > 1 && $1 !~ /^(tmpfs|devtmpfs|shm|overlay|none|squashfs)$/ && $1 !~ /^\/dev\/loop/ {sub(/%/, "", $5); if ($5 + 0 > max) print $6 " " $5 "%"}'
    expect: empty

  - id: DISK-INODES
    name: "No filesystem uses more than {{ max_used_percent }}% of its inodes"
    tags: [files, disk]
    when: facts.os == "linux"
    run: |
      df -Pi | awk -v max={{ max_used_percent }} 'NR > 1 && $5 != "-" && $1 !~ /^(tmpfs|devtmpfs|shm|overlay|none|squashfs)$/ && $1 !~ /^\/dev\/loop/ {sub(/%/, "", $5); if ($5 + 0 > max) print $6 " " $5 "%"}'
    expect: empty

  - id: DISK-LOGS
    name: No log file is larger than 1 GB
    tags: [files, disk, logging]
    severity: low
    run: find /var/log -xdev -type f -size +1048576k 2>/dev/null
    allow_rc: [0, 1]
    expect: empty

  - id: DISK-DELETED
    name: Deleted but open files hold less than 1 GB
    tags: [files, disk]
    severity: low
    when: facts.is_root
    only_if: command -v lsof
    # lsof +L1 lists open files with a link count of 0 (deleted).
    run: |
      lsof -nP +L1 2>/dev/null | awk 'NR > 1 {s += $7} END {print int(s / 1048576)}'
    allow_rc: [0, 1]
    expect: "< 1024"
```
