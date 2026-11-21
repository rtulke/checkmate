# Filesystems and mounts

Separate partitions, hardened mount options, allowed filesystem types, fstab consistency, LVM health and swap.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/files/filesystems.yml`](https://github.com/rtulke/checkmate/blob/main/examples/files/filesystems.yml)
- :material-format-list-checks: **Checks**  
  18 from 7 definitions, 2 with loops
- :material-monitor: **Platforms**  
  linux

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/files/filesystems.yml

# Run the checks
checkmate run examples/files/filesystems.yml

# Override a variable from the command line
checkmate run examples/files/filesystems.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `FS-PART-_tmp` | /tmp is a separate mount point | <span class="sev sev-medium">medium</span> | files, filesystems |
| `FS-PART-_var` | /var is a separate mount point | <span class="sev sev-medium">medium</span> | files, filesystems |
| `FS-PART-_var_log` | /var/log is a separate mount point | <span class="sev sev-medium">medium</span> | files, filesystems |
| `FS-PART-_var_log_audit` | /var/log/audit is a separate mount point | <span class="sev sev-medium">medium</span> | files, filesystems |
| `FS-PART-_home` | /home is a separate mount point | <span class="sev sev-medium">medium</span> | files, filesystems |
| `FS-OPT-_tmp-nodev` | /tmp is mounted with nodev | <span class="sev sev-medium">medium</span> | files, filesystems |
| `FS-OPT-_tmp-nosuid` | /tmp is mounted with nosuid | <span class="sev sev-medium">medium</span> | files, filesystems |
| `FS-OPT-_tmp-noexec` | /tmp is mounted with noexec | <span class="sev sev-medium">medium</span> | files, filesystems |
| `FS-OPT-_dev_shm-nodev` | /dev/shm is mounted with nodev | <span class="sev sev-medium">medium</span> | files, filesystems |
| `FS-OPT-_dev_shm-nosuid` | /dev/shm is mounted with nosuid | <span class="sev sev-medium">medium</span> | files, filesystems |
| `FS-OPT-_dev_shm-noexec` | /dev/shm is mounted with noexec | <span class="sev sev-medium">medium</span> | files, filesystems |
| `FS-OPT-_home-nodev` | /home is mounted with nodev | <span class="sev sev-medium">medium</span> | files, filesystems |
| `FS-OPT-_var_tmp-nosuid` | /var/tmp is mounted with nosuid | <span class="sev sev-medium">medium</span> | files, filesystems |
| `FS-001` | Only approved filesystem types are mounted | <span class="sev sev-medium">medium</span> | files, filesystems |
| `FS-002` | /etc/fstab is consistent | <span class="sev sev-medium">medium</span> | files, filesystems |
| `FS-003` | The root filesystem is mounted read-write | <span class="sev sev-medium">medium</span> | files, filesystems |
| `FS-004` | No LVM physical volume is missing | <span class="sev sev-high">high</span> | files, filesystems, lvm |
| `FS-005` | At least 1024 MB swap | <span class="sev sev-low">low</span> | files, filesystems, memory |

## Policy

```yaml title="examples/files/filesystems.yml" linenums="1"
name: Filesystems and mounts
version: 1.0.0
description: >
  Separate partitions, hardened mount options, allowed filesystem types,
  fstab consistency, LVM health and swap.

vars:
  separate_partitions: [/tmp, /var, /var/log, /var/log/audit, /home]
  mount_options:
    - { path: /tmp, option: nodev }
    - { path: /tmp, option: nosuid }
    - { path: /tmp, option: noexec }
    - { path: /dev/shm, option: nodev }
    - { path: /dev/shm, option: nosuid }
    - { path: /dev/shm, option: noexec }
    - { path: /home, option: nodev }
    - { path: /var/tmp, option: nosuid }
  allowed_fstypes:
    [ext4, xfs, btrfs, vfat, swap, tmpfs, devtmpfs, proc, sysfs, cgroup2, devpts, mqueue,
     securityfs, debugfs, tracefs, pstore, bpf, hugetlbfs, configfs, fusectl, autofs,
     binfmt_misc, rpc_pipefs, nfs4, efivarfs, overlay, nsfs, fuse.portal]
  min_swap_mb: 1024

checks:
  - id: "FS-PART-{{ item | replace('/', '_') }}"
    name: "{{ item }} is a separate mount point"
    tags: [files, filesystems]
    when: facts.os == "linux"
    loop: "{{ separate_partitions }}"
    # findmnt exits 1 if the path is not a mount point.
    run: findmnt -n -o TARGET {{ item }}
    allow_rc: [0, 1]
    expect: "== {{ item }}"

  - id: "FS-OPT-{{ item.path | replace('/', '_') }}-{{ item.option }}"
    name: "{{ item.path }} is mounted with {{ item.option }}"
    tags: [files, filesystems]
    when: facts.os == "linux"
    loop: "{{ mount_options }}"
    only_if: findmnt -n {{ item.path }} >/dev/null
    run: findmnt -n -o OPTIONS {{ item.path }}
    expect: "~ (^|,){{ item.option }}(,|$)"

  - id: FS-001
    name: Only approved filesystem types are mounted
    tags: [files, filesystems]
    when: facts.os == "linux"
    run: |
      findmnt -rn -o FSTYPE | sort -u | grep -vxF {% for t in allowed_fstypes %}-e {{ t }} {% endfor %}
    allow_rc: [0, 1]
    expect: empty

  - id: FS-002
    name: /etc/fstab is consistent
    tags: [files, filesystems]
    when: facts.os == "linux" and facts.is_root
    only_if: test -s /etc/fstab
    run: findmnt --verify 2>&1
    allow_rc: [0, 1]
    # Errors are prefixed with [E]; the summary line mentions "errors" either way.
    expect: "!~ \\[E\\]"

  - id: FS-003
    name: The root filesystem is mounted read-write
    tags: [files, filesystems]
    when: facts.os == "linux"
    run: findmnt -n -o OPTIONS / | cut -d, -f1
    expect: "== rw"

  - id: FS-004
    name: No LVM physical volume is missing
    tags: [files, filesystems, lvm]
    severity: high
    when: facts.is_root
    only_if: command -v pvs
    # The third character of pv_attr is "m" for missing devices.
    run: |
      pvs --noheadings -o pv_name,pv_attr 2>/dev/null | awk 'substr($2, 3, 1) == "m" {print $1}'
    expect: empty

  - id: FS-005
    name: "At least {{ min_swap_mb }} MB swap"
    tags: [files, filesystems, memory]
    severity: low
    when: facts.os == "linux"
    run: |
      awk '/^SwapTotal:/ {print int($2 / 1024)}' /proc/meminfo
    expect: ">= {{ min_swap_mb }}"
```
