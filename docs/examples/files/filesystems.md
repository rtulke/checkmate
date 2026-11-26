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
    rationale: "On its own file system {{ item }} cannot fill up the root file system and can get its own mount options."
    remediation: "Create a file system for {{ item }}, move the data to it and add it to /etc/fstab."

  - id: "FS-OPT-{{ item.path | replace('/', '_') }}-{{ item.option }}"
    name: "{{ item.path }} is mounted with {{ item.option }}"
    tags: [files, filesystems]
    when: facts.os == "linux"
    loop: "{{ mount_options }}"
    only_if: findmnt -n {{ item.path }} >/dev/null
    run: findmnt -n -o OPTIONS {{ item.path }}
    expect: "~ (^|,){{ item.option }}(,|$)"
    rationale: "Without {{ item.option }} a user can place device files, setuid programs or executables on {{ item.path }} and use them."
    remediation: "Add {{ item.option }} to the options of {{ item.path }} in /etc/fstab and run `mount -o remount {{ item.path }}`."

  - id: FS-001
    name: Only approved filesystem types are mounted
    tags: [files, filesystems]
    when: facts.os == "linux"
    run: |
      findmnt -rn -o FSTYPE | sort -u | grep -vxF {% for t in allowed_fstypes %}-e {{ t }} {% endfor %}
    allow_rc: [0, 1]
    expect: empty
    rationale: An unusual file system type points to an unexpected mount and brings rarely tested kernel code into use.
    remediation: Unmount the file system or add its type to allowed_fstypes.

  - id: FS-002
    name: /etc/fstab is consistent
    tags: [files, filesystems]
    when: facts.os == "linux" and facts.is_root
    only_if: test -s /etc/fstab
    run: findmnt --verify 2>&1
    allow_rc: [0, 1]
    # Errors are prefixed with [E]; the summary line mentions "errors" either way.
    expect: "!~ \\[E\\]"
    rationale: An inconsistent fstab can keep the system from booting.
    remediation: Correct the entries that `findmnt --verify` reports.

  - id: FS-003
    name: The root filesystem is mounted read-write
    tags: [files, filesystems]
    when: facts.os == "linux"
    run: findmnt -n -o OPTIONS / | cut -d, -f1
    expect: "== rw"
    rationale: The kernel remounts a file system read-only after I/O or file system errors, which points to a failing disk.
    remediation: Look for I/O errors in the output of `dmesg`, check the disk and repair the file system with fsck.

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
    rationale: A missing physical volume means a lost disk, and the logical volumes on it are incomplete.
    remediation: Reconnect or replace the device and check the volume group with `pvs` and `vgs`.

  - id: FS-005
    name: "At least {{ min_swap_mb }} MB swap"
    tags: [files, filesystems, memory]
    severity: low
    when: facts.os == "linux"
    run: |
      awk '/^SwapTotal:/ {print int($2 / 1024)}' /proc/meminfo
    expect: ">= {{ min_swap_mb }}"
    rationale: Without enough swap the kernel kills processes as soon as memory runs short.
    remediation: Add a swap partition or swap file and enable it with `swapon`.
```
