# Searching the file system

Find risky files across the whole file system: SUID/SGID binaries that do not come from a package or an allowlist, files with capabilities, world-writable files and recent changes. Searches stay on local file systems with -xdev.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/files/search.yml`](https://github.com/rtulke/checkmate/blob/main/examples/files/search.yml)
- :material-format-list-checks: **Checks**  
  7 from 7 definitions
- :material-monitor: **Platforms**  
  debian, linux, rhel, suse

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/files/search.yml

# Run the checks
checkmate run examples/files/search.yml

# Override a variable from the command line
checkmate run examples/files/search.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `FIND-001` | Every SUID/SGID file belongs to a package | <span class="sev sev-critical">critical</span> | files, search, suid |
| `FIND-002` | Only approved SUID binaries exist | <span class="sev sev-high">high</span> | files, search, suid |
| `FIND-003` | Only approved files carry capabilities | <span class="sev sev-high">high</span> | files, search, capabilities |
| `FIND-004` | No world-writable files | <span class="sev sev-high">high</span> | files, search |
| `FIND-005` | No executable files in /tmp and /dev/shm | <span class="sev sev-low">low</span> | files, search |
| `FIND-006` | Fewer than 100 files in /etc changed in the last 24 hours | <span class="sev sev-info">info</span> | files, search |
| `FIND-007` | No hidden files in system binary directories | <span class="sev sev-high">high</span> | files, search |

## Policy

```yaml title="examples/files/search.yml" linenums="1"
name: Searching the file system
version: 1.0.0
description: >
  Find risky files across the whole file system: SUID/SGID binaries that
  do not come from a package or an allowlist, files with capabilities,
  world-writable files and recent changes. Searches stay on local file
  systems with -xdev.

vars:
  allowed_suid:
    - /usr/bin/chage
    - /usr/bin/chfn
    - /usr/bin/chsh
    - /usr/bin/crontab
    - /usr/bin/gpasswd
    - /usr/bin/mount
    - /usr/bin/newgrp
    - /usr/bin/passwd
    - /usr/bin/su
    - /usr/bin/sudo
    - /usr/bin/umount
    - /usr/bin/pkexec
    - /usr/bin/at
    - /usr/bin/expiry
    - /usr/bin/fusermount
    - /usr/bin/fusermount3
    - /usr/bin/newgidmap
    - /usr/bin/newuidmap
    - /usr/sbin/unix_chkpwd
    - /usr/sbin/unix2_chkpwd
    - /sbin/unix_chkpwd
    - /sbin/unix2_chkpwd
    - /usr/sbin/userhelper
    - /usr/lib/polkit-1/polkit-agent-helper-1
    - /usr/libexec/polkit-agent-helper-1
    - /usr/lib/dbus-1.0/dbus-daemon-launch-helper
    - /usr/libexec/dbus-1/dbus-daemon-launch-helper
    - /usr/sbin/pam_timestamp_check
    - /usr/lib/openssh/ssh-keysign
    - /usr/libexec/openssh/ssh-keysign
  allowed_capabilities:
    - /usr/bin/ping
    - /usr/bin/arping
    - /usr/bin/newgidmap
    - /usr/bin/newuidmap
    - /usr/sbin/arping

checks:
  - id: FIND-001
    name: Every SUID/SGID file belongs to a package
    tags: [files, search, suid]
    severity: critical
    timeout: 10m
    run:
      rhel,suse: |
        find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null |
          while read -r f; do rpm -qf "$f" >/dev/null 2>&1 || echo "$f"; done
      debian: |
        find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null |
          while read -r f; do
            # With merged /usr, dpkg may know the file as /bin/... instead of /usr/bin/...
            dpkg -S "$f" >/dev/null 2>&1 || dpkg -S "${f#/usr}" >/dev/null 2>&1 || echo "$f"
          done
    allow_rc: [0, 1]
    expect: empty
    remediation: Remove the setuid bit (chmod u-s,g-s <file>) or the file itself.

  - id: FIND-002
    name: Only approved SUID binaries exist
    tags: [files, search, suid]
    severity: high
    timeout: 10m
    when: facts.os == "linux"
    run: |
      find / -xdev -type f -perm -4000 2>/dev/null | sort |
        grep -vxF {% for f in allowed_suid %}-e {{ f }} {% endfor %}
    allow_rc: [0, 1]
    expect: empty

  - id: FIND-003
    name: Only approved files carry capabilities
    tags: [files, search, capabilities]
    severity: high
    timeout: 10m
    only_if: command -v getcap
    # File capabilities such as cap_setuid grant root powers without SUID.
    run: |
      getcap -r / 2>/dev/null | awk '{print $1}' |
        grep -vxF {% for f in allowed_capabilities %}-e {{ f }} {% endfor %}
    allow_rc: [0, 1]
    expect: empty

  - id: FIND-004
    name: No world-writable files
    tags: [files, search]
    severity: high
    timeout: 10m
    run: |
      find / -xdev -type f -perm -0002 ! -path '/proc/*' ! -path '/sys/*' 2>/dev/null
    allow_rc: [0, 1]
    expect: empty

  - id: FIND-005
    name: No executable files in /tmp and /dev/shm
    tags: [files, search]
    severity: low
    when: facts.os == "linux"
    run: |
      find /tmp /var/tmp /dev/shm -xdev -type f -perm /111 2>/dev/null
    allow_rc: [0, 1]
    expect: empty

  - id: FIND-006
    name: Fewer than 100 files in /etc changed in the last 24 hours
    tags: [files, search]
    severity: info
    run: |
      find /etc -xdev -type f -mmin -1440 2>/dev/null
    allow_rc: [0, 1]
    expect: { lines: "< 100" }

  - id: FIND-007
    name: No hidden files in system binary directories
    tags: [files, search]
    severity: high
    run: |
      find /bin /sbin /usr/bin /usr/sbin /usr/local/bin -maxdepth 1 -name '.*' ! -name '.' ! -name '..' 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
```
