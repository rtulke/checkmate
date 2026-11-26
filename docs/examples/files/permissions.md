# File permissions and ownership

Mode, owner and group of sensitive files. A snippet hides the different `stat` syntax of GNU (Linux) and BSD (macOS), and `in` accepts the variants distributions use (e.g. /etc/shadow is 000 on RHEL, 640 on Debian).

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/files/permissions.yml`](https://github.com/rtulke/checkmate/blob/main/examples/files/permissions.yml)
- :material-format-list-checks: **Checks**  
  11 from 6 definitions, 1 with loops
- :material-monitor: **Platforms**  
  linux, macos

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/files/permissions.yml

# Run the checks
checkmate run examples/files/permissions.yml
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `PERM-_etc_passwd` | /etc/passwd has safe permissions | <span class="sev sev-high">high</span> | files, permissions |
| `PERM-_etc_group` | /etc/group has safe permissions | <span class="sev sev-high">high</span> | files, permissions |
| `PERM-_etc_shadow` | /etc/shadow has safe permissions | <span class="sev sev-high">high</span> | files, permissions |
| `PERM-_etc_gshadow` | /etc/gshadow has safe permissions | <span class="sev sev-high">high</span> | files, permissions |
| `PERM-_etc_ssh_sshd_config` | /etc/ssh/sshd_config has safe permissions | <span class="sev sev-high">high</span> | files, permissions |
| `PERM-_etc_crontab` | /etc/crontab has safe permissions | <span class="sev sev-high">high</span> | files, permissions |
| `PERM-001` | /etc/hosts is owned by root and not writable by others | <span class="sev sev-medium">medium</span> | files, permissions |
| `PERM-002` | No world-writable files in system directories | <span class="sev sev-high">high</span> | files, permissions |
| `PERM-003` | World-writable directories have the sticky bit | <span class="sev sev-high">high</span> | files, permissions |
| `PERM-004` | No files without a valid owner or group | <span class="sev sev-medium">medium</span> | files, permissions |
| `PERM-005` | No .rhosts, .netrc or .shosts files in home directories | <span class="sev sev-high">high</span> | files, permissions, users |

## Policy

```yaml title="examples/files/permissions.yml" linenums="1"
name: File permissions and ownership
version: 1.0.0
description: >
  Mode, owner and group of sensitive files. A snippet hides the different
  `stat` syntax of GNU (Linux) and BSD (macOS), and `in` accepts the
  variants distributions use (e.g. /etc/shadow is 000 on RHEL, 640 on
  Debian).

snippets:
  # Prints "<mode> <owner> <group>", e.g. "644 root root".
  file_mode:
    linux: stat -c '%a %U %G' {{ arg }}
    macos: stat -f '%Lp %Su %Sg' {{ arg }}

checks:
  - id: "PERM-{{ item.path | replace('/', '_') }}"
    name: "{{ item.path }} has safe permissions"
    tags: [files, permissions]
    severity: high
    when: facts.os == "linux"
    loop:
      - { path: /etc/passwd, allowed: ["644 root root"] }
      - { path: /etc/group, allowed: ["644 root root"] }
      - { path: /etc/shadow, allowed: ["0 root root", "600 root root", "640 root shadow", "400 root root"] }
      - { path: /etc/gshadow, allowed: ["0 root root", "600 root root", "640 root shadow", "400 root root"] }
      - { path: /etc/ssh/sshd_config, allowed: ["600 root root", "640 root root", "644 root root"] }
      - { path: /etc/crontab, allowed: ["600 root root", "644 root root"] }
    only_if: test -e {{ item.path }}
    run: { use: file_mode, arg: "{{ item.path }}" }
    expect: "in {{ item.allowed }}"
    rationale: "{{ item.path }} controls accounts, logins or scheduled jobs, so looser permissions let local users read password hashes or change the system."
    remediation: "Set owner, group and mode of {{ item.path }} to one of the allowed combinations with `chown` and `chmod`."

  - id: PERM-001
    name: /etc/hosts is owned by root and not writable by others
    tags: [files, permissions]
    run: { use: file_mode, arg: /etc/hosts }
    expect: "~ ^6[0-4]4 root (root|wheel)$"
    rationale: Whoever can write /etc/hosts can point host names to other addresses.
    remediation: chown root /etc/hosts && chmod 644 /etc/hosts

  - id: PERM-002
    name: No world-writable files in system directories
    tags: [files, permissions]
    severity: high
    run: |
      find /etc /usr/bin /usr/sbin /usr/lib -xdev -type f -perm -0002 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    rationale: A world-writable file in a system directory lets any user change programs or configuration that root uses.
    remediation: chmod o-w <file>

  - id: PERM-003
    name: World-writable directories have the sticky bit
    tags: [files, permissions]
    severity: high
    timeout: 5m
    run: |
      find / -xdev -type d -perm -0002 ! -perm -1000 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    rationale: Without the sticky bit every user can delete or replace the files of others in the directory.
    remediation: chmod +t <directory>

  - id: PERM-004
    name: No files without a valid owner or group
    tags: [files, permissions]
    timeout: 5m
    when: facts.os == "linux"
    run: |
      find / -xdev \( -nouser -o -nogroup \) 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    rationale: A file without a valid owner falls to whichever new account receives its UID or GID.
    remediation: Assign an owner and group with `chown <user>:<group> <file>` or delete the file.

  - id: PERM-005
    name: No .rhosts, .netrc or .shosts files in home directories
    tags: [files, permissions, users]
    severity: high
    run: |
      find /root /home -maxdepth 2 \( -name .rhosts -o -name .netrc -o -name .shosts \) 2>/dev/null
    allow_rc: [0, 1]
    expect: empty
    rationale: .rhosts and .shosts allow logins without a password, and .netrc stores passwords in clear text.
    remediation: Delete the listed files.
```
