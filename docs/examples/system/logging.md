# Logging and auditing

journald persistence, syslog forwarding, auditd and its rules, and the permissions of log files.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/system/logging.yml`](https://github.com/rtulke/checkmate/blob/main/examples/system/logging.yml)
- :material-format-list-checks: **Checks**  
  12 from 8 definitions, 1 with loops
- :material-monitor: **Platforms**  
  linux

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/system/logging.yml

# Run the checks
checkmate run examples/system/logging.yml

# Override a variable from the command line
checkmate run examples/system/logging.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `LOG-001` | journald stores logs persistently | <span class="sev sev-medium">medium</span> | system, logging |
| `LOG-002` | auditd is running | <span class="sev sev-high">high</span> | system, logging, audit |
| `LOG-003` | Audit rules are loaded | <span class="sev sev-high">high</span> | system, logging, audit |
| `LOG-WATCH-_etc_passwd` | Changes to /etc/passwd are audited | <span class="sev sev-medium">medium</span> | system, logging, audit |
| `LOG-WATCH-_etc_shadow` | Changes to /etc/shadow are audited | <span class="sev sev-medium">medium</span> | system, logging, audit |
| `LOG-WATCH-_etc_group` | Changes to /etc/group are audited | <span class="sev sev-medium">medium</span> | system, logging, audit |
| `LOG-WATCH-_etc_gshadow` | Changes to /etc/gshadow are audited | <span class="sev sev-medium">medium</span> | system, logging, audit |
| `LOG-WATCH-_etc_sudoers` | Changes to /etc/sudoers are audited | <span class="sev sev-medium">medium</span> | system, logging, audit |
| `LOG-004` | The audit log never fills the disk silently | <span class="sev sev-medium">medium</span> | system, logging, audit |
| `LOG-005` | Logs are forwarded to a central server | <span class="sev sev-low">low</span> | system, logging |
| `LOG-006` | No log file is writable by others | <span class="sev sev-medium">medium</span> | system, logging, files |
| `LOG-007` | logrotate runs regularly | <span class="sev sev-low">low</span> | system, logging |

## Policy

```yaml title="examples/system/logging.yml" linenums="1"
name: Logging and auditing
version: 1.0.0
description: >
  journald persistence, syslog forwarding, auditd and its rules, and the
  permissions of log files.

vars:
  audited_files: [/etc/passwd, /etc/shadow, /etc/group, /etc/gshadow, /etc/sudoers]

checks:
  - id: LOG-001
    name: journald stores logs persistently
    tags: [system, logging]
    when: facts.os == "linux"
    run: test -d /var/log/journal
    expect: true
    remediation: Set Storage=persistent in /etc/systemd/journald.conf.

  - id: LOG-002
    name: auditd is running
    tags: [system, logging, audit]
    severity: high
    when: facts.os == "linux"
    run: systemctl is-active auditd
    allow_rc: [0, 3, 4]
    expect: "== active"

  - id: LOG-003
    name: Audit rules are loaded
    tags: [system, logging, audit]
    severity: high
    when: facts.os == "linux" and facts.is_root
    run: auditctl -l
    expect: ["!empty", "!~ ^No rules"]

  - id: "LOG-WATCH-{{ item | replace('/', '_') }}"
    name: "Changes to {{ item }} are audited"
    tags: [system, logging, audit]
    when: facts.os == "linux" and facts.is_root
    loop: "{{ audited_files }}"
    # Watches appear as "-w <path>" or, on newer kernels, as "path=<path>".
    run: auditctl -l
    expect: "~ (-w |path=){{ item }}( |$)"

  - id: LOG-004
    name: The audit log never fills the disk silently
    tags: [system, logging, audit]
    when: facts.os == "linux" and facts.is_root
    run: |
      cat /etc/audit/auditd.conf 2>/dev/null | awk -F= '/^[[:space:]]*disk_full_action/ {gsub(/[[:space:]]/, "", $2); print tolower($2)}'
    allow_rc: [0, 1]
    expect: "in [halt, single, suspend]"

  - id: LOG-005
    name: Logs are forwarded to a central server
    tags: [system, logging]
    severity: low
    when: facts.os == "linux"
    # Classic "@host" / "@@host" syntax or RainerScript omfwd actions.
    run: |
      grep -rhE '^[^#]*(@@?[A-Za-z0-9._-]+|type="omfwd")' /etc/rsyslog.conf /etc/rsyslog.d 2>/dev/null
    # 1 = no match, 2 = rsyslog not configured at all; both mean "not forwarded".
    allow_rc: [0, 1, 2]
    expect: { lines: ">= 1" }

  - id: LOG-006
    name: No log file is writable by others
    tags: [system, logging, files]
    when: facts.os == "linux"
    run: find /var/log -type f -perm /o+w 2>/dev/null
    allow_rc: [0, 1]
    expect: empty

  - id: LOG-007
    name: logrotate runs regularly
    tags: [system, logging]
    severity: low
    when: facts.os == "linux"
    run: systemctl is-enabled logrotate.timer 2>/dev/null || test -x /etc/cron.daily/logrotate
    expect: true
```
