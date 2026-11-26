# systemd services

Required services must run, unwanted services must be neither active nor enabled, and the system must boot into a non-graphical target.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/system/services.yml`](https://github.com/rtulke/checkmate/blob/main/examples/system/services.yml)
- :material-format-list-checks: **Checks**  
  19 from 5 definitions, 2 with loops
- :material-monitor: **Platforms**  
  linux

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/system/services.yml

# Run the checks
checkmate run examples/system/services.yml

# Override a variable from the command line
checkmate run examples/system/services.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `SVC-REQ-chronyd` | chronyd is running | <span class="sev sev-medium">medium</span> | system, services |
| `SVC-REQ-auditd` | auditd is running | <span class="sev sev-medium">medium</span> | system, services |
| `SVC-REQ-rsyslog` | rsyslog is running | <span class="sev sev-medium">medium</span> | system, services |
| `SVC-FORBIDDEN-telnet.socket` | telnet.socket is neither running nor enabled | <span class="sev sev-medium">medium</span> | system, services |
| `SVC-FORBIDDEN-rsh.socket` | rsh.socket is neither running nor enabled | <span class="sev sev-medium">medium</span> | system, services |
| `SVC-FORBIDDEN-rlogin.socket` | rlogin.socket is neither running nor enabled | <span class="sev sev-medium">medium</span> | system, services |
| `SVC-FORBIDDEN-tftp.socket` | tftp.socket is neither running nor enabled | <span class="sev sev-medium">medium</span> | system, services |
| `SVC-FORBIDDEN-vsftpd` | vsftpd is neither running nor enabled | <span class="sev sev-medium">medium</span> | system, services |
| `SVC-FORBIDDEN-xinetd` | xinetd is neither running nor enabled | <span class="sev sev-medium">medium</span> | system, services |
| `SVC-FORBIDDEN-avahi-daemon` | avahi-daemon is neither running nor enabled | <span class="sev sev-medium">medium</span> | system, services |
| `SVC-FORBIDDEN-cups` | cups is neither running nor enabled | <span class="sev sev-medium">medium</span> | system, services |
| `SVC-FORBIDDEN-nfs-server` | nfs-server is neither running nor enabled | <span class="sev sev-medium">medium</span> | system, services |
| `SVC-FORBIDDEN-rpcbind` | rpcbind is neither running nor enabled | <span class="sev sev-medium">medium</span> | system, services |
| `SVC-FORBIDDEN-snmpd` | snmpd is neither running nor enabled | <span class="sev sev-medium">medium</span> | system, services |
| `SVC-FORBIDDEN-squid` | squid is neither running nor enabled | <span class="sev sev-medium">medium</span> | system, services |
| `SVC-FORBIDDEN-named` | named is neither running nor enabled | <span class="sev sev-medium">medium</span> | system, services |
| `SVC-001` | The default target is not graphical | <span class="sev sev-low">low</span> | system, services |
| `SVC-002` | Ctrl-Alt-Del reboot is masked | <span class="sev sev-low">low</span> | system, services |
| `SVC-003` | No failed units | <span class="sev sev-medium">medium</span> | system, services |

## Policy

```yaml title="examples/system/services.yml" linenums="1"
name: systemd services
version: 1.0.0
description: >
  Required services must run, unwanted services must be neither active nor
  enabled, and the system must boot into a non-graphical target.

vars:
  required_services: [chronyd, auditd, rsyslog]
  forbidden_services:
    - telnet.socket
    - rsh.socket
    - rlogin.socket
    - tftp.socket
    - vsftpd
    - xinetd
    - avahi-daemon
    - cups
    - nfs-server
    - rpcbind
    - snmpd
    - squid
    - named

checks:
  - id: "SVC-REQ-{{ item }}"
    name: "{{ item }} is running"
    tags: [system, services]
    when: facts.os == "linux"
    loop: "{{ required_services }}"
    run: systemctl is-active {{ item }}
    allow_rc: [0, 3, 4]
    expect: "== active"
    rationale: "{{ item }} is part of the required baseline, and its function is missing while it is stopped."
    remediation: "systemctl enable --now {{ item }}"

  - id: "SVC-FORBIDDEN-{{ item }}"
    name: "{{ item }} is neither running nor enabled"
    tags: [system, services]
    when: facts.os == "linux"
    loop: "{{ forbidden_services }}"
    # Both commands fail for unknown units, which is fine.
    run: systemctl is-active --quiet {{ item }} || systemctl is-enabled --quiet {{ item }}
    expect: false
    rationale: "{{ item }} is not needed on this host, and every extra service adds attack surface."
    remediation: "systemctl disable --now {{ item }}"

  - id: SVC-001
    name: The default target is not graphical
    tags: [system, services]
    severity: low
    when: facts.os == "linux"
    run: systemctl get-default
    expect: "== multi-user.target"
    rationale: A graphical session brings a large amount of software that a server does not need.
    remediation: systemctl set-default multi-user.target

  - id: SVC-002
    name: Ctrl-Alt-Del reboot is masked
    tags: [system, services]
    severity: low
    when: facts.os == "linux"
    run: systemctl show -p UnitFileState ctrl-alt-del.target | cut -d= -f2
    expect: "== masked"
    rationale: Anyone with access to the console can reboot the host with Ctrl-Alt-Del.
    remediation: systemctl mask ctrl-alt-del.target

  - id: SVC-003
    name: No failed units
    tags: [system, services]
    when: facts.os == "linux"
    run: systemctl list-units --state=failed --no-legend --plain
    expect: empty
    rationale: A failed unit means a service or job is not doing its work, often without anyone noticing.
    remediation: Inspect each unit with `systemctl status <unit>`, fix the cause and clear the state with `systemctl reset-failed`.
```
