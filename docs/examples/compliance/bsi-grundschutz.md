# BSI IT-Grundschutz Linux server

Technical checks for the host-verifiable requirements of the BSI IT-Grundschutz building blocks SYS.1.1 "Allgemeiner Server" and SYS.1.3 "Server unter Linux und Unix" (IT-Grundschutz-Kompendium, Edition 2023). Check names and descriptions are written for checkmate and refer to the requirement IDs; they do not reproduce BSI text. Organisational requirements (server rooms, documentation, planning, emergency management) cannot be checked on a host and are not included.
The tags follow the BSI levels: `bsi-basis` (B), `bsi-standard` (B and S) and `bsi-hoch` (B, S and the requirements for increased protection needs). Run for example `checkmate run bsi-grundschutz.yml --tags bsi-standard`.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/compliance/bsi-grundschutz.yml`](https://github.com/rtulke/checkmate/blob/main/examples/compliance/bsi-grundschutz.yml)
- :material-format-list-checks: **Checks**  
  53 from 33 definitions, 5 with loops
- :material-monitor: **Platforms**  
  alpine, debian, linux, rhel, suse

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/compliance/bsi-grundschutz.yml

# Run the checks
checkmate run examples/compliance/bsi-grundschutz.yml

# Override a variable from the command line
checkmate run examples/compliance/bsi-grundschutz.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `BSI-SYS.1.1.A1-NO-DESKTOP` | The server does not boot into a graphical desktop | <span class="sev sev-high">high</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch |
| `BSI-SYS.1.1.A1-NO-WORKSTATION-APPS` | No web browser or office program is installed | <span class="sev sev-high">high</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch |
| `BSI-SYS.1.1.A2-SSH-EMPTY-PASSWORDS` | SSH rejects empty passwords | <span class="sev sev-critical">critical</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, ssh |
| `BSI-SYS.1.1.A2-EMPTY-PASSWORDS` | No account has an empty password | <span class="sev sev-critical">critical</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, accounts |
| `BSI-SYS.1.1.A5-MODULE-USB-STORAGE` | Kernel module usb-storage cannot be loaded | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, modules |
| `BSI-SYS.1.1.A5-MODULE-FIREWIRE-CORE` | Kernel module firewire-core cannot be loaded | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, modules |
| `BSI-SYS.1.1.A6-SERVICE-AVAHI-DAEMON` | Service avahi-daemon is not active | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, services |
| `BSI-SYS.1.1.A6-SERVICE-CUPS` | Service cups is not active | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, services |
| `BSI-SYS.1.1.A6-SERVICE-CUPS-BROWSED` | Service cups-browsed is not active | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, services |
| `BSI-SYS.1.1.A6-SERVICE-TELNET.SOCKET` | Service telnet.socket is not active | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, services |
| `BSI-SYS.1.1.A6-SERVICE-RSH.SOCKET` | Service rsh.socket is not active | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, services |
| `BSI-SYS.1.1.A6-SERVICE-RLOGIN.SOCKET` | Service rlogin.socket is not active | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, services |
| `BSI-SYS.1.1.A6-SERVICE-REXEC.SOCKET` | Service rexec.socket is not active | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, services |
| `BSI-SYS.1.1.A6-SERVICE-TFTP.SOCKET` | Service tftp.socket is not active | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, services |
| `BSI-SYS.1.1.A6-SERVICE-VSFTPD` | Service vsftpd is not active | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, services |
| `BSI-SYS.1.1.A6-SERVICE-XINETD` | Service xinetd is not active | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, services |
| `BSI-SYS.1.1.A6-SERVICE-YPBIND` | Service ypbind is not active | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, services |
| `BSI-SYS.1.1.A6-SERVICE-BLUETOOTH` | Service bluetooth is not active | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, services |
| `BSI-SYS.1.1.A6-SERVICE-MODEMMANAGER` | Service ModemManager is not active | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, services |
| `BSI-SYS.1.1.A6-LEGACY-LISTENERS` | No telnet, rsh, rlogin, rexec, TFTP or FTP service is listening | <span class="sev sev-high">high</span> | bsi, bsi-sys.1.1, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch, services |
| `BSI-SYS.1.1.A10-AUDITD` | The audit daemon is running | <span class="sev sev-high">high</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, logging |
| `BSI-SYS.1.1.A10-AUDIT-LOGINS` | Logins and failed logins are audited | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, logging, audit |
| `BSI-SYS.1.1.A10-AUDIT-IDENTITY` | Changes to users and groups are audited | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, logging, audit |
| `BSI-SYS.1.1.A10-AUDIT-PERMISSIONS` | Changes of file permissions are audited | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, logging, audit |
| `BSI-SYS.1.1.A10-AUDIT-ACCESS-DENIED` | Failed access attempts are audited | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, logging, audit |
| `BSI-SYS.1.1.A10-PERSISTENT-LOG` | System events are written to a persistent log | <span class="sev sev-high">high</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, logging |
| `BSI-SYS.1.1.A10-FIREWALL-LOG` | Blocked network traffic is logged | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, logging, firewall |
| `BSI-SYS.1.1.A19-FIREWALL-DEFAULT-DENY` | The local packet filter rejects incoming traffic by default | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.1, bsi-standard, bsi-hoch, firewall |
| `BSI-SYS.1.1.A23-MONITORING` | A monitoring agent is running | <span class="sev sev-low">low</span> | bsi, bsi-sys.1.1, bsi-standard, bsi-hoch, monitoring |
| `BSI-SYS.1.1.A27-HIDS` | File integrity monitoring or a host-based IDS is in place | <span class="sev sev-low">low</span> | bsi, bsi-sys.1.1, bsi-hoch, integrity |
| `BSI-SYS.1.1.A30-ONE-SERVICE` | The server offers at most one network service | <span class="sev sev-low">low</span> | bsi, bsi-sys.1.1, bsi-hoch, services |
| `BSI-SYS.1.1.A31-EXECUTION-CONTROL` | Execution control allows only approved programs | <span class="sev sev-low">low</span> | bsi, bsi-sys.1.1, bsi-hoch |
| `BSI-SYS.1.1.A34-DISK-ENCRYPTION` | The root file system is encrypted | <span class="sev sev-low">low</span> | bsi, bsi-sys.1.1, bsi-hoch, encryption |
| `BSI-SYS.1.1.A36-SECURE-BOOT` | Secure Boot is enabled | <span class="sev sev-low">low</span> | bsi, bsi-sys.1.1, bsi-hoch, boot |
| `BSI-SYS.1.1.A38-READ-ONLY-ROOT` | The root file system is read-only | <span class="sev sev-low">low</span> | bsi, bsi-sys.1.1, bsi-hoch |
| `BSI-SYS.1.3.A2-UNIQUE-LOGIN` | Every login name is unique | <span class="sev sev-high">high</span> | bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch, accounts |
| `BSI-SYS.1.3.A2-UNIQUE-UID` | Every UID is unique | <span class="sev sev-high">high</span> | bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch, accounts |
| `BSI-SYS.1.3.A2-UNIQUE-GROUP` | Every group name is unique | <span class="sev sev-high">high</span> | bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch, accounts |
| `BSI-SYS.1.3.A2-UNIQUE-GID` | Every GID is unique | <span class="sev sev-high">high</span> | bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch, accounts |
| `BSI-SYS.1.3.A2-GROUPS-DEFINED` | Every primary group of an account exists | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch, accounts |
| `BSI-SYS.1.3.A3-AUTOFS` | Removable media are not mounted automatically | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch |
| `BSI-SYS.1.3.A3-DESKTOP-AUTOMOUNT` | The desktop does not mount removable media automatically | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch |
| `BSI-SYS.1.3.A4-ASLR` | Address space layout randomization is fully enabled | <span class="sev sev-high">high</span> | bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch, kernel |
| `BSI-SYS.1.3.A4-NX` | The NX bit is available and not disabled | <span class="sev sev-high">high</span> | bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch, kernel |
| `BSI-SYS.1.3.A4-KERNEL-PROTECTION` | Kernel security functions are not switched off at boot | <span class="sev sev-high">high</span> | bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch, kernel |
| `BSI-SYS.1.3.A5-UNPACKAGED-BINARIES` | System binary directories contain only files from packages | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch, packages |
| `BSI-SYS.1.3.A8-SSH-KEYS` | SSH logins use keys instead of passwords | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.3, bsi-standard, bsi-hoch, ssh |
| `BSI-SYS.1.3.A10-MAC` | SELinux is enforcing or AppArmor enforces profiles | <span class="sev sev-medium">medium</span> | bsi, bsi-sys.1.3, bsi-standard, bsi-hoch, kernel |
| `BSI-SYS.1.3.A14-DMESG` | Only privileged users can read the kernel log | <span class="sev sev-low">low</span> | bsi, bsi-sys.1.3, bsi-hoch, kernel |
| `BSI-SYS.1.3.A14-KPTR` | Kernel pointers are hidden from users | <span class="sev sev-low">low</span> | bsi, bsi-sys.1.3, bsi-hoch, kernel |
| `BSI-SYS.1.3.A14-LOG-FILES` | Log files are not readable by all users | <span class="sev sev-low">low</span> | bsi, bsi-sys.1.3, bsi-hoch, logging, permissions |
| `BSI-SYS.1.3.A16-SECCOMP` | Network services run with a system call filter | <span class="sev sev-low">low</span> | bsi, bsi-sys.1.3, bsi-hoch, services |
| `BSI-SYS.1.3.A17-LOCKDOWN` | The kernel runs in lockdown mode | <span class="sev sev-low">low</span> | bsi, bsi-sys.1.3, bsi-hoch, kernel |

## Policy

```yaml title="examples/compliance/bsi-grundschutz.yml" linenums="1"
name: BSI IT-Grundschutz Linux server
version: 1.0.0
description: >
  Technical checks for the host-verifiable requirements of the BSI
  IT-Grundschutz building blocks SYS.1.1 "Allgemeiner Server" and SYS.1.3
  "Server unter Linux und Unix" (IT-Grundschutz-Kompendium, Edition 2023).
  Check names and descriptions are written for checkmate and refer to the
  requirement IDs; they do not reproduce BSI text. Organisational
  requirements (server rooms, documentation, planning, emergency management)
  cannot be checked on a host and are not included.

  The tags follow the BSI levels: `bsi-basis` (B), `bsi-standard` (B and S)
  and `bsi-hoch` (B, S and the requirements for increased protection needs).
  Run for example `checkmate run bsi-grundschutz.yml --tags bsi-standard`.

vars:
  # SYS.1.1.A6: services that a server normally does not need.
  bsi_unwanted_services: [avahi-daemon, cups, cups-browsed, telnet.socket, rsh.socket, rlogin.socket, rexec.socket, tftp.socket, vsftpd, xinetd, ypbind, bluetooth, ModemManager]
  # SYS.1.1.A5: kernel modules for interfaces that must not be usable.
  bsi_disabled_modules: [usb-storage, firewire-core]
  # SYS.1.1.A1: programs of a workstation that must not be on a server.
  bsi_workstation_programs: [firefox, chromium, chromium-browser, google-chrome, microsoft-edge, thunderbird, libreoffice]
  # SYS.1.1.A23: processes of an accepted monitoring agent.
  bsi_monitoring_agents: [node_exporter, prometheus-node-exporter, zabbix_agentd, zabbix_agent2, telegraf, collectd, nrpe, icinga2, datadog-agent, check_mk_agent, cmk-agent-ctl, elastic-agent, metricbeat]
  # SYS.1.1.A27: processes of a host-based intrusion detection agent.
  bsi_hids_agents: [wazuh-agentd, ossec-agentd, falcon-sensor, mdatp, wdavdaemon, sentinelone, osqueryd, auditbeat]
  # SYS.1.1.A30: listening programs that do not count as a service of their own.
  bsi_infrastructure_listeners: [sshd, chronyd, systemd-resolve, systemd-resolved, rpcbind, node_exporter, zabbix_agentd, zabbix_agent2, nrpe, master, exim4]

snippets:
  # Audit rules: the loaded rules if auditd runs, else the rule files.
  audit_rules: |
    if command -v auditctl >/dev/null && auditctl -s 2>/dev/null | grep 'enabled [12]' >/dev/null; then auditctl -l 2>/dev/null
    else cat /etc/audit/rules.d/*.rules /etc/audit/audit.rules 2>/dev/null || true; fi

defaults:
  when: facts.os == "linux"
  timeout: 120s

checks:
  # ===== SYS.1.1 Allgemeiner Server ============================================

  - id: BSI-SYS.1.1.A1-NO-DESKTOP
    name: The server does not boot into a graphical desktop
    description: SYS.1.1.A1 (B), a server must not be used as a workstation.
    tags: [bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch]
    severity: high
    only_if: command -v systemctl && test -d /run/systemd/system
    run: systemctl get-default
    expect: "!= graphical.target"
    rationale: A graphical desktop adds software a server does not need and invites its use as a workstation.
    remediation: Run `systemctl set-default multi-user.target` and reboot.

  - id: BSI-SYS.1.1.A1-NO-WORKSTATION-APPS
    name: No web browser or office program is installed
    description: SYS.1.1.A1 (B), browsers on a server must not be used to fetch information or software from the internet.
    tags: [bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch]
    severity: high
    run: |
      for p in {{ bsi_workstation_programs | join(' ') }}; do
        if command -v "$p" >/dev/null 2>&1; then command -v "$p"; fi
      done
    expect: empty
    rationale: A browser, mail client or office program opens untrusted content from the internet on a system that holds server data.
    remediation: Remove the listed programs with the package manager.

  - id: BSI-SYS.1.1.A2-SSH-EMPTY-PASSWORDS
    name: SSH rejects empty passwords
    description: SYS.1.1.A2 (B), logins use authentication appropriate to the protection needs.
    tags: [bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, ssh]
    severity: critical
    when: facts.is_root
    only_if: command -v sshd
    run: sshd -T 2>/dev/null | awk '$1 == "permitemptypasswords" {print $2}'
    expect: "== no"
    rationale: With PermitEmptyPasswords yes an account without a password can be used over the network without any credential.
    remediation: Set PermitEmptyPasswords no in /etc/ssh/sshd_config and reload sshd.

  - id: BSI-SYS.1.1.A2-EMPTY-PASSWORDS
    name: No account has an empty password
    description: SYS.1.1.A2 (B).
    tags: [bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, accounts]
    severity: critical
    when: facts.is_root
    run: |
      awk -F: '$2 == "" {print $1}' /etc/shadow
    expect: empty
    rationale: Anyone can log in to an account whose password field in /etc/shadow is empty.
    remediation: Set a password for each listed account or lock it with `passwd -l <account>`.

  - id: "BSI-SYS.1.1.A5-MODULE-{{ item | upper }}"
    name: "Kernel module {{ item }} cannot be loaded"
    description: SYS.1.1.A5 (B), only intended devices can be connected and unused interfaces are disabled.
    tags: [bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, modules]
    severity: medium
    when: facts.is_root
    only_if: command -v modprobe
    loop: "{{ bsi_disabled_modules }}"
    run:
      # BusyBox modprobe has no -n; read the configuration instead.
      alpine: grep -rhE '^(install|blacklist)[[:space:]]+{{ item }}([[:space:]]|$)' /etc/modprobe.d /lib/modprobe.d 2>/dev/null
      linux: modprobe -n -v {{ item }} 2>&1
    allow_rc: [0, 1, 2]
    expect: { any: ["~ install( {{ item }})? /(usr/)?bin/(true|false)", "~ (?i)not found", "~ ^blacklist"] }
    rationale: "The {{ item }} module makes an interface usable through which anyone with physical access can copy data or attack the system."
    remediation: "printf 'install {{ item }} /bin/false\\nblacklist {{ item }}\\n' > /etc/modprobe.d/{{ item }}.conf"

  - id: "BSI-SYS.1.1.A6-SERVICE-{{ item | upper }}"
    name: "Service {{ item }} is not active"
    description: SYS.1.1.A6 (B), services a server does not need are disabled or removed.
    tags: [bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, services]
    severity: medium
    only_if: command -v systemctl && test -d /run/systemd/system
    loop: "{{ bsi_unwanted_services }}"
    run: systemctl show -p ActiveState {{ item }} | cut -d= -f2
    expect: "!= active"
    rationale: "A running {{ item }} adds attack surface for a function the server does not need."
    remediation: "systemctl disable --now {{ item }}"

  - id: BSI-SYS.1.1.A6-LEGACY-LISTENERS
    name: No telnet, rsh, rlogin, rexec, TFTP or FTP service is listening
    description: SYS.1.1.A6 (B) and SYS.1.3.A8 (S), protocols that SSH replaces are switched off.
    tags: [bsi, bsi-sys.1.1, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch, services]
    severity: high
    when: facts.is_root
    only_if: command -v ss
    run: ss -Htulnp | awk '{split($5, a, ":"); p = a[length(a)]} p == 21 || p == 23 || p == 69 || p == 512 || p == 513 || p == 514'
    expect: empty
    rationale: These protocols transfer data and passwords in clear text, and SSH replaces all of them.
    remediation: Stop and disable the service behind each listed socket and remove its package.

  - id: BSI-SYS.1.1.A10-AUDITD
    name: The audit daemon is running
    description: SYS.1.1.A10 (B), security-relevant system events are logged.
    tags: [bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, logging]
    severity: high
    when: facts.is_root
    only_if: command -v systemctl && test -d /run/systemd/system
    run: systemctl show -p ActiveState auditd | cut -d= -f2
    expect: "== active"
    rationale: Without auditd security-relevant events such as logins and permission changes leave no audit trail.
    remediation: Install the audit package and run `systemctl enable --now auditd`.

  - id: "BSI-SYS.1.1.A10-AUDIT-{{ item.key }}"
    name: "{{ item.value.name }}"
    description: "SYS.1.1.A10 (B) lists the events that must be logged at least; this check covers {{ item.value.event }}."
    tags: [bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, logging, audit]
    severity: medium
    when: facts.is_root
    only_if: command -v auditctl || test -d /etc/audit
    loop:
      LOGINS:
        name: Logins and failed logins are audited
        event: successful and failed logins
        pattern: "(/var/log/lastlog|/var/run/faillock|/var/log/faillog|/var/log/tallylog)"
      IDENTITY:
        name: Changes to users and groups are audited
        event: creation and changes of users and groups
        pattern: "/etc/(passwd|shadow|group|gshadow)"
      PERMISSIONS:
        name: Changes of file permissions are audited
        event: changes of permissions
        pattern: "(chmod|fchmod|chown|fchown|setxattr)"
      ACCESS-DENIED:
        name: Failed access attempts are audited
        event: failed permission checks
        pattern: "(EACCES|EPERM|exit=-13|exit=-1 )"
    run: { use: audit_rules }
    expect: { some: "~ {{ item.value.pattern }}" }
    rationale: "Without an audit rule for {{ item.value.event }} these events cannot be traced after an incident."
    remediation: "Add an audit rule for {{ item.value.event }} to a file in /etc/audit/rules.d and load it with `augenrules --load`."

  - id: BSI-SYS.1.1.A10-PERSISTENT-LOG
    name: System events are written to a persistent log
    description: SYS.1.1.A10 (B), including system starts and security-relevant error messages.
    tags: [bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, logging]
    severity: high
    run: |
      for s in rsyslog syslog-ng; do
        if command -v systemctl >/dev/null && [ "$(systemctl show -p ActiveState "$s" 2>/dev/null | cut -d= -f2)" = active ]; then echo "$s"; exit 0; fi
      done
      storage=$({ cat /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null || true; } |
        awk -F= '$1 == "Storage" {v = $2} END {print v}')
      if [ "$storage" = persistent ] || { [ "${storage:-auto}" = auto ] && [ -d /var/log/journal ]; }; then echo journald; exit 0; fi
      echo none
    expect: "!= none"
    rationale: A journal that is kept only in memory is lost at reboot, and with it the record of system starts and errors.
    remediation: Set Storage=persistent in /etc/systemd/journald.conf and restart systemd-journald, or run rsyslog or syslog-ng.

  - id: BSI-SYS.1.1.A10-FIREWALL-LOG
    name: Blocked network traffic is logged
    description: SYS.1.1.A10 (B), blocked data flows (violations of firewall rules) are logged.
    tags: [bsi, bsi-sys.1.1, bsi-basis, bsi-standard, bsi-hoch, logging, firewall]
    severity: medium
    when: facts.is_root
    run: |
      if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
        echo "firewalld LogDenied=$(firewall-cmd --get-log-denied 2>/dev/null)"; exit 0
      fi
      if command -v ufw >/dev/null && ufw status verbose 2>/dev/null | grep '^Status: active' >/dev/null; then
        ufw status verbose | awk -F': ' '/^Logging/ {print "ufw " $2}'; exit 0
      fi
      if command -v nft >/dev/null && nft list ruleset 2>/dev/null | grep -w log >/dev/null; then echo "nftables log rule"; exit 0; fi
      if command -v iptables >/dev/null && iptables -S 2>/dev/null | grep -- '-j LOG' >/dev/null; then echo "iptables LOG rule"; exit 0; fi
      echo "no logging of blocked traffic"
    expect: { all: ["!~ ^no logging", "!~ LogDenied=(off|)$", "!~ ^ufw off"] }
    rationale: Blocked connections that are not logged hide port scans and attempts to get around the firewall rules.
    remediation: Run `firewall-cmd --set-log-denied=all` with firewalld or `ufw logging on` with ufw. With nftables or iptables add a log rule in front of the final drop.

  - id: BSI-SYS.1.1.A19-FIREWALL-DEFAULT-DENY
    name: The local packet filter rejects incoming traffic by default
    description: SYS.1.1.A19 (S), inbound communication is limited to the required partners, protocols and ports.
    tags: [bsi, bsi-sys.1.1, bsi-standard, bsi-hoch, firewall]
    severity: medium
    when: facts.is_root
    run: |
      if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then
        t=$(firewall-cmd --info-zone="$(firewall-cmd --get-default-zone)" 2>/dev/null | awk -F': ' '$1 ~ /target/ {print $2}')
        case "$t" in ACCEPT) echo "firewalld default zone accepts everything" ;; *) echo "firewalld target $t" ;; esac; exit 0
      fi
      if command -v ufw >/dev/null && ufw status verbose 2>/dev/null | grep '^Status: active' >/dev/null; then
        ufw status verbose | awk -F': ' '/^Default/ {print "ufw " $2}'; exit 0
      fi
      if command -v nft >/dev/null && nft list ruleset 2>/dev/null | grep -E 'hook input.*policy drop' >/dev/null; then echo "nftables input policy drop"; exit 0; fi
      if command -v iptables >/dev/null && iptables -S INPUT 2>/dev/null | grep -E '^-P INPUT (DROP|REJECT)' >/dev/null; then echo "iptables input policy drop"; exit 0; fi
      echo "no packet filter with a default deny for incoming traffic"
    expect: { all: ["!~ ^no packet filter", "!~ accepts everything", "!~ ^ufw allow \\(incoming\\)"] }
    rationale: A packet filter that accepts by default exposes every listening port to the whole network.
    remediation: Allow the required ports first. Then run `ufw default deny incoming`, set the input policy of nftables or iptables to drop, or use a firewalld default zone whose target is not ACCEPT.

  - id: BSI-SYS.1.1.A23-MONITORING
    name: A monitoring agent is running
    description: SYS.1.1.A23 (S), the server is part of a monitoring concept. Adjust bsi_monitoring_agents to the agents in use.
    tags: [bsi, bsi-sys.1.1, bsi-standard, bsi-hoch, monitoring]
    severity: low
    only_if: command -v pgrep
    run: |
      for a in {{ bsi_monitoring_agents | join(' ') }}; do
        if pgrep -x "$a" >/dev/null 2>&1; then echo "$a"; exit 0; fi
      done
      echo none
    expect: "!= none"
    rationale: A server without a monitoring agent can fail or run out of resources without anyone noticing.
    remediation: Install and start the monitoring agent in use, or add its process name to bsi_monitoring_agents.

  - id: BSI-SYS.1.1.A27-HIDS
    name: File integrity monitoring or a host-based IDS is in place
    description: SYS.1.1.A27 (H), changes to system files and configuration are detected and reported (AIDE, Tripwire, Samhain scheduled, or an IDS agent).
    tags: [bsi, bsi-sys.1.1, bsi-hoch, integrity]
    severity: low
    when: facts.is_root
    run: |
      for a in {{ bsi_hids_agents | join(' ') }}; do
        if pgrep -x "$a" >/dev/null 2>&1; then echo "agent $a"; exit 0; fi
      done
      for t in aide tripwire samhain; do
        command -v "$t" >/dev/null 2>&1 || continue
        if grep -rqs "$t" /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.weekly /var/spool/cron 2>/dev/null ||
           { command -v systemctl >/dev/null && systemctl list-timers --all --no-legend 2>/dev/null | grep -i "$t" >/dev/null; }; then
          echo "$t scheduled"; exit 0
        fi
      done
      echo none
    expect: "!= none"
    rationale: Without integrity monitoring a manipulated system file or configuration stays undetected.
    remediation: Install AIDE, initialize its database and schedule a regular check, or add the process name of the IDS agent in use to bsi_hids_agents.

  - id: BSI-SYS.1.1.A30-ONE-SERVICE
    name: The server offers at most one network service
    description: >
      SYS.1.1.A30 (H). Counts programs listening on non-loopback addresses,
      without SSH, time, DNS stub and monitoring daemons
      (bsi_infrastructure_listeners).
    tags: [bsi, bsi-sys.1.1, bsi-hoch, services]
    severity: low
    when: facts.is_root
    only_if: command -v ss
    run: |
      ss -Htlnp | awk -v skip="{{ bsi_infrastructure_listeners | join(' ') }}" '
        BEGIN {n = split(skip, s, " "); for (i = 1; i <= n; i++) ok[s[i]] = 1}
        $4 !~ /^(127\.|\[::1\]|::1)/ && match($0, /users:\(\("[^"]+"/) {
          p = substr($0, RSTART + 9, RLENGTH - 10); if (!(p in ok)) seen[p] = 1
        }
        END {for (p in seen) print p}' | sort
    expect: { lines: "<= 1" }
    rationale: Services that share a server share its weaknesses, so a compromise of one exposes the data of the others.
    remediation: Move the additional services to servers of their own, or add infrastructure daemons to bsi_infrastructure_listeners.

  - id: BSI-SYS.1.1.A31-EXECUTION-CONTROL
    name: Execution control allows only approved programs
    description: SYS.1.1.A31 (H). fapolicyd must be active.
    tags: [bsi, bsi-sys.1.1, bsi-hoch]
    severity: low
    only_if: command -v systemctl && test -d /run/systemd/system
    run: systemctl show -p ActiveState fapolicyd | cut -d= -f2
    expect: "== active"
    rationale: Without execution control any file that a user or an attacker places on the server can be run.
    remediation: Install fapolicyd, review its rules and run `systemctl enable --now fapolicyd`.

  - id: BSI-SYS.1.1.A34-DISK-ENCRYPTION
    name: The root file system is encrypted
    description: SYS.1.1.A34 (H), the storage of servers with increased protection needs is encrypted.
    tags: [bsi, bsi-sys.1.1, bsi-hoch, encryption]
    severity: low
    when: facts.is_root
    only_if: command -v lsblk && command -v findmnt
    run: |
      src=$(findmnt -n -o SOURCE /)
      if lsblk -s -n -o TYPE "$src" 2>/dev/null | grep crypt >/dev/null; then echo encrypted; else echo "$src is not on a dm-crypt device"; fi
    expect: "== encrypted"
    rationale: An unencrypted disk can be read by anyone who gets hold of the drive or of a copy of the volume.
    remediation: Reinstall or migrate the server onto a LUKS-encrypted root volume.

  - id: BSI-SYS.1.1.A36-SECURE-BOOT
    name: Secure Boot is enabled
    description: SYS.1.1.A36 (H), boot loader and kernel are verified in a chain of trust.
    tags: [bsi, bsi-sys.1.1, bsi-hoch, boot]
    severity: low
    only_if: test -d /sys/firmware/efi
    run: |
      if command -v mokutil >/dev/null; then mokutil --sb-state 2>&1 | sed -n 1p; exit 0; fi
      f=$(ls /sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null | sed -n 1p)
      if [ -n "$f" ] && [ "$(od -An -tu1 -j4 -N1 "$f" | tr -d ' ')" = 1 ]; then echo "SecureBoot enabled"; else echo "SecureBoot disabled"; fi
    expect: "~ (?i)SecureBoot enabled"
    rationale: Without Secure Boot a modified boot loader or kernel starts unnoticed.
    remediation: Enable Secure Boot in the UEFI firmware setup and boot a signed boot loader and kernel.

  - id: BSI-SYS.1.1.A38-READ-ONLY-ROOT
    name: The root file system is read-only
    description: SYS.1.1.A38 (H), immutable host system (read-only root or an image-based OS such as rpm-ostree).
    tags: [bsi, bsi-sys.1.1, bsi-hoch]
    severity: low
    only_if: command -v findmnt
    run: |
      if [ -e /run/ostree-booted ]; then echo immutable; exit 0; fi
      findmnt -n -o OPTIONS / | tr ',' '\n' | grep -x ro >/dev/null && echo immutable || echo "root is mounted read-write"
    expect: "== immutable"
    rationale: On a writable root file system an attacker with root rights can change system files permanently.
    remediation: Mount / read-only or deploy the server as an image-based system such as rpm-ostree.

  # ===== SYS.1.3 Server unter Linux und Unix ===================================

  - id: "BSI-SYS.1.3.A2-UNIQUE-{{ item.key }}"
    name: "{{ item.value.name }}"
    description: SYS.1.3.A2 (B), login names, UIDs and GIDs occur only once.
    tags: [bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch, accounts]
    severity: high
    loop:
      LOGIN: { name: Every login name is unique, file: /etc/passwd, field: 1 }
      UID: { name: Every UID is unique, file: /etc/passwd, field: 3 }
      GROUP: { name: Every group name is unique, file: /etc/group, field: 1 }
      GID: { name: Every GID is unique, file: /etc/group, field: 3 }
    run: cut -d':' -f{{ item.value.field }} {{ item.value.file }} | sort | uniq -d
    expect: empty
    rationale: "Duplicate entries in {{ item.value.file }} make it impossible to tell from file ownership and logs which account or group is meant."
    remediation: "Rename or renumber the duplicates listed from {{ item.value.file }} with usermod or groupmod."

  - id: BSI-SYS.1.3.A2-GROUPS-DEFINED
    name: Every primary group of an account exists
    description: SYS.1.3.A2 (B), every GID used in /etc/passwd is defined in /etc/group.
    tags: [bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch, accounts]
    severity: medium
    run: |
      awk -F: 'NR == FNR {gid[$3] = 1; next} !($4 in gid) {print $1 " (GID " $4 ")"}' /etc/group /etc/passwd
    expect: empty
    rationale: Files of an undefined GID belong to no administered group, and a group created later with that GID gets access to them.
    remediation: Create the missing group with `groupadd -g <gid> <name>` or assign the account an existing primary group with `usermod -g`.

  - id: BSI-SYS.1.3.A3-AUTOFS
    name: Removable media are not mounted automatically
    description: SYS.1.3.A3 (B). The automounter autofs must not run.
    tags: [bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch]
    severity: medium
    only_if: command -v systemctl && test -d /run/systemd/system
    run: systemctl show -p ActiveState autofs | cut -d= -f2
    expect: "!= active"
    rationale: Automatically mounted removable media bring unchecked files and programs onto the server.
    remediation: systemctl disable --now autofs

  - id: BSI-SYS.1.3.A3-DESKTOP-AUTOMOUNT
    name: The desktop does not mount removable media automatically
    description: SYS.1.3.A3 (B). If GNOME settings are managed in dconf, automount must be off.
    tags: [bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch]
    severity: medium
    only_if: test -d /etc/dconf/db && command -v gsettings
    run: |
      cat /etc/dconf/db/*.d/* 2>/dev/null | awk -F= '$1 ~ /^automount$/ {gsub(/[[:space:]]/, "", $2); v = $2} END {print (v == "" ? "not set" : v)}'
    expect: "== false"
    rationale: A desktop session that mounts inserted media by itself makes their content available without a decision by an administrator.
    remediation: Set automount=false under [org/gnome/desktop/media-handling] in a file below /etc/dconf/db/local.d and run `dconf update`.

  - id: BSI-SYS.1.3.A4-ASLR
    name: Address space layout randomization is fully enabled
    description: SYS.1.3.A4 (B), ASLR is active in the kernel.
    tags: [bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch, kernel]
    severity: high
    run: cat /proc/sys/kernel/randomize_va_space
    expect: "== 2"
    rationale: Without full address space randomization memory addresses are predictable, which makes memory corruption exploits reliable.
    remediation: Set kernel.randomize_va_space = 2 in a file below /etc/sysctl.d and run `sysctl --system`.

  - id: BSI-SYS.1.3.A4-NX
    name: The NX bit is available and not disabled
    description: >
      SYS.1.3.A4 (B), DEP/NX is active. On x86 the CPU must report the nx
      flag; on every architecture the kernel command line must not switch
      it off.
    tags: [bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch, kernel]
    severity: high
    run: |
      for o in $(cat /proc/cmdline); do
        case "$o" in noexec=off|noexec32=off|nx=off) echo "kernel command line disables NX: $o" ;; esac
      done
      case "$(uname -m)" in
        x86_64|i?86) grep -qw nx /proc/cpuinfo || echo "the CPU does not report the nx flag" ;;
      esac
    expect: empty
    rationale: Without NX an attacker can execute data injected into the stack or heap as code.
    remediation: Remove the listed option from the kernel command line in the boot loader configuration and reboot. If the CPU flag is missing, enable NX/XD in the firmware setup.

  - id: BSI-SYS.1.3.A4-KERNEL-PROTECTION
    name: Kernel security functions are not switched off at boot
    description: SYS.1.3.A4 (B), security functions of the kernel must not be disabled (no norandmaps, mitigations=off, nopti, nosmap, nosmep, kaslr off).
    tags: [bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch, kernel]
    severity: high
    run: |
      for o in $(cat /proc/cmdline); do
        case "$o" in norandmaps|mitigations=off|nopti|pti=off|nosmap|nosmep|nokaslr|selinux=0|apparmor=0|enforcing=0|audit=0) echo "$o" ;; esac
      done
    expect: empty
    rationale: Each of these boot options switches off a kernel protection such as KASLR, page table isolation, CPU vulnerability mitigations, mandatory access control or auditing.
    remediation: Remove the listed options from the kernel command line in the boot loader configuration and reboot.

  - id: BSI-SYS.1.3.A5-UNPACKAGED-BINARIES
    name: System binary directories contain only files from packages
    description: >
      SYS.1.3.A5 (B), software built from source must not be installed
      uncontrolled into the root file system. Lists regular files in /usr/bin
      and /usr/sbin that belong to no package (use /usr/local or /opt
      instead).
    tags: [bsi, bsi-sys.1.3, bsi-basis, bsi-standard, bsi-hoch, packages]
    severity: medium
    run:
      rhel,suse: |
        tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
        rpm -qa --qf '[%{FILENAMES}\n]' | sed -e 's|^/bin/|/usr/bin/|' -e 's|^/sbin/|/usr/sbin/|' | sort -u > "$tmp/pkg"
        find /usr/bin /usr/sbin -maxdepth 1 -type f | sort > "$tmp/fs"
        comm -23 "$tmp/fs" "$tmp/pkg"
      debian: |
        tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
        cat /var/lib/dpkg/info/*.list | sed -e 's|^/bin/|/usr/bin/|' -e 's|^/sbin/|/usr/sbin/|' | sort -u > "$tmp/pkg"
        find /usr/bin /usr/sbin -maxdepth 1 -type f | sort > "$tmp/fs"
        comm -23 "$tmp/fs" "$tmp/pkg"
    expect: empty
    rationale: Files in /usr/bin and /usr/sbin that belong to no package receive no updates and cannot be verified against the package database.
    remediation: Move self-built software to /usr/local or /opt or install it as a package. Investigate listed files of unknown origin.

  - id: BSI-SYS.1.3.A8-SSH-KEYS
    name: SSH logins use keys instead of passwords
    description: SYS.1.3.A8 (S), certificates or keys are preferred over passwords.
    tags: [bsi, bsi-sys.1.3, bsi-standard, bsi-hoch, ssh]
    severity: medium
    when: facts.is_root
    only_if: command -v sshd
    run: sshd -T 2>/dev/null | awk '$1 == "passwordauthentication" {print $2}'
    expect: "== no"
    rationale: Passwords can be guessed, phished and reused, while a private key never leaves the client.
    remediation: Set PasswordAuthentication no in /etc/ssh/sshd_config and reload sshd once key logins work.

  - id: BSI-SYS.1.3.A10-MAC
    name: SELinux is enforcing or AppArmor enforces profiles
    description: SYS.1.3.A10 (S), services are confined by a mandatory access control with the shipped default policy active.
    tags: [bsi, bsi-sys.1.3, bsi-standard, bsi-hoch, kernel]
    severity: medium
    when: facts.is_root
    run: |
      if command -v getenforce >/dev/null && [ "$(getenforce 2>/dev/null)" != Disabled ]; then echo "SELinux $(getenforce)"; exit 0; fi
      if [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = Y ]; then
        n=$(grep -c '(enforce)' /sys/kernel/security/apparmor/profiles 2>/dev/null || true)
        echo "AppArmor ${n:-0} profiles in enforce mode"; exit 0
      fi
      echo "no mandatory access control"
    expect: { any: ["== SELinux Enforcing", "~ ^AppArmor [1-9][0-9]* profiles"] }
    rationale: Without mandatory access control a compromised service can use every right of its user account.
    remediation: Set SELINUX=enforcing in /etc/selinux/config and reboot, or enable AppArmor and put the shipped profiles into enforce mode with aa-enforce.

  - id: "BSI-SYS.1.3.A14-{{ item.key }}"
    name: "{{ item.value.name }}"
    description: SYS.1.3.A14 (H), system information is only shown to users as far as necessary.
    tags: [bsi, bsi-sys.1.3, bsi-hoch, kernel]
    severity: low
    loop:
      DMESG: { name: Only privileged users can read the kernel log, file: /proc/sys/kernel/dmesg_restrict, expect: "== 1" }
      KPTR: { name: Kernel pointers are hidden from users, file: /proc/sys/kernel/kptr_restrict, expect: ">= 1" }
    run: cat {{ item.value.file }}
    expect: "{{ item.value.expect }}"
    rationale: The kernel log and kernel pointers reveal addresses that help a local user to exploit kernel bugs.
    remediation: "Set the sysctl behind {{ item.value.file }} to 1 in a file below /etc/sysctl.d and run `sysctl --system`."

  - id: BSI-SYS.1.3.A14-LOG-FILES
    name: Log files are not readable by all users
    description: SYS.1.3.A14 (H), access to log files is limited. Lists world-readable files below /var/log.
    tags: [bsi, bsi-sys.1.3, bsi-hoch, logging, permissions]
    severity: low
    when: facts.is_root
    run: find -H /var/log -type f -perm -0004 2>/dev/null
    expect: empty
    rationale: Log files contain user names, addresses and error details that help an unprivileged user to prepare an attack.
    remediation: Run `chmod o-r` on the listed files and correct the mode in the logrotate or syslog configuration that creates them.

  - id: BSI-SYS.1.3.A16-SECCOMP
    name: Network services run with a system call filter
    description: >
      SYS.1.3.A16 (H), exposed services may only use the system calls they
      need. Lists programs listening on non-loopback addresses without a
      seccomp filter (Seccomp 2 in /proc/PID/status, e.g. from SystemCallFilter=).
    tags: [bsi, bsi-sys.1.3, bsi-hoch, services]
    severity: low
    when: facts.is_root
    only_if: command -v ss
    run: |
      ss -Htulnp | awk '$5 !~ /^(127\.|\[::1\]|::1)/' | { grep -oE 'pid=[0-9]+' || true; } | cut -d= -f2 | sort -u |
      while read -r pid; do
        mode=$(awk '/^Seccomp:/ {print $2}' "/proc/$pid/status" 2>/dev/null)
        if [ "$mode" != 2 ]; then echo "$(cat "/proc/$pid/comm" 2>/dev/null) (pid $pid)"; fi
      done
    expect: empty
    rationale: A network service without a system call filter can use the whole kernel interface once it is compromised.
    remediation: Add a filter such as SystemCallFilter=@system-service to the systemd unit of each listed service and restart it.

  - id: BSI-SYS.1.3.A17-LOCKDOWN
    name: The kernel runs in lockdown mode
    description: SYS.1.3.A17 (H), additional kernel protection; lockdown integrity or confidentiality is active.
    tags: [bsi, bsi-sys.1.3, bsi-hoch, kernel]
    severity: low
    run: cat /sys/kernel/security/lockdown 2>/dev/null || echo "[none] (not supported)"
    expect: "~ \\[(integrity|confidentiality)\\]"
    rationale: Without lockdown root can modify the running kernel, for example through /dev/mem or unsigned modules.
    remediation: Add lockdown=integrity to the kernel command line and reboot.
```
