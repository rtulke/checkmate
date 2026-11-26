# Juniper Junos

Remote checks of Junos devices over SSH. `display set` turns the hierarchical configuration into one line per statement, which makes it easy to match with regular expressions.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/network-devices/juniper-junos.yml`](https://github.com/rtulke/checkmate/blob/main/examples/network-devices/juniper-junos.yml)
- :material-format-list-checks: **Checks**  
  6 from 6 definitions, 6 with loops
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/network-devices/juniper-junos.yml

# Run the checks
checkmate run examples/network-devices/juniper-junos.yml

# Override a variable from the command line
checkmate run examples/network-devices/juniper-junos.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `JUNOS-TELNET-fw-edge-01.example.net` | fw-edge-01.example.net: telnet is disabled | <span class="sev sev-critical">critical</span> | network-devices, juniper |
| `JUNOS-ROOTLOGIN-fw-edge-01.example.net` | fw-edge-01.example.net: root cannot log in over SSH | <span class="sev sev-high">high</span> | network-devices, juniper, ssh |
| `JUNOS-SSHV2-fw-edge-01.example.net` | fw-edge-01.example.net: SSH protocol version 2 only | <span class="sev sev-medium">medium</span> | network-devices, juniper, ssh |
| `JUNOS-NTP-fw-edge-01.example.net` | fw-edge-01.example.net: NTP servers are configured | <span class="sev sev-medium">medium</span> | network-devices, juniper, time |
| `JUNOS-SYSLOG-fw-edge-01.example.net` | fw-edge-01.example.net: remote syslog is configured | <span class="sev sev-medium">medium</span> | network-devices, juniper, logging |
| `JUNOS-SNMP-fw-edge-01.example.net` | fw-edge-01.example.net: no default SNMP communities | <span class="sev sev-critical">critical</span> | network-devices, juniper, snmp |

## Policy

```yaml title="examples/network-devices/juniper-junos.yml" linenums="1"
name: Juniper Junos
version: 1.0.0
description: >
  Remote checks of Junos devices over SSH. `display set` turns the
  hierarchical configuration into one line per statement, which makes it
  easy to match with regular expressions.

vars:
  junos_devices: [fw-edge-01.example.net]
  junos_user: audit

snippets:
  junos: >-
    ssh -o BatchMode=yes -o ConnectTimeout=5 {{ junos_user }}@{{ arg }}
    'show configuration {{ args.path | default("") }} | display set'

checks:
  - id: "JUNOS-TELNET-{{ item }}"
    name: "{{ item }}: telnet is disabled"
    tags: [network-devices, juniper]
    severity: critical
    loop: "{{ junos_devices }}"
    run: { use: junos, arg: "{{ item }}", args: { path: system services } }
    expect: "!~ set system services telnet"
    rationale: telnet sends passwords and the whole session in clear text.
    remediation: "Run `delete system services telnet` on {{ item }} and commit."

  - id: "JUNOS-ROOTLOGIN-{{ item }}"
    name: "{{ item }}: root cannot log in over SSH"
    tags: [network-devices, juniper, ssh]
    severity: high
    loop: "{{ junos_devices }}"
    run: { use: junos, arg: "{{ item }}", args: { path: system services ssh } }
    expect: "~ root-login deny"
    rationale: Direct root logins expose the most powerful account to password guessing and cannot be attributed to a person.
    remediation: "Run `set system services ssh root-login deny` on {{ item }} and commit."

  - id: "JUNOS-SSHV2-{{ item }}"
    name: "{{ item }}: SSH protocol version 2 only"
    tags: [network-devices, juniper, ssh]
    loop: "{{ junos_devices }}"
    run: { use: junos, arg: "{{ item }}", args: { path: system services ssh } }
    expect: "!~ protocol-version v1"
    rationale: SSH version 1 has known protocol weaknesses that allow session hijacking.
    remediation: "Run `delete system services ssh protocol-version v1` on {{ item }} and commit."

  - id: "JUNOS-NTP-{{ item }}"
    name: "{{ item }}: NTP servers are configured"
    tags: [network-devices, juniper, time]
    loop: "{{ junos_devices }}"
    run: { use: junos, arg: "{{ item }}", args: { path: system ntp } }
    expect: "~ set system ntp server"
    rationale: "Without NTP the clock of {{ item }} drifts and its log timestamps cannot be correlated with other devices."
    remediation: "Run `set system ntp server <address>` on {{ item }} and commit."

  - id: "JUNOS-SYSLOG-{{ item }}"
    name: "{{ item }}: remote syslog is configured"
    tags: [network-devices, juniper, logging]
    loop: "{{ junos_devices }}"
    run: { use: junos, arg: "{{ item }}", args: { path: system syslog } }
    expect: "~ set system syslog host"
    rationale: Local log files are limited in size and are lost with the device, so events need a copy on a server.
    remediation: "Run `set system syslog host <address> any notice` on {{ item }} and commit."

  - id: "JUNOS-SNMP-{{ item }}"
    name: "{{ item }}: no default SNMP communities"
    tags: [network-devices, juniper, snmp]
    severity: critical
    loop: "{{ junos_devices }}"
    run: { use: junos, arg: "{{ item }}", args: { path: snmp } }
    expect: "!~ community (public|private)( |$)"
    rationale: The communities public and private are the first ones every scanner tries, and they expose the device data to anyone.
    remediation: "Run `delete snmp community public` and `delete snmp community private` on {{ item }} and commit."
```
