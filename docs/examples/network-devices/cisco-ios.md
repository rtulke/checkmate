# Cisco IOS / IOS-XE switches and routers

Remote checks of Cisco IOS devices over SSH, run from a management host. Every check loops over the device inventory, so one definition creates a check per device. Authentication uses SSH keys (BatchMode, no prompts).

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/network-devices/cisco-ios.yml`](https://github.com/rtulke/checkmate/blob/main/examples/network-devices/cisco-ios.yml)
- :material-format-list-checks: **Checks**  
  20 from 10 definitions, 10 with loops
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/network-devices/cisco-ios.yml

# Run the checks
checkmate run examples/network-devices/cisco-ios.yml

# Override a variable from the command line
checkmate run examples/network-devices/cisco-ios.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `IOS-PWENC-sw-core-01.example.net` | sw-core-01.example.net: passwords are stored encrypted | <span class="sev sev-high">high</span> | network-devices, cisco |
| `IOS-PWENC-sw-access-01.example.net` | sw-access-01.example.net: passwords are stored encrypted | <span class="sev sev-high">high</span> | network-devices, cisco |
| `IOS-SECRET-sw-core-01.example.net` | sw-core-01.example.net: enable secret instead of enable password | <span class="sev sev-high">high</span> | network-devices, cisco |
| `IOS-SECRET-sw-access-01.example.net` | sw-access-01.example.net: enable secret instead of enable password | <span class="sev sev-high">high</span> | network-devices, cisco |
| `IOS-SSHV2-sw-core-01.example.net` | sw-core-01.example.net: only SSH version 2 is enabled | <span class="sev sev-high">high</span> | network-devices, cisco, ssh |
| `IOS-SSHV2-sw-access-01.example.net` | sw-access-01.example.net: only SSH version 2 is enabled | <span class="sev sev-high">high</span> | network-devices, cisco, ssh |
| `IOS-NOTELNET-sw-core-01.example.net` | sw-core-01.example.net: VTY lines do not accept telnet | <span class="sev sev-critical">critical</span> | network-devices, cisco |
| `IOS-NOTELNET-sw-access-01.example.net` | sw-access-01.example.net: VTY lines do not accept telnet | <span class="sev sev-critical">critical</span> | network-devices, cisco |
| `IOS-TIMEOUT-sw-core-01.example.net` | sw-core-01.example.net: VTY sessions time out | <span class="sev sev-medium">medium</span> | network-devices, cisco |
| `IOS-TIMEOUT-sw-access-01.example.net` | sw-access-01.example.net: VTY sessions time out | <span class="sev sev-medium">medium</span> | network-devices, cisco |
| `IOS-HTTP-sw-core-01.example.net` | sw-core-01.example.net: the plain HTTP server is disabled | <span class="sev sev-high">high</span> | network-devices, cisco |
| `IOS-HTTP-sw-access-01.example.net` | sw-access-01.example.net: the plain HTTP server is disabled | <span class="sev sev-high">high</span> | network-devices, cisco |
| `IOS-SNMP-sw-core-01.example.net` | sw-core-01.example.net: no default SNMP communities | <span class="sev sev-critical">critical</span> | network-devices, cisco, snmp |
| `IOS-SNMP-sw-access-01.example.net` | sw-access-01.example.net: no default SNMP communities | <span class="sev sev-critical">critical</span> | network-devices, cisco, snmp |
| `IOS-NTP-sw-core-01.example.net` | sw-core-01.example.net: NTP is synchronised | <span class="sev sev-medium">medium</span> | network-devices, cisco, time |
| `IOS-NTP-sw-access-01.example.net` | sw-access-01.example.net: NTP is synchronised | <span class="sev sev-medium">medium</span> | network-devices, cisco, time |
| `IOS-LOG-sw-core-01.example.net` | sw-core-01.example.net: logs are sent to a syslog server | <span class="sev sev-medium">medium</span> | network-devices, cisco, logging |
| `IOS-LOG-sw-access-01.example.net` | sw-access-01.example.net: logs are sent to a syslog server | <span class="sev sev-medium">medium</span> | network-devices, cisco, logging |
| `IOS-VERSION-sw-core-01.example.net` | sw-core-01.example.net: runs IOS-XE 17.9 or newer | <span class="sev sev-medium">medium</span> | network-devices, cisco, firmware |
| `IOS-VERSION-sw-access-01.example.net` | sw-access-01.example.net: runs IOS-XE 17.9 or newer | <span class="sev sev-medium">medium</span> | network-devices, cisco, firmware |

## Policy

```yaml title="examples/network-devices/cisco-ios.yml" linenums="1"
name: Cisco IOS / IOS-XE switches and routers
version: 1.0.0
description: >
  Remote checks of Cisco IOS devices over SSH, run from a management host.
  Every check loops over the device inventory, so one definition creates a
  check per device. Authentication uses SSH keys (BatchMode, no prompts).

vars:
  ios_devices: [sw-core-01.example.net, sw-access-01.example.net]
  ios_user: audit

snippets:
  # Runs one IOS exec command on the device {{ arg }}.
  ios: >-
    ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=yes
    {{ ios_user }}@{{ arg }} '{{ args.cmd }}'

checks:
  - id: "IOS-PWENC-{{ item }}"
    name: "{{ item }}: passwords are stored encrypted"
    tags: [network-devices, cisco]
    severity: high
    loop: "{{ ios_devices }}"
    run: { use: ios, arg: "{{ item }}", args: { cmd: "show running-config | include ^service password-encryption" } }
    expect: "== service password-encryption"

  - id: "IOS-SECRET-{{ item }}"
    name: "{{ item }}: enable secret instead of enable password"
    tags: [network-devices, cisco]
    severity: high
    loop: "{{ ios_devices }}"
    run: { use: ios, arg: "{{ item }}", args: { cmd: "show running-config | include ^enable" } }
    expect: ["~ ^enable secret", "!~ ^enable password"]

  - id: "IOS-SSHV2-{{ item }}"
    name: "{{ item }}: only SSH version 2 is enabled"
    tags: [network-devices, cisco, ssh]
    severity: high
    loop: "{{ ios_devices }}"
    run: { use: ios, arg: "{{ item }}", args: { cmd: "show ip ssh" } }
    expect: "~ SSH Enabled - version 2\\.0"

  - id: "IOS-NOTELNET-{{ item }}"
    name: "{{ item }}: VTY lines do not accept telnet"
    tags: [network-devices, cisco]
    severity: critical
    loop: "{{ ios_devices }}"
    run: { use: ios, arg: "{{ item }}", args: { cmd: "show running-config | section line vty" } }
    expect: ["~ transport input ssh", "!~ transport input .*(telnet|all)"]

  - id: "IOS-TIMEOUT-{{ item }}"
    name: "{{ item }}: VTY sessions time out"
    tags: [network-devices, cisco]
    loop: "{{ ios_devices }}"
    run: { use: ios, arg: "{{ item }}", args: { cmd: "show running-config | section line vty" } }
    expect: ["~ exec-timeout", "!~ exec-timeout 0 0"]

  - id: "IOS-HTTP-{{ item }}"
    name: "{{ item }}: the plain HTTP server is disabled"
    tags: [network-devices, cisco]
    severity: high
    loop: "{{ ios_devices }}"
    run: { use: ios, arg: "{{ item }}", args: { cmd: "show running-config | include ^ip http" } }
    expect: "!~ ^ip http server"

  - id: "IOS-SNMP-{{ item }}"
    name: "{{ item }}: no default SNMP communities"
    tags: [network-devices, cisco, snmp]
    severity: critical
    loop: "{{ ios_devices }}"
    run: { use: ios, arg: "{{ item }}", args: { cmd: "show running-config | include ^snmp-server community" } }
    expect: "!~ community (public|private)( |$)"

  - id: "IOS-NTP-{{ item }}"
    name: "{{ item }}: NTP is synchronised"
    tags: [network-devices, cisco, time]
    loop: "{{ ios_devices }}"
    run: { use: ios, arg: "{{ item }}", args: { cmd: "show ntp status" } }
    expect: "~ Clock is synchronized"

  - id: "IOS-LOG-{{ item }}"
    name: "{{ item }}: logs are sent to a syslog server"
    tags: [network-devices, cisco, logging]
    loop: "{{ ios_devices }}"
    run: { use: ios, arg: "{{ item }}", args: { cmd: "show running-config | include ^logging host" } }
    expect: "!empty"

  - id: "IOS-VERSION-{{ item }}"
    name: "{{ item }}: runs IOS-XE 17.9 or newer"
    tags: [network-devices, cisco, firmware]
    loop: "{{ ios_devices }}"
    run: >-
      ssh -o BatchMode=yes -o ConnectTimeout=5 {{ ios_user }}@{{ item }} 'show version'
      | sed -nE 's/.*Version ([0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/p' | head -1
    as: version
    expect: ">= 17.9"
```
