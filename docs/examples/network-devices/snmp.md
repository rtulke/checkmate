# SNMP polling (any vendor)

Vendor-neutral device checks with the net-snmp tools: uptime, interface status and firmware strings. SNMPv3 credentials come from the environment (SNMP_USER, SNMP_AUTH, SNMP_PRIV).

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/network-devices/snmp.yml`](https://github.com/rtulke/checkmate/blob/main/examples/network-devices/snmp.yml)
- :material-format-list-checks: **Checks**  
  8 from 4 definitions, 4 with loops
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/network-devices/snmp.yml

# Run the checks
checkmate run examples/network-devices/snmp.yml

# Override a variable from the command line
checkmate run examples/network-devices/snmp.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `SNMP-UPTIME-sw-core-01.example.net` | sw-core-01.example.net: up for at least 1 day(s) | <span class="sev sev-low">low</span> | network-devices, snmp |
| `SNMP-UPTIME-ups-01.example.net` | ups-01.example.net: up for at least 1 day(s) | <span class="sev sev-low">low</span> | network-devices, snmp |
| `SNMP-IFDOWN-sw-core-01.example.net` | sw-core-01.example.net: no administratively enabled interface is down | <span class="sev sev-medium">medium</span> | network-devices, snmp, interfaces |
| `SNMP-IFDOWN-ups-01.example.net` | ups-01.example.net: no administratively enabled interface is down | <span class="sev sev-medium">medium</span> | network-devices, snmp, interfaces |
| `SNMP-DESCR-sw-core-01.example.net` | sw-core-01.example.net: answers SNMPv3 queries | <span class="sev sev-medium">medium</span> | network-devices, snmp |
| `SNMP-DESCR-ups-01.example.net` | ups-01.example.net: answers SNMPv3 queries | <span class="sev sev-medium">medium</span> | network-devices, snmp |
| `SNMP-V1-sw-core-01.example.net` | sw-core-01.example.net: does not answer to the community 'public' | <span class="sev sev-critical">critical</span> | network-devices, snmp |
| `SNMP-V1-ups-01.example.net` | ups-01.example.net: does not answer to the community 'public' | <span class="sev sev-critical">critical</span> | network-devices, snmp |

## Policy

```yaml title="examples/network-devices/snmp.yml" linenums="1"
name: SNMP polling (any vendor)
version: 1.0.0
description: >
  Vendor-neutral device checks with the net-snmp tools: uptime, interface
  status and firmware strings. SNMPv3 credentials come from the
  environment (SNMP_USER, SNMP_AUTH, SNMP_PRIV).

vars:
  snmp_devices: [sw-core-01.example.net, ups-01.example.net]
  min_uptime_days: 1

snippets:
  # snmpget/snmpwalk with SNMPv3 authPriv; {{ args.oid }} is the object.
  # -Oqvt prints bare values, timeticks as plain numbers (1/100 s).
  snmp: >-
    snmp{{ args.op | default("get") }} -v3 -l authPriv -u "$SNMP_USER"
    -a SHA -A "$SNMP_AUTH" -x AES -X "$SNMP_PRIV" -Oqvt -t 3 -r 1
    {{ arg }} {{ args.oid }}

defaults:
  # Shell commands for Unix-like systems.
  when: facts.os != "windows"

checks:
  - id: "SNMP-UPTIME-{{ item }}"
    name: "{{ item }}: up for at least {{ min_uptime_days }} day(s)"
    tags: [network-devices, snmp]
    severity: low
    loop: "{{ snmp_devices }}"
    run: { use: snmp, arg: "{{ item }}", args: { oid: SNMPv2-MIB::sysUpTime.0 } }
    expect: ">= {{ min_uptime_days * 8640000 }}"
    rationale: "A short uptime means that {{ item }} restarted recently, possibly after a crash or a power loss."
    remediation: "Look for the reason of the restart in the log of {{ item }}."

  - id: "SNMP-IFDOWN-{{ item }}"
    name: "{{ item }}: no administratively enabled interface is down"
    tags: [network-devices, snmp, interfaces]
    loop: "{{ snmp_devices }}"
    # Admin and oper status are walked separately and joined line by line.
    run: |
      walk() { snmpwalk -v3 -l authPriv -u "$SNMP_USER" -a SHA -A "$SNMP_AUTH" -x AES -X "$SNMP_PRIV" -Oqv {{ item }} "$1"; }
      paste -d' ' <(walk IF-MIB::ifAdminStatus) <(walk IF-MIB::ifOperStatus) | grep -c '^up down$'
    allow_rc: [0, 1]
    expect: "== 0"
    rationale: An enabled interface that is down is a failed link or an unused port that nobody shut down.
    remediation: "Repair the link on {{ item }} or shut the unused interface down administratively."

  - id: "SNMP-DESCR-{{ item }}"
    name: "{{ item }}: answers SNMPv3 queries"
    tags: [network-devices, snmp]
    loop: "{{ snmp_devices }}"
    run: { use: snmp, arg: "{{ item }}", args: { oid: SNMPv2-MIB::sysDescr.0 } }
    expect: "!empty"
    rationale: A device that does not answer is unreachable or uses other SNMPv3 settings, and monitoring cannot see it.
    remediation: "Check that {{ item }} is reachable and compare its SNMPv3 user, authentication and privacy settings."

  - id: "SNMP-V1-{{ item }}"
    name: "{{ item }}: does not answer to the community 'public'"
    tags: [network-devices, snmp]
    severity: critical
    loop: "{{ snmp_devices }}"
    run: snmpget -v2c -c public -t 2 -r 0 {{ item }} SNMPv2-MIB::sysDescr.0 >/dev/null 2>&1
    expect: false
    rationale: The community public is the first one every scanner tries, and SNMPv2c sends it in clear text.
    remediation: "Remove the community public on {{ item }} and allow SNMPv3 only."
```
