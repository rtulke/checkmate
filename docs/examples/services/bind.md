# BIND DNS server

Security of the BIND name server (named): valid configuration, no open recursion, restricted zone transfers, hidden version, DNSSEC validation, an unprivileged process and a protected rndc key. Options are read from the effective configuration printed by named-checkconf -p.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/services/bind.yml`](https://github.com/rtulke/checkmate/blob/main/examples/services/bind.yml)
- :material-format-list-checks: **Checks**  
  8 from 8 definitions
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/services/bind.yml

# Run the checks
checkmate run examples/services/bind.yml
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `BIND-CONFIG` | The BIND configuration is valid | <span class="sev sev-high">high</span> | services, dns, bind |
| `BIND-SERVICE` | BIND is running | <span class="sev sev-medium">medium</span> | services, dns, bind |
| `BIND-NO-OPEN-RECURSION` | Recursion is not offered to everyone | <span class="sev sev-critical">critical</span> | services, dns, bind |
| `BIND-ALLOW-TRANSFER` | Zone transfers are restricted | <span class="sev sev-high">high</span> | services, dns, bind |
| `BIND-VERSION-HIDDEN` | The version is not disclosed | <span class="sev sev-low">low</span> | services, dns, bind |
| `BIND-DNSSEC-VALIDATION` | DNSSEC validation is not switched off | <span class="sev sev-medium">medium</span> | services, dns, bind |
| `BIND-USER` | named does not run as root | <span class="sev sev-high">high</span> | services, dns, bind |
| `BIND-RNDC-KEY` | The rndc key is not readable by other users | <span class="sev sev-high">high</span> | services, dns, bind, permissions |

## Policy

```yaml title="examples/services/bind.yml" linenums="1"
name: BIND DNS server
version: 1.0.0
description: >
  Security of the BIND name server (named): valid configuration, no open
  recursion, restricted zone transfers, hidden version, DNSSEC validation,
  an unprivileged process and a protected rndc key. Options are read from
  the effective configuration printed by named-checkconf -p.

defaults:
  when:
    - facts.os == "linux"
    - facts.is_root

snippets:
  # The effective options block, one statement per line.
  options: named-checkconf -p 2>/dev/null | awk '/^options \{/ {o = 1; next} o && /^\};/ {o = 0} o'

checks:
  - id: BIND-CONFIG
    name: The BIND configuration is valid
    tags: [services, dns, bind]
    severity: high
    only_if: command -v named-checkconf
    run: named-checkconf 2>&1
    allow_rc: [0, 1]
    expect: [true, empty]

  - id: BIND-SERVICE
    name: BIND is running
    tags: [services, dns, bind]
    severity: medium
    only_if: command -v named-checkconf && command -v systemctl && test -d /run/systemd/system
    run: |
      for u in named bind9; do
        if [ "$(systemctl show -p ActiveState "$u" 2>/dev/null | cut -d= -f2)" = active ]; then echo active; exit 0; fi
      done
      echo inactive
    expect: "== active"

  - id: BIND-NO-OPEN-RECURSION
    name: Recursion is not offered to everyone
    description: With recursion on, allow-recursion and allow-query-cache must not contain any (open resolvers are used for amplification attacks).
    tags: [services, dns, bind]
    severity: critical
    only_if: command -v named-checkconf
    run: { use: options, arg: "" }
    expect: { none: '~ ^[[:space:]]*allow-(recursion|query-cache)[[:space:]]*\{[^}]*\bany;' }

  - id: BIND-ALLOW-TRANSFER
    name: Zone transfers are restricted
    description: allow-transfer must be set in the options and not allow any host.
    tags: [services, dns, bind]
    severity: high
    only_if: command -v named-checkconf
    run: { use: options, arg: "" }
    expect:
      - { some: '~ ^[[:space:]]*allow-transfer[[:space:]]' }
      - { none: '~ ^[[:space:]]*allow-transfer[[:space:]]*\{[^}]*\bany;' }

  - id: BIND-VERSION-HIDDEN
    name: The version is not disclosed
    description: 'Set version "none" (or any text) so that "dig version.bind chaos txt" does not reveal it.'
    tags: [services, dns, bind]
    severity: low
    only_if: command -v named-checkconf
    run: { use: options, arg: "" }
    expect: { some: '~ ^[[:space:]]*version[[:space:]]' }

  - id: BIND-DNSSEC-VALIDATION
    name: DNSSEC validation is not switched off
    tags: [services, dns, bind]
    severity: medium
    only_if: command -v named-checkconf
    run: { use: options, arg: "" }
    expect: { none: '~ ^[[:space:]]*dnssec-validation[[:space:]]+no;' }

  - id: BIND-USER
    name: named does not run as root
    tags: [services, dns, bind]
    severity: high
    only_if: pgrep -x named
    run: ps -o user= -C named | sort -u
    expect:
      - "!empty"
      - { none: "== root" }

  - id: BIND-RNDC-KEY
    name: The rndc key is not readable by other users
    tags: [services, dns, bind, permissions]
    severity: high
    only_if: test -e /etc/rndc.key || test -e /etc/bind/rndc.key
    run: find -H /etc/rndc.key /etc/bind/rndc.key -perm /007 -print 2>/dev/null || true
    expect: empty
```
