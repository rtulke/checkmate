# Host firewall

firewalld, nftables, iptables and ufw. Each check runs only where its tool exists (`only_if`), so one policy covers all Linux distributions.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/network/firewall.yml`](https://github.com/rtulke/checkmate/blob/main/examples/network/firewall.yml)
- :material-format-list-checks: **Checks**  
  6 from 6 definitions
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/network/firewall.yml

# Run the checks
checkmate run examples/network/firewall.yml

# Override a variable from the command line
checkmate run examples/network/firewall.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `FW-001` | firewalld is running | <span class="sev sev-high">high</span> | network, firewall |
| `FW-002` | The default zone is not "trusted" | <span class="sev sev-high">high</span> | network, firewall |
| `FW-003` | Only approved services are open in the default zone | <span class="sev sev-medium">medium</span> | network, firewall |
| `FW-004` | nftables drops unsolicited input by default | <span class="sev sev-high">high</span> | network, firewall |
| `FW-005` | iptables INPUT policy is DROP | <span class="sev sev-high">high</span> | network, firewall |
| `FW-006` | ufw is active | <span class="sev sev-high">high</span> | network, firewall |

## Policy

```yaml title="examples/network/firewall.yml" linenums="1"
name: Host firewall
version: 1.0.0
description: >
  firewalld, nftables, iptables and ufw. Each check runs only where its
  tool exists (`only_if`), so one policy covers all Linux distributions.

vars:
  allowed_firewalld_services: [ssh, dhcpv6-client, cockpit]

checks:
  - id: FW-001
    name: firewalld is running
    tags: [network, firewall]
    severity: high
    only_if: command -v firewall-cmd
    run: firewall-cmd --state 2>&1
    allow_rc: [0, 252]
    expect: "== running"

  - id: FW-002
    name: The default zone is not "trusted"
    tags: [network, firewall]
    severity: high
    only_if: command -v firewall-cmd && firewall-cmd --state >/dev/null 2>&1
    run: firewall-cmd --get-default-zone
    expect: "!in [trusted]"

  - id: FW-003
    name: Only approved services are open in the default zone
    tags: [network, firewall]
    only_if: command -v firewall-cmd && firewall-cmd --state >/dev/null 2>&1
    run: |
      firewall-cmd --list-services | tr ' ' '\n' | grep -v '^$' |
        grep -vxF {% for s in allowed_firewalld_services %}-e {{ s }} {% endfor %}
    allow_rc: [0, 1]
    expect: empty

  - id: FW-004
    name: nftables drops unsolicited input by default
    tags: [network, firewall]
    severity: high
    when: facts.is_root
    only_if: command -v nft && ! command -v firewall-cmd
    run: |
      nft list ruleset 2>/dev/null | grep -E 'hook input .*policy drop'
    allow_rc: [0, 1]
    expect: { lines: ">= 1" }

  - id: FW-005
    name: iptables INPUT policy is DROP
    tags: [network, firewall]
    severity: high
    when: facts.is_root
    only_if: command -v iptables && ! command -v firewall-cmd && ! command -v nft
    run: iptables -S INPUT | sed -n 1p
    expect: "in ['-P INPUT DROP', '-P INPUT REJECT']"

  - id: FW-006
    name: ufw is active
    tags: [network, firewall]
    severity: high
    when: facts.is_root
    only_if: command -v ufw
    run: ufw status | sed -n 1p
    expect: "== Status: active"
```
