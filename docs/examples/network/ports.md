# Listening ports and reachability

Only approved ports may listen, sensitive services must not listen on all interfaces, and required remote endpoints must be reachable.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/network/ports.yml`](https://github.com/rtulke/checkmate/blob/main/examples/network/ports.yml)
- :material-format-list-checks: **Checks**  
  9 from 4 definitions, 2 with loops
- :material-monitor: **Platforms**  
  linux, macos

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/network/ports.yml

# Run the checks
checkmate run examples/network/ports.yml

# Override a variable from the command line
checkmate run examples/network/ports.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `PORT-001` | Only approved TCP and UDP ports are listening | <span class="sev sev-high">high</span> | network, ports |
| `PORT-LOCAL-3306` | Port 3306 only listens on loopback | <span class="sev sev-high">high</span> | network, ports |
| `PORT-LOCAL-5432` | Port 5432 only listens on loopback | <span class="sev sev-high">high</span> | network, ports |
| `PORT-LOCAL-6379` | Port 6379 only listens on loopback | <span class="sev sev-high">high</span> | network, ports |
| `PORT-LOCAL-11211` | Port 11211 only listens on loopback | <span class="sev sev-high">high</span> | network, ports |
| `PORT-LOCAL-27017` | Port 27017 only listens on loopback | <span class="sev sev-high">high</span> | network, ports |
| `PORT-002` | SSH is listening | <span class="sev sev-medium">medium</span> | network, ports, ssh |
| `PORT-REACH-1.1.1.1-53` | 1.1.1.1:53 is reachable | <span class="sev sev-medium">medium</span> | network, ports, reachability |
| `PORT-REACH-github.com-443` | github.com:443 is reachable | <span class="sev sev-medium">medium</span> | network, ports, reachability |

## Policy

```yaml title="examples/network/ports.yml" linenums="1"
name: Listening ports and reachability
version: 1.0.0
description: >
  Only approved ports may listen, sensitive services must not listen on all
  interfaces, and required remote endpoints must be reachable.

vars:
  allowed_ports: [22, 53, 123, 323]
  local_only_ports: [3306, 5432, 6379, 11211, 27017]
  required_endpoints:
    - { host: 1.1.1.1, port: 53 }
    - { host: github.com, port: 443 }

checks:
  - id: PORT-001
    name: Only approved TCP and UDP ports are listening
    tags: [network, ports]
    severity: high
    run:
      linux: |
        ss -Hlntu | awk '{print $5}' | sed -E 's/.*:([0-9]+)$/\1/' | sort -nu |
          grep -vxF {% for p in allowed_ports %}-e {{ p }} {% endfor %}
      macos: |
        lsof -nP -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR > 1 {print $9}' | sed -E 's/.*:([0-9]+)$/\1/' | sort -nu |
          grep -vxF {% for p in allowed_ports %}-e {{ p }} {% endfor %}
    allow_rc: [0, 1]
    expect: empty
    remediation: Stop or firewall the services listening on the listed ports.

  - id: "PORT-LOCAL-{{ item }}"
    name: "Port {{ item }} only listens on loopback"
    tags: [network, ports]
    severity: high
    when: facts.os == "linux"
    loop: "{{ local_only_ports }}"
    # Local addresses like 0.0.0.0:5432, *:5432 or [::]:5432 mean "all interfaces".
    run: |
      ss -Hlnt "sport = :{{ item }}" | awk '{print $4}'
    expect: "!~ ^(0\\.0\\.0\\.0|\\*|\\[::\\]):"

  - id: PORT-002
    name: SSH is listening
    tags: [network, ports, ssh]
    run:
      linux: ss -Hlnt 'sport = :22'
      macos: lsof -nP -iTCP:22 -sTCP:LISTEN
    allow_rc: [0, 1]
    expect: "!empty"

  - id: "PORT-REACH-{{ item.host }}-{{ item.port }}"
    name: "{{ item.host }}:{{ item.port }} is reachable"
    tags: [network, ports, reachability]
    loop: "{{ required_endpoints }}"
    run: nc -z -w 3 {{ item.host }} {{ item.port }}
    timeout: 10s
    expect: true
```
