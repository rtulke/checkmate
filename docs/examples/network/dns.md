# DNS and name resolution

Resolver configuration, approved name servers, working resolution and a sane /etc/hosts.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/network/dns.yml`](https://github.com/rtulke/checkmate/blob/main/examples/network/dns.yml)
- :material-format-list-checks: **Checks**  
  6 from 6 definitions
- :material-monitor: **Platforms**  
  linux, macos

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/network/dns.yml

# Run the checks
checkmate run examples/network/dns.yml

# Override a variable from the command line
checkmate run examples/network/dns.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `DNS-001` | At least one name server is configured | <span class="sev sev-high">high</span> | network, dns |
| `DNS-002` | Only approved name servers are used | <span class="sev sev-medium">medium</span> | network, dns |
| `DNS-003` | example.com resolves | <span class="sev sev-high">high</span> | network, dns |
| `DNS-004` | /etc/hosts maps localhost to 127.0.0.1 | <span class="sev sev-medium">medium</span> | network, dns, files |
| `DNS-005` | /etc/hosts contains only valid IP addresses | <span class="sev sev-low">low</span> | network, dns, files |
| `DNS-006` | The host name resolves to a non-loopback address | <span class="sev sev-low">low</span> | network, dns |

## Policy

```yaml title="examples/network/dns.yml" linenums="1"
name: DNS and name resolution
version: 1.0.0
description: >
  Resolver configuration, approved name servers, working resolution and a
  sane /etc/hosts.

vars:
  allowed_nameservers: [127.0.0.53, 127.0.0.1, 10.0.0.2, 1.1.1.1, 9.9.9.9]
  dns_test_name: example.com

checks:
  - id: DNS-001
    name: At least one name server is configured
    tags: [network, dns]
    severity: high
    run:
      linux: grep -cE '^[[:space:]]*nameserver[[:space:]]' /etc/resolv.conf
      macos: scutil --dns | grep -c 'nameserver\['
    allow_rc: [0, 1]
    expect: ">= 1"

  - id: DNS-002
    name: Only approved name servers are used
    tags: [network, dns]
    when: facts.os == "linux"
    run: |
      awk '$1 == "nameserver" {print $2}' /etc/resolv.conf |
        grep -vxF {% for ns in allowed_nameservers %}-e {{ ns }} {% endfor %}
    allow_rc: [0, 1]
    expect: empty

  - id: DNS-003
    name: "{{ dns_test_name }} resolves"
    tags: [network, dns]
    severity: high
    timeout: 10s
    run:
      linux: getent ahosts {{ dns_test_name }} | sed -n 1p
      macos: dscacheutil -q host -a name {{ dns_test_name }} | sed -n 1,2p
    expect: "!empty"

  - id: DNS-004
    name: /etc/hosts maps localhost to 127.0.0.1
    tags: [network, dns, files]
    run: |
      grep -E '^127\.0\.0\.1[[:space:]]+([^#]*[[:space:]])?localhost([[:space:]]|$)' /etc/hosts
    allow_rc: [0, 1]
    expect: { lines: ">= 1" }

  - id: DNS-005
    name: /etc/hosts contains only valid IP addresses
    tags: [network, dns, files]
    severity: low
    # Prints every line whose first field is neither an IPv4 nor an IPv6 address.
    run: |
      awk '!/^[[:space:]]*(#|$)/ && $1 !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $1 !~ /:/ {print}' /etc/hosts
    expect: empty

  - id: DNS-006
    name: The host name resolves to a non-loopback address
    tags: [network, dns]
    severity: low
    when: facts.os == "linux"
    run: getent hosts "$(hostname -f)" | awk '{print $1}' | sed -n 1p
    expect: ["!empty", "!~ ^(127\\.|::1$)"]
```
