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
    rationale: Without a name server the host resolves no names, and most network services fail.
    remediation: Add a nameserver entry to /etc/resolv.conf or to the network configuration that writes the file.

  - id: DNS-002
    name: Only approved name servers are used
    tags: [network, dns]
    when: facts.os == "linux"
    run: |
      awk '$1 == "nameserver" {print $2}' /etc/resolv.conf |
        grep -vxF {% for ns in allowed_nameservers %}-e {{ ns }} {% endfor %}
    allow_rc: [0, 1]
    expect: empty
    rationale: An unapproved resolver sees every name the host looks up and can answer with forged addresses.
    remediation: Remove the listed servers from the resolver configuration or add them to allowed_nameservers.

  - id: DNS-003
    name: "{{ dns_test_name }} resolves"
    tags: [network, dns]
    severity: high
    timeout: 10s
    run:
      linux: getent ahosts {{ dns_test_name }} | sed -n 1p
      macos: dscacheutil -q host -a name {{ dns_test_name }} | sed -n 1,2p
    expect: "!empty"
    rationale: A failed lookup means that name resolution does not work although name servers are configured.
    remediation: Check that the configured name servers are reachable and that the firewall lets port 53 through.

  - id: DNS-004
    name: /etc/hosts maps localhost to 127.0.0.1
    tags: [network, dns, files]
    run: |
      grep -E '^127\.0\.0\.1[[:space:]]+([^#]*[[:space:]])?localhost([[:space:]]|$)' /etc/hosts
    allow_rc: [0, 1]
    expect: { lines: ">= 1" }
    rationale: Many programs expect localhost to resolve to 127.0.0.1 and fail without this entry.
    remediation: Add the line `127.0.0.1 localhost` to /etc/hosts.

  - id: DNS-005
    name: /etc/hosts contains only valid IP addresses
    tags: [network, dns, files]
    severity: low
    # Prints every line whose first field is neither an IPv4 nor an IPv6 address.
    run: |
      awk '!/^[[:space:]]*(#|$)/ && $1 !~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ && $1 !~ /:/ {print}' /etc/hosts
    expect: empty
    rationale: The resolver skips malformed lines, so the entry that someone meant to add has no effect.
    remediation: Correct or remove the listed lines in /etc/hosts.

  - id: DNS-006
    name: The host name resolves to a non-loopback address
    tags: [network, dns]
    severity: low
    when: facts.os == "linux"
    run: getent hosts "$(hostname -f)" | awk '{print $1}' | sed -n 1p
    expect: ["!empty", "!~ ^(127\\.|::1$)"]
    rationale: A host name that resolves to loopback makes cluster software and services announce an address that no other host can reach.
    remediation: Map the fully qualified host name to the primary address in DNS or in /etc/hosts.
```
