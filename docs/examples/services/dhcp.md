# DHCP servers (Kea, ISC dhcpd)

Security of the DHCP servers Kea and ISC dhcpd: valid configuration, a protected control channel, no unauthenticated management API, and the end of life of ISC dhcpd.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/services/dhcp.yml`](https://github.com/rtulke/checkmate/blob/main/examples/services/dhcp.yml)
- :material-format-list-checks: **Checks**  
  6 from 6 definitions
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/services/dhcp.yml

# Run the checks
checkmate run examples/services/dhcp.yml
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `KEA-CONFIG` | The Kea DHCPv4 configuration is valid | <span class="sev sev-high">high</span> | services, dhcp, kea |
| `KEA-CONTROL-SOCKET` | The Kea control socket is not writable by other users | <span class="sev sev-high">high</span> | services, dhcp, kea, permissions |
| `KEA-CONTROL-AGENT` | The Kea control agent listens only locally or requires authentication | <span class="sev sev-high">high</span> | services, dhcp, kea |
| `DHCPD-END-OF-LIFE` | ISC dhcpd is not in use | <span class="sev sev-medium">medium</span> | services, dhcp, dhcpd |
| `DHCPD-CONFIG` | The ISC dhcpd configuration is valid | <span class="sev sev-high">high</span> | services, dhcp, dhcpd |
| `DHCPD-OMAPI` | The ISC dhcpd management API is off or protected by a key | <span class="sev sev-high">high</span> | services, dhcp, dhcpd |

## Policy

```yaml title="examples/services/dhcp.yml" linenums="1"
name: DHCP servers (Kea, ISC dhcpd)
version: 1.0.0
description: >
  Security of the DHCP servers Kea and ISC dhcpd: valid configuration, a
  protected control channel, no unauthenticated management API, and the
  end of life of ISC dhcpd.

defaults:
  when:
    - facts.os == "linux"
    - facts.is_root

checks:
  # ===== Kea ===================================================================
  - id: KEA-CONFIG
    name: The Kea DHCPv4 configuration is valid
    tags: [services, dhcp, kea]
    severity: high
    only_if: command -v kea-dhcp4 && test -e /etc/kea/kea-dhcp4.conf
    run: kea-dhcp4 -t /etc/kea/kea-dhcp4.conf >/dev/null 2>&1
    expect: true
    rationale: Kea does not start with an invalid configuration, so clients get no addresses after the next restart.
    remediation: Run `kea-dhcp4 -t /etc/kea/kea-dhcp4.conf`, correct the reported error and reload Kea.

  - id: KEA-CONTROL-SOCKET
    name: The Kea control socket is not writable by other users
    description: Whoever can write to the control socket can change the running configuration.
    tags: [services, dhcp, kea, permissions]
    severity: high
    only_if: command -v kea-dhcp4
    run: find /run/kea /var/run/kea /tmp -maxdepth 1 -type s -name 'kea*' -perm /002 -print 2>/dev/null || true
    expect: empty
    rationale: Whoever can write to the control socket can change the running configuration and the leases.
    remediation: Move the socket to a directory that only the Kea account can access, such as /run/kea.

  - id: KEA-CONTROL-AGENT
    name: The Kea control agent listens only locally or requires authentication
    tags: [services, dhcp, kea]
    severity: high
    only_if: test -e /etc/kea/kea-ctrl-agent.conf
    run: |
      host=$(sed -e 's|//.*||' -e 's|#.*||' /etc/kea/kea-ctrl-agent.conf | grep -oE '"http-host"[[:space:]]*:[[:space:]]*"[^"]*"' | sed -n 1p | cut -d'"' -f4)
      if [ -z "$host" ] || [ "$host" = 127.0.0.1 ] || [ "$host" = ::1 ] || [ "$host" = localhost ]; then echo local; exit 0; fi
      if grep -q '"authentication"' /etc/kea/kea-ctrl-agent.conf; then echo authenticated; else echo "listens on $host without authentication"; fi
    expect: "in [local, authenticated]"
    rationale: The control agent accepts commands that change the DHCP configuration, and without authentication it takes them from anyone who reaches the port.
    remediation: Set http-host to 127.0.0.1 in /etc/kea/kea-ctrl-agent.conf or add an authentication block.

  # ===== ISC dhcpd =============================================================
  - id: DHCPD-END-OF-LIFE
    name: ISC dhcpd is not in use
    description: ISC DHCP reached its end of maintenance in 2022 and gets no security fixes; ISC recommends Kea.
    tags: [services, dhcp, dhcpd]
    severity: medium
    only_if: command -v dhcpd
    run: |
      for c in /etc/dhcp/dhcpd.conf /etc/dhcpd.conf; do
        [ -s "$c" ] && grep -qE '^[[:space:]]*(subnet|host)[[:space:]]' "$c" && echo "$c configures ISC dhcpd"
      done
      true
    expect: empty
    rationale: ISC DHCP reached its end of maintenance in 2022 and gets no security fixes.
    remediation: Migrate the configuration to Kea and remove ISC dhcpd.

  - id: DHCPD-CONFIG
    name: The ISC dhcpd configuration is valid
    tags: [services, dhcp, dhcpd]
    severity: high
    only_if: command -v dhcpd && test -s /etc/dhcp/dhcpd.conf
    run: dhcpd -t -cf /etc/dhcp/dhcpd.conf >/dev/null 2>&1
    expect: true
    rationale: dhcpd does not start with an invalid configuration, so clients get no addresses after the next restart.
    remediation: Run `dhcpd -t -cf /etc/dhcp/dhcpd.conf`, correct the reported error and restart dhcpd.

  - id: DHCPD-OMAPI
    name: The ISC dhcpd management API is off or protected by a key
    tags: [services, dhcp, dhcpd]
    severity: high
    only_if: command -v dhcpd && test -s /etc/dhcp/dhcpd.conf
    run: |
      c=/etc/dhcp/dhcpd.conf
      if grep -qE '^[[:space:]]*omapi-port' "$c" && ! grep -qE '^[[:space:]]*omapi-key' "$c"; then echo "omapi-port without omapi-key"; fi
    expect: empty
    rationale: OMAPI without a key lets anyone who reaches the port read and change leases and host entries.
    remediation: Remove omapi-port from dhcpd.conf or define a key and name it with omapi-key.
```
