# Network interfaces and routing

Default route, interface state, MTU, promiscuous mode, IP forwarding, IPv6 policy and wireless interfaces.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/network/interfaces.yml`](https://github.com/rtulke/checkmate/blob/main/examples/network/interfaces.yml)
- :material-format-list-checks: **Checks**  
  10 from 8 definitions, 1 with loops
- :material-monitor: **Platforms**  
  linux, macos

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/network/interfaces.yml

# Run the checks
checkmate run examples/network/interfaces.yml

# Override a variable from the command line
checkmate run examples/network/interfaces.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `NET-001` | A default route exists | <span class="sev sev-high">high</span> | network, routing |
| `NET-002` | No relevant interface is down | <span class="sev sev-medium">medium</span> | network, interfaces |
| `NET-003` | eth0 uses MTU 1500 | <span class="sev sev-low">low</span> | network, interfaces |
| `NET-004` | No interface is in promiscuous mode | <span class="sev sev-high">high</span> | network, interfaces |
| `NET-005` | IP forwarding is disabled | <span class="sev sev-high">high</span> | network, routing |
| `NET-006` | IPv6 is disabled | <span class="sev sev-medium">medium</span> | network, ipv6 |
| `NET-REDIRECTS-net.ipv4.conf.all.accept_redirects` | net.ipv4.conf.all.accept_redirects is 0 (ICMP redirects are not accepted) | <span class="sev sev-medium">medium</span> | network, routing |
| `NET-REDIRECTS-net.ipv4.conf.default.accept_redirects` | net.ipv4.conf.default.accept_redirects is 0 (ICMP redirects are not accepted) | <span class="sev sev-medium">medium</span> | network, routing |
| `NET-REDIRECTS-net.ipv6.conf.all.accept_redirects` | net.ipv6.conf.all.accept_redirects is 0 (ICMP redirects are not accepted) | <span class="sev sev-medium">medium</span> | network, routing |
| `NET-008` | Wireless interfaces are disabled on servers | <span class="sev sev-low">low</span> | network, interfaces |

## Policy

```yaml title="examples/network/interfaces.yml" linenums="1"
name: Network interfaces and routing
version: 1.0.0
description: >
  Default route, interface state, MTU, promiscuous mode, IP forwarding,
  IPv6 policy and wireless interfaces.

vars:
  primary_interface: eth0
  expected_mtu: 1500
  ipv6_disabled: false
  ignored_interfaces: "^(lo|docker|veth|virbr|br-|cni|flannel|cali|tun|tap)"

checks:
  - id: NET-001
    name: A default route exists
    tags: [network, routing]
    severity: high
    run:
      linux: ip route show default
      macos: route -n get default 2>/dev/null | awk '/gateway:/ {print $2}'
    expect: "!empty"
    rationale: Without a default route the host reaches only its directly connected networks.
    remediation: Set the gateway in the network configuration of the host.

  - id: NET-002
    name: No relevant interface is down
    tags: [network, interfaces]
    when: facts.os == "linux"
    run: |
      ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 |
        grep -vE '{{ ignored_interfaces }}' |
        while read -r dev; do
          state=$(cat "/sys/class/net/$dev/operstate" 2>/dev/null)
          if [ "$state" = "down" ]; then echo "$dev"; fi
        done
    allow_rc: [0, 1]
    expect: empty
    rationale: An interface that is down means a broken link or a bond that has lost its redundancy.
    remediation: Check cable, switch port and configuration of the listed interfaces, or add unused ones to ignored_interfaces.

  - id: NET-003
    name: "{{ primary_interface }} uses MTU {{ expected_mtu }}"
    tags: [network, interfaces]
    severity: low
    when: facts.os == "linux"
    only_if: test -d /sys/class/net/{{ primary_interface }}
    run: cat /sys/class/net/{{ primary_interface }}/mtu
    expect: "== {{ expected_mtu }}"
    rationale: A wrong MTU causes fragmentation or silently dropped large packets.
    remediation: "Set the MTU of {{ primary_interface }} to {{ expected_mtu }} in the network configuration."

  - id: NET-004
    name: No interface is in promiscuous mode
    tags: [network, interfaces]
    severity: high
    run:
      linux: ip -o link show | grep -i promisc
      macos: ifconfig | grep -i promisc
    allow_rc: [0, 1]
    expect: empty
    rationale: An interface in promiscuous mode receives all traffic on the segment, which is how a sniffer works.
    remediation: Stop the process that switched the mode on, for example a packet capture, or run `ip link set <interface> promisc off`.

  - id: NET-005
    name: IP forwarding is disabled
    tags: [network, routing]
    severity: high
    when: facts.os == "linux"
    run: sysctl -n net.ipv4.ip_forward
    expect: "== 0"
    rationale: A host that forwards packets acts as a router and can connect networks that are meant to be separate.
    remediation: Set net.ipv4.ip_forward = 0 in a file in /etc/sysctl.d and run `sysctl --system`.

  - id: NET-006
    name: IPv6 is disabled
    tags: [network, ipv6]
    when: facts.os == "linux" and ipv6_disabled
    run: sysctl -n net.ipv6.conf.all.disable_ipv6
    expect: "== 1"
    rationale: IPv6 that nobody manages is a second, often unfiltered path to the host.
    remediation: Set net.ipv6.conf.all.disable_ipv6 = 1 in a file in /etc/sysctl.d and run `sysctl --system`.

  - id: "NET-REDIRECTS-{{ item }}"
    name: "{{ item }} is 0 (ICMP redirects are not accepted)"
    tags: [network, routing]
    when: facts.os == "linux"
    loop: [net.ipv4.conf.all.accept_redirects, net.ipv4.conf.default.accept_redirects, net.ipv6.conf.all.accept_redirects]
    run: sysctl -n {{ item }} 2>/dev/null || echo 0
    expect: "== 0"
    rationale: An accepted ICMP redirect lets another host on the network change the routing table and divert traffic.
    remediation: "Set {{ item }} = 0 in a file in /etc/sysctl.d and run `sysctl --system`."

  - id: NET-008
    name: Wireless interfaces are disabled on servers
    tags: [network, interfaces]
    severity: low
    when: facts.os == "linux"
    only_if: command -v nmcli
    run: nmcli radio wifi
    expect: "== disabled"
    rationale: An active wireless interface is a network path around the wired firewall and monitoring.
    remediation: nmcli radio wifi off
```
