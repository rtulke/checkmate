# Network

Interfaces and routing, listening ports, host firewalls, DNS and TLS.

| Example | Description | Checks |
|---|---|---|
| [DNS and name resolution](dns.md) | Resolver configuration, approved name servers, working resolution and a sane /etc/hosts. | 6 |
| [Host firewall](firewall.md) | firewalld, nftables, iptables and ufw. | 6 |
| [Network interfaces and routing](interfaces.md) | Default route, interface state, MTU, promiscuous mode, IP forwarding, IPv6 policy and wireless interfaces. | 10 |
| [Listening ports and reachability](ports.md) | Only approved ports may listen, sensitive services must not listen on all interfaces, and required remote endpoints must be reachable. | 9 |
| [TLS certificates and endpoints](tls.md) | Certificate expiry for local files and remote endpoints, chain validation and protocol versions, all with the openssl command line. | 5 |
