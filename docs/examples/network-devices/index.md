# Network devices

Switches, routers and firewalls over SSH, eAPI and SNMP: Cisco, Juniper, Arista and any SNMP device.

| Example | Description | Checks |
|---|---|---|
| [Arista EOS (eAPI)](arista-eos.md) | Checks Arista switches through the JSON-RPC eAPI with curl and jq. | 8 |
| [Cisco IOS / IOS-XE switches and routers](cisco-ios.md) | Remote checks of Cisco IOS devices over SSH, run from a management host. | 20 |
| [Juniper Junos](juniper-junos.md) | Remote checks of Junos devices over SSH. | 6 |
| [SNMP polling (any vendor)](snmp.md) | Vendor-neutral device checks with the net-snmp tools: uptime, interface status and firmware strings. | 8 |
