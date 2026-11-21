# Arista EOS (eAPI)

Checks Arista switches through the JSON-RPC eAPI with curl and jq. The password comes from the environment variable EOS_PASSWORD, never from the policy file. The JSON request body contains braces, so it is wrapped in a Jinja2 raw block.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/network-devices/arista-eos.yml`](https://github.com/rtulke/checkmate/blob/main/examples/network-devices/arista-eos.yml)
- :material-format-list-checks: **Checks**  
  8 from 4 definitions, 4 with loops
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/network-devices/arista-eos.yml

# Run the checks
checkmate run examples/network-devices/arista-eos.yml

# Override a variable from the command line
checkmate run examples/network-devices/arista-eos.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `EOS-VERSION-leaf-01.example.net` | leaf-01.example.net: EOS 4.30 or newer | <span class="sev sev-medium">medium</span> | network-devices, arista, firmware |
| `EOS-VERSION-leaf-02.example.net` | leaf-02.example.net: EOS 4.30 or newer | <span class="sev sev-medium">medium</span> | network-devices, arista, firmware |
| `EOS-NTP-leaf-01.example.net` | leaf-01.example.net: NTP is synchronised | <span class="sev sev-medium">medium</span> | network-devices, arista, time |
| `EOS-NTP-leaf-02.example.net` | leaf-02.example.net: NTP is synchronised | <span class="sev sev-medium">medium</span> | network-devices, arista, time |
| `EOS-ERRDISABLED-leaf-01.example.net` | leaf-01.example.net: no interface is err-disabled | <span class="sev sev-high">high</span> | network-devices, arista, interfaces |
| `EOS-ERRDISABLED-leaf-02.example.net` | leaf-02.example.net: no interface is err-disabled | <span class="sev sev-high">high</span> | network-devices, arista, interfaces |
| `EOS-TELNET-leaf-01.example.net` | leaf-01.example.net: telnet management is disabled | <span class="sev sev-critical">critical</span> | network-devices, arista |
| `EOS-TELNET-leaf-02.example.net` | leaf-02.example.net: telnet management is disabled | <span class="sev sev-critical">critical</span> | network-devices, arista |

## Policy

```yaml title="examples/network-devices/arista-eos.yml" linenums="1"
name: Arista EOS (eAPI)
version: 1.0.0
description: >
  Checks Arista switches through the JSON-RPC eAPI with curl and jq. The
  password comes from the environment variable EOS_PASSWORD, never from the
  policy file. The JSON request body contains braces, so it is wrapped in a
  Jinja2 raw block.

vars:
  eos_devices: [leaf-01.example.net, leaf-02.example.net]
  eos_user: audit
  min_eos_version: "4.30"

snippets:
  # Runs args.cmd on device {{ arg }} (format args.format, default json)
  # and applies the jq filter args.jq to the result.
  eapi: |
    curl -sS --fail --max-time 10 -u "{{ eos_user }}:$EOS_PASSWORD" \
      -H 'Content-Type: application/json' "https://{{ arg }}/command-api" \
      -d '{% raw %}{"jsonrpc": "2.0", "method": "runCmds", "id": 1, "params": {"version": 1, "format": "{% endraw %}{{ args.format | default("json") }}{% raw %}", "cmds": ["{% endraw %}{{ args.cmd }}{% raw %}"]}}{% endraw %}' |
      jq -r '{{ args.jq }}'

checks:
  - id: "EOS-VERSION-{{ item }}"
    name: "{{ item }}: EOS {{ min_eos_version }} or newer"
    tags: [network-devices, arista, firmware]
    loop: "{{ eos_devices }}"
    run:
      use: eapi
      arg: "{{ item }}"
      args: { cmd: show version, jq: ".result[0].version" }
    as: version
    expect: ">= {{ min_eos_version }}"

  - id: "EOS-NTP-{{ item }}"
    name: "{{ item }}: NTP is synchronised"
    tags: [network-devices, arista, time]
    loop: "{{ eos_devices }}"
    run:
      use: eapi
      arg: "{{ item }}"
      args: { cmd: show ntp status, format: text, jq: ".result[0].output" }
    expect: "~ (?i)synchroni[sz]ed"

  - id: "EOS-ERRDISABLED-{{ item }}"
    name: "{{ item }}: no interface is err-disabled"
    tags: [network-devices, arista, interfaces]
    severity: high
    loop: "{{ eos_devices }}"
    run:
      use: eapi
      arg: "{{ item }}"
      args:
        cmd: show interfaces status
        jq: '.result[0].interfaceStatuses | to_entries[] | select(.value.linkStatus == "errdisabled") | .key'
    expect: empty

  - id: "EOS-TELNET-{{ item }}"
    name: "{{ item }}: telnet management is disabled"
    tags: [network-devices, arista]
    severity: critical
    loop: "{{ eos_devices }}"
    run:
      use: eapi
      arg: "{{ item }}"
      args: { cmd: show running-config section management telnet, format: text, jq: ".result[0].output" }
    expect: "!~ (?m)^[[:space:]]*no shutdown"
```
