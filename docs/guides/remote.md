# Checking remote systems

checkmate runs commands locally, but nothing stops a command from reaching another system. Run checkmate on a management host and check switches, firewalls, appliances or servers that cannot run it themselves.

## Over SSH

Put the connection into a snippet and loop over an inventory:

```yaml
vars:
  devices: [sw-core-01.example.net, sw-core-02.example.net]
  ssh_user: audit

snippets:
  ios: >-
    ssh -o BatchMode=yes -o ConnectTimeout=5 {{ ssh_user }}@{{ arg }} '{{ args.cmd }}'

checks:
  - id: "IOS-SSHV2-{{ item }}"
    name: "{{ item }}: only SSH version 2"
    loop: "{{ devices }}"
    run: { use: ios, arg: "{{ item }}", args: { cmd: show ip ssh } }
    expect: "~ SSH Enabled - version 2\\.0"
```

- `BatchMode=yes` fails instead of prompting for a password; use keys or certificates.
- Keep `StrictHostKeyChecking` enabled and manage `known_hosts`.
- Use a read-only account on the device.
- `-j` controls how many devices are contacted in parallel.

For Linux servers, a heredoc avoids quoting problems with remote awk programs:

```yaml
snippets:
  remote: |
    ssh -o BatchMode=yes {{ ssh_user }}@{{ arg }} sudo -n bash -s <<'REMOTE'
    {{ args.script }}
    REMOTE
```

See [Linux hosts over SSH](../examples/remote/linux-over-ssh.md).

## Over HTTP APIs

curl and jq cover most REST and JSON-RPC APIs. Keep credentials in environment variables, never in the policy:

```yaml
run: |
  curl -sS --fail -u "audit:$EOS_PASSWORD" https://{{ item }}/command-api \
    -d '{% raw %}{"jsonrpc":"2.0","method":"runCmds","id":1,"params":{"version":1,"cmds":["show version"]}}{% endraw %}' |
    jq -r '.result[0].version'
```

JSON bodies contain braces, so wrap them in `{% raw %}` blocks. See [Arista EOS](../examples/network-devices/arista-eos.md).

## Over SNMP

```yaml
run: snmpget -v3 -l authPriv -u "$SNMP_USER" -a SHA -A "$SNMP_AUTH" -x AES -X "$SNMP_PRIV" -Oqv {{ item }} SNMPv2-MIB::sysDescr.0
```

See [SNMP polling](../examples/network-devices/snmp.md).

## Unreachable devices

A device that cannot be reached returns a non-zero exit code (ssh: 255, curl: 6/7/28) and the check becomes an <span class="st st-error">ERROR</span>. That is intentional: an unreachable device has not been checked and must not count as compliant.
