# Checking remote systems

There are two ways to check a system checkmate is not installed on:

- **`--host`** and **`--inventory`** run a whole policy on other hosts over SSH. The policy is the same file you would run locally. This works for Linux, macOS and BSD servers, for Windows with OpenSSH, and for switches and firewalls that take commands over SSH.
- **A command that reaches out**: nothing stops a command from calling `ssh`, `curl` or `snmpget`. Use it for systems that speak HTTP or SNMP only, and for checks that look at a system from outside.

## A whole policy on another host

```bash
checkmate run baseline.yml --host web01.example.net
checkmate run baseline.yml --host audit@web01.example.net:2222 --become
```

Nothing is installed or copied to the host. checkmate first asks it for its facts (distribution, version, user), so platform variants and `when` are decided for that host, not for the machine checkmate runs on. Then every command of the policy (`run`, `only_if`, `loop_run`) is executed there, and the report is written here, with the facts of the host.

| | |
|---|---|
| Connection | The `ssh` program of the machine, so `~/.ssh/config`, agents, jump hosts and `known_hosts` apply as on the command line. One connection is shared by all commands. Set `CHECKMATE_SSH` to use another ssh program. |
| Authentication | Keys or an agent. checkmate never asks for a password or passphrase (`BatchMode`); a host that needs one is reported as not reachable. An unknown host key is refused, as ssh does. |
| Privileges | `--become` runs every command through `sudo -n`. The remote user needs a sudoers rule without password; each command then shows up in the sudo log of the host. Without `--become` the checks run as the remote user and `facts.is_root` is false. |
| Shell | `bash` if the host has it, else `sh`; `shell:` in the policy can ask for `bash`, `sh` or `zsh`. For Windows see below. |
| Environment | `LC_ALL=C`, the `env` of the policy, and `PATH` extended by `/usr/local/sbin:/usr/sbin:/sbin`, where many audit tools live and which SSH sessions often lack. |
| Working directory | The home directory of the remote user. Files next to the policy are **not** on the host: checks that read them (`{{ policy_dir }}`, relative paths) need the content in a variable instead. |
| Parallelism | At most 8 commands at a time per host, whatever `--jobs` says: they share one connection, and sshd accepts 10 sessions per connection by default (`MaxSessions`). |
| Timeouts | If the host has `timeout` (coreutils, BusyBox), it ends the command and its children there. Otherwise only the connection is ended and the command may keep running on the host. |
| Unreachable host | The run ends with an error before any check; a host that stops answering during the run turns the remaining checks into ERROR. It never looks compliant. |

The login shell of the remote user must be a POSIX shell (sh, bash, zsh, ksh, dash).

### Windows hosts

A Windows host with the OpenSSH server is recognized by itself: when it does not answer as a POSIX system, checkmate asks again in PowerShell. Nothing has to be configured, and it does not matter whether the default shell of sshd is `cmd.exe` or PowerShell.

| | |
|---|---|
| Shell | `pwsh` if the host has PowerShell 7, else `powershell` (Windows PowerShell 5.1). `shell:` in the policy can ask for either; `cmd`, `bash` and `sh` are not available. |
| Commands | A script travels on the standard input of PowerShell, never on the command line, so there is no quoting to get wrong and no limit to its length. Variables (`env`, `CHECKMATE_ITEM`) are set at the top of the script. Input and output are UTF-8. |
| Privileges | `--become` does not exist on Windows. Connect as a user with administrator rights; `facts.is_root` says whether the session is elevated. |
| Timeouts | Only the connection is ended; a command that hangs may keep running on the host. |

```bash
checkmate run cis/win2022.yml --host Administrator@win01.example.net --tags cis-level1-member-server
```

## Many hosts

List the hosts in an [inventory](../reference/inventory.md) and run the policy on all of them:

```yaml
# hosts.yml
defaults: { user: audit, become: true }
groups:
  web:
    vars: { role: web }
    hosts: [web01.example.net, web02.example.net]
  db:
    hosts: [db01.example.net]
```

```bash
checkmate run baseline.yml -i hosts.yml --export html,pdf -o reports/
checkmate run baseline.yml -i hosts.yml --limit web
```

Linux, Windows and devices can share an inventory; what each host is, is found out per host. The hosts are checked in parallel, each one as described above. The console shows an overview of all hosts, and every export format contains all of them. A host that cannot be reached has no results: it is listed as unreachable and counts neither as compliant nor as non-compliant.

## Switches, firewalls and other devices

A device has no shell that could set variables, report facts or run a pipeline: it takes a command and prints an answer. Mark such hosts with `device` in the [inventory](../reference/inventory.md) and name their platform:

```yaml
# hosts.yml
groups:
  switches:
    device: ios
    user: audit
    hosts: [sw-core-01.example.net, sw-core-02.example.net]
  firewalls:
    device: junos
    hosts: [fw-01.example.net]
```

```yaml
# network.yml
checks:
  - id: NTP-SYNCED
    name: The clock is synchronized
    run:
      ios: show ntp status
      junos: show ntp status
    expect: "~ (Clock is synchronized|synchronised to)"

  - id: NO-TELNET
    name: Telnet is not enabled on the lines
    when: facts.os == "ios"
    run: show running-config | include transport input
    expect: { none: "~ telnet" }
```

```bash
checkmate run network.yml -i hosts.yml
```

- The command is sent exactly as written. The device name is the platform: it selects the variant of `run` and is `facts.os` and `facts.distro`.
- One command at a time per device, each over a connection of its own: many devices accept only one session.
- Nothing is asked of the device beforehand. A device that is down therefore shows up with the first check: its checks are ERROR with the reason, the host is not listed as unreachable.
- `env`, `loop_run` and `become` need a shell and are refused for devices. Judge the output with `expect`; many devices exit with 0 whatever happens.

Without an inventory, or for devices that need special client options per command, put the connection into the command yourself:

## Over SSH, from inside a command

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
