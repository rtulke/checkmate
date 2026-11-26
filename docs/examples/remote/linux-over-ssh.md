# Linux hosts over SSH

Check many Linux servers from one management host without installing anything on them. The remote command is passed through a snippet; the heredoc keeps quoting simple even for awk programs.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/remote/linux-over-ssh.yml`](https://github.com/rtulke/checkmate/blob/main/examples/remote/linux-over-ssh.yml)
- :material-format-list-checks: **Checks**  
  12 from 4 definitions, 4 with loops
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/remote/linux-over-ssh.yml

# Run the checks
checkmate run examples/remote/linux-over-ssh.yml

# Override a variable from the command line
checkmate run examples/remote/linux-over-ssh.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `REMOTE-ROOTLOGIN-web-01.example.net` | web-01.example.net: root login over SSH is disabled | <span class="sev sev-high">high</span> | remote, ssh |
| `REMOTE-ROOTLOGIN-web-02.example.net` | web-02.example.net: root login over SSH is disabled | <span class="sev sev-high">high</span> | remote, ssh |
| `REMOTE-ROOTLOGIN-db-01.example.net` | db-01.example.net: root login over SSH is disabled | <span class="sev sev-high">high</span> | remote, ssh |
| `REMOTE-UPDATES-web-01.example.net` | web-01.example.net: no security updates pending | <span class="sev sev-high">high</span> | remote, updates |
| `REMOTE-UPDATES-web-02.example.net` | web-02.example.net: no security updates pending | <span class="sev sev-high">high</span> | remote, updates |
| `REMOTE-UPDATES-db-01.example.net` | db-01.example.net: no security updates pending | <span class="sev sev-high">high</span> | remote, updates |
| `REMOTE-DISK-web-01.example.net` | web-01.example.net: root filesystem below 90% usage | <span class="sev sev-medium">medium</span> | remote, disk |
| `REMOTE-DISK-web-02.example.net` | web-02.example.net: root filesystem below 90% usage | <span class="sev sev-medium">medium</span> | remote, disk |
| `REMOTE-DISK-db-01.example.net` | db-01.example.net: root filesystem below 90% usage | <span class="sev sev-medium">medium</span> | remote, disk |
| `REMOTE-UID0-web-01.example.net` | web-01.example.net: root is the only UID 0 account | <span class="sev sev-critical">critical</span> | remote, users |
| `REMOTE-UID0-web-02.example.net` | web-02.example.net: root is the only UID 0 account | <span class="sev sev-critical">critical</span> | remote, users |
| `REMOTE-UID0-db-01.example.net` | db-01.example.net: root is the only UID 0 account | <span class="sev sev-critical">critical</span> | remote, users |

## Policy

```yaml title="examples/remote/linux-over-ssh.yml" linenums="1"
name: Linux hosts over SSH
version: 1.0.0
description: >
  Check many Linux servers from one management host without installing
  anything on them. The remote command is passed through a snippet; the
  heredoc keeps quoting simple even for awk programs.

vars:
  hosts: [web-01.example.net, web-02.example.net, db-01.example.net]
  ssh_user: audit

snippets:
  # Runs the script given in args.script on host {{ arg }} with sudo.
  remote: |
    ssh -o BatchMode=yes -o ConnectTimeout=5 {{ ssh_user }}@{{ arg }} sudo -n bash -s <<'REMOTE'
    {{ args.script }}
    REMOTE

defaults:
  # Shell commands for Unix-like systems.
  when: facts.os != "windows"

checks:
  - id: "REMOTE-ROOTLOGIN-{{ item }}"
    name: "{{ item }}: root login over SSH is disabled"
    tags: [remote, ssh]
    severity: high
    loop: "{{ hosts }}"
    run:
      use: remote
      arg: "{{ item }}"
      args:
        script: sshd -T | awk '$1 == "permitrootlogin" {print $2}'
    expect: "== no"
    rationale: "With root login enabled attackers can guess the root password of {{ item }} directly, and logins cannot be attributed to a person."
    remediation: "Set PermitRootLogin no in /etc/ssh/sshd_config on {{ item }} and reload sshd."

  - id: "REMOTE-UPDATES-{{ item }}"
    name: "{{ item }}: no security updates pending"
    tags: [remote, updates]
    severity: high
    loop: "{{ hosts }}"
    timeout: 3m
    run:
      use: remote
      arg: "{{ item }}"
      args:
        script: |
          if command -v dnf >/dev/null; then
            dnf -q updateinfo list --security --available 2>/dev/null | wc -l
          else
            apt-get -s upgrade 2>/dev/null | grep -c '^Inst .*[Ss]ecurity' || true
          fi
    expect: "== 0"
    rationale: "A pending security update means that {{ item }} runs software with a publicly known vulnerability."
    remediation: "Install the security updates on {{ item }} with `dnf upgrade --security` or `apt-get upgrade`."

  - id: "REMOTE-DISK-{{ item }}"
    name: "{{ item }}: root filesystem below 90% usage"
    tags: [remote, disk]
    loop: "{{ hosts }}"
    run:
      use: remote
      arg: "{{ item }}"
      args:
        script: df -P / | awk 'NR == 2 {sub(/%/, "", $5); print $5}'
    expect: "< 90"
    rationale: "A full root file system stops services and can keep {{ item }} from booting or accepting logins."
    remediation: "Remove old files from the root file system of {{ item }} or enlarge it."

  - id: "REMOTE-UID0-{{ item }}"
    name: "{{ item }}: root is the only UID 0 account"
    tags: [remote, users]
    severity: critical
    loop: "{{ hosts }}"
    run:
      use: remote
      arg: "{{ item }}"
      args:
        script: |
          awk -F: '$3 == 0 {print $1}' /etc/passwd
    expect: "== root"
    rationale: Every account with UID 0 has full root rights under a name that nobody watches.
    remediation: "Remove the additional account on {{ item }} or give it another UID with `usermod -u <uid> <user>`."
```
