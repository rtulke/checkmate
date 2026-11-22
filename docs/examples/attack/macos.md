# MITRE ATT&CK macOS

Checks for traces and mitigations of MITRE ATT&CK techniques on macOS: persistence (launch agents and daemons, emond, login hooks, shell profiles, cron, SSH keys), stealth (preloaded libraries, hidden users and files, processes from temporary folders) and impairing defenses (Gatekeeper, System Integrity Protection, firewall, Guest account, remote access). Every check carries the technique and its tactics as tags, so `--export attack` turns the results into an ATT&CK Navigator layer. Most checks run as any user; run with sudo to include the root-only checks.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/attack/macos.yml`](https://github.com/rtulke/checkmate/blob/main/examples/attack/macos.yml)
- :material-format-list-checks: **Checks**  
  18 from 18 definitions
- :material-monitor: **Platforms**  
  any (POSIX shell)

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/attack/macos.yml

# Run the checks
checkmate run examples/attack/macos.yml

# Override a variable from the command line
checkmate run examples/attack/macos.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `ATT-MAC-LAUNCHD-SUSPICIOUS` | No launch agent or daemon runs code from a temporary or hidden location | <span class="sev sev-high">high</span> | attack, attack-t1543.001, attack-t1543.004, attack-persistence, attack-privilege-escalation, launchd |
| `ATT-MAC-LAUNCHD-SIGNATURE` | Every launch daemon starts a validly signed program | <span class="sev sev-medium">medium</span> | attack, attack-t1543.004, attack-persistence, attack-privilege-escalation, launchd |
| `ATT-MAC-DYLD-INSERT` | No launch agent or daemon injects libraries | <span class="sev sev-critical">critical</span> | attack, attack-t1574.006, attack-stealth, attack-execution, launchd |
| `ATT-MAC-EMOND` | The event monitor daemon runs no custom rules | <span class="sev sev-high">high</span> | attack, attack-t1546.014, attack-persistence, attack-privilege-escalation |
| `ATT-MAC-LOGIN-HOOK` | No login or logout hook is set | <span class="sev sev-high">high</span> | attack, attack-t1037.002, attack-persistence, attack-privilege-escalation |
| `ATT-MAC-SHELL-PROFILE` | System shell start-up files contain no download or reverse shell | <span class="sev sev-high">high</span> | attack, attack-t1546.004, attack-persistence, attack-privilege-escalation |
| `ATT-MAC-CRON` | No cron job downloads code or runs from a temporary folder | <span class="sev sev-high">high</span> | attack, attack-t1053.003, attack-persistence, attack-execution, cron |
| `ATT-MAC-AUTHKEYS-PERMS` | authorized_keys files are writable only by their owner | <span class="sev sev-high">high</span> | attack, attack-t1098.004, attack-persistence, attack-privilege-escalation, ssh |
| `ATT-MAC-PRIVATE-KEYS` | Private SSH keys are readable only by their owner | <span class="sev sev-high">high</span> | attack, attack-t1552.004, attack-credential-access, ssh |
| `ATT-MAC-SUDO-NOPASSWD` | sudo always asks for a password | <span class="sev sev-medium">medium</span> | attack, attack-t1548.003, attack-privilege-escalation, sudo |
| `ATT-MAC-HIDDEN-USERS` | No regular account is hidden from the login window | <span class="sev sev-high">high</span> | attack, attack-t1564.002, attack-stealth, accounts |
| `ATT-MAC-HIDDEN-EXECUTABLES` | No hidden executables lie in temporary or shared folders | <span class="sev sev-high">high</span> | attack, attack-t1564.001, attack-stealth |
| `ATT-MAC-TEMP-PROCESSES` | No process runs from a temporary or shared folder | <span class="sev sev-high">high</span> | attack, attack-t1105, attack-t1036.005, attack-command-and-control, attack-stealth |
| `ATT-MAC-GATEKEEPER` | Gatekeeper is enabled | <span class="sev sev-high">high</span> | attack, attack-t1553.001, attack-defense-impairment |
| `ATT-MAC-SIP` | System Integrity Protection is enabled | <span class="sev sev-critical">critical</span> | attack, attack-t1685, attack-t1014, attack-defense-impairment, attack-stealth |
| `ATT-MAC-FIREWALL` | The application firewall is enabled | <span class="sev sev-medium">medium</span> | attack, attack-t1686, attack-defense-impairment, firewall |
| `ATT-MAC-GUEST` | The Guest account is disabled | <span class="sev sev-medium">medium</span> | attack, attack-t1078.001, attack-persistence, attack-initial-access, accounts |
| `ATT-MAC-SCREEN-SHARING` | Screen sharing is off | <span class="sev sev-medium">medium</span> | attack, attack-t1021.005, attack-lateral-movement |

## Policy

```yaml title="examples/attack/macos.yml" linenums="1"
name: MITRE ATT&CK macOS
version: 1.0.0
description: >
  Checks for traces and mitigations of MITRE ATT&CK techniques on macOS:
  persistence (launch agents and daemons, emond, login hooks, shell
  profiles, cron, SSH keys), stealth (preloaded libraries, hidden users and
  files, processes from temporary folders) and impairing defenses
  (Gatekeeper, System Integrity Protection, firewall, Guest account, remote
  access). Every check carries the technique and its tactics as tags, so
  `--export attack` turns the results into an ATT&CK Navigator layer. Most
  checks run as any user; run with sudo to include the root-only checks.

vars:
  attack_mac_suspicious: '(curl|wget)[^|;]*\|[[:space:]]*(ba|z)?sh|/dev/tcp/|base64[[:space:]]+(-d|-D|--decode)|osascript[[:space:]]+-e|(^|[[:space:]"=>])(/tmp|/private/tmp|/var/tmp|/private/var/tmp|/Users/Shared)/'

defaults:
  when: facts.os == "darwin"

checks:
  # ===== Persistence ===========================================================

  - id: ATT-MAC-LAUNCHD-SUSPICIOUS
    name: No launch agent or daemon runs code from a temporary or hidden location
    description: T1543.001 Launch Agent and T1543.004 Launch Daemon. Checks the plists of the system and of every user.
    tags: [attack, attack-t1543.001, attack-t1543.004, attack-persistence, attack-privilege-escalation, launchd]
    severity: high
    run: |
      for f in /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist /Users/*/Library/LaunchAgents/*.plist; do
        [ -f "$f" ] || continue
        if plutil -p "$f" 2>/dev/null | grep -qE '{{ attack_mac_suspicious }}'; then echo "$f"; fi
      done
    expect: empty

  - id: ATT-MAC-LAUNCHD-SIGNATURE
    name: Every launch daemon starts a validly signed program
    description: T1543.004 Launch Daemon. Lists daemons in /Library/LaunchDaemons whose program fails code signature verification.
    tags: [attack, attack-t1543.004, attack-persistence, attack-privilege-escalation, launchd]
    severity: medium
    run: |
      for f in /Library/LaunchDaemons/*.plist; do
        [ -f "$f" ] || continue
        p=$(plutil -extract Program raw "$f" 2>/dev/null || plutil -extract ProgramArguments.0 raw "$f" 2>/dev/null || true)
        [ -n "$p" ] && [ -e "$p" ] || continue
        codesign --verify "$p" >/dev/null 2>&1 || echo "$f: $p"
      done
    expect: empty

  - id: ATT-MAC-DYLD-INSERT
    name: No launch agent or daemon injects libraries
    description: T1574.006 Dynamic Linker Hijacking. DYLD_INSERT_LIBRARIES in the environment of a launchd job loads a library into the program.
    tags: [attack, attack-t1574.006, attack-stealth, attack-execution, launchd]
    severity: critical
    run: |
      for f in /Library/LaunchAgents/*.plist /Library/LaunchDaemons/*.plist /Users/*/Library/LaunchAgents/*.plist; do
        [ -f "$f" ] || continue
        if plutil -p "$f" 2>/dev/null | grep -q DYLD_INSERT_LIBRARIES; then echo "$f"; fi
      done
    expect: empty

  - id: ATT-MAC-EMOND
    name: The event monitor daemon runs no custom rules
    description: T1546.014 Emond. Rules other than the shipped sample run commands on system events.
    tags: [attack, attack-t1546.014, attack-persistence, attack-privilege-escalation]
    severity: high
    run: |
      for f in /etc/emond.d/rules/* /private/var/db/emondClients/*; do
        [ -e "$f" ] || continue
        case "$f" in */SampleRules.plist) ;; *) echo "$f" ;; esac
      done
    expect: empty

  - id: ATT-MAC-LOGIN-HOOK
    name: No login or logout hook is set
    description: T1037.002 Login Hook.
    tags: [attack, attack-t1037.002, attack-persistence, attack-privilege-escalation]
    severity: high
    run: |
      for d in /Library/Preferences/com.apple.loginwindow /var/root/Library/Preferences/com.apple.loginwindow; do
        for k in LoginHook LogoutHook; do
          v=$(defaults read "$d" "$k" 2>/dev/null || true)
          if [ -n "$v" ]; then echo "$d $k = $v"; fi
        done
      done
    expect: empty

  - id: ATT-MAC-SHELL-PROFILE
    name: System shell start-up files contain no download or reverse shell
    description: T1546.004 Unix Shell Configuration Modification.
    tags: [attack, attack-t1546.004, attack-persistence, attack-privilege-escalation]
    severity: high
    run: |
      for f in /etc/zshrc /etc/zprofile /etc/zshenv /etc/zlogin /etc/profile /etc/bashrc; do
        [ -f "$f" ] || continue
        grep -HEn '{{ attack_mac_suspicious }}|DYLD_INSERT_LIBRARIES' "$f" | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true
      done
    expect: empty

  - id: ATT-MAC-CRON
    name: No cron job downloads code or runs from a temporary folder
    description: T1053.003 Cron.
    tags: [attack, attack-t1053.003, attack-persistence, attack-execution, cron]
    severity: high
    when: facts.is_root
    run: |
      for f in /usr/lib/cron/tabs/* /etc/crontab; do
        [ -f "$f" ] || continue
        grep -HEn '{{ attack_mac_suspicious }}' "$f" | grep -vE '^[^:]+:[0-9]+:[[:space:]]*#' || true
      done
    expect: empty

  - id: ATT-MAC-AUTHKEYS-PERMS
    name: authorized_keys files are writable only by their owner
    description: T1098.004 SSH Authorized Keys.
    tags: [attack, attack-t1098.004, attack-persistence, attack-privilege-escalation, ssh]
    severity: high
    run: find /Users/*/.ssh /var/root/.ssh -name 'authorized_keys*' -perm +022 -print 2>/dev/null || true
    expect: empty

  - id: ATT-MAC-PRIVATE-KEYS
    name: Private SSH keys are readable only by their owner
    description: T1552.004 Private Keys.
    tags: [attack, attack-t1552.004, attack-credential-access, ssh]
    severity: high
    run: find /Users/*/.ssh /var/root/.ssh -type f -name 'id_*' ! -name '*.pub' -perm +077 -print 2>/dev/null || true
    expect: empty

  - id: ATT-MAC-SUDO-NOPASSWD
    name: sudo always asks for a password
    description: T1548.003 Sudo and Sudo Caching.
    tags: [attack, attack-t1548.003, attack-privilege-escalation, sudo]
    severity: medium
    when: facts.is_root
    run: grep -rhiE '^[^#]*(NOPASSWD|!authenticate)' /etc/sudoers /etc/sudoers.d 2>/dev/null || true
    expect: empty

  # ===== Stealth ===============================================================

  - id: ATT-MAC-HIDDEN-USERS
    name: No regular account is hidden from the login window
    description: T1564.002 Hidden Users. Lists accounts with a UID of 500 or more and IsHidden set.
    tags: [attack, attack-t1564.002, attack-stealth, accounts]
    severity: high
    run: |
      dscl . -list /Users UniqueID | while read -r u id; do
        if [ "$id" -ge 500 ] && [ "$(dscl . -read "/Users/$u" IsHidden 2>/dev/null | awk '{print $2}')" = 1 ]; then echo "$u ($id)"; fi
      done
    expect: empty

  - id: ATT-MAC-HIDDEN-EXECUTABLES
    name: No hidden executables lie in temporary or shared folders
    description: T1564.001 Hidden Files and Directories.
    tags: [attack, attack-t1564.001, attack-stealth]
    severity: high
    run: |
      { find /private/tmp /private/var/tmp /Users/Shared -xdev -type f -name '.*' -perm +111 2>/dev/null || true; } |
        while read -r f; do
          if file -b "$f" | grep -qE 'Mach-O|script|executable'; then echo "$f"; fi
        done
    expect: empty

  - id: ATT-MAC-TEMP-PROCESSES
    name: No process runs from a temporary or shared folder
    description: T1105 Ingress Tool Transfer and T1036.005 Match Legitimate Resource Name or Location.
    tags: [attack, attack-t1105, attack-t1036.005, attack-command-and-control, attack-stealth]
    severity: high
    run: ps -axo pid=,comm= | awk '$2 ~ /^\/(private\/)?(tmp|var\/tmp)\// || $2 ~ /^\/Users\/Shared\//'
    expect: empty

  # ===== Defense impairment and remote access ==================================

  - id: ATT-MAC-GATEKEEPER
    name: Gatekeeper is enabled
    description: T1553.001 Gatekeeper Bypass.
    tags: [attack, attack-t1553.001, attack-defense-impairment]
    severity: high
    run: spctl --status 2>&1
    allow_rc: [0, 1]
    expect: "~ assessments enabled"

  - id: ATT-MAC-SIP
    name: System Integrity Protection is enabled
    description: T1685 Disable or Modify Tools and T1014 Rootkit. Without SIP, system files and kernel extensions can be modified.
    tags: [attack, attack-t1685, attack-t1014, attack-defense-impairment, attack-stealth]
    severity: critical
    run: csrutil status
    expect: "~ (?i)status: enabled"

  - id: ATT-MAC-FIREWALL
    name: The application firewall is enabled
    description: T1686 Disable or Modify System Firewall.
    tags: [attack, attack-t1686, attack-defense-impairment, firewall]
    severity: medium
    run: /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
    expect: "~ (?i)(enabled|State = [12])"

  - id: ATT-MAC-GUEST
    name: The Guest account is disabled
    description: T1078.001 Default Accounts.
    tags: [attack, attack-t1078.001, attack-persistence, attack-initial-access, accounts]
    severity: medium
    run: defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null || echo 0
    expect: "== 0"

  - id: ATT-MAC-SCREEN-SHARING
    name: Screen sharing is off
    description: T1021.005 VNC.
    tags: [attack, attack-t1021.005, attack-lateral-movement]
    severity: medium
    run: launchctl print-disabled system 2>/dev/null | grep '"com.apple.screensharing"' || echo '"com.apple.screensharing" => disabled'
    expect: "~ => (disabled|true)"
```
