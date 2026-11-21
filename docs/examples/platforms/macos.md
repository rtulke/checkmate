# macOS

Security baseline for macOS workstations. Most checks work without root; checks that need it are guarded with `when: facts.is_root`.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/platforms/macos.yml`](https://github.com/rtulke/checkmate/blob/main/examples/platforms/macos.yml)
- :material-format-list-checks: **Checks**  
  15 from 13 definitions, 1 with loops
- :material-monitor: **Platforms**  
  macos

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/platforms/macos.yml

# Run the checks
checkmate run examples/platforms/macos.yml

# Override a variable from the command line
checkmate run examples/platforms/macos.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `MAC-001` | macOS 14.0 or newer | <span class="sev sev-high">high</span> | platform, macos, updates |
| `MAC-002` | FileVault disk encryption is on | <span class="sev sev-critical">critical</span> | platform, macos, encryption |
| `MAC-003` | System Integrity Protection is enabled | <span class="sev sev-critical">critical</span> | platform, macos |
| `MAC-004` | Gatekeeper is enabled | <span class="sev sev-high">high</span> | platform, macos |
| `MAC-005` | Application firewall is enabled | <span class="sev sev-high">high</span> | platform, macos, firewall |
| `MAC-006` | Firewall stealth mode is on | <span class="sev sev-low">low</span> | platform, macos, firewall |
| `MAC-007` | Automatic update checks are on | <span class="sev sev-medium">medium</span> | platform, macos, updates |
| `MAC-008` | Critical security updates install automatically | <span class="sev sev-medium">medium</span> | platform, macos, updates |
| `MAC-009` | Screen lock is not disabled | <span class="sev sev-medium">medium</span> | platform, macos, screenlock |
| `MAC-010` | Display sleeps after at most 15 minutes | <span class="sev sev-low">low</span> | platform, macos, screenlock |
| `MAC-011` | Guest account is disabled | <span class="sev sev-medium">medium</span> | platform, macos, users |
| `MAC-SVC-SSH` | Remote Login (SSH) is disabled | <span class="sev sev-medium">medium</span> | platform, macos, services |
| `MAC-SVC-SCREENSHARING` | Screen Sharing is disabled | <span class="sev sev-medium">medium</span> | platform, macos, services |
| `MAC-SVC-SMB` | File Sharing (SMB) is disabled | <span class="sev sev-medium">medium</span> | platform, macos, services |
| `MAC-012` | Internal disk reports a healthy SMART status | <span class="sev sev-medium">medium</span> | platform, macos, hardware |

## Policy

```yaml title="examples/platforms/macos.yml" linenums="1"
name: macOS
version: 1.0.0
description: >
  Security baseline for macOS workstations. Most checks work without root;
  checks that need it are guarded with `when: facts.is_root`.

vars:
  min_macos: "14.0"
  max_display_sleep_minutes: 15

checks:
  - id: MAC-001
    name: "macOS {{ min_macos }} or newer"
    tags: [platform, macos, updates]
    severity: high
    when: facts.os == "darwin"
    run: sw_vers -productVersion
    as: version
    expect: ">= {{ min_macos }}"

  - id: MAC-002
    name: FileVault disk encryption is on
    tags: [platform, macos, encryption]
    severity: critical
    when: facts.os == "darwin"
    run: fdesetup status
    expect: "~ ^FileVault is On"
    remediation: System Settings → Privacy & Security → FileVault

  - id: MAC-003
    name: System Integrity Protection is enabled
    tags: [platform, macos]
    severity: critical
    when: facts.os == "darwin"
    run: csrutil status
    expect: "~ status: enabled"

  - id: MAC-004
    name: Gatekeeper is enabled
    tags: [platform, macos]
    severity: high
    when: facts.os == "darwin"
    run: spctl --status
    expect: "== assessments enabled"

  - id: MAC-005
    name: Application firewall is enabled
    tags: [platform, macos, firewall]
    severity: high
    when: facts.os == "darwin"
    run: /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
    expect: "~ enabled"
    remediation: sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on

  - id: MAC-006
    name: Firewall stealth mode is on
    tags: [platform, macos, firewall]
    severity: low
    when: facts.os == "darwin"
    run: /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
    expect: "~ (?i)stealth mode is on"

  - id: MAC-007
    name: Automatic update checks are on
    tags: [platform, macos, updates]
    when: facts.os == "darwin"
    run: softwareupdate --schedule
    expect: "~ turned on"

  - id: MAC-008
    name: Critical security updates install automatically
    tags: [platform, macos, updates]
    when: facts.os == "darwin"
    run: defaults read /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall
    expect: "== 1"

  - id: MAC-009
    name: Screen lock is not disabled
    tags: [platform, macos, screenlock]
    when: facts.os == "darwin"
    # sysadminctl writes its answer to stderr, prefixed with a timestamp.
    run: sysadminctl -screenLock status
    expect: { stderr: "!~ screenLock is off" }

  - id: MAC-010
    name: "Display sleeps after at most {{ max_display_sleep_minutes }} minutes"
    tags: [platform, macos, screenlock]
    severity: low
    when: facts.os == "darwin"
    run: |
      pmset -g | awk '$1 == "displaysleep" {print $2}'
    expect: ["!empty", "<= {{ max_display_sleep_minutes }}", "> 0"]

  - id: MAC-011
    name: Guest account is disabled
    tags: [platform, macos, users]
    when: facts.os == "darwin"
    run: defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled
    expect: "== 0"

  - id: "MAC-SVC-{{ item.id }}"
    name: "{{ item.label }} is disabled"
    tags: [platform, macos, services]
    when: facts.os == "darwin"
    loop:
      - { id: SSH, label: Remote Login (SSH), service: com.openssh.sshd }
      - { id: SCREENSHARING, label: Screen Sharing, service: com.apple.screensharing }
      - { id: SMB, label: File Sharing (SMB), service: com.apple.smbd }
    run: |
      launchctl print-disabled system | grep -F '"{{ item.service }}"'
    allow_rc: [0, 1]
    # Not listed means launchd uses the default, which is "disabled".
    expect: { any: [empty, "~ => (disabled|true)"] }

  - id: MAC-012
    name: Internal disk reports a healthy SMART status
    tags: [platform, macos, hardware]
    when: facts.os == "darwin"
    run: |
      diskutil info disk0 | awk -F: '/SMART Status/ {gsub(/^[[:space:]]+/, "", $2); print $2}'
    expect: "in [Verified, Not Supported]"
```
