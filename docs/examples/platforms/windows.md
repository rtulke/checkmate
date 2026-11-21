# Windows

Security baseline for Windows 10/11 and Windows Server. Commands run in PowerShell (pwsh if installed, otherwise Windows PowerShell). Several checks need an elevated (administrator) session.

<div class="grid cards" markdown>

- :material-file-code: **Policy file**  
  [`examples/platforms/windows.yml`](https://github.com/rtulke/checkmate/blob/main/examples/platforms/windows.yml)
- :material-format-list-checks: **Checks**  
  12 from 12 definitions
- :material-monitor: **Platforms**  
  windows

</div>

## Run it

```bash
# Show what would run on this host
checkmate list -v examples/platforms/windows.yml

# Run the checks
checkmate run examples/platforms/windows.yml

# Override a variable from the command line
checkmate run examples/platforms/windows.yml -e name=value
```

## Checks

| ID | Check | Severity | Tags |
|---|---|---|---|
| `WIN-001` | Defender real-time protection is enabled | <span class="sev sev-critical">critical</span> | platform, windows, antivirus |
| `WIN-002` | Defender signatures are at most 3 days old | <span class="sev sev-high">high</span> | platform, windows, antivirus |
| `WIN-003` | Firewall is enabled for all profiles | <span class="sev sev-high">high</span> | platform, windows, firewall |
| `WIN-004` | BitLocker protects the system drive | <span class="sev sev-critical">critical</span> | platform, windows, encryption |
| `WIN-005` | SMBv1 is disabled | <span class="sev sev-high">high</span> | platform, windows, network |
| `WIN-006` | Remote Desktop requires Network Level Authentication | <span class="sev sev-medium">medium</span> | platform, windows, rdp |
| `WIN-007` | User Account Control is enabled | <span class="sev sev-high">high</span> | platform, windows |
| `WIN-008` | The built-in Guest account is disabled | <span class="sev sev-medium">medium</span> | platform, windows, users |
| `WIN-009` | No reboot pending | <span class="sev sev-medium">medium</span> | platform, windows, updates |
| `WIN-010` | An update was installed within 45 days | <span class="sev sev-high">high</span> | platform, windows, updates |
| `WIN-011` | PowerShell v2 engine is removed | <span class="sev sev-medium">medium</span> | platform, windows |
| `WIN-012` | Windows version is supported | <span class="sev sev-medium">medium</span> | platform, windows, updates |

## Policy

```yaml title="examples/platforms/windows.yml" linenums="1"
name: Windows
version: 1.0.0
description: >
  Security baseline for Windows 10/11 and Windows Server. Commands run in
  PowerShell (pwsh if installed, otherwise Windows PowerShell). Several
  checks need an elevated (administrator) session.

vars:
  max_signature_age_days: 3
  max_days_since_update: 45

checks:
  - id: WIN-001
    name: Defender real-time protection is enabled
    tags: [platform, windows, antivirus]
    severity: critical
    when: facts.os == "windows"
    run: (Get-MpComputerStatus).RealTimeProtectionEnabled
    expect: "== True"

  - id: WIN-002
    name: "Defender signatures are at most {{ max_signature_age_days }} days old"
    tags: [platform, windows, antivirus]
    severity: high
    when: facts.os == "windows"
    run: (Get-MpComputerStatus).AntivirusSignatureAge
    expect: "<= {{ max_signature_age_days }}"
    remediation: Update-MpSignature

  - id: WIN-003
    name: Firewall is enabled for all profiles
    tags: [platform, windows, firewall]
    severity: high
    when: facts.os == "windows"
    run: |
      Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | Select-Object -ExpandProperty Name
    expect: empty
    remediation: Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

  - id: WIN-004
    name: BitLocker protects the system drive
    tags: [platform, windows, encryption]
    severity: critical
    when: facts.os == "windows"
    run: |
      (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus
    expect: "== On"

  - id: WIN-005
    name: SMBv1 is disabled
    tags: [platform, windows, network]
    severity: high
    when: facts.os == "windows"
    run: (Get-SmbServerConfiguration).EnableSMB1Protocol
    expect: "== False"
    remediation: Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

  - id: WIN-006
    name: Remote Desktop requires Network Level Authentication
    tags: [platform, windows, rdp]
    when: facts.os == "windows"
    run: |
      (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
    expect: "== 1"

  - id: WIN-007
    name: User Account Control is enabled
    tags: [platform, windows]
    severity: high
    when: facts.os == "windows"
    run: |
      (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA
    expect: "== 1"

  - id: WIN-008
    name: The built-in Guest account is disabled
    tags: [platform, windows, users]
    when: facts.os == "windows"
    run: |
      (Get-LocalUser | Where-Object { $_.SID -like '*-501' }).Enabled
    expect: "== False"

  - id: WIN-009
    name: No reboot pending
    tags: [platform, windows, updates]
    when: facts.os == "windows"
    run: |
      $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
      )
      ($keys | Where-Object { Test-Path $_ }).Count
    expect: "== 0"

  - id: WIN-010
    name: "An update was installed within {{ max_days_since_update }} days"
    tags: [platform, windows, updates]
    severity: high
    when: facts.os == "windows"
    run: |
      $last = Get-HotFix | Where-Object InstalledOn | Sort-Object InstalledOn -Descending | Select-Object -First 1
      ((Get-Date) - $last.InstalledOn).Days
    expect: "<= {{ max_days_since_update }}"

  - id: WIN-011
    name: PowerShell v2 engine is removed
    tags: [platform, windows]
    when: facts.os == "windows"
    run: |
      (Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root).State
    expect: "in [Disabled, DisabledWithPayloadRemoved]"

  - id: WIN-012
    name: Windows version is supported
    tags: [platform, windows, updates]
    when: facts.os == "windows"
    run: echo "{{ facts.version }}"
    as: version
    expect: ">= 10.0.19045"
```
