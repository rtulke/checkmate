# Runs policies over a real SSH connection to this Windows machine and
# compares the results with a local run. Made for a disposable CI runner: it
# starts sshd and authorizes a new key for administrators.
param([string]$Checkmate = '.\checkmate.exe')
$ErrorActionPreference = 'Stop'
$out = Join-Path $PWD 'ssh-out'
New-Item -ItemType Directory -Force -Path $out | Out-Null

# --- sshd ---------------------------------------------------------------------
if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
    Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null
}
Start-Service sshd
# The key goes into the profile: ssh refuses a private key that other users
# can read, as a file in the workspace could be.
$sshDir = Join-Path $env:USERPROFILE '.ssh'
New-Item -ItemType Directory -Force -Path $sshDir | Out-Null
$key = Join-Path $sshDir 'checkmate_test_key'
& ssh-keygen -q -t ed25519 -N '' -f $key
if ($LASTEXITCODE) { throw 'ssh-keygen failed' }
# Keys of administrators live in one file that only they and SYSTEM may write.
$authorized = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
Get-Content "$key.pub" | Add-Content -Path $authorized -Encoding ascii
& icacls $authorized /inheritance:r /grant 'Administrators:F' /grant 'SYSTEM:F' | Out-Null
$ErrorActionPreference = 'Continue'
& ssh-keyscan -T 10 localhost 2>$null | Add-Content -Path (Join-Path $sshDir 'known_hosts') -Encoding ascii
$ErrorActionPreference = 'Stop'
"Host localhost`n  IdentityFile $($key -replace '\\', '/')`n  IdentitiesOnly yes`n" |
    Add-Content -Path (Join-Path $sshDir 'config') -Encoding ascii

$script:status = 0
function Fail([string]$message) {
    Write-Output "FAILED: $message"
    $script:status = 1
}

# Runs checkmate and returns the parsed JSON report. A non-compliant run is
# a result, not an error.
function Run-Report([string[]]$arguments, [string]$name) {
    $file = Join-Path $out "$name.json"
    $ErrorActionPreference = 'Continue'
    # --allow-insecure-policy: every user may write to the workspace of a runner.
    & $Checkmate run @arguments --allow-insecure-policy --format json 2> (Join-Path $out "$name.err") | Out-File -FilePath $file -Encoding utf8
    $ErrorActionPreference = 'Stop'
    if (-not (Test-Path $file) -or (Get-Item $file).Length -eq 0) {
        Fail "${name}: no report. $(Get-Content (Join-Path $out "$name.err") -Raw)"
        return $null
    }
    Get-Content -LiteralPath $file -Raw | ConvertFrom-Json
}

function Statuses($report) {
    @($report.results | ForEach-Object { "$($_.id) $($_.status)" } | Sort-Object)
}

# --- the same results as a local run ---------------------------------------------
foreach ($policy in @('examples/platforms/windows.yml')) {
    $name = [IO.Path]::GetFileNameWithoutExtension($policy) + '-' + (Split-Path (Split-Path $policy) -Leaf)
    $local = Run-Report @($policy) "$name-local"
    $remote = Run-Report @($policy, '--host', 'localhost') "$name-ssh"
    if ($null -eq $local -or $null -eq $remote) { continue }
    $diff = Compare-Object (Statuses $local) (Statuses $remote)
    if ($diff) {
        Fail "${policy}: local (<=) and SSH (=>) results differ"
        $diff | ForEach-Object { Write-Output "  $($_.SideIndicator) $($_.InputObject)" }
        $remote.results | Where-Object { $_.status -eq 'ERROR' } | Select-Object -First 5 |
            ForEach-Object { Write-Output "  $($_.id): $($_.message)" }
    } else {
        Write-Output "ok      ${policy}: $(@($remote.results).Count) results match"
    }
    if ($policy -like '*platforms*') {
        $l = $local.facts | ConvertTo-Json -Compress
        $r = $remote.facts | ConvertTo-Json -Compress
        if ($l -eq $r) { Write-Output "ok      facts match: $r" } else { Fail "facts differ: local $l, SSH $r" }
    }
}

# --- quoting, encoding, variables, exit codes, long scripts -----------------------
$long = ('# ' + ('x' * 120) + "`n      ") * 120
@"
name: SSH probe
checks:
  - id: QUOTING
    run: |
      Write-Output ('it''s' + '|' + "say ""hi""" + '|' + '`$(x) %PATH% ^ & < >')
    expect: 'it''s|say "hi"|`$(x) %PATH% ^ & < >'
  - id: UNICODE
    run: Write-Output ([string][char]0xE4 + [char]0x20AC + 'ö')
    expect: "ä€ö"
  - id: NATIVE-EXIT
    run: cmd /c exit 3
    expect: { rc: "== 3" }
  - id: THROW
    run: throw 'broken'
    expect: false
  - id: SILENCED
    run: |
      `$null = Get-Item C:\nope -ErrorAction SilentlyContinue
      Write-Output done
    expect: done
  - id: "ITEM-{{ item | replace(' ', '_') | replace(';', '') | replace('`$', '') | replace('(', '') | replace(')', '') }}"
    loop_run: |
      Write-Output 'plain'
      Write-Output 'with space'
      Write-Output 'it''s; `$(New-Item C:\checkmate-ssh-pwned)'
    run: Write-Output `$env:CHECKMATE_ITEM
    expect: "{{ item }}"
  - id: LONG
    run: |
      $long
      Write-Output long-ok
    expect: long-ok
  - id: SHELL-51
    shell: powershell
    run: Write-Output `$PSVersionTable.PSVersion.Major
    expect: "5"
  - id: NOT-FOUND
    run: no-such-command-on-this-host
    expect: true
"@ | Out-File -FilePath (Join-Path $out 'probe.yml') -Encoding utf8
$probe = Run-Report @((Join-Path $out 'probe.yml'), '--host', 'localhost') 'probe'
$want = @("ITEM-it's_New-Item_C:\checkmate-ssh-pwned PASS", 'ITEM-plain PASS', 'ITEM-with_space PASS', 'LONG PASS', 'NATIVE-EXIT PASS',
    'NOT-FOUND FAIL', 'QUOTING PASS', 'SHELL-51 PASS', 'SILENCED PASS', 'THROW PASS', 'UNICODE PASS') | Sort-Object
if ($null -ne $probe) {
    $diff = Compare-Object $want (Statuses $probe)
    if ($diff) {
        Fail 'probe results differ (<= expected, => got)'
        $diff | ForEach-Object { Write-Output "  $($_.SideIndicator) $($_.InputObject)" }
        $probe.results | Where-Object { $_.status -ne 'PASS' } | ForEach-Object { Write-Output "  $($_.id): $($_.message)" }
    } else {
        Write-Output 'ok      quoting, encoding, exit codes, items, a long script and Windows PowerShell 5.1'
    }
}
if (Test-Path 'C:\checkmate-ssh-pwned') { Fail 'an item was executed on the host' }

# --- from an inventory, with a host that is down ---------------------------------
@"
groups:
  windows:
    vars: { expected: one }
    hosts: [localhost]
  down:
    hosts:
      - { name: down.example.net, address: 127.0.0.1, port: 1 }
"@ | Out-File -FilePath (Join-Path $out 'hosts.yml') -Encoding utf8
@"
name: Inventory probe
checks:
  - id: VALUE
    run: Write-Output "{{ expected }} {{ inventory_hostname }} {{ facts.os }}"
    expect: "one localhost windows"
"@ | Out-File -FilePath (Join-Path $out 'inventory.yml') -Encoding utf8
$ErrorActionPreference = 'Continue'
& $Checkmate run (Join-Path $out 'inventory.yml') -i (Join-Path $out 'hosts.yml') --allow-insecure-policy --format json 2>$null |
    Out-File -FilePath (Join-Path $out 'inventory.json') -Encoding utf8
$code = $LASTEXITCODE
$ErrorActionPreference = 'Stop'
$inventory = Get-Content -LiteralPath (Join-Path $out 'inventory.json') -Raw | ConvertFrom-Json
$got = @($inventory.reports | ForEach-Object { if ($_.unreachable) { "$($_.host) unreachable" } else { "$($_.host) $($_.results[0].status)" } })
if ($code -eq 3 -and ($got -join '; ') -eq 'localhost PASS; down.example.net unreachable') {
    Write-Output 'ok      inventory: one host checked, one unreachable, exit 3'
} else {
    Fail "inventory: exit $code, $($got -join '; ')"
}

exit $script:status
