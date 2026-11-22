# Runs examples/attack/windows.yml on a clean CI runner, plants typical
# attacker artifacts and checks that every one of them is found. Only for
# disposable machines: it changes the registry, WMI and scheduled tasks.
param([string]$Checkmate = '.\checkmate.exe')
$ErrorActionPreference = 'Stop'

function Run-Policy([string]$out) {
    & $Checkmate run examples/attack/windows.yml -q --format json --export json -o $out | Out-Null
    Get-Content -LiteralPath $out -Raw | ConvertFrom-Json
}

$before = Run-Policy 'attack-before.json'
$errors = @($before.results | Where-Object { $_.status -eq 'ERROR' })

# --- plant ------------------------------------------------------------------
$payload = "$env:LOCALAPPDATA\Temp\updater.exe"
New-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Force -ErrorAction SilentlyContinue | Out-Null
New-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name Updater -Value $payload -Force | Out-Null
$ifeo = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe'
New-Item -Path $ifeo -Force | Out-Null
New-ItemProperty -Path $ifeo -Name Debugger -Value 'C:\Windows\System32\cmd.exe' -Force | Out-Null
$consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property @{ Name = 'checkmate-sim'; CommandLineTemplate = 'cmd.exe /c echo pwned' }
$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA'
Register-ScheduledTask -TaskName 'CheckmateSim' -Action $action -Force | Out-Null
New-Item -Path 'HKCU:\Software\Microsoft\Office test\Special\Perf' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name Shell -Value 'explorer.exe, C:\Users\Public\shell.exe'
New-Service -Name CheckmateSim -BinaryPathName 'C:\Program Files\Checkmate Sim\service.exe' -StartupType Manual | Out-Null

$after = Run-Policy 'attack-after.json'
$errors += @($after.results | Where-Object { $_.status -eq 'ERROR' })

# Each planted artifact and a marker that must appear in the finding.
$expected = [ordered]@{
    'ATT-WIN-RUN-KEYS'         = 'Updater'
    'ATT-WIN-IFEO'             = 'sethc.exe'
    'ATT-WIN-WMI-SUBSCRIPTION' = 'checkmate-sim'
    'ATT-WIN-SCHEDULED-TASKS'  = 'CheckmateSim'
    'ATT-WIN-OFFICE-TEST'      = 'Office test'
    'ATT-WIN-WINLOGON'         = 'shell.exe'
    'ATT-WIN-SERVICE-PATHS'    = 'CheckmateSim'
}
$status = 0
foreach ($id in $expected.Keys) {
    $r = $after.results | Where-Object { $_.id -eq $id }
    if ($r.status -eq 'FAIL' -and "$($r.stdout)" -like "*$($expected[$id])*") { Write-Output "found     $id" }
    else { Write-Output "NOT FOUND $id ($($r.status)): $($r.message)"; $status = 1 }
}
foreach ($e in $errors) { Write-Output "ERROR     $($e.id): $($e.message) $($e.stderr)"; $status = 1 }
Write-Output ("before: {0}" -f (($before.results | Group-Object status | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join ' '))
foreach ($r in $before.results | Where-Object { $_.status -eq 'FAIL' }) { Write-Output "  runner finding: $($r.id): $($r.message)" }

# --- clean up ---------------------------------------------------------------
Get-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Filter "Name='checkmate-sim'" | Remove-CimInstance
Unregister-ScheduledTask -TaskName CheckmateSim -Confirm:$false
& sc.exe delete CheckmateSim | Out-Null
exit $status
