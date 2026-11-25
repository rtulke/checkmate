# Removes PowerShell 7 from PATH for the current session, so that checkmate
# falls back to Windows PowerShell 5.1, the only PowerShell on a default
# server installation. Dot-source it: . ./test/windows/without-pwsh.ps1
$env:PATH = (($env:PATH -split ';') | Where-Object {
    $_ -and -not (Test-Path (Join-Path $_ 'pwsh.exe'))
}) -join ';'
if (Get-Command pwsh -ErrorAction SilentlyContinue) {
    throw 'pwsh is still on PATH'
}
"PowerShell used by checks: $((Get-Command powershell).Source)"
