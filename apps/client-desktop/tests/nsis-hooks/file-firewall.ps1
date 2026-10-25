# Run elevated. Uses an inert test executable, never the installed daemon, and
# always removes its rule. Refuses to touch a pre-existing installation rule.
param([Parameter(Mandatory = $true)][string]$Report)
$ErrorActionPreference = 'Stop'
$name = 'Calabi.FileTransfer.Inbound.v1'
$script = (Resolve-Path (Join-Path $PSScriptRoot '../../../client/internal/filecontrol/filefirewall_windows.ps1')).Path
$work = Join-Path ([IO.Path]::GetTempPath()) ('calabi-file-firewall-' + [guid]::NewGuid().ToString('N'))
$owned = $false
$result = @{ state = 'running' }
function Invoke-Rule($action, $receiving = 'off', $program = $script:program) {
    $out = & "$PSHOME/powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script -Action $action -Program $program -Receiving $receiving 2>&1
    if ($LASTEXITCODE -ne 0) { throw ($out -join "`n") }
}
function Assert($condition, $message) { if (-not $condition) { throw $message } }
try {
    if (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue) { throw 'A real enrollment already exists; refusing to change it.' }
    New-Item -ItemType Directory -Path $work | Out-Null
    $program = Join-Path $work 'calabi-test.exe'
    Copy-Item -LiteralPath "$env:SystemRoot/System32/whoami.exe" -Destination $program
    $owned = $true
    Invoke-Rule Install
    $r = Get-NetFirewallRule -DisplayName $name
    Assert ($r.Enabled -eq 'False') 'Installation enabled reception without opt-in.'
    $result.installedDisabled = $true
    Invoke-Rule Apply on
    Invoke-Rule Apply on
    $rules = @(Get-NetFirewallRule -DisplayName $name)
    Assert ($rules.Count -eq 1) 'Repeated activation duplicated the rule.'
    $r = $rules[0]
    Assert ($r.Enabled -eq 'True' -and $r.Direction -eq 'Inbound' -and $r.Action -eq 'Allow') 'Rule is not enabled inbound allow.'
    Assert (($r | Get-NetFirewallApplicationFilter).Program -eq $program) 'Program scope was lost.'
    $ports = $r | Get-NetFirewallPortFilter
    Assert ($ports.Protocol -eq 'TCP' -and $ports.LocalPort -eq '17401') 'Port scope was lost.'
    $addresses = $r | Get-NetFirewallAddressFilter
    Assert ($addresses.LocalAddress -eq '100.64.0.0/255.192.0.0' -or $addresses.LocalAddress -eq '100.64.0.0/10') 'Local address scope was lost.'
    Assert ($addresses.RemoteAddress -eq '100.64.0.0/255.192.0.0' -or $addresses.RemoteAddress -eq '100.64.0.0/10') 'Remote address scope was lost.'
    Assert (($r | Get-NetFirewallInterfaceFilter).InterfaceAlias -eq 'calabi-mesh') 'Interface scope was lost.'
    $result.scopedAndIdempotent = $true
    Invoke-Rule Apply off
    Assert ((Get-NetFirewallRule -DisplayName $name).Enabled -eq 'False') 'Receive off did not disable the rule.'
    $result.disabled = $true
    Invoke-Rule Install
    Assert ((Get-NetFirewallRule -DisplayName $name).Enabled -eq 'False') 'Upgrade enabled reception.'
    Invoke-Rule Remove
    Invoke-Rule Remove
    Assert (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) 'Uninstall left its rule behind.'
    Invoke-Rule Apply on
    Assert (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) 'Unenrolled executable created a rule.'
    $result.removedAndUnenrolledNoop = $true
    $result.state = 'passed'
} catch {
    $result.state = 'failed'
    $result.error = $_.Exception.Message
} finally {
    if ($owned) {
        try { Invoke-Rule Remove } catch { $result.cleanupError = $_.Exception.Message; $result.state = 'failed' }
        if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force }
    }
    $result | ConvertTo-Json | Set-Content -LiteralPath $Report -Encoding UTF8
}
