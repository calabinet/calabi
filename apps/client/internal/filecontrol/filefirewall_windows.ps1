param(
    [Parameter(Mandatory = $true)][ValidateSet('Install', 'Apply', 'Remove')][string]$Action,
    [Parameter(Mandatory = $true)][string]$Program,
    [ValidateSet('on', 'off')][string]$Receiving = 'off'
)
$ErrorActionPreference = 'Stop'
$name = 'Calabi.FileTransfer.Inbound.v1'
$group = 'Calabi.FileTransfer'
$mutex = $null
$locked = $false
try {
    # Serialize the elevated installer and SYSTEM daemon, especially uninstall
    # racing with a reception toggle. Only administrators and SYSTEM may enter.
    $security = New-Object Security.AccessControl.MutexSecurity
    $security.SetAccessRuleProtection($true, $false)
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $identity = New-Object Security.Principal.SecurityIdentifier($sid)
        $security.AddAccessRule([Security.AccessControl.MutexAccessRule]::new($identity, 'FullControl', 'Allow'))
    }
    $created = $false
    $mutex = [Threading.Mutex]::new($false, 'Global\Calabi.FileTransfer.Firewall.v1', [ref]$created, $security)
    try { $locked = $mutex.WaitOne(2000) }
    catch [Threading.AbandonedMutexException] { $locked = $true }
    if (-not $locked) { throw 'Another Calabi firewall update is still running; retry.' }
    $Program = [IO.Path]::GetFullPath($Program)
    $policy = New-Object -ComObject HNetCfg.FwPolicy2
    $existing = @($policy.Rules | Where-Object { $_.Name -eq $name })
    foreach ($entry in $existing) {
        if ($entry.Grouping -ne $group -or $entry.ApplicationName -ne $Program) {
            throw 'The Calabi file firewall rule belongs to a different installation.'
        }
    }
    if ($Action -eq 'Remove') {
        foreach ($entry in $existing) { $entry.Enabled = $false }
        foreach ($entry in $existing) { $policy.Rules.Remove($name) }
        Write-Output 'Calabi file firewall rule removed.'
        exit 0
    }
    # Apply never grants a ZIP/dev binary permission without installer enrollment.
    if ($Action -eq 'Apply' -and $existing.Count -eq 0) { exit 0 }
    if ($Action -eq 'Apply' -and $Receiving -eq 'off') {
        foreach ($entry in $existing) { $entry.Enabled = $false }
        Write-Output 'Calabi file firewall rule disabled.'
        exit 0
    }
    if (-not (Test-Path -LiteralPath $Program -PathType Leaf)) { throw 'Calabi executable not found.' }
    $rule = New-Object -ComObject HNetCfg.FWRule
    $rule.Name = $name
    $rule.Grouping = $group
    $rule.Description = 'Calabi file reception on its mesh adapter only; reception and confirmation are controlled in Calabi.'
    $rule.ApplicationName = $Program
    $rule.Protocol = 6
    $rule.LocalPorts = '17401'
    $rule.LocalAddresses = '100.64.0.0/10'
    $rule.RemoteAddresses = '100.64.0.0/10'
    $rule.Direction = 1
    $rule.Action = 1
    $rule.Profiles = 2147483647
    $rule.EdgeTraversal = $false
    # Install only enrolls a disabled rule, even before Wintun exists. Only the
    # authenticated receiving lease can enable it, after binding the adapter.
    $ready = $Action -eq 'Apply' -and $Receiving -eq 'on'
    if ($ready) { $rule.Interfaces = @('calabi-mesh') }
    $rule.Enabled = $ready
    # COM Add permits duplicate display names. Disable/remove only our previous
    # entries before committing a fully configured replacement. Fail closed if
    # the replacement fails; never expose an unrestricted intermediate rule.
    foreach ($entry in $existing) { $entry.Enabled = $false }
    foreach ($entry in $existing) { $policy.Rules.Remove($name) }
    $policy.Rules.Add($rule)
    if ($ready) { Write-Output 'Calabi file firewall rule applied to calabi-mesh.' }
    else { Write-Output 'Calabi file firewall rule enrolled, disabled until reception is enabled.' }
} catch {
    [Console]::Error.WriteLine('Calabi file firewall: ' + $_.Exception.Message)
    exit 1
} finally {
    if ($locked) { $mutex.ReleaseMutex() }
    if ($null -ne $mutex) { $mutex.Dispose() }
}
