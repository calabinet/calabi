# Used only by the elevated installer for the desktop and user file agent.
param([Parameter(Mandatory = $true)][string]$InstallDir, [switch]$VerifyOnly, [ValidateRange(0,120)][int]$WaitSeconds=30,
    [ValidateSet('Register','Remove')][string]$Startup)
$ErrorActionPreference = 'Stop'

function Get-CalabiUpgradeRole($Process, [string]$Directory) {
    if (-not $Process.ExecutablePath) { return '' }
    $desktop = [IO.Path]::GetFullPath((Join-Path $Directory 'calabi-desktop.exe'))
    $daemon = [IO.Path]::GetFullPath((Join-Path $Directory 'calabi.exe'))
    if ([string]::Equals($Process.ExecutablePath, $desktop, [StringComparison]::OrdinalIgnoreCase)) { return 'desktop' }
    foreach ($name in @('calabi-rdp.exe','calabi-paste.exe')) {
        $helper = [IO.Path]::GetFullPath((Join-Path $Directory "rdp/$name"))
        if ([string]::Equals($Process.ExecutablePath, $helper, [StringComparison]::OrdinalIgnoreCase)) { return 'remote-helper' }
    }
    # Exclude the system daemon, interactive CLI and every other installation.
    if ([string]::Equals($Process.ExecutablePath, $daemon, [StringComparison]::OrdinalIgnoreCase) -and
        $Process.CommandLine -match '^(?:"[^"]+"|\S+)\s+mesh\s+files\s+--(?:stdio|background)(?:\s|$)') { return 'file-agent' }
    return ''
}

function Stop-CalabiUpgradeProcess($Target) {
    # NSIS may launch 32-bit PowerShell. Its Process.Path cannot reliably read
    # a 64-bit process, so revalidate the image through CIM instead.
    $current = Get-CimInstance Win32_Process -Filter "ProcessId=$($Target.ProcessId)"
    if (-not $current) { return }
    if (-not [string]::Equals($current.ExecutablePath, $Target.ExecutablePath, [StringComparison]::OrdinalIgnoreCase) -or
        $current.CreationDate -ne $Target.CreationDate) { throw 'Process identity changed while preparing the upgrade.' }
    $process = Get-Process -Id $Target.ProcessId -ErrorAction SilentlyContinue
    if (-not $process) { return }
    try {
        if ([Math]::Abs(($process.StartTime.ToUniversalTime() - $Target.CreationDate.ToUniversalTime()).TotalMilliseconds) -gt 100) {
            throw 'Process identity changed while preparing the upgrade.'
        }
        Stop-Process -InputObject $process -Force
        if (-not $process.WaitForExit(5000)) { throw 'Desktop or file agent did not exit.' }
    } finally { $process.Dispose() }
}

function Wait-CalabiUpgradeFiles([string]$Directory, [int]$Seconds) {
    # Open existing files without truncating/writing. Probe write access as well
    # as sharing: process exit alone does not prove image sections are released.
    $files = @(Get-ChildItem -LiteralPath $Directory -File -ErrorAction Stop | Where-Object Extension -in '.exe','.dll')
    $rdp = Join-Path $Directory 'rdp'
    if (Test-Path -LiteralPath $rdp) {
        $files += @(Get-ChildItem -LiteralPath $rdp -File -Recurse -ErrorAction Stop | Where-Object Extension -in '.exe','.dll')
    }
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        $busy = @()
        foreach ($file in $files) {
            $handle = $null
            try { $handle = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::None) }
            catch { $busy += "$($file.FullName): $($_.Exception.Message)" }
            finally { if ($handle) { $handle.Dispose() } }
        }
        if (-not $busy.Count) { return }
        if ([DateTime]::UtcNow -ge $deadline) { throw ("Files remain locked or unwritable after ${Seconds}s:`r`n" + ($busy -join "`r`n")) }
        Start-Sleep -Milliseconds 500
    } while ($true)
}

function Get-CalabiFileAgentTask([string]$Directory) {
    $task = Get-ScheduledTask | Where-Object { $_.TaskPath -eq '\' -and $_.TaskName -eq 'Calabi User File Agent' }
    if ($task) {
        $desktop = [IO.Path]::GetFullPath((Join-Path $Directory 'calabi-desktop.exe'))
        if (@($task.Actions).Count -ne 1 -or $task.Actions[0].Execute -ne $desktop -or
            $task.Actions[0].Arguments -ne '--run-file-agent') {
            throw 'The existing Calabi User File Agent task belongs to another installation.'
        }
    }
    return $task
}

function New-CalabiFileAgentTask([string]$Directory) {
    $desktop = [IO.Path]::GetFullPath((Join-Path $Directory 'calabi-desktop.exe'))
    $action = New-ScheduledTaskAction -Execute $desktop -Argument '--run-file-agent'
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    # INTERACTIVE is a well-known SID. Group activation uses the triggering
    # user's token, including a Windows Remote Desktop sign-in.
    $principal = New-ScheduledTaskPrincipal -GroupId 'S-1-5-4' -RunLevel Limited
    $options = @{
        AllowStartIfOnBatteries = $true
        DontStopIfGoingOnBatteries = $true
        ExecutionTimeLimit = [TimeSpan]::Zero
        MultipleInstances = 'Parallel'
    }
    $settings = New-ScheduledTaskSettingsSet @options
    return @{
        TaskName = 'Calabi User File Agent'
        Action = $action
        Trigger = $trigger
        Principal = $principal
        Settings = $settings
        Force = $true
    }
}

function Register-CalabiFileAgentTask([string]$Directory) {
    $null = Get-CalabiFileAgentTask $Directory
    $definition = New-CalabiFileAgentTask $Directory
    Register-ScheduledTask @definition | Out-Null
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        if ($VerifyOnly) { Wait-CalabiUpgradeFiles $InstallDir $WaitSeconds; exit 0 }
        if ($Startup -eq 'Register') { Register-CalabiFileAgentTask $InstallDir; exit 0 }
        $task = $null
        if ($Startup -eq 'Remove') {
            $task = Get-CalabiFileAgentTask $InstallDir
            if ($task) { $task | Disable-ScheduledTask | Out-Null }
        }
        # Stop the shell first so it cannot recreate its file agent.
        foreach ($role in @('desktop', 'file-agent', 'remote-helper')) {
            $targets = Get-CimInstance Win32_Process -Filter "Name='calabi-desktop.exe' OR Name='calabi.exe' OR Name='calabi-rdp.exe' OR Name='calabi-paste.exe'"
            foreach ($target in $targets) {
                if ((Get-CalabiUpgradeRole $target $InstallDir) -eq $role) { Stop-CalabiUpgradeProcess $target }
            }
        }
        if ($task) { $task | Unregister-ScheduledTask -Confirm:$false }
        exit 0
    } catch {
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 1
    }
}
