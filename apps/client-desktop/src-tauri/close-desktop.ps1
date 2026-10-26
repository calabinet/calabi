# Used only by the elevated installer before it stops/replaces the daemon.
param([Parameter(Mandatory = $true)][string]$InstallDir)
$ErrorActionPreference = 'Stop'

function Get-CalabiUpgradeRole($Process, [string]$Directory) {
    if (-not $Process.ExecutablePath) { return '' }
    $desktop = [IO.Path]::GetFullPath((Join-Path $Directory 'calabi-desktop.exe'))
    $daemon = [IO.Path]::GetFullPath((Join-Path $Directory 'calabi.exe'))
    if ([string]::Equals($Process.ExecutablePath, $desktop, [StringComparison]::OrdinalIgnoreCase)) { return 'desktop' }
    # Exclude the system daemon, interactive CLI and every other installation.
    if ([string]::Equals($Process.ExecutablePath, $daemon, [StringComparison]::OrdinalIgnoreCase) -and
        $Process.CommandLine -match '^(?:"[^"]+"|\S+)\s+mesh\s+files\s+--stdio(?:\s|$)') { return 'file-agent' }
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

if ($MyInvocation.InvocationName -ne '.') {
    try {
        # Stop the shell first so it cannot recreate its private file agent.
        foreach ($role in @('desktop', 'file-agent')) {
            $targets = Get-CimInstance Win32_Process -Filter "Name='calabi-desktop.exe' OR Name='calabi.exe'"
            foreach ($target in $targets) {
                if ((Get-CalabiUpgradeRole $target $InstallDir) -eq $role) { Stop-CalabiUpgradeProcess $target }
            }
        }
        exit 0
    } catch {
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 1
    }
}
