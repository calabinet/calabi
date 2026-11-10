# Uses stand-ins in isolated directories; never stops an installed Calabi.
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$script = (Resolve-Path (Join-Path $here '../../src-tauri/close-desktop.ps1')).Path
$work = Join-Path $env:TEMP ('calabi-upgrade-process-test-' + [guid]::NewGuid().ToString('N'))
$victims = @()
$previousWork = $env:GOWORK
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $env:GOWORK = 'off'
    $fake = Join-Path $work 'stand-in.exe'
    & pwsh -NoProfile -File (Join-Path $here '../../../../scripts/dev/build.ps1') go build -o $fake (Join-Path $here 'fakedaemon/main.go')
    if ($LASTEXITCODE -ne 0) { throw 'Stand-in build failed.' }
    $install = Join-Path $work 'install'
    $other = Join-Path $work 'other'
    foreach ($directory in @($install, $other)) {
        New-Item -ItemType Directory -Path $directory | Out-Null
        foreach ($name in @('calabi.exe','calabi-desktop.exe')) { Copy-Item -LiteralPath $fake -Destination (Join-Path $directory $name) }
    }
    $desktop = Start-Process -FilePath (Join-Path $install 'calabi-desktop.exe') -ArgumentList 'desktop-idle' -WindowStyle Hidden -PassThru
    $victims += $desktop
    $agent = Start-Process -FilePath (Join-Path $install 'calabi.exe') -ArgumentList 'mesh files --stdio' -WindowStyle Hidden -PassThru
    $victims += $agent
    $broker = Start-Process -FilePath (Join-Path $install 'calabi.exe') -ArgumentList 'mesh files --background' -WindowStyle Hidden -PassThru
    $victims += $broker
    $daemon = Start-Process -FilePath (Join-Path $install 'calabi.exe') -ArgumentList 'daemon-idle' -WindowStyle Hidden -PassThru
    $victims += $daemon
    $otherDesktop = Start-Process -FilePath (Join-Path $other 'calabi-desktop.exe') -ArgumentList 'desktop-idle' -WindowStyle Hidden -PassThru
    $victims += $otherDesktop
    $otherAgent = Start-Process -FilePath (Join-Path $other 'calabi.exe') -ArgumentList 'mesh files --stdio' -WindowStyle Hidden -PassThru
    $victims += $otherAgent
    $helpers = @()
    foreach ($directory in @($install, $other)) {
        New-Item -ItemType Directory -Path (Join-Path $directory 'rdp') | Out-Null
        foreach ($name in @('calabi-paste.exe','calabi-rdp.exe')) {
            $path = Join-Path $directory "rdp/$name"
            Copy-Item -LiteralPath $fake -Destination $path
            $child = Start-Process -FilePath $path -ArgumentList 'desktop-idle' -WindowStyle Hidden -PassThru
            $victims += $child
            if ($directory -eq $install) { $helpers += $child }
        }
    }
    Start-Sleep -Milliseconds 400
    if (@($victims | Where-Object HasExited).Count) { throw 'A stand-in did not stay running.' }
    $shell = "$env:WINDIR/SysWOW64/WindowsPowerShell/v1.0/powershell.exe"
    if (-not (Test-Path -LiteralPath $shell)) { $shell = "$env:WINDIR/System32/WindowsPowerShell/v1.0/powershell.exe" }
    & $shell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script -InstallDir $install
    if ($LASTEXITCODE -ne 0) { throw 'Upgrade process cleanup failed.' }
    if (-not $desktop.WaitForExit(2000) -or -not $agent.WaitForExit(2000) -or -not $broker.WaitForExit(2000)) { throw 'Desktop/file agent still running.' }
    if ($daemon.HasExited -or $otherDesktop.HasExited -or $otherAgent.HasExited) { throw 'Killed a daemon or another installation.' }
    foreach ($child in $helpers) { if (-not $child.WaitForExit(2000)) { throw 'Remote helper still running.' } }
    foreach ($child in $victims | Where-Object { $_.Id -notin @($desktop.Id,$agent.Id,$broker.Id) -and $_.Id -notin $helpers.Id }) {
        if ($child.HasExited) { throw 'Stopped an unrelated process.' }
    }
    # The fake daemon is intentionally left alive by process cleanup; stop only
    # our test instance before the independent write-access check.
    Stop-Process -InputObject $daemon -Force; $daemon.WaitForExit()
    . $script -InstallDir $install
    $lockedPath = Join-Path $install 'rdp/locked.dll'
    [IO.File]::WriteAllText($lockedPath,'keep these bytes')
    $before = (Get-FileHash $lockedPath).Hash
    $lock = [IO.File]::Open($lockedPath,'Open','Read','None')
    try {
        $failed = $false
        try { Wait-CalabiUpgradeFiles $install 0 } catch { $failed = $_.Exception.Message.Contains('locked.dll') }
        if (-not $failed) { throw 'Did not reject locked DLL with its file name.' }
    } finally { $lock.Dispose() }
    $ready = Join-Path $work 'lock-ready'
    $job = Start-Job -ArgumentList $lockedPath,$ready -ScriptBlock {
        param($path,$ready)
        $handle = [IO.File]::Open($path,'Open','Read','None')
        try { [IO.File]::WriteAllText($ready,'ready'); Start-Sleep -Seconds 2 } finally { $handle.Dispose() }
    }
    try {
        $deadline = [DateTime]::UtcNow.AddSeconds(15)
        while (-not (Test-Path $ready)) { if ([DateTime]::UtcNow -gt $deadline) { throw 'Lock fixture not ready' }; Start-Sleep -Milliseconds 50 }
        Wait-CalabiUpgradeFiles $install 5
        Wait-Job $job | Out-Null; Receive-Job $job -ErrorAction Stop
    } finally { Stop-Job $job -ErrorAction SilentlyContinue; Remove-Job $job -Force }
    if ((Get-FileHash $lockedPath).Hash -ne $before) { throw 'Write probe changed file content.' }
    Write-Output 'PASS: file lock timeout reports DLL; delayed release retries successfully; content unchanged.'
    Write-Output 'PASS: current desktop, stdio relay and background agent stopped; daemon and other installation untouched.'
} finally {
    $env:GOWORK = $previousWork
    foreach ($process in $victims) {
        if (-not $process.HasExited) { Stop-Process -InputObject $process -Force; $process.WaitForExit() }
        $process.Dispose()
    }
    $absoluteWork = [IO.Path]::GetFullPath($work)
    if ((Split-Path -Parent $absoluteWork) -ne [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') -or (Split-Path -Leaf $absoluteWork) -notmatch '^calabi-upgrade-process-test-[a-f0-9]{32}$') { throw 'Unexpected process-test path.' }
    Remove-Item -LiteralPath $absoluteWork -Recurse -Force
}
