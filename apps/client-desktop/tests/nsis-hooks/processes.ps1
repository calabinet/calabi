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
    $daemon = Start-Process -FilePath (Join-Path $install 'calabi.exe') -ArgumentList 'daemon-idle' -WindowStyle Hidden -PassThru
    $victims += $daemon
    $otherDesktop = Start-Process -FilePath (Join-Path $other 'calabi-desktop.exe') -ArgumentList 'desktop-idle' -WindowStyle Hidden -PassThru
    $victims += $otherDesktop
    $otherAgent = Start-Process -FilePath (Join-Path $other 'calabi.exe') -ArgumentList 'mesh files --stdio' -WindowStyle Hidden -PassThru
    $victims += $otherAgent
    Start-Sleep -Milliseconds 400
    if (@($victims | Where-Object HasExited).Count) { throw 'A stand-in did not stay running.' }
    $shell = "$env:WINDIR/SysWOW64/WindowsPowerShell/v1.0/powershell.exe"
    if (-not (Test-Path -LiteralPath $shell)) { $shell = "$env:WINDIR/System32/WindowsPowerShell/v1.0/powershell.exe" }
    & $shell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $script -InstallDir $install
    if ($LASTEXITCODE -ne 0) { throw 'Upgrade process cleanup failed.' }
    if (-not $desktop.WaitForExit(2000) -or -not $agent.WaitForExit(2000)) { throw 'Desktop/file agent still running.' }
    if ($daemon.HasExited -or $otherDesktop.HasExited -or $otherAgent.HasExited) { throw 'Killed a daemon or another installation.' }
    Write-Output 'PASS: current desktop and stdio agent stopped; daemon and other installation untouched.'
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
