# Runs only a hidden layout fixture; no real installation, services or credentials.
$ErrorActionPreference = 'Stop'
$tauri = (Resolve-Path (Join-Path $PSScriptRoot '../../src-tauri')).Path
$nsis = Join-Path $env:LOCALAPPDATA 'tauri/NSIS'
$work = Join-Path $env:TEMP ('calabi-layout-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $work | Out-Null
try {
    foreach ($page in @('maintenance','welcome','finish')) {
    Write-Output "Checking $page page"
    $exe = Join-Path $work "layout-$page.exe"
    $result = Join-Path $work 'metrics.txt'
    & (Join-Path $nsis 'Bin/makensis.exe') /V2 "/DTEST_PAGE=$page" "/DTEST_OUT=$exe" "/DRESULT_FILE=$result" "/DPLUGIN_DIR=$(Join-Path $nsis 'Plugins/x86-unicode/additional')" "/DHOOKS=$(Join-Path $tauri 'nsis-hooks.nsh')" "/DLANGUAGE_ROOT=$(Join-Path $tauri 'nsis-languages')" (Join-Path $PSScriptRoot 'layout.nsi')
    if ($LASTEXITCODE -ne 0) { throw 'Layout fixture compilation failed.' }
    $process = Start-Process -FilePath $exe -WindowStyle Hidden -PassThru
    if (-not $process.WaitForExit(15000)) { $process.Kill(); throw 'Layout fixture timed out.' }
    if (Test-Path -LiteralPath $result) { [IO.File]::ReadAllText($result, [Text.Encoding]::Unicode) | Write-Output }
    if ($process.ExitCode -ne 0) { throw 'Chinese installer text exceeds its control or font fallback occurred.' }
    }
    Write-Output 'PASS: maintenance, welcome and finish text and control bounds.'
} finally {
    $absoluteWork = [IO.Path]::GetFullPath($work)
    if ((Split-Path -Parent $absoluteWork) -ne [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') -or (Split-Path -Leaf $absoluteWork) -notmatch '^calabi-layout-test-[a-f0-9]{32}$') { throw 'Unexpected layout test path.' }
    Remove-Item -LiteralPath $absoluteWork -Recurse -Force
}
