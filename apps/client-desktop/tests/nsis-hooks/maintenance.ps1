# Isolated installer maintenance-default regression; never runs a real installer.
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$tauri = (Resolve-Path (Join-Path $here '../../src-tauri')).Path
$nsis = Join-Path $env:LOCALAPPDATA 'tauri/NSIS'
$hookText = Get-Content -LiteralPath (Join-Path $tauri 'nsis-hooks.nsh') -Raw
$messageKeys = [regex]::Matches($hookText, '\$\((calabi\w+)\)') | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique
foreach ($language in @('English', 'SimpChinese')) {
    $strings = Get-Content -LiteralPath (Join-Path $tauri "nsis-languages/$language.nsh") -Raw -Encoding utf8
    foreach ($key in $messageKeys) {
        if ($strings -notmatch ('(?m)^LangString ' + [regex]::Escape($key) + '\s')) { throw "Missing installer message: $language/$key" }
    }
}
$work = Join-Path $env:TEMP ('calabi-maintenance-test-' + [guid]::NewGuid().ToString('N'))
$key = 'Software\CalabiNsisMaintenanceTest-' + [guid]::NewGuid().ToString('N')
New-Item -ItemType Directory -Path $work | Out-Null
try {
    $exe = Join-Path $work 'maintenance.exe'
    & (Join-Path $nsis 'Bin/makensis.exe') /V2 "/DTEST_OUT=$exe" "/DTEST_KEY=$key" "/DPLUGIN_DIR=$(Join-Path $nsis 'Plugins/x86-unicode/additional')" "/DHOOKS=$(Join-Path $tauri 'nsis-hooks.nsh')" "/DLANGUAGE_ROOT=$(Join-Path $tauri 'nsis-languages')" (Join-Path $here 'maintenance.nsi')
    if ($LASTEXITCODE -ne 0) { throw 'Maintenance harness compilation failed.' }
    $process = Start-Process -FilePath $exe -WindowStyle Hidden -Wait -PassThru
    if ($process.ExitCode -ne 0) { throw 'Maintenance default or register-preservation assertion failed.' }
    Write-Output 'PASS: fresh/same-version/downgrade retain first choice; older stable/preview defaults to keep-data upgrade; scratch registers preserved.'
} finally {
    $absoluteWork = [IO.Path]::GetFullPath($work)
    if ((Split-Path -Parent $absoluteWork) -ne [IO.Path]::GetFullPath($env:TEMP).TrimEnd('\') -or (Split-Path -Leaf $absoluteWork) -notmatch '^calabi-maintenance-test-[a-f0-9]{32}$') { throw 'Unexpected test directory.' }
    Remove-Item -LiteralPath $absoluteWork -Recurse -Force
    if (Test-Path -LiteralPath "HKCU:\$key") { Remove-Item -LiteralPath "HKCU:\$key" -Recurse -Force }
}
