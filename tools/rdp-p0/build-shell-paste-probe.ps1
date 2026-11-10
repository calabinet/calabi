[CmdletBinding()]
param([switch]$Bridge)
$ErrorActionPreference='Stop'
$root=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
. (Join-Path $root 'scripts/dev/build-cache.ps1')
if (-not (Test-CalabiBuildLease)) {
    & (Join-Path $root 'scripts/dev/build.ps1') __script $PSCommandPath $PSBoundParameters
    exit $LASTEXITCODE
}
$out=Join-Path $root 'bin/rdp-shell-paste-probe'
New-Item -ItemType Directory -Force $out | Out-Null
$exe=Join-Path $out $(if($Bridge){'calabi-paste.exe'}else{'calabi-shell-paste-probe.exe'})
& g++ -std=c++17 -O2 -Wall -Wextra -Wno-misleading-indentation -static -municode -mwindows (Join-Path $PSScriptRoot 'shell-paste-probe.cpp') -o $exe -lole32 -lshell32 -luuid -luser32 -lgdi32
if($LASTEXITCODE -ne 0){throw 'Shell paste probe compilation failed'}
& $exe --self-test
if($LASTEXITCODE -ne 0){throw 'Shell paste contract self-test failed'}
Get-FileHash $exe -Algorithm SHA256
Write-Output "Built standalone experiment: $exe. Not installed or launched interactively."
