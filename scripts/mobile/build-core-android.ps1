<#
.SYNOPSIS
  Builds the Go mobile core (apps/client/mobile) into the Android library the
  app links: apps/client-android/app/libs/calabicore.aar.

.DESCRIPTION
  gomobile bind needs golang.org/x/mobile in the module graph, and adding it to
  apps/client/go.mod would raise the desktop client's Go version and shared
  dependencies (x/crypto, x/sys, ...) with it. So the bind runs in a throwaway
  module generated here: it requires apps/client through a replace, plus
  x/mobile, and apps/client's own go.mod is never touched.

  Toolchain (see docs/runbook/mobile-client-plan.md M1):
    - Android SDK + NDK: ANDROID_HOME (default D:\Android\Sdk), newest NDK under it
    - gomobile + gobind: go install golang.org/x/mobile/cmd/gomobile@<version>

  Edge CA: like scripts/build-desktop.ps1, a build without -EdgeCa embeds the
  committed DEV edge CA and can only reach a development control plane. Pass
  the deployment's public ca.crt for a build that talks to production.

.EXAMPLE
  scripts\mobile\build-core-android.ps1
.EXAMPLE
  $env:EDGE_CA='deploy\compose\data\edge-certs\ca.crt'; scripts\mobile\build-core-android.ps1
#>
param(
    [string]$EdgeCa = $env:EDGE_CA,
    [string]$Targets = "android/arm64,android/arm",
    [string]$AndroidHome = $(if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { "D:\Android\Sdk" })
)
$ErrorActionPreference = 'Stop'

# Runs a native command and returns its exit code. Windows PowerShell 5.1 turns
# anything a native command writes to stderr into a terminating error under
# 'Stop' - and go prints its progress ("go: downloading ...") there.
function Invoke-Native([string]$exe, [string[]]$argv) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $exe @argv 2>&1 | ForEach-Object { Write-Host "$_" }
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $prev
    }
}

$root = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$client = Join-Path $root "apps\client"
$outDir = Join-Path $root "apps\client-android\app\libs"
$out = Join-Path $outDir "calabicore.aar"

# --- toolchain ---------------------------------------------------------------
if (-not (Test-Path $AndroidHome)) { throw "Android SDK not found at $AndroidHome (set ANDROID_HOME)" }
$ndk = Get-ChildItem (Join-Path $AndroidHome "ndk") -Directory -ErrorAction SilentlyContinue |
    Sort-Object { [version]$_.Name } | Select-Object -Last 1
if (-not $ndk) { throw "no NDK under $AndroidHome\ndk (sdkmanager 'ndk;27.3.13750724')" }
$gobin = Join-Path (& go env GOPATH) "bin"
$gomobile = Join-Path $gobin "gomobile.exe"
if (-not (Test-Path $gomobile)) { throw "gomobile not found in $gobin (go install golang.org/x/mobile/cmd/gomobile@latest; also gobind)" }
# The x/mobile the bind links must be the one gomobile was built from.
$mobileVersion = (& go version -m $gomobile | Select-String -Pattern '^\s+mod\s+golang.org/x/mobile\s+(\S+)').Matches[0].Groups[1].Value
if (-not $mobileVersion) { throw "cannot tell which golang.org/x/mobile $gomobile was built from" }

# --- edge CA -------------------------------------------------------------------
$embedCa = Join-Path $client "internal\transport\certs\edge-ca.pem"
$caBackup = $null
if ($EdgeCa) {
    if (-not (Test-Path $EdgeCa)) { throw "EDGE_CA not found: $EdgeCa" }
    $caText = Get-Content $EdgeCa -Raw
    if ($caText -notmatch "BEGIN CERTIFICATE") { throw "EDGE_CA is not a PEM certificate: $EdgeCa" }
    if ($caText -match "PRIVATE KEY") { throw "refusing: EDGE_CA contains a PRIVATE KEY - pass the public ca.crt only" }
    if ((Get-Content $embedCa -Raw) -eq $caText) { throw "refusing: EDGE_CA is byte-identical to the committed DEV CA" }
    $caBackup = [System.IO.File]::ReadAllBytes($embedCa)
    Copy-Item -Force $EdgeCa $embedCa
    Write-Host "embedding edge CA: $EdgeCa"
} else {
    Write-Warning "no -EdgeCa / `$env:EDGE_CA - embedding the DEV edge CA. This core can only reach a development control plane."
}

# --- throwaway bind module -----------------------------------------------------
# The core's bytes depend on where the source tree sits: gomobile writes its own
# module whose replace directives are the ABSOLUTE directories of these modules
# (x/mobile cmd/gomobile/bind.go parseModuleVersions), and Go records them in the
# library's build info, which -trimpath does not touch. Same path, same bytes;
# another checkout directory, a different libgojni.so (measured 2026-09-17).
# Relative paths here do not help - gomobile resolves them. A reproducible
# Android build needs a fixed build path (docs/runbook/release-mac-and-android.md).
$work = Join-Path $env:TEMP "calabi-mobile-bind"
if (Test-Path $work) { Remove-Item -Recurse -Force $work }
New-Item -ItemType Directory -Force $work | Out-Null

function Abs([string]$rel) { ((Resolve-Path (Join-Path $client $rel)).Path -replace '\\', '/') }
$replaces = @("replace github.com/calabi/calabi/apps/client => `"$($client -replace '\\','/')`"")
# apps/client's own replaces point at sibling modules by relative path; in this
# module they have to be absolute.
foreach ($line in Get-Content (Join-Path $client "go.mod")) {
    # One-line replaces and the entries of a replace ( ... ) block alike.
    if ($line -match '^\s*(?:replace\s+)?(\S+)\s+=>\s+(\.\.?/\S+)\s*$') {
        $replaces += "replace $($Matches[1]) => `"$(Abs $Matches[2])`""
    }
}
$utf8 = New-Object System.Text.UTF8Encoding $false
[System.IO.File]::WriteAllText((Join-Path $work "go.mod"), @"
module calabi.local/mobilebind

go 1.25.0

require (
	github.com/calabi/calabi/apps/client v0.0.0
	golang.org/x/mobile $mobileVersion
)

$($replaces -join "`n")
"@, $utf8)
[System.IO.File]::WriteAllText((Join-Path $work "tools.go"), @"
//go:build tools

package tools

import (
	_ "github.com/calabi/calabi/apps/client/mobile"
	_ "golang.org/x/mobile/bind"
)
"@, $utf8)

New-Item -ItemType Directory -Force $outDir | Out-Null
$env:ANDROID_HOME = $AndroidHome
$env:ANDROID_NDK_HOME = $ndk.FullName
$env:GOWORK = "off"
$env:GOFLAGS = ""
# gomobile copies Go doc comments into the generated Java; javac otherwise reads
# them in the system code page (GBK on a Chinese Windows) and fails on the first
# non-ASCII character.
$env:JAVA_TOOL_OPTIONS = "-Dfile.encoding=UTF-8"
$env:PATH = "$gobin;$env:PATH"

Push-Location $work
try {
    Write-Host "resolving modules (x/mobile $mobileVersion)..."
    if ((Invoke-Native "go" @("mod", "tidy")) -ne 0) { throw "go mod tidy failed in $work" }
    Write-Host "gomobile bind -target=$Targets (NDK $($ndk.Name))..."
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $bind = @("bind", "-target=$Targets", "-androidapi", "26", "-javapkg=net.calabi.core", "-trimpath", "-ldflags=-s -w",
        "-o", $out, "github.com/calabi/calabi/apps/client/mobile")
    if ((Invoke-Native $gomobile $bind) -ne 0) { throw "gomobile bind failed" }
    Write-Host ("built {0} ({1:N1} MB) in {2:N0}s" -f $out, ((Get-Item $out).Length / 1MB), $sw.Elapsed.TotalSeconds)
} finally {
    Pop-Location
    if ($caBackup) { [System.IO.File]::WriteAllBytes($embedCa, $caBackup) }
}
