<#
.SYNOPSIS
  Builds the release APK, checks it, and stages it as dist\release\calabi-android.apk.

.DESCRIPTION
  docs/runbook/release-mac-and-android.md. In order:

    1. the Go core for both ABIs (build-core-android.ps1) with the production edge CA
    2. gradle assembleRelease, signed with the release keystore
    3. checks on the APK itself - not on what the build was asked to do:
         - signed by the pinned release certificate, not a debug key
         - versionName is VERSION
         - each ABI's libgojni.so carries the production edge CA and not the DEV one
         - the app's control plane is https://api.calabi.net
    4. copies it to the release directory and records it in SHA256SUMS

  A build without -EdgeCa is refused: build-core-android.ps1 alone only warns and
  embeds the DEV CA, and an installer carrying a DEV core looks exactly like a
  good one (docs/runbook/release-pitfalls-and-verification.md 1).

  The keystore passwords are read from CALABI_ANDROID_KEYSTORE_PASSWORD (and
  CALABI_ANDROID_KEY_PASSWORD when the key has its own), or prompted for. They
  are handed to Gradle through this process's environment and removed after.

.PARAMETER Tree
  The source tree to build. The official release builds the public export
  (dist\public-export, after release-official.sh), like the other clients.

.PARAMETER CertSha256
  The release certificate's SHA-256, overriding scripts\mobile\android-release-cert.sha256.

.EXAMPLE
  scripts\mobile\build-release-android.ps1 -EdgeCa deploy\compose\data\edge-certs\ca.crt -Tree dist\public-export -Gradle D:\gradle\gradle-8.11.1\bin\gradle.bat
#>
param(
    [string]$EdgeCa = $env:EDGE_CA,
    [string]$Tree = "",
    [string]$Keystore = $(if ($env:CALABI_ANDROID_KEYSTORE) { $env:CALABI_ANDROID_KEYSTORE } else { ".secrets\calabi-android-release.jks" }),
    [string]$KeyAlias = "calabi",
    [string]$CertSha256 = "",
    [string]$OutDir = "dist\release",
    [string]$Gradle = $env:GRADLE,
    [switch]$Online,
    [string]$AndroidHome = $(if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { "D:\Android\Sdk" })
)
$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
function FromRepo([string]$p) { if ([IO.Path]::IsPathRooted($p)) { $p } else { Join-Path $repo $p } }

# --- inputs ---------------------------------------------------------------------
if (-not $EdgeCa) { throw "-EdgeCa is required: a release APK without the production edge CA can only reach a development control plane" }
$EdgeCa = (Resolve-Path (FromRepo $EdgeCa)).Path
$Tree = if ($Tree) { (Resolve-Path (FromRepo $Tree)).Path } else { $repo }
$Keystore = FromRepo $Keystore
if (-not (Test-Path $Keystore)) { throw "release keystore not found: $Keystore (docs/runbook/release-mac-and-android.md A1)" }
$OutDir = FromRepo $OutDir
# From this repository, not the tree: the public export has no VERSION file.
$version = (Get-Content (Join-Path $repo "VERSION") -Raw).Trim()

$pinFile = Join-Path $repo "scripts\mobile\android-release-cert.sha256"
if (-not $CertSha256) {
    if (-not (Test-Path $pinFile)) {
        throw "no pinned release certificate: write its SHA-256 to $pinFile (apksigner verify --print-certs on a signed APK, or keytool -list -v -keystore $Keystore -alias $KeyAlias)"
    }
    $CertSha256 = (Get-Content $pinFile -Raw).Trim()
}
$CertSha256 = ($CertSha256 -replace '[:\s]', '').ToLowerInvariant()

$buildTools = Get-ChildItem (Join-Path $AndroidHome "build-tools") -Directory | Sort-Object { [version]$_.Name } | Select-Object -Last 1
if (-not $buildTools) { throw "no build-tools under $AndroidHome" }
$apksigner = Join-Path $buildTools.FullName "apksigner.bat"
$aapt2 = Join-Path $buildTools.FullName "aapt2.exe"

if (-not $Gradle) {
    $Gradle = if (Get-Command gradle -ErrorAction SilentlyContinue) { "gradle" } else { Join-Path $Tree "apps\client-android\gradlew.bat" }
}

# Runs a native command, echoing its output; returns the exit code. Under 'Stop',
# Windows PowerShell 5.1 would turn stderr progress lines into terminating errors.
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

function Capture-Native([string]$exe, [string[]]$argv) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $exe @argv 2>&1 | ForEach-Object { "$_" }
        if ($LASTEXITCODE -ne 0) { throw "$exe failed (exit $LASTEXITCODE): $($out -join "`n")" }
        return $out
    } finally {
        $ErrorActionPreference = $prev
    }
}

$setPassword = $false
try {
    if (-not $env:CALABI_ANDROID_KEYSTORE_PASSWORD) {
        $secure = Read-Host -AsSecureString "Password for $Keystore"
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
        try { $env:CALABI_ANDROID_KEYSTORE_PASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
        finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
        $setPassword = $true
    }
    $env:CALABI_ANDROID_KEYSTORE = $Keystore
    $env:CALABI_ANDROID_KEY_ALIAS = $KeyAlias
    $env:JAVA_TOOL_OPTIONS = "-Dfile.encoding=UTF-8"

    # --- 1. Go core ------------------------------------------------------------------
    Write-Host "==> Go core ($version) from $Tree"
    & (Join-Path $Tree "scripts\mobile\build-core-android.ps1") -EdgeCa $EdgeCa -Targets "android/arm64,android/arm" -AndroidHome $AndroidHome

    # --- 2. APK ----------------------------------------------------------------------
    Write-Host "==> gradle assembleRelease"
    $project = Join-Path $Tree "apps\client-android"
    $apkDir = Join-Path $project "app\build\outputs\apk\release"
    if (Test-Path $apkDir) { Remove-Item -Recurse -Force $apkDir }
    $gradleArgs = @("-p", $project, "-PcalabiVersion=$version", "assembleRelease")
    if (-not $Online) { $gradleArgs = @("--offline") + $gradleArgs }
    if ((Invoke-Native $Gradle $gradleArgs) -ne 0) { throw "gradle assembleRelease failed" }
    $apk = Join-Path $apkDir "app-release.apk"
    if (-not (Test-Path $apk)) {
        throw "no signed app-release.apk in $apkDir - Gradle did not pick up the signing config"
    }
} finally {
    if ($setPassword) { Remove-Item Env:\CALABI_ANDROID_KEYSTORE_PASSWORD -ErrorAction SilentlyContinue }
    Remove-Item Env:\CALABI_ANDROID_KEYSTORE, Env:\CALABI_ANDROID_KEY_ALIAS -ErrorAction SilentlyContinue
}

# --- 3. checks on the result ------------------------------------------------------
Write-Host "==> checking $apk"
$failures = @()

$certs = Capture-Native $apksigner @("verify", "--print-certs", $apk)
$digests = @($certs | Where-Object { $_ -match 'certificate SHA-256 digest:\s*([0-9a-fA-F]+)' } | ForEach-Object { ($_ -replace '.*digest:\s*', '').Trim().ToLowerInvariant() })
if ($digests.Count -ne 1) { $failures += "expected exactly one signer, found $($digests.Count)" }
elseif ($digests[0] -ne $CertSha256) { $failures += "signed by $($digests[0]), not the release certificate $CertSha256" }
if ($certs -match 'CN=Android Debug') { $failures += "signed with a DEBUG key" }

$badging = Capture-Native $aapt2 @("dump", "badging", $apk)
$pkgLine = @($badging | Where-Object { $_ -like "package:*" })[0]
if ($pkgLine -notmatch "versionName='([^']*)'") { $failures += "no versionName in: $pkgLine" }
elseif ($Matches[1] -ne $version) { $failures += "versionName is $($Matches[1]), VERSION is $version" }

# The third body line of each CA, as in release-pitfalls-and-verification.md 2:
# a whole PEM line, so the probe cannot straddle a line break.
function CaProbe([string]$path) { @(Get-Content $path | Where-Object { $_ -and $_ -notmatch 'CERTIFICATE' })[2].Trim() }
$prodProbe = CaProbe $EdgeCa
$devCa = Join-Path $repo "deploy\dev\certs\ca.crt"
$devProbe = if (Test-Path $devCa) { CaProbe $devCa } else { $null }
if (-not $devProbe) { Write-Warning "no $devCa - cannot check the DEV CA is absent" }

$latin1 = [Text.Encoding]::GetEncoding(28591)
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::OpenRead($apk)
try {
    function EntryText([string]$name) {
        $e = $zip.GetEntry($name)
        if (-not $e) { return $null }
        $ms = New-Object IO.MemoryStream
        $s = $e.Open(); try { $s.CopyTo($ms) } finally { $s.Dispose() }
        return $latin1.GetString($ms.ToArray())
    }
    foreach ($abi in "arm64-v8a", "armeabi-v7a") {
        $so = EntryText "lib/$abi/libgojni.so"
        if ($null -eq $so) { $failures += "missing lib/$abi/libgojni.so"; continue }
        if (-not $so.Contains($prodProbe)) { $failures += "$abi core: production edge CA NOT embedded" }
        if ($devProbe -and $so.Contains($devProbe)) { $failures += "$abi core: DEV edge CA embedded" }
    }
    $dex = ($zip.Entries | Where-Object { $_.FullName -match '^classes\d*\.dex$' } | ForEach-Object { EntryText $_.FullName }) -join ""
    if (-not $dex.Contains("https://api.calabi.net")) { $failures += "the app's control plane is not https://api.calabi.net" }
} finally {
    $zip.Dispose()
}

if ($failures.Count -gt 0) {
    $failures | ForEach-Object { Write-Host "  FAIL  $_" -ForegroundColor Red }
    throw "the APK failed $($failures.Count) check(s); nothing was staged"
}
Write-Host "  OK  signer $CertSha256"
Write-Host "  OK  versionName $version"
Write-Host "  OK  both ABIs: production CA in, DEV CA out"
Write-Host "  OK  control plane https://api.calabi.net"

# --- 4. stage ---------------------------------------------------------------------
$name = "calabi-android.apk"
New-Item -ItemType Directory -Force $OutDir | Out-Null
$dest = Join-Path $OutDir $name
Copy-Item -Force $apk $dest
$hash = (Get-FileHash -Algorithm SHA256 $dest).Hash.ToLowerInvariant()
$sums = Join-Path $OutDir "SHA256SUMS"
$lines = @()
if (Test-Path $sums) { $lines = @([IO.File]::ReadAllLines($sums) | Where-Object { $_ -and $_ -notmatch "\s$([regex]::Escape($name))$" }) }
$lines += "$hash  $name"
# LF, not PowerShell's CRLF: sha256sum -c reads a CR as part of the file name.
[IO.File]::WriteAllText($sums, (($lines -join "`n") + "`n"))

Write-Host
Write-Host "Done: $dest"
Write-Host "  sha256 $hash"
Write-Host "  recorded in $sums - run scripts/sync-packaging.sh once every installer is staged"
