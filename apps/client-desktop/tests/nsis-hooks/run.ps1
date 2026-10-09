# Regression tests for NSIS_HOOK_PREINSTALL and NSIS_HOOK_POSTINSTALL
# (apps/client-desktop/src-tauri/nsis-hooks.nsh).
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File apps\client-desktop\tests\nsis-hooks\run.ps1
#
# WHY THIS EXISTS. Until 1.11.1 the Windows desktop self-update ran `setup.exe /S`
# over a running service. NSIS cannot write a running exe, and in /S mode it does
# not fail on that — it skips the file, exits 0, and records the new version in
# Apps & features. Every update "succeeded" and replaced nothing. Nothing in the
# build, the installer's exit code, or the registry could show it; only the file.
# So these tests assert on the FILE (its hash), never on an exit code.
#
# SAFE TO RUN ANYWHERE. Nothing real is touched: $INSTDIR is a temp directory, the
# "service" key lives under HKCU\Software\CalabiNsisHookTest, and the service
# name handed to `sc stop/start` does not exist. The "running service" is a copy
# of PING.EXE.
#
# POSTINSTALL (step 3) is here for a different silent failure. The hook ran
# `daemon install --system`, ignored what came back, and let the installer finish:
# when the daemon refused to register the service, the install still "completed"
# and the app then started with no daemon to find. Those scenarios assert on what
# is REGISTERED and on the installer's exit code — the two things a person or a
# script launching the installer can actually see.
#
# Needs makensis — `cargo tauri build` puts it under %LOCALAPPDATA%\tauri\NSIS —
# and, for step 3, `go` (it builds the stand-in daemon in .\fakedaemon).
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$hooks = (Resolve-Path (Join-Path $here '..\..\src-tauri\nsis-hooks.nsh')).Path
$harness = Join-Path $here 'harness.nsi'
$makensis = @(
    (Join-Path $env:LOCALAPPDATA 'tauri\NSIS\Bin\makensis.exe'),
    (Join-Path $env:LOCALAPPDATA 'tauri\NSIS\makensis.exe')
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $makensis) { throw "makensis not found under %LOCALAPPDATA%\tauri\NSIS — run cargo tauri build once." }

$work = Join-Path $env:TEMP 'calabi-nsis-hooks-test'
$regParent = 'HKCU:\Software\CalabiNsisHookTest'
$regKey = "$regParent\svc"
$svcName = 'calabi-nsis-hook-test-does-not-exist'

if (Test-Path $work) { [System.IO.Directory]::Delete($work, $true) }
New-Item -ItemType Directory -Force -Path $work | Out-Null
$oldExe = Join-Path $work 'old.exe'           # the "installed daemon": can be run
$newExe = Join-Path $work 'replacement.exe'   # what the installer lays down
Copy-Item "$env:WINDIR\System32\PING.EXE" $oldExe
Copy-Item "$env:WINDIR\System32\whoami.exe" $newExe
$oldHash = (Get-FileHash $oldExe).Hash
$newHash = (Get-FileHash $newExe).Hash

# Two install dirs: Program Files has a space, so its ImagePath is QUOTED; a
# scoop-style path usually has none, so its ImagePath is NOT. Both must be read.
$dirSpace = Join-Path $work 'Calabi Test'
$dirPlain = Join-Path $work 'CalabiTest'

function Build($name, $instdir, $tries, $replacement = $newExe, [switch]$Post) {
    $out = Join-Path $work "$name.exe"
    $args = @(
        '/V2',
        "/DHOOKS=$hooks",
        "/DTEST_OUT=$out",
        "/DTEST_INSTDIR=$instdir",
        "/DTEST_REPLACEMENT=$replacement",
        '/DCALABI_SVC_ROOT=HKCU',
        '/DCALABI_SVC_KEY=Software\CalabiNsisHookTest\svc',
        "/DCALABI_SVC_NAME=$svcName",
        "/DCALABI_UNLOCK_TRIES=$tries"
    )
    if ($Post) { $args += '/DTEST_POST=1' }
    $args += $harness
    & $makensis @args | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $out)) { throw "makensis failed for $name" }
    return $out
}

$instSpace = Build 'inst-space' $dirSpace 20   # 10s to release the file
$instPlain = Build 'inst-plain' $dirPlain 20
$instShort = Build 'inst-short' $dirSpace 4    # 2s, for the give-up case

# Step 3's stand-in for calabi.exe: it answers `daemon install` / `daemon start`
# the way each scenario asks (see fakedaemon\main.go). GOWORK=off because this
# one file lives outside every module the repo's go.work lists.
$fakeExe = Join-Path $work 'fakedaemon.exe'
$dirPost = Join-Path $work 'Calabi Post'
$fakeLog = Join-Path $work 'fake-calls.log'
$fakeKey = 'HKCU\Software\CalabiNsisHookTest\svc'
if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw "go not found - step 3 builds its stand-in daemon with it." }
$prevWork = $env:GOWORK
$env:GOWORK = 'off'
try {
    & go build -o $fakeExe (Join-Path $here 'fakedaemon\main.go')
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $fakeExe)) { throw "go build of the stand-in daemon failed" }
} finally {
    $env:GOWORK = $prevWork
}
$instPost = Build 'inst-post' $dirPost 4 $fakeExe -Post

function Set-ImagePath($value) {
    if (Test-Path $regParent) { Remove-Item $regParent -Recurse -Force }
    if ($null -ne $value) {
        New-Item -Path $regKey -Force | Out-Null
        Set-ItemProperty -Path $regKey -Name 'ImagePath' -Value $value
    }
}

$failures = 0
function Scenario {
    param($name, $installer, $instdir, $imagePath, [int]$runVictimSeconds, [bool]$expectInstall, [double]$minSeconds = 0)

    if (Test-Path $instdir) { [System.IO.Directory]::Delete($instdir, $true) }
    New-Item -ItemType Directory -Force -Path $instdir | Out-Null
    $target = Join-Path $instdir 'calabi.exe'
    Copy-Item $oldExe $target
    Set-ImagePath $imagePath

    $victim = $null
    if ($runVictimSeconds -gt 0) {
        # ping -n N sends N echoes a second apart, so it holds its image ~N-1 s.
        $victim = Start-Process -FilePath $target -ArgumentList '-n', "$runVictimSeconds", '127.0.0.1' -WindowStyle Hidden -PassThru
        Start-Sleep -Milliseconds 500
    }

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process -FilePath $installer -ArgumentList '/S' -Wait -PassThru
    $sw.Stop()
    if ($victim -and -not $victim.HasExited) { Stop-Process -Id $victim.Id -Force; Start-Sleep -Milliseconds 300 }

    $hash = (Get-FileHash $target).Hash
    $afterHook = Test-Path (Join-Path $instdir 'after-hook.txt')
    $skipped = Test-Path (Join-Path $instdir 'file-error.txt')
    $replaced = ($hash -eq $newHash)
    $untouched = ($hash -eq $oldHash)

    $problems = @()
    if ($expectInstall) {
        if (-not $afterHook) { $problems += 'hook aborted' }
        if ($skipped) { $problems += 'File skipped calabi.exe (the silent failure)' }
        if (-not $replaced) { $problems += 'calabi.exe was NOT replaced' }
        if ($sw.Elapsed.TotalSeconds -lt $minSeconds) { $problems += ("finished in {0:N1}s — did not wait for the lock" -f $sw.Elapsed.TotalSeconds) }
    } else {
        if ($afterHook) { $problems += 'hook did NOT abort' }
        if (-not $untouched) { $problems += 'calabi.exe was modified' }
    }

    $verdict = if ($problems.Count -eq 0) { 'PASS' } else { 'FAIL' }
    if ($problems.Count -gt 0) { $script:failures++ }
    "{0}  {1,-52} {2,5:N1}s  exit={3}  {4}" -f $verdict, $name, $sw.Elapsed.TotalSeconds, $p.ExitCode, ($problems -join '; ')
}

# PostScenario runs the installer with POSTINSTALL enabled against the stand-in
# daemon and checks the three things that matter afterwards: is the "service"
# registered, did the installer say so truthfully (exit code), and what did the
# hook actually run.
function PostScenario {
    param($name, $installMode, $startMode, [bool]$preRegistered, [bool]$expectOk, $expectInErrorLog = '')

    if (Test-Path $dirPost) { [System.IO.Directory]::Delete($dirPost, $true) }
    New-Item -ItemType Directory -Force -Path $dirPost | Out-Null
    if (Test-Path $fakeLog) { Remove-Item $fakeLog -Force }
    # An upgrade finds the service already there, pointing at this install.
    if ($preRegistered) { Set-ImagePath "`"$dirPost\calabi.exe`" daemon" } else { Set-ImagePath $null }

    $env:CALABI_FAKE_INSTALL = $installMode
    $env:CALABI_FAKE_START = $startMode
    $env:CALABI_FAKE_REGKEY = $fakeKey
    $env:CALABI_FAKE_LOG = $fakeLog

    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process -FilePath $instPost -ArgumentList '/S' -Wait -PassThru
    $sw.Stop()

    $afterPost = Test-Path (Join-Path $dirPost 'after-post.txt')
    $registered = [bool](Get-ItemProperty -Path $regKey -Name 'ImagePath' -ErrorAction SilentlyContinue)
    $calls = @()
    if (Test-Path $fakeLog) { $calls = @(Get-Content $fakeLog) }
    $errLogPath = Join-Path $dirPost 'service-install-error.log'
    $errLog = ''
    if (Test-Path $errLogPath) { $errLog = [System.IO.File]::ReadAllText($errLogPath) }

    $problems = @()
    # Always: the hook must state its intent. Without --platform a command-line
    # mode the user saved long ago decides whether a desktop install works.
    if ($calls.Count -lt 1 -or $calls[0] -ne 'daemon install --system --platform') {
        $problems += "first command was '$($calls[0])', want 'daemon install --system --platform'"
    }
    if ($expectOk) {
        if (-not $afterPost) { $problems += 'hook aborted' }
        if ($p.ExitCode -ne 0) { $problems += "installer exited $($p.ExitCode)" }
        if (-not $registered) { $problems += 'service is NOT registered' }
        if ($calls.Count -ne 2 -or $calls[1] -ne 'daemon start') { $problems += "ran [$($calls -join ' | ')], want install then start" }
        if ($errLog) { $problems += 'left a service-install-error.log behind' }
    } else {
        if ($afterPost) { $problems += 'hook did NOT abort' }
        # The whole point: an installer that could not set the service up must
        # not report success.
        if ($p.ExitCode -eq 0) { $problems += 'installer exited 0 (reported success)' }
        if (-not $errLog) { $problems += 'no service-install-error.log - a silent run leaves no reason anywhere' }
        elseif ($expectInErrorLog -and $errLog -notlike "*$expectInErrorLog*") { $problems += "error log does not carry the daemon's reason ('$expectInErrorLog')" }
        if ($installMode -eq 'refuse' -and ($calls -contains 'daemon start')) { $problems += 'tried to START a service that was never registered' }
    }

    $verdict = if ($problems.Count -eq 0) { 'PASS' } else { 'FAIL' }
    if ($problems.Count -gt 0) { $script:failures++ }
    "{0}  {1,-52} {2,5:N1}s  exit={3}  {4}" -f $verdict, $name, $sw.Elapsed.TotalSeconds, $p.ExitCode, ($problems -join '; ')
}

try {
    ''
    '--- step 1: whose service is it ---'
    Scenario 'fresh machine, no service'                     $instSpace $dirSpace $null 0 $true
    Scenario 'ours, quoted (path with a space)'              $instSpace $dirSpace "`"$dirSpace\calabi.exe`" daemon" 0 $true
    Scenario 'ours, unquoted (path without a space)'         $instPlain $dirPlain "$dirPlain\calabi.exe daemon" 0 $true
    Scenario 'ours, different letter case'                   $instSpace $dirSpace "`"$($dirSpace.ToUpper())\CALABI.EXE`" daemon" 0 $true
    Scenario 'foreign: scoop, unquoted'                      $instSpace $dirSpace 'C:\Users\ada\scoop\apps\calabi\current\calabi.exe daemon' 0 $false
    Scenario 'foreign: hand-extracted zip, quoted'           $instSpace $dirSpace '"C:\Program Files (x86)\tools\calabi.exe" daemon' 0 $false
    Scenario 'foreign: our path as a PREFIX (calabi.exe.old)' $instSpace $dirSpace "`"$dirSpace\calabi.exe.old`" daemon" 0 $false

    ''
    '--- step 2: the running image ---'
    # ping -n 4 releases after ~3s: the hook must WAIT for it, then replace.
    Scenario 'ours, running, releases after ~3s'             $instSpace $dirSpace "`"$dirSpace\calabi.exe`" daemon" 4 $true 2.0
    # Never releases within 2s: must abort, not "succeed" by skipping the file.
    Scenario 'ours, running, never releases (gives up)'      $instShort $dirSpace "`"$dirSpace\calabi.exe`" daemon" 30 $false

    ''
    '--- step 3: registering the service ---'
    PostScenario 'fresh install: registered and started'           'ok'     'ok'   $false $true
    # install fails with "already exists" on every upgrade; that is not a failure.
    PostScenario 'upgrade: already registered, install says so'    'exists' 'ok'   $true  $true
    # The field failure: refused, nothing registered, and the installer said "Completed".
    PostScenario 'install refused: nothing registered'             'refuse' 'ok'   $false $false 'standalone mode'
    PostScenario 'registered, but the service will not start'      'ok'     'fail' $false $false 'did not respond'
}
finally {
    Set-ImagePath $null
    foreach ($v in 'CALABI_FAKE_INSTALL', 'CALABI_FAKE_START', 'CALABI_FAKE_REGKEY', 'CALABI_FAKE_LOG') {
        Remove-Item "Env:$v" -ErrorAction SilentlyContinue
    }
}

''
if ($failures -gt 0) { "$failures scenario(s) FAILED"; exit 1 }
'all scenarios passed'
