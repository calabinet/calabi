# Offline regression tests. All deletions are confined to a synthetic cache.
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'build-cache.ps1')
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('calabi-cache-test-'+[Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$paths=[pscustomobject]@{Repo=$testRoot;Base=$testRoot;Go=(Join-Path $testRoot 'build');Rust=(Join-Path $testRoot 'rust');Temp=(Join-Path $testRoot 'tmp');Lock=(Join-Path $testRoot 'lease')}
$policy=@{GoLimitGiB=1.5MB/1GB;RustLimitGiB=6;TempLimitGiB=1;MinimumFreeGiB=12;RecoveryFreeGiB=20;RecentHours=24}
$script:busy=$false;$script:free=100GB
function Get-CalabiBuildProcesses { if($script:busy){[pscustomobject]@{ProcessName='go'}} }
function Get-CalabiFreeBytes([string]$Path) { $script:free }
function Get-CalabiCachePaths { $paths }
function Check([string]$Name,[bool]$OK) {if(-not $OK){throw "FAILED: $Name"};Write-Host "PASS $Name"}
function Entry([string]$Root,[string]$Name,[int]$AgeHours) {
    New-Item -ItemType Directory -Path $Root -Force | Out-Null
    $p=Join-Path $Root $Name;[IO.File]::WriteAllBytes($p,[byte[]]::new(1MB));[IO.File]::SetLastWriteTimeUtc($p,[DateTime]::UtcNow.AddHours(-$AgeHours));return $p
}
$outside=Join-Path $testRoot 'source-and-release';New-Item -ItemType Directory -Path $outside | Out-Null
$sentinel=Join-Path $outside 'keep.exe';Set-Content -LiteralPath $sentinel 'release sentinel'
$savedGo=$env:GOCACHE
try {
    $a=Entry $paths.Go (('a'*64)+'-d') 80
    $b=Entry $paths.Go (('b'*64)+'-d') 48
    $c=Entry $paths.Go (('c'*64)+'-d') 0
    Invoke-CalabiCacheMaintenance $paths $policy
    Check 'old entries evicted to budget, recent entry retained' ((-not(Test-Path $a)) -and (-not(Test-Path $b)) -and (Test-Path $c))
    $d=Entry $paths.Go (('d'*64)+'-d') 0
    Invoke-CalabiCacheMaintenance $paths $policy -WarningAction SilentlyContinue
    Check 'soft limit does not repeatedly delete fresh caches' ((Test-Path $c) -and (Test-Path $d))
    $script:busy=$true;$blocked=$false
    try {Invoke-CalabiCacheMaintenance $paths $policy}catch{$blocked=$true}
    Check 'busy compiler blocks cleanup' ($blocked -and (Test-Path $c))
    $script:busy=$false;$script:free=0;$blocked=$false
    try {Invoke-CalabiCacheMaintenance $paths $policy}catch{$blocked=$true}
    Check 'insufficient free space blocks build even after cleanup' $blocked
    Check 'outside source/release sentinel preserved' ((Get-Content -LiteralPath $sentinel) -eq 'release sentinel')
    $script:free=100GB
    $script:pressureFile=Entry $paths.Temp 'abandoned-build.tmp' 0
    function Get-CalabiFreeBytes([string]$Path) { if(Test-Path -LiteralPath $script:pressureFile){10GB}else{21GB} }
    Invoke-CalabiCacheMaintenance $paths $policy
    Check 'pressure cleanup recovers space before starting build' (-not(Test-Path -LiteralPath $script:pressureFile))
    function Get-CalabiFreeBytes([string]$Path) { $script:free }
    $blocked=$false;try{$null=Assert-CalabiCachePath $outside $paths.Go}catch{$blocked=$true}
    Check 'sibling directory rejected' $blocked
    New-Item -ItemType Directory -Path $paths.Go -Force | Out-Null
    $junction=Join-Path $paths.Go 'linked'
    New-Item -ItemType Junction -Path $junction -Target $outside | Out-Null
    $blocked=$false;try{$null=@(Get-CalabiCacheFiles $paths.Go)}catch{$blocked=$true}
    Check 'junction cache entry rejected' $blocked
    # Delete the junction itself, never its target.
    [IO.Directory]::Delete($junction)
    $r=Entry $paths.Rust 'unmarked.bin' 80
    $blocked=$false;try{Invoke-CalabiCacheMaintenance $paths $policy}catch{$blocked=$true}
    Check 'unmarked Rust directory refused' ($blocked -and (Test-Path $r))
    Set-Content -LiteralPath (Join-Path $paths.Rust '.calabi-cache') 'wrong marker'
    $blocked=$false;try{Invoke-CalabiCacheMaintenance $paths $policy}catch{$blocked=$true}
    Check 'invalid Rust marker refused without deletion' ($blocked -and (Test-Path $r))
    Remove-Item -LiteralPath (Join-Path $paths.Rust '.calabi-cache')
    Remove-Item -LiteralPath $r
    New-Item -ItemType Junction -Path $paths.Lock -Target $outside | Out-Null
    $blocked=$false;try{$unexpected=Enter-CalabiBuild;Exit-CalabiBuild $unexpected}catch{$blocked=$true}
    Check 'linked lease path rejected' $blocked
    [IO.Directory]::Delete($paths.Lock)
    New-Item -ItemType HardLink -Path $paths.Lock -Target $sentinel | Out-Null
    $lease=Enter-CalabiBuild
    $heldToken=$env:CALABI_BUILD_LEASE
    try {
        Check 'owner validates inherited lease' (Test-CalabiBuildLease)
        Check 'unified Go and Rust intermediate paths' ($env:GOCACHE -eq $paths.Go -and $env:CARGO_BUILD_BUILD_DIR -eq $paths.Rust)
        $blocked=$false;try{$second=Enter-CalabiBuild;$second.Handle.Dispose()}catch{$blocked=$true}
        Check 'second guard cannot clean while first lease is held' $blocked
    } finally {Exit-CalabiBuild $lease}
    Check 'existing lock file is never truncated or rewritten' ((Get-Content -LiteralPath $sentinel) -eq 'release sentinel')
    Check 'environment restored after lease exit' ($env:GOCACHE -eq $savedGo)
    $env:CALABI_BUILD_LEASE=$heldToken
    Check 'stale inherited token cannot bypass preflight' (-not(Test-CalabiBuildLease))
    Remove-Item Env:CALABI_BUILD_LEASE
    $lease=Enter-CalabiBuild;Exit-CalabiBuild $lease
    Check 'lease reusable after release' $true
    Check 'source/release still untouched after all cases' ((Get-Content -LiteralPath $sentinel) -eq 'release sentinel')
} finally {
    $resolved=(Resolve-Path -LiteralPath $testRoot).ProviderPath
    if($resolved -ne [IO.Path]::GetFullPath($testRoot) -or -not ([IO.Path]::GetFileName($resolved)).StartsWith('calabi-cache-test-')){throw 'Unexpected test cleanup root'}
    if(Test-Path -LiteralPath (Join-Path $paths.Go 'linked')){[IO.Directory]::Delete((Join-Path $paths.Go 'linked'))}
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
exit 0
