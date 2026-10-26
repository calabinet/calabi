# Shared Windows build lease and cache maintenance. Dot-source; never cleans on import.
function Get-CalabiCachePaths {
    $repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
    $base = Join-Path ([IO.Path]::GetPathRoot($repo)) 'gocache'
    [pscustomobject]@{ Repo=$repo; Base=$base; Go=(Join-Path $base 'build'); Rust=(Join-Path $base 'rust/calabi-desktop'); Temp=(Join-Path $base 'tmp/calabi-build'); Lock=(Join-Path $base '.calabi-build.lock') }
}

function Assert-CalabiCachePath([string]$Path, [string]$Root) {
    $full=[IO.Path]::GetFullPath($Path).TrimEnd('\')
    $allowed=[IO.Path]::GetFullPath($Root).TrimEnd('\')
    if ($full -ne $allowed -and -not $full.StartsWith($allowed+'\',[StringComparison]::OrdinalIgnoreCase)) { throw "Cache path escaped allowlist: $full" }
    # Check every existing ancestor, including the cache root itself.
    $part=$full
    while ($part) {
        if (Test-Path -LiteralPath $part) {
            if ((Get-Item -LiteralPath $part -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Cache path contains a link: $part" }
        }
        $parent=[IO.Path]::GetDirectoryName($part)
        if ($parent -eq $part) { break }; $part=$parent
    }
    return $full
}

function Get-CalabiBuildProcesses {
    # Include unguarded native compilers. Do not stop or kill them.
    @(Get-Process -Name go,compile,link,cargo,rustc,cl,clang,gcc,cc1,msbuild,ninja -ErrorAction SilentlyContinue)
}

function Assert-CalabiBuildIdle {
    $busy=@(Get-CalabiBuildProcesses)
    if ($busy.Count) { throw "Another compiler is running; no cache cleanup/start allowed: $($busy.ProcessName -join ', ')" }
}

function Get-CalabiFreeBytes([string]$Path) {
    ([IO.DriveInfo]::new([IO.Path]::GetPathRoot([IO.Path]::GetFullPath($Path)))).AvailableFreeSpace
}

function Get-CalabiCacheFiles([string]$Root) {
    $null=Assert-CalabiCachePath $Root $Root
    if (-not (Test-Path -LiteralPath $Root)) { return }
    $stack=[Collections.Generic.Stack[string]]::new(); $stack.Push($Root)
    while ($stack.Count) {
        foreach ($item in (Get-ChildItem -LiteralPath $stack.Pop() -Force -ErrorAction Stop)) {
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Linked cache entry refused: $($item.FullName)" }
            if ($item.PSIsContainer) { $stack.Push($item.FullName) } else { $item }
        }
    }
}

function Remove-CalabiCacheFile($File, [string]$Root) {
    Assert-CalabiBuildIdle
    $path=Assert-CalabiCachePath $File.FullName $Root
    Remove-Item -LiteralPath $path -Force -ErrorAction Stop
}

function Invoke-CalabiCacheMaintenance($Paths, $Policy) {
    Assert-CalabiBuildIdle
    $urgent=(Get-CalabiFreeBytes $Paths.Base) -lt ($Policy.MinimumFreeGiB*1GB)
    $recent=[DateTime]::UtcNow.AddHours(-$Policy.RecentHours)
    foreach ($kind in @('Temp','Go','Rust')) {
        $root=$Paths.$kind
        $files=@(Get-CalabiCacheFiles $root)
        # Rust root is exclusively intermediate files via CARGO_BUILD_BUILD_DIR.
        # A marker is mandatory; final target/bundle directories are never managed.
        if ($kind -eq 'Rust' -and $files.Count) {
            $marker=Join-Path $root '.calabi-cache'
            if (-not (Test-Path -LiteralPath $marker -PathType Leaf) -or (Get-Content -LiteralPath $marker -Raw).Trim() -ne 'calabi-intermediate-cache-v1') { throw 'Unmarked or invalid Rust cache; refusing cleanup' }
        }
        $limit=$Policy[($kind+'LimitGiB')]*1GB
        $bytes=[long](($files | Measure-Object Length -Sum).Sum)
        if ($bytes -le $limit -and -not $urgent) { continue }
        $candidates=@($files | Where-Object {
            $_.Name -ne '.calabi-cache' -and
            # Evict compiled data, not thousands of tiny action-index records.
            # Go treats a missing data file as a cache miss and trims metadata.
            ($kind -ne 'Go' -or $_.Name -match '^[0-9a-f]{64}-d$') -and
            ($urgent -or $_.LastWriteTimeUtc -lt $recent)
        } | Sort-Object LastWriteTimeUtc)
        foreach ($file in $candidates) {
            if ($urgent) {
                if ((Get-CalabiFreeBytes $Paths.Base) -ge ($Policy.RecoveryFreeGiB*1GB) -and $bytes -le $limit) { break }
            } elseif ($bytes -le $limit) { break }
            Remove-CalabiCacheFile $file $root
            $bytes-=$file.Length
        }
        if ($bytes -gt $limit) { Write-Warning "$kind cache exceeds soft limit; recent entries retained. It will be checked before the next build." }
        if ($urgent -and (Get-CalabiFreeBytes $Paths.Base) -ge ($Policy.RecoveryFreeGiB*1GB)) { $urgent=$false }
    }
    $free=Get-CalabiFreeBytes $Paths.Base
    if ($free -lt ($Policy.MinimumFreeGiB*1GB)) { throw "Build refused: only $([math]::Round($free/1GB,2)) GiB free; need $($Policy.MinimumFreeGiB) GiB. Source, module cache and release artifacts were not touched." }
    Write-Host "Build cache preflight: $([math]::Round($free/1GB,2)) GiB free; minimum $($Policy.MinimumFreeGiB) GiB."
}

function Test-CalabiBuildLease {
    if ($env:CALABI_BUILD_LEASE -notmatch '^[0-9a-f]{32}$') { return $false }
    $paths=Get-CalabiCachePaths
    try {
        $recordPath=Join-Path $paths.Base ('.calabi-build-'+$env:CALABI_BUILD_LEASE+'.json')
        $null=Assert-CalabiCachePath $paths.Lock $paths.Base
        $null=Assert-CalabiCachePath $recordPath $paths.Base
        $record=Get-Content -LiteralPath $recordPath -Raw -ErrorAction Stop | ConvertFrom-Json
        if ($record.Token -ne $env:CALABI_BUILD_LEASE) { return $false }
        # A surviving child must not reuse a stale token after the owner released
        # the handle (the owning PowerShell process can still be alive).
        try {
            $probe=[IO.File]::Open($paths.Lock,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None)
            $probe.Dispose()
            return $false
        } catch [IO.IOException] {
            if (($_.Exception.HResult -band 0xffff) -ne 32) { return $false }
        }
        # Inherited token is only valid for the owning process or its descendants.
        $current=$PID
        for ($i=0; $i -lt 64 -and $current; $i++) {
            if ($current -eq $record.Owner) { return $true }
            $process=Get-CimInstance Win32_Process -Filter "ProcessId=$current" -ErrorAction Stop
            if (-not $process -or $process.ParentProcessId -eq $current) { break }
            $current=$process.ParentProcessId
        }
    } catch { return $false }
    return $false
}

function Enter-CalabiBuild {
    $paths=Get-CalabiCachePaths
    $policy=Import-PowerShellDataFile (Join-Path $PSScriptRoot 'build-cache-policy.psd1')
    if ($policy.MinimumFreeGiB -le 0 -or $policy.RecoveryFreeGiB -lt $policy.MinimumFreeGiB -or $policy.RecentHours -lt 0) { throw 'Invalid cache policy' }
    foreach ($key in @('GoLimitGiB','RustLimitGiB','TempLimitGiB')) { if ($policy[$key] -le 0) {throw 'Invalid cache limit'} }
    $null=Assert-CalabiCachePath $paths.Base $paths.Base
    New-Item -ItemType Directory -Path $paths.Base -Force | Out-Null
    $null=Assert-CalabiCachePath $paths.Lock $paths.Base
    # Never truncate an existing file. An exclusive READ handle is the lease;
    # owner metadata is created in a fresh unique file, readable by descendants.
    if (-not (Test-Path -LiteralPath $paths.Lock)) {
        try { $created=[IO.File]::Open($paths.Lock,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$created.Dispose() }
        catch [IO.IOException] { if (-not (Test-Path -LiteralPath $paths.Lock)) { throw } }
    }
    try { $lease=[IO.File]::Open($paths.Lock,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::None) }
    catch { throw "Cannot acquire build cache lease at $($paths.Lock). Another guarded build may be running, or the directory may not be writable. $($_.Exception.Message)" }
    $recordHandle=$null;$recordPath=$null;$saved=@{}
    try {
        $token=[Guid]::NewGuid().ToString('N')
        $recordPath=Join-Path $paths.Base ('.calabi-build-'+$token+'.json')
        $recordHandle=[IO.File]::Open($recordPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::Read)
        $data=[Text.Encoding]::UTF8.GetBytes((@{Owner=$PID;Token=$token}|ConvertTo-Json -Compress))
        $recordHandle.Write($data,0,$data.Length);$recordHandle.Flush()
        Assert-CalabiBuildIdle
        Invoke-CalabiCacheMaintenance $paths $policy
        foreach($key in @('Go','Rust','Temp')) {
            $null=Assert-CalabiCachePath $paths.$key $paths.$key
            New-Item -ItemType Directory -Path $paths.$key -Force | Out-Null
        }
        $marker=Join-Path $paths.Rust '.calabi-cache'
        $null=Assert-CalabiCachePath $marker $paths.Rust
        if (-not (Test-Path -LiteralPath $marker)) {
            $markerHandle=[IO.File]::Open($marker,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            try { $bytes=[Text.Encoding]::ASCII.GetBytes('calabi-intermediate-cache-v1');$markerHandle.Write($bytes,0,$bytes.Length) } finally { $markerHandle.Dispose() }
        }
        $settings=@{GOCACHE=$paths.Go;GOMODCACHE=(Join-Path $paths.Base 'mod');GOTMPDIR=$paths.Temp;CARGO_TARGET_DIR=(Join-Path $paths.Repo 'apps/client-desktop/src-tauri/target');CARGO_BUILD_BUILD_DIR=$paths.Rust;CALABI_BUILD_LEASE=$token}
        foreach($key in $settings.Keys) { $saved[$key]=[Environment]::GetEnvironmentVariable($key,'Process');[Environment]::SetEnvironmentVariable($key,$settings[$key],'Process') }
        return [pscustomobject]@{Handle=$lease;Saved=$saved;RecordHandle=$recordHandle;RecordPath=$recordPath}
    } catch {
        try { Restore-CalabiBuildEnvironment $saved }
        finally {
            try {
                if ($recordHandle) { $recordHandle.Dispose();[IO.File]::Delete($recordPath) }
            } finally { $lease.Dispose() }
        }
        throw
    }
}

function Restore-CalabiBuildEnvironment($Saved) {
    foreach($key in $Saved.Keys) {
        if ($null -eq $Saved[$key]) { Remove-Item -LiteralPath "Env:\$key" -ErrorAction SilentlyContinue }
        else { [Environment]::SetEnvironmentVariable($key,$Saved[$key],'Process') }
    }
}

function Exit-CalabiBuild($Lease) {
    try { Restore-CalabiBuildEnvironment $Lease.Saved }
    finally {
        try { $Lease.RecordHandle.Dispose();[IO.File]::Delete($Lease.RecordPath) }
        finally { $Lease.Handle.Dispose() }
    }
}
