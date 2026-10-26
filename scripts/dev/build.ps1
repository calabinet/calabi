# Usage: pwsh scripts/dev/build.ps1 go build ./apps/client/cmd/calabi
# Direct CLI commands must use this runner to receive the preflight and lease.
# Deliberately no param block: native flags such as go test -c / -v must
# never bind to PowerShell's own abbreviated or common parameter names.
$ErrorActionPreference='Stop'
$forward=@($args)
if (-not $forward.Count) { throw 'Usage: build.ps1 <command> [arguments...], or build.ps1 --check' }
. (Join-Path $PSScriptRoot 'build-cache.ps1')
$lease=$null
try {
    if (-not (Test-CalabiBuildLease)) { $lease=Enter-CalabiBuild }
    $global:LASTEXITCODE=0
    if ($forward[0] -eq '--check') { return }
    if ($forward[0] -eq '__script') {
        if ($forward.Count -ne 3 -or $forward[2] -isnot [Collections.IDictionary]) {throw 'Invalid internal script invocation'}
        $scriptPath=[string]$forward[1];$scriptParameters=$forward[2]
        & $scriptPath @scriptParameters
    }
    else {
        $Command=[string]$forward[0]
        $nativeArgs=@();if($forward.Count -gt 1){$nativeArgs=@($forward[1..($forward.Count-1)])}
        if ($Command -eq 'git-bash') {
            $git=(Get-Command git.exe -ErrorAction Stop).Source
            $directory=Split-Path $git -Parent
            $Command=$null
            while($directory) {
                $candidate=Join-Path $directory 'bin/bash.exe'
                if(Test-Path -LiteralPath $candidate){$Command=$candidate;break}
                $directory=Split-Path $directory -Parent
            }
            if(-not $Command){throw 'Cannot locate Git for Windows bash.exe; WSL bash is not supported by this Windows guard'}
        }
        $application=Get-Command $Command -CommandType Application -ErrorAction Stop
        if ($PSVersionTable.PSVersion.Major -lt 7 -and $application.Source -match '\.exe$') {
            # 5.1's native invocation drops embedded quotes. Use the Windows CRT
            # quoting rules. Read both streams asynchronously to avoid deadlocks;
            # stderr remains stderr and is not interpreted as an ErrorRecord.
            $quoted=@(foreach($argument in $nativeArgs) {
                $value=[string]$argument
                $value=[regex]::Replace($value,'(\\*)"','$1$1\"')
                $value=[regex]::Replace($value,'(\\+)$','$1$1')
                '"'+$value+'"'
            })
            $start=[Diagnostics.ProcessStartInfo]::new()
            $start.FileName=$application.Source
            $start.Arguments=$quoted -join ' '
            $start.WorkingDirectory=(Get-Location).ProviderPath
            $start.UseShellExecute=$false;$start.CreateNoWindow=$true
            $start.RedirectStandardOutput=$true;$start.RedirectStandardError=$true
            $child=[Diagnostics.Process]::Start($start)
            try {
                $stdout=$child.StandardOutput.ReadToEndAsync();$stderr=$child.StandardError.ReadToEndAsync()
                $child.WaitForExit()
                [Console]::Out.Write($stdout.Result);[Console]::Error.Write($stderr.Result)
                $global:LASTEXITCODE=$child.ExitCode
            } finally { $child.Dispose() }
        } else {
            $previousErrorAction=$ErrorActionPreference
            try { $ErrorActionPreference='Continue'; & $application.Source @nativeArgs }
            finally { $ErrorActionPreference=$previousErrorAction }
        }
    }
    $result=$LASTEXITCODE
} finally { if ($lease) { Exit-CalabiBuild $lease } }
if ($null -ne $result -and $result -ne 0) { exit $result }
