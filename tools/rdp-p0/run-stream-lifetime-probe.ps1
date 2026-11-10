param([Parameter(Mandatory)][string]$Exe,[Parameter(Mandatory)][string]$LogPath)
$ErrorActionPreference='Stop'
$session=(Get-Process -Id $PID).SessionId
$expected=Join-Path $env:ProgramFiles 'Calabi/rdp/calabi-paste.exe'
$helpers=@(Get-Process -Name calabi-paste -ErrorAction Stop | Where-Object {$_.SessionId -eq $session -and $_.Path -eq $expected})
if($helpers.Count -ne 1){throw 'Expected exactly one installed Calabi paste helper in this user session'}
Add-Type @'
using System;
using System.Runtime.InteropServices;
public static class PasteProbeNative {
 [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr OpenProcess(uint access,bool inherit,int id);
 [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
 [DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr handle);
 [DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr handle);
}
'@
$handle=[PasteProbeNative]::OpenProcess(0x0800,$false,$helpers[0].Id)
if($handle -eq [IntPtr]::Zero){throw 'Cannot open the user paste helper for temporary suspension'}
$paused=$false;$child=$null
try {
 if([PasteProbeNative]::NtSuspendProcess($handle) -ne 0){throw 'Cannot temporarily suspend the paste helper'}
 $paused=$true
 $child=Start-Process -FilePath $Exe -PassThru -WindowStyle Hidden -RedirectStandardOutput $LogPath -RedirectStandardError ($LogPath+'.stderr')
 Write-Output "Probe started; paste helper $($helpers[0].Id) temporarily suspended; log=$LogPath"
 $deadline=[DateTime]::UtcNow.AddSeconds(200)
 while(-not $child.WaitForExit(200)) {if([DateTime]::UtcNow -ge $deadline){Stop-Process -Id $child.Id -Force;throw 'Probe timed out'}}
 Write-Output "Probe exit=$($child.ExitCode)"
 Get-Content -LiteralPath $LogPath
 Get-Content -LiteralPath ($LogPath+'.stderr')
} finally {
 if($child -and -not $child.HasExited){Stop-Process -Id $child.Id -Force}
 if($paused){$result=[PasteProbeNative]::NtResumeProcess($handle);Write-Output "Paste helper resumed: status=$result"}
 [PasteProbeNative]::CloseHandle($handle)|Out-Null
}
