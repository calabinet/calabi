; Calabi NSIS installer hooks.
;
; Register the daemon as a LocalSystem service at install and remove it at
; uninstall. The installer runs perMachine (elevated), so `daemon install
; --system` — which registers a LocalSystem service + writes C:\ProgramData\Calabi
; via the CALABI_SYSTEM_SERVICE marker — has the rights it needs. NO API key is
; baked: the service serves the console at http://127.0.0.1:7400 and runs under
; whoever signs in there (serviceInstallEnv's no-key / interactive path).
;
; calabi.exe is shipped next to calabi-desktop.exe via bundle.resources, so
; $INSTDIR\calabi.exe is the daemon the service runs.
;
; Tests: apps/client-desktop/tests/nsis-hooks/run.ps1 drives PREINSTALL and
; POSTINSTALL against a fake service key and stand-in exes. It never touches a
; real service.

; The function is included by our language files after Tauri declares its
; maintenance-page variables. MUI calls it once, when the installer opens.
!define MUI_CUSTOMFUNCTION_GUIINIT CalabiMaintenanceDefault
!define CALABI_MAINTENANCE_FILE "${__FILEDIR__}\nsis-maintenance.nsh"
!include "${__FILEDIR__}\nsis-layout.nsh"

; Overridable ONLY so the test harness can point PREINSTALL at a fake service.
; The installer build defines none of these.
!ifndef CALABI_SVC_ROOT
  !define CALABI_SVC_ROOT HKLM
!endif
!ifndef CALABI_SVC_KEY
  !define CALABI_SVC_KEY "SYSTEM\CurrentControlSet\Services\calabi"
!endif
!ifndef CALABI_SVC_NAME
  !define CALABI_SVC_NAME "calabi"
!endif
!ifndef CALABI_UNLOCK_TRIES
  !define CALABI_UNLOCK_TRIES 60 ; x 500ms = 30s
!endif
!define CALABI_CLOSE_DESKTOP_SCRIPT "${__FILEDIR__}\close-desktop.ps1"

; Enrollment/removal uses the same embedded implementation as runtime toggles.
; Return status/output; no installed PowerShell copy is required.
!macro CALABI_FILE_FIREWALL ACTION
  nsExec::ExecToStack '"$INSTDIR\calabi.exe" mesh files firewall ${ACTION}'
  Pop $R0
  Pop $R1
!macroend

!macro NSIS_HOOK_PREINSTALL
  Push $R0
  Push $R1
  Push $R2
  Push $R3
  Push $R4

  ; ---- 1. do not take over an install this installer did not make ----------
  ;
  ; A `calabi` service can exist without us: scoop or a zip, plus
  ; `calabi daemon install --system`. Installing over it is broken every way:
  ; registering our service fails (the name is taken), the daemon it runs is not
  ; a file we replace, and the machine just gains a desktop app. When the
  ; service's ImagePath is not OUR calabi.exe, stop before touching anything.
  ;
  ; ImagePath is written with EscapeArg: quoted only when the path contains a
  ; space (Program Files does, a scoop path usually does not), then " daemon".
  ; StrCmp — which LogicLib's == is — ignores case, as Windows paths do.
  ReadRegStr $R0 ${CALABI_SVC_ROOT} "${CALABI_SVC_KEY}" "ImagePath"
  ${If} $R0 != ""
    StrCpy $R1 $R0 1
    ${If} $R1 == '"'
      StrCpy $R0 $R0 "" 1
    ${EndIf}
    StrLen $R2 "$INSTDIR\calabi.exe"
    StrCpy $R1 $R0 $R2    ; the leading path, exactly as long as ours
    StrCpy $R3 $R0 1 $R2  ; the character right after it
    StrCpy $R4 "foreign"
    ${If} $R1 == "$INSTDIR\calabi.exe"
      ; A prefix match alone would accept "...\calabi.exe.old daemon".
      ${If} $R3 == '"'
        StrCpy $R4 "ours"
      ${ElseIf} $R3 == " "
        StrCpy $R4 "ours"
      ${ElseIf} $R3 == ""
        StrCpy $R4 "ours"
      ${EndIf}
    ${EndIf}
    ${If} $R4 == "foreign"
      DetailPrint "$(calabiForeignService)"
      MessageBox MB_OK|MB_ICONSTOP "$(calabiForeignServiceError)" /SD IDOK
      Abort
    ${EndIf}
  ${EndIf}

  ; ---- 2. stop the service, and wait until its image is actually released ---
  ;
  ; File below overwrites $INSTDIR\calabi.exe — the running service's own image.
  ; Windows will not open a running exe for writing, and NSIS in /S mode does
  ; NOT fail on that: it skips the file, exits 0, and writes the new version
  ; into Apps & features. Measured 2026-09-16 with a stand-in exe and a control
  ; run: before this hook, every desktop self-update reported success and left
  ; the daemon exactly as it was.
  ;
  ; `sc stop` returns once the SCM has ACCEPTED the request, not once the process
  ; is gone — so poll the file itself. Opening it for append succeeds exactly
  ; when nothing holds the image, and changes nothing about it.
  ;
  ; During a self-update this stops the daemon that launched us. That is
  ; survivable by design: apply_windows.go starts the installer DETACHED and
  ; broken away from any job, so it outlives its parent.
  ${If} ${FileExists} "$INSTDIR\calabi.exe"
    InitPluginsDir
    File /oname=$PLUGINSDIR\calabi-close-desktop.ps1 "${CALABI_CLOSE_DESKTOP_SCRIPT}"
    DetailPrint "$(calabiClosingDesktop)"
    nsExec::ExecToStack '"$SYSDIR\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "$PLUGINSDIR\calabi-close-desktop.ps1" -InstallDir "$INSTDIR"'
    Pop $R0
    Pop $R1
    ${If} $R0 != 0
      MessageBox MB_OK|MB_ICONSTOP "$(calabiCloseDesktopFailed)" /SD IDOK
      SetErrorLevel 6
      Abort
    ${EndIf}
    DetailPrint "$(calabiStoppingService)"
    nsExec::ExecToStack 'sc.exe stop ${CALABI_SVC_NAME}'
    Pop $R0
    Pop $R1
    StrCpy $R1 0
    ${Do}
      ClearErrors
      FileOpen $R2 "$INSTDIR\calabi.exe" a
      ${IfNot} ${Errors}
        FileClose $R2
        ${ExitDo}
      ${EndIf}
      IntOp $R1 $R1 + 1
      ${If} $R1 >= ${CALABI_UNLOCK_TRIES}
        ; Refuse rather than "succeed": a skipped calabi.exe is the exact silent
        ; failure this hook exists to end. Put back what we stopped, so a machine
        ; is never left without its daemon by an update that did not happen.
        DetailPrint "$(calabiFileBusy)"
        nsExec::ExecToStack 'sc.exe start ${CALABI_SVC_NAME}'
        Pop $R0
        Pop $R1
        MessageBox MB_OK|MB_ICONSTOP "$(calabiFileBusyError)" /SD IDOK
        Abort
      ${EndIf}
      Sleep 500
    ${Loop}
  ${EndIf}

  Pop $R4
  Pop $R3
  Pop $R2
  Pop $R1
  Pop $R0
!macroend

; POSTINSTALL registers the service and starts it -- and says so when it could
; not.
;
; It used to run both commands, print their exit codes into a details pane
; nobody opens, and carry on. So when `daemon install` refused, the installer
; finished with "Completed", the app started, and found no daemon: a machine
; that had just been told the install worked, with nothing anywhere saying why.
; That is exactly what a fresh install did for anyone whose command-line client
; had ever been put in standalone mode (the install refused to register a
; PLATFORM service from a standalone shell), and it stayed hidden for as long as
; the service already existed -- an upgrade's `daemon install` fails harmlessly
; with "already exists", which is why the exit code was being ignored at all.
;
; Two changes:
;
;   --platform   This package's product IS the platform service; whichever mode
;                the installing user once saved for the command line has no say
;                in it. The flag covers this one install and is not baked into
;                the service (see serviceInstallEnv in the daemon).
;
;   the outcome  Whether the service is registered is read from the service key,
;                not from the exit code: non-zero is the NORMAL answer on an
;                upgrade. If the key is not there, the install failed -- say so,
;                with what the daemon printed, and fail the installer (a silent
;                run exits non-zero, and the reason is left in
;                $INSTDIR\service-install-error.log because a silent run has no
;                window to show it in).
!macro NSIS_HOOK_POSTINSTALL
  Push $R0
  Push $R1
  Push $R2

  DetailPrint "$(calabiRegisteringService)"
  nsExec::ExecToStack '"$INSTDIR\calabi.exe" daemon install --system --platform'
  Pop $R0 ; exit code (or "error" / "timeout")
  Pop $R1 ; everything it printed
  DetailPrint "$(calabiServiceInstallResult)"

  ReadRegStr $R2 ${CALABI_SVC_ROOT} "${CALABI_SVC_KEY}" "ImagePath"
  ${If} $R2 == ""
    DetailPrint "$(calabiServiceNotRegistered)"
    FileOpen $R2 "$INSTDIR\service-install-error.log" w
    FileWrite $R2 "calabi daemon install --system --platform exited: $R0$\r$\n$R1$\r$\n"
    FileClose $R2
    MessageBox MB_OK|MB_ICONSTOP "$(calabiServiceInstallFailed)" /SD IDOK
    SetErrorLevel 3
    Abort
  ${EndIf}
  ; Registered. Clear what an earlier failed attempt left behind.
  Delete "$INSTDIR\service-install-error.log"

  DetailPrint "$(calabiConfiguringFirewall)"
  !insertmacro CALABI_FILE_FIREWALL install
  ${If} $R0 != 0
    FileOpen $R2 "$INSTDIR\file-firewall-error.log" w
    FileWrite $R2 "$R0$\r$\n$R1$\r$\n"
    FileClose $R2
    MessageBox MB_OK|MB_ICONSTOP "$(calabiFirewallFailed)" /SD IDOK
    SetErrorLevel 5
    Abort
  ${EndIf}
  Delete "$INSTDIR\file-firewall-error.log"
  ; Migrate older installs only after the embedded enrollment succeeded.
  Delete "$INSTDIR\file-firewall.ps1"

  nsExec::ExecToStack '"$INSTDIR\calabi.exe" daemon start'
  Pop $R0
  Pop $R1
  DetailPrint "$(calabiServiceStartResult)"
  ${If} $R0 != 0
    DetailPrint "$(calabiServiceNotStarted)"
    FileOpen $R2 "$INSTDIR\service-install-error.log" w
    FileWrite $R2 "calabi daemon start exited: $R0$\r$\n$R1$\r$\n"
    FileClose $R2
    MessageBox MB_OK|MB_ICONSTOP "$(calabiServiceStartFailed)" /SD IDOK
    SetErrorLevel 4
    Abort
  ${EndIf}

  Pop $R2
  Pop $R1
  Pop $R0
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  Push $R0
  Push $R1
  DetailPrint "$(calabiRemovingFirewall)"
  !insertmacro CALABI_FILE_FIREWALL remove
  ${If} $R0 != 0
    MessageBox MB_OK|MB_ICONSTOP "$(calabiRemoveFirewallFailed)" /SD IDOK
    SetErrorLevel 5
    Abort
  ${EndIf}
  Pop $R1
  Pop $R0
  Delete "$INSTDIR\file-firewall.ps1"
  DetailPrint "$(calabiRemovingService)"
  nsExec::ExecToStack '"$INSTDIR\calabi.exe" daemon stop'
  Pop $0
  Pop $1
  nsExec::ExecToStack '"$INSTDIR\calabi.exe" daemon uninstall'
  Pop $0
  Pop $1
  ; Match Tauri's data deletion choice, including its update-mode safeguard.
  ; This directory holds the service login AND mesh identity: deleting it on
  ; an ordinary upgrade silently enrolls the same computer as a new device.
  ${If} $DeleteAppDataCheckboxState = 1
  ${AndIf} $UpdateMode <> 1
    ReadEnvStr $1 "ProgramData"
    RMDir /r "$1\Calabi"
  ${EndIf}
!macroend
