; Calabi NSIS installer hooks — F3, docs/runbook/privileged-service-and-updates-plan.md.
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
; Tests: apps/client-desktop/tests/nsis-hooks/run.ps1 drives PREINSTALL against a
; fake service key and a stand-in exe. It never touches a real service.

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
      DetailPrint "A Calabi service from another install already exists: $R0"
      MessageBox MB_OK|MB_ICONSTOP "Calabi is already installed on this computer another way (for example with scoop), and its service runs:$\r$\n$\r$\n$R0$\r$\n$\r$\nRemove that service first with:  calabi daemon uninstall$\r$\nthen run this installer again." /SD IDOK
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
    DetailPrint "Stopping the Calabi service before replacing calabi.exe..."
    nsExec::ExecToLog 'sc.exe stop ${CALABI_SVC_NAME}'
    Pop $R0
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
        DetailPrint "calabi.exe is still in use after stopping the service — not installing."
        nsExec::ExecToLog 'sc.exe start ${CALABI_SVC_NAME}'
        Pop $R0
        MessageBox MB_OK|MB_ICONSTOP "calabi.exe is still in use, so it cannot be replaced.$\r$\n$\r$\nClose any program running Calabi and run this installer again." /SD IDOK
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

!macro NSIS_HOOK_POSTINSTALL
  DetailPrint "Registering Calabi system service..."
  nsExec::ExecToLog '"$INSTDIR\calabi.exe" daemon install --system'
  Pop $0
  DetailPrint "calabi daemon install --system exited: $0"
  nsExec::ExecToLog '"$INSTDIR\calabi.exe" daemon start'
  Pop $0
  DetailPrint "calabi daemon start exited: $0"
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  DetailPrint "Removing Calabi system service..."
  nsExec::ExecToLog '"$INSTDIR\calabi.exe" daemon stop'
  Pop $0
  nsExec::ExecToLog '"$INSTDIR\calabi.exe" daemon uninstall'
  Pop $0
  ; Clean uninstall: remove the machine-wide data dir (login/config/logs). A
  ; fresh install re-enrolls via the console. $1 avoids clobbering $0 (Pop above).
  ReadEnvStr $1 "ProgramData"
  RMDir /r "$1\Calabi"
!macroend
