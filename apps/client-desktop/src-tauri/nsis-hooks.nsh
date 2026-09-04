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
