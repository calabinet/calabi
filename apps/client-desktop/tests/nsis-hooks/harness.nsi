; Test harness for NSIS_HOOK_PREINSTALL (src-tauri/nsis-hooks.nsh).
;
; Built and driven by run.ps1 — run that, not this. It stands in for the Tauri
; installer's Install section at the only two points that matter here: the hook
; runs, then calabi.exe is overwritten with `File`, exactly as the real template
; does it (and with the same AllowSkipFiles/SetOverwrite defaults).
;
; Command-line defines (makensis /D...):
;   HOOKS             path to nsis-hooks.nsh
;   TEST_OUT          output installer path
;   TEST_INSTDIR      the fake $INSTDIR
;   TEST_REPLACEMENT  what gets copied over $INSTDIR\calabi.exe
;   CALABI_SVC_ROOT / CALABI_SVC_KEY / CALABI_SVC_NAME / CALABI_UNLOCK_TRIES
;                     the hooks file's test overrides — a fake service key and a
;                     service name that does not exist, so nothing real is stopped
Unicode true
SilentInstall silent
RequestExecutionLevel user
OutFile "${TEST_OUT}"
InstallDir "${TEST_INSTDIR}"

!include "LogicLib.nsh"
!include "${HOOKS}"

Section
  SetOutPath $INSTDIR
  !insertmacro NSIS_HOOK_PREINSTALL

  ; Reached only if the hook did not Abort.
  FileOpen $0 "$INSTDIR\after-hook.txt" w
  FileClose $0

  ClearErrors
  File /a "/oname=calabi.exe" "${TEST_REPLACEMENT}"
  ${If} ${Errors}
    ; The silent skip the hook exists to prevent.
    FileOpen $0 "$INSTDIR\file-error.txt" w
    FileClose $0
  ${EndIf}
SectionEnd
