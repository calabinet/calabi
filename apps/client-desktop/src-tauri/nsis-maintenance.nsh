!ifndef CALABI_MAINTENANCE_DEFAULT_INCLUDED
!define CALABI_MAINTENANCE_DEFAULT_INCLUDED

Function CalabiMaintenanceDefault
  Push $R0
  Push $R1
  ; Tauri's first choice is reinstall for the same version, but uninstall
  ; for an upgrade. Only an upgrade should select its second (keep-data) choice.
  StrCpy $ReinstallPageCheck 1
  ReadRegStr $R0 SHCTX "${UNINSTKEY}" "DisplayVersion"
  ${If} $R0 != ""
    nsis_tauri_utils::SemverCompare "${VERSION}" $R0
    Pop $R1
    ${If} $R1 = 1
      StrCpy $ReinstallPageCheck 2
    ${EndIf}
  ${EndIf}
  Pop $R1
  Pop $R0
FunctionEnd

!endif
