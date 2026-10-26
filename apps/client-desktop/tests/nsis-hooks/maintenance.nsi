Unicode true
SilentInstall silent
RequestExecutionLevel user
OutFile "${TEST_OUT}"
!include "MUI2.nsh"
!include "LogicLib.nsh"
!addplugindir "${PLUGIN_DIR}"
!include "${HOOKS}"
!define PRODUCTNAME "Calabi test"
!define VERSION "2.4.0"
!define UNINSTKEY "${TEST_KEY}"
Var ReinstallPageCheck
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "SimpChinese"
!include "${LANGUAGE_ROOT}\English.nsh"
!include "${LANGUAGE_ROOT}\SimpChinese.nsh"

!macro CheckDefault OLD_VERSION EXPECTED
  DeleteRegKey HKCU "${TEST_KEY}"
  !if "${OLD_VERSION}" != ""
    WriteRegStr HKCU "${TEST_KEY}" "DisplayVersion" "${OLD_VERSION}"
  !endif
  StrCpy $R0 "preserved-r0"
  StrCpy $R1 "preserved-r1"
  Call CalabiMaintenanceDefault
  ${If} $ReinstallPageCheck != ${EXPECTED}
  ${OrIf} $R0 != "preserved-r0"
  ${OrIf} $R1 != "preserved-r1"
    SetErrorLevel 1
    Goto done
  ${EndIf}
!macroend

Section
  SetShellVarContext current
  !insertmacro CheckDefault "" 1
  !insertmacro CheckDefault "2.3.0" 2
  !insertmacro CheckDefault "2.4.0-p2.20261026.7" 2
  !insertmacro CheckDefault "2.4.0" 1
  !insertmacro CheckDefault "2.5.0" 1
  done:
  DeleteRegKey HKCU "${TEST_KEY}"
SectionEnd
