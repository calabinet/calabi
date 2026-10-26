; Measures the actual controls and their rendered text, without installing.
Unicode true
ManifestDPIAware true
RequestExecutionLevel user
OutFile "${TEST_OUT}"
!include "MUI2.nsh"
!include "LogicLib.nsh"
!addplugindir "${PLUGIN_DIR}"
!include "${HOOKS}"
!define PRODUCTNAME "Calabi test"
!define VERSION "2.4.0"
!define UNINSTKEY "Software\CalabiLayoutTestNoInstallation"
Var ReinstallPageCheck
!define MUI_DISABLE_INSERT_LANGUAGE_AFTER_PAGES_WARNING
Page custom CheckLayout
Page instfiles
!insertmacro MUI_LANGUAGE "English"
!insertmacro MUI_LANGUAGE "SimpChinese"
!include "${LANGUAGE_ROOT}\English.nsh"
!include "${LANGUAGE_ROOT}\SimpChinese.nsh"

Function .onInit
  StrCpy $LANGUAGE ${LANG_SIMPCHINESE}
  SetShellVarContext current
FunctionEnd

Function MeasureControl
  Pop $1 ; HWND
  Pop $0 ; text
  System::Alloc 16
  Pop $2
  System::Call 'user32::GetClientRect(p r1, p r2)'
  System::Call '*$2(i, i, i.r5, i.r6)'
  System::Call 'user32::GetDC(p r1) p.r7'
  SendMessage $1 ${WM_GETFONT} 0 0 $8
  System::Call 'gdi32::SelectObject(p r7, p r8) p.r9'
  ; DT_CALCRECT | DT_WORDBREAK, using the real client width and font.
  System::Call 'user32::DrawTextW(p r7, w r0, i -1, p r2, i 0x410) i.r4'
  System::Call 'gdi32::GetTextFaceW(p r7, i ${NSIS_MAX_STRLEN}, w .r8)'
  FileWriteUTF16LE $R8 "font=$8 width=$5 required=$4 available=$6$\r$\n"
  System::Call 'gdi32::SelectObject(p r7, p r9)'
  System::Call 'user32::ReleaseDC(p r1, p r7)'
  System::Free $2
  ${If} $4 <= 0
  ${OrIf} $4 > $6
  ${OrIf} $8 != "Microsoft YaHei UI"
    FileClose $R8
    SetErrorLevel 1
    Quit
  ${EndIf}
FunctionEnd

Function CheckLayout
  nsDialogs::Create 1018
  Pop $R4
  FileOpen $R8 "${RESULT_FILE}" w
  ${NSD_CreateLabel} 0 0 100% 24u "$(olderOrUnknownVersionInstalled)"
  Pop $1
  Push "$(olderOrUnknownVersionInstalled)"
  Push $1
  Call MeasureControl
  ${NSD_CreateRadioButton} 30u 50u -30u 8u "$(uninstallBeforeInstalling)"
  Pop $1
  Push "$(uninstallBeforeInstalling)"
  Push $1
  Call MeasureControl
  ${NSD_CreateRadioButton} 30u 70u -30u 8u "$(dontUninstall)"
  Pop $1
  Push "$(dontUninstall)"
  Push $1
  Call MeasureControl
  FileClose $R8
  SetErrorLevel 0
  Quit
FunctionEnd

Section
SectionEnd
