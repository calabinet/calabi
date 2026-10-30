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
!if "${TEST_PAGE}" == "welcome"
  !define MUI_PAGE_CUSTOMFUNCTION_SHOW CheckWelcome
  !insertmacro MUI_PAGE_WELCOME
!else if "${TEST_PAGE}" == "finish"
  !define MUI_FINISHPAGE_RUN "$INSTDIR\unused-fixture.exe"
  !define MUI_PAGE_CUSTOMFUNCTION_SHOW CheckFinish
  !insertmacro MUI_PAGE_FINISH
!else
  Page custom CheckLayout
!endif
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

; Check the actual MUI-created control, including its position in the resized
; page. Measuring text height alone misses the right-edge clipping regression.
Function MeasureBounds
  Pop $1
  System::Alloc 16
  Pop $2
  System::Alloc 16
  Pop $3
  System::Call 'user32::GetClientRect(p $R4, p r2)'
  System::Call '*$2(i, i, i.r5, i.r6)'
  System::Call 'user32::GetWindowRect(p r1, p r3)'
  System::Call 'user32::MapWindowPoints(p 0, p $R4, p r3, i 2)'
  System::Call '*$3(i.r0, i.r4, i.r7, i.r9)'
  FileWriteUTF16LE $R8 "bounds=$0,$4,$7,$9 page=$5,$6$\r$\n"
  System::Free $2
  System::Free $3
  ${If} $0 < 0
  ${OrIf} $4 < 0
  ${OrIf} $7 > $5
  ${OrIf} $9 > $6
    FileClose $R8
    SetErrorLevel 1
    Quit
  ${EndIf}
FunctionEnd

!if "${TEST_PAGE}" == "welcome"
Function CheckWelcome
  StrCpy $R4 $mui.WelcomePage
  FileOpen $R8 "${RESULT_FILE}" w
  Push "$(MUI_TEXT_WELCOME_INFO_TEXT)"
  Push $mui.WelcomePage.Text
  Call MeasureControl
  Push $mui.WelcomePage.Text
  Call MeasureBounds
  Push $mui.WelcomePage.Title
  Call MeasureBounds
  FileClose $R8
  SetErrorLevel 0
  Quit
FunctionEnd
!endif

!if "${TEST_PAGE}" == "finish"
Function CheckFinish
  StrCpy $R4 $mui.FinishPage
  FileOpen $R8 "${RESULT_FILE}" w
  Push "$(MUI_TEXT_FINISH_INFO_TEXT)"
  Push $mui.FinishPage.Text
  Call MeasureControl
  Push $mui.FinishPage.Text
  Call MeasureBounds
  Push $mui.FinishPage.Title
  Call MeasureBounds
  Push $mui.FinishPage.Run
  Call MeasureBounds
  FileClose $R8
  SetErrorLevel 0
  Quit
FunctionEnd
!endif

Function CheckLayout
  nsDialogs::Create 1018
  Pop $R4
  FileOpen $R8 "${RESULT_FILE}" w
  ; The page's client width must use the compact UI resource, not stock MUI.
  System::Alloc 16
  Pop $2
  System::Call 'user32::GetClientRect(p $R4, p r2)'
  System::Call '*$2(i, i, i.r5, i.r6)'
  FileWriteUTF16LE $R8 "page width=$5 height=$6$\r$\n"
  System::Free $2
  ${NSD_CreateLabel} 0 0 100% 24u "$(olderOrUnknownVersionInstalled)"
  Pop $1
  Push "$(olderOrUnknownVersionInstalled)"
  Push $1
  Call MeasureControl
  ${NSD_CreateLabel} 0 0 100% 24u "$(newerVersionInstalled)"
  Pop $1
  Push "$(newerVersionInstalled)"
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
