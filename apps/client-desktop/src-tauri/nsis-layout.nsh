; Compact maintenance layout, with a 12-DLU radio height to keep Chinese
; glyphs intact. SetFont in each language file scales the entire wizard;
; coordinates remain dialog units for DPI scaling.
!tempfile CALABI_COMPACT_UI
!system 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "${__FILEDIR__}\nsis-compact-ui.ps1" -Source "${NSISDIR}\Contrib\UIs\modern.exe" -Destination "${CALABI_COMPACT_UI}"' = 0
!define MUI_UI "${CALABI_COMPACT_UI}"
!macro CalabiCompactControl CLASS STYLE EXSTYLE X Y WIDTH HEIGHT TEXT
  ; MUI welcome/finish controls are created at runtime with hard-coded DLU
  ; coordinates. They must follow the compact resource dimensions too.
  !if "${X}" == "120u"
    !searchreplace CALABI_Y "${Y}" "u" ""
    !searchreplace CALABI_H "${HEIGHT}" "u" ""
    !define /math CALABI_SY ${CALABI_Y} * 88
    !define /math CALABI_SH ${CALABI_H} * 88
    !define /math CALABI_CY ${CALABI_SY} / 100
    !define /math CALABI_CH ${CALABI_SH} / 100
    !if ${CALABI_CH} < 12
      !undef CALABI_CH
      !define CALABI_CH 12
    !endif
    nsDialogs::CreateControl "${CLASS}" ${STYLE} ${EXSTYLE} 108u ${CALABI_CY}u 174u ${CALABI_CH}u "${TEXT}"
    !undef CALABI_Y
    !undef CALABI_H
    !undef CALABI_SY
    !undef CALABI_SH
    !undef CALABI_CY
    !undef CALABI_CH
  !else if "${WIDTH}" == "109u"
    nsDialogs::CreateControl "${CLASS}" ${STYLE} ${EXSTYLE} 0u 0u 98u 170u "${TEXT}"
  !else
    nsDialogs::CreateControl "${CLASS}" ${STYLE} ${EXSTYLE} "${X}" "${Y}" "${WIDTH}" "${HEIGHT}" "${TEXT}"
  !endif
!macroend

!undef NSD_CreateLabel
!define NSD_CreateLabel "!insertmacro CalabiCreateLabel"
!macro CalabiCreateLabel X Y WIDTH HEIGHT TEXT
  !insertmacro CalabiCompactControl ${__NSD_Label_CLASS} ${__NSD_Label_STYLE} ${__NSD_Label_EXSTYLE} "${X}" "${Y}" "${WIDTH}" "${HEIGHT}" "${TEXT}"
!macroend
!undef NSD_CreateBitmap
!define NSD_CreateBitmap "!insertmacro CalabiCreateBitmap"
!macro CalabiCreateBitmap X Y WIDTH HEIGHT TEXT
  !insertmacro CalabiCompactControl ${__NSD_Bitmap_CLASS} ${__NSD_Bitmap_STYLE} ${__NSD_Bitmap_EXSTYLE} "${X}" "${Y}" "${WIDTH}" "${HEIGHT}" "${TEXT}"
!macroend
!undef NSD_CreateCheckBox
!define NSD_CreateCheckBox "!insertmacro CalabiCreateCheckBox"
!macro CalabiCreateCheckBox X Y WIDTH HEIGHT TEXT
  !insertmacro CalabiCompactControl ${__NSD_CheckBox_CLASS} ${__NSD_CheckBox_STYLE} ${__NSD_CheckBox_EXSTYLE} "${X}" "${Y}" "${WIDTH}" "${HEIGHT}" "${TEXT}"
!macroend
!undef NSD_CreateLink
!define NSD_CreateLink "!insertmacro CalabiCreateLink"
!macro CalabiCreateLink X Y WIDTH HEIGHT TEXT
  !insertmacro CalabiCompactControl ${__NSD_Link_CLASS} ${__NSD_Link_STYLE} ${__NSD_Link_EXSTYLE} "${X}" "${Y}" "${WIDTH}" "${HEIGHT}" "${TEXT}"
!macroend

!ifdef NSD_CreateRadioButton
  !undef NSD_CreateRadioButton
  !define NSD_CreateRadioButton "!insertmacro CalabiCreateRadioButton"
  !macro CalabiCreateRadioButton X Y WIDTH HEIGHT TEXT
    !if "${HEIGHT}" == "8u"
      !if "${Y}" == "50u"
        nsDialogs::CreateControl ${__NSD_RadioButton_CLASS} ${__NSD_RadioButton_STYLE} ${__NSD_RadioButton_EXSTYLE} 12u 36u -12u 12u "${TEXT}"
      !else if "${Y}" == "70u"
        nsDialogs::CreateControl ${__NSD_RadioButton_CLASS} ${__NSD_RadioButton_STYLE} ${__NSD_RadioButton_EXSTYLE} 12u 52u -12u 12u "${TEXT}"
      !else
        nsDialogs::CreateControl ${__NSD_RadioButton_CLASS} ${__NSD_RadioButton_STYLE} ${__NSD_RadioButton_EXSTYLE} "${X}" "${Y}" "${WIDTH}" 12u "${TEXT}"
      !endif
    !else
      !insertmacro CalabiCompactControl ${__NSD_RadioButton_CLASS} ${__NSD_RadioButton_STYLE} ${__NSD_RadioButton_EXSTYLE} "${X}" "${Y}" "${WIDTH}" "${HEIGHT}" "${TEXT}"
    !endif
  !macroend
!endif
