; The stock maintenance page uses an 8-DLU radio height, which is too tight
; for Chinese glyphs. Keep the upstream template and enlarge only its compact
; control dimensions. Coordinates remain dialog units for DPI scaling.
!ifdef NSD_CreateLabel
  !undef NSD_CreateLabel
  !define NSD_CreateLabel "!insertmacro CalabiCreateLabel"
  !macro CalabiCreateLabel X Y WIDTH HEIGHT TEXT
    !if "${HEIGHT}" == "24u"
      nsDialogs::CreateControl ${__NSD_Label_CLASS} ${__NSD_Label_STYLE} ${__NSD_Label_EXSTYLE} "${X}" "${Y}" "${WIDTH}" 36u "${TEXT}"
    !else
      nsDialogs::CreateControl ${__NSD_Label_CLASS} ${__NSD_Label_STYLE} ${__NSD_Label_EXSTYLE} "${X}" "${Y}" "${WIDTH}" "${HEIGHT}" "${TEXT}"
    !endif
  !macroend
!endif

!ifdef NSD_CreateRadioButton
  !undef NSD_CreateRadioButton
  !define NSD_CreateRadioButton "!insertmacro CalabiCreateRadioButton"
  !macro CalabiCreateRadioButton X Y WIDTH HEIGHT TEXT
    !if "${HEIGHT}" == "8u"
      nsDialogs::CreateControl ${__NSD_RadioButton_CLASS} ${__NSD_RadioButton_STYLE} ${__NSD_RadioButton_EXSTYLE} "${X}" "${Y}" "${WIDTH}" 12u "${TEXT}"
    !else
      nsDialogs::CreateControl ${__NSD_RadioButton_CLASS} ${__NSD_RadioButton_STYLE} ${__NSD_RadioButton_EXSTYLE} "${X}" "${Y}" "${WIDTH}" "${HEIGHT}" "${TEXT}"
    !endif
  !macroend
!endif
