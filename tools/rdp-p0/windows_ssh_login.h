#pragma once

// The SSH mode uses the same Win32 form as RDP. It sends form submissions to
// the desktop shell over inherited private pipes. Only the shell starts SSH.
static BOOL ssh_used_saved;

static void ssh_initialize(HWND dlg) {
    ShowWindow(GetDlgItem(dlg,IDC_FILES),SW_HIDE);
    SendDlgItemMessageW(dlg,IDC_ACCOUNT,0x1501,TRUE,(LPARAM)rdp_text(Rdp_Account));
    SendDlgItemMessageW(dlg,IDC_ACCOUNT,EM_SETLIMITTEXT,128,0);
    SendDlgItemMessageW(dlg,IDC_PASSWORD,EM_SETLIMITTEXT,1000,0);
    // Remove the space occupied by the RDP file option.
    shift_login_footer(dlg,-15);
}

enum {SSH_DONE,SSH_AUTH,SSH_KEY_CHANGED,SSH_KEY_REJECTED,SSH_READ_FAILED,SSH_INVALID,SSH_TIMEOUT,SSH_FAILED};

static DWORD WINAPI ssh_read_result(void *argument) {
    HWND dlg=argument;
    char reply[64];
    unsigned result=SSH_FAILED;
    if(fgets(reply,sizeof(reply),stdin)){
        reply[strcspn(reply,"\r\n")]=0;
        if(!strcmp(reply,"ok"))result=SSH_DONE;
        else if(!strcmp(reply,"auth"))result=SSH_AUTH;
        else if(!strcmp(reply,"key-changed"))result=SSH_KEY_CHANGED;
        else if(!strcmp(reply,"key-rejected"))result=SSH_KEY_REJECTED;
        else if(!strcmp(reply,"read-failed"))result=SSH_READ_FAILED;
        else if(!strcmp(reply,"invalid"))result=SSH_INVALID;
        else if(!strcmp(reply,"timeout"))result=SSH_TIMEOUT;
    }
    PostMessageW(dlg,MSG_SSH_RESULT,result,0);
    return 0;
}

static void ssh_result(HWND dlg,unsigned result) {
    if(result==SSH_DONE){cancel_login();return;}
    RdpMessage hint=Rdp_SshConnectFailed;
    switch(result){
    case SSH_AUTH: hint=ssh_used_saved?Rdp_SavedRejected:Rdp_SshAuthFailed;break;
    case SSH_KEY_CHANGED: hint=Rdp_SshHostKeyChanged;break;
    case SSH_KEY_REJECTED: hint=Rdp_SshHostKeyRejected;break;
    case SSH_READ_FAILED: hint=Rdp_ReadFailed;break;
    case SSH_INVALID: hint=Rdp_SshInvalidLogin;break;
    case SSH_TIMEOUT: hint=Rdp_SshLoginTimeout;break;
    }
    connecting=FALSE;
    enable_login(TRUE);
    set_login_hint(dlg,rdp_text(hint));
    SetForegroundWindow(dlg);
    SetFocus(GetDlgItem(dlg,IDC_PASSWORD));
}

static void ssh_hex(const char *text) {
    if(!*text){fputc('-',stdout);return;}
    for(const unsigned char *p=(const unsigned char*)text;*p;p++)fprintf(stdout,"%02x",*p);
}

static void ssh_submit(HWND dlg) {
    wchar_t account[129],secret[1001];
    char user[513],utf8[1001];
    unsigned port=login_port(dlg);
    if(!port){invalid_port(dlg);return;}
    if(!GetDlgItemTextW(dlg,IDC_ACCOUNT,account,ARRAYSIZE(account))){
        ssh_result(dlg,SSH_INVALID);return;
    }
    GetDlgItemTextW(dlg,IDC_PASSWORD,secret,ARRAYSIZE(secret));
    BOOL ok=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,account,-1,user,sizeof(user),NULL,NULL)>0 &&
        WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,secret,-1,utf8,sizeof(utf8),NULL,NULL)>0;
    SecureZeroMemory(secret,sizeof(secret));
    if(!ok){
        SecureZeroMemory(utf8,sizeof(utf8));
        set_login_hint(dlg,rdp_text(Rdp_TooLong));return;
    }
    ssh_used_saved=!utf8[0] && login_has_saved_password(dlg,account);
    BOOL remember=utf8[0] && IsDlgButtonChecked(dlg,IDC_REMEMBER)==BST_CHECKED;
    SetDlgItemTextW(dlg,IDC_PASSWORD,L"");
    set_login_hint(dlg,rdp_text(Rdp_Connecting));
    connecting=TRUE;enable_login(FALSE);
    report_login_display(dlg);
    fputs("ssh-connect ",stdout);ssh_hex(user);
    fprintf(stdout," %u %u %u ",port,(unsigned)remember,(unsigned)ssh_used_saved);
    ssh_hex(utf8);
    SecureZeroMemory(utf8,sizeof(utf8));
    fputc('\n',stdout);
    if(fflush(stdout)){ssh_result(dlg,SSH_FAILED);return;}
    HANDLE worker=CreateThread(NULL,0,ssh_read_result,dlg,0,NULL);
    if(worker)CloseHandle(worker);else cancel_login();
}

static int ssh_dialog(HINSTANCE instance,const wchar_t *target) {
    panelBrush=CreateSolidBrush(panel);fieldBrush=CreateSolidBrush(field);
    loginWindow=CreateDialogParamW(instance,MAKEINTRESOURCEW(IDD_LOGIN),NULL,login_proc,(LPARAM)target);
    int result=1;
    if(loginWindow){
        char reply[32];
        if(fprintf(stdout,"ssh-ready %llu\n",(unsigned long long)(uintptr_t)loginWindow)>=0 &&
           !fflush(stdout) && fgets(reply,sizeof(reply),stdin)
           && (!strcmp(reply,"ssh-show\n") || !strcmp(reply,"ssh-show\r\n"))){
            SetWindowPos(loginWindow,HWND_TOP,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE|SWP_SHOWWINDOW);
            SetForegroundWindow(loginWindow);
            SetFocus(GetDlgItem(loginWindow,IDC_ACCOUNT));
            MSG msg;
            while(GetMessageW(&msg,NULL,0,0)>0){
                if(!loginWindow || !IsDialogMessageW(loginWindow,&msg)){TranslateMessage(&msg);DispatchMessageW(&msg);}
            }
            result=0;
        }
        if(loginWindow){DestroyWindow(loginWindow);loginWindow=NULL;}
    }
    DeleteObject(panelBrush);DeleteObject(fieldBrush);
    if(headingFont)DeleteObject(headingFont);
    return result;
}
