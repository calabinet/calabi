#pragma once
#define MSG_FILE_STATUS (WM_APP+2)
static SRWLOCK fileStatusLock=SRWLOCK_INIT;
static uint64_t statusDone,statusTotal;
static int statusState;
static HWND fileStatusWindow;
static BOOL sendProgressHidden;
void probe_files_progress(uint64_t done,uint64_t total,int state) {
    AcquireSRWLockExclusive(&fileStatusLock);
    BOOL changed=state!=statusState || done!=statusDone || total!=statusTotal;
    statusDone=done;statusTotal=total;statusState=state;
    ReleaseSRWLockExclusive(&fileStatusLock);
    if(changed && window)PostMessageW(window,MSG_FILE_STATUS,0,0);
}
static void place_file_status(void) {
    if(!fileStatusWindow)return;
    RECT r;GetClientRect(window,&r);int width=min(460,max(100,r.right-32));
    SetWindowPos(fileStatusWindow,HWND_TOP,r.right-width-16,16,width,112,SWP_NOACTIVATE);
}
static LRESULT CALLBACK file_status_proc(HWND hwnd,UINT m,WPARAM wp,LPARAM lp) {
    if(m==WM_PAINT) {
        PAINTSTRUCT ps;HDC dc=BeginPaint(hwnd,&ps);RECT r;GetClientRect(hwnd,&r);
        uint64_t done,total;int state;
        AcquireSRWLockShared(&fileStatusLock);done=statusDone;total=statusTotal;state=statusState;ReleaseSRWLockShared(&fileStatusLock);
        SetDCBrushColor(dc,RGB(32,36,44));FillRect(dc,&r,GetStockObject(DC_BRUSH));
        SetBkMode(dc,TRANSPARENT);SetTextColor(dc,RGB(231,235,246));
        HGDIOBJ old=SelectObject(dc,GetStockObject(DEFAULT_GUI_FONT));
        wchar_t heading[100],detail[220];unsigned percent=total?(unsigned)(done*100/total):0;
        wcscpy(heading,rdp_text(Rdp_ReceiveIncomplete));wcscpy(detail,rdp_text(Rdp_CopyAgain));
        if(state==1 || state==3) {
            swprintf(heading,ARRAYSIZE(heading),L"%ls · %u%%",rdp_text(state==1?Rdp_ReceiveActive:Rdp_Sending),percent);
            swprintf(detail,ARRAYSIZE(detail),L"%.1f / %.1f MiB · %ls",done/1048576.0,total/1048576.0,
                state==1?rdp_text(Rdp_PasteInFolder):rdp_text(Rdp_CancelOnRemote));
        } else switch(state) {
            case 2:wcscpy(heading,rdp_text(Rdp_ReadyToPaste));wcscpy(detail,rdp_text(Rdp_PasteInFolder));break;
            case 4:wcscpy(heading,rdp_text(Rdp_Sent));wcscpy(detail,rdp_text(Rdp_CheckRemotePaste));break;
            case 5:wcscpy(heading,rdp_text(Rdp_Preparing));detail[0]=0;break;
            case 6:wcscpy(heading,rdp_text(Rdp_ReadyToPaste));wcscpy(detail,rdp_text(Rdp_ReadyRemote));break;
            case -2:wcscpy(detail,rdp_text(Rdp_CopyLimits));break;
            case -3:case -4:case -17:wcscpy(detail,rdp_text(Rdp_OfferExpired));break;
            case -5:wcscpy(detail,rdp_text(Rdp_NetworkTimeout));break;
            case -6:wcscpy(detail,rdp_text(Rdp_SourceChanged));break;
            case -7:wcscpy(detail,rdp_text(Rdp_CopyDataMismatch));break;
            case -8:case -9:wcscpy(detail,rdp_text(Rdp_TemporaryWriteFailed));break;
            case -10:wcscpy(detail,rdp_text(Rdp_TemporaryLimit));break;
            case -11:case -16:wcscpy(detail,rdp_text(Rdp_SessionEnded));break;
            case -12:wcscpy(heading,rdp_text(Rdp_ReceiveCancelled));wcscpy(detail,rdp_text(Rdp_PartialsRemoved));break;
            case -18:wcscpy(heading,rdp_text(Rdp_SendCancelled));wcscpy(detail,rdp_text(Rdp_CheckRemotePaste));break;
            case -19:wcscpy(heading,rdp_text(Rdp_PrepareFailed));wcscpy(detail,rdp_text(Rdp_CheckCopyEnabled));break;
            case -13:case -15:wcscpy(detail,rdp_text(Rdp_SourceChanged));break;
            case -14:wcscpy(detail,rdp_text(Rdp_ClipboardWriteFailed));break;
        }
        RECT line={16,12,r.right-76,36};DrawTextW(dc,heading,-1,&line,DT_SINGLELINE|DT_END_ELLIPSIS|DT_NOPREFIX);
        line=(RECT){16,42,r.right-16,85};DrawTextW(dc,detail,-1,&line,DT_WORDBREAK|DT_NOPREFIX);
        line=(RECT){r.right-68,10,r.right-8,36};DrawTextW(dc,state==1?rdp_text(Rdp_Cancel):rdp_text(Rdp_Hide),-1,&line,DT_CENTER|DT_SINGLELINE);
        if(state==1 || state==3){RECT bar={16,96,r.right-16,100};SetDCBrushColor(dc,RGB(66,74,88));FillRect(dc,&bar,GetStockObject(DC_BRUSH));
            bar.right=bar.left+(int)((bar.right-bar.left)*percent/100);SetDCBrushColor(dc,RGB(178,198,246));FillRect(dc,&bar,GetStockObject(DC_BRUSH));}
        SelectObject(dc,old);EndPaint(hwnd,&ps);return 0;
    }
    if(m==WM_LBUTTONDOWN) {
        RECT r;GetClientRect(hwnd,&r);
        if(GET_X_LPARAM(lp)>=r.right-76 && GET_Y_LPARAM(lp)<38) {
            AcquireSRWLockShared(&fileStatusLock);int state=statusState;ReleaseSRWLockShared(&fileStatusLock);
            if(state==1)clipboard_cancel_files();else {if(state==3)sendProgressHidden=TRUE;ShowWindow(hwnd,SW_HIDE);}
        }
        return 0;
    }
    if(m==WM_TIMER){ShowWindow(hwnd,SW_HIDE);KillTimer(hwnd,1);return 0;}
    if(m==WM_MOUSEACTIVATE)return MA_NOACTIVATE;
    if(m==WM_ERASEBKGND)return 1;
    return DefWindowProcW(hwnd,m,wp,lp);
}
static void update_file_status(void) {
    AcquireSRWLockShared(&fileStatusLock);int state=statusState;ReleaseSRWLockShared(&fileStatusLock);
    if(state!=3)sendProgressHidden=FALSE;
    if(state==3 && sendProgressHidden)return;
    if(!fileStatusWindow) {
        WNDCLASSW c={0};c.lpfnWndProc=file_status_proc;c.hInstance=GetModuleHandleW(NULL);c.lpszClassName=L"CalabiRdpFileStatus";
        c.hCursor=LoadCursor(NULL,IDC_ARROW);RegisterClassW(&c);
        fileStatusWindow=CreateWindowExW(0,c.lpszClassName,rdp_text(Rdp_CopyTitle),WS_CHILD,0,0,460,112,window,NULL,c.hInstance,NULL);
    }
    place_file_status();KillTimer(fileStatusWindow,1);
    ShowWindow(fileStatusWindow,SW_SHOWNOACTIVATE);InvalidateRect(fileStatusWindow,NULL,FALSE);
    AcquireSRWLockShared(&fileStatusLock);BOOL complete=statusState==2 || statusState==4 || statusState==6;ReleaseSRWLockShared(&fileStatusLock);
    if(complete)SetTimer(fileStatusWindow,1,8000,NULL);
}
