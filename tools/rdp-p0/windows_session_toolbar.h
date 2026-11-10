#pragma once
#define TOOLBAR_TIMER 0x4341
#define TOOL_EXIT_FULLSCREEN 9101
#define TOOL_MINIMIZE 9102
#define TOOL_END_SESSION 9103
static HWND sessionToolbar;
static HFONT toolbarFont;
static ULONGLONG toolbarLastHover;
static LRESULT CALLBACK toolbar_proc(HWND hwnd,UINT msg,WPARAM wp,LPARAM lp) {
    switch(msg) {
    case WM_COMMAND:
        if(LOWORD(wp)==TOOL_EXIT_FULLSCREEN){toggle(window);SetFocus(window);}
        else if(LOWORD(wp)==TOOL_MINIMIZE)ShowWindow(window,SW_MINIMIZE);
        else if(LOWORD(wp)==TOOL_END_SESSION)PostMessageW(window,WM_CLOSE,0,0);
        return 0;
    case WM_DRAWITEM:{
        const DRAWITEMSTRUCT *item=(const DRAWITEMSTRUCT*)lp;RECT r=item->rcItem;
        SetDCBrushColor(item->hDC,(item->itemState&ODS_SELECTED)?RGB(64,74,94):RGB(32,36,44));
        FillRect(item->hDC,&r,GetStockObject(DC_BRUSH));SetBkMode(item->hDC,TRANSPARENT);
        SetTextColor(item->hDC,item->CtlID==TOOL_END_SESSION?RGB(255,185,175):RGB(225,233,250));
        wchar_t text[48];GetWindowTextW(item->hwndItem,text,ARRAYSIZE(text));
        HGDIOBJ old=SelectObject(item->hDC,toolbarFont);DrawTextW(item->hDC,text,-1,&r,DT_CENTER|DT_VCENTER|DT_SINGLELINE);SelectObject(item->hDC,old);
        if((item->itemState&ODS_FOCUS) && !(item->itemState&ODS_NOFOCUSRECT)){InflateRect(&r,-3,-3);DrawFocusRect(item->hDC,&r);}
        return TRUE;
    }
    case WM_ERASEBKGND:return 1;
    case WM_PAINT:{PAINTSTRUCT p;HDC dc=BeginPaint(hwnd,&p);SetDCBrushColor(dc,RGB(32,36,44));FillRect(dc,&p.rcPaint,GetStockObject(DC_BRUSH));EndPaint(hwnd,&p);return 0;}
    case WM_DESTROY:if(toolbarFont){DeleteObject(toolbarFont);toolbarFont=NULL;}sessionToolbar=NULL;return 0;
    }
    return DefWindowProcW(hwnd,msg,wp,lp);
}
static void hide_toolbar(void) {
    if(sessionToolbar)ShowWindow(sessionToolbar,SW_HIDE);
}
static void place_toolbar(void) {
    if(!sessionToolbar)return;
    RECT client;GetClientRect(window,&client);UINT dpi=GetDpiForWindow(window);if(!dpi)dpi=96;
    int w=min(client.right,MulDiv(330,dpi,96)),h=MulDiv(38,dpi,96);
    SetWindowPos(sessionToolbar,HWND_TOP,(client.right-w)/2,0,w,h,SWP_NOACTIVATE);
    for(int i=0;i<3;i++)SetWindowPos(GetDlgItem(sessionToolbar,TOOL_EXIT_FULLSCREEN+i),NULL,
        i*w/3,0,(i+1)*w/3-i*w/3,h,SWP_NOZORDER|SWP_NOACTIVATE);
}
static void ensure_toolbar(void) {
    if(sessionToolbar)return;
    WNDCLASSW c={0};c.lpfnWndProc=toolbar_proc;c.hInstance=GetModuleHandleW(NULL);c.lpszClassName=L"CalabiRdpToolbar";
    c.hCursor=LoadCursor(NULL,IDC_ARROW);RegisterClassW(&c);
    sessionToolbar=CreateWindowExW(0,c.lpszClassName,L"远程桌面工具条",WS_CHILD|WS_CLIPCHILDREN,0,0,330,38,window,NULL,c.hInstance,NULL);
    UINT dpi=GetDpiForWindow(window);if(!dpi)dpi=96;
    toolbarFont=CreateFontW(-MulDiv(10,dpi,72),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,0,0,CLEARTYPE_QUALITY,0,L"Microsoft YaHei UI");
    const wchar_t *labels[]={rdp_text(Rdp_ExitFullscreen),rdp_text(Rdp_Minimize),rdp_text(Rdp_EndRemote)};
    for(int i=0;i<3;i++)CreateWindowExW(0,L"BUTTON",labels[i],WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_OWNERDRAW,
        0,0,110,38,sessionToolbar,(HMENU)(INT_PTR)(TOOL_EXIT_FULLSCREEN+i),c.hInstance,NULL);
    place_toolbar();
}
// Pointer is in session client coordinates; separate from polling for isolated UI checks.
static void toolbar_pointer(POINT p,BOOL foreground,ULONGLONG now) {
    if(!fullscreen || !foreground || IsIconic(window)){hide_toolbar();return;}
    RECT client;GetClientRect(window,&client);UINT dpi=GetDpiForWindow(window);if(!dpi)dpi=96;
    BOOL edge=p.x>=0 && p.x<client.right && p.y>=0 && p.y<MulDiv(8,dpi,96);
    if(edge){ensure_toolbar();place_toolbar();ShowWindow(sessionToolbar,SW_SHOWNOACTIVATE);toolbarLastHover=now;}
    if(!sessionToolbar)return;
    RECT rect;GetWindowRect(sessionToolbar,&rect);MapWindowPoints(NULL,window,(POINT*)&rect,2);
    if(PtInRect(&rect,p))toolbarLastHover=now;
    else if(now-toolbarLastHover>=1200)hide_toolbar();
}
static void poll_toolbar(void) {
    POINT p;if(!GetCursorPos(&p))return;ScreenToClient(window,&p);
    HWND active=GetForegroundWindow();toolbar_pointer(p,active==window || IsChild(window,active),GetTickCount64());
}
