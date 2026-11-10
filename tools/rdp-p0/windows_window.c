#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <windowsx.h>
#include <wincred.h>
#include <wincrypt.h>
#include <imm.h>
#include <math.h>
#include <dwmapi.h>
#include <commctrl.h>
#include "windows_login.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "probe.h"
#include "rdp_login_record.h"
#include "clipboard.h"
#include "clipboard_payload.h"
#include "rdp_locale.h"

#define MSG_DONE (WM_APP+1)
#define MSG_FIRST_FRAME (WM_APP+3)
#define MSG_RECONNECTING (WM_APP+4)
#define MSG_SSH_RESULT (WM_APP+5)
static HWND loginWindow;
static BOOL connecting,sshLogin;
static DWORD rdpLoginParent;
static void login_failed(unsigned code);
static void cancel_login(void);
static INT_PTR CALLBACK login_proc(HWND dlg,UINT m,WPARAM wp,LPARAM lp);
static HWND window;
#include "windows_clipboard.h"
#include "windows_transfer_status.h"
static volatile LONG closing;
int probe_requested_stop(void) {return InterlockedCompareExchange(&closing,0,0)!=0;}
static SRWLOCK pixelsLock=SRWLOCK_INIT, inputLock=SRWLOCK_INIT;
static BYTE *pixels;
static int width,height;
static struct probe_input queue[512];
static unsigned head,count;
static BOOL pressed[512], leftHeld, rightHeld, fullscreen;
static WINDOWPLACEMENT placement={sizeof(WINDOWPLACEMENT)};
static volatile LONG ready, pinFailed, overflow;
static volatile LONG stage;
static volatile LONG reconnectAttempt;
void probe_reconnecting(unsigned attempt) {
    AcquireSRWLockExclusive(&inputLock);
    InterlockedExchange(&ready,0);
    head=count=0;
    ReleaseSRWLockExclusive(&inputLock);
    InterlockedExchange(&reconnectAttempt,(LONG)attempt);
    PostMessageW(window,MSG_RECONNECTING,0,0);
}
void windows_waiting_for_frame(void) {
    InterlockedExchange(&stage,2);
    InvalidateRect(window,NULL,FALSE);
}
static char host[32],username[2048],domain[1024],password[2048];
static char accountLabel[2048];
static wchar_t credentialKey[65],credentialTarget[1024];
static BOOL rememberPassword,usedSavedPassword,loginRecorded;
static uint16_t rdpPort=PROBE_RDP_DEFAULT_PORT;

static unsigned login_port(HWND dlg) {
    wchar_t text[7];
    int length=GetDlgItemTextW(dlg,IDC_PORT,text,ARRAYSIZE(text));
    if(!length || length>5 || wcsspn(text,L"0123456789")!=(size_t)length)return 0;
    unsigned long port=wcstoul(text,NULL,10);
    return port<=65535?(unsigned)port:0;
}

static BOOL credential_target(const wchar_t *account,unsigned port,wchar_t *target) {
    if(!credentialKey[0] || !*account || !port)return FALSE;
    if(sshLogin)return swprintf(target,1024,L"Calabi/SSH/%ls/%u/%ls",credentialKey,port,account)>0;
    if(port==PROBE_RDP_DEFAULT_PORT)return swprintf(target,1024,L"Calabi/RDP/%ls/%ls",credentialKey,account)>0;
    return swprintf(target,1024,L"Calabi/RDPPort/%ls/%u/%ls",credentialKey,port,account)>0;
}

static BOOL login_has_saved_password(HWND dlg,const wchar_t *account) {
    wchar_t target[1024];
    PCREDENTIALW credential=NULL;
    if(!credential_target(account,login_port(dlg),target) || !CredReadW(target,CRED_TYPE_GENERIC,0,&credential))return FALSE;
    DWORD bytes=credential->CredentialBlobSize;
    if(bytes)SecureZeroMemory(credential->CredentialBlob,bytes);
    CredFree(credential);
    return bytes>0;
}

static void login_refresh_password_hint(HWND dlg) {
    wchar_t account[CREDUI_MAX_USERNAME_LENGTH+1];
    GetDlgItemTextW(dlg,IDC_ACCOUNT,account,ARRAYSIZE(account));
    BOOL saved=login_has_saved_password(dlg,account);
    ShowWindow(GetDlgItem(dlg,IDC_FORGET),saved?SW_SHOW:SW_HIDE);
    SendDlgItemMessageW(dlg,IDC_PASSWORD,0x1501,TRUE,(LPARAM)rdp_text(saved?Rdp_UseSaved:
        sshLogin?Rdp_SshKeyHint:Rdp_PasswordPlaceholder));
}

static void layout_login_fields(HWND dlg) {
    const int labels[]={IDC_ACCOUNT_LABEL,IDC_PASSWORD_LABEL,IDC_PORT_LABEL};
    const int fields[]={IDC_ACCOUNT,IDC_PASSWORD,IDC_PORT};
    HDC dc=GetDC(dlg);
    if(!dc)return;
    HFONT font=(HFONT)SendDlgItemMessageW(dlg,IDC_ACCOUNT_LABEL,WM_GETFONT,0,0);
    HGDIOBJ previous=font?SelectObject(dc,font):NULL;
    int widest=0;
    for(unsigned i=0;i<ARRAYSIZE(labels);i++){
        wchar_t text[64];GetDlgItemTextW(dlg,labels[i],text,ARRAYSIZE(text));
        RECT size={0};
        DrawTextW(dc,text,-1,&size,DT_CALCRECT|DT_SINGLELINE|DT_NOPREFIX);
        widest=max(widest,size.right);
    }
    if(previous)SelectObject(dc,previous);
    ReleaseDC(dlg,dc);
    if(!widest)return;

    RECT spacing={2,0,8,0};
    MapDialogRect(dlg,&spacing);
    for(unsigned i=0;i<ARRAYSIZE(labels);i++){
        HWND label=GetDlgItem(dlg,labels[i]), field=GetDlgItem(dlg,fields[i]);
        RECT labelRect,fieldRect;
        GetWindowRect(label,&labelRect);GetWindowRect(field,&fieldRect);
        MapWindowPoints(NULL,dlg,(POINT*)&labelRect,2);
        MapWindowPoints(NULL,dlg,(POINT*)&fieldRect,2);
        int fieldX=labelRect.left+widest+spacing.right;
        SetWindowPos(label,NULL,0,0,widest+spacing.left,labelRect.bottom-labelRect.top,
            SWP_NOMOVE|SWP_NOZORDER|SWP_NOACTIVATE);
        SetWindowPos(field,NULL,fieldX,fieldRect.top,fieldRect.right-fieldX,fieldRect.bottom-fieldRect.top,
            SWP_NOZORDER|SWP_NOACTIVATE);
    }
}

static void shift_login_footer(HWND dlg,int units) {
    RECT offset={0,0,0,units};MapDialogRect(dlg,&offset);
    const int ids[]={IDC_FILES,IDC_REMEMBER,IDC_FORGET,IDCANCEL,IDOK};
    for(unsigned i=0;i<ARRAYSIZE(ids);i++){
        HWND control=GetDlgItem(dlg,ids[i]);
        RECT rect;GetWindowRect(control,&rect);
        MapWindowPoints(NULL,dlg,(POINT*)&rect,2);
        SetWindowPos(control,NULL,rect.left,rect.top+offset.bottom,0,0,SWP_NOSIZE|SWP_NOZORDER|SWP_NOACTIVATE);
    }
    RECT frame;GetWindowRect(dlg,&frame);
    SetWindowPos(dlg,NULL,0,0,frame.right-frame.left,frame.bottom-frame.top+offset.bottom,
        SWP_NOMOVE|SWP_NOZORDER|SWP_NOACTIVATE);
}

static void set_login_hint(HWND dlg,const wchar_t *text) {
    HWND hint=GetDlgItem(dlg,IDC_HINT);
    if(!(GetWindowLongPtrW(hint,GWL_STYLE)&WS_VISIBLE)){
        // The status line only takes up space after a message is shown.
        shift_login_footer(dlg,19);
        ShowWindow(hint,SW_SHOWNA);
    }
    SetWindowTextW(hint,text);
}

static void invalid_port(HWND dlg) {
    set_login_hint(dlg,rdp_text(Rdp_InvalidPort));
    SetFocus(GetDlgItem(dlg,IDC_PORT));
}

static BOOL read_saved_password(void) {
    PCREDENTIALW credential=NULL;
    if(!credentialTarget[0])return TRUE;
    if(!CredReadW(credentialTarget,CRED_TYPE_GENERIC,0,&credential))return GetLastError()==ERROR_NOT_FOUND;
    DWORD bytes=credential->CredentialBlobSize;
    if(bytes && bytes<sizeof(password) && !memchr(credential->CredentialBlob,0,bytes)){
        memcpy(password,credential->CredentialBlob,bytes);password[bytes]=0;
        usedSavedPassword=TRUE;
    }
    if(bytes)SecureZeroMemory(credential->CredentialBlob,bytes);
    CredFree(credential);
    return usedSavedPassword;
}

static void record_login(void) {
    if(loginRecorded || probe_requested_stop())return;
    loginRecorded=TRUE;
    if(rememberPassword && credentialTarget[0] && password[0]){
        CREDENTIALW credential={0};
        credential.Type=CRED_TYPE_GENERIC;credential.TargetName=credentialTarget;
        credential.CredentialBlob=(BYTE *)password;credential.CredentialBlobSize=(DWORD)strlen(password);
        credential.Persist=CRED_PERSIST_LOCAL_MACHINE;
        if(!CredWriteW(&credential,0))fprintf(stderr,"RDP credential store failed (%lu)\n",GetLastError());
    }
    if(credentialKey[0])rdp_record_login(accountLabel,rdpPort);
}

int probe_verify_leaf(const uint8_t *pem,size_t length) {
    static const char end[]="-----END CERTIFICATE-----";
    char *chain=NULL, *first=NULL, *last=NULL;
    BYTE *der=NULL,hash[32];
    DWORD bytes=0,hashBytes=sizeof(hash);
    char actual[65],answer[80];
    int ok=0;
    if (!length || length>1024*1024 || !(chain=malloc(length+1))) goto done;
    memcpy(chain,pem,length); chain[length]=0;
    first=strstr(chain,"-----BEGIN CERTIFICATE-----");
    if (!first || !(last=strstr(first,end))) goto done;
    DWORD chars=(DWORD)(last-first+sizeof(end)-1);
    if (!CryptStringToBinaryA(first,chars,CRYPT_STRING_BASE64HEADER,NULL,&bytes,NULL,NULL) || !bytes ||
        !(der=malloc(bytes)) || !CryptStringToBinaryA(first,chars,CRYPT_STRING_BASE64HEADER,der,&bytes,NULL,NULL) ||
        !CryptHashCertificate2(L"SHA256",0,NULL,der,bytes,hash,&hashBytes) || hashBytes!=32) goto done;
    for(unsigned i=0;i<32;i++) snprintf(actual+2*i,3,"%02X",hash[i]);
    AcquireSRWLockExclusive(&copyPipeLock);
    fprintf(stdout,"rdp-pin %s\n",actual); fflush(stdout);
    if(fgets(answer,sizeof(answer),stdin)){answer[strcspn(answer,"\r\n")]=0;ok=!_stricmp(answer,actual);}
    ReleaseSRWLockExclusive(&copyPipeLock);
done:
    free(der); free(chain);
    if(!ok) InterlockedExchange(&pinFailed,1);
    else if(window){InterlockedExchange(&stage,1);InvalidateRect(window,NULL,FALSE);}
    return ok;
}
void probe_frame(const uint8_t *src,int w,int h,unsigned stride) {
#ifdef CALABI_REMOTE_WORKSPACE
    if(!probe_workspace_enabled()){
#endif
    AcquireSRWLockExclusive(&pixelsLock);
    if(w!=width || h!=height) {
        BYTE *next=realloc(pixels,(size_t)w*h*4);
        if(!next){ReleaseSRWLockExclusive(&pixelsLock);PostMessageW(window,WM_CLOSE,0,0);return;}
        pixels=next;width=w;height=h;
    }
    for(int y=0;y<h;y++) memcpy(pixels+(size_t)y*w*4,src+(size_t)y*stride,(size_t)w*4);
    ReleaseSRWLockExclusive(&pixelsLock);
#ifdef CALABI_REMOTE_WORKSPACE
    }
#endif
    InterlockedExchange(&reconnectAttempt,0);
    record_login();
    if(!InterlockedExchange(&ready,1))PostMessageW(window,MSG_FIRST_FRAME,0,0);
#ifdef CALABI_REMOTE_WORKSPACE
    if(!probe_workspace_enabled())
#endif
        InvalidateRect(window,NULL,FALSE);
}
int probe_next_input(struct probe_input *out) {
    AcquireSRWLockExclusive(&inputLock);
    BOOL any=count!=0;
    if(any){*out=queue[head];head=(head+1)%512;count--;}
    ReleaseSRWLockExclusive(&inputLock);
    return any;
}
static void enqueue(int kind,int a,int b,int delta) {
    struct probe_input e={kind,(uint16_t)a,(uint16_t)b,(int16_t)delta};
    AcquireSRWLockExclusive(&inputLock);
    if(!ready || overflow){ReleaseSRWLockExclusive(&inputLock);return;}
    unsigned tail=(head+count)%512;
    if(kind==PROBE_MOVE && count && queue[(tail+511)%512].kind==PROBE_MOVE)queue[(tail+511)%512]=e;
    else if(count<512){queue[tail]=e;count++;}
    else {InterlockedExchange(&overflow,1);PostMessageW(window,WM_CLOSE,0,0);}
    ReleaseSRWLockExclusive(&inputLock);
}
static RECT fit(RECT client,int w,int h) {
    int cw=client.right-client.left,ch=client.bottom-client.top;
    if(!w||!h||!cw||!ch)return (RECT){0};
    int fw=cw,fh=MulDiv(cw,h,w);
    if(fh>ch){fh=ch;fw=MulDiv(ch,w,h);}
    int x=(cw-fw)/2,y=(ch-fh)/2;
    return (RECT){x,y,x+fw,y+fh};
}
static int mouseX,mouseY;
static BOOL pointer(HWND hwnd,int x,int y,BOOL clamp) {
    if(!ready)return FALSE;
    RECT client;GetClientRect(hwnd,&client);
    AcquireSRWLockShared(&pixelsLock);int w=width,h=height;ReleaseSRWLockShared(&pixelsLock);
    RECT r=fit(client,w,h);
    POINT p={x,y};
    if(IsRectEmpty(&r)||(!clamp && !PtInRect(&r,p)))return FALSE;
    mouseX=MulDiv(max(r.left,min(x,r.right-1))-r.left,w-1,max(1,r.right-r.left-1));
    mouseY=MulDiv(max(r.top,min(y,r.bottom-1))-r.top,h-1,max(1,r.bottom-r.top-1));
    return TRUE;
}
static void releaseMouse(void) {
    if(leftHeld) enqueue(PROBE_LEFT_UP,mouseX,mouseY,0);
    if(rightHeld) enqueue(PROBE_RIGHT_UP,mouseX,mouseY,0);
    leftHeld=rightHeld=FALSE;
}
static void hide_toolbar(void);
static void toggle(HWND hwnd){
    if(!fullscreen){
        MONITORINFO info={sizeof(info)};GetMonitorInfoW(MonitorFromWindow(hwnd,MONITOR_DEFAULTTONEAREST),&info);
        GetWindowPlacement(hwnd,&placement);SetWindowLongPtrW(hwnd,GWL_STYLE,WS_POPUP|WS_CLIPCHILDREN|WS_VISIBLE);
        RECT r=info.rcMonitor;SetWindowPos(hwnd,HWND_TOP,r.left,r.top,r.right-r.left,r.bottom-r.top,SWP_FRAMECHANGED);
    }else{
        SetWindowLongPtrW(hwnd,GWL_STYLE,WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN|WS_VISIBLE);SetWindowPlacement(hwnd,&placement);
        SetWindowPos(hwnd,NULL,0,0,0,0,SWP_NOZORDER|SWP_NOMOVE|SWP_NOSIZE|SWP_FRAMECHANGED);
    }
    fullscreen=!fullscreen;
    if(fullscreen)SetTimer(hwnd,0x4341,100,NULL);else{KillTimer(hwnd,0x4341);hide_toolbar();}
}
#include "windows_session_toolbar.h"
static LRESULT CALLBACK proc(HWND hwnd,UINT m,WPARAM wp,LPARAM lp) {
    switch(m) {
    case WM_PAINT:{
        PAINTSTRUCT ps;HDC dc=BeginPaint(hwnd,&ps);RECT c;GetClientRect(hwnd,&c);
        AcquireSRWLockShared(&pixelsLock);
        LONG attempt=InterlockedCompareExchange(&reconnectAttempt,0,0);
        if(pixels && !attempt){RECT r=fit(c,width,height);BITMAPINFO info={0};
            // Keep the previous desktop visible until the next blit. Only
            // the letterbox belongs to the local window background.
            int saved=SaveDC(dc);
            if(saved){
                ExcludeClipRect(dc,r.left,r.top,r.right,r.bottom);
                FillRect(dc,&ps.rcPaint,(HBRUSH)GetStockObject(BLACK_BRUSH));
                RestoreDC(dc,saved);
            }
            info.bmiHeader=(BITMAPINFOHEADER){sizeof(BITMAPINFOHEADER),width,-height,1,32,BI_RGB};
            SetStretchBltMode(dc,HALFTONE);SetBrushOrgEx(dc,0,0,NULL);
            StretchDIBits(dc,r.left,r.top,r.right-r.left,r.bottom-r.top,0,0,width,height,pixels,&info,DIB_RGB_COLORS,SRCCOPY);
        }else{
            FillRect(dc,&ps.rcPaint,(HBRUSH)GetStockObject(BLACK_BRUSH));
            const wchar_t *status=stage==2 ? rdp_text(Rdp_AwaitingFrame) :
                                  stage==1 ? rdp_text(Rdp_OpeningSession) : rdp_text(Rdp_ConnectingWindows);
            wchar_t retry[96];
            if(attempt){swprintf(retry,ARRAYSIZE(retry),L"%ls (%ld/%d)",rdp_text(Rdp_Reconnecting),attempt,PROBE_RECONNECT_LIMIT);status=retry;}
            SetBkMode(dc,TRANSPARENT);SetTextColor(dc,RGB(225,230,240));DrawTextW(dc,status,-1,&c,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
        }
        ReleaseSRWLockShared(&pixelsLock);EndPaint(hwnd,&ps);return 0;
    }
    case WM_ERASEBKGND:return 1;
    case WM_SIZE:place_file_status();place_toolbar();InvalidateRect(hwnd,NULL,FALSE);return 0;
    case WM_TIMER:if(wp==TOOLBAR_TIMER){poll_toolbar();return 0;}break;
    case MSG_FILE_STATUS:update_file_status();return 0;
    case MSG_RECONNECTING:
        memset(pressed,0,sizeof(pressed));leftHeld=rightHeld=FALSE;
        if(GetCapture()==hwnd)ReleaseCapture();
        InvalidateRect(hwnd,NULL,FALSE);return 0;
    case MSG_FIRST_FRAME:
        if(loginWindow && connecting && !closing && ready) {
            DestroyWindow(loginWindow);loginWindow=NULL;
#ifdef CALABI_REMOTE_WORKSPACE
            if(probe_workspace_enabled()){
                puts("rdp-workspace-connected");fflush(stdout);return 0;
            }
#endif
            if(!fullscreen)toggle(hwnd);
            ShowWindow(hwnd,SW_SHOW);SetForegroundWindow(hwnd);SetFocus(hwnd);UpdateWindow(hwnd);
            if(rdpLoginParent){puts("rdp-login-connected");fflush(stdout);}
        }
        return 0;
    case WM_CLOSE:cancel_login();return 0;
    case WM_SYSKEYDOWN:case WM_KEYDOWN:case WM_KEYUP:case WM_SYSKEYUP:{
        BOOL down=m==WM_KEYDOWN||m==WM_SYSKEYDOWN;
        if(wp==VK_F11){if(down && !(lp&(1L<<30)))toggle(hwnd);return 0;}
        if(!ready)return 0;
        int scan=(lp>>16)&255, ext=(lp>>24)&1;
        if(scan){pressed[scan+ext*256]=down;enqueue(down?PROBE_KEY_DOWN:PROBE_KEY_UP,scan,ext,0);}
        return 0;
    }
    case WM_KILLFOCUS:
        for(int i=0;i<512;i++)if(pressed[i]){enqueue(PROBE_KEY_UP,i&255,i>>8,0);pressed[i]=FALSE;}
        releaseMouse();return 0;
    case WM_CAPTURECHANGED:releaseMouse();return 0;
    case WM_LBUTTONDOWN:case WM_RBUTTONDOWN:
        if(pointer(hwnd,GET_X_LPARAM(lp),GET_Y_LPARAM(lp),FALSE)){
            SetFocus(hwnd);SetCapture(hwnd);
            if(m==WM_LBUTTONDOWN)leftHeld=TRUE;else rightHeld=TRUE;
            enqueue(m==WM_LBUTTONDOWN?PROBE_LEFT_DOWN:PROBE_RIGHT_DOWN,mouseX,mouseY,0);
        }return 0;
    case WM_LBUTTONUP:case WM_RBUTTONUP:
        if(m==WM_LBUTTONUP?leftHeld:rightHeld){
            pointer(hwnd,GET_X_LPARAM(lp),GET_Y_LPARAM(lp),TRUE);
            enqueue(m==WM_LBUTTONUP?PROBE_LEFT_UP:PROBE_RIGHT_UP,mouseX,mouseY,0);
            if(m==WM_LBUTTONUP)leftHeld=FALSE;else rightHeld=FALSE;
            if(!leftHeld&&!rightHeld)ReleaseCapture();
        }return 0;
    case WM_MOUSEMOVE:
        if(pointer(hwnd,GET_X_LPARAM(lp),GET_Y_LPARAM(lp),leftHeld||rightHeld))enqueue(PROBE_MOVE,mouseX,mouseY,0);return 0;
    case WM_MOUSEWHEEL:case WM_MOUSEHWHEEL:{
        POINT pt={GET_X_LPARAM(lp),GET_Y_LPARAM(lp)};ScreenToClient(hwnd,&pt);
        if(pointer(hwnd,pt.x,pt.y,FALSE))enqueue(m==WM_MOUSEWHEEL?PROBE_WHEEL:PROBE_HWHEEL,mouseX,mouseY,GET_WHEEL_DELTA_WPARAM(wp));return 0;
    }
    case MSG_DONE:
        connecting=FALSE;
        if(loginWindow && !closing){login_failed((unsigned)wp);return 0;}
        if(wp && !closing
#ifdef CALABI_REMOTE_WORKSPACE
            && !probe_workspace_enabled()
#endif
        ){
            RdpLocale locale=rdp_locale_current();
            RdpMessage reason=(unsigned)wp==(unsigned)PROBE_RECONNECT_EXHAUSTED?Rdp_ReconnectFailed:
                (unsigned)wp==(unsigned)-2?Rdp_NoFrame:pinFailed?Rdp_VerifyFailed:Rdp_ConnectFailed;
            wchar_t text[512],caption[128];
            swprintf(text,ARRAYSIZE(text),L"%ls\n%ls 0x%08X",rdp_text_in(locale,reason),rdp_text_in(locale,Rdp_Code),(unsigned)wp);
            swprintf(caption,ARRAYSIZE(caption),L"Calabi · %ls",rdp_text_in(locale,Rdp_Login));
            MessageBoxW(hwnd,text,caption,MB_OK|MB_ICONINFORMATION);
        }
        DestroyWindow(hwnd);return 0;
    case WM_DESTROY:PostQuitMessage(0);return 0;
    }
    return DefWindowProcW(hwnd,m,wp,lp);
}
static DWORD WINAPI connectWorker(void *arg) {
    (void)arg;
    WSADATA wsa;
    int rc=WSAStartup(MAKEWORD(2,2),&wsa);
    if(rc==0){rc=probe_connect(host,rdpPort,domain,username,password);WSACleanup();}
    if(rdp_password_rejected((unsigned)rc) && usedSavedPassword && credentialTarget[0])
        CredDeleteW(credentialTarget,CRED_TYPE_GENERIC,0);
    SecureZeroMemory(password,sizeof(password));
    PostMessageW(window,MSG_DONE,(WPARAM)(unsigned)rc,0);return 0;
}
// Credentials stay in the native helper; the parent only receives certificate queries.
static const COLORREF panel=RGB(32,36,44), field=RGB(42,48,58), accent=RGB(220,227,255);
static HBRUSH panelBrush,fieldBrush;
static HFONT headingFont;

static void rounded_box(HDC dc,RECT r,COLORREF fill,COLORREF edge,int radius){
    HGDIOBJ oldBrush=SelectObject(dc,GetStockObject(DC_BRUSH));
    HGDIOBJ oldPen=SelectObject(dc,GetStockObject(DC_PEN));
    SetDCBrushColor(dc,fill);SetDCPenColor(dc,edge);
    RoundRect(dc,r.left,r.top,r.right,r.bottom,radius,radius);
    SelectObject(dc,oldBrush);SelectObject(dc,oldPen);
}

// RoundRect uses a binary edge. Blend the two end caps against the actual
// dialog background at the button's current device-pixel size.
static void draw_pill(HDC dc, RECT r, COLORREF fill) {
    const int w = r.right - r.left, h = r.bottom - r.top;
    if (w <= 0 || h <= 0) return;
    DWORD *bitmap = malloc((size_t)w * h * sizeof(*bitmap));
    if (!bitmap) { rounded_box(dc, r, fill, fill, h); return; }
    const double radius = min(w, h) * 0.5;
    for (int y = 0; y < h; ++y) {
        for (int x = 0; x < w; ++x) {
            double dx = fmax(0, fabs(x + 0.5 - w * 0.5) - (w * 0.5 - radius));
            double dy = fmax(0, fabs(y + 0.5 - h * 0.5) - (h * 0.5 - radius));
            double mix = fmin(1, fmax(0, radius + 0.5 - sqrt(dx*dx + dy*dy)));
            DWORD red = (DWORD)(GetRValue(panel) + mix * (GetRValue(fill) - GetRValue(panel)) + 0.5);
            DWORD green = (DWORD)(GetGValue(panel) + mix * (GetGValue(fill) - GetGValue(panel)) + 0.5);
            DWORD blue = (DWORD)(GetBValue(panel) + mix * (GetBValue(fill) - GetBValue(panel)) + 0.5);
            bitmap[(size_t)y*w + x] = (red << 16) | (green << 8) | blue;
        }
    }
    BITMAPINFO info = {0};
    info.bmiHeader = (BITMAPINFOHEADER){sizeof(BITMAPINFOHEADER), w, -h, 1, 32, BI_RGB};
    SetDIBitsToDevice(dc, r.left, r.top, w, h, 0, 0, 0, h, bitmap, &info, DIB_RGB_COLORS);
    free(bitmap);
}

static BOOL read_credentials(HWND dlg){
    unsigned port=login_port(dlg);
    if(!port){invalid_port(dlg);return FALSE;}
    rdpPort=(uint16_t)port;
    clipboardFilesEnabled = IsDlgButtonChecked(dlg, IDC_FILES) == BST_CHECKED;
    wchar_t name[CREDUI_MAX_USERNAME_LENGTH+1],pass[CREDUI_MAX_PASSWORD_LENGTH+1];
    wchar_t usr[CREDUI_MAX_USERNAME_LENGTH+1],dom[CREDUI_MAX_DOMAIN_TARGET_LENGTH+1]=L"";
    if(!GetDlgItemTextW(dlg,IDC_ACCOUNT,name,ARRAYSIZE(name))){
        SetFocus(GetDlgItem(dlg,IDC_ACCOUNT));
        set_login_hint(dlg,rdp_text(Rdp_EnterAccount));
        return FALSE;
    }
    GetDlgItemTextW(dlg,IDC_PASSWORD,pass,ARRAYSIZE(pass));
    usedSavedPassword=FALSE;credentialTarget[0]=0;
    credential_target(name,port,credentialTarget);
    rememberPassword=IsDlgButtonChecked(dlg,IDC_REMEMBER)==BST_CHECKED;
    const wchar_t *user=name;
    if(wcschr(name,L'\\') && !CredUIParseUserNameW(name,usr,ARRAYSIZE(usr),dom,ARRAYSIZE(dom)))user=usr;
    BOOL ok=WideCharToMultiByte(CP_UTF8,0,name,-1,accountLabel,sizeof(accountLabel),NULL,NULL)>0 &&
            WideCharToMultiByte(CP_UTF8,0,user,-1,username,sizeof(username),NULL,NULL)>0 &&
            WideCharToMultiByte(CP_UTF8,0,dom,-1,domain,sizeof(domain),NULL,NULL)>0 &&
            WideCharToMultiByte(CP_UTF8,0,pass,-1,password,sizeof(password),NULL,NULL)>0;
    SecureZeroMemory(pass,sizeof(pass));
    if(ok && !password[0] && !read_saved_password()){
        set_login_hint(dlg,rdp_text(Rdp_ReadFailed));
        return FALSE;
    }
    if(!ok)set_login_hint(dlg,rdp_text(Rdp_TooLong));
    return ok;
}

static void enable_login(BOOL enabled) {
    const int ids[]={IDC_ACCOUNT,IDC_PASSWORD,IDC_FILES,IDC_REMEMBER,IDC_FORGET,IDC_PORT,IDOK};
    for(unsigned i=0;i<ARRAYSIZE(ids);i++)EnableWindow(GetDlgItem(loginWindow,ids[i]),enabled);
    InvalidateRect(loginWindow,NULL,FALSE);
}
static void login_failed(unsigned code) {
    SecureZeroMemory(password,sizeof(password));
    SetDlgItemTextW(loginWindow,IDC_PASSWORD,L"");
    BOOL rejected=rdp_password_rejected(code);
    if(rejected && usedSavedPassword){
        SendDlgItemMessageW(loginWindow,IDC_PASSWORD,0x1501,TRUE,(LPARAM)rdp_text(Rdp_NewPassword));
    }
    const wchar_t *hint=pinFailed?rdp_text(Rdp_VerifyFailed):
        rejected?(usedSavedPassword?rdp_text(Rdp_SavedRejected):rdp_text(Rdp_LoginFailed)):
        (code==0x0002000e || code==0x0002000f || code==0x00020013)?rdp_text(Rdp_PasswordExpired):
        (code==0x0002000a || (code>=0x00020016 && code<=0x0002001a) || code==0x00020012)?rdp_text(Rdp_AccountRestricted):
        code==(unsigned)-2?rdp_text(Rdp_NoFrame):rdp_text(Rdp_ConnectFailed);
    enable_login(TRUE);set_login_hint(loginWindow,hint);
    SetWindowPos(loginWindow,HWND_TOP,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE|SWP_SHOWWINDOW);SetForegroundWindow(loginWindow);SetFocus(GetDlgItem(loginWindow,IDC_PASSWORD));
}
static void report_login_display(HWND dlg) {
    DPI_AWARENESS_CONTEXT previous = SetThreadDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE);
    MONITORINFO monitor = {sizeof(monitor)};
    BOOL found = GetMonitorInfoW(MonitorFromWindow(dlg, MONITOR_DEFAULTTONULL), &monitor);
    if (previous) SetThreadDpiAwarenessContext(previous);
    if (found) {
        RECT bounds = monitor.rcMonitor;
        fprintf(stdout, "remote-display %ld %ld\n", bounds.left + (bounds.right - bounds.left) / 2,
                bounds.top + (bounds.bottom - bounds.top) / 2);
    } else {
        puts("remote-display none");
    }
    fflush(stdout);
}
static void start_connection(HWND dlg) {
#ifdef CALABI_REMOTE_WORKSPACE
    if(probe_workspace_enabled()) report_login_display(dlg);
#endif
    InterlockedExchange(&ready,0);InterlockedExchange(&pinFailed,0);InterlockedExchange(&overflow,0);InterlockedExchange(&stage,0);
    InterlockedExchange(&reconnectAttempt,0);
    loginRecorded=FALSE;
    AcquireSRWLockExclusive(&pixelsLock);free(pixels);pixels=NULL;width=height=0;ReleaseSRWLockExclusive(&pixelsLock);
    AcquireSRWLockExclusive(&inputLock);head=count=0;ReleaseSRWLockExclusive(&inputLock);
    memset(pressed,0,sizeof(pressed));leftHeld=rightHeld=FALSE;
    SetDlgItemTextW(dlg,IDC_PASSWORD,L"");set_login_hint(dlg,rdp_text(Rdp_CheckingLogin));
    connecting=TRUE;enable_login(FALSE);
    HANDLE worker=CreateThread(NULL,0,connectWorker,NULL,0,NULL);
    if(worker)CloseHandle(worker);else{connecting=FALSE;login_failed((unsigned)-1);}
}
static DWORD login_parent_pid(const wchar_t *variable) {
    wchar_t parent[16];
    DWORD size=GetEnvironmentVariableW(variable,parent,ARRAYSIZE(parent));
    return size && size<ARRAYSIZE(parent)?wcstoul(parent,NULL,10):0;
}

static void cancel_login(void) {
    InterlockedExchange(&closing,1);
    if(loginWindow){
        DWORD parent=sshLogin?login_parent_pid(L"CALABI_SSH_PARENT_PID"):rdpLoginParent;
        if(parent)AllowSetForegroundWindow(parent);
        DestroyWindow(loginWindow);loginWindow=NULL;
        if(!sshLogin && rdpLoginParent){puts("rdp-login-cancelled");fflush(stdout);}
    }
    if(sshLogin){PostQuitMessage(0);return;}
    ShowWindow(window,SW_HIDE);
    if(!connecting)DestroyWindow(window);
}

#include "windows_ssh_login.h"

static INT_PTR CALLBACK login_proc(HWND dlg,UINT m,WPARAM wp,LPARAM lp){
    switch(m){
    case WM_INITDIALOG:{
        ShowWindow(GetDlgItem(dlg,IDC_HINT),SW_HIDE);
        RdpLocale locale=rdp_locale_current();
        const struct {int control;RdpMessage message;} labels[]={
            {IDC_BRAND,Rdp_Login},{IDC_ACCOUNT_LABEL,Rdp_Account},{IDC_PASSWORD_LABEL,Rdp_Password},
            {IDC_FILES,Rdp_AllowFiles},{IDC_REMEMBER,Rdp_Remember},
            {IDC_FORGET,Rdp_ClearCredentials},{IDCANCEL,Rdp_Cancel},{IDOK,Rdp_Connect},{IDC_DISMISS,Rdp_Close},
            {IDC_PORT_LABEL,Rdp_Port}
        };
        for(size_t i=0;i<ARRAYSIZE(labels);i++)SetDlgItemTextW(dlg,labels[i].control,rdp_text_in(locale,labels[i].message));
        layout_login_fields(dlg);
        CheckDlgButton(dlg,IDC_FILES,BST_CHECKED);
        wchar_t name[256];
        const wchar_t *target=(const wchar_t *)lp;
        wchar_t caption[128];swprintf(caption,ARRAYSIZE(caption),L"Calabi · %ls",rdp_text_in(locale,Rdp_Login));
        SetWindowTextW(dlg,caption);
        DWORD n=GetEnvironmentVariableW(L"CALABI_RDP_NAME",name,ARRAYSIZE(name));
        SetDlgItemTextW(dlg,IDC_DEVICE,n && n<ARRAYSIZE(name) && wcscmp(name,target)?name:sshLogin?L"Linux":rdp_text(Rdp_Device));
        SetDlgItemTextW(dlg,IDC_ADDRESS,target);
        SendDlgItemMessageW(dlg,IDC_ACCOUNT,0x1501,TRUE,(LPARAM)rdp_text(Rdp_AccountPlaceholder));
        SendDlgItemMessageW(dlg,IDC_PASSWORD,0x1501,TRUE,(LPARAM)rdp_text(Rdp_PasswordPlaceholder));
        SendDlgItemMessageW(dlg,IDC_ACCOUNT,EM_SETLIMITTEXT,CREDUI_MAX_USERNAME_LENGTH,0);
        SendDlgItemMessageW(dlg,IDC_PASSWORD,EM_SETLIMITTEXT,CREDUI_MAX_PASSWORD_LENGTH,0);
        SendDlgItemMessageW(dlg,IDC_PORT,EM_SETLIMITTEXT,5,0);
        SetDlgItemInt(dlg,IDC_PORT,sshLogin?22:PROBE_RDP_DEFAULT_PORT,FALSE);
        wchar_t port[6];
        DWORD portLength=GetEnvironmentVariableW(sshLogin?L"CALABI_SSH_PORT":L"CALABI_RDP_PORT",port,ARRAYSIZE(port));
        if(portLength && portLength<ARRAYSIZE(port)){
            SetDlgItemTextW(dlg,IDC_PORT,port);
            if(!login_port(dlg))SetDlgItemInt(dlg,IDC_PORT,sshLogin?22:PROBE_RDP_DEFAULT_PORT,FALSE);
        }
        if(GetEnvironmentVariableW(L"CALABI_RDP_CREDENTIAL_KEY",credentialKey,ARRAYSIZE(credentialKey))!=64)credentialKey[0]=0;
        if(!credentialKey[0]){
            ShowWindow(GetDlgItem(dlg,IDC_REMEMBER),SW_HIDE);ShowWindow(GetDlgItem(dlg,IDC_FORGET),SW_HIDE);
        }else{
            wchar_t previous[CREDUI_MAX_USERNAME_LENGTH+1];
            DWORD length=GetEnvironmentVariableW(L"CALABI_RDP_ACCOUNT_HINT",previous,ARRAYSIZE(previous));
            if(length && length<ARRAYSIZE(previous))SetDlgItemTextW(dlg,IDC_ACCOUNT,previous);
        }
        if(sshLogin)ssh_initialize(dlg);
        login_refresh_password_hint(dlg);
        LOGFONTW font={0};
        if(GetObjectW((HFONT)SendDlgItemMessageW(dlg,IDC_DEVICE,WM_GETFONT,0,0),sizeof(font),&font)){
            font.lfHeight=MulDiv(font.lfHeight,16,9);font.lfWeight=FW_SEMIBOLD;
            headingFont=CreateFontIndirectW(&font);
            if(headingFont)SendDlgItemMessageW(dlg,IDC_DEVICE,WM_SETFONT,(WPARAM)headingFont,TRUE);
        }
        BOOL dark=TRUE;DwmSetWindowAttribute(dlg,20,&dark,sizeof(dark));
        SendMessageW(dlg,WM_SETICON,ICON_SMALL,(LPARAM)LoadIconW(GetModuleHandleW(NULL),MAKEINTRESOURCEW(IDI_CALABI)));
        SendMessageW(dlg,DM_SETDEFID,IDOK,0);
        SetFocus(GetDlgItem(dlg,IDC_ACCOUNT));return FALSE;
    }
    case WM_NCHITTEST:{
        POINT pt={GET_X_LPARAM(lp),GET_Y_LPARAM(lp)};
        ScreenToClient(dlg,&pt);
        RECT grip={0,0,211,20};
        MapDialogRect(dlg,&grip);
        if(PtInRect(&grip,pt)){
            SetWindowLongPtrW(dlg,DWLP_MSGRESULT,HTCAPTION);
            return TRUE;
        }
        break;
    }
    case WM_NOTIFY:{
        NMCUSTOMDRAW *draw=(NMCUSTOMDRAW*)lp;
        if((draw->hdr.idFrom==IDC_FILES || draw->hdr.idFrom==IDC_REMEMBER) &&
           draw->hdr.code==NM_CUSTOMDRAW && draw->dwDrawStage==CDDS_PREPAINT) {
            HDC dc=draw->hdc;RECT r=draw->rc;
            FillRect(dc,&r,panelBrush);
            HFONT font=(HFONT)SendMessageW(draw->hdr.hwndFrom,WM_GETFONT,0,0);
            HGDIOBJ old=SelectObject(dc,font);TEXTMETRICW tm;GetTextMetricsW(dc,&tm);
            int size=max(12,tm.tmHeight-2),top=r.top+(r.bottom-r.top-size)/2;
            RECT box={r.left,top,r.left+size,top+size};
            BOOL checked=SendMessageW(draw->hdr.hwndFrom,BM_GETCHECK,0,0)==BST_CHECKED;
            rounded_box(dc,box,checked?accent:field,RGB(154,172,201),3);
            if(checked){HPEN pen=CreatePen(PS_SOLID,max(1,size/8),RGB(37,53,101));HGDIOBJ prev=SelectObject(dc,pen);
                MoveToEx(dc,box.left+size/4,top+size/2,NULL);LineTo(dc,box.left+size*2/5,top+size*3/4);
                LineTo(dc,box.left+size*4/5,top+size/4);SelectObject(dc,prev);DeleteObject(pen);}
            wchar_t label[128];GetWindowTextW(draw->hdr.hwndFrom,label,ARRAYSIZE(label));
            r.left+=size+max(6,size/2);SetBkMode(dc,TRANSPARENT);SetTextColor(dc,RGB(222,230,244));
            DrawTextW(dc,label,-1,&r,DT_SINGLELINE|DT_VCENTER|DT_NOPREFIX);
            if((draw->uItemState&CDIS_FOCUS) && !(SendMessageW(draw->hdr.hwndFrom,WM_QUERYUISTATE,0,0)&UISF_HIDEFOCUS))DrawFocusRect(dc,&r);
            SelectObject(dc,old);SetWindowLongPtrW(dlg,DWLP_MSGRESULT,CDRF_SKIPDEFAULT);return TRUE;
        }
        break;
    }
    case WM_CTLCOLORDLG:return (INT_PTR)panelBrush;
    case WM_CTLCOLORBTN:
        SetBkColor((HDC)wp,panel);
        return (INT_PTR)panelBrush;
    case WM_CTLCOLOREDIT:case WM_CTLCOLORSTATIC:{
        int id=GetDlgCtrlID((HWND)lp);
        BOOL edit=id==IDC_ACCOUNT||id==IDC_PASSWORD||id==IDC_ACCOUNT_LABEL||id==IDC_PASSWORD_LABEL||id==IDC_PORT||id==IDC_PORT_LABEL;
        COLORREF text=RGB(235,238,250);
        if(id==IDC_BRAND)text=RGB(185,196,213);
        if(id==IDC_ADDRESS)text=RGB(176,187,205);
        if(id==IDC_HINT)text=RGB(255,183,160);
        SetTextColor((HDC)wp,text);SetBkColor((HDC)wp,edit?field:panel);
        return (INT_PTR)(edit?fieldBrush:panelBrush);
    }
    case WM_PAINT:{
        PAINTSTRUCT ps;HDC dc=BeginPaint(dlg,&ps);
        FillRect(dc,&ps.rcPaint,panelBrush);
        RECT rows={14,52,222,112}, icon={196,21,222,42};
        MapDialogRect(dlg,&rows);MapDialogRect(dlg,&icon);
        rounded_box(dc,rows,field,RGB(66,73,85),12);
        int rowHeight=(rows.bottom-rows.top)/3;
        SetDCBrushColor(dc,RGB(67,74,87));
        for(int i=1;i<3;i++){
            int y=rows.top+i*rowHeight;
            RECT divider={rows.left+1,y,rows.right-1,y+1};
            FillRect(dc,&divider,GetStockObject(DC_BRUSH));
        }
        rounded_box(dc,icon,panel,RGB(70,80,95),10);
        RECT screen={202,27,216,34}, stand={205,36,213,37};
        MapDialogRect(dlg,&screen);MapDialogRect(dlg,&stand);
        rounded_box(dc,screen,panel,RGB(206,216,237),3);
        SetDCBrushColor(dc,RGB(206,216,237));FillRect(dc,&stand,GetStockObject(DC_BRUSH));
        HWND focus=GetFocus();
        int focusID=focus?GetDlgCtrlID(focus):0;
        if(focusID==IDC_ACCOUNT || focusID==IDC_PASSWORD || focusID==IDC_PORT){
            int top=rows.top+rowHeight*(focusID==IDC_PORT?2:focusID==IDC_PASSWORD?1:0);
            RECT bar={rows.left+2,top+6,rows.left+4,top+rowHeight-6};
            SetDCBrushColor(dc,RGB(144,158,200));FillRect(dc,&bar,GetStockObject(DC_BRUSH));
        }
        EndPaint(dlg,&ps);return TRUE;
    }
    case WM_DRAWITEM:{
        const DRAWITEMSTRUCT *item=(const DRAWITEMSTRUCT *)lp;
        BOOL primary=item->CtlID==IDOK,dismiss=item->CtlID==IDC_DISMISS,pressed=(item->itemState&ODS_SELECTED)!=0;
        RECT r=item->rcItem;
        FillRect(item->hDC,&r,panelBrush);
        if(primary){
            COLORREF fill=pressed?RGB(184,196,234):accent;
            draw_pill(item->hDC,r,fill);
        }
        SetTextColor(item->hDC,primary?RGB(37,53,101):pressed?RGB(146,158,182):RGB(193,201,214));
        SetBkMode(item->hDC,TRANSPARENT);
        wchar_t label[64]={0};
        GetWindowTextW(item->hwndItem,label,ARRAYSIZE(label));
        const wchar_t *text=primary?(connecting?rdp_text(Rdp_Connecting):rdp_text(Rdp_Connect)):dismiss?L"×":label;
        DrawTextW(item->hDC,text,-1,&r,(primary||dismiss?DT_CENTER:DT_LEFT)|DT_VCENTER|DT_SINGLELINE);
        if((item->itemState & (ODS_FOCUS|ODS_NOFOCUSRECT)) == ODS_FOCUS){
            // Follow Windows keyboard cues without flashing an XOR rectangle on click.
            int h=r.bottom-r.top;
            int x=primary||dismiss?(r.left+r.right)/2-h/6:r.left+h/5;
            RECT cue={x,r.bottom-h/4,x+h/3,r.bottom-h/4+2};
            SetDCBrushColor(item->hDC,primary?RGB(73,89,137):RGB(154,172,213));
            FillRect(item->hDC,&cue,GetStockObject(DC_BRUSH));
        }
        return TRUE;
    }
    case WM_COMMAND:
        if(HIWORD(wp)==EN_CHANGE && (LOWORD(wp)==IDC_ACCOUNT || LOWORD(wp)==IDC_PORT)){
            login_refresh_password_hint(dlg);return TRUE;
        }
        if(HIWORD(wp)==EN_SETFOCUS || HIWORD(wp)==EN_KILLFOCUS){InvalidateRect(dlg,NULL,FALSE);return TRUE;}
        if(LOWORD(wp)==IDOK){
            if(!connecting){
                if(sshLogin)ssh_submit(dlg);
                else if(read_credentials(dlg))start_connection(dlg);
            }
            return TRUE;
        }
        if(LOWORD(wp)==IDC_FORGET && !connecting){
            wchar_t account[CREDUI_MAX_USERNAME_LENGTH+1],target[1024];
            GetDlgItemTextW(dlg,IDC_ACCOUNT,account,ARRAYSIZE(account));
            if(credential_target(account,login_port(dlg),target)){
                BOOL deleted=CredDeleteW(target,CRED_TYPE_GENERIC,0);
                set_login_hint(dlg,deleted?rdp_text(Rdp_Cleared):
                    GetLastError()==ERROR_NOT_FOUND?rdp_text(Rdp_NoCredentials):rdp_text(Rdp_ClearFailed));
                login_refresh_password_hint(dlg);
            }
            return TRUE;
        }
        if(LOWORD(wp)==IDCANCEL || LOWORD(wp)==IDC_DISMISS){cancel_login();return TRUE;}
        break;
    case WM_CLOSE:cancel_login();return TRUE;
    case MSG_SSH_RESULT:
        if(sshLogin){ssh_result(dlg,(unsigned)wp);return TRUE;}
        break;
    }
    return FALSE;
}

int WINAPI wWinMain(HINSTANCE instance,HINSTANCE prev,PWSTR args,int show) {
    (void)prev;
    if(!wcscmp(args,L"--self-test")){
        RECT r=fit((RECT){0,0,1600,1000},1920,1080);
        return (r.top==50 && r.bottom==950 && r.right==1600)?0:1;
    }
    if(!wcscmp(args,L"--check-pin")){
        static const uint8_t cert[]="-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----";
        return probe_verify_leaf(cert,sizeof(cert)-1)?0:1;
    }
    sshLogin=!wcscmp(args,L"--ssh-login");
    wchar_t target[32],title[128];
    DWORD size=GetEnvironmentVariableW(L"CALABI_P0_PEER",target,ARRAYSIZE(target));
    if(!size||size>=ARRAYSIZE(target)||(!sshLogin && !GetEnvironmentVariableA("CALABI_RDP_LOCAL",NULL,0))||
       !WideCharToMultiByte(CP_UTF8,0,target,-1,host,sizeof(host),NULL,NULL))return 1;
    SetProcessDPIAware();
    if(sshLogin)return ssh_dialog(instance,target);
    rdpLoginParent=login_parent_pid(L"CALABI_RDP_PARENT_PID");
    swprintf(title,ARRAYSIZE(title),L"Calabi · %ls %ls  (F11: %ls)",rdp_text(Rdp_Login),target,rdp_text(Rdp_Fullscreen));
    WNDCLASSW wc={0};wc.lpfnWndProc=proc;wc.hInstance=instance;wc.lpszClassName=L"CalabiRdpSession";
    wc.hIcon=LoadIconW(instance,MAKEINTRESOURCEW(IDI_CALABI));
    wc.hCursor=LoadCursor(NULL,IDC_ARROW);if(!RegisterClassW(&wc))return 1;
    window=CreateWindowExW(0,wc.lpszClassName,title,WS_OVERLAPPEDWINDOW|WS_CLIPCHILDREN,CW_USEDEFAULT,CW_USEDEFAULT,1180,760,NULL,NULL,instance,NULL);
    if(!window)return 1;
    ImmAssociateContext(window,NULL);
    panelBrush=CreateSolidBrush(panel);fieldBrush=CreateSolidBrush(field);
    loginWindow=CreateDialogParamW(instance,MAKEINTRESOURCEW(IDD_LOGIN),NULL,login_proc,(LPARAM)target);
    if(!loginWindow){DestroyWindow(window);return 1;}
    if(rdpLoginParent){
        char reply[32];
        if(puts("rdp-login-ready")<0 || fflush(stdout) || !fgets(reply,sizeof(reply),stdin) ||
           (strcmp(reply,"rdp-login-show\n") && strcmp(reply,"rdp-login-show\r\n"))){
            DestroyWindow(loginWindow);DestroyWindow(window);return 1;
        }
    }
    SetWindowPos(loginWindow,HWND_TOP,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE|SWP_SHOWWINDOW);SetForegroundWindow(loginWindow);SetFocus(GetDlgItem(loginWindow,IDC_ACCOUNT));
    MSG msg;
    while(GetMessageW(&msg,NULL,0,0)>0){
        if(!loginWindow || !IsDialogMessageW(loginWindow,&msg)){TranslateMessage(&msg);DispatchMessageW(&msg);}
    }
    DeleteObject(panelBrush);DeleteObject(fieldBrush);if(headingFont)DeleteObject(headingFont);
    free(pixels);SecureZeroMemory(password,sizeof(password));
    return 0;
}
