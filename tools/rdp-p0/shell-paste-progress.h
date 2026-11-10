#pragma once
#include "rdp_locale.h"
// Progress runs independently of the OLE STA and all synchronous file RPCs.
static std::atomic<HWND> pasteProgressWindow{nullptr};
static std::thread pasteProgressThread;
static HANDLE pasteProgressReady;
static BatchPtr uiBatch; // only the progress thread touches this shared_ptr
static HFONT uiFont,uiHeading,uiSmallFont;
static RECT hideHit,cancelHit,expandHit={24,220,220,248},prevHit,nextHit;
static bool uiExpanded=false;
static unsigned uiPage=0;
static constexpr int compactHeight=310,expandedHeight=600,rowsPerPage=5;
static void progress_layout(HWND w){
    RECT r;GetWindowRect(w,&r);int height=uiExpanded?expandedHeight:compactHeight;
    MONITORINFO m={};m.cbSize=sizeof(m);GetMonitorInfoW(MonitorFromWindow(w,MONITOR_DEFAULTTONEAREST),&m);
    int y=std::max(m.rcWork.top,std::min(r.bottom,m.rcWork.bottom)-height);
    SetWindowPos(w,nullptr,r.left,y,480,height,SWP_NOACTIVATE|SWP_NOZORDER);
    hideHit={24,height-54,112,height-18};cancelHit={320,height-54,456,height-18};
    prevHit={270,510,350,538};nextHit={360,510,452,538};
}
static void progress_text(HDC dc,const wchar_t *text,RECT rect,COLORREF color,HFONT font,UINT flags=DT_LEFT|DT_SINGLELINE|DT_VCENTER|DT_END_ELLIPSIS){
    SetTextColor(dc,color);SetBkMode(dc,TRANSPARENT);auto old=SelectObject(dc,font);DrawTextW(dc,text,-1,&rect,flags);SelectObject(dc,old);
}
static std::wstring progress_bytes(ULONGLONG bytes){
    wchar_t text[64];
    if(bytes<1024)swprintf(text,64,L"%llu B",bytes);
    else if(bytes<1048576)swprintf(text,64,L"%.1f KiB",bytes/1024.0);
    else if(bytes<1073741824)swprintf(text,64,L"%.1f MiB",bytes/1048576.0);
    else swprintf(text,64,L"%.1f GiB",bytes/1073741824.0);
    return text;
}
static void progress_highlight(HDC dc,RECT r){
    auto brush=CreateSolidBrush(RGB(46,58,78));FillRect(dc,&r,brush);DeleteObject(brush);
    r.right=r.left+3;brush=CreateSolidBrush(RGB(161,184,255));FillRect(dc,&r,brush);DeleteObject(brush);
}
static bool paste_cancelled(HRESULT result){
    return result==HRESULT_FROM_WIN32(ERROR_CANCELLED) || result==COPYENGINE_E_USER_CANCELLED;
}
static const wchar_t *paste_failure_detail(HRESULT result,RdpLocale locale=rdp_locale_current()){
    switch(result){
    case HRESULT_FROM_WIN32(ERROR_TIMEOUT): return rdp_text_in(locale,Rdp_NetworkTimeout);
    case HRESULT_FROM_WIN32(ERROR_CONNECTION_ABORTED): return rdp_text_in(locale,Rdp_SessionEnded);
    case HRESULT_FROM_WIN32(ERROR_INVALID_STATE): return rdp_text_in(locale,Rdp_OfferExpired);
    case HRESULT_FROM_WIN32(ERROR_FILE_INVALID): return rdp_text_in(locale,Rdp_SourceChanged);
    case HRESULT_FROM_WIN32(ERROR_ACCESS_DENIED):
    case STG_E_ACCESSDENIED:
    case HRESULT_FROM_WIN32(ERROR_WRITE_PROTECT): return rdp_text_in(locale,Rdp_TargetReadOnly);
    case HRESULT_FROM_WIN32(ERROR_DISK_FULL):
    case HRESULT_FROM_WIN32(ERROR_HANDLE_DISK_FULL):
    case STG_E_MEDIUMFULL: return rdp_text_in(locale,Rdp_DiskFull);
    case HRESULT_FROM_WIN32(ERROR_PATH_NOT_FOUND):
    case HRESULT_FROM_WIN32(ERROR_DIRECTORY): return rdp_text_in(locale,Rdp_TargetUnavailable);
    case HRESULT_FROM_WIN32(ERROR_BUSY): return rdp_text_in(locale,Rdp_ReceiveBusy);
    case DV_E_FORMATETC: return rdp_text_in(locale,Rdp_NoRemoteFiles);
    default: return rdp_text_in(locale,Rdp_CopyAgain);
    }
}
static void progress_paint(HWND window,HDC dc){
    RECT area;GetClientRect(window,&area);HBRUSH bg=CreateSolidBrush(RGB(31,36,44));FillRect(dc,&area,bg);DeleteObject(bg);
    if(!uiBatch)return;
    RdpLocale locale=rdp_locale_current();
    auto b=uiBatch;
    bool stopped=b->cancelled,finished=b->finished;
    HRESULT result=b->interruption;
    if(SUCCEEDED(result) && finished)result=b->result;
    bool cancelled=paste_cancelled(result) || (stopped && !finished && SUCCEEDED(result));
    bool failed=FAILED(result) && !cancelled;
    const wchar_t *heading=cancelled?rdp_text_in(locale,Rdp_ReceiveCancelled):failed?rdp_text_in(locale,Rdp_PasteIncomplete):finished?rdp_text_in(locale,Rdp_PasteDone):rdp_text_in(locale,Rdp_ReceiveActive);
    std::wstring title=std::wstring(L"CALABI  /  ")+rdp_text_in(locale,Rdp_CopyTitle);
    progress_text(dc,title.c_str(),{24,17,450,39},RGB(160,174,196),uiFont);
    progress_text(dc,heading,{24,47,452,80},RGB(240,244,252),uiHeading);
    std::vector<FileProgress> files;unsigned current;
    {std::lock_guard<std::mutex> guard(b->progressLock);files=b->fileProgress;current=b->currentFile;}
    files.resize(b->descriptors.size());current=files.empty()?0:std::min<unsigned>(current,(unsigned)files.size()-1);
    auto sizeOf=[&](size_t i){auto &d=b->descriptors[i];return ((ULONGLONG)d.nFileSizeHigh<<32)|d.nFileSizeLow;};
    auto status=[&](size_t i)->const wchar_t*{
        auto &f=files[i];bool complete=f.touched && f.bytes==sizeOf(i);
        if(f.failed && !cancelled)return rdp_text_in(locale,Rdp_Failed);
        if(complete && finished && SUCCEEDED(result) && !cancelled)return rdp_text_in(locale,Rdp_Completed);
        if(complete)return rdp_text_in(locale,Rdp_Received);
        if(cancelled)return rdp_text_in(locale,Rdp_Cancelled);
        if(finished || stopped)return f.touched?rdp_text_in(locale,Rdp_Incomplete):rdp_text_in(locale,Rdp_NotTransferred);
        return f.touched?rdp_text_in(locale,Rdp_Transferring):rdp_text_in(locale,Rdp_Waiting);
    };
    size_t completed=0;for(size_t i=0;i<files.size();i++)if(files[i].touched && files[i].bytes==sizeOf(i))completed++;
    ULONGLONG done=std::min(b->read.load(),b->total);
    unsigned percent=b->total?(unsigned)(100*done/b->total):(finished && SUCCEEDED(result)?100:0);
    wchar_t detail[200];swprintf(detail,200,L"%ls  %ls / %ls  ·  %u%%  ·  %ls %zu/%zu",
        rdp_text_in(locale,Rdp_TotalProgress),progress_bytes(done).c_str(),progress_bytes(b->total).c_str(),percent,rdp_text_in(locale,Rdp_Received),completed,files.size());
    progress_text(dc,detail,{24,83,452,109},RGB(171,185,206),uiSmallFont);
    auto bar=[&](int top,unsigned value){RECT r={24,top,452,top+6};auto brush=CreateSolidBrush(RGB(61,70,85));FillRect(dc,&r,brush);DeleteObject(brush);
        r.right=24+428*(int)value/100;brush=CreateSolidBrush(cancelled?RGB(144,151,163):RGB(145,172,255));FillRect(dc,&r,brush);DeleteObject(brush);};
    bar(117,percent);
    if(!files.empty()){
        if(!finished && !stopped)progress_highlight(dc,{16,130,460,201});
        progress_text(dc,b->descriptors[current].cFileName,{24,134,452,160},RGB(235,240,250),uiFont);
        auto &f=files[current];auto size=sizeOf(current);unsigned pct=size?(unsigned)(100*f.bytes/size):(f.touched?100:0);
        swprintf(detail,200,L"%ls  ·  %ls / %ls  ·  %u%%",status(current),progress_bytes(f.bytes).c_str(),progress_bytes(size).c_str(),pct);
        progress_text(dc,detail,{24,163,452,189},f.failed?RGB(255,180,165):RGB(171,185,206),uiFont);
    }
    if(failed)progress_text(dc,paste_failure_detail(result,locale),{24,188,452,221},RGB(255,180,165),uiSmallFont,DT_LEFT|DT_WORDBREAK|DT_END_ELLIPSIS);
    progress_text(dc,uiExpanded?rdp_text_in(locale,Rdp_Collapse):rdp_text_in(locale,Rdp_Expand),expandHit,RGB(180,198,255),uiFont);
    if(uiExpanded){
        size_t first=uiPage*rowsPerPage,last=std::min(files.size(),first+rowsPerPage);
        for(size_t i=first;i<last;i++){
            int y=254+(int)(i-first)*50;
            progress_text(dc,b->descriptors[i].cFileName,{24,y,325,y+23},RGB(220,229,242),uiFont);
            progress_text(dc,status(i),{334,y,452,y+23},files[i].failed?RGB(255,180,165):RGB(171,185,206),uiFont,DT_RIGHT|DT_SINGLELINE|DT_VCENTER);
            swprintf(detail,200,L"%ls / %ls  ·  %u%%",progress_bytes(files[i].bytes).c_str(),progress_bytes(sizeOf(i)).c_str(),sizeOf(i)?(unsigned)(100*files[i].bytes/sizeOf(i)):(files[i].touched?100:0));
            progress_text(dc,detail,{24,y+23,452,y+45},RGB(153,169,193),uiFont);
        }
        swprintf(detail,200,L"%u / %zu",uiPage+1,std::max<size_t>(1,(files.size()+rowsPerPage-1)/rowsPerPage));
        progress_text(dc,detail,{24,510,220,538},RGB(171,185,206),uiFont);
        progress_text(dc,rdp_text_in(locale,Rdp_Previous),prevHit,RGB(180,198,255),uiFont);
        progress_text(dc,rdp_text_in(locale,Rdp_Next),nextHit,RGB(180,198,255),uiFont);
    }
    progress_text(dc,rdp_text_in(locale,Rdp_Hide),hideHit,RGB(205,215,231),uiFont,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
    auto brush=CreateSolidBrush(RGB(219,226,255));FillRect(dc,&cancelHit,brush);DeleteObject(brush);
    progress_text(dc,finished||stopped?rdp_text_in(locale,Rdp_Close):rdp_text_in(locale,Rdp_Cancel),cancelHit,RGB(34,49,85),uiFont,DT_CENTER|DT_VCENTER|DT_SINGLELINE);
}
static LRESULT CALLBACK progress_proc(HWND w,UINT msg,WPARAM wp,LPARAM lp){
    switch(msg){
    case WM_CREATE:
        uiFont=CreateFontW(-16,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");
        uiHeading=CreateFontW(-23,0,0,0,FW_SEMIBOLD,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");
        uiSmallFont=CreateFontW(-13,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Microsoft YaHei UI");
        SetTimer(w,1,150,nullptr);return 0;
    case WM_APP+20:{
        std::unique_ptr<BatchPtr> value((BatchPtr*)lp);uiBatch=*value;uiExpanded=false;uiPage=0;
        RECT work={0,0,1024,768};
        MONITORINFO monitor={};monitor.cbSize=sizeof(monitor);
        HMONITOR screen=MonitorFromWindow(GetForegroundWindow(),MONITOR_DEFAULTTOPRIMARY);
        if(GetMonitorInfoW(screen,&monitor))work=monitor.rcWork;
        else SystemParametersInfoW(SPI_GETWORKAREA,0,&work,0);
        // ShowWindow can apply inherited startup show/z-order settings. Set the
        // final position and topmost state AFTER it, not before it.
        ShowWindow(w,SW_SHOWNOACTIVATE);
        int x=std::max(work.left,work.right-500),y=std::max(work.top,work.bottom-286);
        SetLastError(0);
        BOOL positioned=SetWindowPos(w,HWND_TOPMOST,x,y,480,250,SWP_NOACTIVATE|SWP_NOOWNERZORDER|SWP_SHOWWINDOW);
        progress_layout(w);DWORD error=positioned?0:GetLastError();RECT actual={};GetWindowRect(w,&actual);
        fprintf(stderr,"paste_ui visible=%d topmost=%d show_ok=%d rect=%ld,%ld,%ld,%ld error=%lu\n",
            (GetWindowLongPtrW(w,GWL_STYLE)&WS_VISIBLE)!=0,(GetWindowLongPtrW(w,GWL_EXSTYLE)&WS_EX_TOPMOST)!=0,
            positioned,actual.left,actual.top,actual.right,actual.bottom,error);fflush(stderr);
        InvalidateRect(w,nullptr,FALSE);return 0;}
    case WM_TIMER:InvalidateRect(w,nullptr,FALSE);return 0;
    case WM_ERASEBKGND:return 1;
    case WM_PRINTCLIENT:progress_paint(w,(HDC)wp);return 0;
    case WM_PAINT:{PAINTSTRUCT ps;HDC dc=BeginPaint(w,&ps);RECT r;GetClientRect(w,&r);HDC mem=CreateCompatibleDC(dc);HBITMAP image=CreateCompatibleBitmap(dc,r.right,r.bottom);auto old=SelectObject(mem,image);progress_paint(w,mem);BitBlt(dc,0,0,r.right,r.bottom,mem,0,0,SRCCOPY);SelectObject(mem,old);DeleteObject(image);DeleteDC(mem);EndPaint(w,&ps);return 0;}
    case WM_LBUTTONUP:{POINT pt={static_cast<short>(LOWORD(lp)),static_cast<short>(HIWORD(lp))};
        if(PtInRect(&expandHit,pt)){uiExpanded=!uiExpanded;progress_layout(w);InvalidateRect(w,nullptr,FALSE);return 0;}
        if(uiExpanded && PtInRect(&prevHit,pt)){if(uiPage)uiPage--;InvalidateRect(w,nullptr,FALSE);return 0;}
        if(uiExpanded && PtInRect(&nextHit,pt)){if(uiBatch && (uiPage+1)*rowsPerPage<uiBatch->descriptors.size())uiPage++;InvalidateRect(w,nullptr,FALSE);return 0;}
        if(PtInRect(&hideHit,pt)){ShowWindow(w,SW_HIDE);return 0;}
        if(PtInRect(&cancelHit,pt))SendMessageW(w,WM_COMMAND,2,0);return 0;}
    case WM_COMMAND:
        if(wp==2 && uiBatch){
            if(uiBatch->finished || uiBatch->cancelled){ShowWindow(w,SW_HIDE);return 0;}
            auto b=uiBatch;b->cancel();
            std::thread([b]{bridge_cancel(b);}).detach();InvalidateRect(w,nullptr,FALSE);
        }return 0;
    case WM_KEYDOWN:if(wp==VK_ESCAPE)ShowWindow(w,SW_HIDE);return 0;
    case WM_CLOSE:ShowWindow(w,SW_HIDE);return 0;
    case WM_APP+21:DestroyWindow(w);return 0;
    case WM_DESTROY:DeleteObject(uiFont);DeleteObject(uiHeading);DeleteObject(uiSmallFont);uiBatch.reset();PostQuitMessage(0);return 0;
    }
    return DefWindowProcW(w,msg,wp,lp);
}
static bool start_progress_ui(){
    if(pasteProgressThread.joinable())return pasteProgressWindow!=nullptr;
    pasteProgressReady=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!pasteProgressReady)return false;
    HDESK desktop=GetThreadDesktop(GetCurrentThreadId());
    pasteProgressThread=std::thread([desktop]{
        HWND w=nullptr;
        if(SetThreadDesktop(desktop)){
            WNDCLASSW cls={};cls.hInstance=GetModuleHandleW(nullptr);cls.lpfnWndProc=progress_proc;cls.lpszClassName=L"CalabiPasteProgress";cls.hCursor=LoadCursor(nullptr,IDC_ARROW);RegisterClassW(&cls);
            std::wstring caption=std::wstring(L"Calabi · ")+rdp_text(Rdp_ReceiveTitle);
            w=CreateWindowExW(WS_EX_TOPMOST|WS_EX_TOOLWINDOW|WS_EX_NOACTIVATE,cls.lpszClassName,caption.c_str(),WS_POPUP|WS_BORDER,0,0,480,250,nullptr,nullptr,cls.hInstance,nullptr);
        }
        pasteProgressWindow=w;SetEvent(pasteProgressReady);
        if(w){MSG m;while(GetMessageW(&m,nullptr,0,0)>0){TranslateMessage(&m);DispatchMessageW(&m);}}
        pasteProgressWindow=nullptr;
    });
    WaitForSingleObject(pasteProgressReady,INFINITE);CloseHandle(pasteProgressReady);pasteProgressReady=nullptr;
    return pasteProgressWindow!=nullptr;
}
static void stop_progress_ui(){if(HWND w=pasteProgressWindow)PostMessageW(w,WM_APP+21,0,0);if(pasteProgressThread.joinable())pasteProgressThread.join();}
static void show_paste_progress(BatchPtr b){
    if(b->progressShown.exchange(true))return;
    HWND w=pasteProgressWindow;if(!w){b->progressShown=false;return;}
    auto value=new BatchPtr(b);if(!PostMessageW(w,WM_APP+20,0,(LPARAM)value)){delete value;b->progressShown=false;}
}
