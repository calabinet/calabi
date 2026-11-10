// Embedded destination OLE adapter: remote Windows -> this controller.
// Reuses the same Files/Stream and independent progress UI as calabi-paste.
#include "windows_shell_receive.h"
extern "C" {
#include "clipboard_payload.h"
}
static std::thread receiveThread;
static std::atomic<HWND> receiveWindow{nullptr};
static HANDLE receiveReady;
static Files *receiveObject;
static BatchPtr receiveBatch;
static std::mutex receiveReadLock;
static std::mutex receiveCancelLock;
static std::atomic<bool> receiveStopping{false};
static std::atomic<uint64_t> receiveGeneration{0};
struct ReceiveOffer {BatchPtr batch;DWORD sequence;};

static std::string bridge_rpc(const std::string &){return "ok";}
static void bridge_cancel(BatchPtr b){
    std::lock_guard<std::mutex> guard(receiveCancelLock);
    if(!receiveStopping && !b->cancelSent.exchange(true))clipboard_shell_cancel(std::stoull(b->marker));
}
static HRESULT bridge_read(BatchPtr b,unsigned index,ULONGLONG offset,void *out,ULONG count,ULONG *got){
    *got=0;show_paste_progress(b);
    std::lock_guard<std::mutex> guard(receiveReadLock);
    if(receiveStopping || b->cancelled)return HRESULT_FROM_WIN32(ERROR_CANCELLED);
    // Bound each wire request even when Explorer asks for a much larger Read.
    ULONG done=0;
    while(done<count){
        if(receiveStopping || b->cancelled)return HRESULT_FROM_WIN32(ERROR_CANCELLED);
        unsigned n=std::min<ULONG>(65536,count-done);
        if(!clipboard_shell_read(std::stoull(b->marker),index,offset+done,(BYTE*)out+done,n))
            return b->cancelled?HRESULT_FROM_WIN32(ERROR_CANCELLED):STG_E_READFAULT;
        done+=n;
        // Read/Seek can repeat ranges; count only each file's contiguous prefix.
        // Only one Shell Read executes at a time under receiveReadLock.
        auto &prefix=b->receivedPrefixes;
        if(prefix.size()<b->descriptors.size())prefix.resize(b->descriptors.size());
        if(offset+done-n<=prefix[index] && offset+done>prefix[index]){
            b->read+=offset+done-prefix[index];prefix[index]=offset+done;
        }
    }
    if(b->cancelled)return HRESULT_FROM_WIN32(ERROR_CANCELLED);
    *got=done;return S_OK;
}
static LRESULT CALLBACK receive_proc(HWND w,UINT msg,WPARAM wp,LPARAM lp){
    if(msg==WM_APP+30){
        std::unique_ptr<ReceiveOffer> offer((ReceiveOffer*)lp);
        if(receiveStopping || std::stoull(offer->batch->marker)!=receiveGeneration || GetClipboardSequenceNumber()!=offer->sequence)return 0;
        auto next=new Files(offer->batch);
        HRESULT published=E_FAIL;
        for(unsigned attempt=0;attempt<20;attempt++){
            if(receiveStopping || std::stoull(offer->batch->marker)!=receiveGeneration || GetClipboardSequenceNumber()!=offer->sequence)break;
            published=OleSetClipboard(next);if(SUCCEEDED(published))break;Sleep(10);
        }
        if(SUCCEEDED(published)){
            if(receiveBatch){receiveBatch->cancelled=true;bridge_cancel(receiveBatch);}
            if(receiveObject)receiveObject->Release();receiveObject=next;receiveBatch=offer->batch;
        }else {fprintf(stderr,"rdp_receive publish_failed=0x%08lX\n",published);fflush(stderr);next->Release();}
        return 0;
    }
    if(msg==WM_APP+31){
        if(receiveBatch && std::stoull(receiveBatch->marker)!=receiveGeneration && !receiveBatch->finished)receiveBatch->cancelled=true;
        return 0;
    }
    if(msg==WM_CLOSE){
        if(receiveBatch){receiveBatch->cancelled=true;bridge_cancel(receiveBatch);}
        if(receiveObject){if(OleIsCurrentClipboard(receiveObject)==S_OK)OleSetClipboard(nullptr);receiveObject->Release();receiveObject=nullptr;}
        receiveBatch.reset();DestroyWindow(w);return 0;
    }
    if(msg==WM_DESTROY){PostQuitMessage(0);return 0;}
    return DefWindowProcW(w,msg,wp,lp);
}
static bool receive_start(){
    if(receiveThread.joinable())return receiveWindow!=nullptr;
    receiveStopping=false;
    receiveReady=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!receiveReady)return false;
    HDESK desktop=GetThreadDesktop(GetCurrentThreadId());
    receiveThread=std::thread([desktop]{
        HWND w=nullptr;bool ole=false;
        if(SetThreadDesktop(desktop) && SUCCEEDED(OleInitialize(nullptr))){
            ole=true;
            if(start_progress_ui()){
                WNDCLASSW cls={};cls.hInstance=GetModuleHandleW(nullptr);cls.lpfnWndProc=receive_proc;cls.lpszClassName=L"CalabiRdpReceive";RegisterClassW(&cls);
                w=CreateWindowW(cls.lpszClassName,L"",0,0,0,0,0,HWND_MESSAGE,nullptr,cls.hInstance,nullptr);
            }
        }
        receiveWindow=w;SetEvent(receiveReady);
        if(w){MSG m;while(GetMessageW(&m,nullptr,0,0)>0){TranslateMessage(&m);DispatchMessageW(&m);}}
        stop_progress_ui();if(ole)OleUninitialize();receiveWindow=nullptr;
    });
    WaitForSingleObject(receiveReady,INFINITE);CloseHandle(receiveReady);receiveReady=nullptr;
    return receiveWindow!=nullptr;
}
extern "C" int shell_receive_offer(const uint8_t *data,size_t length,uint64_t generation,uint64_t sequence){
    if(!clip_valid_files(data,length) || !generation || !receive_start())return 0;
    unsigned count=0;memcpy(&count,data,4);
    if(!count || count>32 || length!=4+count*sizeof(FILEDESCRIPTORW))return 0;
    auto b=std::make_shared<Batch>();b->marker=std::to_string(generation);b->total=0;
    b->descriptors.resize(count);memcpy(b->descriptors.data(),data+4,length-4);
    for(size_t i=0;i<b->descriptors.size();i++){
        auto &d=b->descriptors[i];
        wchar_t stem[260];wcscpy(stem,d.cFileName);if(auto dot=wcschr(stem,L'.'))*dot=0;
        if(!_wcsicmp(stem,L"CON") || !_wcsicmp(stem,L"PRN") || !_wcsicmp(stem,L"AUX") || !_wcsicmp(stem,L"NUL") ||
           !_wcsicmp(stem,L"CONIN$") || !_wcsicmp(stem,L"CONOUT$") ||
           (wcslen(stem)==4 && (!_wcsnicmp(stem,L"COM",3) || !_wcsnicmp(stem,L"LPT",3)) &&
            ((stem[3]>=L'0' && stem[3]<=L'9') || stem[3]==0xb9 || stem[3]==0xb2 || stem[3]==0xb3)))return 0;
        for(size_t j=0;j<i;j++)if(!_wcsicmp(d.cFileName,b->descriptors[j].cFileName))return 0;
        d.dwFlags=FD_FILESIZE|FD_ATTRIBUTES|FD_UNICODE;d.dwFileAttributes=FILE_ATTRIBUTE_NORMAL;
        b->total+=((ULONGLONG)d.nFileSizeHigh<<32)|d.nFileSizeLow;
    }
    auto offer=new ReceiveOffer{b,(DWORD)sequence};
    receiveGeneration=generation;
    if(!PostMessageW(receiveWindow,WM_APP+30,0,(LPARAM)offer)){delete offer;return 0;}return 1;
}
extern "C" void shell_receive_invalidate(){
    receiveGeneration=0;if(HWND w=receiveWindow)PostMessageW(w,WM_APP+31,0,0);
}
extern "C" void shell_receive_stop(){
    receiveStopping=true;
    if(HWND w=receiveWindow)PostMessageW(w,WM_CLOSE,0,0);
    if(receiveThread.joinable())receiveThread.join();
    // clipboard_stop wakes any wire Read before calling us. Join its critical
    // section before the C adapter destroys its lock and response event.
    std::lock_guard<std::mutex> guard(receiveReadLock);
    std::lock_guard<std::mutex> cancelGuard(receiveCancelLock);
}
