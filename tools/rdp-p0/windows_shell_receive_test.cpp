// All clipboard and UI state belongs to an anonymous, invisible test desktop.
#define CALABI_SHELL_RECEIVE
#include "shell-paste-probe.cpp"
static std::atomic<unsigned> wireReads{0};
static std::atomic<uint64_t> allowed{1};
static HANDLE blocked,unblock;
static std::atomic<bool> blockReads{false};
extern "C" int clipboard_shell_read(uint64_t generation,unsigned index,uint64_t offset,void *data,unsigned count){
    wireReads++;
    if(blockReads){SetEvent(blocked);WaitForSingleObject(unblock,5000);}
    if(generation!=allowed)return 0;
    for(unsigned i=0;i<count;i++)((BYTE*)data)[i]=(BYTE)((offset+i+index)%251);
    return 1;
}
extern "C" void clipboard_shell_cancel(uint64_t generation){if(allowed==generation){allowed=0;SetEvent(unblock);}}
static std::vector<BYTE> manifest(){
    std::vector<BYTE> data(4+2*sizeof(FILEDESCRIPTORW));clip_put32(data.data(),2);
    auto d=(FILEDESCRIPTORW*)(data.data()+4);
    for(unsigned i=0;i<2;i++){d[i].dwFlags=FD_FILESIZE|FD_ATTRIBUTES;d[i].dwFileAttributes=FILE_ATTRIBUTE_NORMAL;d[i].nFileSizeLow=i?0:4*1024*1024;}
    wcscpy(d[0].cFileName,L"远程-测试.bin");wcscpy(d[1].cFileName,L"empty.txt");return data;
}
static IDataObject *publish(uint64_t generation){
    auto data=manifest();allowed=generation;
    DWORD sequence=GetClipboardSequenceNumber();
    assert(shell_receive_offer(data.data(),data.size(),generation,sequence));
    IDataObject *object=nullptr;
    for(unsigned i=0;i<200;i++){
        MSG message;while(PeekMessageW(&message,nullptr,0,0,PM_REMOVE)){TranslateMessage(&message);DispatchMessageW(&message);}
        if(GetClipboardSequenceNumber()!=sequence && IsClipboardFormatAvailable(RegisterClipboardFormatW(CFSTR_FILEDESCRIPTORW)) && SUCCEEDED(OleGetClipboard(&object)))break;
        Sleep(10);
    }
    assert(object);return object;
}
static IStream *stream(IDataObject *object,unsigned index){
    FORMATETC f={(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_FILECONTENTS),nullptr,DVASPECT_CONTENT,(LONG)index,TYMED_ISTREAM};
    STGMEDIUM m={};assert(SUCCEEDED(object->GetData(&f,&m)));return m.pstm;
}
int main(){
    auto station=CreateWindowStationW(nullptr,0,WINSTA_ALL_ACCESS,nullptr);assert(station && SetProcessWindowStation(station));
    auto desktop=CreateDesktopW(L"reverse",nullptr,nullptr,0,GENERIC_ALL,nullptr);assert(desktop && SetThreadDesktop(desktop));
    assert(SUCCEEDED(OleInitialize(nullptr)));
    blocked=CreateEventW(nullptr,TRUE,FALSE,nullptr);unblock=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    auto object=publish(1);assert(wireReads==0); // Copy/manifest never downloads.
    FORMATETC f={(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_FILEDESCRIPTORW),nullptr,DVASPECT_CONTENT,-1,TYMED_HGLOBAL};
    STGMEDIUM m={};assert(SUCCEEDED(object->GetData(&f,&m)));
    auto group=(FILEGROUPDESCRIPTORW*)GlobalLock(m.hGlobal);assert(group->cItems==2 && !(group->fgd[0].dwFlags&FD_PROGRESSUI));GlobalUnlock(m.hGlobal);ReleaseStgMedium(&m);
    IDataObjectAsyncCapability *operation=nullptr;assert(SUCCEEDED(object->QueryInterface(IID_IDataObjectAsyncCapability,(void**)&operation)));
    assert(SUCCEEDED(operation->StartOperation(nullptr)));
    for(unsigned i=0;i<200 && !(GetWindowLongPtrW(pasteProgressWindow,GWL_STYLE)&WS_VISIBLE);i++)Sleep(10);
    assert(GetWindowLongPtrW(pasteProgressWindow,GWL_STYLE)&WS_VISIBLE);
    assert(GetWindowLongPtrW(pasteProgressWindow,GWL_EXSTYLE)&WS_EX_TOPMOST);
    auto input=stream(object,0);BYTE buffer[131072];ULONG got=0;
    for(unsigned at=0;at<4*1024*1024;at+=sizeof(buffer)){
        assert(input->Read(buffer,sizeof(buffer),&got)==S_OK && got==sizeof(buffer));
        for(unsigned j=0;j<got;j++)assert(buffer[j]==(BYTE)((at+j)%251));
    }
    assert(input->Read(buffer,1,&got)==S_FALSE && got==0);input->Release();
    auto empty=stream(object,1);assert(empty->Read(buffer,1,&got)==S_FALSE && got==0);empty->Release();
    assert(operation->EndOperation(S_OK,nullptr,DROPEFFECT_COPY)==S_OK);
    assert(operation->StartOperation(nullptr)==S_OK);input=stream(object,0);
    assert(input->Read(buffer,4,&got)==S_OK && got==4 && buffer[3]==3);input->Release();
    assert(operation->EndOperation(S_OK,nullptr,DROPEFFECT_COPY)==S_OK);operation->Release();object->Release();
    shell_receive_invalidate();
    // Let the STA relinquish the old object before the next local copy.
    assert(SUCCEEDED(OleSetClipboard(nullptr)));
    object=publish(2);input=stream(object,0);blockReads=true;
    HRESULT outcome=S_OK;
    std::thread read([&]{CoInitializeEx(nullptr,COINIT_MULTITHREADED);ULONG n=0;outcome=input->Read(buffer,sizeof(buffer),&n);CoUninitialize();});
    assert(WaitForSingleObject(blocked,3000)==WAIT_OBJECT_0);
    // FIFO after show_paste_progress; never read the UI thread's shared_ptr.
    assert(PostMessageW(pasteProgressWindow,WM_COMMAND,2,0));
    read.join();assert(outcome==HRESULT_FROM_WIN32(ERROR_CANCELLED));input->Release();object->Release();
    allowed=0;SetEvent(unblock);shell_receive_stop();OleUninitialize();CloseHandle(blocked);CloseHandle(unblock);
    puts("Windows reverse paste: lazy multi-file/empty/content/progress/cancel tests passed");return 0;
}
