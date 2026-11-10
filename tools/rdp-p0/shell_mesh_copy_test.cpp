// Isolated Shell + self-owned transport fixture. No user clipboard or network.
#define CALABI_MESH_COPY_TEST
#define wWinMain unused_probe_main
#include "shell-paste-probe.cpp"
#undef wWinMain
static std::atomic<unsigned> requests{0},cancelRequests{0};
static std::atomic<unsigned> offerRequests{0},clearRequests{0};
static std::atomic<bool> stall{false};
static std::string readFailure;
static std::string mesh_test_rpc(const std::string &request){
    if(request.rfind("mesh_offer ",0)==0){offerRequests++;return "ok";}
    if(request.rfind("mesh_clear ",0)==0){clearRequests++;return "ok";}
    if(request.rfind("mesh_cancel ",0)==0){cancelRequests++;return "ok";}
    if(request.rfind("mesh_read ",0)!=0)return "none";
    requests++;if(stall)return "wait";
    if(!readFailure.empty())return readFailure;
    std::istringstream in(request);std::string op,offer;unsigned index,count;ULONGLONG offset;
    assert(bool(in>>op>>offer>>index>>offset>>count));assert(index<3&&count<=65536);
    std::string out="data ";for(unsigned i=0;i<count;i++){unsigned char c=(offset+i)%251;out.push_back("0123456789abcdef"[c>>4]);out.push_back("0123456789abcdef"[c&15]);}return out;
}
static void pump_mesh(){MSG m;while(PeekMessageW(&m,nullptr,0,0,PM_REMOVE)){TranslateMessage(&m);DispatchMessageW(&m);}}
int main(){
    auto station=CreateWindowStationW(nullptr,0,WINSTA_ALL_ACCESS,nullptr);assert(station&&SetProcessWindowStation(station));
    auto desktop=CreateDesktopW(L"mesh-copy-test",nullptr,nullptr,0,GENERIC_ALL,nullptr);assert(desktop&&SetThreadDesktop(desktop));
    assert(SUCCEEDED(OleInitialize(nullptr)));
    assert(start_progress_ui());
    WNDCLASSW cls={};cls.hInstance=GetModuleHandleW(nullptr);cls.lpfnWndProc=window_proc;cls.lpszClassName=L"CalabiMeshCopyTest";RegisterClassW(&cls);
    HWND w=CreateWindowW(cls.lpszClassName,L"",0,0,0,0,0,HWND_MESSAGE,nullptr,cls.hInstance,nullptr);assert(w);
    FILEGROUPDESCRIPTORW group={};group.cItems=1;auto &d=group.fgd[0];d.dwFlags=FD_FILESIZE|FD_UNICODE|FD_ATTRIBUTES;d.dwFileAttributes=FILE_ATTRIBUTE_NORMAL;d.nFileSizeLow=131089;wcscpy(d.cFileName,L"测试.bin");
    std::string hex;auto raw=(BYTE*)&group;for(size_t i=0;i<sizeof(group);i++){hex.push_back("0123456789abcdef"[raw[i]>>4]);hex.push_back("0123456789abcdef"[raw[i]&15]);}
    mesh_apply_state(w,"state session 0 100.64.0.36 offer "+hex);
    assert(active&&active->total==131089&&requests==0);assert(OleIsCurrentClipboard(files)==S_OK);
    auto received=active;std::atomic<bool> done{false};HRESULT result=E_PENDING;
    std::thread reader([&]{CoInitializeEx(nullptr,COINIT_MULTITHREADED);Stream stream(received);std::vector<BYTE> data(131089);ULONG got=0;result=stream.Read(data.data(),(ULONG)data.size(),&got);assert(SUCCEEDED(result)&&got==data.size());for(unsigned i=0;i<got;i++)assert(data[i]==i%251);CoUninitialize();done=true;});
    auto deadline=GetTickCount64()+5000;while(!done&&GetTickCount64()<deadline){pump_mesh();Sleep(5);}assert(done);reader.join();pump_mesh();
    assert(requests==3&&received->read==131089);
    deadline=GetTickCount64()+1500;while((!pasteProgressWindow||!(GetWindowLongPtrW(pasteProgressWindow,GWL_STYLE)&WS_VISIBLE))&&GetTickCount64()<deadline){pump_mesh();Sleep(5);}
    assert(pasteProgressWindow&&(GetWindowLongPtrW(pasteProgressWindow,GWL_STYLE)&WS_VISIBLE));
    stall=true;done=false;
    std::thread blocked([&]{CoInitializeEx(nullptr,COINIT_MULTITHREADED);Stream stream(received);BYTE data[100];ULONG got;result=stream.Read(data,100,&got);CoUninitialize();done=true;});
    deadline=GetTickCount64()+1000;while(requests<4&&GetTickCount64()<deadline){pump_mesh();Sleep(5);}assert(requests>=4);
    assert(PostMessageW(pasteProgressWindow,WM_COMMAND,2,0));deadline=GetTickCount64()+1000;
    while(!done&&GetTickCount64()<deadline){pump_mesh();Sleep(5);}assert(done);blocked.join();assert(result==HRESULT_FROM_WIN32(ERROR_CANCELLED)&&cancelRequests==1);
    mesh_apply_state(w,"none");assert(OleIsCurrentClipboard(files)!=S_OK);
    // Actual Windows clipboard contention must not revoke the current offer
    // or consume the sequence of a newly copied file.
    mesh_apply_state(w,"state next 0 100.64.0.36 - 00000000");
    assert(OpenClipboard(w));assert(EmptyClipboard());
    const wchar_t paths[]=L"C:\\test\\中文.bin\0";
    auto memory=GlobalAlloc(GMEM_MOVEABLE,sizeof(DROPFILES)+sizeof(paths));auto drop=(DROPFILES*)GlobalLock(memory);
    memset(drop,0,sizeof(DROPFILES));drop->pFiles=sizeof(DROPFILES);drop->fWide=TRUE;memcpy((BYTE*)drop+sizeof(DROPFILES),paths,sizeof(paths));GlobalUnlock(memory);
    assert(SetClipboardData(CF_HDROP,memory));CloseClipboard();
    DWORD before=meshSequence;HANDLE locked=CreateEventW(nullptr,TRUE,FALSE,nullptr),release=CreateEventW(nullptr,TRUE,FALSE,nullptr);
    auto testDesktop=GetThreadDesktop(GetCurrentThreadId());
    std::thread locker([&]{assert(SetThreadDesktop(testDesktop));assert(OpenClipboard(nullptr));SetEvent(locked);WaitForSingleObject(release,2000);CloseClipboard();});
    assert(WaitForSingleObject(locked,1000)==WAIT_OBJECT_0);
    mesh_apply_state(w,"state next 0 100.64.0.36 - 00000000");
    assert(meshSequence==before&&offerRequests==0&&clearRequests==0);
    SetEvent(release);locker.join();CloseHandle(locked);CloseHandle(release);
    mesh_apply_state(w,"state next 0 100.64.0.36 - 00000000");
    deadline=GetTickCount64()+1000;while(meshPublishing&&GetTickCount64()<deadline)Sleep(5);
    assert(offerRequests==1&&clearRequests==0&&meshSequence==GetClipboardSequenceNumber());
    // A remote revoke must not swallow a newly copied local file sequence.
    meshOffer="previous";meshSequence=0;
    mesh_apply_state(w,"state next 0 100.64.0.36 - 00000000");
    deadline=GetTickCount64()+1000;while(meshPublishing&&GetTickCount64()<deadline)Sleep(5);
    assert(offerRequests==2&&clearRequests==0);
    stall=false;
    // Real Stream/bridge path: separate files, seeks/re-reads and zero-byte files.
    auto multi=std::make_shared<Batch>();multi->descriptors.resize(3);multi->total=150;
    multi->descriptors[0].nFileSizeLow=100;multi->descriptors[1].nFileSizeLow=50;
    multi->rdpSource=std::make_shared<MeshCopySource>("multi");
    BYTE sample[100];ULONG got=0;Stream first(multi,0),second(multi,1),empty(multi,2);
    LARGE_INTEGER seek={};seek.QuadPart=50;assert(SUCCEEDED(first.Seek(seek,STREAM_SEEK_SET,nullptr)));
    assert(SUCCEEDED(first.Read(sample,50,&got)) && multi->read==50);
    seek.QuadPart=0;assert(SUCCEEDED(first.Seek(seek,STREAM_SEEK_SET,nullptr)));
    assert(SUCCEEDED(first.Read(sample,100,&got)) && multi->read==100);
    assert(SUCCEEDED(second.Read(sample,50,&got)) && multi->read==150 && multi->currentFile==1);
    assert(empty.Read(sample,1,&got)==S_FALSE && got==0 && multi->fileProgress[2].touched);
    assert(multi->fileProgress[0].bytes==100 && multi->fileProgress[1].bytes==50);
    auto timeout=std::make_shared<Batch>();timeout->rdpSource=std::make_shared<MeshCopySource>("timeout");
    auto timeoutFiles=new Files(timeout);
    assert(SUCCEEDED(timeoutFiles->StartOperation(nullptr)));
    Stream timedRead(timeout);
    readFailure="error timeout";
    HRESULT timeoutResult=HRESULT_FROM_WIN32(ERROR_TIMEOUT);
    assert(timedRead.Read(sample,1,&got)==timeoutResult && got==0);
    timeoutFiles->EndOperation(E_FAIL,nullptr,0);
    timeout->cancel(HRESULT_FROM_WIN32(ERROR_CONNECTION_ABORTED));
    assert(timeout->interruption==timeoutResult);
    assert(!wcscmp(paste_failure_detail(timeout->interruption,RdpLocaleSimplified),L"网络连接超时，恢复后请重新粘贴。"));
    assert(!wcscmp(paste_failure_detail(timeout->interruption,RdpLocaleJapanese),
        L"ネットワークがタイムアウトしました。復旧後に貼り付け直してください。"));
    timeoutFiles->Release();
    files->Release();files=nullptr;active.reset();received.reset();DestroyWindow(w);stop_progress_ui();OleUninitialize();
    puts("Mesh clipboard adapter passed: lazy paste, 64 KiB blocks, custom live progress, pending-read cancel, session revocation.");
}
