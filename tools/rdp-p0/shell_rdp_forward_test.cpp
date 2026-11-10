// Synthetic RDP OLE provider, real clipboard replacement/COM worker consumption.
// Everything runs inside an anonymous window station, never the user desktop.
#define wWinMain unused_probe_main
#include "shell-paste-probe.cpp"
#undef wWinMain
static std::vector<BYTE> wire;
static size_t wireAt;static unsigned wireReads;static bool stall,late=true;static unsigned emptyPolls;
static HANDLE WINAPI fake_open(HANDLE,DWORD,LPSTR){return (HANDLE)1;}
static BOOL WINAPI fake_close(HANDLE){wire.clear();return TRUE;}
static BOOL WINAPI fake_write(HANDLE,PCHAR data,ULONG n,PULONG written){
    assert(n==CALFILE_REQUEST && cf_u32(data)==CALFILE_MAGIC);
    auto count=cf_u32(data+36);auto offset=cf_u64(data+28);assert(count<=CALFILE_BLOCK);
    wire.assign(CALFILE_HEADER+count,0);wireAt=0;
    cf_put32(wire.data(),CALFILE_MAGIC);cf_put32(wire.data()+4,cf_u32(data+4));cf_put32(wire.data()+12,count);
    for(unsigned i=0;i<count;i++)wire[CALFILE_HEADER+i]=(BYTE)((offset+i)%251);
    *written=n;return TRUE;
}
static BOOL WINAPI fake_read(HANDLE,ULONG,PCHAR data,ULONG capacity,PULONG got){
    wireReads++;
    // Real Windows WTS returned FALSE/ERROR_IO_INCOMPLETE on an empty 50ms
    // poll. Exercise it both before the header and between payload fragments.
    if(stall || wireReads==1 || wireReads==5){Sleep(25);*got=0;SetLastError(ERROR_IO_INCOMPLETE);emptyPolls++;return FALSE;}
    if(late){late=false;memset(data,0,CALFILE_HEADER);cf_put32(data,CALFILE_MAGIC);*got=CALFILE_HEADER;return TRUE;}
    // Fragment headers and payloads, as the real static WTS channel does.
    *got=(ULONG)std::min<size_t>(std::min<ULONG>(capacity,777),wire.size()-wireAt);
    memcpy(data,wire.data()+wireAt,*got);wireAt+=*got;return TRUE;
}
// Model a valid provider that cannot Seek and returns smaller chunks. The old
// adapter failed immediately at Seek(0), or rejected its first partial Read.
class SequentialStream final:public IStream {
    std::atomic<ULONG> refs{1};IStream *inner;IUnknown *marshal=nullptr;
public:
    explicit SequentialStream(IStream *s):inner(s){CoCreateFreeThreadedMarshaler(this,&marshal);}
    ~SequentialStream(){inner->Release();if(marshal)marshal->Release();}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void **out)override{if(!out)return E_POINTER;*out=nullptr;if(id==IID_IUnknown || id==IID_IStream || id==IID_ISequentialStream){*out=this;AddRef();return S_OK;}if(id==IID_IMarshal)return marshal->QueryInterface(id,out);return E_NOINTERFACE;}
    ULONG STDMETHODCALLTYPE AddRef()override{return ++refs;}
    ULONG STDMETHODCALLTYPE Release()override{auto n=--refs;if(!n)delete this;return n;}
    HRESULT STDMETHODCALLTYPE Read(void *d,ULONG n,ULONG *got)override{return inner->Read(d,std::min<ULONG>(n,16384),got);}
    HRESULT STDMETHODCALLTYPE Seek(LARGE_INTEGER,DWORD,ULARGE_INTEGER*)override{return STG_E_INVALIDFUNCTION;}
    HRESULT STDMETHODCALLTYPE Write(const void*,ULONG,ULONG*)override{return STG_E_ACCESSDENIED;}
    HRESULT STDMETHODCALLTYPE SetSize(ULARGE_INTEGER)override{return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE CopyTo(IStream*,ULARGE_INTEGER,ULARGE_INTEGER*,ULARGE_INTEGER*)override{return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE Commit(DWORD)override{return S_OK;}
    HRESULT STDMETHODCALLTYPE Revert()override{return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE LockRegion(ULARGE_INTEGER,ULARGE_INTEGER,DWORD)override{return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE UnlockRegion(ULARGE_INTEGER,ULARGE_INTEGER,DWORD)override{return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE Stat(STATSTG *s,DWORD f)override{return inner->Stat(s,f);}
    HRESULT STDMETHODCALLTYPE Clone(IStream**)override{return E_NOTIMPL;}
};
class Provider final:public IDataObject {
    std::atomic<ULONG> refs{1};Files *inner;IUnknown *marshaler=nullptr;
    CLIPFORMAT marker=(CLIPFORMAT)RegisterClipboardFormatW(L"CalabiRdpStreamV2");
public:
    Provider(BatchPtr b):inner(new Files(b)){CoCreateFreeThreadedMarshaler(this,&marshaler);}
    ~Provider(){inner->Release();if(marshaler)marshaler->Release();}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void **out)override{
        if(!out)return E_POINTER;*out=nullptr;
        if(id==IID_IUnknown || id==IID_IDataObject){*out=this;AddRef();return S_OK;}
        if(id==IID_IMarshal)return marshaler->QueryInterface(id,out);
        return inner->QueryInterface(id,out);
    }
    ULONG STDMETHODCALLTYPE AddRef()override{return ++refs;}
    ULONG STDMETHODCALLTYPE Release()override{auto n=--refs;if(!n)delete this;return n;}
    HRESULT STDMETHODCALLTYPE GetData(FORMATETC *f,STGMEDIUM *m)override{
        // The real rdpclip source cannot survive replacement. No source stream
        // may be acquired at all: the new path only reads metadata here.
        if(f->cfFormat==(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_FILECONTENTS)){assert(false);return E_FAIL;}
        if(f->cfFormat!=marker)return inner->GetData(f,m);
        *m={};m->tymed=TYMED_HGLOBAL;m->hGlobal=GlobalAlloc(GMEM_MOVEABLE|GMEM_ZEROINIT,CALFILE_MARKER_SIZE);
        auto p=GlobalLock(m->hGlobal);memcpy(p,CALFILE_MARKER,18);GlobalUnlock(m->hGlobal);return S_OK;
    }
    HRESULT STDMETHODCALLTYPE QueryGetData(FORMATETC *f)override{return f->cfFormat==marker?S_OK:inner->QueryGetData(f);}
    HRESULT STDMETHODCALLTYPE EnumFormatEtc(DWORD direction,IEnumFORMATETC **out)override{
        if(direction!=DATADIR_GET)return E_NOTIMPL;
        FORMATETC formats[]={{(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_FILEDESCRIPTORW),nullptr,DVASPECT_CONTENT,-1,TYMED_HGLOBAL},
            {(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_FILECONTENTS),nullptr,DVASPECT_CONTENT,0,TYMED_ISTREAM},{marker,nullptr,DVASPECT_CONTENT,-1,TYMED_HGLOBAL}};
        return SHCreateStdEnumFmtEtc(3,formats,out);
    }
    HRESULT STDMETHODCALLTYPE GetDataHere(FORMATETC*,STGMEDIUM*)override{return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE GetCanonicalFormatEtc(FORMATETC*,FORMATETC*)override{return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE SetData(FORMATETC*,STGMEDIUM*,BOOL)override{return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE DAdvise(FORMATETC*,DWORD,IAdviseSink*,DWORD*)override{return OLE_E_ADVISENOTSUPPORTED;}
    HRESULT STDMETHODCALLTYPE DUnadvise(DWORD)override{return OLE_E_ADVISENOTSUPPORTED;}
    HRESULT STDMETHODCALLTYPE EnumDAdvise(IEnumSTATDATA**)override{return OLE_E_ADVISENOTSUPPORTED;}
};
static void pump(){MSG m;while(PeekMessageW(&m,nullptr,0,0,PM_REMOVE)){TranslateMessage(&m);DispatchMessageW(&m);}}
int main(){
    fileTransport.open=fake_open;fileTransport.close=fake_close;fileTransport.read=fake_read;fileTransport.write=fake_write;
    auto station=CreateWindowStationW(nullptr,0,WINSTA_ALL_ACCESS,nullptr);assert(station && SetProcessWindowStation(station));
    auto desktop=CreateDesktopW(L"forward",nullptr,nullptr,0,GENERIC_ALL,nullptr);assert(desktop && SetThreadDesktop(desktop));
    assert(SUCCEEDED(OleInitialize(nullptr)));assert(start_progress_ui());bridgeMode=true;
    WNDCLASSW cls={};cls.hInstance=GetModuleHandleW(nullptr);cls.lpfnWndProc=window_proc;cls.lpszClassName=L"CalabiForwardTest";RegisterClassW(&cls);
    HWND w=CreateWindowW(cls.lpszClassName,L"",0,0,0,0,0,HWND_MESSAGE,nullptr,cls.hInstance,nullptr);assert(w);
    auto source=std::make_shared<Batch>();source->delay=0;source->size=4*1024*1024;
    source->descriptors.resize(2);
    for(auto &d:source->descriptors){d.dwFlags=FD_FILESIZE|FD_ATTRIBUTES;d.dwFileAttributes=FILE_ATTRIBUTE_NORMAL;}
    source->descriptors[0].nFileSizeLow=(DWORD)source->size;wcscpy(source->descriptors[0].cFileName,L"正向文件.bin");
    wcscpy(source->descriptors[1].cFileName,L"空文件.txt");
    auto provider=new Provider(source);assert(OleSetClipboard(provider)==S_OK);provider->Release();
    poll_bridge_clipboard(w);pump();assert(active && active->rdpSource && !source->read && !wireReads);
    assert(IsClipboardFormatAvailable(RegisterClipboardFormatW(L"CalabiRdpCopyOwnedV1")));
    assert(!IsClipboardFormatAvailable(RegisterClipboardFormatW(L"CalabiRdpStreamV2")));
    auto received=active;
    std::atomic<bool> done{false};HRESULT status=E_PENDING;
    std::thread worker([&]{
        CoInitializeEx(nullptr,COINIT_MULTITHREADED);
        Stream stream(received);BYTE data[131072];ULONG got;
        for(unsigned offset=0;offset<source->size;offset+=sizeof(data)){
            assert(stream.Read(data,sizeof(data),&got)==S_OK && got==sizeof(data));
            for(unsigned i=0;i<got;i++)assert(data[i]==(BYTE)((offset+i)%251));
        }
        assert(received->read==source->size);
        Stream empty(received,1);assert(empty.Read(data,1,&got)==S_FALSE && got==0);
        received->cancelled=true;status=stream.Read(data,1,&got);CoUninitialize();done=true;
    });
    ULONGLONG deadline=GetTickCount64()+10000;while(!done && GetTickCount64()<deadline){pump();Sleep(5);}assert(done);worker.join();
    assert(status==HRESULT_FROM_WIN32(ERROR_CANCELLED));
    assert(emptyPolls>=2);
    assert(GetWindowLongPtrW(pasteProgressWindow,GWL_STYLE)&WS_VISIBLE);
    assert(GetWindowLongPtrW(pasteProgressWindow,GWL_EXSTYLE)&WS_EX_TOPMOST);
    source->started=false;stall=true;done=false;
    provider=new Provider(source);assert(OleSetClipboard(provider)==S_OK);provider->Release();
    poll_bridge_clipboard(w);pump();received=active;assert(received && !received->cancelled);
    std::thread cancelWorker([&]{
        CoInitializeEx(nullptr,COINIT_MULTITHREADED);Stream stream(received);BYTE data[131072];ULONG got;
        status=stream.Read(data,sizeof(data),&got);CoUninitialize();done=true;
    });
    // StartOperation may mark the source started before any Read. Wait for the
    // new batch's reader (and therefore its queued progress panel), not that flag.
    deadline=GetTickCount64()+3000;while(!received->rdpReadThread && GetTickCount64()<deadline){pump();Sleep(5);}assert(received->rdpReadThread);
    assert(PostMessageW(pasteProgressWindow,WM_COMMAND,2,0));
    deadline=GetTickCount64()+1500;while(!done && GetTickCount64()<deadline){pump();Sleep(5);}assert(done);cancelWorker.join();
    assert(status==HRESULT_FROM_WIN32(ERROR_CANCELLED));
    OleSetClipboard(nullptr);if(files){files->Release();files=nullptr;}active.reset();received.reset();source.reset();
    DestroyWindow(w);stop_progress_ui();OleUninitialize();
    puts("Forward RDP channel passed: no system IStream, lazy first paste, fragmented bytes, progress and stalled-read cancellation.");return 0;
}
