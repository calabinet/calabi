// Explicit interactive diagnostic. Reads at most 4 * 64 KiB of the next
// copied RDP file, logs HRESULT/length only, and never writes file content.
#define wWinMain unused_shell_probe_main
#include "shell-paste-probe.cpp"
#undef wWinMain
static void probe_pump(){MSG m;while(PeekMessageW(&m,nullptr,0,0,PM_REMOVE)){TranslateMessage(&m);DispatchMessageW(&m);}}
static HRESULT probe_get_stream(IDataObject *source,IStream **stream){
    FORMATETC format={(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_FILECONTENTS),nullptr,DVASPECT_CONTENT,0,TYMED_ISTREAM};
    STGMEDIUM medium={};HRESULT hr=source->GetData(&format,&medium);
    if(FAILED(hr))return hr;
    if(medium.tymed!=TYMED_ISTREAM || !medium.pstm){ReleaseStgMedium(&medium);return DV_E_TYMED;}
    *stream=medium.pstm;(*stream)->AddRef();ReleaseStgMedium(&medium);return S_OK;
}
static void probe_read(const char *phase,IStream *stream){
    BYTE buffer[65536];ULONG got=0;HRESULT hr=stream->Read(buffer,sizeof(buffer),&got);
    SecureZeroMemory(buffer,sizeof(buffer));
    printf("probe phase=%s hr=0x%08lX received=%lu\n",phase,hr,got);fflush(stdout);
}
static void probe_worker(const char *phase,IStream *stream){
    IStream *marshaled=nullptr;HRESULT hr=CoMarshalInterThreadInterfaceInStream(IID_IStream,stream,&marshaled);
    if(FAILED(hr)){printf("probe phase=%s marshal_hr=0x%08lX\n",phase,hr);fflush(stdout);return;}
    std::atomic<bool> done{false};
    std::thread worker([&]{
        CoInitializeEx(nullptr,COINIT_MULTITHREADED);IStream *remote=nullptr;
        HRESULT result=CoGetInterfaceAndReleaseStream(marshaled,IID_IStream,(void**)&remote);
        if(SUCCEEDED(result)){probe_read(phase,remote);remote->Release();}
        else {printf("probe phase=%s unmarshal_hr=0x%08lX\n",phase,result);fflush(stdout);}
        CoUninitialize();done=true;
    });
    while(!done){probe_pump();Sleep(10);}worker.join();
}
int main(){
    assert(SUCCEEDED(OleInitialize(nullptr)));
    DWORD initial=GetClipboardSequenceNumber();UINT marker=RegisterClipboardFormatW(L"CalabiRdpStreamV1");
    printf("probe ready session=%lu waiting_for_new_rdp_copy=1\n",GetCurrentProcessId());fflush(stdout);
    ULONGLONG deadline=GetTickCount64()+180000;
    while(GetTickCount64()<deadline){
        probe_pump();
        if(GetClipboardSequenceNumber()!=initial && IsClipboardFormatAvailable(marker))break;
        Sleep(30);
    }
    if(GetTickCount64()>=deadline){puts("probe timeout");return 2;}
    IDataObject *source=nullptr;HRESULT hr=OleGetClipboard(&source);
    printf("probe get_clipboard_hr=0x%08lX\n",hr);fflush(stdout);if(FAILED(hr))return 3;
    IDataObjectAsyncCapability *operation=nullptr;
    HRESULT async=source->QueryInterface(IID_IDataObjectAsyncCapability,(void**)&operation);
    printf("probe async_query_hr=0x%08lX\n",async);
    if(SUCCEEDED(async)){printf("probe async_mode_hr=0x%08lX\n",operation->SetAsyncMode(TRUE));printf("probe async_start_hr=0x%08lX\n",operation->StartOperation(nullptr));}fflush(stdout);
    IStream *streams[4]={};
    for(unsigned i=0;i<4;i++){
        hr=probe_get_stream(source,&streams[i]);printf("probe acquire=%u hr=0x%08lX\n",i,hr);fflush(stdout);
        if(FAILED(hr))return 4;
    }
    probe_read("owner_before",streams[0]);
    probe_worker("worker_before",streams[1]);
    auto batch=std::make_shared<Batch>();auto replacement=new Files(batch);
    hr=OleSetClipboard(replacement);printf("probe replace_hr=0x%08lX\n",hr);fflush(stdout);
    if(SUCCEEDED(hr)){
        probe_read("owner_after",streams[2]);
        probe_worker("worker_after",streams[3]);
    }
    if(OleIsCurrentClipboard(replacement)==S_OK)OleSetClipboard(nullptr);
    for(auto stream:streams)stream->Release();
    if(operation){operation->EndOperation(S_OK,nullptr,DROPEFFECT_COPY);operation->Release();}
    source->Release();replacement->Release();OleUninitialize();puts("probe finished content_saved=0");return 0;
}
