#pragma once
// Legacy adapter retained for isolated compatibility fixtures only. Real
// Windows rdpclip streams die after clipboard replacement; production uses
// the calfile RDP channel (shell-file-channel.h), never this constructor.
struct RdpApartment {
    HRESULT result=CoInitializeEx(nullptr,COINIT_MULTITHREADED);
    ~RdpApartment(){if(SUCCEEDED(result))CoUninitialize();}
};
class RdpSource {
    std::vector<DWORD> cookies;
    std::vector<ULONGLONG> positions;
    DWORD operationCookie=0;
    static IGlobalInterfaceTable *table(){
        IGlobalInterfaceTable *git=nullptr;
        CoCreateInstance(CLSID_StdGlobalInterfaceTable,nullptr,CLSCTX_INPROC_SERVER,IID_IGlobalInterfaceTable,(void**)&git);return git;
    }
public:
    RdpSource()=default;
    explicit RdpSource(IDataObject *object,unsigned count){
        auto git=table();if(!git)return;
        IDataObjectAsyncCapability *operation=nullptr;
        if(SUCCEEDED(object->QueryInterface(IID_IDataObjectAsyncCapability,(void**)&operation))){
            operation->SetAsyncMode(TRUE);
            if(SUCCEEDED(operation->StartOperation(nullptr)))git->RegisterInterfaceInGlobal(operation,IID_IDataObjectAsyncCapability,&operationCookie);
            operation->Release();
        }
        for(unsigned i=0;i<count;i++){
            FORMATETC format={(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_FILECONTENTS),nullptr,DVASPECT_CONTENT,(LONG)i,TYMED_ISTREAM};
            STGMEDIUM medium={};DWORD cookie=0;
            if(FAILED(object->GetData(&format,&medium)))break;
            if(medium.tymed==TYMED_ISTREAM && medium.pstm)git->RegisterInterfaceInGlobal(medium.pstm,IID_IStream,&cookie);
            ReleaseStgMedium(&medium);if(!cookie)break;cookies.push_back(cookie);positions.push_back(0);
        }
        git->Release();
    }
    bool valid(unsigned count)const{return cookies.size()==count;}
    virtual ~RdpSource(){
        RdpApartment apartment;
        if(auto git=table()){
            IDataObjectAsyncCapability *operation=nullptr;
            if(operationCookie && SUCCEEDED(git->GetInterfaceFromGlobal(operationCookie,IID_IDataObjectAsyncCapability,(void**)&operation))){
                operation->EndOperation(S_OK,nullptr,DROPEFFECT_COPY);operation->Release();
            }
            if(operationCookie)git->RevokeInterfaceFromGlobal(operationCookie);
            for(auto cookie:cookies)git->RevokeInterfaceFromGlobal(cookie);git->Release();
        }
    }
    virtual void cancel(){}
    virtual HRESULT read(unsigned index,ULONGLONG offset,void *out,ULONG count,ULONG *got){
        *got=0;RdpApartment apartment;
        auto git=table();if(!git)return E_FAIL;
        if(index>=cookies.size()){git->Release();return DV_E_LINDEX;}
        IStream *stream=nullptr;HRESULT hr=git->GetInterfaceFromGlobal(cookies[index],IID_IStream,(void**)&stream);git->Release();
        if(FAILED(hr)){fprintf(stderr,"rdp_stream stage=marshal hr=0x%08lX index=%u\n",hr,index);fflush(stderr);return hr;}
        // Some RDP providers offer sequential streams. Do not Seek(0) before
        // the first Read or redundantly seek before each subsequent block.
        if(positions[index]!=offset){
            LARGE_INTEGER at;at.QuadPart=offset;hr=stream->Seek(at,STREAM_SEEK_SET,nullptr);
            if(SUCCEEDED(hr))positions[index]=offset;
            else {fprintf(stderr,"rdp_stream stage=seek hr=0x%08lX index=%u offset=%llu\n",hr,index,offset);fflush(stderr);}
        }
        if(SUCCEEDED(hr)){
            hr=stream->Read(out,count,got);
            if(*got<=count)positions[index]+=*got;else hr=STG_E_READFAULT;
            if(FAILED(hr) || !*got || offset==0){
                fprintf(stderr,"rdp_stream stage=read hr=0x%08lX index=%u offset=%llu requested=%lu received=%lu\n",hr,index,offset,count,*got);fflush(stderr);
            }
        }
        stream->Release();return hr;
    }
};
