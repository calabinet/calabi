#pragma once
#include <sstream>
#include <shellapi.h>

struct MeshCopySource final : RdpSource {
    std::string offer;
    std::atomic<bool> stopped{false};
    explicit MeshCopySource(std::string value):offer(std::move(value)){}
    HRESULT read(unsigned index,ULONGLONG offset,void *data,ULONG count,ULONG *got) override {
        *got=0;
        auto request="mesh_read "+offer+" "+std::to_string(index)+" "+std::to_string(offset)+" "+std::to_string(count);
        while(!stopped){
            auto answer=bridge_rpc(request);
            if(answer=="wait"){Sleep(25);continue;}
            std::vector<BYTE> bytes;
            if(answer.rfind("data ",0)!=0||!decode_hex(answer.substr(5),bytes)||bytes.size()!=count){
                HRESULT error=STG_E_READFAULT;
                if(answer=="error timeout")error=HRESULT_FROM_WIN32(ERROR_TIMEOUT);
                else if(answer=="error session")error=HRESULT_FROM_WIN32(ERROR_CONNECTION_ABORTED);
                else if(answer=="error offer")error=HRESULT_FROM_WIN32(ERROR_INVALID_STATE);
                else if(answer=="error source")error=HRESULT_FROM_WIN32(ERROR_FILE_INVALID);
                fprintf(stderr,"rdp_stream stage=mesh_read hr=0x%08lx index=%u offset=%llu requested=%lu received=%zu reply_bytes=%zu\n",(unsigned long)error,index,offset,count,bytes.size(),answer.size());fflush(stderr);
                return error;
            }
            if(stopped)break;memcpy(data,bytes.data(),count);*got=count;return S_OK;
        }
        return HRESULT_FROM_WIN32(ERROR_CANCELLED);
    }
    void cancel() override {if(!stopped.exchange(true))bridge_rpc("mesh_cancel "+offer);}
};
static std::atomic<bool> meshPolling{false};
static bool meshEnabled=false;
static std::string meshSession, meshOffer;
static DWORD meshSequence;
static std::atomic<bool> meshPublishing{false};
static int meshLastState=-1;
static bool mesh_host_matches(const std::string &peer) {
    if(!GetSystemMetrics(SM_REMOTESESSION))return false;
    LPWSTR value=nullptr;DWORD bytes=0;bool match=false;
    static HMODULE dll=LoadLibraryExW(L"wtsapi32.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
    static auto query=dll?(decltype(&WTSQuerySessionInformationW))GetProcAddress(dll,"WTSQuerySessionInformationW"):nullptr;
    static auto release=dll?(decltype(&WTSFreeMemory))GetProcAddress(dll,"WTSFreeMemory"):nullptr;
    if(query&&release&&query(WTS_CURRENT_SERVER_HANDLE,WTS_CURRENT_SESSION,WTSClientAddress,&value,&bytes)) {
        auto address=(WTS_CLIENT_ADDRESS*)value;
        if(bytes>=sizeof(*address)&&address->AddressFamily==2){char ip[32];
            snprintf(ip,sizeof(ip),"%u.%u.%u.%u",address->Address[2],address->Address[3],address->Address[4],address->Address[5]);match=peer==ip;}
        release(value);
    }
    return match;
}
static bool mesh_encode_paths(HWND window,std::string &encoded) {
    if(!OpenClipboard(window))return false;
    encoded.clear();bool valid=true;
    if(!IsClipboardFormatAvailable(RegisterClipboardFormatW(L"CalabiRdpCopyOwnedV1"))&&IsClipboardFormatAvailable(CF_HDROP)){
        auto drop=(HDROP)GetClipboardData(CF_HDROP);UINT count=DragQueryFileW(drop,0xffffffff,nullptr,0);
        if(!drop||!count||count>32)valid=false;
        if(valid)for(UINT i=0;i<count;i++){
            UINT length=DragQueryFileW(drop,i,nullptr,0);std::vector<wchar_t> path(length+1);
            if(!length||length>32767||!DragQueryFileW(drop,i,path.data(),length+1)){valid=false;break;}
            int n=WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,path.data(),-1,nullptr,0,nullptr,nullptr);
            if(n<=0){valid=false;break;}std::vector<char> utf8(n);
            WideCharToMultiByte(CP_UTF8,WC_ERR_INVALID_CHARS,path.data(),-1,utf8.data(),n,nullptr,nullptr);
            for(unsigned char c:utf8){encoded.push_back("0123456789abcdef"[c>>4]);encoded.push_back("0123456789abcdef"[c&15]);}
            if(encoded.size()>16384){valid=false;break;}
        }
    }
    CloseClipboard();return valid;
}
static void mesh_apply_state(HWND window,const std::string &reply) {
    std::istringstream input(reply);std::string tag,session,peer,offer,manifest;int host=0;
    bool parsed=bool(input>>tag>>session>>host>>peer>>offer>>manifest)&&tag=="state";
    bool live=parsed&&(!host||mesh_host_matches(peer));
    int state=!parsed?0:!live?1:2;
    if(state!=meshLastState){meshLastState=state;fprintf(stderr,"rdp_stream stage=mesh_state state=%d host=%d hr=%s\n",state,host,state==1?"0x80004005":"0x00000000");fflush(stderr);}
    if(!live || (!meshSession.empty() && session!=meshSession)){
        if(!meshSession.empty()&&active&&std::dynamic_pointer_cast<MeshCopySource>(active->rdpSource)){
            active->cancel(reply=="none" || parsed?HRESULT_FROM_WIN32(ERROR_CONNECTION_ABORTED):STG_E_READFAULT);
            auto b=active;std::thread([b]{bridge_cancel(b);}).detach();
            if(files&&OleIsCurrentClipboard(files)==S_OK)OleSetClipboard(nullptr);
        }
    }
    if(!live){
        meshSession.clear();meshOffer.clear();meshSequence=GetClipboardSequenceNumber();return;
    }
    if(session!=meshSession){meshSession=session;meshOffer.clear();meshSequence=GetClipboardSequenceNumber();}
    if(offer!="-"&&offer!=meshOffer){
        std::vector<BYTE> raw;DWORD count=0;
        if(decode_hex(manifest,raw)&&raw.size()>=4){memcpy(&count,raw.data(),4);
            if(count>0&&count<=32&&raw.size()==4+count*sizeof(FILEDESCRIPTORW)){
                auto b=std::make_shared<Batch>();b->total=0;b->descriptors.resize(count);
                memcpy(b->descriptors.data(),raw.data()+4,count*sizeof(FILEDESCRIPTORW));
                for(const auto &d:b->descriptors)b->total+=((ULONGLONG)d.nFileSizeHigh<<32)|d.nFileSizeLow;
                b->rdpSource=std::make_shared<MeshCopySource>(offer);auto object=new Files(b);
                if(SUCCEEDED(OleSetClipboard(object))){if(active)active->cancel(HRESULT_FROM_WIN32(ERROR_INVALID_STATE));if(files)files->Release();files=object;active=b;meshOffer=offer;}
                else object->Release();
                meshSequence=GetClipboardSequenceNumber();
            }
        }
    }
    if(offer=="-"&&!meshOffer.empty()){
        if(active&&std::dynamic_pointer_cast<MeshCopySource>(active->rdpSource)){active->cancel(HRESULT_FROM_WIN32(ERROR_INVALID_STATE));if(files&&OleIsCurrentClipboard(files)==S_OK){OleSetClipboard(nullptr);meshSequence=GetClipboardSequenceNumber();}}
        meshOffer.clear();
    }
    DWORD sequence=GetClipboardSequenceNumber();
    if(sequence!=meshSequence&&!meshPublishing){std::string paths;
        // Busy or not-yet-rendered clipboard: retain the previous source and
        // sequence, then retry. An empty successful read is a different event.
        if(!mesh_encode_paths(window,paths))return;
        meshSequence=GetClipboardSequenceNumber();
        std::string request;
        if(!paths.empty())request="mesh_offer "+session+" "+paths;
        else if(!IsClipboardFormatAvailable(RegisterClipboardFormatW(L"CalabiRdpCopyOwnedV1")))request="mesh_clear "+session;
        if(!request.empty()){meshPublishing=true;std::thread([request]{bridge_rpc(request);meshPublishing=false;}).detach();}}
}
static void poll_mesh_copy(HWND window) {
    if(meshPolling.exchange(true))return;
    std::thread([window]{auto reply=new std::string(bridge_rpc("mesh_state"));
        if(!PostMessageW(window,WM_APP+6,0,(LPARAM)reply))delete reply;meshPolling=false;
    }).detach();
}
