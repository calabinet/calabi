#pragma once
static std::mutex pipeMutex;
static bool bridgeMode=false;
#ifdef CALABI_MESH_COPY_TEST
static std::string mesh_test_rpc(const std::string &request);
#endif
static std::string bridge_rpc(const std::string &request){
#ifdef CALABI_MESH_COPY_TEST
    return mesh_test_rpc(request);
#endif
    std::lock_guard<std::mutex> guard(pipeMutex);
    if(fprintf(stdout,"%s\n",request.c_str())<0 || fflush(stdout))return "error";
    std::vector<char> line(140000);if(!fgets(line.data(),(int)line.size(),stdin))return "error";
    size_t n=strcspn(line.data(),"\r\n");if(!line[n])return "error";line[n]=0;return line.data();
}
static bool decode_hex(const std::string &s,std::vector<BYTE> &out){
    if(s.size()%2 || s.size()>131072)return false;out.clear();out.reserve(s.size()/2);
    auto digit=[](char c)->int{return c>='0' && c<='9'?c-'0':c>='a' && c<='f'?c-'a'+10:-1;};
    for(size_t i=0;i<s.size();i+=2){int a=digit(s[i]),b=digit(s[i+1]);if(a<0 || b<0)return false;out.push_back((BYTE)(a*16+b));}return true;
}
static void bridge_cancel(BatchPtr b){
    if(b->rdpSource){b->rdpSource->cancel();RdpApartment apartment;if(DWORD thread=b->rdpReadThread.load())CoCancelCall(thread,0);return;}
    if(!b->marker.empty() && !b->cancelSent.exchange(true))bridge_rpc("cancel "+b->marker);
}
static HRESULT bridge_read(BatchPtr b,unsigned index,ULONGLONG offset,void *data,ULONG count,ULONG *got){
    *got=0;
    if(b->cancelled){bridge_cancel(b);return HRESULT_FROM_WIN32(ERROR_CANCELLED);}
    show_paste_progress(b);
    if(b->rdpSource){
        std::lock_guard<std::mutex> guard(b->rdpReadLock);
        RdpApartment apartment;CoEnableCallCancellation(nullptr);
        b->rdpReadThread=GetCurrentThreadId();HRESULT hr=S_OK;
        while(*got<count && !b->cancelled){
            ULONG n=std::min<ULONG>(65536,count-*got),read=0;
            hr=b->rdpSource->read(index,offset+*got,(BYTE*)data+*got,n,&read);
            // IStream may return a partial block; continue at its actual
            // position. Only zero progress before the advertised EOF fails.
            if(FAILED(hr) || !read || read>n){if(SUCCEEDED(hr))hr=STG_E_READFAULT;break;}
            b->progress(index,offset+*got,read);
            *got+=read;
        }
        b->rdpReadThread=0;CoDisableCallCancellation(nullptr);
        return b->cancelled?HRESULT_FROM_WIN32(ERROR_CANCELLED):hr;
    }
    if(bridge_rpc("begin "+b->marker)!="ok")return STG_E_READFAULT;

    while(true){
        if(b->cancelled){bridge_cancel(b);return HRESULT_FROM_WIN32(ERROR_CANCELLED);}
        std::string status=bridge_rpc("status "+b->marker+" "+std::to_string(index));
        char state[12];unsigned long long done,total;
        if(sscanf(status.c_str(),"%11s %llu %llu",state,&done,&total)!=3 || total!=b->total)return STG_E_READFAULT;
        b->read=std::min<ULONGLONG>(done,total);
        if(!strcmp(state,"ready"))break;if(strcmp(state,"wait"))return STG_E_READFAULT;Sleep(100);
    }
    while(*got<count){
        if(b->cancelled){bridge_cancel(b);return HRESULT_FROM_WIN32(ERROR_CANCELLED);}
        ULONG n=std::min<ULONG>(count-*got,65536);
        std::string answer=bridge_rpc("read "+b->marker+" "+std::to_string(index)+" "+std::to_string(offset+*got)+" "+std::to_string(n));
        std::vector<BYTE> bytes;
        if(answer.rfind("data ",0)!=0 || !decode_hex(answer.substr(5),bytes) || bytes.size()!=n)return STG_E_READFAULT;
        if(b->cancelled){bridge_cancel(b);return HRESULT_FROM_WIN32(ERROR_CANCELLED);}
        memcpy((BYTE*)data+*got,bytes.data(),n);*got+=n;
    }
    return S_OK;
}
struct ResolvedPaste {DWORD sequence;BatchPtr batch;};
static std::atomic<bool> resolving{false};
static DWORD observedSequence;
static bool poll_rdp_clipboard(HWND window){
    const UINT marker=RegisterClipboardFormatW(L"CalabiRdpStreamV2");
    if(!IsClipboardFormatAvailable(marker))return false;
    IDataObject *source=nullptr;if(FAILED(OleGetClipboard(&source)))return true;
    HWND owner=GetClipboardOwner();
    FORMATETC format={(CLIPFORMAT)marker,nullptr,DVASPECT_CONTENT,-1,TYMED_HGLOBAL};
    STGMEDIUM medium={};bool valid=false;BYTE token[16]={};
    if(SUCCEEDED(source->GetData(&format,&medium))){
        if(medium.tymed==TYMED_HGLOBAL){auto text=(const char*)GlobalLock(medium.hGlobal);
            valid=text && GlobalSize(medium.hGlobal)>=CALFILE_MARKER_SIZE && !memcmp(text,CALFILE_MARKER,18);
            if(valid)memcpy(token,text+18,16);if(text)GlobalUnlock(medium.hGlobal);}
        ReleaseStgMedium(&medium);
    }
    auto batch=std::make_shared<Batch>();batch->total=0;
    format.cfFormat=(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_FILEDESCRIPTORW);medium={};
    if(valid && SUCCEEDED(source->GetData(&format,&medium))){
        valid=false;
        if(medium.tymed==TYMED_HGLOBAL){
            auto group=(FILEGROUPDESCRIPTORW*)GlobalLock(medium.hGlobal);SIZE_T bytes=GlobalSize(medium.hGlobal);
            if(group && bytes>=4 && group->cItems>0 && group->cItems<=32 && bytes>=4+group->cItems*sizeof(FILEDESCRIPTORW)){
                valid=true;batch->descriptors.assign(group->fgd,group->fgd+group->cItems);
                for(auto &d:batch->descriptors){
                    ULONGLONG size=((ULONGLONG)d.nFileSizeHigh<<32)|d.nFileSizeLow;
                    if(!(d.dwFlags&FD_FILESIZE) || (d.dwFileAttributes&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) ||
                       !wmemchr(d.cFileName,0,260) || !d.cFileName[0] || wcspbrk(d.cFileName,L"\\/:*?\"<>|") || size>100ull*1024*1024-batch->total){valid=false;break;}
                    d.dwFlags=FD_FILESIZE|FD_ATTRIBUTES|FD_UNICODE;d.dwFileAttributes=FILE_ATTRIBUTE_NORMAL;batch->total+=size;
                }
            }
            if(group)GlobalUnlock(medium.hGlobal);
        }
        ReleaseStgMedium(&medium);
    }else valid=false;
    if(valid && GetClipboardOwner()==owner){
        batch->rdpSource=std::make_shared<FileChannelSource>(token,(unsigned)batch->descriptors.size());
    }else valid=false;
    // Acquiring delayed FILECONTENTS streams can also advance the sequence.
    DWORD sequence=GetClipboardSequenceNumber();valid=valid && GetClipboardOwner()==owner;
    source->Release();
    if(valid){auto resolved=new ResolvedPaste{sequence,batch};if(!PostMessageW(window,WM_APP+4,0,(LPARAM)resolved))delete resolved;observedSequence=sequence;}
    return true;
}
static void poll_bridge_clipboard(HWND window){
    DWORD seq=GetClipboardSequenceNumber();
    if(seq==observedSequence || resolving)return;
    if(poll_rdp_clipboard(window))return;
    UINT format=RegisterClipboardFormatW(L"CalabiRdpCopyV1");
    if(!IsClipboardFormatAvailable(format)){observedSequence=seq;return;}
    if(!OpenClipboard(window))return;
    HGLOBAL memory=(HGLOBAL)GetClipboardData(format);SIZE_T length=memory?GlobalSize(memory):0;
    const char *text=length>0 && length<=256?(const char*)GlobalLock(memory):nullptr;
    std::string marker;
    if(text && memchr(text,0,length))marker=text;
    if(text)GlobalUnlock(memory);
    // Delayed RDP rendering can change the sequence during GetClipboardData.
    seq=GetClipboardSequenceNumber();CloseClipboard();
    if(marker.empty())return;
    observedSequence=seq;
    if(marker.empty() || marker.find('/')==std::string::npos || marker.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+=_-")!=std::string::npos)return;
    resolving=true;
    std::thread([window,marker,seq]{
        auto batch=std::make_shared<Batch>();batch->marker=marker;batch->total=0;
        std::string reply;
        for(unsigned retry=0;retry<20;retry++) {
            if(GetClipboardSequenceNumber()!=seq)break;
            reply=bridge_rpc("resolve "+marker);
            if(reply.rfind("data ",0)==0)break;
            Sleep(250);
        }
        std::vector<BYTE> data;
        bool ok=reply.rfind("data ",0)==0 && decode_hex(reply.substr(5),data) && data.size()>=4;
        DWORD count=0;if(ok)memcpy(&count,data.data(),4);
        ok=ok && count>0 && count<=32 && data.size()==4+sizeof(FILEDESCRIPTORW)*count;
        if(ok){batch->descriptors.resize(count);memcpy(batch->descriptors.data(),data.data()+4,count*sizeof(FILEDESCRIPTORW));
            for(const auto &d:batch->descriptors){ULONGLONG size=((ULONGLONG)d.nFileSizeHigh<<32)|d.nFileSizeLow;
                if(!wmemchr(d.cFileName,0,260) || size>100ull*1024*1024-batch->total){ok=false;break;}batch->total+=size;}}
        auto result=new ResolvedPaste{seq,ok?batch:nullptr};
        if(!PostMessageW(window,WM_APP+4,0,(LPARAM)result)){delete result;bridge_cancel(batch);}
        resolving=false;
    }).detach();
}
