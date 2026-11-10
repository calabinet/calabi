// Destination-side Shell contract probe. No network, real source files, hooks,
// COM registration or clipboard access before an explicit click on Copy.
#ifndef UNICODE
#define UNICODE
#endif
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shlobj.h>
#include <shldisp.h>
#include <sherrors.h>
#include <atomic>
#include <algorithm>
#include <memory>
#include <mutex>
#include <cstdio>
#include <cassert>
#include <cstring>
#include <thread>
#include <vector>
#include <string>
// GUI test binaries must fail through stderr, never a CRT modal assertion.
#undef assert
#define assert(expr) do { if(!(expr)) { fprintf(stderr,"Test assertion failed: %s (%s:%d, win32=%lu)\n",#expr,__FILE__,__LINE__,GetLastError()); fflush(stderr); ExitProcess(3); } } while(0)

static const ULONGLONG fileSize=32ull*1024*1024;
static const wchar_t *fileName=L"Calabi-粘贴验证-32MiB.bin";
#include "shell-rdp-source.h"
#include "shell-file-channel.h"
struct FileProgress {
    std::vector<std::pair<ULONGLONG,ULONGLONG>> ranges;
    ULONGLONG bytes=0;
    bool touched=false,failed=false;
};
struct Batch {
    std::atomic<bool> cancelled{false}, started{false}, finished{false};
    std::atomic<ULONGLONG> read{0};
    std::atomic<LONG> result{S_OK};
    std::atomic<HRESULT> interruption{S_OK};
    ULONGLONG size=fileSize;
    DWORD delay=25;
    std::string marker;
    std::vector<FILEDESCRIPTORW> descriptors;
    std::vector<ULONGLONG> receivedPrefixes; // embedded RDP reader, protected by its read lock
    std::shared_ptr<RdpSource> rdpSource;
    std::mutex rdpReadLock;
    std::atomic<DWORD> rdpReadThread{0};
    ULONGLONG total=fileSize;
    std::atomic<bool> cancelSent{false}, progressShown{false};
    std::mutex attemptLock; // serializes retry setup and cancellation
    std::mutex progressLock; // never held across network/COM calls
    std::vector<FileProgress> fileProgress;
    unsigned currentFile=0;
    void progress(unsigned index,ULONGLONG offset,ULONG count,bool failed=false){
        std::lock_guard<std::mutex> guard(progressLock);
        if(index>=descriptors.size())return;
        fileProgress.resize(descriptors.size());currentFile=index;
        auto &f=fileProgress[index];f.touched=true;f.failed=f.failed||failed;
        ULONGLONG limit=((ULONGLONG)descriptors[index].nFileSizeHigh<<32)|descriptors[index].nFileSizeLow;
        if(count && offset<limit){
            f.ranges.emplace_back(offset,offset+std::min<ULONGLONG>(count,limit-offset));
            std::sort(f.ranges.begin(),f.ranges.end());
            std::vector<std::pair<ULONGLONG,ULONGLONG>> merged;
            for(auto range:f.ranges){
                if(!merged.empty() && range.first<=merged.back().second)merged.back().second=std::max(merged.back().second,range.second);
                else merged.push_back(range);
            }
            f.ranges=std::move(merged);f.bytes=0;for(auto range:f.ranges)f.bytes+=range.second-range.first;
        }
        ULONGLONG sum=0;for(auto &item:fileProgress)sum+=item.bytes;read=sum;
    }
    void resetProgress(){std::lock_guard<std::mutex> guard(progressLock);fileProgress.clear();currentFile=0;read=0;}

    void recordInterruption(HRESULT reason) {
        HRESULT expected=S_OK;
        interruption.compare_exchange_strong(expected,reason);
    }
    void cancel(HRESULT reason=HRESULT_FROM_WIN32(ERROR_CANCELLED)) {
        std::lock_guard<std::mutex> guard(attemptLock);
        if(!finished)recordInterruption(reason);
        cancelled=true;
    }
};
using BatchPtr=std::shared_ptr<Batch>;
static HRESULT bridge_read(BatchPtr,unsigned,ULONGLONG,void*,ULONG,ULONG*);
static void bridge_cancel(BatchPtr);
static std::string bridge_rpc(const std::string &);
static HWND bridgeWindow;
#include "shell-paste-progress.h"

// FTM lets Explorer consume the stream on its copy worker; the UI never blocks
// waiting for a network-style Read. Real integration must keep this property.
class Stream final:public IStream {
    std::atomic<ULONG> refs{1};
    IUnknown *marshaler=nullptr;
    BatchPtr batch;
    ULONGLONG position=0;
    unsigned index=0;
    ULONGLONG size()const{return batch->descriptors.empty()?batch->size:((ULONGLONG)batch->descriptors[index].nFileSizeHigh<<32)|batch->descriptors[index].nFileSizeLow;}
    std::mutex lock;
public:
    explicit Stream(BatchPtr b,unsigned i=0):batch(b),index(i) {CoCreateFreeThreadedMarshaler(this,&marshaler);}
    ~Stream(){if(marshaler)marshaler->Release();}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void **out) override {
        if(!out)return E_POINTER;*out=nullptr;
        if(id==IID_IUnknown || id==IID_ISequentialStream || id==IID_IStream)*out=static_cast<IStream*>(this);
        else if(id==IID_IMarshal && marshaler)return marshaler->QueryInterface(id,out);
        else return E_NOINTERFACE;
        AddRef();return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override{return ++refs;}
    ULONG STDMETHODCALLTYPE Release() override{ULONG n=--refs;if(!n)delete this;return n;}
    HRESULT STDMETHODCALLTYPE Read(void *out,ULONG count,ULONG *got) override {
        if(got)*got=0;if(count && !out)return STG_E_INVALIDPOINTER;
        std::lock_guard<std::mutex> guard(lock);
        if(batch->cancelled)return HRESULT_FROM_WIN32(ERROR_CANCELLED);
        batch->started=true;
        ULONG length=(ULONG)std::min<ULONGLONG>(count,size()-position);
        if(!batch->marker.empty() || batch->rdpSource){
            batch->progress(index,position,0);
            ULONG read=0;HRESULT hr=bridge_read(batch,index,position,out,length,&read);batch->progress(index,position,read,FAILED(hr));position+=read;if(got)*got=read;
            if(FAILED(hr)){batch->recordInterruption(hr);batch->result=hr;batch->finished=true;return hr;}return read==count?S_OK:S_FALSE;
        }
        for(ULONG i=0;i<length;) {
            if(batch->delay)Sleep(batch->delay);
            if(batch->cancelled)return HRESULT_FROM_WIN32(ERROR_CANCELLED);
            ULONG end=std::min<ULONG>(length,i+65536);
            for(;i<end;i++)static_cast<BYTE*>(out)[i]=(BYTE)((position+i)%251);
        }
        position+=length;if(got)*got=length;
        ULONGLONG old=batch->read;
        while(old<position && !batch->read.compare_exchange_weak(old,position)){}
        return length==count?S_OK:S_FALSE;
    }
    HRESULT STDMETHODCALLTYPE Write(const void*,ULONG,ULONG*) override{return STG_E_ACCESSDENIED;}
    HRESULT STDMETHODCALLTYPE Seek(LARGE_INTEGER move,DWORD origin,ULARGE_INTEGER *at) override {
        std::lock_guard<std::mutex> guard(lock);
        if(origin>STREAM_SEEK_END)return STG_E_INVALIDFUNCTION;
        LONGLONG base=origin==STREAM_SEEK_SET?0:origin==STREAM_SEEK_CUR?(LONGLONG)position:(LONGLONG)size();
        if(move.QuadPart < -base || move.QuadPart>(LONGLONG)size()-base)return STG_E_INVALIDFUNCTION;
        position=base+move.QuadPart;if(at)at->QuadPart=position;return S_OK;
    }
    HRESULT STDMETHODCALLTYPE SetSize(ULARGE_INTEGER) override{return STG_E_ACCESSDENIED;}
    HRESULT STDMETHODCALLTYPE CopyTo(IStream *to,ULARGE_INTEGER size,ULARGE_INTEGER *read,ULARGE_INTEGER *written) override {
        if(read)read->QuadPart=0;if(written)written->QuadPart=0;if(!to)return E_POINTER;
        BYTE buffer[65536];ULONGLONG left=size.QuadPart;
        while(left) {
            ULONG got=0,sent=0;HRESULT hr=Read(buffer,(ULONG)std::min<ULONGLONG>(left,sizeof(buffer)),&got);
            if(FAILED(hr))return hr;
            if(read)read->QuadPart+=got;
            HRESULT write=to->Write(buffer,got,&sent);if(written)written->QuadPart+=sent;
            if(FAILED(write))return write;if(sent!=got)return STG_E_MEDIUMFULL;
            left-=got;if(hr==S_FALSE)return S_FALSE;
        }
        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Commit(DWORD) override{return S_OK;}
    HRESULT STDMETHODCALLTYPE Revert() override{return STG_E_REVERTED;}
    HRESULT STDMETHODCALLTYPE LockRegion(ULARGE_INTEGER,ULARGE_INTEGER,DWORD) override{return STG_E_INVALIDFUNCTION;}
    HRESULT STDMETHODCALLTYPE UnlockRegion(ULARGE_INTEGER,ULARGE_INTEGER,DWORD) override{return STG_E_INVALIDFUNCTION;}
    HRESULT STDMETHODCALLTYPE Stat(STATSTG *s,DWORD) override {
        if(!s)return E_POINTER;*s={};s->type=STGTY_STREAM;s->cbSize.QuadPart=size();s->grfMode=STGM_READ;return S_OK;
    }
    HRESULT STDMETHODCALLTYPE Clone(IStream **out) override {
        if(!out)return E_POINTER;std::lock_guard<std::mutex> guard(lock);
        auto copy=new Stream(batch,index);copy->position=position;*out=copy;return S_OK;
    }
};

class Files final:public IDataObject,public IDataObjectAsyncCapability {
    std::atomic<ULONG> refs{1};
    std::atomic<BOOL> asynchronous{TRUE},inOperation{FALSE};
    IUnknown *marshaler=nullptr;
    BatchPtr batch;
    CLIPFORMAT descriptor=(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_FILEDESCRIPTORW);
    CLIPFORMAT contents=(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_FILECONTENTS);
    CLIPFORMAT preferred=(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_PREFERREDDROPEFFECT);
    CLIPFORMAT owned=(CLIPFORMAT)RegisterClipboardFormatW(L"CalabiRdpCopyOwnedV1");
public:
    explicit Files(BatchPtr b):batch(b){CoCreateFreeThreadedMarshaler(static_cast<IDataObject*>(this),&marshaler);}
    ~Files(){if(marshaler)marshaler->Release();}
    HRESULT STDMETHODCALLTYPE QueryInterface(REFIID id,void **out) override {
        if(!out)return E_POINTER;*out=nullptr;
        if(id==IID_IUnknown || id==IID_IDataObject)*out=static_cast<IDataObject*>(this);
        else if(id==IID_IDataObjectAsyncCapability)*out=static_cast<IDataObjectAsyncCapability*>(this);
        else if(id==IID_IMarshal && marshaler)return marshaler->QueryInterface(id,out);
        else return E_NOINTERFACE;
        AddRef();return S_OK;
    }
    ULONG STDMETHODCALLTYPE AddRef() override{return ++refs;}
    ULONG STDMETHODCALLTYPE Release() override{ULONG n=--refs;if(!n)delete this;return n;}
    HRESULT STDMETHODCALLTYPE QueryGetData(FORMATETC *f) override {
        if(!f)return E_POINTER;if(f->dwAspect!=DVASPECT_CONTENT)return DV_E_DVASPECT;
        if(f->cfFormat==contents)return f->lindex<0 || (size_t)f->lindex>=std::max<size_t>(1,batch->descriptors.size())?DV_E_LINDEX:(f->tymed&TYMED_ISTREAM)?S_OK:DV_E_TYMED;
        if(f->cfFormat==descriptor || f->cfFormat==preferred || f->cfFormat==owned)return (f->tymed&TYMED_HGLOBAL)?S_OK:DV_E_TYMED;
        return DV_E_FORMATETC;
    }
    HRESULT STDMETHODCALLTYPE GetData(FORMATETC *f,STGMEDIUM *m) override {
        if(!m)return E_POINTER;*m={};HRESULT hr=QueryGetData(f);if(FAILED(hr))return hr;
        if(batch->cancelled)return HRESULT_FROM_WIN32(ERROR_CANCELLED);
        if(f->cfFormat==contents){m->tymed=TYMED_ISTREAM;m->pstm=new Stream(batch,(unsigned)f->lindex);return S_OK;}
        SIZE_T size=f->cfFormat==descriptor?4+sizeof(FILEDESCRIPTORW)*std::max<size_t>(1,batch->descriptors.size()):sizeof(DWORD);
        HGLOBAL global=GlobalAlloc(GMEM_MOVEABLE|GMEM_ZEROINIT,size);if(!global)return E_OUTOFMEMORY;
        void *data=GlobalLock(global);if(!data){GlobalFree(global);return E_OUTOFMEMORY;}
        if(f->cfFormat==descriptor) {
            auto group=static_cast<FILEGROUPDESCRIPTORW*>(data);group->cItems=1;
            if(!batch->descriptors.empty()){group->cItems=(UINT)batch->descriptors.size();memcpy(group->fgd,batch->descriptors.data(),batch->descriptors.size()*sizeof(FILEDESCRIPTORW));}
            else {auto &d=group->fgd[0];d.dwFlags=FD_ATTRIBUTES|FD_FILESIZE|FD_PROGRESSUI|FD_UNICODE;
            d.dwFileAttributes=FILE_ATTRIBUTE_NORMAL;d.nFileSizeLow=(DWORD)batch->size;
            d.nFileSizeHigh=(DWORD)(batch->size>>32);wcscpy(d.cFileName,fileName);}
        } else *static_cast<DWORD*>(data)=DROPEFFECT_COPY;
        GlobalUnlock(global);m->tymed=TYMED_HGLOBAL;m->hGlobal=global;return S_OK;
    }
    HRESULT STDMETHODCALLTYPE GetDataHere(FORMATETC*,STGMEDIUM*) override{return DATA_E_FORMATETC;}
    HRESULT STDMETHODCALLTYPE GetCanonicalFormatEtc(FORMATETC*,FORMATETC *out) override{if(out)out->ptd=nullptr;return E_NOTIMPL;}
    HRESULT STDMETHODCALLTYPE SetData(FORMATETC*,STGMEDIUM *m,BOOL release) override {
        // Shell may report performed effect. It does not grant source deletion.
        if(release && m)ReleaseStgMedium(m);return S_OK;
    }
    HRESULT STDMETHODCALLTYPE EnumFormatEtc(DWORD direction,IEnumFORMATETC **out) override {
        if(direction!=DATADIR_GET)return E_NOTIMPL;
        FORMATETC formats[]={{descriptor,nullptr,DVASPECT_CONTENT,-1,TYMED_HGLOBAL},
            {contents,nullptr,DVASPECT_CONTENT,0,TYMED_ISTREAM},{preferred,nullptr,DVASPECT_CONTENT,-1,TYMED_HGLOBAL},
            {owned,nullptr,DVASPECT_CONTENT,-1,TYMED_HGLOBAL}};
        return SHCreateStdEnumFmtEtc(batch->marker.empty() && !batch->rdpSource?3:4,formats,out);
    }
    HRESULT STDMETHODCALLTYPE DAdvise(FORMATETC*,DWORD,IAdviseSink*,DWORD*) override{return OLE_E_ADVISENOTSUPPORTED;}
    HRESULT STDMETHODCALLTYPE DUnadvise(DWORD) override{return OLE_E_ADVISENOTSUPPORTED;}
    HRESULT STDMETHODCALLTYPE EnumDAdvise(IEnumSTATDATA**) override{return OLE_E_ADVISENOTSUPPORTED;}
    HRESULT STDMETHODCALLTYPE SetAsyncMode(BOOL value) override{asynchronous=value;return S_OK;}
    HRESULT STDMETHODCALLTYPE GetAsyncMode(BOOL *value) override{if(!value)return E_POINTER;*value=asynchronous;return S_OK;}
    HRESULT STDMETHODCALLTYPE StartOperation(IBindCtx*) override{
        {
            std::lock_guard<std::mutex> guard(batch->attemptLock);
            if(batch->cancelled){
                auto reason=batch->interruption.load();
                return FAILED(reason)?reason:HRESULT_FROM_WIN32(ERROR_CANCELLED);
            }
            bool retryable=batch->rdpSource!=nullptr;
#ifdef CALABI_SHELL_RECEIVE
            retryable=true;
#endif
            if(retryable && batch->finished.exchange(false)){
                batch->interruption=S_OK;
                batch->progressShown=false;batch->resetProgress();batch->receivedPrefixes.clear();
            }
        }
        if(!batch->marker.empty() || batch->rdpSource)show_paste_progress(batch);
        if(!batch->marker.empty() && bridge_rpc("begin "+batch->marker)!="ok"){batch->result=STG_E_READFAULT;batch->finished=true;return STG_E_READFAULT;}
        inOperation=TRUE;batch->started=true;batch->finished=false;

        return S_OK;
    }
    HRESULT STDMETHODCALLTYPE InOperation(BOOL *value) override{if(!value)return E_POINTER;*value=inOperation;return S_OK;}
    HRESULT STDMETHODCALLTYPE EndOperation(HRESULT result,IBindCtx*,DWORD) override {
        if(FAILED(result) && !batch->marker.empty())bridge_cancel(batch);
        batch->result=result;batch->finished=true;inOperation=FALSE;return S_OK;
    }
};

#ifdef CALABI_SHELL_RECEIVE
#include "windows-shell-receive.inc"
#else
#include "shell-paste-bridge.h"
static Files *files;
static BatchPtr active;
#include "shell-mesh-copy.h"
#include "windows_remote_menu.h"
static HWND statusLabel,copyButton,cancelButton;
static void update_status() {
    wchar_t text[512];
    if(bridgeMode){
        if(!active)wcscpy(text,L"请重新复制文件，并确认 远程登录已允许复制文件。");
        else if(active->cancelled)wcscpy(text,L"已取消接收。\n未完成的网络文件已停止接收；目标文件由资源管理器清理。");
        else if(active->finished)wcscpy(text,SUCCEEDED(active->result)?L"文件粘贴已结束。\n请以目标文件夹的结果为准。":L"文件粘贴未完成。\n请检查连接，再重新复制。");
        else if(!active->started)wcscpy(text,L"文件已可粘贴。\n到目标文件夹按 Ctrl+V 即开始接收，无需再次复制。");
        else swprintf(text,512,L"接收：%.80ls（共 %zu 个文件）\n%.1f / %.1f MiB\n接收并校验后写入目标文件夹。",active->descriptors[0].cFileName,active->descriptors.size(),active->read.load()/1048576.0,active->total/1048576.0);
    }
    else if(!active)wcscpy(text,L"独立验证程序，不连接远端、不读取真实文件。\n点击下方按钮后，到资源管理器的空文件夹按 Ctrl+V。\n会生成一个 32 MiB 测试文件。关闭程序会停止未完成的读取。");
    else if(active->finished)swprintf(text,512,L"资源管理器已结束任务，结果 0x%08lX。\n请检查目标文件是否完整；取消测试请检查是否出现错误弹窗。",active->result.load());
    else if(active->cancelled)wcscpy(text,L"已请求取消，后续读取返回 ERROR_CANCELLED。\n请观察资源管理器是否显示错误，并检查目标目录残留文件。\n这是验证程序，尚不能保证资源管理器能无提示取消。");
    else if(active->started)swprintf(text,512,L"目的端接收进度：%.1f / 32 MiB（%u%%）\n这是目的端本地窗口。可以点击「取消接收」。\n读完不等于写入完成，请以资源管理器结果为准。",active->read.load()/1048576.0,(unsigned)(100*active->read/active->size));
    else wcscpy(text,L"测试文件已放入剪贴板。\n到资源管理器目标文件夹按 Ctrl+V；无需等待准备完成。\n请分别测试正常完成和中途点击「取消接收」。");
    SetWindowTextW(statusLabel,text);
    EnableWindow(copyButton,bridgeMode || !active || active->finished || active->cancelled || !active->started);
    EnableWindow(cancelButton,active && !active->finished && !active->cancelled);
}
static LRESULT CALLBACK window_proc(HWND w,UINT msg,WPARAM wp,LPARAM lp) {
    switch(msg) {
    case WM_CREATE:
        statusLabel=CreateWindowW(L"STATIC",L"",WS_CHILD|WS_VISIBLE,20,20,550,120,w,nullptr,nullptr,nullptr);
        copyButton=CreateWindowW(L"BUTTON",L"复制测试文件",WS_CHILD|WS_VISIBLE|WS_TABSTOP,20,155,170,34,w,(HMENU)1,nullptr,nullptr);
        cancelButton=CreateWindowW(L"BUTTON",L"取消接收",WS_CHILD|WS_VISIBLE|WS_TABSTOP,210,155,150,34,w,(HMENU)2,nullptr,nullptr);
        for(HWND child:{statusLabel,copyButton,cancelButton})SendMessageW(child,WM_SETFONT,(WPARAM)GetStockObject(DEFAULT_GUI_FONT),TRUE);
        SetTimer(w,1,150,nullptr);update_status();return 0;
    case WM_TIMER:if(bridgeMode){if(meshEnabled)poll_mesh_copy(w);poll_bridge_clipboard(w);if(remoteMenuEnabled)remote_menu_refresh();}update_status();return 0;
    case WM_APP+6:{std::unique_ptr<std::string> reply((std::string*)lp);mesh_apply_state(w,*reply);return 0;}
    case WM_APP+4:{
        std::unique_ptr<ResolvedPaste> resolved((ResolvedPaste*)lp);
        if(!resolved->batch && GetClipboardSequenceNumber()!=resolved->sequence)return 0;
        if(!resolved->batch){SetWindowTextW(statusLabel,L"无法接收这批文件，请确认两端 Calabi 正在运行并重新复制，然后重新复制。");ShowWindow(w,SW_SHOWNOACTIVATE);return 0;}
        if(GetClipboardSequenceNumber()!=resolved->sequence){auto batch=resolved->batch;std::thread([batch]{bridge_cancel(batch);}).detach();return 0;}
        auto object=new Files(resolved->batch);
        if(SUCCEEDED(OleSetClipboard(object))){if(active)active->cancelled=true;if(files)files->Release();files=object;active=resolved->batch;observedSequence=GetClipboardSequenceNumber();}
        else {object->Release();auto batch=resolved->batch;std::thread([batch]{bridge_cancel(batch);}).detach();}
        update_status();return 0;
    }
    case WM_APP+5:ShowWindow(w,SW_SHOWNOACTIVATE);update_status();return 0;
    case WM_COMMAND:
        if(LOWORD(wp)==1 && bridgeMode){ShowWindow(w,SW_HIDE);return 0;}
        if(LOWORD(wp)==1 && !bridgeMode) {
            if(active && !active->finished)active->cancelled=true;
            auto next=std::make_shared<Batch>();auto object=new Files(next);
            HRESULT hr=OleSetClipboard(object);
            if(SUCCEEDED(hr)){if(files)files->Release();files=object;active=next;}
            else {object->Release();MessageBoxW(w,L"剪贴板暂不可用，请稍后重试。",L"Calabi 粘贴验证",MB_OK|MB_ICONWARNING);}
        } else if(LOWORD(wp)==2 && active){active->cancelled=true;if(bridgeMode){auto batch=active;std::thread([batch]{bridge_cancel(batch);}).detach();}}
        update_status();return 0;
    case WM_CLOSE:
        if(bridgeMode){ShowWindow(w,SW_HIDE);return 0;}
        if(active)active->cancelled=true;
        if(files && OleIsCurrentClipboard(files)==S_OK)OleSetClipboard(nullptr);
        DestroyWindow(w);return 0;
    case WM_DESTROY:PostQuitMessage(0);return 0;
    }
    return DefWindowProcW(w,msg,wp,lp);
}
static int self_test() {
    assert(SUCCEEDED(CoInitializeEx(nullptr,COINIT_MULTITHREADED)));
    auto b=std::make_shared<Batch>();b->delay=0;b->size=1000;
    auto data=new Files(b);FORMATETC format={(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_FILECONTENTS),nullptr,DVASPECT_CONTENT,0,TYMED_ISTREAM};
    STGMEDIUM medium={};assert(data->GetData(&format,&medium)==S_OK);
    BYTE out[1024];ULONG got;assert(medium.pstm->Read(out,500,&got)==S_OK && got==500);
    for(unsigned i=0;i<got;i++)assert(out[i]==i%251);
    IStream *clone=nullptr;assert(medium.pstm->Clone(&clone)==S_OK);
    assert(clone->Read(out,1024,&got)==S_FALSE && got==500 && out[0]==500%251);clone->Release();
    IStream *marshaled=nullptr;
    assert(CoMarshalInterThreadInterfaceInStream(IID_IStream,medium.pstm,&marshaled)==S_OK);
    std::thread consumer([marshaled] {
        assert(SUCCEEDED(CoInitializeEx(nullptr,COINIT_MULTITHREADED)));
        IStream *remote=nullptr;assert(CoGetInterfaceAndReleaseStream(marshaled,IID_IStream,(void**)&remote)==S_OK);
        BYTE bytes[16];ULONG count=0;assert(remote->Read(bytes,16,&count)==S_OK && count==16 && bytes[0]==500%251);
        remote->Release();CoUninitialize();
    });consumer.join();
    LARGE_INTEGER at;at.QuadPart=-517;assert(FAILED(medium.pstm->Seek(at,STREAM_SEEK_CUR,nullptr)));
    format.lindex=1;assert(data->QueryGetData(&format)==DV_E_LINDEX);
    b->cancelled=true;assert(medium.pstm->Read(out,1,&got)==HRESULT_FROM_WIN32(ERROR_CANCELLED) && got==0);
    IDataObjectAsyncCapability *async=nullptr;assert(data->QueryInterface(IID_IDataObjectAsyncCapability,(void**)&async)==S_OK);
    BOOL value=FALSE;assert(async->GetAsyncMode(&value)==S_OK && value);
    assert(async->StartOperation(nullptr)==HRESULT_FROM_WIN32(ERROR_CANCELLED));b->cancelled=false;
    assert(async->StartOperation(nullptr)==S_OK && async->InOperation(&value)==S_OK && value);
    async->EndOperation(HRESULT_FROM_WIN32(ERROR_CANCELLED),nullptr,0);assert(b->finished && FAILED(b->result));
    async->Release();ReleaseStgMedium(&medium);data->Release();CoUninitialize();
    puts("Shell paste contract passed: stream content/EOF/clone/seek/index, cross-thread COM consumption, cancellation HRESULT and async lifecycle. No user clipboard accessed.");return 0;
}
// Test the actual private-pipe transport and native IStream against a caller's
// isolated TLS receiver, without touching any clipboard or creating a window.
static int bridge_test(const wchar_t *argument){
    wchar_t token[256],mode[16];if(swscanf(argument,L"%255ls %15ls",token,mode)!=2)return 2;
    char encoded[512];if(!WideCharToMultiByte(CP_UTF8,0,token,-1,encoded,sizeof(encoded),nullptr,nullptr))return 2;
    assert(SUCCEEDED(CoInitializeEx(nullptr,COINIT_MULTITHREADED)));
    std::string reply=bridge_rpc(std::string("resolve ")+encoded);std::vector<BYTE> bytes;
    assert(reply.rfind("data ",0)==0 && decode_hex(reply.substr(5),bytes) && bytes.size()==4+sizeof(FILEDESCRIPTORW));
    auto b=std::make_shared<Batch>();b->marker=encoded;b->descriptors.resize(1);memcpy(b->descriptors.data(),bytes.data()+4,sizeof(FILEDESCRIPTORW));
    b->total=((ULONGLONG)b->descriptors[0].nFileSizeHigh<<32)|b->descriptors[0].nFileSizeLow;
    auto stream=new Stream(b);std::atomic<HRESULT> result{E_PENDING};
    bool cancel=!wcscmp(mode,L"cancel");
    std::thread reader([&]{
        CoInitializeEx(nullptr,COINIT_MULTITHREADED);
        BYTE data[65536];ULONGLONG offset=0;HRESULT hr=S_OK;
        while(offset<b->total){ULONG n=0;hr=stream->Read(data,sizeof(data),&n);if(FAILED(hr))break;
            if(!n){hr=E_FAIL;break;}for(ULONG i=0;i<n;i++)assert(data[i]==(BYTE)((offset+i)%251));offset+=n;}
        result=hr;CoUninitialize();
    });
    if(cancel){ULONGLONG deadline=GetTickCount64()+15000;while(!b->read && result==E_PENDING && GetTickCount64()<deadline)Sleep(5);
        assert(b->read>0 && result==E_PENDING);b->cancelled=true;bridge_cancel(b);}
    reader.join();assert(cancel?result==HRESULT_FROM_WIN32(ERROR_CANCELLED):SUCCEEDED(result));
    if(!cancel)assert(bridge_rpc("release "+b->marker)=="ok");
    stream->Release();CoUninitialize();fprintf(stderr,"Native pipe + IStream %s passed.\n",cancel?"cancellation":"verified copy");return 0;
}

// Uses an isolated window station: never reads or replaces the user's clipboard.
static std::string testMarker;
static unsigned testRenderAttempts;
static LRESULT CALLBACK delayed_owner(HWND w,UINT m,WPARAM wp,LPARAM lp){
    if(m==WM_RENDERFORMAT && wp==RegisterClipboardFormatW(L"CalabiRdpCopyV1")){
        if(++testRenderAttempts==1)return 0; // Retry a transient RDP render failure.
        HGLOBAL h=GlobalAlloc(GMEM_MOVEABLE,testMarker.size()+1);
        void *p=GlobalLock(h);memcpy(p,testMarker.c_str(),testMarker.size()+1);GlobalUnlock(h);
        assert(SetClipboardData((UINT)wp,h));return 0;
    }
    return DefWindowProcW(w,m,wp,lp);
}
static int clipboard_contract_test(HINSTANCE instance,const wchar_t *token){
    HWINSTA station=CreateWindowStationW(nullptr,0,WINSTA_ALL_ACCESS,nullptr);assert(station && SetProcessWindowStation(station));
    HDESK desktop=CreateDesktopW(L"test",nullptr,nullptr,0,GENERIC_ALL,nullptr);assert(desktop && SetThreadDesktop(desktop));
    assert(SUCCEEDED(OleInitialize(nullptr)));
    char encoded[256];assert(WideCharToMultiByte(CP_UTF8,0,token,-1,encoded,sizeof(encoded),nullptr,nullptr));testMarker=encoded;
    WNDCLASSW cls={};cls.hInstance=instance;cls.lpfnWndProc=delayed_owner;cls.lpszClassName=L"CalabiDelayedClipboardTest";RegisterClassW(&cls);
    HWND owner=CreateWindowW(cls.lpszClassName,L"",0,0,0,1,1,nullptr,nullptr,instance,nullptr);assert(owner);
    assert(OpenClipboard(owner));assert(EmptyClipboard());SetClipboardData(RegisterClipboardFormatW(L"CalabiRdpCopyV1"),nullptr);CloseClipboard();
    cls.lpfnWndProc=window_proc;cls.lpszClassName=L"CalabiPasteContractTest";RegisterClassW(&cls);
    bridgeMode=true;
    HWND w=CreateWindowW(cls.lpszClassName,L"",0,0,0,610,250,nullptr,nullptr,instance,nullptr);assert(w);bridgeWindow=w;
    poll_bridge_clipboard(w);
    ULONGLONG deadline=GetTickCount64()+10000;
    while(!active && GetTickCount64()<deadline){MSG msg;while(PeekMessageW(&msg,nullptr,0,0,PM_REMOVE)){TranslateMessage(&msg);DispatchMessageW(&msg);}Sleep(5);}
    assert(active && active->marker==testMarker && !active->started && testRenderAttempts>=2);
    IDataObject *data=nullptr;assert(SUCCEEDED(OleGetClipboard(&data)));
    FORMATETC desc={(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_FILEDESCRIPTORW),nullptr,DVASPECT_CONTENT,-1,TYMED_HGLOBAL};
    STGMEDIUM md={};assert(data->GetData(&desc,&md)==S_OK);ReleaseStgMedium(&md);
    IDataObjectAsyncCapability *async=nullptr;assert(SUCCEEDED(data->QueryInterface(IID_IDataObjectAsyncCapability,(void**)&async)));
    assert(async->StartOperation(nullptr)==S_OK);
    FORMATETC content={(CLIPFORMAT)RegisterClipboardFormatW(CFSTR_FILECONTENTS),nullptr,DVASPECT_CONTENT,0,TYMED_ISTREAM};
    assert(data->GetData(&content,&md)==S_OK);
    ULONGLONG offset=0;BYTE bytes[65536];while(offset<active->total){ULONG n=0;assert(SUCCEEDED(md.pstm->Read(bytes,sizeof(bytes),&n)) && n);for(ULONG i=0;i<n;i++)assert(bytes[i]==(BYTE)((offset+i)%251));offset+=n;}
    ReleaseStgMedium(&md);assert(async->EndOperation(S_OK,nullptr,DROPEFFECT_COPY)==S_OK);async->Release();data->Release();
    assert(bridge_rpc("release "+testMarker)=="ok");OleSetClipboard(nullptr);
    if(files){files->Release();files=nullptr;}active.reset();DestroyWindow(w);DestroyWindow(owner);OleUninitialize();
    fprintf(stderr,"Isolated delayed clipboard -> OLE first paste -> TLS content passed.\n");return 0;
}

static int progress_ui_test(){
    HWINSTA station=CreateWindowStationW(nullptr,0,WINSTA_ALL_ACCESS,nullptr);assert(station && SetProcessWindowStation(station));
    HDESK desk=CreateDesktopW(L"test",nullptr,nullptr,0,GENERIC_ALL,nullptr);assert(desk && SetThreadDesktop(desk));
    assert(start_progress_ui());
    auto b=std::make_shared<Batch>();b->total=43ull*1024*1024;b->descriptors.resize(7);
    for(unsigned i=0;i<7;i++){swprintf(b->descriptors[i].cFileName,260,L"演示文稿-%u.pptx",i+1);b->descriptors[i].nFileSizeLow=(DWORD)(b->total/7);}
    b->total=(b->total/7)*7;
    // Overlapping reads and nonsequential ranges count each byte exactly once.
    b->progress(0,100,100);b->progress(0,0,150);b->progress(0,0,150);assert(b->read==200);
    b->progress(0,300,100);assert(b->read==300);
    b->progress(0,200,100);assert(b->read==400);
    b->progress(1,0,75,true);assert(b->read==475 && b->fileProgress[1].failed);
    b->resetProgress();assert(b->read==0 && b->fileProgress.empty());
    show_paste_progress(b);HWND w=pasteProgressWindow;DWORD_PTR result;
    assert(SendMessageTimeoutW(w,WM_NULL,0,0,SMTO_ABORTIFHUNG,1000,&result));
    ULONGLONG shownDeadline=GetTickCount64()+2000;while(!(GetWindowLongPtrW(w,GWL_STYLE)&WS_VISIBLE) && GetTickCount64()<shownDeadline)Sleep(5);
    assert((GetWindowLongPtrW(w,GWL_STYLE)&WS_VISIBLE) && b->read==0);
    assert(GetWindowLongPtrW(w,GWL_EXSTYLE)&WS_EX_TOPMOST); // visible before any network bytes
    b->progress(0,0,b->descriptors[0].nFileSizeLow);
    b->descriptors[1].nFileSizeLow=20*1024; b->total-=43ull*1024*1024/7-20*1024;
    b->progress(1,0,12*1024);
    assert(SendMessageTimeoutW(w,WM_LBUTTONUP,0,MAKELPARAM(40,230),SMTO_ABORTIFHUNG,1000,&result));
    RECT measured;GetWindowRect(w,&measured);assert(measured.bottom-measured.top==expandedHeight);
    assert(SendMessageTimeoutW(w,WM_LBUTTONUP,0,MAKELPARAM(390,523),SMTO_ABORTIFHUNG,1000,&result));
    assert(SendMessageTimeoutW(w,WM_LBUTTONUP,0,MAKELPARAM(290,523),SMTO_ABORTIFHUNG,1000,&result));
    wchar_t *path=_wgetenv(L"CALABI_PASTE_UI_CAPTURE");
    if(path && *path){
        HDC dc=GetDC(w),mem=CreateCompatibleDC(dc);BITMAPINFO info={};info.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);info.bmiHeader.biWidth=480;info.bmiHeader.biHeight=-expandedHeight;info.bmiHeader.biPlanes=1;info.bmiHeader.biBitCount=32;info.bmiHeader.biCompression=BI_RGB;
        void *pixels;HBITMAP bmp=CreateDIBSection(dc,&info,DIB_RGB_COLORS,&pixels,nullptr,0);auto old=SelectObject(mem,bmp);
        SendMessageW(w,WM_PRINTCLIENT,(WPARAM)mem,PRF_CLIENT);
        BITMAPFILEHEADER head={};head.bfType=0x4d42;head.bfOffBits=sizeof(head)+sizeof(info.bmiHeader);head.bfSize=head.bfOffBits+480*expandedHeight*4;
        FILE *file=_wfopen(path,L"wb");assert(file);fwrite(&head,sizeof(head),1,file);fwrite(&info.bmiHeader,sizeof(info.bmiHeader),1,file);fwrite(pixels,480*expandedHeight*4,1,file);fclose(file);
        SelectObject(mem,old);DeleteObject(bmp);DeleteDC(mem);ReleaseDC(w,dc);
    }
    {
        // A stalled file RPC on the OLE thread cannot freeze Cancel in the UI.
        std::lock_guard<std::mutex> blocked(pipeMutex);
        assert(SendMessageTimeoutW(w,WM_COMMAND,2,0,SMTO_ABORTIFHUNG,1000,&result));
        assert(b->cancelled);
    }
    stop_progress_ui();fprintf(stderr,"Independent progress UI passed: visible at zero bytes, live progress, cancel while RPC thread blocked.\n");return 0;
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,LPWSTR args,int show) {
    if(!wcsncmp(args,L"--paste-remote ",15))return remote_menu_command();
    if(!wcsncmp(args,L"--clipboard-contract-test ",wcslen(L"--clipboard-contract-test ")))return clipboard_contract_test(instance,args+wcslen(L"--clipboard-contract-test "));
    if(!wcscmp(args,L"--progress-ui-test"))return progress_ui_test();
    if(!wcscmp(args,L"--self-test"))return self_test();
    if(!wcsncmp(args,L"--bridge-test ",14))return bridge_test(args+14);
    bridgeMode=!wcscmp(args,L"--bridge");
    remoteMenuEnabled=bridgeMode;
    meshEnabled=bridgeMode;
    if(bridgeMode && !start_progress_ui()){stop_progress_ui();return 2;}
    if(FAILED(OleInitialize(nullptr))){stop_progress_ui();return 1;}
    WNDCLASSW cls={};cls.hInstance=instance;cls.lpfnWndProc=window_proc;cls.lpszClassName=L"CalabiShellPasteProbe";
    cls.hCursor=LoadCursor(nullptr,IDC_ARROW);cls.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);RegisterClassW(&cls);
    HWND w=CreateWindowW(cls.lpszClassName,bridgeMode?L"Calabi · 接收文件":L"Calabi · 目的端粘贴验证（独立实验）",WS_OVERLAPPED|WS_CAPTION|WS_SYSMENU|WS_MINIMIZEBOX,
        CW_USEDEFAULT,CW_USEDEFAULT,610,250,nullptr,nullptr,instance,nullptr);
    if(!w){OleUninitialize();stop_progress_ui();return 1;}bridgeWindow=w;
    if(bridgeMode)SetWindowTextW(copyButton,L"收起");else ShowWindow(w,show);
    MSG message;while(GetMessageW(&message,nullptr,0,0)>0){TranslateMessage(&message);DispatchMessageW(&message);}
    if(remoteMenuEnabled)remote_menu_register(L"",false);
    if(files)files->Release();active.reset();OleUninitialize();stop_progress_ui();return 0;
}
#endif // CALABI_SHELL_RECEIVE
