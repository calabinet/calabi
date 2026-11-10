#pragma once
#include "file_channel_protocol.h"
#include <wtsapi32.h>
// One serialized transport per destination process/current RDP session.
// Dynamically load the system DLL so isolated Shell fixtures need no RDP SDK.
struct FileChannelTransport {
    std::mutex mutex;HANDLE channel=nullptr;uint32_t next=0;BYTE activeToken[16]={};
    HMODULE dll=LoadLibraryExW(L"wtsapi32.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
    decltype(&WTSVirtualChannelOpen) open=dll?(decltype(open))GetProcAddress(dll,"WTSVirtualChannelOpen"):nullptr;
    decltype(&WTSVirtualChannelClose) close=dll?(decltype(close))GetProcAddress(dll,"WTSVirtualChannelClose"):nullptr;
    decltype(&WTSVirtualChannelRead) read=dll?(decltype(read))GetProcAddress(dll,"WTSVirtualChannelRead"):nullptr;
    decltype(&WTSVirtualChannelWrite) write=dll?(decltype(write))GetProcAddress(dll,"WTSVirtualChannelWrite"):nullptr;
    void reset(){if(channel && close)close(channel);channel=nullptr;}
    ~FileChannelTransport(){reset();if(dll)FreeLibrary(dll);}
};
static FileChannelTransport fileTransport;
class FileChannelSource final:public RdpSource {
    BYTE token[16];std::atomic<bool> cancelled{false};unsigned files;
public:
    FileChannelSource(const BYTE *value,unsigned count):files(count){memcpy(token,value,16);}
    void cancel()override{cancelled=true;}
    HRESULT read(unsigned index,ULONGLONG offset,void *out,ULONG count,ULONG *got)override{
        *got=0;if(index>=files || !count || count>CALFILE_BLOCK)return E_INVALIDARG;
        auto &t=fileTransport;std::lock_guard<std::mutex> guard(t.mutex);
        if(cancelled)return HRESULT_FROM_WIN32(ERROR_CANCELLED);
        if(!t.open || !t.close || !t.read || !t.write)return E_NOTIMPL;
        // A new copy may follow an RDP reconnect in the same Windows session.
        // Never reuse the preceding connection's WTS handle for its new token.
        if(memcmp(t.activeToken,token,16)){t.reset();memcpy(t.activeToken,token,16);}
        if(!t.channel)t.channel=t.open(WTS_CURRENT_SERVER_HANDLE,WTS_CURRENT_SESSION,(LPSTR)"calfile");
        if(!t.channel){fprintf(stderr,"rdp_stream stage=channel_open error=%lu\n",GetLastError());fflush(stderr);return STG_E_READFAULT;}
        BYTE request[CALFILE_REQUEST]={};uint32_t id=++t.next;if(!id)id=++t.next;
        cf_put32(request,CALFILE_MAGIC);cf_put32(request+4,id);memcpy(request+8,token,16);
        cf_put32(request+24,index);cf_put64(request+28,offset);cf_put32(request+36,count);
        ULONG written=0;
        if(!t.write(t.channel,(PCHAR)request,sizeof(request),&written) || written!=sizeof(request)){t.reset();return STG_E_READFAULT;}
        std::vector<BYTE> packet;packet.reserve(CALFILE_HEADER+CALFILE_BLOCK);
        ULONGLONG start=GetTickCount64(),deadline=start+15000;HRESULT result=STG_E_READFAULT;
        const char *reason="timeout";DWORD readError=0;ULONG lastBytes=0;uint32_t responseStatus=0;
        while(!cancelled && GetTickCount64()<deadline){
            BYTE chunk[1600];ULONG n=0;
            if(!t.read(t.channel,50,(PCHAR)chunk,sizeof(chunk),&n)){
                DWORD error=GetLastError();
                // WTS uses ERROR_IO_INCOMPLETE for a timed-out empty poll on
                // real Windows. The operation is pending, not a disk failure.
                if(error==ERROR_IO_INCOMPLETE || error==ERROR_TIMEOUT || error==WAIT_TIMEOUT)continue;
                readError=error;reason="api_read";break;
            }
            lastBytes=n;
            if(n>sizeof(chunk) || packet.size()+n>CALFILE_HEADER+CALFILE_BLOCK){reason="oversize";break;}
            packet.insert(packet.end(),chunk,chunk+n);
            if(packet.size()<CALFILE_HEADER)continue;
            if(cf_u32(packet.data())!=CALFILE_MAGIC || cf_u32(packet.data()+12)>CALFILE_BLOCK){reason="header";break;}
            size_t expected=CALFILE_HEADER+cf_u32(packet.data()+12);
            if(packet.size()<expected)continue;
            if(packet.size()!=expected){reason="length";break;}
            if(cf_u32(packet.data()+4)!=id){packet.clear();continue;} // discard late, canceled request
            responseStatus=cf_u32(packet.data()+8);reason="peer_response";
            if(!responseStatus && expected==CALFILE_HEADER+count && !cancelled){
                memcpy(out,packet.data()+CALFILE_HEADER,count);*got=count;result=S_OK;
            }
            break;
        }
        if(cancelled){result=HRESULT_FROM_WIN32(ERROR_CANCELLED);reason="cancelled";}
        if(FAILED(result))t.reset();
        if(!offset || FAILED(result)){fprintf(stderr,"rdp_stream stage=channel_read hr=0x%08lX index=%u offset=%llu requested=%lu detail=%s error=%lu buffered=%zu last=%lu status=%u elapsed=%llu received=%lu\n",result,index,offset,count,reason,readError,packet.size(),lastBytes,responseStatus,GetTickCount64()-start,*got);fflush(stderr);}
        return result;
    }
};
