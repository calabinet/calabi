// Interactive, bounded read-only file-channel diagnostic. No content saved.
#define wWinMain unused_channel_probe_main
#include "shell-paste-probe.cpp"
#undef wWinMain
int main(){
    OleInitialize(nullptr);UINT format=RegisterClipboardFormatW(L"CalabiRdpStreamV2");
    DWORD sequence=GetClipboardSequenceNumber();BYTE token[16]={};bool found=false;
    printf("channel_probe ready waiting_for_new_copy=1\n");fflush(stdout);
    auto deadline=GetTickCount64()+180000;
    while(GetTickCount64()<deadline){
        MSG m;while(PeekMessageW(&m,nullptr,0,0,PM_REMOVE)){TranslateMessage(&m);DispatchMessageW(&m);}
        if(GetClipboardSequenceNumber()!=sequence && IsClipboardFormatAvailable(format) && OpenClipboard(nullptr)){
            auto h=GetClipboardData(format);auto p=h?(BYTE*)GlobalLock(h):nullptr;
            if(p && GlobalSize(h)>=CALFILE_MARKER_SIZE && !memcmp(p,CALFILE_MARKER,18)){memcpy(token,p+18,16);found=true;}
            if(p)GlobalUnlock(h);CloseClipboard();if(found)break;
        }
        Sleep(30);
    }
    if(!found){puts("channel_probe timeout");return 2;}
    auto &t=fileTransport;t.channel=t.open(WTS_CURRENT_SERVER_HANDLE,WTS_CURRENT_SESSION,(LPSTR)"calfile");
    printf("channel_probe open_ok=%d error=%lu\n",t.channel!=nullptr,t.channel?0:GetLastError());fflush(stdout);
    if(!t.channel)return 3;
    BYTE idle[1600];ULONG idleBytes=0;SetLastError(0);
    BOOL idleOK=t.read(t.channel,50,(PCHAR)idle,sizeof(idle),&idleBytes);
    printf("channel_probe idle_ok=%d error=%lu bytes=%lu\n",idleOK,GetLastError(),idleBytes);fflush(stdout);
    t.reset();
    std::thread actual([&]{CoInitializeEx(nullptr,COINIT_MULTITHREADED);
        FileChannelSource source(token,1);BYTE data[65536];ULONG got=0;HRESULT hr=source.read(0,0,data,sizeof(data),&got);
        printf("channel_probe production_reader hr=0x%08lX bytes=%lu\n",hr,got);fflush(stdout);SecureZeroMemory(data,sizeof(data));CoUninitialize();});
    actual.join();t.reset();
    t.channel=t.open(WTS_CURRENT_SERVER_HANDLE,WTS_CURRENT_SESSION,(LPSTR)"calfile");if(!t.channel)return 3;
    BYTE request[CALFILE_REQUEST]={};cf_put32(request,CALFILE_MAGIC);cf_put32(request+4,0x71590001);
    memcpy(request+8,token,16);cf_put32(request+36,65536);ULONG written=0;
    BOOL ok=t.write(t.channel,(PCHAR)request,sizeof(request),&written);
    printf("channel_probe write_ok=%d error=%lu bytes=%lu\n",ok,ok?0:GetLastError(),written);fflush(stdout);
    std::vector<BYTE> buffer(CALFILE_HEADER+CALFILE_BLOCK+8);unsigned total=0;deadline=GetTickCount64()+15000;
    for(unsigned i=0;i<200 && GetTickCount64()<deadline;i++){
        ULONG n=0;ULONG capacity=i? (ULONG)buffer.size():1600;
        SetLastError(0);ok=t.read(t.channel,100,(PCHAR)buffer.data(),capacity,&n);DWORD error=ok?0:GetLastError();
        printf("channel_probe read=%u ok=%d error=%lu capacity=%lu bytes=%lu magic_at_0=%d magic_at_8=%d\n",i,ok,error,capacity,n,n>=4 && cf_u32(buffer.data())==CALFILE_MAGIC,n>=12 && cf_u32(buffer.data()+8)==CALFILE_MAGIC);fflush(stdout);
        if(ok)total+=n;SecureZeroMemory(buffer.data(),buffer.size());
        if(total>=CALFILE_HEADER+CALFILE_BLOCK)break;
        if(!ok && error!=ERROR_MORE_DATA && error!=ERROR_INSUFFICIENT_BUFFER && error!=ERROR_TIMEOUT && error!=WAIT_TIMEOUT)break;
    }
    printf("channel_probe total=%u content_saved=0\n",total);t.reset();OleUninitialize();return 0;
}
