#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "clipboard_payload.h"
static HWND window;
static int progressState;
void probe_files_progress(uint64_t d,uint64_t t,int s){(void)d;(void)t;progressState=s;}
#include "windows_clipboard.h"

static void put_clip(UINT format,const void *bytes,size_t size) {
    HGLOBAL data=GlobalAlloc(GMEM_MOVEABLE,size);assert(data);
    void *p=GlobalLock(data);assert(p);memcpy(p,bytes,size);GlobalUnlock(data);
    assert(OpenClipboard(window));assert(EmptyClipboard());assert(SetClipboardData(format,data));CloseClipboard();
}
int main(void) {
    // Clipboard belongs to the window station, not the desktop. Never use the user's clipboard.
    HWINSTA original=GetProcessWindowStation();HDESK originalDesk=GetThreadDesktop(GetCurrentThreadId());
    HWINSTA station=CreateWindowStationW(NULL,0,WINSTA_ALL_ACCESS,NULL);assert(station && SetProcessWindowStation(station));
    HDESK desktop=CreateDesktopW(L"Default",NULL,NULL,0,GENERIC_ALL,NULL);assert(desktop && SetThreadDesktop(desktop));
    window=CreateWindowExW(0,L"STATIC",L"clipboard fixture",WS_POPUP,0,0,10,10,NULL,NULL,NULL,NULL);assert(window);
    clipboardFilesEnabled=1;
    const wchar_t text[]=L"中文 clipboard\r\nsecond line";
    put_clip(CF_UNICODETEXT,text,sizeof(text));uint64_t seq=UINT64_MAX;BYTE *data;size_t n;uint32_t fmt;
    assert(probe_clipboard_read(&data,&n,&fmt,&seq) && fmt==PROBE_FORMAT_TEXT && n==sizeof(text) && !memcmp(data,text,n));free(data);
    uint64_t after;assert(probe_clipboard_write((BYTE*)text,sizeof(text),PROBE_FORMAT_TEXT,seq,&after));
    assert(!probe_clipboard_write((BYTE*)text,sizeof(text),PROBE_FORMAT_TEXT,seq,&after));
    BYTE dib[48]={0};clip_put32(dib,40);clip_put32(dib+4,2);clip_put32(dib+8,1);dib[12]=1;dib[14]=24;dib[42]=255;
    seq=GetClipboardSequenceNumber();assert(probe_clipboard_write(dib,sizeof(dib),PROBE_FORMAT_DIB,seq,&after));
    seq=UINT64_MAX;assert(probe_clipboard_read(&data,&n,&fmt,&seq) && fmt==PROBE_FORMAT_DIB && n==48 && !memcmp(data,dib,n));free(data);
    wchar_t temp[MAX_PATH],folder[MAX_PATH];assert(GetTempPathW(MAX_PATH,temp));assert(GetTempFileNameW(temp,L"cft",0,folder));
    assert(DeleteFileW(folder) && CreateDirectoryW(folder,NULL));
    FileBatch fixture={0};fixture.count=3;
    const wchar_t *names[]={L"中文.pptx",L"empty.txt",L"large.bin"};
    for(unsigned i=0;i<3;i++) {
        swprintf(fixture.paths[i],MAX_PATH,L"%ls\\%ls",folder,names[i]);
        HANDLE f=CreateFileW(fixture.paths[i],GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);assert(f!=INVALID_HANDLE_VALUE);
        DWORD wrote;
        if(i==0)assert(WriteFile(f,"test",4,&wrote,NULL) && wrote==4);
        if(i==2){LARGE_INTEGER size;size.QuadPart=43u*1024u*1024u;assert(SetFilePointerEx(f,size,NULL,FILE_BEGIN) && SetEndOfFile(f));}
        CloseHandle(f);
    }
    HGLOBAL drop=make_drop_files(&fixture);assert(drop && OpenClipboard(window));assert(EmptyClipboard() && SetClipboardData(CF_HDROP,drop));CloseClipboard();
    seq=UINT64_MAX;assert(probe_clipboard_read(&data,&n,&fmt,&seq) && fmt==PROBE_FORMAT_FILES && clip_valid_files(data,n));
    assert(sourceCount==3 && clip_file_size(data+4+2*CLIP_DESCRIPTOR_SIZE)==43u*1024u*1024u);
    BYTE bytes[4];size_t length=4;uint64_t size;assert(probe_file_read(0,0,bytes,&length,&size) && size==4 && !memcmp(bytes,"test",4));
    length=4;assert(probe_file_read(2,43u*1024u*1024u-4,bytes,&length,&size) && length==4);
    assert(!probe_file_read(3,0,bytes,&length,&size));
    assert(probe_files_begin(data,n)==1);
    assert(probe_file_write(0,0,(BYTE*)"test",4));
    BYTE *chunk=calloc(1,65536);assert(chunk);
    for(uint64_t off=0;off<43u*1024u*1024u;off+=65536)assert(probe_file_write(2,off,chunk,65536));free(chunk);
    assert(!probe_file_write(0,4,(BYTE*)"x",1));
    assert(!probe_clipboard_write(NULL,0,PROBE_FORMAT_FILES,seq+99,&after));
    assert(probe_clipboard_write(NULL,0,PROBE_FORMAT_FILES,seq,&after));assert(completedFiles && !receivingFiles);
    assert(OpenClipboard(window));HDROP received=GetClipboardData(CF_HDROP);assert(received && DragQueryFileW(received,0xffffffff,NULL,0)==3);
    wchar_t path[MAX_PATH],copy[MAX_PATH];assert(DragQueryFileW(received,0,path,MAX_PATH));CloseClipboard();
    swprintf(copy,MAX_PATH,L"%ls\\pasted.pptx",folder);assert(CopyFileW(path,copy,TRUE));
    HANDLE f=CreateFileW(copy,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,0,NULL);DWORD read;
    assert(f!=INVALID_HANDLE_VALUE && ReadFile(f,bytes,4,&read,NULL) && read==4 && !memcmp(bytes,"test",4));CloseHandle(f);
    uint64_t retained=retainedBytes;assert(probe_files_begin(data,n)==1);probe_files_cancel();assert(retainedBytes==retained);
    assert(probe_files_begin(data,n)==1);assert(!publish_received_files(seq,&after));probe_files_cancel();
    assert(!safe_file_name(L"CON.txt") && !safe_file_name(L"..") && !safe_file_name(L"a:b") && safe_file_name(L"中文.txt"));
    uint64_t saved=retainedBytes;retainedBytes=256u*1024u*1024u;assert(probe_files_begin(data,n)==-10);retainedBytes=saved;
    assert(probe_file_lock(77));close_file_sources();length=4;
    assert(probe_file_read_locked(77,0,0,bytes,&length,&size) && length==4 && !memcmp(bytes,"test",4));
    assert(!probe_file_read_locked(78,0,0,bytes,&length,&size));probe_file_unlock(77);
    assert(!probe_file_read_locked(77,0,0,bytes,&length,&size));
    free(data);
    clipboardFilesEnabled=0;seq=UINT64_MAX;assert(probe_clipboard_read(&data,&n,&fmt,&seq) && !data && !n);
    probe_files_cleanup();assert(GetFileAttributesW(path)==INVALID_FILE_ATTRIBUTES);
    assert(!completedFiles && !sourceCount && !retainedBytes);
    for(unsigned i=0;i<3;i++)assert(DeleteFileW(fixture.paths[i]));assert(DeleteFileW(copy));assert(RemoveDirectoryW(folder));
    DWORD effect=DROPEFFECT_COPY;put_clip(RegisterClipboardFormatW(L"CalabiRdpCopyOwnedV1"),&effect,sizeof(effect));
    seq=UINT64_MAX;assert(probe_clipboard_read(&data,&n,&fmt,&seq)==3 && !data && !n);
    DestroyWindow(window);window=NULL;assert(SetProcessWindowStation(original));
    assert(SetThreadDesktop(originalDesk));CloseDesktop(desktop);CloseWindowStation(station);
    puts("Windows isolated clipboard text/image/files fixtures passed (43 MiB, Unicode, empty, cancel, stale, quota, copy-out).");
    return 0;
}
