// Local transport between the native RDP worker and the desktop workspace.
// The parent binds loopback and passes an unpredictable token over the private
// child environment. Certificate and file-copy RPCs retain their stdio pipe.
#pragma once
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <freerdp/graphics.h>
#include <freerdp/codec/color.h>
#include <winpr/sysinfo.h>
#ifndef _WIN32
#include <winpr/handle.h>
#include <winpr/interlocked.h>
#include <winpr/synch.h>
#include <winpr/thread.h>
#endif

#ifdef _WIN32
typedef SOCKET workspace_socket_t;
#define WORKSPACE_INVALID INVALID_SOCKET
#define workspace_close_socket closesocket
static int workspace_would_block(void) { return WSAGetLastError() == WSAEWOULDBLOCK; }
static int workspace_nonblocking(SOCKET fd) { u_long value=1; return ioctlsocket(fd,FIONBIO,&value)==0; }
#else
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int workspace_socket_t;
#define WORKSPACE_INVALID (-1)
#define workspace_close_socket close
static int workspace_would_block(void) { return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR; }
static int workspace_nonblocking(int fd) { return fcntl(fd,F_SETFL,O_NONBLOCK)==0; }
#endif

static workspace_socket_t workspace_fd=WORKSPACE_INVALID;
static HANDLE workspace_thread, workspace_event;
static CRITICAL_SECTION workspace_lock;
static volatile LONG workspace_selected, workspace_stopping;
static volatile LONG workspace_selection;
static unsigned char *workspace_latest;
static size_t workspace_latest_size;
static unsigned char *workspace_cursor;
static size_t workspace_cursor_size;
static BOOL workspace_cursor_enabled;
static DWORD workspace_active_interval = 65;
static unsigned char workspace_packet[8];
static unsigned workspace_packet_size;
#ifdef _WIN32
static wchar_t workspace_active_path[32768];
#else
static const char *workspace_active_path;
#endif

int probe_workspace_enabled(void) { return getenv("CALABI_RDP_WORKSPACE_PORT") != NULL; }
int probe_workspace_active(void) {
    if(!probe_workspace_enabled())return 1;
    if(!InterlockedCompareExchange(&workspace_selected,0,0))return 0;
#ifdef _WIN32
    FILE *file=_wfopen(workspace_active_path,L"rb");
#else
    FILE *file=workspace_active_path?fopen(workspace_active_path,"rb"):NULL;
#endif
    if(!file)return 0;
    int active=fgetc(file)=='1';
    fclose(file);
    return active;
}
unsigned probe_workspace_selection(void) {
    return (unsigned)InterlockedCompareExchange(&workspace_selection,0,0);
}
static int workspace_stopped(void) { return InterlockedCompareExchange(&workspace_stopping,0,0)!=0; }

static int workspace_write(const unsigned char *data,size_t length) {
    while(length && !workspace_stopped()) {
        int sent=send(workspace_fd,(const char *)data,(int)length,0);
        if(sent>0){data+=sent;length-=(size_t)sent;}
        else if(sent<0 && workspace_would_block()){
#ifdef _WIN32
            fd_set writable;
            FD_ZERO(&writable);
            FD_SET(workspace_fd,&writable);
            struct timeval timeout={0,50000};
            if(select(0,NULL,&writable,NULL,&timeout)==SOCKET_ERROR)return 0;
#else
            Sleep(4);
#endif
        }
        else return 0;
    }
    return length==0;
}

static DWORD WINAPI workspace_send_frames(void *unused) {
    (void)unused;
    ULONGLONG last=0;
#ifdef _WIN32
    HANDLE timer=CreateWaitableTimerExW(NULL,NULL,CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                                       TIMER_MODIFY_STATE|SYNCHRONIZE);
#endif
    while(!workspace_stopped()) {
        if(WaitForSingleObject(workspace_event,INFINITE)!=WAIT_OBJECT_0)break;
        ULONGLONG next=last+(probe_workspace_active()?workspace_active_interval:400);
        ULONGLONG now=WINPR_TIME_NS_TO_MS(winpr_GetTickCount64NS());
        if(now<next){
            DWORD delay=(DWORD)(next-now);
#ifdef _WIN32
            LARGE_INTEGER due;
            due.QuadPart=-(LONGLONG)delay*10000;
            if(timer && SetWaitableTimer(timer,&due,0,NULL,NULL,FALSE))
                WaitForSingleObject(timer,INFINITE);
            else
#endif
                Sleep(delay);
        }
        if(workspace_stopped())break;
        EnterCriticalSection(&workspace_lock);
        // Reset under the same lock as publication so a new payload can't lose its wakeup.
        if(!ResetEvent(workspace_event)){
            LeaveCriticalSection(&workspace_lock);
            break;
        }
        unsigned char *frame=workspace_latest;size_t size=workspace_latest_size;
        unsigned char *cursor=workspace_cursor;size_t cursor_size=workspace_cursor_size;
        workspace_latest=NULL;
        workspace_cursor=NULL;
        LeaveCriticalSection(&workspace_lock);
        int ok=!cursor || workspace_write(cursor,cursor_size);
        free(cursor);
        if(frame){
            if(ok)ok=workspace_write(frame,size);
            free(frame);
            last=WINPR_TIME_NS_TO_MS(winpr_GetTickCount64NS());
        }
        if(!ok)break;
    }
#ifdef _WIN32
    if(timer)CloseHandle(timer);
#endif
    InterlockedExchange(&workspace_selected,0);
    InterlockedExchange(&workspace_stopping,1);
    return 0;
}

static void workspace_finish(void) {
    if(workspace_fd==WORKSPACE_INVALID)return;
    InterlockedExchange(&workspace_stopping,1);
#ifdef _WIN32
    shutdown(workspace_fd,SD_BOTH);
#else
    shutdown(workspace_fd,SHUT_RDWR);
#endif
    SetEvent(workspace_event);
    WaitForSingleObject(workspace_thread,INFINITE);
    CloseHandle(workspace_thread);
    CloseHandle(workspace_event);
    workspace_close_socket(workspace_fd);
    workspace_fd=WORKSPACE_INVALID;
    free(workspace_latest);
    free(workspace_cursor);
    DeleteCriticalSection(&workspace_lock);
#ifdef _WIN32
    WSACleanup();
#endif
}

static int workspace_start(void) {
    if(!probe_workspace_enabled())return 1;
    if(workspace_fd!=WORKSPACE_INVALID)return !workspace_stopped();
    const char *token=getenv("CALABI_RDP_WORKSPACE_TOKEN"), *port=getenv("CALABI_RDP_WORKSPACE_PORT");
    char *end=NULL;
    long value=strtol(port,&end,10);
    if(!token || strlen(token)!=32 || !*port || *end || value<1 || value>65535)return 0;
#ifdef _WIN32
    DWORD path_length=GetEnvironmentVariableW(L"CALABI_RDP_WORKSPACE_ACTIVE",workspace_active_path,32768);
    if(!path_length || path_length>=32768)return 0;
    WSADATA winsock;
    if(WSAStartup(MAKEWORD(2,2),&winsock)!=0)return 0;
#endif
#ifndef _WIN32
    workspace_active_path=getenv("CALABI_RDP_WORKSPACE_ACTIVE");
    if(!workspace_active_path)return 0;
#endif
    const char *fast_bridge = getenv("CALABI_RDP_WORKSPACE_FAST");
    if (fast_bridge && !strcmp(fast_bridge, "1")) workspace_active_interval = 16;
    workspace_socket_t fd=socket(AF_INET,SOCK_STREAM,0);
    if(fd==WORKSPACE_INVALID)goto failed;
    struct sockaddr_in address={0};
    address.sin_family=AF_INET;address.sin_port=htons((uint16_t)value);
    address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
#ifndef _WIN32
    int no_signal=1;
    if(setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&no_signal,sizeof(no_signal))<0){workspace_close_socket(fd);goto failed;}
#endif
    if(connect(fd,(struct sockaddr *)&address,sizeof(address))!=0 || send(fd,token,32,0)!=32 || !workspace_nonblocking(fd)) {
        workspace_close_socket(fd);goto failed;
    }
    InitializeCriticalSection(&workspace_lock);
    const char *cursor=getenv("CALABI_RDP_WORKSPACE_CURSOR");
    workspace_cursor_enabled=cursor && !strcmp(cursor,"1");
    // WinPR on macOS does not implement auto-reset events.
    workspace_event=CreateEvent(NULL,TRUE,FALSE,NULL);
    workspace_fd=fd;
    if(workspace_event)workspace_thread=CreateThread(NULL,0,workspace_send_frames,NULL,0,NULL);
    if(!workspace_thread){
        if(workspace_event)CloseHandle(workspace_event);
        DeleteCriticalSection(&workspace_lock);workspace_close_socket(fd);
        workspace_fd=WORKSPACE_INVALID;goto failed;
    }
    atexit(workspace_finish);
    return 1;
failed:
#ifdef _WIN32
    WSACleanup();
#endif
    return 0;
}

static void workspace_u32(unsigned char *p,unsigned value) {
    p[0]=(unsigned char)value;p[1]=(unsigned char)(value>>8);
    p[2]=(unsigned char)(value>>16);p[3]=(unsigned char)(value>>24);
}

static BOOL workspace_publish_cursor(rdpContext *context, const rdpPointer *pointer, BOOL hidden) {
    if(workspace_stopped())return TRUE;
    if(pointer && (!pointer->width || !pointer->height || pointer->width>128 || pointer->height>128 ||
                   pointer->xPos>=pointer->width || pointer->yPos>=pointer->height))pointer=NULL;
    size_t pixels=pointer?(size_t)pointer->width*pointer->height*4:0;
    // Zero frame dimensions mark a cursor packet. Its payload starts with
    // four u16 values (width, height, hotspot x and y), followed by RGBA.
    unsigned char *packet=calloc(1,20+pixels);
    if(!packet)return TRUE;
    if(pointer && freerdp_image_copy_from_pointer_data(packet+20,PIXEL_FORMAT_RGBA32,0,0,0,
        pointer->width,pointer->height,pointer->xorMaskData,pointer->lengthXorMask,
        pointer->andMaskData,pointer->lengthAndMask,pointer->xorBpp,&context->gdi->palette)){
        workspace_u32(packet+12,pointer->width|(pointer->height<<16));
        workspace_u32(packet+16,pointer->xPos|(pointer->yPos<<16));
    }else{
        pixels=0;
        packet[16]=hidden?1:0;
    }
    workspace_u32(packet+8,(unsigned)(8+pixels));
    EnterCriticalSection(&workspace_lock);
    if(!workspace_latest && !workspace_cursor)SetEvent(workspace_event);
    free(workspace_cursor);
    workspace_cursor=packet;
    workspace_cursor_size=20+pixels;
    LeaveCriticalSection(&workspace_lock);
    return TRUE;
}

static BOOL workspace_set_cursor(rdpContext *context, rdpPointer *pointer) {
    return workspace_publish_cursor(context,pointer,FALSE);
}
static BOOL workspace_hide_cursor(rdpContext *context) {
    return workspace_publish_cursor(context,NULL,TRUE);
}
static BOOL workspace_reset_cursor(rdpContext *context) {
    return workspace_publish_cursor(context,NULL,FALSE);
}
static void workspace_register_cursor(rdpContext *context) {
    if(!workspace_cursor_enabled)return;
    rdpPointer pointer={.size=sizeof(pointer),.Set=workspace_set_cursor,
        .SetNull=workspace_hide_cursor,.SetDefault=workspace_reset_cursor};
    graphics_register_pointer(context->graphics,&pointer);
    (void)workspace_reset_cursor(context);
}

static void workspace_publish(const uint8_t *pixels,unsigned width,unsigned height,unsigned stride) {
    if(workspace_fd==WORKSPACE_INVALID || workspace_stopped() || width>4096 || height>4096)return;
    size_t row=(size_t)width*4, size=row*height;
    unsigned char *frame=malloc(12+size);
    if(!frame)return;
    workspace_u32(frame,width);workspace_u32(frame+4,height);workspace_u32(frame+8,(unsigned)size);
    for(unsigned y=0;y<height;y++)memcpy(frame+12+y*row,pixels+(size_t)y*stride,row);
    EnterCriticalSection(&workspace_lock);
    if(!workspace_latest && !workspace_cursor)SetEvent(workspace_event);
    free(workspace_latest);
    workspace_latest=frame;workspace_latest_size=12+size;
    LeaveCriticalSection(&workspace_lock);
}

static unsigned workspace_u16(const unsigned char *p) { return p[0] | ((unsigned)p[1]<<8); }

static int workspace_input(struct probe_input *event) {
    while(workspace_fd!=WORKSPACE_INVALID && !workspace_stopped()) {
        int count=recv(workspace_fd,(char *)workspace_packet+workspace_packet_size,
                       (int)(sizeof(workspace_packet)-workspace_packet_size),0);
        if(count<=0){
            if(count==0 || !workspace_would_block()){
                InterlockedExchange(&workspace_selected,0);
                InterlockedExchange(&workspace_stopping,1);
            }
            return 0;
        }
        workspace_packet_size+=(unsigned)count;
        if(workspace_packet_size<sizeof(workspace_packet))continue;
        workspace_packet_size=0;
        unsigned kind=workspace_u16(workspace_packet);
        unsigned a=workspace_u16(workspace_packet+2);
        unsigned b=workspace_u16(workspace_packet+4);
        if(!kind){
            if(a==3){*event=(struct probe_input){0,0,0,0};return 1;}
            if(a==2)InterlockedExchange(&workspace_stopping,1);
            if(a==1 && !InterlockedExchange(&workspace_selected,1))
                InterlockedIncrement(&workspace_selection);
            if(a!=1)InterlockedExchange(&workspace_selected,0);
            // A selection change also releases held keys/buttons on the worker.
            if(a!=1){*event=(struct probe_input){0,0,0,0};return 1;}
        }else if(probe_workspace_active() && kind==PROBE_RESIZE){
#ifdef __APPLE__
            probe_workspace_display(a,b,workspace_u16(workspace_packet+6));
#endif
        }else if(probe_workspace_active() && kind<=PROBE_REFRESH){
            *event=(struct probe_input){(int)kind,(uint16_t)a,(uint16_t)b,(int16_t)workspace_u16(workspace_packet+6)};
            return 1;
        }
    }
    return 0;
}
