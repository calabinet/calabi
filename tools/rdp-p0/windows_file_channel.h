#pragma once
#include "file_channel_protocol.h"
#include <objbase.h>
// Included by clipboard.c. All file access shares the clipboard lock.
static BYTE fileOffer[CALFILE_MARKER_SIZE];
static BOOL fileOfferValid;
typedef struct CalFilePlugin {
    CHANNEL_ENTRY_POINTS_EX api;void *init;DWORD open;
    BYTE request[CALFILE_REQUEST];UINT used;BOOL collecting,connected;
    LONG pending;
} CalFilePlugin;
static void file_offer_refresh(void){
    fileOfferValid=FALSE;memset(fileOffer,0,sizeof(fileOffer));
    if(clipboard.local && clipboard.localFormat==PROBE_FORMAT_FILES && probe_clipboard_files_enabled() && getenv("CALABI_RDP_FILE_STREAM")){
        GUID token;if(SUCCEEDED(CoCreateGuid(&token))){memcpy(fileOffer,CALFILE_MARKER,18);memcpy(fileOffer+18,&token,16);fileOfferValid=TRUE;}
    }
}
static void file_channel_reply(CalFilePlugin *p,const BYTE *request){
    if(cf_u32(request)!=CALFILE_MAGIC || !cf_u32(request+4))return;
    UINT32 index=cf_u32(request+24),count=cf_u32(request+36);uint64_t offset=cf_u64(request+28);
    if(!count || count>CALFILE_BLOCK || index>=PROBE_FILE_COUNT)return;
    if(InterlockedIncrement(&p->pending)>2){InterlockedDecrement(&p->pending);return;}
    BYTE *reply=calloc(1,CALFILE_HEADER+count);if(!reply){InterlockedDecrement(&p->pending);return;}
    cf_put32(reply,CALFILE_MAGIC);cf_put32(reply+4,cf_u32(request+4));cf_put32(reply+8,1);
    size_t got=count;uint64_t size=0;
    EnterCriticalSection(&clipboard.lock);
    if(fileOfferValid && clipboard.localFormat==PROBE_FORMAT_FILES && clipboard.local && probe_clipboard_files_enabled() && !memcmp(request+8,fileOffer+18,16) &&
       probe_file_read(index,offset,reply+CALFILE_HEADER,&got,&size) && got==count){
        cf_put32(reply+8,0);cf_put32(reply+12,(uint32_t)got);
    }
    if(!offset || cf_u32(reply+8))trace_clipboard("files_forward_channel_response",cf_u32(reply+12));
    LeaveCriticalSection(&clipboard.lock);
    UINT result=p->api.pVirtualChannelWriteEx(p->init,p->open,reply,CALFILE_HEADER+cf_u32(reply+12),reply);
    if(result!=CHANNEL_RC_OK){free(reply);InterlockedDecrement(&p->pending);}
}
static VOID VCAPITYPE file_channel_event(void *user,DWORD handle,UINT event,void *data,UINT32 length,UINT32 total,UINT32 flags){
    CalFilePlugin *p=user;(void)handle;
    if(event==CHANNEL_EVENT_WRITE_COMPLETE || event==CHANNEL_EVENT_WRITE_CANCELLED){free(data);InterlockedDecrement(&p->pending);return;}
    if(event!=CHANNEL_EVENT_DATA_RECEIVED || !p->connected)return;
    if(flags&CHANNEL_FLAG_FIRST){p->used=0;p->collecting=total==CALFILE_REQUEST;}
    if(!p->collecting || total!=CALFILE_REQUEST || length>CALFILE_REQUEST-p->used){p->collecting=FALSE;return;}
    memcpy(p->request+p->used,data,length);p->used+=length;
    if(flags&CHANNEL_FLAG_LAST){p->collecting=FALSE;if(p->used==CALFILE_REQUEST)file_channel_reply(p,p->request);}
}
static VOID VCAPITYPE file_channel_init(void *user,void *init,UINT event,void *data,UINT length){
    CalFilePlugin *p=user;(void)init;(void)data;(void)length;
    if(event==CHANNEL_EVENT_CONNECTED){
        p->connected=p->api.pVirtualChannelOpenEx(p->init,&p->open,"calfile",file_channel_event)==CHANNEL_RC_OK;
        trace_clipboard("files_forward_channel_connected",p->connected);
    }else if(event==CHANNEL_EVENT_DISCONNECTED){
        p->connected=FALSE;p->collecting=FALSE;
        EnterCriticalSection(&clipboard.lock);fileOfferValid=FALSE;LeaveCriticalSection(&clipboard.lock);
        if(p->open)p->api.pVirtualChannelCloseEx(p->init,p->open);p->open=0;
    }else if(event==CHANNEL_EVENT_TERMINATED)free(p);
}
static BOOL VCAPITYPE file_channel_entry(PCHANNEL_ENTRY_POINTS_EX api,void *init){
    CalFilePlugin *p=calloc(1,sizeof(*p));if(!p)return FALSE;
    p->api=*api;p->init=init;
    CHANNEL_DEF def={0};memcpy(def.name,"calfile",8);
    // No SHOW_PROTOCOL: WTSVirtualChannelRead returns only application bytes.
    def.options=CHANNEL_OPTION_INITIALIZED|CHANNEL_OPTION_ENCRYPT_RDP;
    UINT rc=api->pVirtualChannelInitEx(p,NULL,init,&def,1,VIRTUAL_CHANNEL_VERSION_WIN2000,file_channel_init);
    if(rc!=CHANNEL_RC_OK){free(p);return FALSE;}return TRUE;
}
