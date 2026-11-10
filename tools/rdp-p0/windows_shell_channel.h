#pragma once
#include "windows_shell_receive.h"
// One outstanding request, serialized by the destination OLE adapter. The
// caller's buffer stays alive until completion/timeout has removed it here.
static struct {
    HANDLE done,wake;
    BOOL active,pending,success,stopping;
    uint64_t generation,allowed,offset;
    unsigned index,count,fileCount;
    uint64_t sizes[PROBE_FILE_COUNT];
    UINT32 stream;
    BOOL canLock,locked;
    UINT32 clipDataId;
    void *data;
} shellWire;
// Never reuse a generation across reconnects in the same helper process: Shell
// may still hold an old IDataObject after its RDP session has gone away.
static uint64_t shellGeneration;
HANDLE clipboard_shell_wake(void){return shellWire.wake;}
static void shell_wire_invalidate(void){
    if(shellWire.locked && clipboard.channel && clipboard.channel->ClientUnlockClipboardData){
        CLIPRDR_UNLOCK_CLIPBOARD_DATA unlock={0};unlock.clipDataId=shellWire.clipDataId;
        clipboard.channel->ClientUnlockClipboardData(clipboard.channel,&unlock);
    }
    shellWire.locked=FALSE;
    shell_receive_invalidate();
    shellWire.allowed=0;shellWire.success=FALSE;shellWire.pending=FALSE;
    if(shellWire.active)SetEvent(shellWire.done);
}
void clipboard_shell_cancel(uint64_t generation){
    EnterCriticalSection(&clipboard.lock);
    if(shellWire.allowed==generation)shell_wire_invalidate();
    LeaveCriticalSection(&clipboard.lock);
}
int clipboard_shell_read(uint64_t generation,unsigned index,uint64_t offset,void *data,unsigned count){
    EnterCriticalSection(&clipboard.lock);
    if(shellWire.stopping || !clipboard.channel || !clipboard.ready || shellWire.active ||
       !probe_clipboard_files_enabled() || generation!=shellWire.allowed || index>=shellWire.fileCount ||
       !count || count>65536 || offset>shellWire.sizes[index] || count>shellWire.sizes[index]-offset){
        LeaveCriticalSection(&clipboard.lock);return 0;
    }
    ResetEvent(shellWire.done);shellWire.active=shellWire.pending=TRUE;shellWire.success=FALSE;
    shellWire.generation=generation;shellWire.index=index;shellWire.offset=offset;
    shellWire.count=count;shellWire.data=data;shellWire.stream=++clipboard.nextStreamId;
    SetEvent(shellWire.wake);
    LeaveCriticalSection(&clipboard.lock);
    DWORD wait=WaitForSingleObject(shellWire.done,30000);
    EnterCriticalSection(&clipboard.lock);
    BOOL ok=wait==WAIT_OBJECT_0 && shellWire.success && generation==shellWire.allowed && !shellWire.stopping;
    if(!ok)trace_clipboard("files_wire_wait_result",wait);
    shellWire.active=shellWire.pending=FALSE;shellWire.data=NULL;
    LeaveCriticalSection(&clipboard.lock);return ok;
}
static void shell_wire_poll(void){
    if(!shellWire.active || !shellWire.pending)return;
    shellWire.pending=FALSE;
    CLIPRDR_FILE_CONTENTS_REQUEST request={0};
    request.streamId=shellWire.stream;request.listIndex=shellWire.index;request.dwFlags=FILECONTENTS_RANGE;
    request.nPositionLow=(UINT32)shellWire.offset;request.nPositionHigh=(UINT32)(shellWire.offset>>32);request.cbRequested=shellWire.count;
    request.haveClipDataId=shellWire.locked;request.clipDataId=shellWire.clipDataId;
    if(!shellWire.offset){trace_clipboard("files_wire_request_locked",request.haveClipDataId);trace_clipboard("files_wire_request_id",request.clipDataId);}
    if(clipboard.channel->ClientFileContentsRequest(clipboard.channel,&request)!=CHANNEL_RC_OK){
        shellWire.success=FALSE;SetEvent(shellWire.done);
    }
}
static BOOL shell_wire_response(const CLIPRDR_FILE_CONTENTS_RESPONSE *response){
    if(!shellWire.active || response->streamId!=shellWire.stream)return FALSE;
    shellWire.success=shellWire.allowed==shellWire.generation && (response->common.msgFlags&CB_RESPONSE_OK) &&
        response->requestedData && response->cbRequested==shellWire.count;
    if(shellWire.success)memcpy(shellWire.data,response->requestedData,shellWire.count);
    if(!shellWire.success || !shellWire.offset){trace_clipboard("files_wire_response_flags",response->common.msgFlags);trace_clipboard("files_wire_received",response->cbRequested);}
    SetEvent(shellWire.done);return TRUE;
}
static void shell_wire_offer(void){
    shell_wire_invalidate();
    shellWire.fileCount=clip_u32(clipboard.incoming);
    for(unsigned i=0;i<shellWire.fileCount;i++)shellWire.sizes[i]=clip_file_size(clipboard.incoming+4+i*CLIP_DESCRIPTOR_SIZE);
    shellWire.allowed=clipboard.generation;
    if(shellWire.canLock){
        CLIPRDR_LOCK_CLIPBOARD_DATA lock={0};lock.clipDataId=++clipboard.nextStreamId;
        if(!clipboard.channel->ClientLockClipboardData || clipboard.channel->ClientLockClipboardData(clipboard.channel,&lock)!=CHANNEL_RC_OK){
            shell_wire_invalidate();probe_files_progress(0,0,-9);return;
        }
        shellWire.clipDataId=lock.clipDataId;shellWire.locked=TRUE;
    }
    if(!shell_receive_offer(clipboard.incoming,clipboard.incomingLength,clipboard.generation,clipboard.sequence)){
        shell_wire_invalidate();probe_files_progress(0,0,-9);
    }
}
