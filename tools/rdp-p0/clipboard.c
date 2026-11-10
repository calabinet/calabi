#include "clipboard.h"
#include "clipboard_payload.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <freerdp/freerdp.h>
#include <freerdp/settings.h>
#include <freerdp/client/cliprdr.h>
#include <freerdp/client/channels.h>
#include <freerdp/channels/channels.h>
#include <winpr/synch.h>
#include <winpr/interlocked.h>
#include <winpr/sysinfo.h>

// One helper owns one connection. Channel callbacks and polling share this lock.
static struct {
    CRITICAL_SECTION lock;
    CliprdrClientContext *channel;
    BOOL ready, requested, remoteText, initialized;
    UINT32 localFormat, remoteFormat, incomingFormat, requestedFormat;
    BOOL fileActive, fileWaiting;
    UINT32 fileIndex, fileCount, streamId, nextStreamId, fileChunk;
    uint64_t fileOffset, fileDone, fileTotal, fileSizes[PROBE_FILE_COUNT], fileGeneration, fileSequence;
    ULONGLONG fileDeadline;
    LONG cancelFiles, cancelSend;
    uint64_t sentPrefix[PROBE_FILE_COUNT], sentTotal, sentDone;
    uint64_t sequence, generation, requestedGeneration, requestedSequence;
    uint64_t consumedGeneration;
    ULONGLONG nextPoll;
    BYTE *local, *incoming;
    size_t localLength, incomingLength;
} clipboard;
static void trace_clipboard(const char *event,unsigned value);
#ifdef CALABI_SHELL_RECEIVE
#include "windows_shell_channel.h"
#endif
static FILE *clipboardLog;
static unsigned logCount, fileLogCount;
static void trace_clipboard(const char *event, unsigned value) {
    // Keep file diagnostics available after ordinary clipboard activity exhausts its budget.
    unsigned *count = !strncmp(event,"file",4) ? &fileLogCount : &logCount;
    if (clipboardLog && *count < 160) {
        ++*count;
        fprintf(clipboardLog, "%llu %s %u\n", (unsigned long long)GetTickCount64(), event, value);
        fflush(clipboardLog);
    }
}

static void clear_text(BYTE **text, size_t *length) {
    if (*text) { memset(*text, 0, *length); free(*text); }
    *text = NULL;
    *length = 0;
}

#ifdef CALABI_SHELL_RECEIVE
#include "windows_file_channel.h"
#endif

static BOOL valid_text(const BYTE *text, size_t length) {
    if (!text || length < 2 || length > PROBE_CLIPBOARD_LIMIT || length % 2 ||
        text[length-1] || text[length-2]) return FALSE;
    for (size_t i = 0; i + 2 < length; i += 2) {
        unsigned unit = text[i] | ((unsigned)text[i+1] << 8);
        if (!unit || (unit >= 0xdc00 && unit <= 0xdfff)) return FALSE;
        if (unit >= 0xd800 && unit <= 0xdbff) {
            if (i + 4 >= length) return FALSE;
            unsigned low = text[i+2] | ((unsigned)text[i+3] << 8);
            if (low < 0xdc00 || low > 0xdfff) return FALSE;
            i += 2;
        }
    }
    return TRUE;
}

static BOOL valid_payload(UINT32 format, const BYTE *data, size_t size) {
    if(format==PROBE_FORMAT_BRIDGE){
        if(!probe_clipboard_files_enabled() || !data || size<3 || size>256 || data[size-1])return FALSE;
        for(size_t i=0;i<size-1;i++)if(data[i]<33 || data[i]>126)return FALSE;
        return TRUE;
    }
    if (format == CF_UNICODETEXT) return probe_clipboard_content_enabled() && valid_text(data,size);
    if (format == CF_DIB) return probe_clipboard_content_enabled() && clip_valid_dib(data,size);
    return probe_clipboard_files_enabled() && clip_valid_files(data,size);
}

static UINT capabilities(CliprdrClientContext *channel, const CLIPRDR_CAPABILITIES *caps) {
    (void)channel; (void)caps;
#ifdef CALABI_SHELL_RECEIVE
    EnterCriticalSection(&clipboard.lock);shellWire.canLock=FALSE;
    const CLIPRDR_GENERAL_CAPABILITY_SET *sets=(const CLIPRDR_GENERAL_CAPABILITY_SET*)caps->capabilitySets;
    for(unsigned i=0;sets && i<caps->cCapabilitiesSets;i++){
        if(sets[i].capabilitySetType==CB_CAPSTYPE_GENERAL && sets[i].capabilitySetLength>=CB_CAPSTYPE_GENERAL_LEN)
            shellWire.canLock=(sets[i].generalFlags&CB_CAN_LOCK_CLIPDATA)!=0;
    }
    trace_clipboard("files_peer_lock_capability",shellWire.canLock);LeaveCriticalSection(&clipboard.lock);
#endif
    return CHANNEL_RC_OK;
}

static UINT monitor_ready(CliprdrClientContext *channel, const CLIPRDR_MONITOR_READY *event) {
    (void)event;
    CLIPRDR_GENERAL_CAPABILITY_SET general = {
        CB_CAPSTYPE_GENERAL, CB_CAPSTYPE_GENERAL_LEN, CB_CAPS_VERSION_2, CB_USE_LONG_FORMAT_NAMES |
        (probe_clipboard_files_enabled() ? CB_STREAM_FILECLIP_ENABLED | CB_FILECLIP_NO_FILE_PATHS : 0)
#ifdef CALABI_SHELL_RECEIVE
        | (probe_clipboard_files_enabled() ? CB_CAN_LOCK_CLIPDATA : 0)
#endif
    };
    CLIPRDR_CAPABILITIES caps = {0};
    caps.cCapabilitiesSets = 1;
    caps.capabilitySets = (CLIPRDR_CAPABILITY_SET *)&general;
    UINT result = channel->ClientCapabilities(channel, &caps);
    EnterCriticalSection(&clipboard.lock);
    clipboard.ready = result == CHANNEL_RC_OK;
    trace_clipboard("monitor_ready", result);
    LeaveCriticalSection(&clipboard.lock);
    return result;
}

static UINT format_list(CliprdrClientContext *channel, const CLIPRDR_FORMAT_LIST *list) {
    EnterCriticalSection(&clipboard.lock);
#ifdef CALABI_SHELL_RECEIVE
    clipboard.generation=++shellGeneration;
    shell_wire_invalidate();
#else
    clipboard.generation++;
#endif
    trace_clipboard("remote_formats", list->numFormats);
    clipboard.remoteText = FALSE;
    clear_text(&clipboard.incoming, &clipboard.incomingLength);
    clipboard.remoteFormat = 0;
    BOOL owned=FALSE;
    if(getenv("CALABI_RDP_FILE_MESH"))for(UINT32 i=0;i<list->numFormats;i++)
        if(list->formats[i].formatName && !strcmp(list->formats[i].formatName,"FileGroupDescriptorW"))owned=TRUE;
    for(UINT32 i=0;i<list->numFormats;i++)if(list->formats[i].formatName && !strcmp(list->formats[i].formatName,"CalabiRdpCopyOwnedV1"))owned=TRUE;
    if (!owned && probe_clipboard_content_enabled()) for (UINT32 i = 0; i < list->numFormats; ++i) {
        const CLIPRDR_FORMAT *f = &list->formats[i];
        if (f->formatId == CF_UNICODETEXT && !clipboard.remoteFormat) clipboard.remoteFormat = CF_UNICODETEXT;
        if (f->formatId == CF_DIB && clipboard.remoteFormat != PROBE_FORMAT_FILES) clipboard.remoteFormat = CF_DIB;
    }
    if (!owned && probe_clipboard_files_enabled()) for (UINT32 i = 0; i < list->numFormats; ++i)
        if (list->formats[i].formatName && !strcmp(list->formats[i].formatName,"FileGroupDescriptorW")) {
            clipboard.remoteFormat = list->formats[i].formatId; break;
        }
    clipboard.remoteText = clipboard.remoteFormat != 0;
    CLIPRDR_FORMAT_LIST_RESPONSE response = {0};
    response.common.msgFlags = CB_RESPONSE_OK;
    UINT result = channel->ClientFormatListResponse(channel, &response);
    LeaveCriticalSection(&clipboard.lock);
    return result;
}

static UINT format_ack(CliprdrClientContext *channel, const CLIPRDR_FORMAT_LIST_RESPONSE *response) {
    (void)channel;
    EnterCriticalSection(&clipboard.lock);
    trace_clipboard("format_ack", response->common.msgFlags);
    LeaveCriticalSection(&clipboard.lock);
    return CHANNEL_RC_OK;
}

static UINT data_request(CliprdrClientContext *channel, const CLIPRDR_FORMAT_DATA_REQUEST *request) {
    EnterCriticalSection(&clipboard.lock);
    trace_clipboard("remote_request", request->requestedFormatId);
    CLIPRDR_FORMAT_DATA_RESPONSE response = {0};
    response.common.msgFlags = CB_RESPONSE_FAIL;
#ifdef CALABI_SHELL_RECEIVE
    if(request->requestedFormatId==0xc003 && fileOfferValid && clipboard.localFormat==PROBE_FORMAT_FILES && clipboard.local && probe_clipboard_files_enabled()){
        response.common.msgFlags=CB_RESPONSE_OK;response.common.dataLen=sizeof(fileOffer);response.requestedFormatData=fileOffer;
    }
#endif
    if (clipboard.local && clipboard.localFormat == PROBE_FORMAT_PNG) {
        size_t pngSize = clip_image_png_size(clipboard.local, clipboard.localLength);
        if (pngSize && request->requestedFormatId == PROBE_FORMAT_PNG) {
            response.requestedFormatData = clipboard.local + 4;
            response.common.dataLen = (UINT32)pngSize;
        } else if (pngSize && request->requestedFormatId == CF_DIB) {
            response.requestedFormatData = clipboard.local + 4 + pngSize;
            response.common.dataLen = (UINT32)(clipboard.localLength - 4 - pngSize);
        }
        if (response.requestedFormatData) {
            response.common.msgFlags = CB_RESPONSE_OK;
            trace_clipboard("image_response_bytes", response.common.dataLen);
        }
    } else if (request->requestedFormatId == clipboard.localFormat && clipboard.local) {
        response.common.msgFlags = CB_RESPONSE_OK;
        response.common.dataLen = (UINT32)clipboard.localLength;
        response.requestedFormatData = clipboard.local;
    }
    UINT result = channel->ClientFormatDataResponse(channel, &response);
    trace_clipboard("local_response", response.common.msgFlags);
    LeaveCriticalSection(&clipboard.lock);
    return result;
}

static UINT data_response(CliprdrClientContext *channel, const CLIPRDR_FORMAT_DATA_RESPONSE *response) {
    (void)channel;
    EnterCriticalSection(&clipboard.lock);
    trace_clipboard("remote_response", response->common.msgFlags);
    if (clipboard.requested && clipboard.requestedGeneration == clipboard.generation &&
        clipboard.requestedSequence == clipboard.sequence &&
        (response->common.msgFlags & CB_RESPONSE_OK) &&
        valid_payload(clipboard.requestedFormat, response->requestedFormatData, response->common.dataLen)) {
        clear_text(&clipboard.incoming, &clipboard.incomingLength);
        clipboard.incoming = malloc(response->common.dataLen);
        if (clipboard.incoming) {
            clipboard.incomingLength = response->common.dataLen;
            clipboard.incomingFormat = clipboard.requestedFormat;
            memcpy(clipboard.incoming, response->requestedFormatData, clipboard.incomingLength);
        }
    } else if (clipboard.requested && clipboard.requestedGeneration == clipboard.generation &&
               clipboard.requestedFormat != CF_UNICODETEXT && clipboard.requestedFormat != CF_DIB) {
        trace_clipboard("file_descriptor_rejected", response->common.msgFlags);
        probe_files_progress(0,0,-2);
    }
    clipboard.requested = FALSE;
    LeaveCriticalSection(&clipboard.lock);
    return CHANNEL_RC_OK;
}

static void receive_files_abort(int reason) {
    trace_clipboard("files_aborted_reason", (unsigned)-reason);
    clipboard.fileActive = clipboard.fileWaiting = FALSE;
    probe_files_cancel();
    probe_files_progress(0,0,reason);
}
void clipboard_cancel_files(void) {
    LONG previous=InterlockedExchange(&clipboard.cancelFiles,1);
    (void)previous;
}
void clipboard_cancel_send(void) {
    InterlockedExchange(&clipboard.cancelSend,1);
}
static BOOL send_cancelled(void) {return InterlockedCompareExchange(&clipboard.cancelSend,0,0)!=0;}
static void receive_files_begin(void) {
    if (clipboard.fileActive) receive_files_abort(-3);
    int prepared = probe_clipboard_files_enabled() && clip_valid_files(clipboard.incoming,clipboard.incomingLength)
        ? probe_files_begin(clipboard.incoming,clipboard.incomingLength) : -2;
    if (prepared <= 0) {
        int reason=prepared<0?prepared:-9;
        trace_clipboard("files_prepare_failed",(unsigned)-reason);
        probe_files_progress(0,0,reason);return;
    }
    clipboard.fileCount=clip_u32(clipboard.incoming);
    trace_clipboard("files_started", clipboard.fileCount);
    clipboard.fileTotal=clipboard.fileDone=clipboard.fileOffset=clipboard.fileIndex=0;
    for(unsigned i=0;i<clipboard.fileCount;i++) {
        clipboard.fileSizes[i]=clip_file_size(clipboard.incoming+4+i*CLIP_DESCRIPTOR_SIZE);
        clipboard.fileTotal+=clipboard.fileSizes[i];
    }
    clipboard.fileSequence=clipboard.sequence; clipboard.fileGeneration=clipboard.generation;
    clipboard.fileActive=TRUE; clipboard.fileWaiting=FALSE;
    LONG previous=InterlockedExchange(&clipboard.cancelFiles,0);
    (void)previous;
    probe_files_progress(0,clipboard.fileTotal,1);
}
static int read_requested_file(const CLIPRDR_FILE_CONTENTS_REQUEST *r,uint64_t offset,BYTE *data,size_t *length,uint64_t *size){
#ifdef CALABI_SHELL_RECEIVE
    if(r->haveClipDataId)return probe_file_read_locked(r->clipDataId,r->listIndex,offset,data,length,size);
#endif
    return probe_file_read(r->listIndex,offset,data,length,size);
}
#ifdef CALABI_SHELL_RECEIVE
static UINT lock_files(CliprdrClientContext *channel,const CLIPRDR_LOCK_CLIPBOARD_DATA *request){
    (void)channel;EnterCriticalSection(&clipboard.lock);
    if(probe_clipboard_files_enabled() && clipboard.localFormat==PROBE_FORMAT_FILES && clipboard.local){
        trace_clipboard("files_source_lock_id",request->clipDataId);trace_clipboard("files_source_lock_ok",probe_file_lock(request->clipDataId));
    }
    LeaveCriticalSection(&clipboard.lock);return CHANNEL_RC_OK;
}
static UINT unlock_files(CliprdrClientContext *channel,const CLIPRDR_UNLOCK_CLIPBOARD_DATA *request){
    (void)channel;EnterCriticalSection(&clipboard.lock);probe_file_unlock(request->clipDataId);LeaveCriticalSection(&clipboard.lock);return CHANNEL_RC_OK;
}
#endif
static UINT file_request(CliprdrClientContext *channel, const CLIPRDR_FILE_CONTENTS_REQUEST *request) {
    EnterCriticalSection(&clipboard.lock);
    CLIPRDR_FILE_CONTENTS_RESPONSE response={0};
    response.streamId=request->streamId; response.common.msgFlags=CB_RESPONSE_FAIL;
    BYTE *data=NULL; size_t length=0; uint64_t size=0;
    BOOL allowed=!request->haveClipDataId && clipboard.localFormat==PROBE_FORMAT_FILES && clipboard.local && request->listIndex<clip_u32(clipboard.local);
#ifdef CALABI_SHELL_RECEIVE
    allowed=allowed || request->haveClipDataId;
#endif
    if (!send_cancelled() && probe_clipboard_files_enabled() && allowed) {
        uint64_t offset=(uint64_t)request->nPositionHigh<<32 | request->nPositionLow;
        if(request->dwFlags==FILECONTENTS_SIZE) {
            data=calloc(1,8);
            if(data && read_requested_file(request,0,NULL,&length,&size)) {
                clip_put32(data,(UINT32)size);clip_put32(data+4,(UINT32)(size>>32));length=8;
                response.common.msgFlags=CB_RESPONSE_OK;
            }
        } else if(request->dwFlags==FILECONTENTS_RANGE && request->cbRequested && request->cbRequested<=PROBE_CLIPBOARD_LIMIT) {
            length=request->cbRequested; data=malloc(length);
            if(data && read_requested_file(request,offset,data,&length,&size)) response.common.msgFlags=CB_RESPONSE_OK;
        }
    }
    if(send_cancelled())response.common.msgFlags=CB_RESPONSE_FAIL;
    response.cbRequested=response.common.msgFlags==CB_RESPONSE_OK?(UINT32)length:0;
    if(!request->nPositionLow || response.common.msgFlags!=CB_RESPONSE_OK){
        trace_clipboard("files_source_request_locked",request->haveClipDataId);
        trace_clipboard("files_source_request_id",request->clipDataId);
        trace_clipboard("files_source_response_flags",response.common.msgFlags);
    }
    response.requestedData=data;
    UINT result=channel->ClientFileContentsResponse(channel,&response);
    if(request->dwFlags==FILECONTENTS_RANGE && clipboard.localFormat==PROBE_FORMAT_FILES && clipboard.local && !getenv("CALABI_RDP_FILE_STREAM")) {
        if(send_cancelled())probe_files_progress(clipboard.sentDone,clipboard.sentTotal,-18);
        else if(response.common.msgFlags==CB_RESPONSE_OK && result==CHANNEL_RC_OK) {
            uint64_t offset=(uint64_t)request->nPositionHigh<<32 | request->nPositionLow;
            if(!clipboard.sentTotal || (clipboard.sentDone==clipboard.sentTotal && offset==0)) {
                memset(clipboard.sentPrefix,0,sizeof(clipboard.sentPrefix));
                clipboard.sentTotal=clipboard.sentDone=0;
                for(unsigned i=0;i<clip_u32(clipboard.local);i++)
                    clipboard.sentTotal+=clip_file_size(clipboard.local+4+i*CLIP_DESCRIPTOR_SIZE);
            }
            uint64_t *prefix=&clipboard.sentPrefix[request->listIndex];
            // Count contiguous bytes only; retries/overlaps must not inflate progress.
            if(offset<=*prefix && offset+length>*prefix) {
                clipboard.sentDone+=offset+length-*prefix;*prefix=offset+length;
            }
            probe_files_progress(clipboard.sentDone,clipboard.sentTotal,
                clipboard.sentDone==clipboard.sentTotal?4:3);
        } else probe_files_progress(clipboard.sentDone,clipboard.sentTotal,-15);
    }
    free(data);LeaveCriticalSection(&clipboard.lock);return result;
}
static UINT file_response(CliprdrClientContext *channel, const CLIPRDR_FILE_CONTENTS_RESPONSE *response) {
    (void)channel;
    EnterCriticalSection(&clipboard.lock);
#ifdef CALABI_SHELL_RECEIVE
    if(shell_wire_response(response)){LeaveCriticalSection(&clipboard.lock);return CHANNEL_RC_OK;}
#endif
    if (clipboard.fileActive && clipboard.fileWaiting && response->streamId==clipboard.streamId) {
        clipboard.fileWaiting=FALSE;
        if (clipboard.fileGeneration!=clipboard.generation) receive_files_abort(-3);
        else if (!(response->common.msgFlags&CB_RESPONSE_OK)) receive_files_abort(-6);
        else if(response->cbRequested!=clipboard.fileChunk || !response->requestedData) {
            trace_clipboard("file_expected_bytes",clipboard.fileChunk);
            trace_clipboard("file_received_bytes",response->cbRequested);
            receive_files_abort(-7);
        } else if(!probe_file_write(clipboard.fileIndex,clipboard.fileOffset,response->requestedData,response->cbRequested)) receive_files_abort(-8);
        else {
            clipboard.fileOffset+=response->cbRequested;clipboard.fileDone+=response->cbRequested;
            probe_files_progress(clipboard.fileDone,clipboard.fileTotal,1);
        }
    }
    LeaveCriticalSection(&clipboard.lock);return CHANNEL_RC_OK;
}
static void receive_files_poll(void) {
    if (!clipboard.fileActive) return;
    int reason=0;
    if(InterlockedExchange(&clipboard.cancelFiles,0))reason=-12;
    else if(clipboard.fileSequence!=clipboard.sequence)reason=-4;
    else if(clipboard.fileGeneration!=clipboard.generation)reason=-3;
    else if(clipboard.fileWaiting && GetTickCount64()>clipboard.fileDeadline)reason=-5;
    if(reason){receive_files_abort(reason);return;}
    if (clipboard.fileWaiting) return;
    while(clipboard.fileIndex<clipboard.fileCount && clipboard.fileOffset==clipboard.fileSizes[clipboard.fileIndex]) {
        clipboard.fileIndex++;clipboard.fileOffset=0;
    }
    if(clipboard.fileIndex==clipboard.fileCount) {
        uint64_t sequence=clipboard.sequence;
        if(probe_clipboard_write(NULL,0,PROBE_FORMAT_FILES,clipboard.sequence,&sequence)) {
            clipboard.sequence=sequence;clipboard.fileActive=FALSE;
            trace_clipboard("files_ready", clipboard.fileCount);
            clear_text(&clipboard.local,&clipboard.localLength);
            probe_files_progress(clipboard.fileDone,clipboard.fileTotal,2);
        } else receive_files_abort(-14);
        return;
    }
    CLIPRDR_FILE_CONTENTS_REQUEST request={0};
    request.streamId=++clipboard.nextStreamId;request.listIndex=clipboard.fileIndex;request.dwFlags=FILECONTENTS_RANGE;
    request.nPositionLow=(UINT32)clipboard.fileOffset;request.nPositionHigh=(UINT32)(clipboard.fileOffset>>32);
    uint64_t remaining=clipboard.fileSizes[clipboard.fileIndex]-clipboard.fileOffset;
    request.cbRequested=(UINT32)(remaining>65536?65536:remaining);
    clipboard.fileChunk=request.cbRequested;clipboard.streamId=request.streamId;
    clipboard.fileWaiting=TRUE;clipboard.fileDeadline=GetTickCount64()+30000;
    if(clipboard.channel->ClientFileContentsRequest(clipboard.channel,&request)!=CHANNEL_RC_OK) receive_files_abort(-13);
}

static void bind_clipboard(const char *name, void *channelInterface) {
    if (strcmp(name, CLIPRDR_SVC_CHANNEL_NAME) || !channelInterface) return;
    EnterCriticalSection(&clipboard.lock);
    CliprdrClientContext *channel = channelInterface;
    trace_clipboard("channel_bound", 1);
    clipboard.channel = channel;
    channel->ServerCapabilities = capabilities;
    channel->MonitorReady = monitor_ready;
    channel->ServerFormatList = format_list;
    channel->ServerFormatListResponse = format_ack;
    channel->ServerFormatDataRequest = data_request;
    channel->ServerFormatDataResponse = data_response;
    channel->ServerFileContentsRequest = file_request;
    channel->ServerFileContentsResponse = file_response;
#ifdef CALABI_SHELL_RECEIVE
    channel->ServerLockClipboardData=lock_files;channel->ServerUnlockClipboardData=unlock_files;
#endif
    LeaveCriticalSection(&clipboard.lock);
}
static void channel_connected(void *context, const ChannelConnectedEventArgs *event) {
    (void)context;
    if (!strcmp(event->name, CLIPRDR_SVC_CHANNEL_NAME)) trace_clipboard("channel_connected", event->pInterface != NULL);
    bind_clipboard(event->name, event->pInterface);
}
static void channel_initialized(void *context, const ChannelInitializedEventArgs *event) {
    (void)context;
    if (!strcmp(event->name, CLIPRDR_SVC_CHANNEL_NAME)) trace_clipboard("channel_initialized", event->pInterface != NULL);
    bind_clipboard(event->name, event->pInterface);
}

static void channel_disconnected(void *context, const ChannelDisconnectedEventArgs *event) {
    (void)context;
    if (strcmp(event->name, CLIPRDR_SVC_CHANNEL_NAME)) return;
    EnterCriticalSection(&clipboard.lock);
#ifdef CALABI_SHELL_RECEIVE
    shell_wire_invalidate();
    probe_file_unlock_all();
#endif
    if (clipboard.fileActive) receive_files_abort(-11);
    clipboard.channel = NULL;
    if(clipboard.sentDone<clipboard.sentTotal) probe_files_progress(clipboard.sentDone,clipboard.sentTotal,-16);
    clipboard.sentTotal=clipboard.sentDone=0;
    clipboard.ready = FALSE;
    trace_clipboard("channel_disconnected", 0);
    LeaveCriticalSection(&clipboard.lock);
}

BOOL clipboard_start(freerdp *rdp) {
    memset(&clipboard, 0, sizeof(clipboard));
    InitializeCriticalSection(&clipboard.lock);
    clipboard.initialized = TRUE;
#ifdef CALABI_SHELL_RECEIVE
    memset(&shellWire,0,sizeof(shellWire));
    shellWire.done=CreateEventW(NULL,TRUE,FALSE,NULL);
    shellWire.wake=CreateEventW(NULL,FALSE,FALSE,NULL);
    if(!shellWire.done || !shellWire.wake)return FALSE;
#endif
    clipboard.sequence = UINT64_MAX;
    const char *logPath = getenv("CALABI_RDP_CLIP_LOG");
    clipboardLog = logPath ? fopen(logPath, "w") : NULL;
    logCount = 0;
    trace_clipboard("enabled", probe_clipboard_enabled());
    if (!probe_clipboard_enabled()) return TRUE;
#ifdef CLIPRDR_FLAG_LOCAL_TO_REMOTE
    if (!freerdp_settings_set_uint32(rdp->context->settings, FreeRDP_ClipboardFeatureMask,
            CLIPRDR_FLAG_LOCAL_TO_REMOTE | CLIPRDR_FLAG_REMOTE_TO_LOCAL |
            (probe_clipboard_files_enabled() ? CLIPRDR_FLAG_LOCAL_TO_REMOTE_FILES | CLIPRDR_FLAG_REMOTE_TO_LOCAL_FILES : 0))) return FALSE;
#endif
    return PubSub_SubscribeChannelInitialized(rdp->context->pubSub, channel_initialized) >= 0 &&
           PubSub_SubscribeChannelConnected(rdp->context->pubSub, channel_connected) >= 0 &&
           PubSub_SubscribeChannelDisconnected(rdp->context->pubSub, channel_disconnected) >= 0;
}

// FreeRDP recreates context->channels after PreConnect and on redirection.
// Load into that new container, never the one about to be destroyed.
BOOL clipboard_load(freerdp *rdp) {
    if (!probe_clipboard_enabled()) return TRUE;
    EnterCriticalSection(&clipboard.lock);
#ifdef CALABI_SHELL_RECEIVE
    shell_wire_invalidate();
    probe_file_unlock_all();
#endif
    if (clipboard.fileActive) receive_files_abort(-11);
    clipboard.channel = NULL;
    clipboard.ready = clipboard.requested = clipboard.remoteText = FALSE;
    clipboard.generation = clipboard.consumedGeneration = 0;
#ifdef CALABI_SHELL_RECEIVE
    clipboard.generation=++shellGeneration;
#endif
    clipboard.sequence = UINT64_MAX;
    clipboard.nextPoll = 0;
    clear_text(&clipboard.local, &clipboard.localLength);
    clear_text(&clipboard.incoming, &clipboard.incomingLength);
    trace_clipboard("load_channels", 1);
    LeaveCriticalSection(&clipboard.lock);
    freerdp_register_addin_provider(freerdp_channels_load_static_addin_entry, 0);
    PVIRTUALCHANNELENTRY entry = freerdp_load_channel_addin_entry(
        "cliprdr", NULL, NULL, FREERDP_ADDIN_CHANNEL_STATIC | FREERDP_ADDIN_CHANNEL_ENTRYEX);
    trace_clipboard("entry_found", entry != NULL);
    if (!entry) return FALSE;
    UINT result = freerdp_channels_client_load_ex(rdp->context->channels, rdp->context->settings,
                                                (PVIRTUALCHANNELENTRYEX)entry, NULL);
    trace_clipboard("channel_load_result", result);
#ifdef CALABI_SHELL_RECEIVE
    if(result==0 && probe_clipboard_files_enabled() && getenv("CALABI_RDP_FILE_STREAM"))
        result=freerdp_channels_client_load_ex(rdp->context->channels,rdp->context->settings,file_channel_entry,NULL);
#endif
    return result == 0;
}

void clipboard_poll(void) {
    if (!clipboard.initialized) return;
#ifdef CALABI_SHELL_RECEIVE
    EnterCriticalSection(&clipboard.lock);
    if(clipboard.channel && clipboard.ready)shell_wire_poll();
    LeaveCriticalSection(&clipboard.lock);
#endif
    if(GetTickCount64() < clipboard.nextPoll) return;
    clipboard.nextPoll = GetTickCount64() + 100;
    EnterCriticalSection(&clipboard.lock);
    CliprdrClientContext *channel = clipboard.channel;
    if (!channel || !clipboard.ready) { LeaveCriticalSection(&clipboard.lock); return; }
    if(send_cancelled())probe_files_progress(clipboard.sentDone,clipboard.sentTotal,-18);
    BYTE *text = NULL;
    size_t length = 0;
    uint64_t sequence = clipboard.sequence;
    UINT32 format = 0;
    int readResult=probe_clipboard_read(&text, &length, &format, &sequence);
    if (!readResult) {
        LeaveCriticalSection(&clipboard.lock);
        return;
    }
    if (readResult == PROBE_CLIPBOARD_INITIAL_SELECTION) {
        clipboard.sequence = sequence;
        if (clipboard.remoteFormat != CF_UNICODETEXT) {
            clear_text(&clipboard.incoming,&clipboard.incomingLength);
            clipboard.consumedGeneration = clipboard.generation;
        }
        trace_clipboard("initial_workspace_clipboard", 1);
    }
    // Our destination IDataObject must not echo an empty format list back to
    // Windows: that would destroy the remote clipboard supplying these files.
    if(readResult==3){
#ifdef __APPLE__
        if(sequence!=clipboard.sequence){
            // A payload queued before the file marker must not inherit its revision.
            clear_text(&clipboard.incoming,&clipboard.incomingLength);
            clipboard.consumedGeneration=clipboard.generation;
            trace_clipboard("mesh_file_clipboard_kept",1);
        }
#endif
        clipboard.sequence=sequence;
    }
    if (sequence != clipboard.sequence || readResult==2) {
#ifdef CALABI_SHELL_RECEIVE
        shell_wire_invalidate();
#endif
        trace_clipboard("local_changed_text", length > 0);
        clipboard.sequence = sequence;
        InterlockedExchange(&clipboard.cancelSend,0);
        if(clipboard.sentDone<clipboard.sentTotal) probe_files_progress(clipboard.sentDone,clipboard.sentTotal,-17);
        clipboard.sentTotal=clipboard.sentDone=0;
        memset(clipboard.sentPrefix,0,sizeof(clipboard.sentPrefix));
        clear_text(&clipboard.local, &clipboard.localLength);
        clear_text(&clipboard.incoming, &clipboard.incomingLength);
        clipboard.consumedGeneration = clipboard.generation;
        BOOL valid = format == PROBE_FORMAT_PNG
            ? probe_clipboard_content_enabled() && clip_image_png_size(text, length) != 0
            : valid_payload(format, text, length);
        if (valid) {
            clipboard.localFormat = format;
            clipboard.local = text; clipboard.localLength = length;
            text = NULL; length = 0;
        }
        CLIPRDR_FORMAT offered = {clipboard.localFormat, clipboard.localFormat == PROBE_FORMAT_FILES ? "FileGroupDescriptorW" : clipboard.localFormat == PROBE_FORMAT_BRIDGE ? "CalabiRdpCopyV1" : NULL};
        CLIPRDR_FORMAT_LIST list = {0};
        list.numFormats = clipboard.local ? 1 : 0;
        list.formats = clipboard.local ? &offered : NULL;
        CLIPRDR_FORMAT imageFormats[2] = {{PROBE_FORMAT_PNG, "PNG"}, {CF_DIB, NULL}};
        if (clipboard.local && clipboard.localFormat == PROBE_FORMAT_PNG) {
            list.formats = imageFormats;
            list.numFormats = 2;
        }
#ifdef CALABI_SHELL_RECEIVE
        file_offer_refresh();
        CLIPRDR_FORMAT streamFormats[2]={offered,{0xc003,CALFILE_MARKER}};
        if(fileOfferValid){
            list.formats=streamFormats;list.numFormats=2;
        }
#endif
        UINT result = channel->ClientFormatList(channel, &list);
        trace_clipboard("local_formats_sent", result);
        if (result != CHANNEL_RC_OK)
            clipboard.ready = FALSE;
    }
    clear_text(&text, &length);
    if (clipboard.incoming && clipboard.incomingFormat != CF_UNICODETEXT && clipboard.incomingFormat != CF_DIB) {
#ifdef CALABI_SHELL_RECEIVE
        shell_wire_offer();
        clear_text(&clipboard.local,&clipboard.localLength);
#else
        receive_files_begin();
#endif
        clear_text(&clipboard.incoming, &clipboard.incomingLength);
    }
    if (clipboard.incoming) {
        if (probe_clipboard_write(clipboard.incoming, clipboard.incomingLength, clipboard.incomingFormat,
                                 clipboard.sequence, &sequence)) {
            clipboard.sequence = sequence;
            trace_clipboard("remote_text_applied", 1);
            clear_text(&clipboard.local, &clipboard.localLength);
            clear_text(&clipboard.incoming, &clipboard.incomingLength);
        }
    }
    if (clipboard.remoteText && !clipboard.requested &&
        clipboard.consumedGeneration != clipboard.generation) {
        clipboard.requested = TRUE;
        clipboard.requestedSequence = clipboard.sequence;
        clipboard.requestedGeneration = clipboard.generation;
        clipboard.requestedFormat = clipboard.remoteFormat;
        clipboard.consumedGeneration = clipboard.generation;
        CLIPRDR_FORMAT_DATA_REQUEST request = {0};
        request.requestedFormatId = clipboard.remoteFormat;
        trace_clipboard("remote_text_requested", 1);
        if (channel->ClientFormatDataRequest(channel, &request) != CHANNEL_RC_OK)
            clipboard.requested = FALSE;
    }
    receive_files_poll();
    LeaveCriticalSection(&clipboard.lock);
}

// Call after freerdp_context_free has joined the channel workers.
void clipboard_stop(void) {
    if (!clipboard.initialized) return;
#ifdef CALABI_SHELL_RECEIVE
    EnterCriticalSection(&clipboard.lock);
    // The FreeRDP context has already been freed here. Never send an unlock
    // through a retained channel pointer while joining the Shell readers.
    clipboard.channel=NULL;shellWire.stopping=TRUE;shell_wire_invalidate();
    LeaveCriticalSection(&clipboard.lock);
    shell_receive_stop();CloseHandle(shellWire.done);CloseHandle(shellWire.wake);
#endif
    clear_text(&clipboard.local, &clipboard.localLength);
    clear_text(&clipboard.incoming, &clipboard.incomingLength);
    probe_files_cleanup();
    DeleteCriticalSection(&clipboard.lock);
    trace_clipboard("stopped", 0);
    if (clipboardLog) fclose(clipboardLog);
    clipboardLog = NULL;
    memset(&clipboard, 0, sizeof(clipboard));
}
