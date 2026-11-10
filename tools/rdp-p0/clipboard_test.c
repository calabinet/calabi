// Protocol tests use an in-memory clipboard and never touch the user's clipboard.
#include <assert.h>
#include "clipboard.c"
#include <freerdp/transport_io.h>

static unsigned realInitialized;
static int offline_connect(rdpContext *ctx, rdpSettings *settings, const char *host, int port, DWORD timeout) {
    (void)ctx; (void)settings; (void)host; (void)port; (void)timeout;
    return -1; // Exercise the real connection lifecycle without accessing any host.
}
static void observe_initialized(void *context, const ChannelInitializedEventArgs *event) {
    (void)context;
    if (!strcmp(event->name, "cliprdr")) {
        CliprdrClientContext *channel = event->pInterface;
        assert(channel && channel->MonitorReady == monitor_ready);
        realInitialized++;
    }
}
static BOOL prepare_lifecycle(freerdp *rdp) {
    return clipboard_start(rdp) &&
        PubSub_SubscribeChannelInitialized(rdp->context->pubSub, observe_initialized) >= 0;
}
static BOOL prepare_legacy_lifecycle(freerdp *rdp) {
    return prepare_lifecycle(rdp) && clipboard_load(rdp);
}

static BYTE nativeText[4096];
static size_t nativeLength;
static uint64_t nativeSequence = 1;
static unsigned announcements, requests, writes;
static BOOL busy;
static int nativeReadResult;
static int enabled = 1, filesEnabled;
static uint32_t nativeFormat=PROBE_FORMAT_TEXT;
static unsigned fileWrites, fileCancels, fileRequests;
static unsigned fileReads;
static BOOL cancelDuringRead;
static BYTE fileBytes[16];
static UINT lastFlags;
static size_t lastLength;
static BYTE lastPayload[4096];

int probe_clipboard_enabled(void) { return enabled; }
int probe_clipboard_content_enabled(void) { return enabled; }
int probe_clipboard_files_enabled(void) { return filesEnabled; }
int probe_file_read(unsigned i,uint64_t o,uint8_t *d,size_t *n,uint64_t *size) {
    fileReads++;if(cancelDuringRead)clipboard_cancel_send();
    static const uint8_t sample[]="test";
    if(i!=0 || o>4)return 0;*size=4;if(!d)return 1;if(*n>4-o)*n=4-o;memcpy(d,&sample[o],*n);return 1;
}
int probe_files_begin(const uint8_t *d,size_t n) { return clip_valid_files(d,n); }
int probe_file_write(unsigned i,uint64_t o,const uint8_t *d,size_t n) {
    if(i!=0 || o+n>sizeof(fileBytes))return 0;memcpy(fileBytes+o,d,n);fileWrites++;return 1;
}
void probe_files_cancel(void) { fileCancels++; }
static int lastFileState;
void probe_files_progress(uint64_t d,uint64_t t,int state) { (void)d;(void)t;lastFileState=state; }
void probe_files_cleanup(void) {}
int probe_clipboard_read(uint8_t **text, size_t *length, uint32_t *format, uint64_t *sequence) {
    *text = NULL; *length = 0; *format=nativeFormat;
    if(nativeReadResult){*sequence=nativeSequence;return nativeReadResult;}
    if (*sequence == nativeSequence) return 1;
    *sequence = nativeSequence;
    if (nativeLength) {
        *text = malloc(nativeLength);
        memcpy(*text, nativeText, nativeLength);
        *length = nativeLength;
    }
    return 1;
}
int probe_clipboard_write(const uint8_t *text, size_t length, uint32_t format, uint64_t expected, uint64_t *sequence) {
    if (busy || expected != nativeSequence) return 0;
    assert(length <= sizeof(nativeText));
    if(length)memcpy(nativeText, text, length);
    nativeFormat=format;
    nativeLength = length;
    *sequence = ++nativeSequence;
    writes++;
    return 1;
}
static UINT list_sent(CliprdrClientContext *channel, const CLIPRDR_FORMAT_LIST *list) {
    (void)channel;
    if (nativeFormat == PROBE_FORMAT_PNG && list->numFormats) {
        assert(list->numFormats == 2 && !strcmp(list->formats[0].formatName, "PNG"));
        assert(list->formats[1].formatId == CF_DIB && !list->formats[1].formatName);
    } else {
        assert(list->numFormats <= 1);
    }
    if (list->numFormats) assert(list->formats[0].formatId == nativeFormat);
    announcements++;
    return 0;
}
static UINT requested(CliprdrClientContext *channel, const CLIPRDR_FORMAT_DATA_REQUEST *request) {
    (void)channel; assert(request->requestedFormatId == CF_UNICODETEXT || request->requestedFormatId == CF_DIB || request->requestedFormatId >= 0xc000);
    requests++;
    return 0;
}
static UINT responded(CliprdrClientContext *channel, const CLIPRDR_FORMAT_DATA_RESPONSE *response) {
    (void)channel;
    lastFlags = response->common.msgFlags;
    lastLength = response->common.dataLen;
    if (lastLength && lastLength <= sizeof(lastPayload))
        memcpy(lastPayload, response->requestedFormatData, lastLength);
    return 0;
}
static UINT file_requested(CliprdrClientContext *channel,const CLIPRDR_FILE_CONTENTS_REQUEST *r) {
    (void)channel;assert(r->listIndex==0 && r->cbRequested==4);fileRequests++;return 0;
}
static UINT file_responded(CliprdrClientContext *channel,const CLIPRDR_FILE_CONTENTS_RESPONSE *r) {
    (void)channel;lastFlags=r->common.msgFlags;lastLength=r->cbRequested;return 0;
}
static UINT acknowledged(CliprdrClientContext *channel, const CLIPRDR_FORMAT_LIST_RESPONSE *response) {
    (void)channel; assert(response->common.msgFlags == CB_RESPONSE_OK); return 0;
}
static void poll_now(void) { clipboard.nextPoll = 0; clipboard_poll(); }
static void response(CliprdrClientContext *channel, const BYTE *text, size_t length) {
    CLIPRDR_FORMAT_DATA_RESPONSE r = {0};
    r.common.msgFlags = CB_RESPONSE_OK; r.common.dataLen = (UINT32)length;
    r.requestedFormatData = text;
    assert(data_response(channel, &r) == 0);
}

int main(void) {
    static const BYTE text[] = {0x2d,0x4e,0x87,0x65,13,0,10,0,0x3d,0xd8,0,0xde,0,0};
    static const BYTE malformed[] = {0,0xd8,0,0};
    assert(valid_text(text,sizeof(text)));
    assert(!valid_text(malformed,sizeof(malformed)));
    assert(!valid_text(text,sizeof(text)-1));
    assert(!valid_text(text,PROBE_CLIPBOARD_LIMIT+2));
    assert(!valid_text(text,sizeof(text)-2));
    BYTE *large=calloc(1,PROBE_CLIPBOARD_LIMIT);
    assert(large);
    for(size_t i=0;i<PROBE_CLIPBOARD_LIMIT-2;i+=2)large[i]='x';
    assert(valid_text(large,PROBE_CLIPBOARD_LIMIT));
    free(large);

    CliprdrClientContext channel = {0};
    channel.ClientFormatList = list_sent;
    channel.ClientFormatDataRequest = requested;
    channel.ClientFormatDataResponse = responded;
    channel.ClientFormatListResponse = acknowledged;
    InitializeCriticalSection(&clipboard.lock);
    clipboard.initialized = clipboard.ready = TRUE;
    clipboard.sequence = UINT64_MAX;
    clipboard.channel = &channel;
    memcpy(nativeText,text,sizeof(text)); nativeLength=sizeof(text);
    poll_now();
    assert(announcements==1 && clipboard.localLength==sizeof(text));
    CLIPRDR_FORMAT_DATA_REQUEST get = {0}; get.requestedFormatId=CF_UNICODETEXT;
    data_request(&channel,&get);
    assert(lastFlags==CB_RESPONSE_OK && lastLength==sizeof(text));
    get.requestedFormatId=CF_HDROP;
    data_request(&channel,&get);
    assert(lastFlags==CB_RESPONSE_FAIL && lastLength==0);

    CLIPRDR_FORMAT unicode={CF_UNICODETEXT,NULL};
    CLIPRDR_FORMAT_LIST list={0};list.numFormats=1;list.formats=&unicode;
    format_list(&channel,&list);poll_now();
    assert(requests==1);
    response(&channel,text,sizeof(text));
    busy=TRUE;poll_now();
    assert(writes==0 && clipboard.incoming);
    busy=FALSE;poll_now();poll_now();
    assert(writes==1 && announcements==1); // Remote write never echoes back.

    format_list(&channel,&list);poll_now();
    nativeSequence++; // Local copy wins over an in-flight remote response.
    response(&channel,text,sizeof(text));poll_now();
    assert(writes==1 && announcements==2);
    format_list(&channel,&list);poll_now();
    format_list(&channel,&list); // Old generation must not overwrite the newer copy.
    response(&channel,text,sizeof(text));poll_now();
    assert(writes==1 && clipboard.requested);
    response(&channel,malformed,sizeof(malformed));poll_now();
    assert(writes==1);
    list.numFormats=0;format_list(&channel,&list);poll_now();
    unsigned before=requests;
    poll_now(); assert(requests==before);
#ifdef __APPLE__
    list.numFormats=1;format_list(&channel,&list);poll_now();response(&channel,text,sizeof(text));
    assert(clipboard.incoming);
    nativeReadResult=3;nativeSequence++;
    unsigned savedWrites=writes,savedAnnouncements=announcements;
    poll_now();assert(writes==savedWrites && announcements==savedAnnouncements && !clipboard.incoming);
    nativeReadResult=0;
#endif
    // Real bitmap payload and malformed geometry.
    BYTE dib[48]={0};clip_put32(dib,40);clip_put32(dib+4,2);clip_put32(dib+8,1);dib[12]=1;dib[14]=24;
    assert(clip_valid_dib(dib,sizeof(dib)));assert(!clip_valid_dib(dib,47));
    clip_put32(dib+4,0xffffffff);assert(!clip_valid_dib(dib,sizeof(dib)));clip_put32(dib+4,2);
    nativeFormat=CF_DIB;nativeLength=sizeof(dib);memcpy(nativeText,dib,sizeof(dib));nativeSequence++;poll_now();
    get.requestedFormatId=CF_DIB;data_request(&channel,&get);assert(lastFlags==CB_RESPONSE_OK && lastLength==48);
    unicode.formatId=CF_DIB;list.numFormats=1;format_list(&channel,&list);poll_now();response(&channel,dib,sizeof(dib));poll_now();
    assert(nativeFormat==CF_DIB && nativeLength==48);
    // A format request gets its image bytes, never the local bundle or both images.
    static const BYTE pngSignature[] = {137, 80, 78, 71, 13, 10, 26, 10};
    nativeFormat = PROBE_FORMAT_PNG;
    nativeLength = 4 + sizeof(pngSignature) + sizeof(dib);
    clip_put32(nativeText, sizeof(pngSignature));
    memcpy(nativeText + 4, pngSignature, sizeof(pngSignature));
    memcpy(nativeText + 4 + sizeof(pngSignature), dib, sizeof(dib));
    assert(!clip_image_png_size(nativeText, nativeLength - 1));
    nativeSequence++;
    poll_now();
    get.requestedFormatId = PROBE_FORMAT_PNG;
    data_request(&channel, &get);
    assert(lastFlags == CB_RESPONSE_OK && lastLength == sizeof(pngSignature) &&
           !memcmp(lastPayload, pngSignature, sizeof(pngSignature)));
    get.requestedFormatId = CF_DIB;
    data_request(&channel, &get);
    assert(lastFlags == CB_RESPONSE_OK && lastLength == sizeof(dib) &&
           !memcmp(lastPayload, dib, sizeof(dib)));
    // File descriptors use wire offsets, never native struct layout.
    BYTE descriptors[4+CLIP_DESCRIPTOR_SIZE]={0};clip_put32(descriptors,1);
    BYTE *d=descriptors+4;clip_put32(d,0x44);clip_put32(d+36,0x80);clip_put32(d+68,4);d[72]='a';
    assert(clip_valid_files(descriptors,sizeof(descriptors)));
    d[72]='/';assert(!clip_valid_files(descriptors,sizeof(descriptors)));d[72]='a';
    clip_put32(d+68,PROBE_FILE_LIMIT+1);assert(!clip_valid_files(descriptors,sizeof(descriptors)));clip_put32(d+68,4);
    clip_put32(d+64,0xffffffff);assert(!clip_valid_files(descriptors,sizeof(descriptors)));clip_put32(d+64,0);
    clip_put32(d+36,0x10);assert(!clip_valid_files(descriptors,sizeof(descriptors)));clip_put32(d+36,0x80);
    filesEnabled=1;channel.ClientFileContentsRequest=file_requested;channel.ClientFileContentsResponse=file_responded;
    unicode.formatId=0xc123;unicode.formatName="FileGroupDescriptorW";
    format_list(&channel,&list);poll_now();response(&channel,descriptors,sizeof(descriptors));poll_now();
    assert(clipboard.fileActive && fileRequests==1 && fileWrites==0);
    CLIPRDR_FILE_CONTENTS_RESPONSE fr={0};fr.common.msgFlags=CB_RESPONSE_OK;fr.cbRequested=4;fr.requestedData=(BYTE*)"test";
    fr.streamId=clipboard.streamId+1;file_response(&channel,&fr);assert(fileWrites==0);
    fr.streamId=clipboard.streamId;file_response(&channel,&fr);poll_now();
    assert(fileWrites==1 && !memcmp(fileBytes,"test",4) && !clipboard.fileActive && nativeFormat==PROBE_FORMAT_FILES);
    format_list(&channel,&list);poll_now();response(&channel,descriptors,sizeof(descriptors));poll_now();
    clipboard_cancel_files();poll_now();assert(!clipboard.fileActive && fileCancels>0 && lastFileState==-12);
    fr.streamId=clipboard.streamId;file_response(&channel,&fr);assert(fileWrites==1);
    // A changed clipboard and a short chunk must each discard the unfinished batch.
    format_list(&channel,&list);poll_now();response(&channel,descriptors,sizeof(descriptors));poll_now();
    nativeSequence++;poll_now();assert(!clipboard.fileActive && lastFileState==-4);
    fr.streamId=clipboard.streamId;file_response(&channel,&fr);assert(fileWrites==1);
    format_list(&channel,&list);poll_now();response(&channel,descriptors,sizeof(descriptors));poll_now();
    fr.streamId=clipboard.streamId;fr.cbRequested=3;file_response(&channel,&fr);assert(!clipboard.fileActive && fileWrites==1 && lastFileState==-7);
    fr.cbRequested=4;
    // Deny out-of-range requests and file access when the option is off.
    clipboard.local=malloc(sizeof(descriptors));memcpy(clipboard.local,descriptors,sizeof(descriptors));
    clipboard.localLength=sizeof(descriptors);clipboard.localFormat=PROBE_FORMAT_FILES;
    CLIPRDR_FILE_CONTENTS_REQUEST fq={0};fq.dwFlags=FILECONTENTS_RANGE;fq.cbRequested=4;
    fq.cbRequested=2;file_request(&channel,&fq);
    assert(lastFlags==CB_RESPONSE_OK && lastLength==2 && clipboard.sentDone==2 && lastFileState==3);
    file_request(&channel,&fq);assert(clipboard.sentDone==2);
    fq.nPositionLow=2;file_request(&channel,&fq);
    assert(clipboard.sentDone==4 && lastFileState==4);
    fq.nPositionLow=0;fq.cbRequested=4;
    file_request(&channel,&fq);assert(lastFlags==CB_RESPONSE_OK && lastLength==4 && clipboard.sentDone==4);
    fq.cbRequested=2;file_request(&channel,&fq);assert(clipboard.sentDone==2);
    clipboard_cancel_send();unsigned readsBefore=fileReads;fq.nPositionLow=2;
    file_request(&channel,&fq);assert(lastFlags==CB_RESPONSE_FAIL && lastLength==0 && fileReads==readsBefore && lastFileState==-18);
    fq.dwFlags=FILECONTENTS_SIZE;file_request(&channel,&fq);assert(lastFlags==CB_RESPONSE_FAIL && fileReads==readsBefore);
    fq.dwFlags=FILECONTENTS_RANGE;fq.nPositionLow=0;file_request(&channel,&fq);assert(lastFlags==CB_RESPONSE_FAIL);
    memcpy(nativeText,descriptors,sizeof(descriptors));nativeLength=sizeof(descriptors);nativeFormat=PROBE_FORMAT_FILES;nativeSequence++;poll_now();
    file_request(&channel,&fq);assert(lastFlags==CB_RESPONSE_OK && clipboard.sentDone==2);
    cancelDuringRead=TRUE;fq.nPositionLow=2;file_request(&channel,&fq);
    assert(lastFlags==CB_RESPONSE_FAIL && lastLength==0 && clipboard.sentDone==2);cancelDuringRead=FALSE;
    nativeSequence++;poll_now();fq.nPositionLow=0;fq.cbRequested=4;
    fq.listIndex=1;file_request(&channel,&fq);assert(lastFlags==CB_RESPONSE_FAIL);
    filesEnabled=0;fq.listIndex=0;file_request(&channel,&fq);assert(lastFlags==CB_RESPONSE_FAIL);
    format_list(&channel,&list);assert(!clipboard.remoteText);
    clipboard_stop();
    // The workspace can activate after Windows announces its clipboard. The
    // first local baseline must neither echo old local text nor discard that offer.
    filesEnabled=0;
    nativeFormat=PROBE_FORMAT_TEXT;
    unicode.formatId=CF_UNICODETEXT;
    list.numFormats=1;list.formats=&unicode;
    InitializeCriticalSection(&clipboard.lock);
    clipboard.initialized=clipboard.ready=TRUE;
    clipboard.sequence=UINT64_MAX;
    clipboard.channel=&channel;
    unsigned firstRequests=requests, firstWrites=writes, firstAnnouncements=announcements;
    format_list(&channel,&list);
    nativeReadResult=PROBE_CLIPBOARD_INITIAL_SELECTION;poll_now();nativeReadResult=0;
    assert(requests==firstRequests+1 && announcements==firstAnnouncements);
    response(&channel,text,sizeof(text));poll_now();
    assert(writes==firstWrites+1 && announcements==firstAnnouncements);
    assert(nativeLength==sizeof(text) && !memcmp(nativeText,text,sizeof(text)));
    clipboard_stop();
    enabled=0;
    freerdp *rdp=freerdp_new();
    assert(rdp && freerdp_context_new(rdp));
    assert(clipboard_start(rdp));
    assert(!freerdp_channels_get_static_channel_interface(rdp->context->channels,"cliprdr"));
    freerdp_context_free(rdp);freerdp_free(rdp);clipboard_stop();
    assert(!clipboard.initialized && !clipboard.local && !clipboard.incoming);
    enabled=1;
    rdp=freerdp_new();
    assert(rdp && freerdp_context_new(rdp));
    assert(clipboard_start(rdp)); // Verify the packaged static channel entry exists.
    assert(clipboard_load(rdp));
    // Exercise registration through the actual event bus, before Connected.
    ChannelInitializedEventArgs initialized = {0};
    EventArgsInit(&initialized, "clipboard-test");
    initialized.name = "cliprdr";
    initialized.pInterface = &channel;
    assert(PubSub_OnChannelInitialized(rdp->context->pubSub, rdp->context, &initialized) >= 0);
    assert(clipboard.channel == &channel);
    assert(channel.MonitorReady == monitor_ready && channel.ServerFormatList == format_list);
    assert(channel.ServerFormatDataRequest == data_request && channel.ServerFormatDataResponse == data_response);
    freerdp_context_free(rdp);
    freerdp_free(rdp);
    clipboard_stop();
    for (int mode = 0; mode < 3; ++mode) {
        enabled = mode != 0;
        rdp = freerdp_new();
        assert(rdp && freerdp_context_new(rdp));
        realInitialized = 0;
        rdp->PreConnect = mode == 1 ? prepare_legacy_lifecycle : prepare_lifecycle;
        rdp->LoadChannels = mode == 1 ? NULL : clipboard_load;
        assert(freerdp_settings_set_string(rdp->context->settings, FreeRDP_ServerHostname, "127.0.0.1"));
        rdpTransportIo io = *freerdp_get_io_callbacks(rdp->context);
        io.TCPConnect = offline_connect;
        assert(freerdp_set_io_callbacks(rdp->context, &io));
        // Subscribe after our callback in PreConnect, so observe the bound interface.
        assert(!freerdp_connect(rdp));
        assert(realInitialized == (mode == 2 ? 1u : 0u));
        freerdp_context_free(rdp); freerdp_free(rdp); clipboard_stop();
    }
    return 0;
}
