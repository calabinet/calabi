#define CALABI_SHELL_RECEIVE
#define main legacy_clipboard_main
#include "clipboard_test.c"
#undef main
#undef assert
#define assert(e) do{if(!(e)){fprintf(stderr,"reverse channel assertion: %s line %d\n",#e,__LINE__);ExitProcess(3);}}while(0)
static unsigned offers;
static BYTE channelReply[CALFILE_HEADER+CALFILE_BLOCK];static UINT channelReplySize;
static UINT VCAPITYPE capture_write(void *init,DWORD handle,void *data,ULONG n,void *user){
    (void)handle;(void)user;assert(n<=sizeof(channelReply));memcpy(channelReply,data,n);channelReplySize=n;
    file_channel_event(init,0,CHANNEL_EVENT_WRITE_COMPLETE,data,0,0,0);return CHANNEL_RC_OK;
}
static void check_forward_transport(void){
    CalFilePlugin plugin={0};plugin.init=&plugin;plugin.connected=TRUE;plugin.api.pVirtualChannelWriteEx=capture_write;
    BYTE request[CALFILE_REQUEST]={0};cf_put32(request,CALFILE_MAGIC);cf_put32(request+4,1);
    memcpy(request+8,fileOffer+18,16);cf_put32(request+36,4);
    unsigned before=fileReads;channelReplySize=0;
    file_channel_event(&plugin,0,CHANNEL_EVENT_DATA_RECEIVED,request,7,sizeof(request),CHANNEL_FLAG_FIRST);
    assert(!channelReplySize && fileReads==before);
    file_channel_event(&plugin,0,CHANNEL_EVENT_DATA_RECEIVED,request+7,sizeof(request)-7,sizeof(request),CHANNEL_FLAG_LAST);
    assert(channelReplySize==20 && !cf_u32(channelReply+8) && !memcmp(channelReply+16,"test",4) && plugin.pending==0);
    // New copies invalidate old capability tokens, and disabled file permission
    // must refuse even a correctly authenticated session's earlier token.
    request[8]^=1;file_channel_reply(&plugin,request);assert(cf_u32(channelReply+8)==1 && channelReplySize==16);
    request[8]^=1;filesEnabled=0;before=fileReads;file_channel_reply(&plugin,request);
    assert(cf_u32(channelReply+8)==1 && fileReads==before);filesEnabled=1;
    file_offer_refresh();file_channel_reply(&plugin,request);assert(cf_u32(channelReply+8)==1);
    cf_put32(request+36,CALFILE_BLOCK+1);channelReplySize=0;file_channel_reply(&plugin,request);assert(!channelReplySize);
}
static uint32_t testLock;
static uint32_t peerLock;
static UINT peer_lock(CliprdrClientContext *c,const CLIPRDR_LOCK_CLIPBOARD_DATA *r){(void)c;assert(!peerLock);peerLock=r->clipDataId;return 0;}
static UINT peer_unlock(CliprdrClientContext *c,const CLIPRDR_UNLOCK_CLIPBOARD_DATA *r){(void)c;assert(peerLock==r->clipDataId);peerLock=0;return 0;}
static UINT locked_request(CliprdrClientContext *c,const CLIPRDR_FILE_CONTENTS_REQUEST *r){assert(r->haveClipDataId && peerLock && r->clipDataId==peerLock);return file_requested(c,r);}
int probe_file_lock(uint32_t id){testLock=id;return 1;}
void probe_file_unlock(uint32_t id){if(testLock==id)testLock=0;}
void probe_file_unlock_all(void){testLock=0;}
int probe_file_read_locked(uint32_t id,unsigned index,uint64_t offset,uint8_t *data,size_t *length,uint64_t *size){return id && id==testLock && probe_file_read(index,offset,data,length,size);}
static UINT forward_announced(CliprdrClientContext *channel,const CLIPRDR_FORMAT_LIST *list){
    (void)channel;assert(list->numFormats==2 && list->formats[0].formatId==PROBE_FORMAT_FILES);
    assert(!strcmp(list->formats[0].formatName,"FileGroupDescriptorW"));
    assert(list->formats[1].formatId==0xc003 && !strcmp(list->formats[1].formatName,CALFILE_MARKER));return 0;
}
int shell_receive_offer(const uint8_t *data,size_t length,uint64_t generation,uint64_t sequence){
    assert(clip_valid_files(data,length) && generation==clipboard.generation && sequence==clipboard.sequence);offers++;return 1;
}
void shell_receive_invalidate(void){}
void shell_receive_stop(void){}
static BYTE received[4];
static int readOK;
static DWORD WINAPI read_worker(void *arg){(void)arg;readOK=clipboard_shell_read(clipboard.generation,0,0,received,4);return 0;}
static HANDLE start_read(void){
    HANDLE worker=CreateThread(NULL,0,read_worker,NULL,0,NULL);assert(worker);
    BOOL active=FALSE;
    for(unsigned i=0;i<200;i++){EnterCriticalSection(&clipboard.lock);active=shellWire.active;LeaveCriticalSection(&clipboard.lock);if(active)break;Sleep(5);}
    assert(active);return worker;
}
static void finish_read(HANDLE worker){assert(WaitForSingleObject(worker,1500)==WAIT_OBJECT_0);CloseHandle(worker);}
int main(void){
    InitializeCriticalSection(&clipboard.lock);clipboard.initialized=clipboard.ready=TRUE;
    shellWire.done=CreateEventW(NULL,TRUE,FALSE,NULL);shellWire.wake=CreateEventW(NULL,FALSE,FALSE,NULL);filesEnabled=1;clipboard.sequence=nativeSequence;
    CliprdrClientContext channel={0};channel.ClientFormatList=list_sent;channel.ClientFormatListResponse=acknowledged;
    channel.ClientFormatDataRequest=requested;channel.ClientFileContentsRequest=locked_request;clipboard.channel=&channel;
    channel.ClientLockClipboardData=peer_lock;channel.ClientUnlockClipboardData=peer_unlock;
    CLIPRDR_GENERAL_CAPABILITY_SET general={CB_CAPSTYPE_GENERAL,CB_CAPSTYPE_GENERAL_LEN,CB_CAPS_VERSION_2,CB_CAN_LOCK_CLIPDATA};
    CLIPRDR_CAPABILITIES caps={0};caps.cCapabilitiesSets=1;caps.capabilitySets=(CLIPRDR_CAPABILITY_SET*)&general;capabilities(&channel,&caps);
    CLIPRDR_FORMAT format={0xc021,"FileGroupDescriptorW"};CLIPRDR_FORMAT_LIST list={0};list.numFormats=1;list.formats=&format;
    BYTE descriptor[4+CLIP_DESCRIPTOR_SIZE]={0};clip_put32(descriptor,1);clip_put32(descriptor+4,0x44);clip_put32(descriptor+4+68,4);descriptor[4+72]='x';
    format_list(&channel,&list);poll_now();response(&channel,descriptor,sizeof(descriptor));poll_now();
    assert(offers==1 && fileRequests==0 && fileWrites==0 && !clipboard.fileActive);
    nativeReadResult=3;nativeSequence++;poll_now();assert(announcements==0 && shellWire.allowed==clipboard.generation);
    HANDLE worker=start_read();poll_now();assert(fileRequests==1);
    CLIPRDR_FILE_CONTENTS_RESPONSE r={0};r.common.msgFlags=CB_RESPONSE_OK;r.streamId=shellWire.stream;r.cbRequested=4;r.requestedData=(BYTE*)"test";
    file_response(&channel,&r);finish_read(worker);assert(readOK && !memcmp(received,"test",4));
    // Cancel unblocks a stalled response immediately; a late response cannot write.
    worker=start_read();poll_now();r.streamId=shellWire.stream;clipboard_shell_cancel(clipboard.generation);finish_read(worker);assert(!readOK);
    memset(received,0,sizeof(received));file_response(&channel,&r);assert(received[0]==0);
    assert(!clipboard_shell_read(clipboard.generation,0,0,received,4));
    // A fresh copy gets a fresh generation; replacing it revokes the old stream.
    format_list(&channel,&list);poll_now();response(&channel,descriptor,sizeof(descriptor));poll_now();assert(offers==2);
    worker=start_read();poll_now();format_list(&channel,&list);finish_read(worker);assert(!readOK);
    poll_now();response(&channel,descriptor,sizeof(descriptor));poll_now();
    worker=start_read();poll_now();ChannelDisconnectedEventArgs event={0};event.name=CLIPRDR_SVC_CHANNEL_NAME;
    channel_disconnected(NULL,&event);finish_read(worker);assert(!readOK);
    // Forward files advertise RDP descriptors plus a UI marker, never an agent batch.
    _putenv("CALABI_RDP_FILE_STREAM=1");nativeReadResult=0;nativeFormat=PROBE_FORMAT_FILES;nativeSequence++;
    memcpy(nativeText,descriptor,sizeof(descriptor));nativeLength=sizeof(descriptor);
    clipboard.channel=&channel;clipboard.ready=TRUE;channel.ClientFormatList=forward_announced;
    channel.ClientFormatDataResponse=responded;channel.ClientFileContentsResponse=file_responded;
    poll_now();
    CLIPRDR_FORMAT_DATA_REQUEST marker={0};marker.requestedFormatId=0xc003;data_request(&channel,&marker);assert(lastFlags==CB_RESPONSE_OK && lastLength==CALFILE_MARKER_SIZE);
    check_forward_transport();
    CLIPRDR_FORMAT owned={0xc004,"CalabiRdpCopyOwnedV1"};list.formats=&owned;format_list(&channel,&list);
    CLIPRDR_FILE_CONTENTS_REQUEST get={0};get.dwFlags=FILECONTENTS_RANGE;get.cbRequested=4;
    file_request(&channel,&get);assert(lastFlags==CB_RESPONSE_OK && lastLength==4 && fileReads>0);
    CLIPRDR_LOCK_CLIPBOARD_DATA lock={0};lock.clipDataId=77;lock_files(&channel,&lock);
    clipboard.localFormat=PROBE_FORMAT_TEXT;get.haveClipDataId=TRUE;get.clipDataId=77;
    file_request(&channel,&get);assert(lastFlags==CB_RESPONSE_OK && lastLength==4);
    CLIPRDR_UNLOCK_CLIPBOARD_DATA unlock={0};unlock.clipDataId=77;unlock_files(&channel,&unlock);
    file_request(&channel,&get);assert(lastFlags==CB_RESPONSE_FAIL);
    filesEnabled=0;file_request(&channel,&get);assert(lastFlags==CB_RESPONSE_FAIL);
    _putenv("CALABI_RDP_FILE_STREAM=");
    clipboard_stop();puts("Windows RDP channel: reverse cancellation/stale/disconnect and forward marker/owned clipboard/file gate/locked source passed");return 0;
}
