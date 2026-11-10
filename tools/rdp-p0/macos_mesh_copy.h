#pragma once
// AppKit adapter only. Credentials, file handles and mesh TLS remain in the
// ordinary user's Go agent. No file data uses an RDP virtual channel.
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <stdatomic.h>
#include "macos_mesh_errors.h"
static atomic_bool macMeshLive;
static dispatch_queue_t macMeshQueue;
static NSLock *macMeshPipe;
static NSString *const macMeshOwned=@"net.calabi.mesh-file-offer";
static void mac_mesh_note(NSString *message){
    const char *path=getenv("CALABI_RDP_MESH_LOG");
    FILE *log=path?fopen(path,"a"):NULL;
    if(log){fprintf(log,"%.3f %s\n",NSDate.date.timeIntervalSince1970,message.UTF8String);fclose(log);}
}
#ifdef CALABI_MAC_MESH_TEST
static NSString *mac_mesh_test_rpc(NSString *request);
#endif
static NSString *mac_mesh_rpc(NSString *request) {
#ifdef CALABI_MAC_MESH_TEST
    return mac_mesh_test_rpc(request);
#endif
    [macMeshPipe lock];
    NSString *reply=@"error";
    if(atomic_load(&macMeshLive)) {
        fprintf(stdout,"rdp-mesh %s\n",request.UTF8String);fflush(stdout);
        // The parent always answers a complete line. getline uses stdio's
        // buffered bytes; polling mid-line would miss bytes buffered by fgets.
        char *line=NULL;size_t capacity=0;
        if(getline(&line,&capacity,stdin)>0 && strlen(line)<200000)
            reply=[[NSString stringWithUTF8String:line] stringByTrimmingCharactersInSet:NSCharacterSet.newlineCharacterSet] ?: @"error";
        free(line);
    }
    [macMeshPipe unlock];return reply;
}
static NSString *mac_mesh_hex(NSData *data) {
    const uint8_t *p=data.bytes;NSMutableString *s=[NSMutableString stringWithCapacity:data.length*2];
    for(NSUInteger i=0;i<data.length;i++)[s appendFormat:@"%02x",p[i]];return s;
}
static NSData *mac_mesh_unhex(NSString *text) {
    if(text.length%2 || text.length>131072)return nil;
    NSMutableData *d=[NSMutableData dataWithLength:text.length/2];uint8_t *p=d.mutableBytes;
    for(NSUInteger i=0;i<d.length;i++){
        unsigned value=0;
        for(unsigned j=0;j<2;j++){unichar c=[text characterAtIndex:i*2+j];unsigned n=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:16;if(n>15)return nil;value=value*16+n;}
        p[i]=(uint8_t)value;
    }return d;
}
static NSString *mac_mesh_size(uint64_t n) {
    if(n<1024)return [NSString stringWithFormat:@"%llu B",(unsigned long long)n];
    if(n<1048576)return [NSString stringWithFormat:@"%.1f KiB",n/1024.0];
    if(n<1073741824)return [NSString stringWithFormat:@"%.1f MiB",n/1048576.0];
    return [NSString stringWithFormat:@"%.1f GiB",n/1073741824.0];
}
@interface CalabiMeshReceive : NSObject
@property(copy) NSString *offer;
@property(copy) NSArray<NSString *> *names;
@property(copy) NSArray<NSNumber *> *sizes;
@property(strong) NSMutableArray<NSNumber *> *received;
@property(strong) NSMutableDictionary<NSString*, NSArray<NSNumber*>*> *partials;
@property(strong) NSOperationQueue *queue;
@property(strong) NSPanel *panel;
@property(copy) NSString *progressScreenNumber;
@property(strong) NSMutableIndexSet *touched;
@property NSUInteger currentIndex;
@property(strong) NSError *failure;
@property(strong) NSError *interruption;
@property BOOL uiHidden;
@property(readonly) BOOL cancelled;
@property BOOL ready;
@property BOOL finished;
@property BOOL directStarted;
@property int destinationFD;
@property(copy) NSString *temporaryName;
@property(copy) NSArray<NSNumber*> *temporaryIdentity;
@property(copy) NSString *cacheRoot;
@property(strong) NSPasteboard *board;
@property NSInteger expectedSequence;
- (NSError *)writeFile:(NSUInteger)index toURL:(NSURL *)url;
- (BOOL)publishReadyURLs:(NSArray<NSURL*>*)urls;
- (void)receiveToCache;
@property uint64_t total;
- (void)cancelReceive:(id)sender;
- (void)hideProgress;
- (void)positionProgressPanel;
- (void)interruptReceive:(NSError *)error;
- (NSError *)receiveInterruption;
@end
@interface CalabiMeshReceive (FinderReceive)
- (void)receiveToDirectoryFD:(int)directory;
@end
static NSData *mac_mesh_read_chunk(CalabiMeshReceive *batch, NSUInteger index, uint64_t offset, NSUInteger count, NSError **error){
    while(!(*error=[batch receiveInterruption])){
        NSString *reply=mac_mesh_rpc([NSString stringWithFormat:@"mesh_read %@ %lu %llu %lu",
            batch.offer,(unsigned long)index,(unsigned long long)offset,(unsigned long)count]);
        *error=[batch receiveInterruption];
        if([reply isEqualToString:@"wait"]){
            if(*error)break;
            [NSThread sleepForTimeInterval:0.025];continue;
        }
        NSData *data=[reply hasPrefix:@"data "]?mac_mesh_unhex([reply substringFromIndex:5]):nil;
        if(data.length!=count && !mac_mesh_is_user_cancelled(*error))
            *error=mac_mesh_read_error(reply) ?: *error ?: mac_mesh_error(MacMeshReadFailed);
        return *error?nil:data;
    }
    return nil;
}
static CalabiMeshReceive *macMeshIncoming;
static CalabiMeshReceive *macMeshProgressBatch;
static NSString *macMeshCancelledOffer;
static NSMutableSet<CalabiMeshReceive*> *macMeshActive;
static NSMutableSet<CalabiMeshReceive*> *macMeshCaches;
static uint64_t macMeshCacheBytes;
static NSInteger macMeshPublished=-1;
#include "macos_mesh_progress.h"
@implementation CalabiMeshReceive
- (instancetype)init {
    if((self=[super init])){self.destinationFD=-1;self.queue=[[NSOperationQueue alloc] init];self.queue.maxConcurrentOperationCount=1;self.received=[NSMutableArray array];self.partials=[NSMutableDictionary dictionary];self.touched=[NSMutableIndexSet indexSet];}return self;
}
- (void)cancelReceive:(id)sender {
    (void)sender;if(self.finished){[self hideProgress];return;}
    [self interruptReceive:mac_mesh_user_cancelled()];
    if(!self.cancelled)return;
    macMeshCancelledOffer=self.offer;
    self.panel.contentView.needsDisplay=YES;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{mac_mesh_rpc([@"mesh_cancel " stringByAppendingString:self.offer]);});
}
- (void)hideProgress {
    self.uiHidden=YES;
    [self.panel orderOut:nil];
    if(macMeshProgressBatch==self)macMeshProgressBatch=nil;
}
- (void)interruptReceive:(NSError *)error {
    @synchronized(self){if(!self.interruption)self.interruption=error;}
}
- (NSError *)receiveInterruption {
    return self.interruption ?: (atomic_load(&macMeshLive)?nil:mac_mesh_error(MacMeshSessionEnded));
}
- (BOOL)cancelled {
    return mac_mesh_is_user_cancelled(self.finished?self.failure:(self.failure ?: self.interruption));
}
- (void)positionProgressPanel {
    NSArray<NSScreen *> *screens=NSScreen.screens;
    NSScreen *pointerScreen=nil,*target=nil;
    NSPoint pointer=NSEvent.mouseLocation;
    for(NSScreen *screen in screens){
        if([self.progressScreenNumber isEqualToString:[screen.deviceDescription[@"NSScreenNumber"] stringValue]]){
            target=screen;
            break;
        }
        if(NSPointInRect(pointer,screen.frame))pointerScreen=screen;
    }
    target=target ?: pointerScreen ?: NSScreen.mainScreen ?: sessionWindow.screen ?: screens.firstObject;
    if(!target)return;
    NSRect area=target.visibleFrame,frame=self.panel.frame;
    [self.panel setFrameOrigin:NSMakePoint(MAX(NSMinX(area),NSMaxX(area)-NSWidth(frame)-80),
        MAX(NSMinY(area),MIN(NSMinY(area)+24,NSMaxY(area)-NSHeight(frame))))];
}
- (void)showIndex:(NSUInteger)index done:(uint64_t)done error:(NSError *)error {
#ifdef CALABI_MAC_MESH_TEST
    return;
#endif
    void (^update)(void)=^{
        if(index>=self.names.count)return;
        if(!self.panel){
            NSLog(@"MESH_PROGRESS_COMPACT_V2");
            self.panel=[[NSPanel alloc] initWithContentRect:NSMakeRect(0,0,420,271.25)
                styleMask:NSWindowStyleMaskBorderless|NSWindowStyleMaskNonactivatingPanel backing:NSBackingStoreBuffered defer:NO];
            self.panel.title=[@"Calabi · " stringByAppendingString:RDP_NS(ReceiveTitle)];self.panel.releasedWhenClosed=NO;self.panel.level=NSFloatingWindowLevel;
            self.panel.hidesOnDeactivate=NO;self.panel.hasShadow=YES;
            self.panel.collectionBehavior=NSWindowCollectionBehaviorCanJoinAllSpaces|NSWindowCollectionBehaviorFullScreenAuxiliary;
            CalabiMeshProgressView *view=[[CalabiMeshProgressView alloc] initWithFrame:NSMakeRect(0,0,420,271.25)];
            view.autoresizingMask=NSViewWidthSizable|NSViewHeightSizable;view.batch=self;self.panel.contentView=view;
            [self positionProgressPanel];
        }
        self.currentIndex=index;self.received[index]=@(MIN(done,self.sizes[index].unsignedLongLongValue));
        [self.touched addIndex:index];if(error)self.failure=error;
        self.panel.contentView.needsDisplay=YES;
        if(!self.uiHidden){
            if(macMeshProgressBatch!=self){[macMeshProgressBatch hideProgress];macMeshProgressBatch=self;}
            [self.panel orderFrontRegardless];
        }
    };
    if(NSThread.isMainThread)update();else dispatch_async(dispatch_get_main_queue(),update);
}

- (NSError *)writeFile:(NSUInteger)index toURL:(NSURL *)url {
    uint64_t size=self.sizes[index].unsignedLongLongValue,offset=0;
    NSError *error=nil;int fd=-1;struct stat created={};BOOL owns=NO;
    @synchronized(CalabiMeshReceive.class){if(!macMeshActive)macMeshActive=[NSMutableSet set];[macMeshActive addObject:self];}
    [self showIndex:index done:0 error:nil];
    error=[self receiveInterruption];
    if(!error && !url.isFileURL)error=mac_mesh_error(MacMeshDestinationUnavailable);
    if(!error){fd=open(url.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(fd<0)error=[NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];else {owns=fstat(fd,&created)==0;if(!owns)error=[NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];}}
    if(owns){@synchronized(self){self.partials[url.path]=@[@((uint64_t)created.st_dev),@((uint64_t)created.st_ino)];}}
    while(!error && offset<size){
        NSUInteger count=(NSUInteger)MIN(65536,size-offset);
        NSData *data=mac_mesh_read_chunk(self,index,offset,count,&error);if(error)break;
        const uint8_t *p=data.bytes;NSUInteger written=0;
        while(written<count){ssize_t n=write(fd,p+written,count-written);if(n<0 && errno==EINTR)continue;if(n<=0){error=[NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];break;}written+=(NSUInteger)n;}
        offset+=written;[self showIndex:index done:offset error:nil];
    }
    if(!error)error=[self receiveInterruption];
    if(fd>=0){if(!error && fsync(fd))error=[NSError errorWithDomain:NSPOSIXErrorDomain code:errno userInfo:nil];close(fd);}
    if(error && owns){struct stat now;if(!lstat(url.fileSystemRepresentation,&now) && now.st_dev==created.st_dev && now.st_ino==created.st_ino)unlink(url.fileSystemRepresentation);}
    @synchronized(self){[self.partials removeObjectForKey:url.path];}
    [self showIndex:index done:offset error:error];
    @synchronized(CalabiMeshReceive.class){[macMeshActive removeObject:self];}
    return error;
}
// Called on the main thread. Never replace a newer user clipboard selection.
- (BOOL)publishReadyURLs:(NSArray<NSURL*>*)urls {
    if([self receiveInterruption] || self.board.changeCount!=self.expectedSequence)return NO;
    NSMutableArray *items=[NSMutableArray array];
    for(NSURL *url in urls){
        NSPasteboardItem *item=[[NSPasteboardItem alloc] init];
        [item setString:url.absoluteString forType:NSPasteboardTypeFileURL];
        [item setString:self.offer forType:macMeshOwned];[items addObject:item];
    }
    [self.board clearContents];BOOL ok=[self.board writeObjects:items];
    if(ok){self.expectedSequence=self.board.changeCount;if(self.board==NSPasteboard.generalPasteboard)macMeshPublished=self.expectedSequence;self.ready=YES;}
    return ok;
}
- (void)receiveToCache {
    NSMutableArray<NSURL*> *urls=[NSMutableArray array];NSError *error=nil;
    for(NSUInteger i=0;i<self.names.count;i++){
        NSURL *url=[NSURL fileURLWithPath:[self.cacheRoot stringByAppendingPathComponent:self.names[i]]];
        error=[self writeFile:i toURL:url];if(error)break;[urls addObject:url];
    }
    dispatch_async(dispatch_get_main_queue(),^{
        NSError *failure=error;
        if(!failure && ![self publishReadyURLs:urls])failure=[self receiveInterruption] ?: mac_mesh_error(MacMeshOfferExpired);
        self.failure=failure;self.finished=YES;
        if(failure){
            [[NSFileManager defaultManager] removeItemAtPath:self.cacheRoot error:NULL];
            @synchronized(CalabiMeshReceive.class){if([macMeshCaches containsObject:self]){macMeshCacheBytes-=self.total;[macMeshCaches removeObject:self];}}
            if(self.board.changeCount==self.expectedSequence)[self.board clearContents];
        }
        [self showIndex:MIN(urls.count,self.names.count-1) done:failure?0:self.sizes.lastObject.unsignedLongLongValue error:failure];
    });
}

@end
#include "macos_finder_receive.h"
#ifndef CALABI_MAC_MESH_TEST
#include "macos_fileprovider_bridge.h"
#endif
static void mac_mesh_revoke(MacMeshReceiveError reason){
    if(macMeshIncoming){mac_mesh_note(@"offer_revoked");[macMeshIncoming interruptReceive:mac_mesh_error(reason)];}
    NSPasteboard *board=NSPasteboard.generalPasteboard;
    if(macMeshPublished>=0 && board.changeCount==macMeshPublished)[board clearContents];
    macMeshPublished=-1;macMeshIncoming=nil;
}
static BOOL mac_mesh_publish(NSString *offer,NSData *manifest){
    if(!clip_valid_files(manifest.bytes,manifest.length)){mac_mesh_note(@"offer_rejected invalid_manifest");return NO;}
    const uint8_t *p=manifest.bytes;NSMutableArray *names=[NSMutableArray array],*sizes=[NSMutableArray array];NSMutableSet *seen=[NSMutableSet set];
    for(unsigned i=0;i<clip_u32(p);i++){
        const uint8_t *d=p+4+i*CLIP_DESCRIPTOR_SIZE;NSUInteger n=0;while(n<260 && (d[72+n*2]||d[73+n*2]))n++;
        NSString *name=[[NSString alloc] initWithBytes:d+72 length:n*2 encoding:NSUTF16LittleEndianStringEncoding];
        if(!name.length || [name isEqualToString:@"."] || [name isEqualToString:@".."] || [name rangeOfCharacterFromSet:[NSCharacterSet characterSetWithCharactersInString:@"/:"]].location!=NSNotFound || [seen containsObject:name.lowercaseString])return NO;
        [seen addObject:name.lowercaseString];[names addObject:name];[sizes addObject:@(clip_file_size(d))];
    }
    mac_mesh_revoke(MacMeshOfferExpired);CalabiMeshReceive *batch=[[CalabiMeshReceive alloc] init];batch.offer=offer;batch.names=names;batch.sizes=sizes;
    for(NSNumber *size in sizes){batch.total+=size.unsignedLongLongValue;[batch.received addObject:@0];}
#ifndef CALABI_MAC_MESH_TEST
    if(macFPListener<0){mac_mesh_note(@"offer_rejected menu_bridge_unavailable");show_transfer_status(RDP_NS(CopyNotReady),RDP_NS(FinderSetupHint),0,NO,NO);return NO;}
    batch.board=NSPasteboard.generalPasteboard;
    NSPasteboardItem *marker=[NSPasteboardItem new];
    [marker setString:offer forType:macMeshOwned];
    [marker setString:[NSString stringWithUTF8String:rdp_locale_codes[rdp_locale_current()]] forType:RDP_PASTEBOARD_LOCALE];
    [batch.board clearContents];
    if(![batch.board writeObjects:@[marker]]){mac_mesh_note(@"offer_rejected marker_write_failed");return NO;}
    batch.expectedSequence=batch.board.changeCount;macMeshPublished=batch.expectedSequence;
    macMeshIncoming=batch;mac_mesh_note([NSString stringWithFormat:@"offer_marker_written files=%lu",(unsigned long)names.count]);
    NSLog(@"FINDER_MENU_OFFER_READY files=%lu",(unsigned long)names.count);return YES;
#else
    @synchronized(CalabiMeshReceive.class){
        if(macMeshCaches.count>=64 || macMeshCacheBytes+batch.total>256u*1024u*1024u){show_transfer_status(RDP_NS(ReceiveNotStarted),RDP_NS(TemporaryLimit),0,NO,NO);return NO;}
    }
    NSString *pattern=[NSTemporaryDirectory() stringByAppendingPathComponent:@"calabi-mesh-copy-XXXXXX"];
    char *temporary=strdup(pattern.fileSystemRepresentation);char *created=temporary?mkdtemp(temporary):NULL;
    if(created)batch.cacheRoot=[[NSFileManager defaultManager] stringWithFileSystemRepresentation:created length:strlen(created)];free(temporary);
    if(!batch.cacheRoot){show_transfer_status(RDP_NS(ReceiveNotStarted),RDP_NS(TemporaryWriteFailed),0,NO,NO);return NO;}
    @synchronized(CalabiMeshReceive.class){if(!macMeshCaches)macMeshCaches=[NSMutableSet set];[macMeshCaches addObject:batch];macMeshCacheBytes+=batch.total;}
    batch.board=NSPasteboard.generalPasteboard;
    [batch.board clearContents];[batch.board setString:offer forType:macMeshOwned];
    batch.expectedSequence=batch.board.changeCount;macMeshPublished=batch.expectedSequence;macMeshIncoming=batch;
    [batch showIndex:0 done:0 error:nil];
    [batch.queue addOperationWithBlock:^{@autoreleasepool{[batch receiveToCache];}}];return YES;
#endif
}
void mac_mesh_start(void){
    if(!getenv("CALABI_RDP_FILE_MESH") || !clipboardFilesEnabled || atomic_exchange(&macMeshLive,true))return;
    mac_mesh_note(@"RDP_MENU_MARKER_V2 start");
    if(!macMeshPipe)macMeshPipe=[[NSLock alloc] init];
#ifndef CALABI_MAC_MESH_TEST
    BOOL startMenu=YES;
#ifdef CALABI_REMOTE_WORKSPACE
    startMenu=!probe_workspace_enabled();
#endif
    BOOL menuReady=!startMenu || mac_fp_start();
    if(startMenu)mac_mesh_note(menuReady?@"menu_bridge_ready":@"menu_bridge_unavailable");
    if(!menuReady)dispatch_async(dispatch_get_main_queue(),^{show_transfer_status(RDP_NS(FileComponentFailed),RDP_NS(FinderSetupHint),0,NO,NO);});
#endif
    macMeshQueue=dispatch_queue_create("net.calabi.mesh-clipboard",DISPATCH_QUEUE_SERIAL);
    dispatch_async(macMeshQueue,^{@autoreleasepool {
        __block NSInteger sequence=-1;
        NSString *offer=nil,*lastObservedOffer=nil;
        NSString *session=nil,*previousState=nil;
        NSTimeInterval nextOfferAttempt=0;
#ifdef CALABI_REMOTE_WORKSPACE
        unsigned selected=0;
        NSTimeInterval nextMenuAttempt=0;
#endif
        while(atomic_load(&macMeshLive)){
            @autoreleasepool {
                NSTimeInterval now=NSProcessInfo.processInfo.systemUptime;
#ifdef CALABI_REMOTE_WORKSPACE
                if(!probe_workspace_active()){
                    if(selected)dispatch_sync(dispatch_get_main_queue(),^{mac_mesh_revoke(MacMeshSessionEnded);});
                    if(macFPHost)mac_fp_stop();
                    offer=lastObservedOffer=nil;selected=0;nextMenuAttempt=nextOfferAttempt=0;
                    [NSThread sleepForTimeInterval:0.2];
                    continue;
                }
                BOOL newSelection=probe_workspace_selection()!=selected;
                if(newSelection)selected=probe_workspace_selection();
                if(probe_workspace_enabled() && !macFPHost.running && now>=nextMenuAttempt){
                    nextMenuAttempt=now+1.5;
                    if(macFPHost)mac_fp_stop();
                    BOOL ready=mac_fp_start();
                    mac_mesh_note(ready?@"menu_bridge_ready":@"menu_bridge_unavailable");
                    if(ready)nextOfferAttempt=0;
                }
#endif
                NSString *reply=mac_mesh_rpc(@"mesh_state");NSArray *f=[reply componentsSeparatedByString:@" "];
                BOOL state=f.count==6 && [f[0] isEqualToString:@"state"];
                NSString *status=state?([f[2] isEqualToString:@"0"]?([f[4] isEqual:@"-"]?@"controller_idle":@"controller_offer"):@"host"):
                    ([reply isEqual:@"none"]?@"no_session":[reply isEqual:@"error"]?@"rpc_error":@"invalid_reply");
                if(![status isEqual:previousState]){mac_mesh_note([@"mesh_state " stringByAppendingString:status]);previousState=status;}
                if(state && [f[2] isEqualToString:@"0"]){
                    if(![session isEqualToString:f[1]]){
                        if(session)dispatch_sync(dispatch_get_main_queue(),^{mac_mesh_revoke(MacMeshSessionEnded);});
                        session=f[1];offer=lastObservedOffer=nil;sequence=-1;nextOfferAttempt=0;
                    }
                    __block NSData *paths=nil;__block BOOL changed=NO;
                    dispatch_sync(dispatch_get_main_queue(),^{
                        NSPasteboard *board=NSPasteboard.generalPasteboard;
#ifdef CALABI_REMOTE_WORKSPACE
                        if(!probe_workspace_active())return;
                        if(newSelection){sequence=board.changeCount;return;}
#endif
                        if(board.changeCount==sequence)return;
                        sequence=board.changeCount;
                        if([board.types containsObject:macMeshOwned])return;
                        if(macMeshIncoming && !macMeshIncoming.ready && !macMeshIncoming.interruption){
                            mac_mesh_note(@"offer_marker_replaced");[macMeshIncoming interruptReceive:mac_mesh_error(MacMeshOfferExpired)];
                        }
                        changed=YES;NSArray<NSURL*> *urls=[board readObjectsForClasses:@[NSURL.class] options:@{NSPasteboardURLReadingFileURLsOnlyKey:@YES}];
                        if(urls.count && urls.count<=32){NSMutableData *data=[NSMutableData data];for(NSURL *url in urls){NSData *part=[url.path dataUsingEncoding:NSUTF8StringEncoding];[data appendData:part];uint8_t zero=0;[data appendBytes:&zero length:1];}if(data.length<=8192)paths=data;}
                    });
                    if(changed){NSString *answer=mac_mesh_rpc(paths?[NSString stringWithFormat:@"mesh_offer %@ %@",session,mac_mesh_hex(paths)]:[@"mesh_clear " stringByAppendingString:session]);
                        if(paths && ![answer isEqualToString:@"ok"])dispatch_async(dispatch_get_main_queue(),^{show_transfer_status(RDP_NS(CopyNotReady),RDP_NS(CopySelectionHint),0,NO,NO);});}
                    NSString *candidate=f[4];
                    BOOL idle=[candidate isEqualToString:@"-"];
                    if(![lastObservedOffer isEqualToString:candidate]){
                        lastObservedOffer=candidate;nextOfferAttempt=0;
                    }else if(changed && !idle){
                        // A newer local clipboard supersedes a pending remote offer.
                        offer=candidate;
                    }
                    if(![offer isEqualToString:candidate] && (idle || now>=nextOfferAttempt)){
                        NSData *manifest=idle?nil:mac_mesh_unhex(f[5]);
                        __block BOOL published=NO;
                        dispatch_sync(dispatch_get_main_queue(),^{
#ifdef CALABI_REMOTE_WORKSPACE
                            if(!probe_workspace_active())return;
                            if(!idle && probe_workspace_enabled() && (!macFPHost.running || macFPListener<0))return;
#endif
                            if(idle){
                                mac_mesh_revoke(MacMeshOfferExpired);
                                published=YES;
                            }else published=mac_mesh_publish(candidate,manifest);
                            if(published)sequence=NSPasteboard.generalPasteboard.changeCount;
                        });
                        // Keep the offer pending if the Finder bridge was not ready.
                        if(published){offer=candidate;nextOfferAttempt=0;}
                        else nextOfferAttempt=now+1;
                    }
                }else if(session){
                    MacMeshReceiveError reason=state || [reply isEqualToString:@"none"]?MacMeshSessionEnded:MacMeshReadFailed;
                    session=nil;offer=lastObservedOffer=nil;dispatch_sync(dispatch_get_main_queue(),^{mac_mesh_revoke(reason);});
                }
            }
            [NSThread sleepForTimeInterval:0.2];
        }
    }});
}
void mac_mesh_stop(void){
    if(!atomic_exchange(&macMeshLive,false))return;
    dispatch_sync(macMeshQueue,^{});
#ifndef CALABI_MAC_MESH_TEST
    mac_fp_stop();
#endif
    [macMeshPipe lock];[macMeshPipe unlock];
    dispatch_async(dispatch_get_main_queue(),^{mac_mesh_revoke(MacMeshSessionEnded);});
}

void mac_mesh_cancel_files(void){
    if(!atomic_load(&macMeshLive)){clipboard_cancel_files();return;}
    dispatch_async(dispatch_get_main_queue(),^{[macMeshIncoming cancelReceive:nil];});
}
static void mac_mesh_exit_cleanup(void){
    atomic_store(&macMeshLive,false);
    // The RDP worker owns the bridge. If the process is forced out before
    // the worker finishes, the menu host exits when its parent disappears.
    @autoreleasepool {
        NSArray *batches;@synchronized(CalabiMeshReceive.class){batches=macMeshActive.allObjects;}
        for(CalabiMeshReceive *batch in batches){@synchronized(batch){
            [batch interruptReceive:mac_mesh_error(MacMeshSessionEnded)];
            if(batch.destinationFD>=0 && batch.temporaryName && batch.temporaryIdentity){struct stat now;
                if(!fstatat(batch.destinationFD,batch.temporaryName.fileSystemRepresentation,&now,AT_SYMLINK_NOFOLLOW) &&
                    (uint64_t)now.st_dev==batch.temporaryIdentity[0].unsignedLongLongValue && (uint64_t)now.st_ino==batch.temporaryIdentity[1].unsignedLongLongValue)
                    unlinkat(batch.destinationFD,batch.temporaryName.fileSystemRepresentation,0);
            }
            for(NSString *path in batch.partials){
                NSArray<NSNumber*> *identity=batch.partials[path];struct stat st;
                if(!lstat(path.fileSystemRepresentation,&st) && (uint64_t)st.st_dev==identity[0].unsignedLongLongValue && (uint64_t)st.st_ino==identity[1].unsignedLongLongValue)unlink(path.fileSystemRepresentation);
            }
        }
        }
        @synchronized(CalabiMeshReceive.class){for(CalabiMeshReceive *cached in macMeshCaches)[[NSFileManager defaultManager] removeItemAtPath:cached.cacheRoot error:NULL];[macMeshCaches removeAllObjects];macMeshCacheBytes=0;}
        NSPasteboard *board=NSPasteboard.generalPasteboard;
        if(macMeshPublished>=0 && board.changeCount==macMeshPublished)[board clearContents];
    }
}
