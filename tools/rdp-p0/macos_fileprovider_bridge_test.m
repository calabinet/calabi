#import <AppKit/AppKit.h>
#include <assert.h>
static __weak NSWindow *sessionWindow;
void clipboard_cancel_files(void) {}
#define CALABI_MAC_MESH_TEST
#include "macos_clipboard.h"
#include "macos_mesh_copy.h"
#include "macos_fileprovider_bridge.h"
static unsigned fixtureReads;
static NSString *mac_mesh_test_rpc(NSString *request){
    if(![request hasPrefix:@"mesh_read "])return @"ok";
    fixtureReads++;
    NSUInteger count=[[[request componentsSeparatedByString:@" "] lastObject] integerValue];
    NSMutableData *data=[NSMutableData dataWithLength:count];memset(data.mutableBytes,0x43,count);
    return [@"data " stringByAppendingString:mac_mesh_hex(data)];
}
int main(void){@autoreleasepool{
    atomic_store(&macMeshLive,true);macFPToken=@"fixture-token";
    CalabiMeshReceive *batch=[CalabiMeshReceive new];batch.offer=@"offer";batch.names=@[@"sample.bin"];batch.sizes=@[@65536];batch.total=65536;[batch.received addObject:@0];macMeshIncoming=batch;
    __block BOOL finished=NO;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{
        assert(![mac_fp_request(@{@"op":@"catalog",@"token":@"wrong"})[@"ok"] boolValue]);
        NSDictionary *catalog=mac_fp_request(@{@"op":@"catalog",@"token":@"fixture-token"});
        assert([catalog[@"ok"] boolValue] && [catalog[@"files"] count]==1 && fixtureReads==0);
        NSMutableDictionary *request=[@{@"op":@"read",@"token":@"fixture-token",@"offer":@"offer",@"index":@0,@"offset":@0,@"count":@65536} mutableCopy];
        NSDictionary *response=mac_fp_request(request);
        NSData *data=[[NSData alloc] initWithBase64EncodedString:response[@"data"] options:0];
        assert([response[@"ok"] boolValue] && data.length==65536 && fixtureReads==1);
        request[@"offset"]=@65536;assert(![mac_fp_request(request)[@"ok"] boolValue]);
        request[@"offset"]=@0;request[@"index"]=@1;assert(![mac_fp_request(request)[@"ok"] boolValue]);
        request[@"index"]=@0;request[@"offer"]=@"stale";assert(![mac_fp_request(request)[@"ok"] boolValue]);
        request[@"offer"]=@"offer";[batch interruptReceive:mac_mesh_user_cancelled()];assert(![mac_fp_request(request)[@"ok"] boolValue]);
        batch.interruption=nil;atomic_store(&macMeshLive,false);assert(![mac_fp_request(request)[@"ok"] boolValue]);
        assert(fixtureReads==1);
        atomic_store(&macMeshLive,true);
        NSString *root=[NSTemporaryDirectory() stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
        assert([[NSFileManager defaultManager] createDirectoryAtPath:root withIntermediateDirectories:NO attributes:nil error:NULL]);
        dispatch_sync(dispatch_get_main_queue(),^{
            batch.board=[NSPasteboard pasteboardWithUniqueName];[batch.board setString:batch.offer forType:macMeshOwned];
            batch.expectedSequence=batch.board.changeCount;batch.directStarted=YES;
        });
        NSDictionary *paste=@{@"op":@"paste",@"token":@"fixture-token",@"offer":@"offer",@"destination":root,@"screen":@"123"};
        assert(![mac_fp_request(paste)[@"ok"] boolValue]); // already receiving
        dispatch_sync(dispatch_get_main_queue(),^{assert(!batch.progressScreenNumber);batch.directStarted=NO;});
        assert(![mac_fp_request(@{@"op":@"paste",@"token":@"wrong",@"offer":@"offer",@"destination":root})[@"ok"] boolValue]);
        assert(![mac_fp_request(@{@"op":@"paste",@"token":@"fixture-token",@"offer":@"stale",@"destination":root})[@"ok"] boolValue]);
        assert(![mac_fp_request(@{@"op":@"paste",@"token":@"fixture-token",@"offer":@"offer",@"destination":@"relative"})[@"ok"] boolValue]);
        NSMutableDictionary *missing=paste.mutableCopy;
        missing[@"destination"]=[root stringByAppendingPathComponent:@"missing"];
        NSDictionary *rejected=mac_fp_request(missing);
        assert(![rejected[@"ok"] boolValue] && [rejected[@"presented"] boolValue]);
        dispatch_sync(dispatch_get_main_queue(),^{
            assert(batch.finished && !batch.cancelled && batch.failure.code==ENOENT);
            assert([batch.progressScreenNumber isEqualToString:@"123"]);
        });
        NSMutableDictionary *legacyPaste=paste.mutableCopy;
        [legacyPaste removeObjectForKey:@"screen"];
        assert([mac_fp_request(legacyPaste)[@"ok"] boolValue]);
        [batch.queue waitUntilAllOperationsAreFinished];
        dispatch_sync(dispatch_get_main_queue(),^{assert(batch.finished && !batch.failure && !batch.progressScreenNumber);});
        NSData *copied=[NSData dataWithContentsOfFile:[root stringByAppendingPathComponent:@"sample.bin"]];
        assert(copied.length==65536 && ((const uint8_t*)copied.bytes)[65535]==0x43 && fixtureReads==2);
        dispatch_sync(dispatch_get_main_queue(),^{
            [batch.board clearContents];[batch.board setString:@"newer clipboard" forType:NSPasteboardTypeString];
        });
        assert(![mac_fp_request(paste)[@"ok"] boolValue]);
        dispatch_sync(dispatch_get_main_queue(),^{[batch.board clearContents];[batch.board releaseGlobally];});
        assert([[NSFileManager defaultManager] removeItemAtPath:root error:NULL]);
        dispatch_async(dispatch_get_main_queue(),^{finished=YES;});
    });
    while(!finished)[NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    puts("Remote menu bridge tests passed: capability, range, stale offer, busy receiver, direct paste, clipboard change");return 0;
}}
