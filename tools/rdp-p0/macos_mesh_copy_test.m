// Named pasteboard and private temporary files only. No network/user clipboard.
#import <AppKit/AppKit.h>
#include <assert.h>
static __weak NSWindow *sessionWindow;
void clipboard_cancel_files(void) {}
#define CALABI_MAC_MESH_TEST
#include "macos_clipboard.h"
#include "macos_mesh_copy.h"
static unsigned reads;
static BOOL failRead;
static BOOL failSecond,disconnectAfterRead;
static NSString *readFailure;
static CalabiMeshReceive *cancelOnRead;
static NSString *mac_mesh_test_rpc(NSString *request){
    if(![request hasPrefix:@"mesh_read "])return @"ok";
    reads++;if(failRead)return @"error";
    if(cancelOnRead)[cancelOnRead interruptReceive:mac_mesh_user_cancelled()];
    NSArray *parts=[request componentsSeparatedByString:@" "];
    if(failSecond && [parts[2] integerValue]==1)return @"error";
    if(disconnectAfterRead)atomic_store(&macMeshLive,false);
    if(readFailure)return readFailure;
    NSUInteger offset=[parts[3] integerValue],count=[parts[4] integerValue];
    NSMutableData *data=[NSMutableData dataWithLength:count];uint8_t *p=data.mutableBytes;
    for(NSUInteger i=0;i<count;i++)p[i]=(offset+i)%251;
    return [@"data " stringByAppendingString:mac_mesh_hex(data)];
}
static CalabiMeshReceive *fixture(uint64_t size){
    CalabiMeshReceive *b=[[CalabiMeshReceive alloc] init];b.offer=@"test";b.names=@[@"中文.bin"];b.sizes=@[@(size)];b.total=size;[b.received addObject:@0];return b;
}
static void finish(CalabiMeshReceive *batch){
    NSDate *limit=[NSDate dateWithTimeIntervalSinceNow:5];
    while(!batch.finished && limit.timeIntervalSinceNow>0)[NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    assert(batch.finished);
}
static void prepare(CalabiMeshReceive *b,NSPasteboard *board,NSString *parent){
    b.cacheRoot=[parent stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
    assert([[NSFileManager defaultManager] createDirectoryAtPath:b.cacheRoot withIntermediateDirectories:NO attributes:@{NSFilePosixPermissions:@0700} error:NULL]);
    b.board=board;[board clearContents];[board setString:b.offer forType:macMeshOwned];b.expectedSequence=board.changeCount;
}
int main(void){@autoreleasepool {
    unsetenv("CALABI_UI_LOCALE_FILE");
    setenv("CALABI_UI_LOCALE","zh-CN",1);
    atomic_store(&macMeshLive,true);macMeshPipe=[[NSLock alloc] init];
    NSString *root=[NSTemporaryDirectory() stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
    assert([[NSFileManager defaultManager] createDirectoryAtPath:root withIntermediateDirectories:YES attributes:nil error:NULL]);
    NSPasteboard *board=[NSPasteboard pasteboardWithUniqueName];
    CalabiMeshReceive *b=fixture(65539);prepare(b,board,root);
    // Exercise the product receive/cache/publish flow, not a Finder promise delegate.
    assert(![board.types containsObject:NSPasteboardTypeFileURL]);
    [b receiveToCache];finish(b);assert(b.ready && reads==2);
    NSArray<NSURL*> *urls=[board readObjectsForClasses:@[NSURL.class] options:@{NSPasteboardURLReadingFileURLsOnlyKey:@YES}];
    assert(urls.count==1 && [board.types containsObject:macMeshOwned]);
    assert(![board.types containsObject:@"com.apple.NSFilePromiseItemMetaData"]);
    NSData *data=[NSData dataWithContentsOfURL:urls[0]];assert(data.length==65539);
    const uint8_t *bytes=data.bytes;for(NSUInteger i=0;i<data.length;i++)assert(bytes[i]==i%251);
    NSError *collision=[b writeFile:0 toURL:urls[0]];assert(collision);
    assert([[NSData dataWithContentsOfURL:urls[0]] isEqualToData:data]);
    // Failure removes the entire private staging directory and publishes no URL.
    b=fixture(5);prepare(b,board,root);failRead=YES;[b receiveToCache];finish(b);
    assert(!b.ready && ![[NSFileManager defaultManager] fileExistsAtPath:b.cacheRoot]);
    assert(![board.types containsObject:NSPasteboardTypeFileURL]);failRead=NO;
    // A newer clipboard selection must survive the completion callback.
    b=fixture(5);prepare(b,board,root);[b receiveToCache];
    [board clearContents];[board setString:@"new user text" forType:NSPasteboardTypeString];finish(b);
    assert(!b.ready && [[board stringForType:NSPasteboardTypeString] isEqualToString:@"new user text"]);
    assert(![[NSFileManager defaultManager] fileExistsAtPath:b.cacheRoot]);
    b=fixture(5);prepare(b,board,root);[b interruptReceive:mac_mesh_user_cancelled()];unsigned previous=reads;
    [b receiveToCache];finish(b);assert(reads==previous && !b.ready);
    assert(![[NSFileManager defaultManager] fileExistsAtPath:b.cacheRoot]);
    b=fixture(0);prepare(b,board,root);[b receiveToCache];finish(b);assert(b.ready);
    urls=[board readObjectsForClasses:@[NSURL.class] options:@{NSPasteboardURLReadingFileURLsOnlyKey:@YES}];
    assert(urls.count==1 && [[NSData dataWithContentsOfURL:urls[0]] length]==0);
    // Multi-file batches publish all URLs together; a later file failure removes earlier files too.
    b=fixture(2);b.names=@[@"a.bin",@"b.bin"];b.sizes=@[@2,@3];b.total=5;[b.received addObject:@0];
    prepare(b,board,root);[b receiveToCache];finish(b);assert(b.ready);
    urls=[board readObjectsForClasses:@[NSURL.class] options:@{NSPasteboardURLReadingFileURLsOnlyKey:@YES}];assert(urls.count==2);
    b=fixture(2);b.names=@[@"a.bin",@"b.bin"];b.sizes=@[@2,@3];b.total=5;[b.received addObject:@0];
    prepare(b,board,root);failSecond=YES;[b receiveToCache];finish(b);failSecond=NO;
    assert(!b.ready && ![[NSFileManager defaultManager] fileExistsAtPath:b.cacheRoot]);
    b=fixture(65539);prepare(b,board,root);disconnectAfterRead=YES;[b receiveToCache];finish(b);
    assert(!b.ready && ![[NSFileManager defaultManager] fileExistsAtPath:b.cacheRoot]);
    atomic_store(&macMeshLive,true);disconnectAfterRead=NO;
    // Product Finder-menu receiver: pin target FD, stream into a hidden partial,
    // commit without replacing existing files; never publish Finder source URLs.
    NSString *target=[root stringByAppendingPathComponent:@"menu-target"];
    assert([[NSFileManager defaultManager] createDirectoryAtPath:target withIntermediateDirectories:NO attributes:nil error:NULL]);
    NSString *existing=[target stringByAppendingPathComponent:@"中文.bin"];
    assert([@"keep" writeToFile:existing atomically:YES encoding:NSUTF8StringEncoding error:NULL]);
    int directory=open(target.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(directory>=0);
    NSString *moved=[root stringByAppendingPathComponent:@"renamed-target"];
    assert([[NSFileManager defaultManager] moveItemAtPath:target toPath:moved error:NULL]);
    b=fixture(65539);b.destinationFD=directory;[b receiveToDirectoryFD:directory];finish(b);
    assert(!b.failure && b.destinationFD==-1);
    assert([[NSString stringWithContentsOfFile:[moved stringByAppendingPathComponent:@"中文.bin"] encoding:NSUTF8StringEncoding error:NULL] isEqual:@"keep"]);
    data=[NSData dataWithContentsOfFile:[moved stringByAppendingPathComponent:@"中文 (1).bin"]];assert(data.length==65539);
    bytes=data.bytes;for(NSUInteger i=0;i<data.length;i++)assert(bytes[i]==i%251);
    // Cancel after read but before write/commit: no final or partial survives.
    b=fixture(65539);cancelOnRead=b;
    directory=open(moved.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(directory>=0);b.destinationFD=directory;
    [b receiveToDirectoryFD:directory];finish(b);cancelOnRead=nil;assert(b.cancelled);
    NSArray *entries=[[NSFileManager defaultManager] contentsOfDirectoryAtPath:moved error:NULL];assert(entries.count==2);
    for(NSString *entry in entries)assert(![entry hasPrefix:@".calabi-receive-"]);
    b=fixture(5);failRead=YES;
    directory=open(moved.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(directory>=0);b.destinationFD=directory;
    [b receiveToDirectoryFD:directory];finish(b);failRead=NO;assert(b.failure && !b.cancelled);
    assert([b.failure.domain isEqual:macMeshErrorDomain] && b.failure.code==MacMeshReadFailed);
    for(NSArray *test in @[
        @[@"error timeout",@(MacMeshReadTimeout),@"网络连接超时"],
        @[@"error session",@(MacMeshSessionEnded),@"文件复制会话已结束"],
        @[@"none",@(MacMeshSessionEnded),@"文件复制会话已结束"],
        @[@"error offer",@(MacMeshOfferExpired),@"远程剪贴板内容已失效"],
        @[@"error source",@(MacMeshSourceChanged),@"源文件已变化"],
    ]){
        b=fixture(5);readFailure=test[0];
        // The current read can return a specific timeout just as the session stops.
        disconnectAfterRead=[readFailure isEqual:@"error timeout"];
        directory=open(moved.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(directory>=0);b.destinationFD=directory;
        [b receiveToDirectoryFD:directory];finish(b);
        assert(!b.cancelled && [b.failure.domain isEqual:macMeshErrorDomain] && b.failure.code==[test[1] integerValue]);
        assert([mac_mesh_failure_detail(b.failure) hasPrefix:test[2]]);
        readFailure=nil;disconnectAfterRead=NO;atomic_store(&macMeshLive,true);
    }
    assert([mac_mesh_failure_detail(mac_mesh_write_error(EACCES)) containsString:@"不可写"]);
    assert([mac_mesh_failure_detail(mac_mesh_write_error(EROFS)) containsString:@"不可写"]);
    assert([mac_mesh_failure_detail(mac_mesh_write_error(ENOSPC)) containsString:@"空间不足"]);
    assert([mac_mesh_failure_detail(mac_mesh_write_error(EDQUOT)) containsString:@"空间不足"]);
    assert([[NSFileManager defaultManager] contentsOfDirectoryAtPath:moved error:NULL].count==2);
    b=fixture(0);
    directory=open(moved.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(directory>=0);b.destinationFD=directory;
    [b receiveToDirectoryFD:directory];finish(b);assert(!b.failure);
    assert([[NSData dataWithContentsOfFile:[moved stringByAppendingPathComponent:@"中文 (2).bin"]] length]==0);
    b=fixture(2);b.names=@[@"first.bin",@"second.bin"];b.sizes=@[@2,@3];b.total=5;[b.received addObject:@0];failSecond=YES;
    directory=open(moved.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(directory>=0);b.destinationFD=directory;
    [b receiveToDirectoryFD:directory];finish(b);failSecond=NO;assert(b.failure);
    assert([[NSData dataWithContentsOfFile:[moved stringByAppendingPathComponent:@"first.bin"]] length]==2);
    assert(![[NSFileManager defaultManager] fileExistsAtPath:[moved stringByAppendingPathComponent:@"second.bin"]]);
    b=fixture(65539);disconnectAfterRead=YES;
    directory=open(moved.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_CLOEXEC);assert(directory>=0);b.destinationFD=directory;
    [b receiveToDirectoryFD:directory];finish(b);disconnectAfterRead=NO;atomic_store(&macMeshLive,true);
    assert(!b.cancelled && [b.failure.domain isEqual:macMeshErrorDomain] && b.failure.code==MacMeshSessionEnded);
    entries=[[NSFileManager defaultManager] contentsOfDirectoryAtPath:moved error:NULL];assert(entries.count==4);
    for(NSString *entry in entries)assert(![entry hasPrefix:@".calabi-receive-"]);
    [board clearContents];[[NSFileManager defaultManager] removeItemAtPath:root error:NULL];[board releaseGlobally];
    puts("macOS mesh fixtures passed: cache and Finder direct receiver, pinned directory, chunks, collision, cancel, failure cleanup, empty file.");
}}
