// Standalone Finder experiment. No Calabi session, network, credentials or hooks.
#import <Cocoa/Cocoa.h>
#import <ApplicationServices/ApplicationServices.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>

@interface FinderPasteProbe : NSObject <NSApplicationDelegate, NSWindowDelegate>
@property(strong) NSWindow *window;
@property(strong) NSTextView *output;
@property(strong) NSURL *target;
@property(copy) NSString *name;
@property(strong) NSURL *written;
@property(copy) NSString *controlRoot;
@property(assign) PasteboardRef board;
@property NSInteger mode;
@property NSUInteger callbacks;
@property dev_t targetDevice;
@property ino_t targetInode;
- (void)note:(NSString *)message;
- (OSStatus)fulfill:(PasteboardRef)board item:(PasteboardItemID)item flavor:(CFStringRef)flavor;
@end
static FinderPasteProbe *probe;
static OSStatus promiseCallback(PasteboardRef board, PasteboardItemID item, CFStringRef flavor, void *context) {
    (void)context;
    @autoreleasepool { return [probe fulfill:board item:item flavor:flavor]; }
}
@implementation FinderPasteProbe
- (void)note:(NSString *)message {
    fprintf(stderr,"%s\n",message.UTF8String);fflush(stderr);
    dispatch_async(dispatch_get_main_queue(),^{
        [self.output.textStorage appendAttributedString:[[NSAttributedString alloc] initWithString:[message stringByAppendingString:@"\n"]]];
        [self.output scrollRangeToVisible:NSMakeRange(self.output.string.length,0)];
    });
}
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;
    self.window=[[NSWindow alloc] initWithContentRect:NSMakeRect(0,0,720,400) styleMask:NSWindowStyleMaskTitled|NSWindowStyleMaskClosable backing:NSBackingStoreBuffered defer:NO];
    self.window.title=@"Calabi · Finder 首次粘贴验证（独立实验）";self.window.delegate=self;self.window.releasedWhenClosed=NO;
    NSArray *titles=@[@"1 选择测试目录",@"2 复制承诺 A",@"3 复制承诺 B",@"普通文件对照"];
    SEL actions[]={@selector(choose:),@selector(copyA:),@selector(copyB:),@selector(control:)};
    for(NSUInteger i=0;i<titles.count;i++){
        NSButton *button=[NSButton buttonWithTitle:titles[i] target:self action:actions[i]];
        button.frame=NSMakeRect(16+i*174,350,168,32);[self.window.contentView addSubview:button];
    }
    NSScrollView *scroll=[[NSScrollView alloc] initWithFrame:NSMakeRect(16,16,688,320)];scroll.hasVerticalScroller=YES;
    self.output=[[NSTextView alloc] initWithFrame:scroll.bounds];self.output.editable=NO;self.output.font=[NSFont monospacedSystemFontOfSize:12 weight:NSFontWeightRegular];scroll.documentView=self.output;[self.window.contentView addSubview:scroll];
    [self.window center];[self.window makeKeyAndOrderFront:nil];[NSApp activateIgnoringOtherApps:YES];
    OSStatus result=PasteboardCreate(kPasteboardClipboard,&_board);
    [self note:[NSString stringWithFormat:@"pasteboard_create=%d macOS=%@",(int)result,NSProcessInfo.processInfo.operatingSystemVersionString]];
    [self note:@"先选择一个测试目录，再点 A，在 Finder 打开同一目录，按一次 ⌘V。\n等待 5 秒后截图；如无反应再点 B，重复一次。普通文件只用作对照，不算通过。\n承诺 A/B 不提前生成文件。只有系统回调提供所选目录才写入约 8 KiB 测试数据。"];
}
- (BOOL)windowShouldClose:(NSWindow *)sender {(void)sender;[NSApp terminate:nil];return YES;}
- (void)choose:(id)sender {
    (void)sender;NSOpenPanel *panel=[NSOpenPanel openPanel];panel.canChooseDirectories=YES;panel.canChooseFiles=NO;panel.allowsMultipleSelection=NO;
    if([panel runModal]!=NSModalResponseOK)return;
    struct stat st;if(stat(panel.URL.fileSystemRepresentation,&st)||!S_ISDIR(st.st_mode))return;
    self.target=panel.URL;self.targetDevice=st.st_dev;self.targetInode=st.st_ino;
    [self note:@"test_directory_selected=1（仅用于核对回调目录，不作为回调缺失时的替代路径）"];
}
- (void)arm:(NSInteger)mode {
    if(!self.target||!self.board){[self note:@"请先选择测试目录。 "];return;}
    PasteboardSynchronize(self.board);PasteboardClear(self.board);
    self.mode=mode;self.callbacks=0;self.written=nil;
    self.name=[NSString stringWithFormat:@"calabi-paste-%ld-%@.txt",(long)mode,NSUUID.UUID.UUIDString];
    OSStatus keeper=PasteboardSetPromiseKeeper(self.board,promiseCallback,NULL);
    CFStringRef flavor=mode==1?CFSTR("com.apple.pasteboard.promised-file-url"):CFSTR("public.file-url");
    PasteboardItemID item=(PasteboardItemID)(uintptr_t)1;
    OSStatus result=PasteboardPutItemFlavor(self.board,item,flavor,NULL,kPasteboardFlavorNoFlags);
    if(mode==1){
        NSData *type=[@"public.plain-text" dataUsingEncoding:NSUTF8StringEncoding];
        PasteboardPutItemFlavor(self.board,item,CFSTR("com.apple.pasteboard.promised-file-content-type"),(__bridge CFDataRef)type,kPasteboardFlavorNoFlags);
    }
    [self note:[NSString stringWithFormat:@"ARM mode=%ld keeper=%d flavor=%d generated_bytes=0 filename=%@",(long)mode,(int)keeper,(int)result,self.name]];
    [self note:@"现在在所选目录的 Finder 中按一次 ⌘V；不要读取剪贴板内容或运行其他剪贴板命令。"];
}
- (void)copyA:(id)sender {(void)sender;[self arm:1];}
- (void)copyB:(id)sender {(void)sender;[self arm:2];}
- (OSStatus)fulfill:(PasteboardRef)board item:(PasteboardItemID)item flavor:(CFStringRef)flavor {
    self.callbacks++;
    CFURLRef location=NULL;OSStatus status=PasteboardCopyPasteLocation(board,&location);
    NSURL *url=CFBridgingRelease(location);
    [self note:[NSString stringWithFormat:@"CALLBACK mode=%ld count=%lu flavor=%@ location_status=%d location_present=%d",(long)self.mode,(unsigned long)self.callbacks,(__bridge NSString*)flavor,(int)status,url!=nil]];
    if(!url.isFileURL){[self note:@"NO_DESTINATION: 不猜测目标、不生成文件。 "];return (OSStatus)-1;}
    int directory=open(url.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
    struct stat st;
    if(directory<0 || fstat(directory,&st) || st.st_dev!=self.targetDevice || st.st_ino!=self.targetInode){if(directory>=0)close(directory);[self note:@"DESTINATION_MISMATCH: 未写入文件。 "];return (OSStatus)-1;}
    [self note:@"DESTINATION_MATCH=1（系统提供的目录与所选测试目录一致）"];
    if(!self.written){
        int file=openat(directory,self.name.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(file<0){close(directory);[self note:@"CREATE_FAILED: 未覆盖任何已有文件。 "];return (OSStatus)-1;}
        const char line[]="CALABI FINDER PASTE PROBE - generated only after destination callback\n";
        BOOL ok=YES;size_t total=0;
        for(unsigned i=0;i<128 && ok;i++){
            size_t offset=0;while(offset<sizeof(line)-1){ssize_t n=write(file,line+offset,sizeof(line)-1-offset);if(n<0&&errno==EINTR)continue;if(n<=0){ok=NO;break;}offset+=(size_t)n;total+=(size_t)n;}
        }
        if(fsync(file))ok=NO;close(file);
        if(!ok){unlinkat(directory,self.name.fileSystemRepresentation,0);close(directory);[self note:@"WRITE_FAILED: 本次测试文件已清理。 "];return (OSStatus)-1;}
        self.written=[url URLByAppendingPathComponent:self.name];
        [self note:[NSString stringWithFormat:@"DIRECT_WRITE bytes=%lu filename=%@",(unsigned long)total,self.name]];
    }
    close(directory);
    NSData *data=[self.written.absoluteString dataUsingEncoding:NSUTF8StringEncoding];
    OSStatus result=PasteboardPutItemFlavor(board,item,flavor,(__bridge CFDataRef)data,kPasteboardFlavorNoFlags);
    [self note:[NSString stringWithFormat:@"RETURN_FILE_URL status=%d；还需确认 Finder 无报错且只生成一个文件。",(int)result]];
    return result;
}
- (void)control:(id)sender {
    (void)sender;if(!self.target)return;
    if(!self.controlRoot){
        char *pattern=strdup([[NSTemporaryDirectory() stringByAppendingPathComponent:@"calabi-finder-control-XXXXXX"] fileSystemRepresentation]);
        if(pattern && mkdtemp(pattern))self.controlRoot=[[NSFileManager defaultManager] stringWithFileSystemRepresentation:pattern length:strlen(pattern)];free(pattern);
    }
    if(!self.controlRoot)return;
    NSURL *url=[NSURL fileURLWithPath:[self.controlRoot stringByAppendingPathComponent:@"calabi-ordinary-control.txt"]];
    [@"Ordinary file control. This is NOT a direct-paste pass.\n" writeToURL:url atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    NSPasteboard *board=NSPasteboard.generalPasteboard;[board clearContents];[board writeObjects:@[url]];
    [self note:@"CONTROL: 普通文件已复制。该文件预先存在，成功粘贴也不证明 A/B 可用。 "];
}
- (void)applicationWillTerminate:(NSNotification *)notification {
    (void)notification;
    // Clear only if we still own this clipboard; never resolve outstanding promises on exit.
    if(self.board){PasteboardSyncFlags flags=PasteboardSynchronize(self.board);if(flags&kPasteboardClientIsOwner)PasteboardClear(self.board);PasteboardSetPromiseKeeper(self.board,NULL,NULL);CFRelease(self.board);self.board=NULL;}
    if(self.controlRoot)[[NSFileManager defaultManager] removeItemAtPath:self.controlRoot error:NULL];
}
@end
int main(void){@autoreleasepool {
    [NSApplication sharedApplication];[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    probe=[[FinderPasteProbe alloc] init];NSApp.delegate=probe;[NSApp run];
}return 0;}
