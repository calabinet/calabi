#import <Cocoa/Cocoa.h>
#import <FinderSync/FinderSync.h>
#import "MenuHealth.h"
#import "../rdp-p0/rdp_locale.h"
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

static NSDictionary *bridge(NSDictionary *values, BOOL *disconnected) {
    if(disconnected)*disconnected=NO;
    NSDictionary *env=NSProcessInfo.processInfo.environment;
    int port=[env[@"CALABI_FP_PORT"] intValue];NSString *token=env[@"CALABI_FP_TOKEN"];
    if(port<=0 || port>65535 || token.length<64)return nil;
    int fd=socket(AF_INET,SOCK_STREAM,0);if(fd<0)return nil;
    // Opening a protected destination may wait for the user's first authorization.
    struct timeval timeout={[values[@"op"] isEqual:@"paste"]?120:5,0};
    setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    int one=1;setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
    struct sockaddr_in address={};address.sin_len=sizeof(address);address.sin_family=AF_INET;address.sin_port=htons((uint16_t)port);address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(connect(fd,(struct sockaddr*)&address,sizeof(address))){
        int error=errno;close(fd);
        if(disconnected)*disconnected=error==ECONNREFUSED;
        return nil;
    }
    NSMutableDictionary *request=values.mutableCopy;request[@"token"]=token;
    NSMutableData *bytes=[[NSJSONSerialization dataWithJSONObject:request options:0 error:NULL] mutableCopy];uint8_t newline='\n';[bytes appendBytes:&newline length:1];
    NSUInteger offset=0;
    while(offset<bytes.length){ssize_t n=write(fd,(const uint8_t*)bytes.bytes+offset,bytes.length-offset);if(n<0 && errno==EINTR)continue;if(n<=0){close(fd);return nil;}offset+=(NSUInteger)n;}
    NSMutableData *response=[NSMutableData data];uint8_t block[4096];BOOL complete=NO;
    while(response.length<65536){ssize_t n=read(fd,block,sizeof(block));if(n<0 && errno==EINTR)continue;if(n<=0)break;[response appendBytes:block length:(NSUInteger)n];if(((const uint8_t*)response.bytes)[response.length-1]=='\n'){complete=YES;break;}}
    close(fd);id reply=complete?[NSJSONSerialization JSONObjectWithData:response options:0 error:NULL]:nil;
    return [reply isKindOfClass:NSDictionary.class]?reply:nil;
}
@interface CalabiRemoteMenuHost : NSObject <NSApplicationDelegate>
@property(strong) NSMutableSet<NSString*> *requests;
@property pid_t ownerPID;
@property BOOL waitingForBridge;
@property(copy) NSString *menuBuildKey;
@property NSTimeInterval nextMenuProbe;
@property NSTimeInterval nextMenuRepair;
@property NSUInteger missedMenuProbes;
@property BOOL menuProbePending;
@property BOOL menuRepairRunning;
@property BOOL waitingForMenuRecovery;
@property RdpLocale menuLocale;
@end
@implementation CalabiRemoteMenuHost
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    (void)notification;if(!self.requests)self.requests=[NSMutableSet set];NSLog(@"FINDER_MENU_HOST_V5_RECOVERY");
    NSString *build=[NSBundle.mainBundle objectForInfoDictionaryKey:@"MenuBuildKey"];
    self.menuBuildKey=build;
    self.menuLocale=RdpLocaleInvalid;
    if(build.length){
        [NSDistributedNotificationCenter.defaultCenter addObserver:self selector:@selector(menuProbeAnswered:)
            name:MenuHealthReply object:build suspensionBehavior:NSNotificationSuspensionBehaviorDeliverImmediately];
        [NSDistributedNotificationCenter.defaultCenter addObserver:self selector:@selector(menuLocaleRequested:)
            name:MenuLocaleRequest object:build suspensionBehavior:NSNotificationSuspensionBehaviorDeliverImmediately];
        [NSWorkspace.sharedWorkspace.notificationCenter addObserver:self selector:@selector(menuHostDidWake:)
            name:NSWorkspaceDidWakeNotification object:nil];
    }
    NSUserDefaults *prefs=NSUserDefaults.standardUserDefaults;
    BOOL attempted=[[prefs stringForKey:@"MenuActivationAttemptBuild"] isEqual:build];
    // Record an enabled build too, so a later explicit user disable is respected.
    [prefs setObject:build forKey:@"MenuActivationAttemptBuild"];
    if(![FIFinderSyncController isExtensionEnabled] && !attempted){
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{
            NSTask *task=[NSTask new];task.executableURL=[NSURL fileURLWithPath:@"/bin/bash"];
            NSString *script=[NSBundle.mainBundle pathForResource:@"activate-menu" ofType:@"sh"];
            if(script)task.arguments=@[script,NSBundle.mainBundle.bundlePath];
            task.standardOutput=[NSFileHandle fileHandleWithNullDevice];
            BOOL launched=script && [task launchAndReturnError:NULL];if(launched)[task waitUntilExit];
            NSLog(@"FINDER_MENU_AUTO_ENABLE launched=%d status=%d",launched,launched?task.terminationStatus:-1);
        });
    }
    [self heartbeat];
}
- (void)publishMenuLocale:(RdpLocale)locale {
    if(!self.menuBuildKey.length)return;
    self.menuLocale=locale;
    NSString *value=[NSString stringWithFormat:@"%@/%s",self.menuBuildKey,rdp_locale_codes[locale]];
    [NSDistributedNotificationCenter.defaultCenter postNotificationName:MenuLocaleUpdate object:value userInfo:nil deliverImmediately:YES];
}
- (void)menuLocaleRequested:(NSNotification *)notification {
    (void)notification;
    dispatch_async(dispatch_get_main_queue(),^{[self publishMenuLocale:rdp_locale_current()];});
}
- (void)menuHostDidWake:(NSNotification *)notification {
    (void)notification;
    dispatch_async(dispatch_get_main_queue(), ^{
        self.menuProbePending=NO;
        self.missedMenuProbes=0;
        self.nextMenuProbe=0;
        [self updateMenuHealthAt:NSProcessInfo.processInfo.systemUptime];
    });
}
- (void)menuProbeAnswered:(NSNotification *)notification {
    (void)notification;
    dispatch_async(dispatch_get_main_queue(), ^{
        if(!self.menuProbePending)return;
        self.menuProbePending=NO;
        self.missedMenuProbes=0;
        self.nextMenuProbe=NSProcessInfo.processInfo.systemUptime+10;
        if(self.waitingForMenuRecovery){
            self.waitingForMenuRecovery=NO;
            NSLog(@"FINDER_MENU_RECOVERY response=received");
        }
    });
}
- (void)sendMenuProbe {
    [NSDistributedNotificationCenter.defaultCenter postNotificationName:MenuHealthProbe
        object:self.menuBuildKey userInfo:nil deliverImmediately:YES];
}
- (void)refreshMenuRegistration {
    self.menuRepairRunning=YES;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0), ^{
        NSString *script=[NSBundle.mainBundle pathForResource:@"activate-menu" ofType:@"sh"];
        NSTask *task=[NSTask new];
        task.executableURL=[NSURL fileURLWithPath:@"/bin/bash"];
        if(script)task.arguments=@[script,NSBundle.mainBundle.bundlePath,@"--refresh"];
        task.standardOutput=[NSFileHandle fileHandleWithNullDevice];
        BOOL launched=script && [task launchAndReturnError:NULL];
        if(launched)[task waitUntilExit];
        int status=launched?task.terminationStatus:-1;
        NSLog(@"FINDER_MENU_RECOVERY refresh_status=%d",status);
        dispatch_async(dispatch_get_main_queue(), ^{
            self.menuRepairRunning=NO;
            self.waitingForMenuRecovery=status==0;
            if(status==3)self.nextMenuProbe=self.nextMenuRepair;
        });
    });
}
- (void)updateMenuHealthAt:(NSTimeInterval)now {
    if(!self.menuBuildKey.length || self.menuRepairRunning || now<self.nextMenuProbe)return;
    if(self.menuProbePending)self.missedMenuProbes++;
    if(self.missedMenuProbes>=2 && now>=self.nextMenuRepair){
        self.menuProbePending=NO;
        self.missedMenuProbes=0;
        self.nextMenuRepair=now+30;
        NSLog(@"FINDER_MENU_RECOVERY reason=probe_timeout");
        [self refreshMenuRegistration];
        return;
    }
    self.nextMenuProbe=now+2;
    self.menuProbePending=YES;
    [self sendMenuProbe];
}
- (void)heartbeat {
    if(self.ownerPID>1 && getppid()!=self.ownerPID){
        NSLog(@"FINDER_MENU_HOST_EXIT reason=owner_exit");[NSApp terminate:nil];return;
    }
    RdpLocale locale=rdp_locale_current();
    if(locale!=self.menuLocale)[self publishMenuLocale:locale];
    [self updateMenuHealthAt:NSProcessInfo.processInfo.systemUptime];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{
        BOOL disconnected=NO;
        NSDictionary *result=bridge(@{@"op":@"catalog"},&disconnected);
        dispatch_async(dispatch_get_main_queue(),^{
            if(disconnected || (result && ![result[@"ok"] boolValue])){
                NSLog(@"FINDER_MENU_HOST_EXIT reason=%@",disconnected?@"bridge_closed":@"session_ended");
                [NSApp terminate:nil];return;
            }
            // A missing response is inconclusive while the owner is alive. The
            // single bridge server may be waiting for a folder permission dialog.
            if(!result && !self.waitingForBridge)NSLog(@"FINDER_MENU_HOST_WAIT reason=bridge_response");
            if(result && self.waitingForBridge)NSLog(@"FINDER_MENU_HOST_RECOVERED");
            self.waitingForBridge=result==nil;
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,NSEC_PER_SEC),dispatch_get_main_queue(),^{[self heartbeat];});
        });
    });
}
- (void)application:(NSApplication *)application openURLs:(NSArray<NSURL*>*)urls {
    (void)application;
    NSLog(@"FINDER_MENU_HOST_OPEN count=%lu",(unsigned long)urls.count);
    if(!self.requests)self.requests=[NSMutableSet set];
    for(NSURL *url in urls){
        NSURLComponents *parts=[NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:NO];
        if(![parts.scheme isEqual:@"calabi-remote-paste"] || ![parts.host isEqual:@"paste"] || url.absoluteString.length>16000)continue;
        NSMutableDictionary *values=[NSMutableDictionary dictionary];BOOL duplicate=NO;
        for(NSURLQueryItem *item in parts.queryItems){if(values[item.name])duplicate=YES;if(item.value)values[item.name]=item.value;}
        NSString *request=values[@"request"],*offer=values[@"offer"];
        NSURL *target=[NSURL URLWithString:values[@"target"]?:@""];
        if(duplicate || !target.isFileURL || (target.host.length && ![target.host isEqual:@"localhost"]) ||
            ![[NSUUID alloc] initWithUUIDString:request?:@""] || self.requests.count>=1024 || [self.requests containsObject:request] ||
            ![values[@"key"] isEqual:[NSBundle.mainBundle objectForInfoDictionaryKey:@"MenuBuildKey"]] ||
            !offer.length || ![offer isEqual:[NSPasteboard.generalPasteboard stringForType:@"net.calabi.mesh-file-offer"]]){NSLog(@"FINDER_MENU_REQUEST_REJECTED");continue;}
        [self.requests addObject:request];
        NSMutableDictionary *paste=[@{@"op":@"paste",@"offer":offer,@"destination":target.path} mutableCopy];
        NSString *screen=values[@"screen"];
        if(screen.length && screen.length<=10)paste[@"screen"]=screen;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{
            NSDictionary *reply=bridge(paste,NULL);
            if(!reply){
                NSLog(@"FINDER_MENU_REQUEST result=unconfirmed");
                dispatch_async(dispatch_get_main_queue(),^{
                    NSAlert *alert=[NSAlert new];alert.messageText=RDP_NS(ReceiveUnconfirmed);
                    alert.informativeText=RDP_NS(CheckFolderAccess);
                    [NSApp activateIgnoringOtherApps:YES];[alert runModal];
                });
                return;
            }
            NSLog(@"FINDER_MENU_REQUEST accepted=%d",[reply[@"ok"] boolValue]);
            if(![reply[@"ok"] boolValue] && ![reply[@"presented"] boolValue])dispatch_async(dispatch_get_main_queue(),^{
                NSAlert *alert=[NSAlert new];alert.messageText=RDP_NS(ReceiveNotStarted);alert.informativeText=RDP_NS(CopyAgain);
                [NSApp activateIgnoringOtherApps:YES];[alert runModal];
            });
        });
    }
}
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication*)sender {(void)sender;return NO;}
@end
int main(void){@autoreleasepool{
    NSDictionary *env=NSProcessInfo.processInfo.environment;
    if(![env[@"CALABI_FP_TOKEN"] length] || ![env[@"CALABI_FP_PORT"] length]){
        NSLog(@"FINDER_MENU_HOST_START_REJECTED reason=no_session");return 2;
    }
    NSString *path=[NSTemporaryDirectory() stringByAppendingPathComponent:@"calabi-remote-files.lock"];
    int lock=open(path.fileSystemRepresentation,O_CREAT|O_RDWR|O_NOFOLLOW|O_CLOEXEC,0600);
    if(lock<0 || flock(lock,LOCK_EX|LOCK_NB)){
        NSLog(@"FINDER_MENU_HOST_START_REJECTED reason=host_lock");return 3;
    }
    [NSApplication sharedApplication];[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    CalabiRemoteMenuHost *host=[CalabiRemoteMenuHost new];host.ownerPID=getppid();
    NSApp.delegate=host;[NSApp run];close(lock);
}return 0;}
