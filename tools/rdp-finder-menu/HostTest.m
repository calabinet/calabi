// Exercise the real host against a serial bridge held by an authorization wait.
#include <assert.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#define main calabi_menu_host_main
#include "Host.m"
#undef main

static NSUInteger terminationCount;
static atomic_bool rejectCatalog;
static atomic_bool serverDone;
@interface MenuTestApplication : NSApplication
@end
@implementation MenuTestApplication
- (void)terminate:(id)sender {(void)sender;terminationCount++;}
@end

@interface MenuHealthTestHost : CalabiRemoteMenuHost
@property NSUInteger probes;
@property NSUInteger refreshes;
@end
@implementation MenuHealthTestHost
- (void)sendMenuProbe {self.probes++;}
- (void)refreshMenuRegistration {self.refreshes++;}
@end

static void pumpUntil(BOOL (^condition)(void), NSTimeInterval seconds) {
    NSDate *deadline=[NSDate dateWithTimeIntervalSinceNow:seconds];
    while(!condition() && deadline.timeIntervalSinceNow>0)
        [NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    assert(condition());
}

static void testMenuHealth(void) {
    MenuHealthTestHost *host=[MenuHealthTestHost new];
    [host updateMenuHealthAt:0];
    assert(host.probes==0 && host.refreshes==0);
    host.menuBuildKey=@"fixture";
    NSTimeInterval now=NSProcessInfo.processInfo.systemUptime;
    [host updateMenuHealthAt:now];
    assert(host.probes==1 && host.refreshes==0);
    [host menuProbeAnswered:nil];
    pumpUntil(^BOOL{return !host.menuProbePending;},1);
    [host updateMenuHealthAt:now+5];
    assert(host.probes==1);
    now=host.nextMenuProbe;
    [host updateMenuHealthAt:now];
    [host updateMenuHealthAt:now+2];
    assert(host.probes==3 && host.refreshes==0);
    [host updateMenuHealthAt:now+4];
    assert(host.refreshes==1);
    [host updateMenuHealthAt:now+6];
    [host updateMenuHealthAt:now+8];
    [host updateMenuHealthAt:now+10];
    assert(host.refreshes==1);
    [host updateMenuHealthAt:now+34];
    assert(host.refreshes==2);
    [host menuHostDidWake:nil];
    pumpUntil(^BOOL{return host.probes==7;},1);
    assert(host.missedMenuProbes==0 && host.refreshes==2);
}

int main(void) {@autoreleasepool{
    [MenuTestApplication sharedApplication];
    testMenuHealth();
    int listener=socket(AF_INET,SOCK_STREAM,0);assert(listener>=0);
    struct sockaddr_in address={};address.sin_len=sizeof(address);address.sin_family=AF_INET;
    address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    assert(bind(listener,(struct sockaddr*)&address,sizeof(address))==0);
    assert(listen(listener,8)==0);
    socklen_t length=sizeof(address);
    assert(getsockname(listener,(struct sockaddr*)&address,&length)==0);
    NSString *port=[NSString stringWithFormat:@"%u",ntohs(address.sin_port)];
    assert(setenv("CALABI_FP_PORT",port.UTF8String,1)==0);
    assert(setenv("CALABI_FP_TOKEN","fixture-token-fixture-token-fixture-token-fixture-token-fixture-token",1)==0);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{
        unsigned requests=0,pastes=0;
        while(pastes<2){
            int fd=accept(listener,NULL,NULL);assert(fd>=0);
            int one=1;assert(setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one))==0);
            struct timeval timeout={20,0};assert(setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout))==0);
            NSMutableData *line=[NSMutableData data];char ch=0;
            while(read(fd,&ch,1)==1 && ch!='\n' && line.length<16384)[line appendBytes:&ch length:1];
            assert(ch=='\n');
            NSDictionary *request=[NSJSONSerialization JSONObjectWithData:line options:0 error:NULL];
            assert(request);
            BOOL paste=[request[@"op"] isEqual:@"paste"];
            requests++;
            if(paste)pastes++;
            if(requests==1 || (paste && pastes==1))[NSThread sleepForTimeInterval:6];
            const char *reply=!paste && atomic_load(&rejectCatalog)?"{\"ok\":false}\n":"{\"ok\":true}\n";
            // The first heartbeat client has already timed out and closed.
            (void)write(fd,reply,strlen(reply));close(fd);
        }
        close(listener);atomic_store(&serverDone,true);
    });
    CalabiRemoteMenuHost *host=[CalabiRemoteMenuHost new];host.ownerPID=getppid();
    [host heartbeat];
    pumpUntil(^BOOL{return host.waitingForBridge || terminationCount>0;},10);
    assert(terminationCount==0); // A pending authorization must preserve the host.
    pumpUntil(^BOOL{return !host.waitingForBridge || terminationCount>0;},10);
    assert(terminationCount==0);
    atomic_store(&rejectCatalog,true);
    pumpUntil(^BOOL{return terminationCount>0;},5);
    assert(terminationCount==1); // An authoritative session end still exits.
    __block BOOL pasted=NO;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{
        for(unsigned i=0;i<2;i++){
            NSDictionary *reply=bridge(@{@"op":@"paste"},NULL);
            assert([reply[@"ok"] boolValue]); // First approval exceeds 5 seconds.
        }
        dispatch_async(dispatch_get_main_queue(),^{pasted=YES;});
    });
    pumpUntil(^BOOL{return pasted && atomic_load(&serverDone);},15);
    BOOL disconnected=NO;
    assert(bridge(@{@"op":@"catalog"},&disconnected)==nil && disconnected);
    host.ownerPID=getppid()+1;[host heartbeat];
    assert(terminationCount==2);
    puts("Finder menu host tests passed: extension health, authorization wait, repeated paste, session end, owner exit.");
    return 0;
}}
