#pragma once
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
// Included after CalabiMeshReceive. All mutable batch state stays on main thread.
static int macFPListener=-1;
static NSString *macFPToken;
static NSTask *macFPHost;
static NSDictionary *mac_fp_request(NSDictionary *request) {
    if(!atomic_load(&macMeshLive) || ![request[@"token"] isKindOfClass:NSString.class] || ![request[@"token"] isEqualToString:macFPToken])return @{@"ok":@NO};
    __block CalabiMeshReceive *batch=nil;
    __block NSString *cancelledOffer=nil;
    dispatch_sync(dispatch_get_main_queue(),^{batch=macMeshIncoming;cancelledOffer=macMeshCancelledOffer;});
    NSString *op=request[@"op"];
    if([op isEqual:@"catalog"]){
        NSMutableArray *files=[NSMutableArray array];
        if(batch && !batch.interruption)for(NSUInteger i=0;i<batch.names.count;i++)
            [files addObject:@{@"id":[NSString stringWithFormat:@"%@-%lu",batch.offer,(unsigned long)i],@"name":batch.names[i],@"size":batch.sizes[i],@"index":@(i),@"offer":batch.offer}];
        return @{@"ok":@YES,@"files":files};
    }
    if(cancelledOffer && [request[@"offer"] isEqual:cancelledOffer])return @{@"ok":@NO,@"cancelled":@YES};
    if(!batch || ![request[@"offer"] isEqual:batch.offer] || batch.interruption)return @{@"ok":@NO};
    if([op isEqual:@"paste"]){
        if(![request[@"destination"] isKindOfClass:NSString.class])return @{@"ok":@NO};
        NSString *path=request[@"destination"];
        if(!path.isAbsolutePath || path.length>8192 || [path rangeOfString:[NSString stringWithFormat:@"%C",(unichar)0]].location!=NSNotFound)return @{@"ok":@NO};
        id screen=request[@"screen"];
        NSString *screenNumber=[screen isKindOfClass:NSString.class] && [screen length]<=10 ? screen : nil;
        __block BOOL accepted=NO,presented=NO;
        dispatch_sync(dispatch_get_main_queue(),^{
#ifdef CALABI_REMOTE_WORKSPACE
            if(!probe_workspace_active())return;
#endif
            if(macMeshIncoming!=batch || [batch receiveInterruption] || (batch.directStarted && !batch.finished) ||
                batch.board.changeCount!=batch.expectedSequence || ![[batch.board stringForType:macMeshOwned] isEqual:batch.offer])return;
            batch.progressScreenNumber=screenNumber;
            if(batch.panel)[batch positionProgressPanel];
            batch.failure=nil;batch.uiHidden=NO;batch.ready=NO;[batch.touched removeAllIndexes];
            for(NSUInteger i=0;i<batch.received.count;i++)batch.received[i]=@0;
            int directory=open(path.fileSystemRepresentation,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
            if(directory<0){
                batch.failure=mac_mesh_write_error(errno);batch.finished=YES;
                [batch showIndex:0 done:0 error:batch.failure];
                presented=YES;return;
            }
            batch.directStarted=YES;batch.finished=NO;batch.destinationFD=directory;
            [batch showIndex:0 done:0 error:nil];
            [batch.queue addOperationWithBlock:^{@autoreleasepool{[batch receiveToDirectoryFD:directory];}}];
            accepted=YES;NSLog(@"FINDER_MENU_PASTE_ACCEPTED files=%lu",(unsigned long)batch.names.count);
        });return @{@"ok":@(accepted),@"presented":@(presented)};
    }
    if([op isEqual:@"cancel"]){dispatch_async(dispatch_get_main_queue(),^{[batch cancelReceive:nil];});return @{@"ok":@YES};}
    if(![request[@"index"] isKindOfClass:NSNumber.class])return @{@"ok":@NO};
    NSInteger index=[request[@"index"] integerValue];
    if(index<0 || (NSUInteger)index>=batch.names.count)return @{@"ok":@NO};
    if([op isEqual:@"done"]){
        dispatch_async(dispatch_get_main_queue(),^{
            batch.received[index]=batch.sizes[index];BOOL complete=YES;
            for(NSUInteger i=0;i<batch.sizes.count;i++)if(![batch.received[i] isEqual:batch.sizes[i]])complete=NO;
            batch.finished=complete;[batch showIndex:index done:batch.sizes[index].unsignedLongLongValue error:nil];
        });return @{@"ok":@YES};
    }
    if(![op isEqual:@"read"] || ![request[@"offset"] isKindOfClass:NSNumber.class] || ![request[@"count"] isKindOfClass:NSNumber.class])return @{@"ok":@NO};
    int64_t offset=[request[@"offset"] longLongValue],count=[request[@"count"] longLongValue];
    uint64_t size=batch.sizes[index].unsignedLongLongValue;
    if(offset<0 || count<=0 || count>65536 || (uint64_t)offset>size || (uint64_t)count>size-(uint64_t)offset)return @{@"ok":@NO};
    NSString *reply=mac_mesh_rpc([NSString stringWithFormat:@"mesh_read %@ %ld %lld %lld",batch.offer,(long)index,(long long)offset,(long long)count]);
    if([reply isEqual:@"wait"])return @{@"ok":@YES,@"wait":@YES};
    NSData *data=[reply hasPrefix:@"data "]?mac_mesh_unhex([reply substringFromIndex:5]):nil;
    if(batch.cancelled)return @{@"ok":@NO,@"cancelled":@YES};
    NSError *failure=[batch receiveInterruption];
    if(data.length!=(NSUInteger)count)failure=mac_mesh_read_error(reply) ?: failure ?: mac_mesh_error(MacMeshReadFailed);
    if(failure){
        [batch showIndex:index done:offset error:failure];
        return @{@"ok":@NO};
    }
    [batch showIndex:index done:offset+count error:nil];
    return @{@"ok":@YES,@"data":[data base64EncodedStringWithOptions:0]};
}
static void mac_fp_serve(int fd){
    struct timeval timeout={15,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    int one=1;setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));
    NSMutableData *line=[NSMutableData data];uint8_t ch=0;
    while(line.length<16384){ssize_t n=read(fd,&ch,1);if(n<0 && errno==EINTR)continue;if(n!=1)break;[line appendBytes:&ch length:1];if(ch=='\n')break;}
    id request=ch=='\n'?[NSJSONSerialization JSONObjectWithData:line options:0 error:NULL]:nil;
    NSDictionary *reply=[request isKindOfClass:NSDictionary.class]?mac_fp_request(request):@{@"ok":@NO};
    NSMutableData *data=[[NSJSONSerialization dataWithJSONObject:reply options:0 error:NULL] mutableCopy];ch='\n';[data appendBytes:&ch length:1];
    NSUInteger offset=0;while(offset<data.length){ssize_t n=write(fd,(const uint8_t*)data.bytes+offset,data.length-offset);if(n<0 && errno==EINTR)continue;if(n<=0)break;offset+=n;}close(fd);
}
static BOOL mac_fp_start(void){
    NSString *directory=[[[NSProcessInfo processInfo] arguments][0] stringByDeletingLastPathComponent];
    NSString *app=[directory stringByAppendingPathComponent:@"CalabiRemoteFiles.app"];
    NSString *exe=[app stringByAppendingPathComponent:@"Contents/MacOS/RemoteFiles"];
    if(![[NSFileManager defaultManager] isExecutableFileAtPath:exe])return NO;
    NSTask *registration=[NSTask new];registration.executableURL=[NSURL fileURLWithPath:@"/usr/bin/pluginkit"];
    registration.arguments=@[@"-a",[app stringByAppendingPathComponent:@"Contents/PlugIns/RemoteMenu.appex"]];
    registration.standardOutput=[NSFileHandle fileHandleWithNullDevice];
    if(![registration launchAndReturnError:NULL])return NO;
    [registration waitUntilExit];if(registration.terminationStatus!=0)return NO;
    NSTask *urls=[NSTask new];urls.executableURL=[NSURL fileURLWithPath:@"/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"];
    urls.arguments=@[@"-f",app];urls.standardOutput=[NSFileHandle fileHandleWithNullDevice];
    if(![urls launchAndReturnError:NULL])return NO;
    [urls waitUntilExit];if(urls.terminationStatus!=0)return NO;
    int listener=socket(AF_INET,SOCK_STREAM,0);if(listener<0)return NO;
    fcntl(listener,F_SETFD,FD_CLOEXEC);
    struct sockaddr_in address={};address.sin_len=sizeof(address);address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(bind(listener,(struct sockaddr*)&address,sizeof(address)) || listen(listener,8)){close(listener);return NO;}
    socklen_t size=sizeof(address);if(getsockname(listener,(struct sockaddr*)&address,&size)){close(listener);return NO;}
    // The accept loop and teardown own separate descriptors for the same socket.
    int serverFD=dup(listener);if(serverFD<0){close(listener);return NO;}
    fcntl(serverFD,F_SETFD,FD_CLOEXEC);
    macFPListener=listener;macFPToken=[NSUUID.UUID.UUIDString stringByAppendingString:NSUUID.UUID.UUIDString];
    macFPHost=[NSTask new];macFPHost.executableURL=[NSURL fileURLWithPath:exe];
    NSMutableDictionary *env=NSProcessInfo.processInfo.environment.mutableCopy;
    env[@"CALABI_FP_PORT"]=[NSString stringWithFormat:@"%u",ntohs(address.sin_port)];env[@"CALABI_FP_TOKEN"]=macFPToken;
    macFPHost.environment=env;macFPHost.standardInput=[NSFileHandle fileHandleWithNullDevice];macFPHost.standardOutput=[NSFileHandle fileHandleWithNullDevice];
    if(![macFPHost launchAndReturnError:NULL]){close(serverFD);close(listener);macFPListener=-1;return NO;}
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{
        while(atomic_load(&macMeshLive)){
            int fd=accept(serverFD,NULL,NULL);if(fd<0){if(errno==EINTR)continue;break;}
            // Bounded concurrency: each accepted request is completed before the next.
            @autoreleasepool{mac_fp_serve(fd);}
        }
        close(serverFD);
    });return YES;
}
static void mac_fp_stop(void){
    if(macFPListener>=0){shutdown(macFPListener,SHUT_RDWR);close(macFPListener);macFPListener=-1;}
    NSTask *host=macFPHost;
    macFPHost=nil;
    // Release the old host's lock before a transport reconnect starts its replacement.
    if(host.running){[host terminate];[host waitUntilExit];}
}
