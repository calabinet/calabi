#pragma once
// Menu actions pin a destination directory FD before returning to Finder.
// No Finder copy operation, File Provider materialization or clipboard file URL.
@implementation CalabiMeshReceive (FinderReceive)
- (void)receiveToDirectoryFD:(int)directory {
    NSLog(@"FINDER_MENU_DIRECT_V1");
    NSError *error=nil;NSUInteger index=0;uint64_t offset=0;
    @synchronized(CalabiMeshReceive.class){if(!macMeshActive)macMeshActive=[NSMutableSet set];[macMeshActive addObject:self];}
    for(index=0;index<self.names.count;index++){
        offset=0;uint64_t size=self.sizes[index].unsignedLongLongValue;
        [self showIndex:index done:0 error:nil];
        NSString *temporary=[NSString stringWithFormat:@".calabi-receive-%@.partial",NSUUID.UUID.UUIDString];
        int fd=-1;struct stat created={};
        @synchronized(self){
            error=[self receiveInterruption];
            if(!error){fd=openat(directory,temporary.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
                if(fd<0)error=mac_mesh_write_error(errno);
                else if(fstat(fd,&created))error=mac_mesh_write_error(errno);
                else {self.temporaryName=temporary;self.temporaryIdentity=@[@((uint64_t)created.st_dev),@((uint64_t)created.st_ino)];}}
        }
        while(!error && offset<size){
            NSUInteger count=(NSUInteger)MIN(65536,size-offset);
            NSData *data=mac_mesh_read_chunk(self,index,offset,count,&error);if(error)break;
            NSUInteger done=0;
            while(done<count){ssize_t n=write(fd,(const uint8_t*)data.bytes+done,count-done);if(n<0 && errno==EINTR)continue;
                if(n<=0){error=mac_mesh_write_error(n<0?errno:EIO);break;}done+=(NSUInteger)n;}
            offset+=done;[self showIndex:index done:offset error:nil];
        }
        if(fd>=0){
            if(!error && fsync(fd))error=mac_mesh_write_error(errno);
            if(close(fd) && !error)error=mac_mesh_write_error(errno);
        }
        // Cancellation and final commit are serialized: never commit after a cancel.
        @synchronized(self){
            if(!error)error=[self receiveInterruption];
            struct stat current={};BOOL owns=self.temporaryName && !fstatat(directory,temporary.fileSystemRepresentation,&current,AT_SYMLINK_NOFOLLOW) && current.st_dev==created.st_dev && current.st_ino==created.st_ino;
            if(!error && !owns)error=mac_mesh_error(MacMeshDestinationUnavailable);
            if(!error){
                NSString *name=self.names[index],*candidate=name;BOOL committed=NO;
                for(unsigned suffix=0;suffix<10000;suffix++){
                    if(suffix){NSString *ext=name.pathExtension,*stem=name.stringByDeletingPathExtension;
                        candidate=ext.length?[NSString stringWithFormat:@"%@ (%u).%@",stem,suffix,ext]:[NSString stringWithFormat:@"%@ (%u)",name,suffix];}
                    if(renameatx_np(directory,temporary.fileSystemRepresentation,directory,candidate.fileSystemRepresentation,RENAME_EXCL)==0){committed=YES;break;}
                    if(errno!=EEXIST)break;
                }
                if(!committed)error=mac_mesh_write_error(errno);
            }
            if(self.temporaryName){if(error && owns)unlinkat(directory,temporary.fileSystemRepresentation,0);self.temporaryName=nil;self.temporaryIdentity=nil;}
        }
        if(error)break;
    }
    @synchronized(self){self.destinationFD=-1;close(directory);}
    dispatch_async(dispatch_get_main_queue(),^{
        // Persist the result before publishing completion. Rendering is asynchronous
        // and may be disabled (fixtures) or hidden; it must not own transfer state.
        self.failure=error;
        self.finished=YES;
        [self showIndex:MIN(index,self.names.count-1) done:offset error:error];
        NSLog(@"FINDER_MENU_RECEIVE_END cancelled=%d domain=%@ code=%ld",self.cancelled,error.domain,(long)error.code);
    });
    @synchronized(CalabiMeshReceive.class){[macMeshActive removeObject:self];}
}
@end
