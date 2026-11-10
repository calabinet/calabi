#pragma once
#include "clipboard_payload.h"
#include "macos_transfer_status.h"
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <math.h>

static BOOL clipboardEnabled, clipboardFilesEnabled;
static int sourceFD[PROBE_FILE_COUNT];
static struct stat sourceStat[PROBE_FILE_COUNT];
static unsigned sourceCount;
static NSString *receiveRoot, *receiveBatch;
static NSArray<NSURL *> *receiveURLs;
static uint64_t publishedSequence;
static uint64_t receiveReserved, receiveBatchReserved;
static uint64_t progressBucket=UINT64_MAX;
int probe_clipboard_enabled(void) { return clipboardEnabled || clipboardFilesEnabled; }
int probe_clipboard_content_enabled(void) { return clipboardEnabled; }
int probe_clipboard_files_enabled(void) { return clipboardFilesEnabled; }
static void close_sources(void) {
    for(unsigned i=0;i<sourceCount;i++) close(sourceFD[i]);
    sourceCount=0;
}
static NSData *copied_files(NSPasteboard *board) {
    close_sources();
    NSArray<NSURL *> *urls=[board readObjectsForClasses:@[NSURL.class]
        options:@{NSPasteboardURLReadingFileURLsOnlyKey:@YES}];
    if(!urls.count || urls.count>PROBE_FILE_COUNT) return nil;
    NSMutableData *data=[NSMutableData dataWithLength:4+urls.count*CLIP_DESCRIPTOR_SIZE];
    uint8_t *p=data.mutableBytes;clip_put32(p,(uint32_t)urls.count);
    uint64_t total=0;
    NSMutableSet *names=[NSMutableSet set];
    for(NSURL *url in urls) {
        NSString *name=url.lastPathComponent;
        NSData *wide=[name dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
        if(!wide.length || wide.length>518 || [names containsObject:name.lowercaseString]) goto fail;
        [names addObject:name.lowercaseString];
        int fd=open(url.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
        struct stat st;
        if(fd<0) goto fail;
        if(fstat(fd,&st) || !S_ISREG(st.st_mode) || st.st_size<0 || (uint64_t)st.st_size>PROBE_FILE_LIMIT) {close(fd);goto fail;}
        total+=(uint64_t)st.st_size;
        if(total>PROBE_FILE_LIMIT) {close(fd);goto fail;}
        unsigned i=sourceCount++;sourceFD[i]=fd;sourceStat[i]=st;
        uint8_t *d=p+4+i*CLIP_DESCRIPTOR_SIZE;
        clip_put32(d,0x44);clip_put32(d+36,0x80);
        clip_put32(d+64,(uint32_t)((uint64_t)st.st_size>>32));clip_put32(d+68,(uint32_t)st.st_size);
        memcpy(d+72,wide.bytes,wide.length);
    }
    if(clip_valid_files(data.bytes,data.length)) return data;
fail:
    close_sources();return nil;
}
static NSData *encode_clipboard_png(CGImageRef image) {
    if (!image) return nil;
    NSMutableData *png = [NSMutableData data];
    CGImageDestinationRef destination = CGImageDestinationCreateWithData(
        (__bridge CFMutableDataRef)png, CFSTR("public.png"), 1, NULL);
    if (!destination) return nil;
    CGImageDestinationAddImage(destination, image, NULL);
    BOOL ok = CGImageDestinationFinalize(destination);
    CFRelease(destination);
    return ok && png.length <= PROBE_IMAGE_SEND_LIMIT ? png : nil;
}

static NSData *copied_image(NSData *encoded, uint32_t *format) {
    *format = PROBE_FORMAT_DIB;
    if(!encoded || encoded.length>PROBE_IMAGE_LIMIT) return nil;
    CGImageSourceRef source=CGImageSourceCreateWithData((__bridge CFDataRef)encoded,NULL);
    if(!source)return nil;
    NSDictionary *properties=CFBridgingRelease(CGImageSourceCopyPropertiesAtIndex(source,0,NULL));
    NSInteger width=[properties[(__bridge NSString *)kCGImagePropertyPixelWidth] integerValue];
    NSInteger height=[properties[(__bridge NSString *)kCGImagePropertyPixelHeight] integerValue];
    if(width<=0 || height<=0 || width>8192 || height>8192) {
        CFRelease(source);return nil;
    }
    uint64_t bitmapBytes = (uint64_t)width * height * 4 + 40;
    BOOL isPNG = clip_has_png_signature(encoded.bytes, encoded.length);
    NSData *png = isPNG && encoded.length <= PROBE_IMAGE_SEND_LIMIT ? encoded : nil;
    if (!isPNG && bitmapBytes <= PROBE_IMAGE_LIMIT && bitmapBytes > PROBE_IMAGE_SEND_LIMIT) {
        CGImageRef fullImage = CGImageSourceCreateImageAtIndex(source, 0, NULL);
        png = encode_clipboard_png(fullImage);
        if (fullImage) CGImageRelease(fullImage);
    }
    CGImageRef original;
    if (bitmapBytes > PROBE_IMAGE_SEND_LIMIT) {
        // The extra pixel of margin accommodates thumbnail dimension rounding.
        double scale = sqrt((PROBE_IMAGE_SEND_LIMIT - 40) / (4.0 * width * height));
        NSUInteger edge = MAX(1, (NSUInteger)(MAX(width, height) * scale) - 1);
        NSDictionary *options = @{
            (__bridge NSString *)kCGImageSourceCreateThumbnailFromImageAlways: @YES,
            (__bridge NSString *)kCGImageSourceThumbnailMaxPixelSize: @(edge),
        };
        original = CGImageSourceCreateThumbnailAtIndex(source, 0, (__bridge CFDictionaryRef)options);
    } else {
        original = CGImageSourceCreateImageAtIndex(source, 0, NULL);
    }
    CFRelease(source);if(!original)return nil;
    size_t w=CGImageGetWidth(original),h=CGImageGetHeight(original);
    if(!w || !h || w>8192 || h>8192 || (uint64_t)w*h*4+40>PROBE_IMAGE_SEND_LIMIT) {
        CGImageRelease(original);return nil;
    }
    if (!png) png = encode_clipboard_png(original);
    NSMutableData *rgb=[NSMutableData dataWithLength:w*h*4];
    CGColorSpaceRef colorSpace=CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
    if(!colorSpace){CGImageRelease(original);return nil;}
    CGContextRef context=CGBitmapContextCreate(rgb.mutableBytes,w,h,8,w*4,colorSpace,
        kCGImageAlphaNoneSkipLast | kCGBitmapByteOrder32Big);
    CGColorSpaceRelease(colorSpace);
    if(!context){CGImageRelease(original);return nil;}
    // RGBX has no alpha and is a supported Quartz drawing destination. Composite on white.
    CGContextSetRGBFillColor(context,1,1,1,1);
    CGContextFillRect(context,CGRectMake(0,0,w,h));
    CGContextSetInterpolationQuality(context,kCGInterpolationNone);
    CGContextDrawImage(context,CGRectMake(0,0,w,h),original);
    CGContextRelease(context);CGImageRelease(original);
    NSMutableData *data=[NSMutableData dataWithLength:40+(NSUInteger)w*h*4];
    uint8_t *p=data.mutableBytes;clip_put32(p,40);clip_put32(p+4,(uint32_t)w);clip_put32(p+8,(uint32_t)h);
    p[12]=1;p[14]=32;clip_put32(p+20,(uint32_t)(w*h*4));
    for(size_t y=0;y<h;y++) for(size_t x=0;x<w;x++) {
        const uint8_t *in=(const uint8_t *)rgb.bytes+(y*w+x)*4;
        uint8_t *out=p+40+((h-1-y)*w+x)*4;
        out[0]=in[2];out[1]=in[1];out[2]=in[0];out[3]=0;
    }
    if (!png) return data;
    NSMutableData *snapshot = [NSMutableData dataWithLength:4];
    clip_put32(snapshot.mutableBytes, (uint32_t)png.length);
    [snapshot appendData:png];
    [snapshot appendData:data];
    *format = PROBE_FORMAT_PNG;
    return snapshot;
}
static int probe_clipboard_read_board(NSPasteboard *source,uint8_t **text,size_t *length,uint32_t *format,uint64_t *sequence) {
    __block NSData *data=nil;__block uint32_t type=0;__block uint64_t revision=*sequence;__block int result=1;
    dispatch_sync(dispatch_get_main_queue(), ^{
        NSPasteboard *board=source ?: NSPasteboard.generalPasteboard;
        uint64_t current=(uint64_t)board.changeCount;
#ifdef CALABI_REMOTE_WORKSPACE
        static unsigned selection;
        if(!source && probe_workspace_enabled()){
            if(!probe_workspace_active())return;
            unsigned selected=probe_workspace_selection();
            if(selected!=selection){
                // The first selection has no previous activation to revoke.
                // Preserve any Windows text format announced before this poll.
                result=!selection && ![board.types containsObject:@"net.calabi.mesh-file-offer"]
                    ? PROBE_CLIPBOARD_INITIAL_SELECTION : 3;
                selection=selected;revision=current;return;
            }
        }
#endif
        if(current==revision) return;
        revision=current;close_sources();
        if(getenv("CALABI_RDP_FILE_MESH") && [board.types containsObject:@"net.calabi.mesh-file-offer"]){result=3;return;}
        if([board.types containsObject:NSPasteboardTypeFileURL]) {
            if(getenv("CALABI_RDP_FILE_MESH")){result=3;return;}
            if(clipboardFilesEnabled) {data=copied_files(board);type=PROBE_FORMAT_FILES;}
            if(clipboardFilesEnabled && !data) probe_files_progress(0,0,-2);
            return;
        }
        if(!clipboardEnabled) return;
        if([board.types containsObject:NSPasteboardTypePNG] || [board.types containsObject:NSPasteboardTypeTIFF]) {
            data=[board dataForType:NSPasteboardTypePNG] ?: [board dataForType:NSPasteboardTypeTIFF];
            type=PROBE_FORMAT_DIB;return;
        }
        NSString *value=[board stringForType:NSPasteboardTypeString];
        if(!value || value.length>PROBE_CLIPBOARD_LIMIT/2-1) return;
        value=[[value stringByReplacingOccurrencesOfString:@"\r\n" withString:@"\n"] stringByReplacingOccurrencesOfString:@"\n" withString:@"\r\n"];
        NSData *encoded=[value dataUsingEncoding:NSUTF16LittleEndianStringEncoding];
        if(!encoded || encoded.length>PROBE_CLIPBOARD_LIMIT-2) return;
        NSMutableData *terminated=[encoded mutableCopy];[terminated increaseLengthBy:2];
        data=terminated;type=PROBE_FORMAT_TEXT;
    });
    if (type == PROBE_FORMAT_DIB) {
        uint32_t imageFormat;
        data = copied_image(data, &imageFormat);
        type = imageFormat;
    }
    *text=NULL;*length=0;*format=type;*sequence=revision;
    if(data.length) {*text=malloc(data.length);if(!*text)return 0;memcpy(*text,data.bytes,data.length);*length=data.length;}
    return result;
}
int probe_clipboard_read(uint8_t **text,size_t *length,uint32_t *format,uint64_t *sequence) {
#ifdef CALABI_REMOTE_WORKSPACE
    if(!probe_workspace_active())return 0;
#endif
    return probe_clipboard_read_board(nil,text,length,format,sequence);
}
int probe_clipboard_write(const uint8_t *data,size_t length,uint32_t format,uint64_t expected,uint64_t *sequence) {
    __block BOOL ok=NO;__block uint64_t revision=expected;
    dispatch_sync(dispatch_get_main_queue(), ^{
#ifdef CALABI_REMOTE_WORKSPACE
        if(!probe_workspace_active())return;
#endif
        NSPasteboard *board=NSPasteboard.generalPasteboard;
        if((uint64_t)board.changeCount!=expected) return;
        if(format==PROBE_FORMAT_FILES) {
            if(!receiveURLs.count) return;
            [board clearContents];ok=[board writeObjects:receiveURLs];
        } else if(format==PROBE_FORMAT_DIB && clipboardEnabled && clip_valid_dib(data,length)) {
            NSMutableData *bmp=[NSMutableData dataWithLength:14+length];uint8_t *p=bmp.mutableBytes;
            p[0]='B';p[1]='M';clip_put32(p+2,(uint32_t)bmp.length);clip_put32(p+10,54);memcpy(p+14,data,length);
            NSBitmapImageRep *image=[NSBitmapImageRep imageRepWithData:bmp];
            NSData *png=[image representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
            if(!png || png.length>PROBE_IMAGE_LIMIT) return;
            [board clearContents];ok=[board setData:png forType:NSPasteboardTypePNG];
        } else if(format==PROBE_FORMAT_TEXT && clipboardEnabled) {
            NSString *value=[[NSString alloc] initWithBytes:data length:length-2 encoding:NSUTF16LittleEndianStringEncoding];
            if(!value)return;value=[value stringByReplacingOccurrencesOfString:@"\r\n" withString:@"\n"];
            [board clearContents];ok=[board setString:value forType:NSPasteboardTypeString];
        }
        revision=(uint64_t)board.changeCount;
        if(ok && format==PROBE_FORMAT_FILES) {
            publishedSequence=revision;receiveBatch=nil;receiveURLs=nil;receiveBatchReserved=0;
        }
    });
    *sequence=revision;return ok;
}
int probe_file_read(unsigned index,uint64_t offset,uint8_t *data,size_t *length,uint64_t *size) {
    if(index>=sourceCount)return 0;
    struct stat st;const struct stat *old=&sourceStat[index];
    if(fstat(sourceFD[index],&st) || st.st_size!=old->st_size || st.st_mtimespec.tv_sec!=old->st_mtimespec.tv_sec ||
       st.st_mtimespec.tv_nsec!=old->st_mtimespec.tv_nsec || offset>(uint64_t)st.st_size)return 0;
    *size=(uint64_t)st.st_size;if(!data)return 1;
    if(*length>*size-offset)*length=(size_t)(*size-offset);
    if(pread(sourceFD[index],data,*length,(off_t)offset)!=(ssize_t)*length || fstat(sourceFD[index],&st))return 0;
    return st.st_size==old->st_size && st.st_mtimespec.tv_sec==old->st_mtimespec.tv_sec &&
        st.st_mtimespec.tv_nsec==old->st_mtimespec.tv_nsec && st.st_ctimespec.tv_sec==old->st_ctimespec.tv_sec &&
        st.st_ctimespec.tv_nsec==old->st_ctimespec.tv_nsec;
}
void probe_files_cancel(void) {
    if(receiveBatch) [[NSFileManager defaultManager] removeItemAtPath:receiveBatch error:NULL];
    if(receiveBatchReserved<=receiveReserved)receiveReserved-=receiveBatchReserved;
    receiveBatchReserved=0;receiveBatch=nil;receiveURLs=nil;
}
int probe_files_begin(const uint8_t *data,size_t length) {
    if(!clip_valid_files(data,length))return 0;
    uint64_t total=0;
    for(unsigned i=0;i<clip_u32(data);i++)total+=clip_file_size(data+4+i*CLIP_DESCRIPTOR_SIZE);
    if(receiveReserved+total>256u*1024u*1024u)return -10;
    // Completed batches stay available until the session closes; never delete a Finder source mid-paste.
    receiveBatch=nil;receiveURLs=nil;
    if(!receiveRoot)receiveRoot=[NSTemporaryDirectory() stringByAppendingPathComponent:[@"calabi-rdp-" stringByAppendingString:NSUUID.UUID.UUIDString]];
    receiveBatch=[receiveRoot stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
    if(![[NSFileManager defaultManager] createDirectoryAtPath:receiveBatch withIntermediateDirectories:YES
        attributes:@{NSFilePosixPermissions:@0700} error:NULL]){probe_files_cancel();return -9;}
    NSMutableArray<NSURL *> *urls=[NSMutableArray array];NSMutableSet *names=[NSMutableSet set];
    for(unsigned i=0;i<clip_u32(data);i++) {
        const uint8_t *d=data+4+i*CLIP_DESCRIPTOR_SIZE;unsigned len=0;while(len<260&&(d[72+len*2]||d[73+len*2]))len++;
        NSString *name=[[NSString alloc] initWithBytes:d+72 length:len*2 encoding:NSUTF16LittleEndianStringEncoding];
        if(!name.length || [names containsObject:name.lowercaseString] || ![name isEqualToString:name.lastPathComponent])goto fail;
        [names addObject:name.lowercaseString];
        NSURL *url=[NSURL fileURLWithPath:[receiveBatch stringByAppendingPathComponent:name]];
        int fd=open(url.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
        if(fd<0)goto fail;close(fd);[urls addObject:url];
    }
    receiveURLs=[urls copy];receiveReserved+=total;receiveBatchReserved=total;return 1;
fail:probe_files_cancel();return 0;
}
int probe_file_write(unsigned index,uint64_t offset,const uint8_t *data,size_t length) {
    if(index>=receiveURLs.count || offset+length>PROBE_FILE_LIMIT)return 0;
    int fd=open(receiveURLs[index].fileSystemRepresentation,O_WRONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return 0;ssize_t n=pwrite(fd,data,length,(off_t)offset);close(fd);return n==(ssize_t)length;
}
void probe_files_progress(uint64_t done,uint64_t total,int state) {
    uint64_t bucket=total?done*100/total:0;
    static int progressState;
    if((state==1 || state==3) && state==progressState && bucket==progressBucket)return;
    progressState=state;progressBucket=(state==1 || state==3)?bucket:UINT64_MAX;
    dispatch_async(dispatch_get_main_queue(), ^{
        NSString *heading=RDP_NS(ReceiveIncomplete), *detail=RDP_NS(CopyAgain);
        if(state==1) {
            heading=[NSString stringWithFormat:@"%@ · %llu%%",RDP_NS(ReceiveActive),(unsigned long long)bucket];
            detail=[NSString stringWithFormat:@"%.1f / %.1f MiB · %@",done/1048576.0,total/1048576.0,RDP_NS(PasteInFolder)];
        } else if(state==2) {heading=RDP_NS(ReadyToPaste);detail=RDP_NS(PasteInFolder);}
        else if(state==3) {
            heading=[NSString stringWithFormat:@"%@ · %llu%%",RDP_NS(Sending),(unsigned long long)bucket];
            detail=[NSString stringWithFormat:@"%.1f / %.1f MiB · %@",done/1048576.0,total/1048576.0,RDP_NS(CheckRemotePaste)];
        } else if(state==4) {heading=RDP_NS(Sent);detail=RDP_NS(CheckRemotePaste);}
        else switch(state) {
            case -15: heading=RDP_NS(SendFailed);detail=RDP_NS(SourceChanged);break;
            case -16: heading=RDP_NS(SendFailed);detail=RDP_NS(SessionEnded);break;
            case -17: heading=RDP_NS(SendFailed);detail=RDP_NS(OfferExpired);break;
            case -2: detail=RDP_NS(CopyLimits);break;
            case -3: detail=RDP_NS(OfferExpired);break;
            case -4: detail=RDP_NS(OfferExpired);break;
            case -5: detail=RDP_NS(NetworkTimeout);break;
            case -6: detail=RDP_NS(SourceChanged);break;
            case -7: detail=RDP_NS(CopyDataMismatch);break;
            case -8: detail=RDP_NS(TemporaryWriteFailed);break;
            case -9: detail=RDP_NS(TemporaryWriteFailed);break;
            case -10: detail=RDP_NS(TemporaryLimit);break;
            case -11: detail=RDP_NS(SessionEnded);break;
            case -12: heading=RDP_NS(ReceiveCancelled);detail=RDP_NS(PartialsRemoved);break;
            case -13: detail=RDP_NS(CopyAgain);break;
            case -14: detail=RDP_NS(ClipboardWriteFailed);break;
        }
        show_transfer_status(heading,detail,(double)bucket,state==1,state==2 || state==4);
        if(state==3)transferStatus.progress.hidden=NO;
    });
}
void probe_files_cleanup(void) {
    close_sources();
    NSString *root=receiveRoot;receiveRoot=nil;receiveBatch=nil;receiveURLs=nil;receiveReserved=receiveBatchReserved=0;
    uint64_t published=publishedSequence;publishedSequence=0;
    dispatch_async(dispatch_get_main_queue(), ^{
        NSPasteboard *board=NSPasteboard.generalPasteboard;
        if(published && (uint64_t)board.changeCount==published)[board clearContents];
        if(root)[[NSFileManager defaultManager] removeItemAtPath:root error:NULL];
    });
}
static void clipboard_exit_cleanup(void) {
    @autoreleasepool {
        close_sources();
        if(receiveRoot)[[NSFileManager defaultManager] removeItemAtPath:receiveRoot error:NULL];
    }
}
