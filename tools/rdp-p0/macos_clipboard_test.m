// Named test pasteboard only: never read or overwrite the user's general pasteboard.
#import <AppKit/AppKit.h>
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
static __weak NSWindow *sessionWindow;
void clipboard_cancel_files(void) {}
#include "macos_clipboard.h"

static void expect_mesh_owned(NSPasteboard *board){
    uint64_t expected=(uint64_t)board.changeCount;
    __block BOOL done=NO;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY,0),^{
        uint8_t *data=NULL;size_t length=0;uint32_t format=0;uint64_t sequence=UINT64_MAX;
        assert(probe_clipboard_read_board(board,&data,&length,&format,&sequence)==3);
        assert(sequence==expected && !data && !length && !format);
        dispatch_async(dispatch_get_main_queue(),^{done=YES;});
    });
    NSDate *deadline=[NSDate dateWithTimeIntervalSinceNow:5];
    while(!done && deadline.timeIntervalSinceNow>0)[NSRunLoop.currentRunLoop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.01]];
    assert(done);
}

int main(void) {
    @autoreleasepool {
        NSPasteboard *board=[NSPasteboard pasteboardWithUniqueName];
        // Independently encoded 2x2 RGBA PNG: top red/blue, bottom green/transparent.
        // Do not create the fixture with the same drawing API being tested.
        static const uint8_t fixture[]={
            0x89,0x50,0x4e,0x47,0x0d,0x0a,0x1a,0x0a,0x00,0x00,0x00,0x0d,0x49,0x48,0x44,0x52,
            0x00,0x00,0x00,0x02,0x00,0x00,0x00,0x02,0x08,0x06,0x00,0x00,0x00,0x72,0xb6,0x0d,
            0x24,0x00,0x00,0x00,0x14,0x49,0x44,0x41,0x54,0x78,0x9c,0x63,0xf8,0xcf,0xc0,0x00,
            0x42,0x60,0xea,0x3f,0x03,0x03,0x03,0x03,0x00,0x3f,0xd2,0x05,0xfb,0x0d,0x08,0xf4,
            0x6f,0x00,0x00,0x00,0x00,0x49,0x45,0x4e,0x44,0xae,0x42,0x60,0x82};
        NSData *png=[NSData dataWithBytes:fixture length:sizeof(fixture)];
        assert([board setData:png forType:NSPasteboardTypePNG]);
        uint32_t imageFormat;
        NSData *snapshot=copied_image([board dataForType:NSPasteboardTypePNG], &imageFormat);
        size_t pngSize=clip_image_png_size(snapshot.bytes,snapshot.length);
        assert(imageFormat==PROBE_FORMAT_PNG && pngSize==png.length);
        assert(!memcmp((const uint8_t *)snapshot.bytes+4,png.bytes,png.length));
        const uint8_t *p=(const uint8_t *)snapshot.bytes+4+pngSize;
        assert(clip_u32(p+4)==2 && clip_u32(p+8)==2);
        // Bottom-up BGR: top-left red is in the second scanline.
        assert(p[48]==0 && p[49]==0 && p[50]==255);
        assert(p[52]==255 && p[53]==0 && p[54]==0);
        assert(p[40]==0 && p[41]==255 && p[42]==0);
        assert(p[44]==255 && p[45]==255 && p[46]==255);
        // A screen-sized, compressible PNG retains its pixels while the DIB stays bounded.
        CGColorSpaceRef rgb=CGColorSpaceCreateDeviceRGB();
        assert(rgb);
        CGContextRef screen=CGBitmapContextCreate(NULL,2880,1800,8,2880*4,rgb,
            kCGImageAlphaNoneSkipLast | kCGBitmapByteOrder32Big);
        CGColorSpaceRelease(rgb);
        assert(screen);
        CGContextSetRGBFillColor(screen,0.2,0.4,0.6,1);
        CGContextFillRect(screen,CGRectMake(0,0,2880,1800));
        CGImageRef screenImage=CGBitmapContextCreateImage(screen);
        CGContextRelease(screen);
        assert(screenImage);
        NSData *screenPNG=encode_clipboard_png(screenImage);
        CGImageRelease(screenImage);
        assert(screenPNG);
        snapshot=copied_image(screenPNG,&imageFormat);
        pngSize=clip_image_png_size(snapshot.bytes,snapshot.length);
        assert(imageFormat==PROBE_FORMAT_PNG && pngSize==screenPNG.length);
        assert(!memcmp((const uint8_t *)snapshot.bytes+4,screenPNG.bytes,pngSize));
        assert(snapshot.length-4-pngSize<=PROBE_IMAGE_SEND_LIMIT);
        p=(const uint8_t *)snapshot.bytes+4+pngSize;
        assert(clip_u32(p+4)<2880 && clip_u32(p+8)<1800);
        NSString *folder=[NSTemporaryDirectory() stringByAppendingPathComponent:NSUUID.UUID.UUIDString];
        assert([[NSFileManager defaultManager] createDirectoryAtPath:folder withIntermediateDirectories:YES attributes:nil error:NULL]);
        NSURL *a=[NSURL fileURLWithPath:[folder stringByAppendingPathComponent:@"中文.txt"]];
        NSURL *b=[NSURL fileURLWithPath:[folder stringByAppendingPathComponent:@"empty.txt"]];
        assert([@"test" writeToURL:a atomically:YES encoding:NSUTF8StringEncoding error:NULL]);
        assert([[NSData data] writeToURL:b atomically:YES]);
        [board clearContents];assert(([board writeObjects:@[a,b]]));
        NSData *files=copied_files(board);assert(files && clip_valid_files(files.bytes,files.length));
        assert(sourceCount==2 && clip_u32(files.bytes)==2);
        uint8_t bytes[4]={0};size_t length=4;uint64_t size=0;
        assert(probe_file_read(0,0,bytes,&length,&size) && length==4 && !memcmp(bytes,"test",4));
        assert(probe_files_begin(files.bytes,files.length));
        assert(probe_file_write(0,0,bytes,4));
        assert([[NSData dataWithContentsOfURL:receiveURLs[0]] isEqualToData:[NSData dataWithBytes:"test" length:4]]);
        assert([[NSData dataWithContentsOfURL:receiveURLs[1]] length]==0);
        int fd=open(a.fileSystemRepresentation,O_WRONLY|O_APPEND);assert(fd>=0);assert(write(fd,"x",1)==1);close(fd);
        length=4;assert(!probe_file_read(0,0,bytes,&length,&size));
        assert(receiveReserved==4);probe_files_cancel();assert(receiveReserved==0);
        assert(probe_files_begin(files.bytes,files.length)==1);probe_files_cancel();assert(receiveReserved==0);
        close_sources();
        [board clearContents];assert([board writeObjects:@[[NSURL fileURLWithPath:folder]]]);assert(!copied_files(board));
        setenv("CALABI_RDP_FILE_MESH","1",1);
        [board clearContents];assert([board setString:@"fixture-offer" forType:@"net.calabi.mesh-file-offer"]);expect_mesh_owned(board);
        [board clearContents];assert([board writeObjects:@[a]]);expect_mesh_owned(board);
        unsetenv("CALABI_RDP_FILE_MESH");
        clipboard_exit_cleanup();
        assert([[NSFileManager defaultManager] removeItemAtPath:folder error:NULL]);
        [board releaseGlobally];
        puts("macOS image/file clipboard fixtures passed");
    }
    return 0;
}
