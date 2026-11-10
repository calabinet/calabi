#import <AppKit/AppKit.h>
#import <QuartzCore/QuartzCore.h>
#include <stdbool.h>
#include <stdint.h>

typedef void (*CalabiRelease)(void *);
typedef void (*CalabiTick)(void *, void *);

@interface CalabiRdpView : NSView
@property(nonatomic) void *context;
@property(nonatomic) CalabiTick tick;
@property(nonatomic) CalabiRelease releaseContext;
@property(nonatomic, strong) NSTimer *timer;
@end

@implementation CalabiRdpView
- (NSView *)hitTest:(NSPoint)point {
    // The web view above this layer owns keyboard, pointer and session controls.
    (void)point;
    return nil;
}

- (void)viewDidMoveToWindow {
    [super viewDidMoveToWindow];
    [self.timer invalidate];
    self.timer = nil;
    if (!self.window) return;
    __weak CalabiRdpView *weakView = self;
    self.timer = [NSTimer timerWithTimeInterval:1.0 / 60.0 repeats:YES block:^(NSTimer *timer) {
        (void)timer;
        CalabiRdpView *view = weakView;
        if (view.window.isVisible && !view.window.isMiniaturized) {
            view.tick(view.context, (__bridge void *)view);
        }
    }];
    [NSRunLoop.mainRunLoop addTimer:self.timer forMode:NSRunLoopCommonModes];
}

- (void)dealloc {
    [_timer invalidate];
    if (_releaseContext) _releaseContext(_context);
}
@end

bool calabi_rdp_view_attach(void *webviewPtr, void *context, CalabiTick tick, CalabiRelease release) {
    NSView *webview = (__bridge NSView *)webviewPtr;
    NSView *parent = webview.superview;
    if (!parent) return false;
    CalabiRdpView *view = [[CalabiRdpView alloc] initWithFrame:webview.frame];
    view.context = context;
    view.tick = tick;
    view.releaseContext = release;
    view.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    view.wantsLayer = YES;
    view.layer.backgroundColor = [NSColor colorWithSRGBRed:8.0/255 green:12.0/255 blue:22.0/255 alpha:1].CGColor;
    view.layer.contentsGravity = kCAGravityResizeAspect;
    [parent addSubview:view positioned:NSWindowBelow relativeTo:webview];
    return true;
}

static void release_pixels(void *context, const void *data, size_t size) {
    (void)data;
    (void)size;
    extern void calabi_rdp_release_pixels(void *);
    calabi_rdp_release_pixels(context);
}

bool calabi_rdp_view_present(void *viewPtr, void *owner, const uint8_t *pixels, uint32_t width, uint32_t height) {
    CalabiRdpView *view = (__bridge CalabiRdpView *)viewPtr;
    CGImageRef image = NULL;
    if (pixels) {
        size_t stride = (size_t)width * 4;
        CGDataProviderRef data = CGDataProviderCreateWithData(owner, pixels, stride * height, release_pixels);
        if (!data) {
            release_pixels(owner, pixels, stride * height);
            return false;
        }
        CGColorSpaceRef color = CGColorSpaceCreateWithName(kCGColorSpaceSRGB);
        if (color) {
            image = CGImageCreate(width, height, 8, 32, stride, color,
                                  kCGBitmapByteOrder32Little | kCGImageAlphaNoneSkipFirst,
                                  data, NULL, true, kCGRenderingIntentDefault);
            CGColorSpaceRelease(color);
        }
        CGDataProviderRelease(data);
        if (!image) return false;
    }
    [CATransaction begin];
    [CATransaction setDisableActions:YES];
    view.layer.contents = (__bridge id)image;
    [CATransaction commit];
    if (image) CGImageRelease(image);
    return true;
}
