#import <AppKit/AppKit.h>
#import <CommonCrypto/CommonDigest.h>
#import <FinderSync/FinderSync.h>
#import "macos_login.h"
#import "macos_ssh_login.h"
#import "macos_rdp_credentials.h"
#include "probe.h"
#include "rdp_login_record.h"
#include "clipboard.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <signal.h>

// Single-session lab window. Credentials are entered locally in AppKit.
static NSString *fingerprint;
static BOOL managedPin;
static NSString *certificateError;
static NSMutableArray<NSValue *> *inputs;
static atomic_bool sessionClosed;
static atomic_bool sessionWorkerActive;
static BOOL inputReady; // guarded by inputs
int probe_requested_stop(void) { return atomic_load(&sessionClosed); }
bool calabi_rdp_request_stop(void) {
    atomic_store(&sessionClosed, true);
    return !atomic_load(&sessionWorkerActive);
}
static __weak NSWindow *sessionWindow;
static LoginForm *pendingLogin;
static dispatch_source_t focusSignal;
static void (^firstLoginRecord)(void);
static NSObject *displayStateLock;
static struct probe_display requestedDisplay;
static NSTimeInterval displayChangedAt;
static BOOL haveDisplay;
int probe_display_snapshot(struct probe_display *out,uint64_t *age) {
    @synchronized(displayStateLock){
        if(!haveDisplay)return 0;
        *out=requestedDisplay;
        NSTimeInterval elapsed=NSProcessInfo.processInfo.systemUptime-displayChangedAt;
        *age=elapsed>0?(uint64_t)(elapsed*1000):0;return 1;
    }
}
static void record_display(struct probe_display next) {
    @synchronized(displayStateLock){
        if(!haveDisplay || !probe_display_equal(&next,&requestedDisplay)){
            requestedDisplay=next;haveDisplay=YES;displayChangedAt=NSProcessInfo.processInfo.systemUptime;
        }
    }
}
#ifdef CALABI_REMOTE_WORKSPACE
void probe_workspace_display(unsigned width,unsigned height,unsigned scale) {
    struct probe_display next;
    if(!probe_display_make(width,height,scale/100.0,&next))return;
    record_display(next);
}
#endif
#include "macos_clipboard.h"
#include "macos_mesh_copy.h"

// Desktop mode revalidates ownership, address and certificate via the parent
// desktop's private pipe. Only the certificate seen on the wire is compared;
// it can never become the trusted value.
static BOOL verifyDevicePin(NSString *actual) {
    if (!managedPin) return fingerprint.length == 64 && [actual isEqualToString:fingerprint];
    char reply[80];
    fprintf(stdout,"rdp-pin %s\n",actual.UTF8String); fflush(stdout);
    if (fgets(reply,sizeof(reply),stdin)) {
        NSString *pin = [[[NSString stringWithUTF8String:reply]
            stringByTrimmingCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet] uppercaseString];
        if (pin.length == 64 && [pin isEqualToString:actual]) return YES;
    }
    certificateError = RDP_NS(VerifyFailed);
    return NO;
}

int probe_verify_leaf(const uint8_t *pem, size_t length) {
    @autoreleasepool {
        NSString *chain = [[NSString alloc] initWithBytes:pem length:length encoding:NSASCIIStringEncoding];
        if (!chain) return 0;
        NSRange begin = [chain rangeOfString:@"-----BEGIN CERTIFICATE-----"];
        NSRange end = [chain rangeOfString:@"-----END CERTIFICATE-----"];
        if (begin.location == NSNotFound || end.location == NSNotFound || end.location <= NSMaxRange(begin)) return 0;
        NSString *leaf = [chain substringWithRange:NSMakeRange(NSMaxRange(begin), end.location - NSMaxRange(begin))];
        NSData *der = [[NSData alloc] initWithBase64EncodedString:leaf options:NSDataBase64DecodingIgnoreUnknownCharacters];
        if (!der.length || der.length > UINT32_MAX) return 0;
        unsigned char hash[CC_SHA256_DIGEST_LENGTH];
        CC_SHA256(der.bytes, (CC_LONG)der.length, hash);
        NSMutableString *actual = [NSMutableString string];
        for (size_t i = 0; i < sizeof(hash); ++i) [actual appendFormat:@"%02X", hash[i]];
        return verifyDevicePin(actual);
    }
}

static BOOL enqueue(struct probe_input event) {
    @synchronized(inputs) {
        if (!inputReady) return NO;
        if (event.kind == PROBE_MOVE && inputs.count) {
            struct probe_input tail;
            [inputs.lastObject getValue:&tail size:sizeof(tail)];
            if (tail.kind == PROBE_MOVE) [inputs removeLastObject];
        }
        if (inputs.count >= 256 && event.kind != PROBE_LEFT_UP && event.kind != PROBE_RIGHT_UP) return NO;
        [inputs addObject:[NSValue valueWithBytes:&event objCType:@encode(struct probe_input)]];
        return YES;
    }
}

int probe_next_input(struct probe_input *event) {
    @autoreleasepool {
        @synchronized(inputs) {
            if (!inputs.count) return 0;
            [inputs.firstObject getValue:event size:sizeof(*event)];
            [inputs removeObjectAtIndex:0];
            return 1;
        }
    }
}

@interface ProbeView : NSView <NSTextInputClient>
@property(copy) NSString *preedit;
@property NSRange preeditSelection;
@property NSPoint inputAnchor;
@property BOOL leftHeld, rightHeld, controlClick;
@property CGFloat wheelRemainderX, wheelRemainderY;
@property NSPoint lastPixel;
@property(strong) NSBitmapImageRep *frameImage;
@property(copy) NSString *connectionStatus;
- (void)recordDisplay;
@end

@implementation ProbeView
- (void)recordDisplay {
#ifdef CALABI_REMOTE_WORKSPACE
    if(probe_workspace_enabled())return;
#endif
    if(!displayStateLock || !self.window || self.window.miniaturized || NSIsEmptyRect(self.bounds))return;
    NSRect backing=[self convertRectToBacking:self.bounds];
    CGFloat ratio=NSWidth(backing)/NSWidth(self.bounds);
    struct probe_display next;
    if(!probe_display_make(NSWidth(self.bounds),NSHeight(self.bounds),ratio,&next))return;
    record_display(next);
}
- (void)displayChanged:(NSNotification*)notification {(void)notification;[self recordDisplay];}
- (void)setFrameSize:(NSSize)size {[super setFrameSize:size];[self recordDisplay];}
- (void)viewDidMoveToWindow {[super viewDidMoveToWindow];[self recordDisplay];}
- (void)viewDidChangeBackingProperties {[super viewDidChangeBackingProperties];[self recordDisplay];self.needsDisplay=YES;}
- (BOOL)acceptsFirstResponder { return YES; }
- (NSRect)desktopRect {
    NSInteger w = self.frameImage.pixelsWide, h = self.frameImage.pixelsHigh;
    if (w <= 0 || h <= 0 || NSIsEmptyRect(self.bounds)) return NSZeroRect;
    CGFloat scale = MIN(NSWidth(self.bounds) / w, NSHeight(self.bounds) / h);
    return NSMakeRect(NSMidX(self.bounds) - w * scale / 2,
                      NSMidY(self.bounds) - h * scale / 2, w * scale, h * scale);
}
- (void)drawRect:(NSRect)dirty {
    [super drawRect:dirty];
    [[NSColor blackColor] setFill];
    NSRectFill(dirty);
    [self.frameImage drawInRect:[self desktopRect]];
    if (self.connectionStatus.length) {
        NSDictionary *style = @{NSForegroundColorAttributeName: NSColor.whiteColor,
                                NSFontAttributeName: [NSFont systemFontOfSize:16]};
        NSSize size = [self.connectionStatus sizeWithAttributes:style];
        [self.connectionStatus drawAtPoint:NSMakePoint(MAX(8, NSMidX(self.bounds)-size.width/2),
                                                     NSMidY(self.bounds)-size.height/2) withAttributes:style];
    }
    if (self.preedit.length) {
        [self.preedit drawAtPoint:self.inputAnchor withAttributes:@{
            NSForegroundColorAttributeName:NSColor.labelColor,
            NSBackgroundColorAttributeName:NSColor.textBackgroundColor,
            NSUnderlineStyleAttributeName:@(NSUnderlineStyleSingle)}];
    }
}
- (BOOL)acceptsFirstMouse:(NSEvent *)event { return YES; }
- (BOOL)locatePointer:(NSEvent *)event clamp:(BOOL)clamp {
    NSPoint p = [self convertPoint:event.locationInWindow fromView:nil];
    NSRect r = [self desktopRect];
    if (NSIsEmptyRect(r) || (!clamp && !NSPointInRect(p, r))) return NO;
    NSInteger w = self.frameImage.pixelsWide, h = self.frameImage.pixelsHigh;
    self.lastPixel = NSMakePoint(MAX(0, MIN(w-1, floor((p.x-NSMinX(r))*w/NSWidth(r)))),
                                 MAX(0, MIN(h-1, floor((NSMaxY(r)-p.y)*h/NSHeight(r)))));
    return YES;
}
- (BOOL)pointer:(int)kind delta:(int)delta {
    return enqueue((struct probe_input){kind, self.lastPixel.x, self.lastPixel.y, delta});
}
- (void)press:(NSEvent *)event right:(BOOL)right {
    if (![self locatePointer:event clamp:NO]) return;
    [self.window makeFirstResponder:self];
    self.inputAnchor = [self convertPoint:event.locationInWindow fromView:nil];
    if (right && !self.rightHeld) self.rightHeld = [self pointer:PROBE_RIGHT_DOWN delta:0];
    if (!right && !self.leftHeld) self.leftHeld = [self pointer:PROBE_LEFT_DOWN delta:0];
}
- (void)releaseRight:(BOOL)right {
    if (right && self.rightHeld) { [self pointer:PROBE_RIGHT_UP delta:0]; self.rightHeld = NO; }
    if (!right && self.leftHeld) { [self pointer:PROBE_LEFT_UP delta:0]; self.leftHeld = NO; }
}
- (void)mouseDown:(NSEvent *)event {
    self.controlClick = (event.modifierFlags & NSEventModifierFlagControl) != 0;
    [self press:event right:self.controlClick];
}
- (void)rightMouseDown:(NSEvent *)event { [self press:event right:YES]; }
- (void)mouseUp:(NSEvent *)event {
    [self locatePointer:event clamp:YES]; [self releaseRight:self.controlClick]; self.controlClick = NO;
}
- (void)rightMouseUp:(NSEvent *)event { [self locatePointer:event clamp:YES]; [self releaseRight:YES]; }
- (void)mouseMoved:(NSEvent *)event {
    if ([self locatePointer:event clamp:self.leftHeld || self.rightHeld]) [self pointer:PROBE_MOVE delta:0];
}
- (void)mouseDragged:(NSEvent *)event { [self mouseMoved:event]; }
- (void)rightMouseDragged:(NSEvent *)event { [self mouseMoved:event]; }
- (void)scrollWheel:(NSEvent *)event {
    if (![self locatePointer:event clamp:NO]) return;
    CGFloat unit = event.hasPreciseScrollingDeltas ? 4.0 : 120.0;
    self.wheelRemainderX -= event.scrollingDeltaX * unit;
    self.wheelRemainderY += event.scrollingDeltaY * unit;
    int dx = MAX(-255, MIN(255, trunc(self.wheelRemainderX)));
    int dy = MAX(-255, MIN(255, trunc(self.wheelRemainderY)));
    self.wheelRemainderX = fmod(self.wheelRemainderX, 1);
    self.wheelRemainderY = fmod(self.wheelRemainderY, 1);
    if (dy) [self pointer:PROBE_WHEEL delta:dy];
    if (dx) [self pointer:PROBE_HWHEEL delta:dx];
}
- (void)releasePointer {
    [self releaseRight:NO]; [self releaseRight:YES];
    self.controlClick = NO;
    self.wheelRemainderX = self.wheelRemainderY = 0;
}
- (void)windowLostFocus:(NSNotification *)notification { [self releasePointer]; }
- (void)keyDown:(NSEvent *)event {
    if (event.modifierFlags & NSEventModifierFlagControl) {
        NSString *key = event.charactersIgnoringModifiers.lowercaseString;
        if ([key isEqualToString:@"c"]) { [self copy:nil]; return; }
        if ([key isEqualToString:@"v"]) { [self paste:nil]; return; }
        if ([key isEqualToString:@"x"]) { [self cut:nil]; return; }
    }
    if (!self.frameImage || event.modifierFlags & (NSEventModifierFlagCommand | NSEventModifierFlagControl)) return;
    [self interpretKeyEvents:@[event]];
}
- (void)clipboardShortcut:(uint16_t)scan {
    if (!self.frameImage || self.hasMarkedText) return;
    @synchronized(inputs) {
        if (inputs.count > 252) { NSBeep(); return; }
        enqueue((struct probe_input){PROBE_KEY_DOWN, 0x1d, 0});
        enqueue((struct probe_input){PROBE_KEY_DOWN, scan, 0});
        enqueue((struct probe_input){PROBE_KEY_UP, scan, 0});
        enqueue((struct probe_input){PROBE_KEY_UP, 0x1d, 0});
    }
}
- (void)copy:(id)sender { [self clipboardShortcut:0x2e]; }
- (void)paste:(id)sender { [self clipboardShortcut:0x2f]; }
- (void)cut:(id)sender { [self clipboardShortcut:0x2d]; }

- (void)setMarkedText:(id)value selectedRange:(NSRange)selection replacementRange:(NSRange)replacement {
    self.preedit = [value isKindOfClass:NSAttributedString.class] ? [value string] : value;
    self.preeditSelection = selection;
    self.needsDisplay = YES;
}
- (BOOL)hasMarkedText { return self.preedit.length > 0; }
- (NSRange)markedRange { return self.hasMarkedText ? NSMakeRange(0, self.preedit.length) : NSMakeRange(NSNotFound, 0); }
- (NSRange)selectedRange { return self.hasMarkedText ? self.preeditSelection : NSMakeRange(0, 0); }
- (void)unmarkText { self.preedit = nil; self.needsDisplay = YES; }
- (NSArray *)validAttributesForMarkedText { return @[]; }
- (NSAttributedString *)attributedSubstringForProposedRange:(NSRange)range actualRange:(NSRangePointer)actual {
    if (range.location != NSNotFound && range.location < self.preedit.length) {
        NSRange part = NSIntersectionRange(range, self.markedRange);
        if (actual) *actual = part;
        return [[NSAttributedString alloc] initWithString:[self.preedit substringWithRange:part]];
    }
    if (actual) *actual = NSMakeRange(NSNotFound, 0);
    return nil;
}
- (NSUInteger)characterIndexForPoint:(NSPoint)point { return NSNotFound; }
- (NSRect)firstRectForCharacterRange:(NSRange)range actualRange:(NSRangePointer)actual {
    if (actual) *actual = self.selectedRange;
    NSRect anchor = NSMakeRect(self.inputAnchor.x, self.inputAnchor.y, 1, 18);
    return [self.window convertRectToScreen:[self convertRect:anchor toView:nil]];
}
- (void)insertText:(id)value replacementRange:(NSRange)replacement {
    [self unmarkText];
    if (!self.frameImage) return;
    NSString *text = [value isKindOfClass:NSAttributedString.class] ? [value string] : value;
    @synchronized(inputs) {
        // Admit a commit atomically, including both UTF-16 units of supplementary characters.
        if (inputs.count >= 256 || text.length > 256 - inputs.count) { NSBeep(); return; }
        for (NSUInteger i = 0; i < text.length; ++i) {
            unichar unit = [text characterAtIndex:i];
            if (unit >= 32 && unit != 127) enqueue((struct probe_input){PROBE_TEXT, unit, 0});
        }
    }
}
- (void)doCommandBySelector:(SEL)command {
    if (!self.frameImage || self.hasMarkedText) return;
    unsigned short scan, extended = 0;
    if (command == @selector(deleteBackward:)) scan = 0x0e;
    else if (command == @selector(deleteForward:)) { scan = 0x53; extended = 1; }
    else if (command == @selector(insertNewline:) || command == @selector(insertLineBreak:) ||
             command == @selector(insertNewlineIgnoringFieldEditor:)) scan = 0x1c;
    else if (command == @selector(insertTab:)) scan = 0x0f;
    else if (command == @selector(cancelOperation:)) scan = 0x01;
    else if (command == @selector(moveLeft:)) { scan = 0x4b; extended = 1; }
    else if (command == @selector(moveRight:)) { scan = 0x4d; extended = 1; }
    else if (command == @selector(moveUp:)) { scan = 0x48; extended = 1; }
    else if (command == @selector(moveDown:)) { scan = 0x50; extended = 1; }
    else return;
    enqueue((struct probe_input){PROBE_SCAN, scan, extended});
}
- (BOOL)resignFirstResponder {
    [self releasePointer];
    [self.inputContext discardMarkedText];
    [self unmarkText];
    return [super resignFirstResponder];
}
@end

void probe_reconnecting(unsigned attempt) {
    dispatch_sync(dispatch_get_main_queue(), ^{
        @synchronized(inputs) { inputReady = NO; [inputs removeAllObjects]; }
        ProbeView *view = (ProbeView *)sessionWindow.contentView;
        if (![view isKindOfClass:ProbeView.class]) return;
        view.frameImage = nil;
        [view releasePointer];
        [view.inputContext discardMarkedText];
        [view unmarkText];
        NSLog(@"RDP_RECONNECT_V1 attempt=%u limit=%d", attempt, PROBE_RECONNECT_LIMIT);
        view.connectionStatus = [NSString stringWithFormat:@"%@ (%u/%d)", RDP_NS(Reconnecting), attempt, PROBE_RECONNECT_LIMIT];
        view.needsDisplay = YES;
    });
}

// GDI supplies BGRA bytes. Desktop pixels are opaque, regardless of the
// contents of the fourth byte. AppKit gets an explicit packed RGB bitmap.
static void copy_opaque_rgb(uint8_t *dst, size_t dst_stride, const uint8_t *src,
                            size_t src_stride, int width, int height) {
    for (int y = 0; y < height; ++y) {
        const uint8_t *in = src + y * src_stride;
        uint8_t *out = dst + y * dst_stride;
        for (int x = 0; x < width; ++x, in += 4, out += 3) {
            out[0] = in[2];
            out[1] = in[1];
            out[2] = in[0];
        }
    }
}

void probe_frame(const uint8_t *pixels, int width, int height, unsigned stride) {
    // Hand off synchronously: FreeRDP owns pixels until this callback returns.
    dispatch_sync(dispatch_get_main_queue(), ^{
        ProbeView *view = (ProbeView *)sessionWindow.contentView;
        if (![view isKindOfClass:ProbeView.class]) return;
#ifdef CALABI_REMOTE_WORKSPACE
        if(probe_workspace_enabled() && !pendingLogin)return;
#endif
        NSBitmapImageRep *image = view.frameImage;
        if (!image || image.pixelsWide != width || image.pixelsHigh != height) {
            image = [[NSBitmapImageRep alloc] initWithBitmapDataPlanes:NULL pixelsWide:width
                pixelsHigh:height bitsPerSample:8 samplesPerPixel:3 hasAlpha:NO isPlanar:NO
                colorSpaceName:NSDeviceRGBColorSpace bitmapFormat:0
                bytesPerRow:0 bitsPerPixel:24];
            if (image) fprintf(stderr, "Calabi RDP desktop: %d x %d\n", width, height);
            view.frameImage = image;
        }
        if (!image.bitmapData) return;
        copy_opaque_rgb(image.bitmapData, image.bytesPerRow, pixels, stride, width, height);
        view.connectionStatus = nil;
        @synchronized(inputs) { inputReady = YES; }
        view.needsDisplay = YES;
        if (pendingLogin) {
            if (firstLoginRecord) firstLoginRecord();
            firstLoginRecord = nil;
            [pendingLogin close];
            pendingLogin.submit = nil;
            pendingLogin.dismiss = nil;
            pendingLogin.forget = nil;
            pendingLogin = nil;
#ifdef CALABI_REMOTE_WORKSPACE
            if(probe_workspace_enabled()){
                puts("rdp-workspace-connected");fflush(stdout);return;
            }
#endif
            [sessionWindow makeKeyAndOrderFront:nil];
            [sessionWindow makeFirstResponder:view];
            if(!(sessionWindow.styleMask & NSWindowStyleMaskFullScreen)){
                NSLog(@"RDP_DEFAULT_FULLSCREEN_V1");
                [sessionWindow toggleFullScreen:nil];
            }
        }
    });
}

void mac_show_finder_menu_settings(void) {
    dispatch_async(dispatch_get_main_queue(), ^{
        [FIFinderSyncController showExtensionManagementInterface];
    });
}

const char *calabi_rdp_finder_settings_title(void) {
    return rdp_text(Rdp_FinderSettings);
}

void calabi_rdp_prompt(void *nativeWindow) {
    atexit(clipboard_exit_cleanup);
    atexit(mac_mesh_exit_cleanup);
    NSString *logDirectory = [NSHomeDirectory() stringByAppendingPathComponent:@"Library/Logs/Calabi"];
    if ([[NSFileManager defaultManager] createDirectoryAtPath:logDirectory
           withIntermediateDirectories:YES attributes:nil error:NULL]) {
        NSString *logFile = [logDirectory stringByAppendingPathComponent:@"rdp-clipboard.log"];
        setenv("CALABI_RDP_CLIP_LOG", logFile.fileSystemRepresentation, 1);
        NSString *displayLog=[logDirectory stringByAppendingPathComponent:@"rdp-display.log"];
        setenv("CALABI_RDP_DISPLAY_LOG",displayLog.fileSystemRepresentation,1);
        NSString *menuLog=[logDirectory stringByAppendingPathComponent:@"rdp-file-menu.log"];
        setenv("CALABI_RDP_MESH_LOG",menuLog.fileSystemRepresentation,1);
    }
    NSWindow *window = (__bridge NSWindow *)nativeWindow;
    window.title = [@"Calabi · " stringByAppendingString:RDP_NS(Login)];
    sessionWindow = window;
    atomic_store(&sessionClosed, false);
    [NSNotificationCenter.defaultCenter addObserverForName:NSWindowWillCloseNotification object:window
        queue:nil usingBlock:^(NSNotification *note) { (void)note; atomic_store(&sessionClosed, true); }];
    displayStateLock=[NSObject new];haveDisplay=NO;
    NSDictionary<NSString *, NSString *> *env = NSProcessInfo.processInfo.environment;
    NSString *host = env[@"CALABI_P0_PEER"];
    fingerprint = [env[@"CALABI_P0_SHA256"] uppercaseString];
    managedPin = env[@"CALABI_RDP_LOCAL"].length > 0;
    inputs = [NSMutableArray array];
    if (!host.length) {
        dispatch_async(dispatch_get_main_queue(), ^{
            NSAlert *message = [[NSAlert alloc] init];
            message.messageText = RDP_NS(OpenFromDevices);
            [message runModal];
            [window close];
        });
        return;
    }
    ProbeView *view = [[ProbeView alloc] initWithFrame:window.contentView.bounds];
    view.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    window.contentView = view;
    window.contentMinSize=NSMakeSize(320,200);
    window.collectionBehavior |= NSWindowCollectionBehaviorFullScreenPrimary;
    window.acceptsMouseMovedEvents = YES;
    window.movableByWindowBackground = NO;
    [[NSNotificationCenter defaultCenter] addObserver:view selector:@selector(windowLostFocus:)
        name:NSWindowDidResignKeyNotification object:window];
    for(NSNotificationName name in @[NSWindowDidResizeNotification,NSWindowDidChangeScreenNotification,
        NSWindowDidChangeBackingPropertiesNotification,NSWindowDidEnterFullScreenNotification,
        NSWindowDidExitFullScreenNotification,NSWindowDidDeminiaturizeNotification]){
        [NSNotificationCenter.defaultCenter addObserver:view selector:@selector(displayChanged:) name:name object:window];
    }
    [NSNotificationCenter.defaultCenter addObserver:view selector:@selector(displayChanged:)
        name:NSApplicationDidChangeScreenParametersNotification object:nil];
    [view recordDisplay];
    NSString *name = env[@"CALABI_RDP_NAME"];
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSApp activateIgnoringOtherApps:YES];
        LoginForm *login = [[LoginForm alloc] initWithName:name host:host];
        [login applyPortHint:env[@"CALABI_RDP_PORT"]];
        NSString *key = env[@"CALABI_RDP_CREDENTIAL_KEY"];
        NSString *service = key.length == 64 ? [@"Calabi/RDP/" stringByAppendingString:key] : nil;
        login.remember.hidden = login.forgetButton.hidden = service == nil;
        NSString *previous = env[@"CALABI_RDP_ACCOUNT_HINT"];
        if (previous.length) {
            login.account.stringValue = previous;
            if (service) [login setPasswordHint:RDP_NS(UseSaved)];
        }
        __weak LoginForm *weakLogin = login;
        login.forget = ^(unsigned port) {
            LoginForm *form = weakLogin;
            OSStatus status = mac_rdp_password(service, port, form.account.stringValue, NULL, nil);
            if (status == errSecSuccess || status == errSecItemNotFound)
                [form setPasswordHint:RDP_NS(PasswordPlaceholder)];
            [form setStatus:status == errSecSuccess ? RDP_NS(Cleared) :
                status == errSecItemNotFound ? RDP_NS(NoCredentials) : RDP_NS(ClearFailed)];
        };
        login.submit = ^(unsigned port) {
            LoginForm *form = weakLogin;
            clipboardEnabled = true;
            clipboardFilesEnabled = form.files.state == NSControlStateValueOn;
            NSString *account = form.account.stringValue;
            NSString *u = account, *d = @"", *p = form.password.stringValue;
            NSString *saved = nil;
            if (!p.length && service) {
                OSStatus status = mac_rdp_password(service, port, account, &saved, nil);
                if (status == errSecSuccess && saved.length) p = saved;
                else if (status != errSecItemNotFound) {
                    [form failed:RDP_NS(ReadFailed)];
                    return;
                }
            }
            BOOL usedSaved = saved.length > 0;
            BOOL remember = service && form.remember.state == NSControlStateValueOn && !usedSaved;
            firstLoginRecord = ^{
                if (remember && p.length && mac_rdp_password(service, port, account, NULL, p) != errSecSuccess)
                    NSLog(@"Unable to save the RDP password in the user keychain");
                if (service) rdp_record_login(account.UTF8String, port);
            };
            NSRange separator = [u rangeOfString:@"\\"];
            if (separator.location != NSNotFound) {
                d = [u substringToIndex:separator.location];
                u = [u substringFromIndex:separator.location + 1];
            }
            form.password.stringValue = @"";
            certificateError = nil;
            pendingLogin = form;
            NSScreen *screen=form.panel.screen;
            if(screen && window.screen!=screen){NSRect visible=screen.visibleFrame,frame=window.frame;
                [window setFrameOrigin:NSMakePoint(NSMidX(visible)-frame.size.width/2,NSMidY(visible)-frame.size.height/2)];}
#ifdef CALABI_REMOTE_WORKSPACE
            if(probe_workspace_enabled()) report_login_display(screen);
            if(probe_workspace_enabled() && screen){
                NSRect bounds=screen.frame;
                probe_workspace_display((unsigned)round(NSWidth(bounds)),(unsigned)round(NSHeight(bounds)),
                    (unsigned)round(screen.backingScaleFactor*100));
            }else
#endif
                [view recordDisplay];
            atomic_store(&sessionWorkerActive, true);
            dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
                int result = probe_connect(host.UTF8String, (uint16_t)port, d.UTF8String, u.UTF8String, p.UTF8String);
                dispatch_async(dispatch_get_main_queue(), ^{
                    atomic_store(&sessionWorkerActive, false);
                    if (probe_requested_stop()) return;
                    firstLoginRecord = nil;
                    BOOL rejected = rdp_password_rejected((unsigned)result);
                    if (rejected && usedSaved) {
                        mac_rdp_password(service, port, account, NULL, nil);
                        [form setPasswordHint:RDP_NS(PasswordPlaceholder)];
                    }
                    if (pendingLogin == form) {
                        NSString *message = certificateError;
                        if (!message) {
                            message = rejected
                                ? (usedSaved ? RDP_NS(SavedRejected) : RDP_NS(LoginFailed))
                                : [NSString stringWithFormat:@"%@ (%@ 0x%08X)", RDP_NS(ConnectFailed), RDP_NS(Code), (unsigned)result];
                        }
                        [form failed:message];
                    } else {
#ifdef CALABI_REMOTE_WORKSPACE
                        if(probe_workspace_enabled()){[window close];return;}
#endif
                        @synchronized(inputs) { inputReady = NO; [inputs removeAllObjects]; }
                        view.frameImage = nil;
                        view.needsDisplay = YES;
                        view.connectionStatus = result == PROBE_RECONNECT_EXHAUSTED
                            ? RDP_NS(ReconnectFailed)
                            : certificateError ?: [NSString stringWithFormat:@"%@ (%@ 0x%08X)", RDP_NS(Disconnected), RDP_NS(Code), (unsigned)result];
                        window.title = [@"Calabi · " stringByAppendingString:RDP_NS(Disconnected)];
                    }
                });
            });
        };
        login.dismiss = ^{
            LoginForm *form = weakLogin;
            form.password.stringValue = @"";
            [form close];
            form.submit = nil;
            form.dismiss = nil;
            form.forget = nil;
            firstLoginRecord = nil;
            pendingLogin = nil;
            [window close];
        };
        pendingLogin = login;
        [login show];
        if (!focusSignal) {
            signal(SIGUSR1, SIG_IGN);
            focusSignal = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGUSR1, 0, dispatch_get_main_queue());
            if (focusSignal) {
                dispatch_source_set_event_handler(focusSignal, ^{
                    NSWindow *active = pendingLogin.panel ?: sessionWindow;
                    if (!active || probe_requested_stop()) return;
                    [NSApp unhide:nil];
                    if (active.miniaturized) [active deminiaturize:nil];
                    [active makeKeyAndOrderFront:nil];
                    [NSApp activateIgnoringOtherApps:YES];
                });
                dispatch_resume(focusSignal);
                puts("rdp-focus-ready");
                fflush(stdout);
            }
        }
    });
}
