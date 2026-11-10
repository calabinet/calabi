// AppKit presentation of the shared Windows login design.
#include "rdp_locale.h"
#include "probe.h"
#include <math.h>
static NSColor *LoginColor(int r, int g, int b) {
    return [NSColor colorWithSRGBRed:r/255.0 green:g/255.0 blue:b/255.0 alpha:1];
}

static unsigned LoginPortValue(NSString *text) {
    NSCharacterSet *nonDigits = [NSCharacterSet characterSetWithCharactersInString:@"0123456789"].invertedSet;
    if (!text.length || text.length > 5 || [text rangeOfCharacterFromSet:nonDigits].location != NSNotFound) return 0;
    unsigned port = (unsigned)text.intValue;
    return port <= UINT16_MAX ? port : 0;
}

@interface LoginPanel : NSPanel
@end
@implementation LoginPanel
- (BOOL)canBecomeKeyWindow { return YES; }
@end

@interface LoginSurface : NSView
@end
@implementation LoginSurface
- (BOOL)isFlipped { return YES; }
- (BOOL)mouseDownCanMoveWindow { return YES; }
- (void)drawRect:(NSRect)dirty {
    [LoginColor(32,36,44) setFill];
    [[NSBezierPath bezierPathWithRoundedRect:self.bounds xRadius:12 yRadius:12] fill];
    NSBezierPath *rows = [NSBezierPath bezierPathWithRoundedRect:NSMakeRect(24,100,352,120) xRadius:8 yRadius:8];
    [LoginColor(42,48,58) setFill]; [rows fill];
    [LoginColor(66,73,85) setStroke]; [rows stroke];
    [LoginColor(67,74,87) setFill]; NSRectFill(NSMakeRect(36,140,328,1));
    NSRectFill(NSMakeRect(36,180,328,1));
    [LoginColor(206,216,237) setStroke];
    [[NSBezierPath bezierPathWithRoundedRect:NSMakeRect(336,43,30,20) xRadius:2 yRadius:2] stroke];
    [LoginColor(206,216,237) setFill]; NSRectFill(NSMakeRect(345,66,12,2));
}
@end

@interface LoginButton : NSButton
@property BOOL primary;
@end
@implementation LoginButton
- (void)drawRect:(NSRect)dirty {
    if (self.primary) {
        [(self.highlighted ? LoginColor(184,196,234) : LoginColor(220,227,255)) setFill];
        [[NSBezierPath bezierPathWithRoundedRect:self.bounds xRadius:self.bounds.size.height/2 yRadius:self.bounds.size.height/2] fill];
    }
    NSColor *color = self.primary ? LoginColor(37,53,101) : LoginColor(193,201,214);
    NSDictionary *attributes = @{NSFontAttributeName:self.font,
                                  NSForegroundColorAttributeName:color};
    NSSize size = [self.title sizeWithAttributes:attributes];
    [self.title drawAtPoint:NSMakePoint((self.bounds.size.width-size.width)/2,
                                      (self.bounds.size.height-size.height)/2) withAttributes:attributes];
    if (self.window.firstResponder == self) {
        [LoginColor(144,158,200) setStroke];
        [[NSBezierPath bezierPathWithRoundedRect:NSInsetRect(self.bounds,3,3) xRadius:12 yRadius:12] stroke];
    }
}
@end

@interface LoginForm : NSObject <NSWindowDelegate, NSTextFieldDelegate>
@property(nonatomic, strong) LoginPanel *panel;
@property(nonatomic, strong) NSTextField *account;
@property(nonatomic, strong) NSSecureTextField *password;
@property(nonatomic, strong) NSTextField *port;
@property(nonatomic, strong) NSTextField *hint;
@property(nonatomic, strong) LoginButton *connectButton;
@property(nonatomic, strong) LoginButton *cancelButton;
@property(nonatomic, strong) NSButton *files;
@property(nonatomic, strong) NSButton *remember;
@property(nonatomic, strong) NSButton *forgetButton;
@property(nonatomic, copy) void (^submit)(unsigned port);
@property(nonatomic, copy) void (^dismiss)(void);
@property(nonatomic, copy) void (^forget)(unsigned port);
@property(nonatomic, readonly) BOOL ssh;
@property BOOL connecting;
- (instancetype)initWithName:(NSString *)name host:(NSString *)host ssh:(BOOL)ssh;
- (void)applyPortHint:(NSString *)hint;
- (void)setStatus:(NSString *)status;
- (void)setPasswordHint:(NSString *)hint;
@end
@implementation LoginForm
- (NSTextField *)label:(NSString *)text rect:(NSRect)rect size:(CGFloat)size color:(NSColor *)color {
    NSTextField *label = [NSTextField labelWithString:text];
    label.frame = rect; label.font = [NSFont systemFontOfSize:size];
    label.textColor = color; label.lineBreakMode = NSLineBreakByTruncatingTail;
    [self.panel.contentView addSubview:label];
    return label;
}
- (LoginButton *)button:(NSString *)text rect:(NSRect)rect action:(SEL)action {
    LoginButton *button = [[LoginButton alloc] initWithFrame:rect];
    button.title = text; button.bordered = NO;
    button.font = [NSFont systemFontOfSize:14 weight:NSFontWeightMedium];
    button.target = self; button.action = action;
    [self.panel.contentView addSubview:button];
    return button;
}
- (instancetype)initWithName:(NSString *)name host:(NSString *)host {
    return [self initWithName:name host:host ssh:NO];
}
- (instancetype)initWithName:(NSString *)name host:(NSString *)host ssh:(BOOL)ssh {
    if ((self = [super init])) {
        _ssh = ssh;
        CGFloat height = ssh ? 300 : 324;
        self.panel = [[LoginPanel alloc] initWithContentRect:NSMakeRect(0,0,400,height)
            styleMask:NSWindowStyleMaskBorderless backing:NSBackingStoreBuffered defer:NO];
        self.panel.delegate = self;
        self.panel.releasedWhenClosed = NO;
        self.panel.opaque = NO; self.panel.backgroundColor = NSColor.clearColor;
        self.panel.hasShadow = YES; self.panel.movableByWindowBackground = YES;
        self.panel.appearance = [NSAppearance appearanceNamed:NSAppearanceNameDarkAqua];
        LoginSurface *surface = [[LoginSurface alloc] initWithFrame:NSMakeRect(0,0,400,height)];
        surface.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
        self.panel.contentView = surface;
        [self label:RDP_NS(Login) rect:NSMakeRect(24,16,260,20) size:12 color:LoginColor(185,196,213)];
        NSTextField *device = [self label:name.length ? name : RDP_NS(Device)
            rect:NSMakeRect(24,40,300,28) size:21 color:LoginColor(235,238,250)];
        device.font = [NSFont systemFontOfSize:21 weight:NSFontWeightSemibold];
        [self label:host rect:NSMakeRect(24,73,290,18) size:12 color:LoginColor(176,187,205)];
        NSArray<NSString *> *fieldLabels = @[RDP_NS(Account), RDP_NS(Password), RDP_NS(Port)];
        const CGFloat labelX = 36, fontSize = 13;
        NSFont *fieldFont = [NSFont systemFontOfSize:fontSize];
        NSDictionary *labelAttributes = @{NSFontAttributeName:fieldFont};
        CGFloat labelWidth = 0;
        for (NSString *label in fieldLabels) {
            CGFloat width = ceil([label sizeWithAttributes:labelAttributes].width);
            labelWidth = MAX(labelWidth, width);
        }
        labelWidth += 4; // AppKit label insets.
        CGFloat fieldX = labelX + labelWidth + 10, fieldWidth = 360 - fieldX;
        for (NSUInteger row = 0; row < fieldLabels.count; ++row)
            [self label:fieldLabels[row] rect:NSMakeRect(labelX,112+40*row,labelWidth,20) size:fontSize color:LoginColor(235,238,250)];
        self.account = [[NSTextField alloc] initWithFrame:NSMakeRect(fieldX,110,fieldWidth,24)];
        self.password = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(fieldX,150,fieldWidth,24)];
        self.port = [[NSTextField alloc] initWithFrame:NSMakeRect(fieldX,190,fieldWidth,24)];
        for (NSTextField *field in @[self.account,self.password,self.port]) {
            field.bordered = NO; field.drawsBackground = NO;
            field.textColor = LoginColor(235,238,250);
            field.font = fieldFont;
            field.focusRingType = NSFocusRingTypeNone;
            field.delegate = self;
            [self.panel.contentView addSubview:field];
        }
        self.account.placeholderString = ssh ? @"" : RDP_NS(AccountPlaceholder);
        [self setPasswordHint:ssh ? RDP_NS(SshSavedOrKeyHint) : RDP_NS(PasswordPlaceholder)];
        self.account.accessibilityLabel = fieldLabels[0];
        self.password.accessibilityLabel = fieldLabels[1];
        self.port.accessibilityLabel = fieldLabels[2];
        [self applyPortHint:nil];
        self.hint = [self label:@"" rect:NSMakeRect(24,226,352,34) size:12 color:LoginColor(255,183,160)];
        self.hint.cell.usesSingleLineMode = NO;
        self.hint.maximumNumberOfLines = 2;
        self.hint.lineBreakMode = NSLineBreakByWordWrapping;
        if (!ssh) {
            self.files = [NSButton checkboxWithTitle:RDP_NS(AllowFiles) target:nil action:nil];
            self.files.state = NSControlStateValueOn;
            self.files.frame = NSMakeRect(24,0,352,22);
            [self.panel.contentView addSubview:self.files];
        }
        self.remember = [NSButton checkboxWithTitle:RDP_NS(Remember) target:nil action:nil];
        self.remember.font = [NSFont systemFontOfSize:12];
        self.remember.toolTip = self.remember.title;
        NSString *clear = RDP_NS(ClearCredentials);
        NSFont *clearFont = [NSFont systemFontOfSize:12 weight:NSFontWeightMedium];
        CGFloat clearWidth = ceil([clear sizeWithAttributes:@{NSFontAttributeName:clearFont}].width) + 16;
        self.remember.frame = NSMakeRect(24,0,352-clearWidth-6,22);
        [self.panel.contentView addSubview:self.remember];
        self.forgetButton = [self button:clear rect:NSMakeRect(376-clearWidth,0,clearWidth,26) action:@selector(forgetPassword:)];
        self.forgetButton.font = clearFont;
        LoginButton *cancel = [self button:RDP_NS(Cancel) rect:NSMakeRect(24,0,100,32) action:@selector(cancel:)];
        cancel.keyEquivalent = @"\033";
        self.cancelButton = cancel;
        LoginButton *connect = [self button:RDP_NS(Connect) rect:NSMakeRect(246,0,130,32) action:@selector(connect:)];
        connect.primary = YES; connect.keyEquivalent = @"\r";
        self.connectButton = connect;
        LoginButton *close = [self button:@"×" rect:NSMakeRect(368,6,26,26) action:@selector(cancel:)];
        close.accessibilityLabel = RDP_NS(Close);
        self.account.nextKeyView = self.password;
        self.password.nextKeyView = self.port;
        self.port.nextKeyView = self.files ?: self.remember;
        self.files.nextKeyView = self.remember;
        self.remember.nextKeyView = self.forgetButton; self.forgetButton.nextKeyView = connect;
        connect.nextKeyView = cancel; cancel.nextKeyView = self.account;
        self.panel.initialFirstResponder = self.account;
        [self setStatus:@""];
    }
    return self;
}
- (void)applyPortHint:(NSString *)hint {
    unsigned port = LoginPortValue(hint);
    self.port.stringValue = [NSString stringWithFormat:@"%u", port ?: (self.ssh ? 22u : PROBE_RDP_DEFAULT_PORT)];
}
- (void)setPasswordHint:(NSString *)hint {
    self.password.placeholderString = hint;
    self.password.toolTip = hint;
}
- (void)setStatus:(NSString *)status {
    self.hint.stringValue = status;
    self.hint.hidden = !status.length;
    CGFloat rememberTop = NSMinY(self.hint.frame) + 6 + (status.length ? NSHeight(self.hint.frame) : 0);
    if (self.files) {
        [self.files setFrameOrigin:NSMakePoint(24,rememberTop)];
        rememberTop += 24;
    }
    [self.remember setFrameOrigin:NSMakePoint(NSMinX(self.remember.frame),rememberTop)];
    [self.forgetButton setFrameOrigin:NSMakePoint(NSMinX(self.forgetButton.frame),rememberTop-2)];
    CGFloat buttonTop = rememberTop + 26;
    [self.cancelButton setFrameOrigin:NSMakePoint(NSMinX(self.cancelButton.frame),buttonTop)];
    [self.connectButton setFrameOrigin:NSMakePoint(NSMinX(self.connectButton.frame),buttonTop)];
    NSRect frame = self.panel.frame;
    CGFloat height = buttonTop + 42;
    frame.origin.y = NSMaxY(frame) - height;
    frame.size.height = height;
    [self.panel setFrame:frame display:self.panel.visible];
}
- (unsigned)validatedPort {
    unsigned port = LoginPortValue(self.port.stringValue);
    if (!port) {
        [self setStatus:RDP_NS(InvalidPort)];
        [self.panel makeFirstResponder:self.port];
    }
    return port;
}
- (void)connect:(id)sender {
    if (self.connecting) return;
    if (![self.panel makeFirstResponder:nil]) return;
    if (!self.account.stringValue.length || [self.account.stringValue hasSuffix:@"\\"]) {
        [self setStatus:self.ssh ? RDP_NS(SshInvalidLogin) : RDP_NS(EnterAccount)];
        [self.panel makeFirstResponder:self.account];
        return;
    }
    unsigned port = [self validatedPort];
    if (!port) return;
    self.connecting = YES;
    self.account.enabled = NO; self.password.enabled = NO; self.port.enabled = NO;
    self.files.enabled = NO;
    self.remember.enabled = NO; self.forgetButton.enabled = NO;
    self.connectButton.enabled = NO;
    self.connectButton.title = RDP_NS(Connecting);
    [self setStatus:RDP_NS(CheckingLogin)];
    if (self.submit) self.submit(port);
}
- (void)failed:(NSString *)message {
    self.connecting = NO;
    self.account.enabled = YES; self.password.enabled = YES; self.port.enabled = YES;
    self.files.enabled = YES;
    self.remember.enabled = YES; self.forgetButton.enabled = YES;
    self.connectButton.enabled = YES; self.connectButton.title = RDP_NS(Connect);
    [self setStatus:message];
    [self.panel makeFirstResponder:self.password];
}
- (void)forgetPassword:(id)sender {
    if (self.connecting || !self.forget || ![self.panel makeFirstResponder:nil]) return;
    unsigned port = [self validatedPort];
    if (port) self.forget(port);
}
- (void)controlTextDidBeginEditing:(NSNotification *)notification {
    NSTextField *field = notification.object;
    if (field == self.account) field.placeholderString = @"";
    NSTextView *editor = (NSTextView *)field.currentEditor;
    editor.insertionPointColor = LoginColor(235,238,250);
}
- (void)controlTextDidEndEditing:(NSNotification *)notification {
    NSTextField *field = notification.object;
    if (field == self.account) field.placeholderString = self.ssh ? @"" : RDP_NS(AccountPlaceholder);
}
- (void)cancel:(id)sender { if (self.dismiss) self.dismiss(); }
- (BOOL)windowShouldClose:(NSWindow *)sender {
    [self cancel:sender];
    return NO;
}
- (void)show {
    self.panel.hidesOnDeactivate = NO;
    self.panel.collectionBehavior = NSWindowCollectionBehaviorMoveToActiveSpace |
                                    NSWindowCollectionBehaviorFullScreenAuxiliary;
    [self.panel center];
    [[NSNotificationCenter defaultCenter] addObserver:self selector:@selector(activated:)
        name:NSApplicationDidBecomeActiveNotification object:NSApp];
    [self.panel orderFrontRegardless];
    [NSApp activateIgnoringOtherApps:YES];
    [self focusAccount];
}
- (void)activated:(NSNotification *)notification {
    [[NSNotificationCenter defaultCenter] removeObserver:self
        name:NSApplicationDidBecomeActiveNotification object:NSApp];
    if (self.panel.visible) [self focusAccount];
}
- (void)focusAccount {
    [self.panel makeKeyAndOrderFront:nil];
    [self.panel makeFirstResponder:self.account];
    self.account.placeholderString = @"";
    NSTextView *editor = (NSTextView *)self.account.currentEditor;
    editor.insertionPointColor = LoginColor(235,238,250);
}
- (void)close {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
    [self.panel orderOut:nil];
    self.panel.delegate = nil;
    [self.panel close];
}
@end
