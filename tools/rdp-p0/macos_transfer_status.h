#pragma once
#include "rdp_locale.h"
// A child of the session view, so it remains visible in macOS full screen.
@interface CalabiTransferStatus : NSView
@property(strong) NSTextField *heading;
@property(strong) NSTextField *detail;
@property(strong) NSProgressIndicator *progress;
@property(strong) NSButton *action;
@property BOOL receiving;
@property NSUInteger revision;
@end
@implementation CalabiTransferStatus
- (instancetype)initWithFrame:(NSRect)frame {
    if((self=[super initWithFrame:frame])) {
        self.appearance=[NSAppearance appearanceNamed:NSAppearanceNameDarkAqua];
        self.heading=[NSTextField labelWithString:@""];
        self.heading.font=[NSFont systemFontOfSize:13 weight:NSFontWeightSemibold];
        self.heading.textColor=[NSColor colorWithSRGBRed:0.92 green:0.94 blue:0.98 alpha:1];
        self.detail=[NSTextField wrappingLabelWithString:@""];
        self.detail.font=[NSFont systemFontOfSize:11];self.detail.textColor=[NSColor colorWithSRGBRed:0.72 green:0.77 blue:0.85 alpha:1];
        self.progress=[[NSProgressIndicator alloc] init];self.progress.indeterminate=NO;self.progress.minValue=0;self.progress.maxValue=100;
        self.action=[NSButton buttonWithTitle:RDP_NS(Cancel) target:self action:@selector(performAction:)];
        for(NSView *v in @[self.heading,self.detail,self.progress,self.action]) [self addSubview:v];
        self.accessibilityLabel=RDP_NS(CopyTitle);
    }
    return self;
}
- (void)layout {
    [super layout];CGFloat w=self.bounds.size.width;
    self.heading.frame=NSMakeRect(16,76,w-100,20);
    self.detail.frame=NSMakeRect(16,30,w-32,40);
    self.progress.frame=NSMakeRect(16,14,w-32,8);
    self.action.frame=NSMakeRect(w-76,73,60,26);
}
- (void)drawRect:(NSRect)rect {
    [[NSColor colorWithSRGBRed:0.12 green:0.14 blue:0.18 alpha:0.97] setFill];
    NSBezierPath *shape=[NSBezierPath bezierPathWithRoundedRect:NSInsetRect(self.bounds,0.5,0.5) xRadius:12 yRadius:12];
    [shape fill];[[NSColor colorWithSRGBRed:0.32 green:0.37 blue:0.48 alpha:1] setStroke];[shape stroke];
}
- (void)mouseDown:(NSEvent *)event { (void)event; }
- (void)mouseUp:(NSEvent *)event { (void)event; }
- (void)mouseDragged:(NSEvent *)event { (void)event; }
- (void)rightMouseDown:(NSEvent *)event { (void)event; }
- (void)rightMouseUp:(NSEvent *)event { (void)event; }
- (void)scrollWheel:(NSEvent *)event { (void)event; }
- (void)performAction:(id)sender {
    (void)sender;
    if(self.receiving){clipboard_cancel_files();self.action.enabled=NO;self.detail.stringValue=RDP_NS(Cancelling);}
    else self.hidden=YES;
    [self.window makeFirstResponder:self.superview];
}
@end
static __weak CalabiTransferStatus *transferStatus;
static void show_transfer_status(NSString *heading,NSString *detail,double percent,BOOL active,BOOL success) {
    NSView *parent=sessionWindow.contentView;
    if(!parent)return;
    CalabiTransferStatus *card=transferStatus;
    if(!card || card.superview!=parent) {
        card=[[CalabiTransferStatus alloc] initWithFrame:NSMakeRect(0,0,380,112)];
        card.translatesAutoresizingMaskIntoConstraints=NO;[parent addSubview:card];transferStatus=card;
        NSLayoutConstraint *width=[card.widthAnchor constraintEqualToConstant:380];width.priority=750;
        [NSLayoutConstraint activateConstraints:@[width,
            [card.widthAnchor constraintLessThanOrEqualToAnchor:parent.widthAnchor constant:-32],
            [card.heightAnchor constraintEqualToConstant:112],
            [card.trailingAnchor constraintEqualToAnchor:parent.trailingAnchor constant:-16],
            [card.topAnchor constraintEqualToAnchor:parent.topAnchor constant:16]]];
    }
    card.hidden=NO;card.receiving=active;card.action.enabled=YES;
    card.action.title=active?RDP_NS(Cancel):RDP_NS(Hide);
    card.heading.stringValue=heading;card.detail.stringValue=detail;
    card.progress.hidden=!active;card.progress.doubleValue=percent;
    NSUInteger revision=++card.revision;
    if(success)dispatch_after(dispatch_time(DISPATCH_TIME_NOW,8*NSEC_PER_SEC),dispatch_get_main_queue(),^{
        if(card.revision==revision)card.hidden=YES;
    });
}
