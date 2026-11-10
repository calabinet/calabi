#pragma once
// Coordinates and palette mirror shell-paste-progress.h (Windows), in AppKit points.
static NSColor *mesh_progress_color(int r,int g,int b){return [NSColor colorWithSRGBRed:r/255.0 green:g/255.0 blue:b/255.0 alpha:1];}
@interface CalabiMeshProgressView : NSView
@property(weak) CalabiMeshReceive *batch;
@property BOOL expanded;
@property NSUInteger page;
@property RdpLocale drawnLocale;
@property(strong) NSTimer *languageTimer;
@end
@implementation CalabiMeshProgressView
- (BOOL)isFlipped{return YES;}
- (BOOL)acceptsFirstMouse:(NSEvent*)event{(void)event;return YES;}
- (void)viewDidMoveToWindow {
    [super viewDidMoveToWindow];
    [self.languageTimer invalidate];self.languageTimer=nil;
    if(!self.window)return;
    __weak CalabiMeshProgressView *weakView=self;
    self.languageTimer=[NSTimer scheduledTimerWithTimeInterval:1 repeats:YES block:^(NSTimer *timer){
        (void)timer;
        CalabiMeshProgressView *view=weakView;
        if(view.window.isVisible && view.drawnLocale!=rdp_locale_current())view.needsDisplay=YES;
    }];
}
- (void)dealloc {[self.languageTimer invalidate];}
- (CGFloat)footerY{return 254+MIN((NSUInteger)5,self.batch.names.count)*50+6;}
- (void)text:(NSString*)text rect:(NSRect)rect color:(NSColor*)color size:(CGFloat)size bold:(BOOL)bold align:(NSTextAlignment)align {
    NSMutableParagraphStyle *style=[NSMutableParagraphStyle new];style.lineBreakMode=NSLineBreakByTruncatingTail;style.alignment=align;
    NSDictionary *attributes=@{NSFontAttributeName:[NSFont systemFontOfSize:size weight:bold?NSFontWeightSemibold:NSFontWeightRegular],NSForegroundColorAttributeName:color,NSParagraphStyleAttributeName:style};
    NSSize measured=[text sizeWithAttributes:attributes];rect.origin.y+=MAX(0,(rect.size.height-measured.height)/2);
    [text drawInRect:rect withAttributes:attributes];
}
- (RdpMessage)state:(NSUInteger)i {
    CalabiMeshReceive *b=self.batch;BOOL touched=[b.touched containsIndex:i];BOOL complete=touched && b.received[i].unsignedLongLongValue==b.sizes[i].unsignedLongLongValue;
    if(b.failure && i==b.currentIndex)return b.cancelled?Rdp_Cancelled:Rdp_Failed;
    if(complete)return b.finished && !b.cancelled && !b.failure?Rdp_Completed:Rdp_Received;
    if(b.cancelled)return Rdp_Cancelled;
    if(b.finished)return touched?Rdp_Incomplete:Rdp_NotTransferred;
    return touched?Rdp_Transferring:Rdp_Waiting;
}
- (NSString*)bytes:(NSUInteger)i {
    CalabiMeshReceive *b=self.batch;uint64_t done=b.received[i].unsignedLongLongValue,size=b.sizes[i].unsignedLongLongValue;
    unsigned pct=size?(unsigned)(100*MIN(done,size)/size):([b.touched containsIndex:i]?100:0);
    return [NSString stringWithFormat:@"%@ / %@  ·  %u%%",mac_mesh_size(done),mac_mesh_size(size),pct];
}
- (void)drawRect:(NSRect)dirty {
    (void)dirty;[NSGraphicsContext saveGraphicsState];NSAffineTransform *scale=[NSAffineTransform transform];[scale scaleBy:0.875];[scale concat];[mesh_progress_color(31,36,44) setFill];NSRectFill(NSMakeRect(0,0,self.bounds.size.width/0.875,self.bounds.size.height/0.875));
    CalabiMeshReceive *b=self.batch;if(!b){[NSGraphicsContext restoreGraphicsState];return;}
    RdpLocale locale=rdp_locale_current();
    if(self.drawnLocale!=locale){
        self.drawnLocale=locale;
        self.window.title=[@"Calabi · " stringByAppendingString:RDP_NS_IN(locale,ReceiveTitle)];
    }
#define PROGRESS_TEXT(key) RDP_NS_IN(locale,key)
    NSColor *primary=mesh_progress_color(240,244,252),*secondary=mesh_progress_color(171,185,206),*link=mesh_progress_color(180,198,255);
    NSColor *cancelledColor=mesh_progress_color(255,180,165);
    [self text:[@"CALABI  /  " stringByAppendingString:PROGRESS_TEXT(CopyTitle)] rect:NSMakeRect(24,17,426,22) color:mesh_progress_color(160,174,196) size:15 bold:NO align:NSTextAlignmentLeft];
    NSString *heading=b.cancelled?PROGRESS_TEXT(ReceiveCancelled):b.failure?PROGRESS_TEXT(ReceiveIncomplete):b.finished?PROGRESS_TEXT(ReceiveDone):PROGRESS_TEXT(ReceiveActive);
    [self text:heading rect:NSMakeRect(24,47,428,33) color:primary size:22 bold:YES align:NSTextAlignmentLeft];
    uint64_t sum=0;NSUInteger completed=0;
    for(NSUInteger i=0;i<b.sizes.count;i++){
        sum+=b.received[i].unsignedLongLongValue;
        if(!(b.failure && i==b.currentIndex) && [b.touched containsIndex:i] && [b.received[i] isEqual:b.sizes[i]])completed++;
    }
    sum=MIN(sum,b.total);unsigned pct=b.total?(unsigned)(100*sum/b.total):(b.finished && !b.failure?100:0);
    NSString *total=[NSString stringWithFormat:@"%@  %@ / %@  ·  %u%%  ·  %@ %lu/%lu",PROGRESS_TEXT(TotalProgress),mac_mesh_size(sum),mac_mesh_size(b.total),pct,PROGRESS_TEXT(Received),(unsigned long)completed,(unsigned long)b.sizes.count];
    [self text:total rect:NSMakeRect(24,83,428,26) color:secondary size:15 bold:NO align:NSTextAlignmentLeft];
    [mesh_progress_color(61,70,85) setFill];NSRectFill(NSMakeRect(24,117,428,6));
    [(b.cancelled?mesh_progress_color(144,151,163):mesh_progress_color(145,172,255)) setFill];NSRectFill(NSMakeRect(24,117,428*pct/100.0,6));
    if(b.names.count){
        NSUInteger current=MIN(b.currentIndex,b.names.count-1);
        if(!b.finished && !b.cancelled && !b.failure){[mesh_progress_color(46,58,78) setFill];NSRectFill(NSMakeRect(16,130,444,71));[mesh_progress_color(161,184,255) setFill];NSRectFill(NSMakeRect(16,130,3,71));}
        [self text:b.names[current] rect:NSMakeRect(24,134,428,26) color:primary size:15 bold:NO align:NSTextAlignmentLeft];
        RdpMessage state=[self state:current];
        NSString *status=[NSString stringWithUTF8String:rdp_text_in(locale,state)];
        NSColor *statusColor=state==Rdp_Cancelled?cancelledColor:secondary;
        [self text:[NSString stringWithFormat:@"%@  ·  %@",status,[self bytes:current]] rect:NSMakeRect(24,163,428,26) color:statusColor size:15 bold:NO align:NSTextAlignmentLeft];
    }
    if(b.failure && !b.cancelled){
        NSDictionary *attributes=@{NSFontAttributeName:[NSFont systemFontOfSize:13],NSForegroundColorAttributeName:secondary};
        [mac_mesh_failure_detail(b.failure) drawWithRect:NSMakeRect(24,189,428,31) options:NSStringDrawingUsesLineFragmentOrigin|NSStringDrawingTruncatesLastVisibleLine attributes:attributes];
    }
    [self text:self.expanded?PROGRESS_TEXT(Collapse):PROGRESS_TEXT(Expand) rect:NSMakeRect(24,220,220,28) color:link size:15 bold:NO align:NSTextAlignmentLeft];
    if(self.expanded){
        NSUInteger pages=MAX(1,(b.names.count+4)/5);self.page=MIN(self.page,pages-1);
        for(NSUInteger i=self.page*5;i<MIN(b.names.count,(self.page+1)*5);i++){
            CGFloat y=254+(i-self.page*5)*50;
            [self text:b.names[i] rect:NSMakeRect(24,y,256,23) color:mesh_progress_color(220,229,242) size:15 bold:NO align:NSTextAlignmentLeft];
            RdpMessage state=[self state:i];
            NSString *status=[NSString stringWithUTF8String:rdp_text_in(locale,state)];
            NSColor *statusColor=i==b.currentIndex && state==Rdp_Cancelled?cancelledColor:secondary;
            [self text:status rect:NSMakeRect(290,y,162,23) color:statusColor size:15 bold:NO align:NSTextAlignmentRight];
            [self text:[self bytes:i] rect:NSMakeRect(24,y+23,428,22) color:mesh_progress_color(153,169,193) size:15 bold:NO align:NSTextAlignmentLeft];
        }
        [self text:[NSString stringWithFormat:@"%lu / %lu",(unsigned long)self.page+1,(unsigned long)pages] rect:NSMakeRect(24,[self footerY],196,28) color:secondary size:15 bold:NO align:NSTextAlignmentLeft];
        [self text:PROGRESS_TEXT(Previous) rect:NSMakeRect(270,[self footerY],80,28) color:link size:15 bold:NO align:NSTextAlignmentLeft];
        [self text:PROGRESS_TEXT(Next) rect:NSMakeRect(360,[self footerY],92,28) color:link size:15 bold:NO align:NSTextAlignmentLeft];
    }
    CGFloat y=self.bounds.size.height/0.875-54;
    [self text:PROGRESS_TEXT(Hide) rect:NSMakeRect(24,y,88,36) color:mesh_progress_color(205,215,231) size:15 bold:NO align:NSTextAlignmentCenter];
    [mesh_progress_color(219,226,255) setFill];NSRectFill(NSMakeRect(320,y,136,36));
    [self text:b.finished||b.cancelled||b.failure?PROGRESS_TEXT(Close):PROGRESS_TEXT(Cancel) rect:NSMakeRect(320,y,136,36) color:mesh_progress_color(34,49,85) size:15 bold:NO align:NSTextAlignmentCenter];
#undef PROGRESS_TEXT
    [NSGraphicsContext restoreGraphicsState];[mesh_progress_color(100,110,125) setStroke];NSFrameRectWithWidth(self.bounds,1);
}
- (void)mouseDown:(NSEvent*)event {
    NSPoint p=[self convertPoint:event.locationInWindow fromView:nil];p.x/=0.875;p.y/=0.875;CGFloat y=self.bounds.size.height/0.875-54;
    if(NSPointInRect(p,NSMakeRect(24,220,220,28))){
        self.expanded=!self.expanded;CGFloat height=(self.expanded?[self footerY]+90:310)*0.875;NSRect frame=self.window.frame;
        NSRect visible=(self.window.screen?:NSScreen.mainScreen).visibleFrame;
        frame.size=NSMakeSize(420,height);frame.origin.y=MAX(NSMinY(visible),MIN(frame.origin.y,NSMaxY(visible)-height));
        [self.window setFrame:frame display:YES];self.needsDisplay=YES;
    }else if(NSPointInRect(p,NSMakeRect(24,y,88,36))){[self.batch hideProgress];}
    else if(NSPointInRect(p,NSMakeRect(320,y,136,36))){
        if(!self.batch||self.batch.finished||self.batch.cancelled||self.batch.failure){[self.batch hideProgress];}
        else [self.batch cancelReceive:nil];
    }else if(self.expanded && NSPointInRect(p,NSMakeRect(270,[self footerY],80,28))){if(self.page)self.page--;self.needsDisplay=YES;}
    else if(self.expanded && NSPointInRect(p,NSMakeRect(360,[self footerY],92,28))){if((self.page+1)*5<self.batch.names.count)self.page++;self.needsDisplay=YES;}
}
@end
