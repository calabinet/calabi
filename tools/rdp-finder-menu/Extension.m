#import <Cocoa/Cocoa.h>
#import <FinderSync/FinderSync.h>
#import "MenuHealth.h"
#import "../rdp-p0/rdp_locale.h"
#include <pwd.h>
#include <unistd.h>

@interface CalabiRemoteMenu : FIFinderSync
@property(copy) NSString *menuOffer;
@property(copy) NSURL *menuTarget;
@property(copy) NSString *menuScreenNumber;
@property NSInteger menuClipboardChangeCount;
@property(copy) NSString *menuBuildKey;
@property RdpLocale clientLocale;
@end
@implementation CalabiRemoteMenu
- (instancetype)init {
    if((self=[super init])){
        NSLog(@"FINDER_MENU_EXTENSION_V4_HEALTH");
        struct passwd *user=getpwuid(getuid());
        NSMutableSet *roots=[NSMutableSet setWithObject:[NSURL fileURLWithPath:@"/Volumes" isDirectory:YES]];
        if(user && user->pw_dir)[roots addObject:[NSURL fileURLWithPath:[NSString stringWithUTF8String:user->pw_dir] isDirectory:YES]];
        [FIFinderSyncController defaultController].directoryURLs=roots;
        NSString *build=[[NSBundle bundleForClass:self.class] objectForInfoDictionaryKey:@"MenuBuildKey"];
        self.menuBuildKey=build;
        self.clientLocale=RdpLocaleInvalid;
        if(build.length){
            [NSDistributedNotificationCenter.defaultCenter addObserver:self selector:@selector(answerMenuProbe:)
                name:MenuHealthProbe object:build suspensionBehavior:NSNotificationSuspensionBehaviorDeliverImmediately];
            [NSDistributedNotificationCenter.defaultCenter addObserver:self selector:@selector(menuLocaleChanged:)
                name:MenuLocaleUpdate object:nil suspensionBehavior:NSNotificationSuspensionBehaviorDeliverImmediately];
            [NSDistributedNotificationCenter.defaultCenter postNotificationName:MenuLocaleRequest object:build userInfo:nil deliverImmediately:YES];
        }
    }return self;
}
- (void)dealloc {
    [NSDistributedNotificationCenter.defaultCenter removeObserver:self];
}
- (void)menuLocaleChanged:(NSNotification *)notification {
    NSString *value=notification.object;
    NSString *prefix=[self.menuBuildKey stringByAppendingString:@"/"];
    if(![value hasPrefix:prefix])return;
    RdpLocale locale=rdp_locale_parse([value substringFromIndex:prefix.length].UTF8String);
    if(locale!=RdpLocaleInvalid)self.clientLocale=locale;
}
- (void)answerMenuProbe:(NSNotification *)notification {
    // Require the same queue that handles menu callbacks to be responsive.
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSDistributedNotificationCenter.defaultCenter postNotificationName:MenuHealthReply
            object:notification.object userInfo:nil deliverImmediately:YES];
    });
}
- (NSMenu *)menuForMenuKind:(FIMenuKind)kind {
    if(kind!=FIMenuKindContextualMenuForContainer)return nil;
    NSPasteboard *board=NSPasteboard.generalPasteboard;
    NSInteger changeCount=board.changeCount;
    NSString *offer=[board stringForType:@"net.calabi.mesh-file-offer"];
    NSURL *target=[FIFinderSyncController defaultController].targetedURL;
    NSLog(@"FINDER_MENU_CONTEXT marker=%d target=%d",offer.length>0,target.isFileURL);
    self.menuOffer=nil;
    self.menuTarget=nil;
    self.menuScreenNumber=nil;
    if(!offer.length || !target.isFileURL || board.changeCount!=changeCount)return nil;
    // Keep the binding here. Finder may dispatch an action with a different sender.
    self.menuOffer=offer;
    self.menuTarget=target;
    self.menuClipboardChangeCount=changeCount;
    // Record the Finder context click before the menu or the pointer can move.
    NSPoint click=NSEvent.mouseLocation;
    for(NSScreen *screen in NSScreen.screens){
        if(NSPointInRect(click,screen.frame)){
            self.menuScreenNumber=[screen.deviceDescription[@"NSScreenNumber"] stringValue];
            break;
        }
    }
    NSMenu *menu=[[NSMenu alloc] initWithTitle:@""];
    RdpLocale locale=self.clientLocale;
    if(locale==RdpLocaleInvalid)locale=rdp_locale_parse([board stringForType:RDP_PASTEBOARD_LOCALE].UTF8String);
    NSMenuItem *item=[[NSMenuItem alloc] initWithTitle:RDP_NS_IN(locale,PasteRemote) action:@selector(pasteRemoteFiles:) keyEquivalent:@""];
    item.target=self;
    NSString *path=[[NSBundle bundleForClass:self.class] pathForResource:@"calabi-menu" ofType:@"png"];
    NSImage *icon=path?[[NSImage alloc] initWithContentsOfFile:path]:nil;icon.size=NSMakeSize(16,16);item.image=icon;
    [menu addItem:item];return menu;
}
- (void)pasteRemoteFiles:(id)sender {
    (void)sender;
    NSLog(@"FINDER_MENU_ACTION");
    NSURL *target=[FIFinderSyncController defaultController].targetedURL;
    NSString *offer=self.menuOffer;
    NSPasteboard *board=NSPasteboard.generalPasteboard;
    BOOL targetMatches=target.isFileURL && [target isEqual:self.menuTarget];
    BOOL offerMatches=offer.length && [offer isEqual:[board stringForType:@"net.calabi.mesh-file-offer"]] &&
        board.changeCount==self.menuClipboardChangeCount;
    if(!targetMatches || !offerMatches){
        NSLog(@"FINDER_MENU_ACTION_REJECTED target=%d target_matches=%d offer_matches=%d",
              target.isFileURL,targetMatches,offerMatches);
        return;
    }
    NSURLComponents *request=[NSURLComponents new];request.scheme=@"calabi-remote-paste";request.host=@"paste";
    NSString *key=[[NSBundle bundleForClass:self.class] objectForInfoDictionaryKey:@"MenuBuildKey"];
    NSMutableArray<NSURLQueryItem *> *items=[@[[NSURLQueryItem queryItemWithName:@"target" value:target.absoluteString],
        [NSURLQueryItem queryItemWithName:@"offer" value:offer],
        [NSURLQueryItem queryItemWithName:@"key" value:key],
        [NSURLQueryItem queryItemWithName:@"request" value:NSUUID.UUID.UUIDString]] mutableCopy];
    if(self.menuScreenNumber) [items addObject:[NSURLQueryItem queryItemWithName:@"screen" value:self.menuScreenNumber]];
    request.queryItems=items;
    BOOL ok=[NSWorkspace.sharedWorkspace openURL:request.URL];NSLog(@"FINDER_MENU_DISPATCH ok=%d",ok);
}
@end
