#import <Foundation/Foundation.h>

// A matching build key separates the installed host from stale extension
// processes. Sandboxed extensions can post with a string object and nil userInfo.
static NSString *const MenuHealthProbe = @"net.calabi.rdp-finder-menu.health.probe";
static NSString *const MenuHealthReply = @"net.calabi.rdp-finder-menu.health.reply";
static NSString *const MenuLocaleRequest = @"net.calabi.rdp-finder-menu.locale.request";
static NSString *const MenuLocaleUpdate = @"net.calabi.rdp-finder-menu.locale.update";
