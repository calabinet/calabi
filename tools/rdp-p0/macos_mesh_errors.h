#pragma once
#include "rdp_locale.h"

typedef NS_ENUM(NSInteger, MacMeshReceiveError) {
    MacMeshReadFailed = 1,
    MacMeshReadTimeout,
    MacMeshSessionEnded,
    MacMeshOfferExpired,
    MacMeshSourceChanged,
    MacMeshDestinationUnavailable,
};
static NSString *const macMeshErrorDomain=@"net.calabi.rdp-file-receive";

static NSError *mac_mesh_error(MacMeshReceiveError code) {
    return [NSError errorWithDomain:macMeshErrorDomain code:code userInfo:nil];
}
static NSError *mac_mesh_user_cancelled(void) {
    return [NSError errorWithDomain:NSCocoaErrorDomain code:NSUserCancelledError userInfo:nil];
}
static BOOL mac_mesh_is_user_cancelled(NSError *error) {
    return error.code==NSUserCancelledError && [error.domain isEqualToString:NSCocoaErrorDomain];
}
static NSError *mac_mesh_read_error(NSString *reply) {
    if([reply isEqualToString:@"error timeout"])return mac_mesh_error(MacMeshReadTimeout);
    if([reply isEqualToString:@"error session"] || [reply isEqualToString:@"none"])return mac_mesh_error(MacMeshSessionEnded);
    if([reply isEqualToString:@"error offer"])return mac_mesh_error(MacMeshOfferExpired);
    if([reply isEqualToString:@"error source"])return mac_mesh_error(MacMeshSourceChanged);
    return nil;
}
static NSError *mac_mesh_write_error(int code) {
    return [NSError errorWithDomain:NSPOSIXErrorDomain code:code userInfo:nil];
}
static NSString *mac_mesh_failure_detail(NSError *error) {
    if([error.domain isEqualToString:macMeshErrorDomain]){
        switch(error.code){
            case MacMeshReadTimeout: return RDP_NS(NetworkTimeout);
            case MacMeshSessionEnded: return RDP_NS(SessionEnded);
            case MacMeshOfferExpired: return RDP_NS(OfferExpired);
            case MacMeshSourceChanged: return RDP_NS(SourceChanged);
            case MacMeshDestinationUnavailable: return RDP_NS(TargetUnavailable);
            default: break;
        }
    }else if([error.domain isEqualToString:NSPOSIXErrorDomain]){
        switch(error.code){
            case EACCES: case EPERM: case EROFS: return RDP_NS(TargetReadOnly);
            case ENOSPC: case EDQUOT: return RDP_NS(DiskFull);
            case ENOENT: case ENOTDIR: case ELOOP: case ESTALE: case ENODEV:
                return RDP_NS(TargetUnavailable);
            default: return RDP_NS(TargetWriteFailed);
        }
    }
    return RDP_NS(CopyAgain);
}
