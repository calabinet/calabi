#pragma once
#import <Security/Security.h>
#include "probe.h"
#include <string.h>

// Preview builds use the current user's file-based keychain and its app ACL.
// Never broaden the ACL when an updated helper needs to be authorized again.
static OSStatus mac_rdp_password(NSString *service, unsigned port, NSString *account, NSString **read, NSString *write) {
    if (!service.length || !account.length) return errSecParam;
    // Keep existing Keychain items accessible on the default port.
    if (port != PROBE_RDP_DEFAULT_PORT) service = [service stringByAppendingFormat:@"/%u", port];
    const char *label = service.UTF8String;
    const char *user = account.lowercaseString.UTF8String;
    UInt32 labelLength = (UInt32)strlen(label), userLength = (UInt32)strlen(user);
    SecKeychainRef keychain = NULL;
    OSStatus status = SecKeychainCopyDomainDefault(kSecPreferencesDomainUser, &keychain);
    if (status != errSecSuccess) return status;
    SecKeychainItemRef item = NULL;
    UInt32 size = 0;
    void *data = NULL;
    status = SecKeychainFindGenericPassword(keychain, labelLength, label, userLength, user,
        read ? &size : NULL, read ? &data : NULL, &item);
    if (read) {
        if (status == errSecSuccess && data && size && size <= 2047)
            *read = [[NSString alloc] initWithBytes:data length:size encoding:NSUTF8StringEncoding];
        if (data) {
            volatile unsigned char *secret = data;
            for (UInt32 i = 0; i < size; ++i) secret[i] = 0;
            SecKeychainItemFreeContent(NULL, data);
        }
    } else if (write) {
        const char *password = write.UTF8String;
        size_t length = strlen(password);
        if (!length || length > 2047) status = errSecParam;
        else if (status == errSecSuccess)
            status = SecKeychainItemModifyAttributesAndData(item, NULL, (UInt32)length, password);
        else if (status == errSecItemNotFound)
            status = SecKeychainAddGenericPassword(keychain, labelLength, label, userLength, user,
                (UInt32)length, password, NULL);
    } else if (status == errSecSuccess) {
        status = SecKeychainItemDelete(item);
    }
    if (item) CFRelease(item);
    CFRelease(keychain);
    return status;
}
