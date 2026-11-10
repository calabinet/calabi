#pragma once
#include <stdio.h>
#include <string.h>

static int rdp_password_rejected(unsigned code) {
    return code==0x00020014 || code==0x00020015 || code==0x00020009 || code==0x0002001b;
}

// The private parent pipe receives the account label and optional port after the first frame.
static void rdp_record_login(const char *account, unsigned port) {
    if (!account || !*account || strlen(account)>2047) return;
    static const char hex[]="0123456789abcdef";
    char line[sizeof("rdp-login-port 65535 ")+4094];
    int offset=port?snprintf(line,sizeof(line),"rdp-login-port %u ",port):snprintf(line,sizeof(line),"rdp-login-ok ");
    char *out=line+offset;
    for (const unsigned char *p=(const unsigned char *)account; *p; ++p) {
        *out++=hex[*p>>4]; *out++=hex[*p&15];
    }
    *out=0;
    puts(line);fflush(stdout);
}
