#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
typedef wchar_t RdpText;
#define RDP_LITERAL_(s) L##s
#else
typedef char RdpText;
#define RDP_LITERAL_(s) s
#endif
#define RDP_LITERAL(s) RDP_LITERAL_(s)

typedef enum {
    RdpLocaleInvalid = -1, RdpLocaleEnglish, RdpLocaleSimplified, RdpLocaleTraditional,
    RdpLocaleJapanese, RdpLocaleKorean, RdpLocaleGerman, RdpLocaleFrench,
    RdpLocaleSpanish, RdpLocaleItalian, RdpLocalePortuguese, RdpLocaleCount
} RdpLocale;
static const char *const rdp_locale_codes[] = {"en","zh-CN","zh-TW","ja","ko","de","fr","es","it","pt"};

static inline RdpLocale rdp_locale_parse(const char *code) {
    if(code)for(int i=0;i<RdpLocaleCount;i++)if(!strcmp(code,rdp_locale_codes[i]))return (RdpLocale)i;
    return RdpLocaleInvalid;
}
static inline RdpLocale rdp_locale_current(void) {
    char code[16]={0};
#ifdef _WIN32
    wchar_t path[32768];
    DWORD length=GetEnvironmentVariableW(L"CALABI_UI_LOCALE_FILE",path,32768);
    if(length && length<32768){
        HANDLE file=CreateFileW(path,GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
        if(file!=INVALID_HANDLE_VALUE){
            DWORD read=0;
            if(!ReadFile(file,code,sizeof(code)-1,&read,NULL) || read>=sizeof(code)-1)code[0]=0;
            CloseHandle(file);
        }
    }
#else
    const char *path=getenv("CALABI_UI_LOCALE_FILE");
    FILE *file=path?fopen(path,"rb"):NULL;
    if(file){
        size_t length=fread(code,1,sizeof(code)-1,file);
        if(length>=sizeof(code)-1)code[0]=0;
        fclose(file);
    }
#endif
    RdpLocale locale=rdp_locale_parse(code);
    if(locale==RdpLocaleInvalid){
#ifdef _WIN32
        DWORD length=GetEnvironmentVariableA("CALABI_UI_LOCALE",code,sizeof(code));
        if(length && length<sizeof(code))locale=rdp_locale_parse(code);
#else
        locale=rdp_locale_parse(getenv("CALABI_UI_LOCALE"));
#endif
    }
    return locale==RdpLocaleInvalid?RdpLocaleEnglish:locale;
}

typedef enum {
#define RDP_MESSAGE(key, ...) Rdp_##key,
#include "rdp_strings.inc"
#undef RDP_MESSAGE
} RdpMessage;

static inline const RdpText *rdp_text_in(RdpLocale locale,RdpMessage message) {
    static const RdpText *const strings[][RdpLocaleCount]={
#define RDP_MESSAGE(key,en,cn,tw,ja,ko,de,fr,es,it,pt) \
        {RDP_LITERAL(en),RDP_LITERAL(cn),RDP_LITERAL(tw),RDP_LITERAL(ja),RDP_LITERAL(ko), \
         RDP_LITERAL(de),RDP_LITERAL(fr),RDP_LITERAL(es),RDP_LITERAL(it),RDP_LITERAL(pt)},
#include "rdp_strings.inc"
#undef RDP_MESSAGE
    };
    return strings[message][locale>=0 && locale<RdpLocaleCount?locale:RdpLocaleEnglish];
}

static inline const RdpText *rdp_text(RdpMessage message) {
    return rdp_text_in(rdp_locale_current(),message);
}

#ifdef __OBJC__
#define RDP_PASTEBOARD_LOCALE @"net.calabi.mesh-file-offer-locale"
#define RDP_NS_IN(locale,key) [NSString stringWithUTF8String:rdp_text_in(locale,Rdp_##key)]
#define RDP_NS(key) [NSString stringWithUTF8String:rdp_text(Rdp_##key)]
#endif
