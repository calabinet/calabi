#pragma once
#include <shellapi.h>
static int clipboardFilesEnabled;
int probe_clipboard_enabled(void) { return 1; }
int probe_clipboard_content_enabled(void) { return 1; }
int probe_clipboard_files_enabled(void) { return clipboardFilesEnabled; }
#include "windows_copy_bridge.h"
#include "windows_files.h"

int probe_clipboard_read(uint8_t **text, size_t *length, uint32_t *format, uint64_t *sequence) {
#ifdef CALABI_REMOTE_WORKSPACE
    if(!probe_workspace_active())return 0;
#endif
    *text = NULL; *length = 0; *format = PROBE_FORMAT_TEXT;
    DWORD current = GetClipboardSequenceNumber();
#ifdef CALABI_REMOTE_WORKSPACE
    static unsigned selection;
    unsigned selected=probe_workspace_selection();
    if(selected!=selection){selection=selected;*sequence=current;return 3;}
#endif
    if (current == *sequence && !getenv("CALABI_RDP_FILE_BRIDGE")) return 1;
    if (!OpenClipboard(NULL)) return 0;
    if(getenv("CALABI_RDP_FILE_MESH") && IsClipboardFormatAvailable(CF_HDROP)){
        *sequence=GetClipboardSequenceNumber();CloseClipboard();return 3;
    }
    if(IsClipboardFormatAvailable(RegisterClipboardFormatW(L"CalabiRdpCopyOwnedV1"))){
        *sequence=GetClipboardSequenceNumber();CloseClipboard();return 3;
    }
    if(clipboardFilesEnabled && IsClipboardFormatAvailable(CF_HDROP)){
        int bridge=copy_bridge_read((HDROP)GetClipboardData(CF_HDROP),current,text,length,format);
        if(bridge>=0){CloseClipboard();if(!bridge)return 0;*sequence=current;return bridge;}
    }
    if(current==*sequence){CloseClipboard();return 1;}
    *sequence = GetClipboardSequenceNumber();
    close_file_sources();
    if(IsClipboardFormatAvailable(CF_HDROP)) {
        if(clipboardFilesEnabled) {
            *text=read_drop_files((HDROP)GetClipboardData(CF_HDROP),length);
            if(*text)*format=PROBE_FORMAT_FILES;
            else probe_files_progress(0,0,-2);
        }
        CloseClipboard();return 1;
    }
    if (!IsClipboardFormatAvailable(CF_HDROP) && IsClipboardFormatAvailable(CF_DIB)) {
        HANDLE h=GetClipboardData(CF_DIB); SIZE_T n=h?GlobalSize(h):0;
        const BYTE *p=h?GlobalLock(h):NULL;
        if(p && clip_valid_dib(p,n)) {
            *text=malloc(n);if(*text){memcpy(*text,p,n);*length=n;*format=PROBE_FORMAT_DIB;}
        }
        if(p)GlobalUnlock(h);CloseClipboard();return 1;
    }
    BOOL hasText = !IsClipboardFormatAvailable(CF_HDROP) && IsClipboardFormatAvailable(CF_UNICODETEXT);
    HANDLE data = hasText ? GetClipboardData(CF_UNICODETEXT) : NULL;
    if (hasText && !data) { CloseClipboard(); return 0; }
    SIZE_T size = data ? GlobalSize(data) : 0;
    if (size >= 2 && size <= PROBE_CLIPBOARD_LIMIT && !(size % 2)) {
        const wchar_t *value = GlobalLock(data);
        if (!value) { CloseClipboard(); return 0; }
        if (value) {
            size_t units = 0;
            while (units < size/2 && value[units]) units++;
            if (units < size/2) {
                *length = (units+1)*2;
                *text = malloc(*length);
                if (*text) memcpy(*text, value, *length);
                else { GlobalUnlock(data); CloseClipboard(); *length = 0; return 0; }
            }
            GlobalUnlock(data);
        }
    }
    CloseClipboard();
    return 1;
}

int probe_clipboard_write(const uint8_t *text, size_t length, uint32_t format, uint64_t expected, uint64_t *sequence) {
#ifdef CALABI_REMOTE_WORKSPACE
    if(!probe_workspace_active())return 0;
#endif
    if(format==PROBE_FORMAT_FILES)return publish_received_files(expected,sequence);
    if(format!=PROBE_FORMAT_TEXT && (format!=PROBE_FORMAT_DIB || !clip_valid_dib(text,length)))return 0;
    HGLOBAL data = GlobalAlloc(GMEM_MOVEABLE, length);
    if (!data) return 0;
    void *target = GlobalLock(data);
    if (!target) { GlobalFree(data); return 0; }
    memcpy(target, text, length);
    GlobalUnlock(data);
    if (!OpenClipboard(window)) { GlobalFree(data); return 0; }
    BOOL ok = GetClipboardSequenceNumber() == expected && EmptyClipboard() &&
              SetClipboardData(format, data) != NULL;
    if (ok) *sequence = GetClipboardSequenceNumber();
    CloseClipboard();
    if (!ok) GlobalFree(data);
    return ok;
}
