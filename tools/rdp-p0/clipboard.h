#pragma once
#include <stddef.h>
#include <stdint.h>
#define PROBE_CLIPBOARD_LIMIT (1024u * 1024u)
#define PROBE_IMAGE_LIMIT (32u * 1024u * 1024u)
#define PROBE_IMAGE_SEND_LIMIT (2u * 1024u * 1024u)
#define PROBE_FILE_LIMIT (100u * 1024u * 1024u)
#define PROBE_FILE_COUNT 32u
#define PROBE_FORMAT_TEXT 13u
#define PROBE_FORMAT_DIB 8u
#define PROBE_FORMAT_FILES 0xc001u
#define PROBE_FORMAT_BRIDGE 0xc002u
#define PROBE_FORMAT_PNG 0xc004u
// The first workspace selection sampled the local revision without exporting it.
#define PROBE_CLIPBOARD_INITIAL_SELECTION 4
// UTF-16LE including the terminating zero. Caller owns returned memory.
int probe_clipboard_enabled(void);
int probe_clipboard_content_enabled(void);
int probe_clipboard_files_enabled(void);
int probe_clipboard_read(uint8_t **text, size_t *length, uint32_t *format, uint64_t *sequence);
int probe_clipboard_write(const uint8_t *text, size_t length, uint32_t format, uint64_t expected, uint64_t *sequence);
int probe_file_read(unsigned index, uint64_t offset, uint8_t *data, size_t *length, uint64_t *size);
int probe_files_begin(const uint8_t *descriptors, size_t length);
int probe_file_write(unsigned index, uint64_t offset, const uint8_t *data, size_t length);
void probe_files_cancel(void);
void probe_files_progress(uint64_t done, uint64_t total, int state);
void probe_files_cleanup(void);
void clipboard_cancel_files(void);
void clipboard_cancel_send(void);
int probe_file_lock(uint32_t id);
void probe_file_unlock(uint32_t id);
void probe_file_unlock_all(void);
int probe_file_read_locked(uint32_t id,unsigned index,uint64_t offset,uint8_t *data,size_t *length,uint64_t *size);
