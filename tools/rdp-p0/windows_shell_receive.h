#pragma once
#include <stdint.h>
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
int shell_receive_offer(const uint8_t *data,size_t length,uint64_t generation,uint64_t sequence);
void shell_receive_stop(void);
void shell_receive_invalidate(void);
// Reads run on the Shell copy worker. Implemented by the RDP channel adapter.
int clipboard_shell_read(uint64_t generation,unsigned index,uint64_t offset,void *data,unsigned count);
void clipboard_shell_cancel(uint64_t generation);
#ifdef __cplusplus
}
#endif
