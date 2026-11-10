#pragma once
#include <stdint.h>
#include <string.h>
// Little-endian wire format, independent of C structure padding.
#define CALFILE_MAGIC 0x32464343u
#define CALFILE_REQUEST 40u
#define CALFILE_HEADER 16u
#define CALFILE_BLOCK 65536u
#define CALFILE_MARKER "CalabiRdpStreamV2"
#define CALFILE_MARKER_SIZE 34u
static uint32_t cf_u32(const void *p){const uint8_t *b=(const uint8_t*)p;return (uint32_t)b[0]|(uint32_t)b[1]<<8|(uint32_t)b[2]<<16|(uint32_t)b[3]<<24;}
static uint64_t cf_u64(const void *p){return cf_u32(p)|((uint64_t)cf_u32((const uint8_t*)p+4)<<32);}
static void cf_put32(void *p,uint32_t n){uint8_t *b=(uint8_t*)p;for(unsigned i=0;i<4;i++)b[i]=(uint8_t)(n>>(8*i));}
static void cf_put64(void *p,uint64_t n){cf_put32(p,(uint32_t)n);cf_put32((uint8_t*)p+4,(uint32_t)(n>>32));}
