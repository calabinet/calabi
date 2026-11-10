#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __APPLE__
#include "display_layout.h"
// Thread-safe AppKit snapshot; age is milliseconds since the latest layout change.
int probe_display_snapshot(struct probe_display *display,uint64_t *age);
#endif

// Called on the worker thread. AppKit state is accessed on the main thread.
int probe_verify_leaf(const uint8_t *pem, size_t length);
void probe_frame(const uint8_t *pixels, int width, int height, unsigned stride);
enum probe_input_kind { PROBE_TEXT = 1, PROBE_SCAN, PROBE_MOVE, PROBE_LEFT_DOWN, PROBE_LEFT_UP,
                        PROBE_RIGHT_DOWN, PROBE_RIGHT_UP, PROBE_WHEEL, PROBE_HWHEEL,
                        PROBE_KEY_DOWN, PROBE_KEY_UP, PROBE_RESIZE, PROBE_REFRESH };
struct probe_input { int kind; uint16_t a, b; int16_t delta; };
int probe_next_input(struct probe_input *event);
enum { PROBE_RECONNECT_LIMIT = 6, PROBE_RECONNECT_EXHAUSTED = -3 };
int probe_requested_stop(void);
void probe_reconnecting(unsigned attempt);
enum { PROBE_RDP_DEFAULT_PORT = 3389 };
int probe_connect(const char *host, uint16_t port, const char *domain, const char *user, const char *password);
#ifdef CALABI_REMOTE_WORKSPACE
int probe_workspace_enabled(void);
int probe_workspace_active(void);
unsigned probe_workspace_selection(void);
#ifdef __APPLE__
void probe_workspace_display(unsigned width,unsigned height,unsigned scale);
#endif
#endif
