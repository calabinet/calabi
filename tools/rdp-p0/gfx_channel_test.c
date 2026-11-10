#include <assert.h>
#include <stdio.h>
#include "gfx_channel.h"
#include "dynamic_channels.h"

static void *surface_data;
static unsigned painted, ended;

static UINT set_surface(RdpgfxClientContext *channel, UINT16 id, void *data) {
    (void)channel;
    assert(id == 1);
    surface_data = data;
    return CHANNEL_RC_OK;
}

static void *get_surface(RdpgfxClientContext *channel, UINT16 id) {
    (void)channel;
    assert(id == 1);
    return surface_data;
}

static UINT surface_ids(RdpgfxClientContext *channel, UINT16 **ids, UINT16 *count) {
    (void)channel;
    *ids = malloc(sizeof(**ids));
    assert(*ids);
    **ids = 1;
    *count = 1;
    return CHANNEL_RC_OK;
}

static BOOL end_paint(rdpContext *context) {
    (void)context;
    painted++;
    return TRUE;
}

static BOOL gfx_present(rdpContext *context) {
    const BYTE *pixels = context->gdi->primary_buffer;
    assert(!gfx_frame_open() && painted > 0);
    // Both rectangles must be visible in the snapshot taken at EndFrame.
    assert(pixels[2] == 255 && pixels[1] == 0);
    assert(pixels[8 * 4 + 2] == 0 && pixels[8 * 4 + 1] == 255);
    ended++;
    return TRUE;
}

static void gfx_log(const char *event, UINT32 value, UINT32 extra) {
    (void)event;
    (void)value;
    (void)extra;
}

static void check_fallback(void) {
    gfx_attempt.enabled = gfx_attempt.advertised = TRUE;
    gfx_connection_error(ERRINFO_SUCCESS, FREERDP_ERROR_CONNECT_WRONG_PASSWORD);
    gfx_connection_error(ERRINFO_SUCCESS, FREERDP_ERROR_TLS_CONNECT_FAILED);
    assert(!gfx_take_fallback());
    assert(!gfx_first_frame_timed_out(FALSE, 7999));
    assert(!gfx_first_frame_timed_out(TRUE, 8000)); // A legacy frame keeps the current connection.
    assert(gfx_first_frame_timed_out(FALSE, 8000));
    assert(gfx_take_fallback() && gfx_attempt.fell_back && !gfx_attempt.enabled);
    assert(!gfx_take_fallback());

    gfx_attempt.enabled = gfx_attempt.advertised = TRUE;
    gfx_attempt.failure = NULL;
    gfx_connection_error(ERRINFO_GRAPHICS_MODE_NOT_SUPPORTED, 0);
    assert(gfx_take_fallback() && !gfx_take_fallback());
}

int main(int argc, char **argv) {
    freerdp *instance = freerdp_new();
    assert(instance && freerdp_context_new(instance));
    rdpContext *context = instance->context;
    gfx_attempt.enabled = TRUE;
    assert(gfx_configure(instance));
    if (argc == 2 && !strcmp(argv[1], "--require-gfx")) {
        assert(gfx_attempt.advertised && rdp_load_drdynvc(instance));
        printf("RDPGFX and drdynvc registered; AVC available=%d\n",
            freerdp_settings_get_bool(context->settings, FreeRDP_GfxH264));
    }
    if (gfx_attempt.advertised) {
        assert(freerdp_settings_get_bool(context->settings, FreeRDP_SupportGraphicsPipeline));
        assert(freerdp_settings_get_bool(context->settings, FreeRDP_SynchronousDynamicChannels));
    } else {
        assert(!gfx_attempt.enabled && !gfx_take_fallback());
        assert(!freerdp_settings_get_bool(context->settings, FreeRDP_SupportGraphicsPipeline));
        assert(PubSub_SubscribeChannelConnected(context->pubSub, gfx_connected) >= 0);
        assert(PubSub_SubscribeChannelDisconnected(context->pubSub, gfx_disconnected) >= 0);
    }
    // A connected FreeRDP normally allocates the legacy caches and primary
    // surface. This offline fixture needs only the GFX output buffer.
    BYTE pixels[16 * 16 * 4] = {0};
    GDI_RGN invalid = { .null = TRUE };
    GDI_RGN regions[16] = {0};
    GDI_WND window = { .count = 16, .invalid = &invalid, .cinvalid = regions };
    GDI_DC dc = { .hwnd = &window };
    gdiBitmap primary = { .hdc = &dc };
    rdpGdi gdi = { .context = context, .width = 16, .height = 16, .stride = 16 * 4,
                   .dstFormat = PIXEL_FORMAT_BGRA32, .hdc = &dc, .primary = &primary,
                   .primary_buffer = pixels };
    context->gdi = &gdi;
    context->update->EndPaint = end_paint;
    RdpgfxClientContext channel = {0};
    channel.SetSurfaceData = set_surface;
    channel.GetSurfaceData = get_surface;
    channel.GetSurfaceIds = surface_ids;
    ChannelConnectedEventArgs connected = {0};
    EventArgsInit(&connected, "gfx-test");
    connected.name = RDPGFX_DVC_CHANNEL_NAME;
    connected.pInterface = &channel;
    assert(PubSub_OnChannelConnected(context->pubSub, context, &connected) >= 0);
    assert(channel.EndFrame == gfx_end);

    RDPGFX_CREATE_SURFACE_PDU create = { .surfaceId = 1, .width = 16, .height = 16,
                                         .pixelFormat = GFX_PIXEL_FORMAT_XRGB_8888 };
    RDPGFX_MAP_SURFACE_TO_OUTPUT_PDU map = { .surfaceId = 1 };
    assert(channel.CreateSurface(&channel, &create) == CHANNEL_RC_OK);
    assert(channel.MapSurfaceToOutput(&channel, &map) == CHANNEL_RC_OK);

    RDPGFX_START_FRAME_PDU start = { .frameId = 1 };
    RDPGFX_END_FRAME_PDU end = { .frameId = 1 };
    RECTANGLE_16 left = {0, 0, 8, 16};
    RECTANGLE_16 right = {8, 0, 16, 16};
    RDPGFX_SOLID_FILL_PDU fill = { .surfaceId = 1, .fillPixel.R = 255,
                                  .fillRectCount = 1, .fillRects = &left };
    assert(channel.StartFrame(&channel, &start) == CHANNEL_RC_OK);
    assert(gfx_frame_open());
    assert(channel.SolidFill(&channel, &fill) == CHANNEL_RC_OK);
    fill.fillPixel.R = 0;
    fill.fillPixel.G = 255;
    fill.fillRects = &right;
    assert(channel.SolidFill(&channel, &fill) == CHANNEL_RC_OK);
    assert(painted == 0 && ended == 0);
    assert(channel.EndFrame(&channel, &end) == CHANNEL_RC_OK);
    assert(painted > 0 && ended == 1);

    RDPGFX_DELETE_SURFACE_PDU remove = { .surfaceId = 1 };
    assert(channel.DeleteSurface(&channel, &remove) == CHANNEL_RC_OK);
    ChannelDisconnectedEventArgs disconnected = {0};
    EventArgsInit(&disconnected, "gfx-test");
    disconnected.name = RDPGFX_DVC_CHANNEL_NAME;
    disconnected.pInterface = &channel;
    assert(PubSub_OnChannelDisconnected(context->pubSub, context, &disconnected) >= 0);
    assert(!gfx.channel && !gfx_frame_open() && !context->gdi->gfx && channel.EndFrame != gfx_end);
    context->gdi = NULL;
    freerdp_context_free(instance);
    freerdp_free(instance);
    check_fallback();
    puts("RDPGFX frame composition and fallback tests passed.");
    return 0;
}
