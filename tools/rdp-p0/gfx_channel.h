#pragma once

#include <freerdp/client/channels.h>
#include <freerdp/client/cmdline.h>
#include <freerdp/channels/channels.h>
#include <freerdp/config.h>
#include <freerdp/error.h>
#include <freerdp/freerdp.h>
#include <freerdp/gdi/gfx.h>
#include <freerdp/settings.h>
#if defined(WITH_GFX_H264)
#include <freerdp/codec/h264.h>
#endif
#include <stdlib.h>
#include <string.h>

static struct {
    RdpgfxClientContext *channel;
    pcRdpgfxCapsConfirm caps;
    pcRdpgfxSurfaceCommand surface;
    pcRdpgfxEndFrame end;
    UINT32 codecs_seen;
    BOOL frame_seen;
} gfx;

static struct {
    BOOL enabled, advertised, fell_back;
    const char *failure;
} gfx_attempt;

static BOOL gfx_present(rdpContext *context);
static void gfx_log(const char *event, UINT32 value, UINT32 extra);

static void gfx_failed(const char *reason, UINT32 code) {
    if (gfx_attempt.failure) return;
    gfx_attempt.failure = reason;
    gfx_log(reason, code, 0);
}

static void gfx_connection_error(UINT32 server, UINT32 client) {
    if (!gfx_attempt.advertised) return;
    if (server == ERRINFO_GRAPHICS_MODE_NOT_SUPPORTED ||
        server == ERRINFO_GRAPHICS_SUBSYSTEM_RESET_FAILED ||
        server == ERRINFO_GRAPHICS_SUBSYSTEM_FAILED) {
        gfx_failed("server_graphics_error", server);
    } else if (client == FREERDP_ERROR_POST_CONNECT_FAILED ||
               client == FREERDP_ERROR_CONNECT_ACTIVATION_TIMEOUT) {
        gfx_failed("graphics_activation_failed", client);
    }
}

static BOOL gfx_first_frame_timed_out(BOOL painted, ULONGLONG elapsed) {
    if (!gfx_attempt.advertised || painted || elapsed < 8000) return FALSE;
    gfx_failed("first_frame_timeout", 0);
    return TRUE;
}

static BOOL gfx_take_fallback(void) {
    if (!gfx_attempt.enabled || !gfx_attempt.failure) return FALSE;
    gfx_attempt.enabled = FALSE;
    gfx_attempt.fell_back = TRUE;
    return TRUE;
}

static UINT gfx_confirm(RdpgfxClientContext *channel, const RDPGFX_CAPS_CONFIRM_PDU *caps) {
    const UINT rc = gfx.caps ? gfx.caps(channel, caps) : CHANNEL_RC_OK;
    if (rc == CHANNEL_RC_OK && caps->capsSet)
        gfx_log("caps", caps->capsSet->version, caps->capsSet->flags);
    return rc;
}

static UINT gfx_surface(RdpgfxClientContext *channel, const RDPGFX_SURFACE_COMMAND *cmd) {
    const UINT rc = gfx.surface(channel, cmd);
    if (rc != CHANNEL_RC_OK) gfx_failed("surface_failed", rc);
    if (rc == CHANNEL_RC_OK && cmd->codecId < 32) {
        const UINT32 bit = 1u << cmd->codecId;
        if (!(gfx.codecs_seen & bit)) gfx_log("codec", cmd->codecId, 0);
        gfx.codecs_seen |= bit;
    }
    return rc;
}

static UINT gfx_end(RdpgfxClientContext *channel, const RDPGFX_END_FRAME_PDU *frame) {
    const UINT rc = gfx.end(channel, frame);
    if (rc != CHANNEL_RC_OK) {
        gfx_failed("end_frame_failed", rc);
        return rc;
    }
    rdpGdi *gdi = channel->custom;
    // FreeRDP composes all mapped surfaces before returning from EndFrame.
    // Its channel sends the frame ACK after this callback returns.
    if (!gfx_present(gdi->context)) {
        gfx_failed("present_failed", ERROR_INTERNAL_ERROR);
        return ERROR_INTERNAL_ERROR;
    }
    if (!gfx.frame_seen) {
        gfx.frame_seen = TRUE;
        gfx_log("first_end_frame", frame->frameId, 0);
    }
    return CHANNEL_RC_OK;
}

static UINT gfx_reject_open(RdpgfxClientContext *channel, BOOL *advertise, BOOL *ack) {
    (void)channel;
    *advertise = *ack = FALSE;
    return ERROR_INTERNAL_ERROR;
}

static void gfx_connected(void *context, const ChannelConnectedEventArgs *event) {
    if (strcmp(event->name, RDPGFX_DVC_CHANNEL_NAME)) return;
    rdpContext *rdp = context;
    RdpgfxClientContext *channel = event->pInterface;
    if (!channel || gfx.channel) return;
    if (!rdp->gdi || !gdi_graphics_pipeline_init(rdp->gdi, channel)) {
        // Initialization can fail before FreeRDP initializes the channel mutex.
        freerdp_client_codecs_free(channel->codecs);
        channel->codecs = NULL;
        channel->custom = NULL;
        if (rdp->gdi) rdp->gdi->gfx = NULL;
        channel->OnOpen = gfx_reject_open;
        gfx_failed("bind_failed", 0);
        return;
    }
    gfx.channel = channel;
    gfx.caps = channel->CapsConfirm;
    gfx.surface = channel->SurfaceCommand;
    gfx.end = channel->EndFrame;
    channel->CapsConfirm = gfx_confirm;
    channel->SurfaceCommand = gfx_surface;
    channel->EndFrame = gfx_end;
    gfx_log("channel_connected", 0, 0);
}

static void gfx_disconnected(void *context, const ChannelDisconnectedEventArgs *event) {
    if (strcmp(event->name, RDPGFX_DVC_CHANNEL_NAME) ||
        !gfx.channel || gfx.channel != event->pInterface) return;
    rdpContext *rdp = context;
    gfx.channel->CapsConfirm = gfx.caps;
    gfx.channel->SurfaceCommand = gfx.surface;
    gfx.channel->EndFrame = gfx.end;
    gdi_graphics_pipeline_uninit(rdp->gdi, gfx.channel);
    memset(&gfx, 0, sizeof(gfx));
    if (rdp->gdi) rdp->gdi->inGfxFrame = FALSE;
    gfx_log("channel_disconnected", 0, 0);
}

static BOOL gfx_frame_open(void) {
    if (!gfx.channel) return FALSE;
    const rdpGdi *gdi = gfx.channel->custom;
    return gdi->inGfxFrame;
}

static BOOL gfx_configure(freerdp *rdp) {
    if (!gfx_attempt.enabled) return TRUE;
    freerdp_register_addin_provider(freerdp_channels_load_static_addin_entry, 0);
    if (!freerdp_load_channel_addin_entry(RDPGFX_CHANNEL_NAME, NULL, NULL, FREERDP_ADDIN_CHANNEL_DYNAMIC)) {
        gfx_log("addin_missing", 0, 0);
        gfx_attempt.enabled = FALSE;
        return TRUE;
    }
    rdpSettings *settings = rdp->context->settings;
    const char *const args[] = { RDPGFX_CHANNEL_NAME };
#ifdef WITH_GFX_H264
    // Check the decoder before advertising AVC. RDPGFX can still negotiate
    // other codecs when the platform decoder is unavailable.
    H264_CONTEXT *decoder = h264_context_new(FALSE);
    const BOOL avc = decoder != NULL;
    h264_context_free(decoder);
#else
    const BOOL avc = FALSE;
#endif
    // Both classic and GFX callbacks touch the same primary surface. Dispatch
    // dynamic channel data on the session thread alongside classic updates.
    const BOOL ok = freerdp_settings_set_bool(settings, FreeRDP_SynchronousDynamicChannels, TRUE) &&
        freerdp_settings_set_bool(settings, FreeRDP_SupportDynamicChannels, TRUE) &&
        freerdp_settings_set_bool(settings, FreeRDP_SupportGraphicsPipeline, TRUE) &&
        freerdp_settings_set_bool(settings, FreeRDP_GfxH264, avc) &&
        freerdp_settings_set_bool(settings, FreeRDP_GfxAVC444, avc) &&
        freerdp_settings_set_bool(settings, FreeRDP_GfxAVC444v2, avc) &&
        PubSub_SubscribeChannelConnected(rdp->context->pubSub, gfx_connected) >= 0 &&
        PubSub_SubscribeChannelDisconnected(rdp->context->pubSub, gfx_disconnected) >= 0 &&
        freerdp_client_add_dynamic_channel(settings, 1, args);
    gfx_attempt.advertised = ok;
    if (ok) gfx_log("requested", avc, 0);
    else gfx_failed("configure_failed", 0);
    return ok;
}
