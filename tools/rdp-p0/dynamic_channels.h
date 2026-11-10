#pragma once
#include <freerdp/client/channels.h>
#include <freerdp/channels/channels.h>

static BOOL rdp_load_drdynvc(freerdp *rdp) {
    freerdp_register_addin_provider(freerdp_channels_load_static_addin_entry, 0);
    PVIRTUALCHANNELENTRY entry = freerdp_load_channel_addin_entry(
        "drdynvc", NULL, NULL, FREERDP_ADDIN_CHANNEL_STATIC | FREERDP_ADDIN_CHANNEL_ENTRYEX);
    return entry && freerdp_channels_client_load_ex(rdp->context->channels, rdp->context->settings,
        (PVIRTUALCHANNELENTRYEX)entry, rdp->context->settings) == 0;
}
