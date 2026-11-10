#include <assert.h>
#include <freerdp/freerdp.h>
#include <freerdp/settings.h>
#include <freerdp/gdi/gdi.h>
#include <winpr/synch.h>
#include "display_layout.h"
static struct probe_display desired;
static uint64_t age=1000;
int probe_display_snapshot(struct probe_display *d,uint64_t *elapsed){*d=desired;*elapsed=age;return 1;}
#include "display_channel.h"
static unsigned sends;
static DISPLAY_CONTROL_MONITOR_LAYOUT sent;
static UINT send_layout(DispClientContext *context,UINT32 count,DISPLAY_CONTROL_MONITOR_LAYOUT *layout){
    (void)context;assert(count==1);sent=*layout;sends++;return CHANNEL_RC_OK;
}
int main(int argc,char **argv){
    BOOL callbacksOnly=argc==2 && !strcmp(argv[1],"--callbacks-only");
    freerdp *rdp=freerdp_new();assert(rdp && freerdp_context_new(rdp));
    assert(probe_display_make(1280,800,2,&desired));
    assert(display_initialize(rdp->context->settings));assert(display_start(rdp));
    // Display loading is independent of clipboard; exercise the real static/DVC addin entries.
    if(!callbacksOnly){
        if(!display_load(rdp)){fputs("Installed FreeRDP could not load drdynvc; dynamic resolution requires client channel support.\n",stderr);return 1;}
        if(!freerdp_load_channel_addin_entry("disp",NULL,NULL,FREERDP_ADDIN_CHANNEL_DYNAMIC)){
            fputs("Installed FreeRDP has no disp client addin; dynamic resolution cannot be packaged.\n",stderr);return 1;
        }
    }
    assert(freerdp_settings_get_uint32(rdp->context->settings,FreeRDP_DesktopScaleFactor)==200);
    DispClientContext channel={0};channel.SendMonitorLayout=send_layout;
    ChannelConnectedEventArgs event={0};EventArgsInit(&event,"display-test");event.name=DISP_DVC_CHANNEL_NAME;event.pInterface=&channel;
    assert(PubSub_OnChannelConnected(rdp->context->pubSub,rdp->context,&event)>=0);assert(channel.DisplayControlCaps);
    assert(channel.DisplayControlCaps(&channel,1,8192,8192)==CHANNEL_RC_OK);
    ULONGLONG start=display.capsAt;
    display_poll_at(start+499);assert(!sends);age=0;display_poll_at(start+1000);assert(!sends);
    age=1000;display_poll_at(start+1000);assert(sends==1 && sent.Width==2560 && sent.Height==1600 && sent.DesktopScaleFactor==200);
    display_poll_at(start+2000);assert(sends==1); // unchanged layout is not resent
    // The windowed resize retains Retina DPI, then a fullscreen transition
    // produces a short-lived size at the target display's DPI.
    assert(probe_display_make(1440,870,2,&desired));
    display_poll_at(start+2000);
    assert(sends==2 && sent.Width==2880 && sent.Height==1740 && sent.DesktopScaleFactor==200);
    assert(probe_display_make(1440,870,1,&desired));
    age=599;display_poll_at(start+3000);assert(sends==2);
    assert(probe_display_make(1920,1080,1,&desired));
    age=600;display_poll_at(start+3500);
    assert(sends==3 && sent.Width==1920 && sent.Height==1080 && sent.DesktopScaleFactor==100 && sent.DeviceScaleFactor==100);
    display_poll_at(start+4000);assert(sends==3);
    assert(probe_display_make(1440,900,2,&desired));
    age=600;display_poll_at(start+5000);
    assert(sends==4 && sent.Width==2880 && sent.Height==1800 && sent.DesktopScaleFactor==200);
    ChannelDisconnectedEventArgs end={0};EventArgsInit(&end,"display-test");end.name=DISP_DVC_CHANNEL_NAME;end.pInterface=&channel;
    assert(PubSub_OnChannelDisconnected(rdp->context->pubSub,rdp->context,&end)>=0);
    display_poll_at(start+6000);assert(sends==4);
    assert(PubSub_OnChannelConnected(rdp->context->pubSub,rdp->context,&event)>=0);
    assert(channel.DisplayControlCaps(&channel,1,1200,800)==CHANNEL_RC_OK);
    display_poll_at(GetTickCount64()+2000);
    assert(sends==5 && (uint64_t)sent.Width*sent.Height<=1200ull*800 && sent.DesktopScaleFactor==200);
    freerdp_context_free(rdp);freerdp_free(rdp);display_stop();
    assert(!display.initialized && !display.channel);
    puts(callbacksOnly?"Display callback tests passed (addin loading excluded).":"Display channel tests passed including real addin loading.");
    return 0;
}
