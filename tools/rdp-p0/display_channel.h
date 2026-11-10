#pragma once
#include "display_layout.h"
#include <freerdp/client/disp.h>
#include <freerdp/client/cmdline.h>
#include <freerdp/client/channels.h>
#include <freerdp/channels/channels.h>
#include <winpr/sysinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#if defined(WITH_CHANNELS)
#include "dynamic_channels.h"
#endif

static struct {
    CRITICAL_SECTION lock;
    BOOL initialized,subscribed,ready,sent;
    DispClientContext *channel;
    ULONGLONG capsAt,lastSend;
    uint64_t area;
    uint32_t frameWidth,frameHeight,requestedScale,maxSide;
    struct probe_display last;
    FILE *log;
} display;
static void display_log(const char *event,const struct probe_display *d,UINT code) {
    if(!display.log)return;
    fprintf(display.log,"%llu %s width=%u height=%u scale=%u device=%u status=%u\n",
        (unsigned long long)GetTickCount64(),event,d?d->width:0,d?d->height:0,d?d->desktop_scale:0,d?d->device_scale:0,code);
    fflush(display.log);
}
static UINT display_caps(DispClientContext *channel,UINT32 monitors,UINT32 a,UINT32 b) {
    EnterCriticalSection(&display.lock);
    if(display.channel==channel){
        display.ready=monitors>0 && a>0 && b>0;display.area=(uint64_t)a*b;
        if(display.area>PROBE_DISPLAY_MAX_PIXELS)display.area=PROBE_DISPLAY_MAX_PIXELS;
        if(display.area<40000)display.ready=FALSE;
        display.capsAt=GetTickCount64();display.sent=FALSE;
        display_log("caps",NULL,display.ready?0:1);
    }
    LeaveCriticalSection(&display.lock);return CHANNEL_RC_OK;
}
static void display_connected(void *context,const ChannelConnectedEventArgs *event) {
    (void)context;if(strcmp(event->name,DISP_DVC_CHANNEL_NAME))return;
    EnterCriticalSection(&display.lock);
    display.channel=(DispClientContext*)event->pInterface;display.ready=FALSE;display.sent=FALSE;display.lastSend=0;
    if(display.channel)display.channel->DisplayControlCaps=display_caps;
    display_log("channel_connected",NULL,0);LeaveCriticalSection(&display.lock);
}
static void display_disconnected(void *context,const ChannelDisconnectedEventArgs *event) {
    (void)context;if(strcmp(event->name,DISP_DVC_CHANNEL_NAME))return;
    EnterCriticalSection(&display.lock);
    if(display.channel==(DispClientContext*)event->pInterface){display.channel=NULL;display.ready=FALSE;display.sent=FALSE;}
    display_log("channel_disconnected",NULL,0);LeaveCriticalSection(&display.lock);
}
static BOOL display_initialize(rdpSettings *settings) {
    memset(&display,0,sizeof(display));InitializeCriticalSection(&display.lock);display.initialized=TRUE;
    const char *path=getenv("CALABI_RDP_DISPLAY_LOG");display.log=path?fopen(path,"a"):NULL;
    struct probe_display initial;uint64_t age;
    if(!probe_display_snapshot(&initial,&age) && !probe_display_make(1024,576,1,&initial))return FALSE;
    display.requestedScale=initial.desktop_scale;
    display.maxSide=PROBE_DISPLAY_MAX_SIDE;
#ifdef CALABI_REMOTE_WORKSPACE
    if(probe_workspace_enabled())display.maxSide=PROBE_WORKSPACE_MAX_SIDE;
#endif
    // Initial core negotiation is bounded by MS-RDPBCGR. The DVC can raise it later.
    probe_display_limit_pixels(&initial,4096,2048,4096ull*2048);
    display_log("RDP_RETINA_DYNAMIC_V1_initial",&initial,0);
    return freerdp_settings_set_uint32(settings,FreeRDP_DesktopWidth,initial.width) &&
        freerdp_settings_set_uint32(settings,FreeRDP_DesktopHeight,initial.height) &&
        freerdp_settings_set_uint32(settings,FreeRDP_DesktopScaleFactor,initial.desktop_scale) &&
        freerdp_settings_set_uint32(settings,FreeRDP_DeviceScaleFactor,initial.device_scale) &&
        freerdp_settings_set_uint32(settings,FreeRDP_DesktopPhysicalWidth,initial.physical_width) &&
        freerdp_settings_set_uint32(settings,FreeRDP_DesktopPhysicalHeight,initial.physical_height) &&
        freerdp_settings_set_bool(settings,FreeRDP_DesktopResize,TRUE) &&
        freerdp_settings_set_bool(settings,FreeRDP_SupportDisplayControl,TRUE) &&
        freerdp_settings_set_bool(settings,FreeRDP_SupportDynamicChannels,TRUE) &&
        freerdp_settings_set_bool(settings,FreeRDP_DynamicResolutionUpdate,TRUE);
}
static BOOL display_start(freerdp *rdp) {
    if(display.subscribed)return TRUE;
    display.subscribed=TRUE;
    return PubSub_SubscribeChannelConnected(rdp->context->pubSub,display_connected)>=0 &&
        PubSub_SubscribeChannelDisconnected(rdp->context->pubSub,display_disconnected)>=0;
}
static BOOL display_load(freerdp *rdp) {
#if defined(WITH_CHANNELS)
    const char *const args[]={DISP_CHANNEL_NAME};
    if(!freerdp_client_add_dynamic_channel(rdp->context->settings,1,args))return FALSE;
    if(!rdp_load_drdynvc(rdp)){display_log("drdynvc_load_failed",NULL,1);return FALSE;}
    return TRUE;
#else
    (void)rdp;display_log("channel_support_missing",NULL,1);return FALSE;
#endif
}
static void display_poll_at(ULONGLONG now) {
    struct probe_display next;uint64_t age;
    if(!probe_display_snapshot(&next,&age) || age<250)return;
    EnterCriticalSection(&display.lock);
    // Windows can ignore a layout sent immediately after capability negotiation.
    if(!display.ready || !display.channel || now<display.capsAt+500 || now<display.lastSend+500)goto done;
    // A fullscreen transition can emit intermediate viewports. Wait for the
    // dimensions to settle before changing the DPI in the same layout update.
    if(next.desktop_scale!=display.requestedScale && age<600)goto done;
    probe_display_limit_pixels(&next,display.maxSide,display.maxSide,display.area);
    if(display.sent && probe_display_equal(&next,&display.last))goto done;
    DISPLAY_CONTROL_MONITOR_LAYOUT layout={0};layout.Flags=DISPLAY_CONTROL_MONITOR_PRIMARY;
    layout.Width=next.width;layout.Height=next.height;layout.PhysicalWidth=next.physical_width;layout.PhysicalHeight=next.physical_height;
    layout.DesktopScaleFactor=next.desktop_scale;layout.DeviceScaleFactor=next.device_scale;
    UINT rc=display.channel->SendMonitorLayout?display.channel->SendMonitorLayout(display.channel,1,&layout):1u;
    display.lastSend=now;display_log("layout_sent",&next,rc);
    if(rc==CHANNEL_RC_OK){display.last=next;display.sent=TRUE;display.requestedScale=next.desktop_scale;}
done:
    LeaveCriticalSection(&display.lock);
}
static void display_stop(void) {
    if(!display.initialized)return;
    if(display.log)fclose(display.log);
    DeleteCriticalSection(&display.lock);memset(&display,0,sizeof(display));
}
