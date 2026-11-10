#if defined(_WIN32) && defined(CALABI_REMOTE_WORKSPACE)
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#endif
#include "probe.h"
#include <freerdp/freerdp.h>
#include <freerdp/error.h>
#include <freerdp/gdi/gdi.h>
#include <freerdp/input.h>
#include <freerdp/settings.h>
#include <winpr/crt.h>
#include <winpr/synch.h>
BOOL clipboard_start(freerdp *rdp);
BOOL clipboard_load(freerdp *rdp);
void clipboard_poll(void);
void clipboard_stop(void);
int probe_clipboard_files_enabled(void);
#if defined(_WIN32) || defined(__APPLE__)
static uint16_t mesh_expected_port;
#endif
#ifdef __APPLE__
#include "display_channel.h"
#endif
#ifdef CALABI_RDP_GFX
#include "gfx_channel.h"
#ifdef _WIN32
#include "dynamic_channels.h"
static FILE *gfx_diagnostic;
static BOOL win_preconnect(freerdp *rdp) {
    return gfx_configure(rdp) && clipboard_start(rdp);
}
static BOOL win_load_channels(freerdp *rdp) {
    if (gfx_attempt.advertised && !rdp_load_drdynvc(rdp)) {
        gfx_failed("drdynvc_load_failed", 0);
        return FALSE;
    }
    return clipboard_load(rdp);
}
#endif
static void gfx_log(const char *event, UINT32 value, UINT32 extra) {
#ifdef _WIN32
    FILE *log = gfx_diagnostic;
#else
    FILE *log = display.log;
#endif
    if (!log) return;
    fprintf(log, "%llu RDPGFX_V1 %s value=%u extra=%u\n",
        (unsigned long long)GetTickCount64(), event, value, extra);
    fflush(log);
}
#endif
#ifdef __APPLE__
static BOOL mac_preconnect(freerdp *rdp) {
#ifdef CALABI_RDP_GFX
    if (!gfx_configure(rdp)) return FALSE;
#endif
    return display_start(rdp) && clipboard_start(rdp);
}
static BOOL mac_load_channels(freerdp *rdp){return display_load(rdp) && clipboard_load(rdp);}
static BOOL mac_resize_desktop(rdpContext *context) {
    UINT32 w=freerdp_settings_get_uint32(context->settings,FreeRDP_DesktopWidth);
    UINT32 h=freerdp_settings_get_uint32(context->settings,FreeRDP_DesktopHeight);
    if(!w || !h || w>PROBE_DISPLAY_MAX_SIDE || h>PROBE_DISPLAY_MAX_SIDE || (uint64_t)w*h>PROBE_DISPLAY_MAX_PIXELS)return FALSE;
    BOOL result=gdi_resize(context->gdi,w,h);
    struct probe_display actual={0};actual.width=w;actual.height=h;
    display_log("desktop_resize",&actual,result?0:1);return result;
}
#endif
#ifdef _WIN32
#include <freerdp/transport_io.h>
#include <freerdp/constants.h>
int windows_mesh_connect(const char *, int, uint16_t, DWORD);
void windows_waiting_for_frame(void);

static BOOL resize_desktop(rdpContext *context) {
    UINT32 w = freerdp_settings_get_uint32(context->settings, FreeRDP_DesktopWidth);
    UINT32 h = freerdp_settings_get_uint32(context->settings, FreeRDP_DesktopHeight);
    return w && h && w <= 4096 && h <= 4096 && gdi_resize(context->gdi, w, h);
}
#endif

#if defined(_WIN32) || defined(CALABI_REMOTE_WORKSPACE)
static BOOL request_desktop(rdpContext *context) {
    rdpGdi *gdi = context->gdi;
    if (!gdi || gdi->width <= 0 || gdi->height <= 0 ||
        !context->update->SuppressOutput || !context->update->RefreshRect) return FALSE;
    RECTANGLE_16 rect = {0, 0, (UINT16)(gdi->width-1), (UINT16)(gdi->height-1)};
    return context->update->SuppressOutput(context, TRUE, &rect) &&
           context->update->RefreshRect(context, 1, &rect);
}
#endif

#ifdef __APPLE__
#include <freerdp/transport_io.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Desktop launches supply the local address from authenticated daemon IPC.
// Bind the socket to its utun for the entire connection, including route changes.
static int mesh_connect(rdpContext *ctx, rdpSettings *settings, const char *host, int port, DWORD timeout) {
    (void)ctx; (void)settings;
    struct sockaddr_in local = {.sin_family=AF_INET}, peer = {.sin_family=AF_INET};
    const char *expected = getenv("CALABI_P0_PEER");
    const char *source = getenv("CALABI_RDP_LOCAL");
    if (!host || !expected || !source || strcmp(host,expected) || port <= 0 || port != mesh_expected_port ||
        inet_pton(AF_INET,host,&peer.sin_addr)!=1 || inet_pton(AF_INET,source,&local.sin_addr)!=1) return -1;
    peer.sin_port = htons(mesh_expected_port);
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list)!=0) return -1;
    unsigned index=0;
    for (struct ifaddrs *i=list;i;i=i->ifa_next) {
        if (i->ifa_addr && i->ifa_addr->sa_family==AF_INET && !strncmp(i->ifa_name,"utun",4) &&
            ((struct sockaddr_in *)i->ifa_addr)->sin_addr.s_addr==local.sin_addr.s_addr) {
            index=if_nametoindex(i->ifa_name);break;
        }
    }
    freeifaddrs(list);
    if (!index) return -1;
    int fd=socket(AF_INET,SOCK_STREAM,0);
    if (fd<0) return -1;
    if (setsockopt(fd,IPPROTO_IP,IP_BOUND_IF,&index,sizeof(index))<0 ||
        bind(fd,(struct sockaddr *)&local,sizeof(local))<0 || fcntl(fd,F_SETFL,O_NONBLOCK)<0) goto failed;
    if (connect(fd,(struct sockaddr *)&peer,sizeof(peer))<0) {
        if (errno!=EINPROGRESS) goto failed;
        struct pollfd ready={.fd=fd,.events=POLLOUT};
        int error=0; socklen_t n=sizeof(error);
        ULONGLONG deadline=GetTickCount64()+(timeout && timeout<10000 ? timeout : 10000);
        int status=0;
        while (!probe_requested_stop() && GetTickCount64()<deadline &&
               (status=poll(&ready,1,100))==0) {}
        if (status<=0 || probe_requested_stop() ||
            getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&n)<0 || error) goto failed;
    }
    int keepIdle=5;
    setsockopt(fd,IPPROTO_TCP,TCP_KEEPALIVE,&keepIdle,sizeof(keepIdle));
    return fd;
failed:
    close(fd);return -1;
}
#endif

static BOOL receivedPaint, meshTCPFailed;
static ULONGLONG firstFrameAt;
#ifdef CALABI_REMOTE_WORKSPACE
#include "workspace_bridge.h"
static BOOL workspace_output_paused;
static ULONGLONG workspace_pause_at;

static void log_workspace_graphics(const char *event, BOOL failed) {
#ifdef __APPLE__
    display_log(event, NULL, failed);
#elif defined(CALABI_RDP_GFX)
    gfx_log(event, failed, 0);
#else
    (void)event;
    (void)failed;
#endif
}

static void sync_workspace_graphics(rdpContext *context, ULONGLONG now, ULONGLONG *next_refresh) {
    // Let a new or reconnecting session paint before suppressing its output.
    if (!receivedPaint || !probe_workspace_selection() || workspace_stopped()) return;
    if (InterlockedCompareExchange(&workspace_selected, 0, 0)) {
        workspace_pause_at = 0;
        if (!workspace_output_paused || now < *next_refresh) return;
        *next_refresh = now + 250;
        workspace_output_paused = !request_desktop(context);
        log_workspace_graphics("background_graphics_resume", workspace_output_paused);
        return;
    }
    if (workspace_output_paused || !context->update->SuppressOutput ||
        !freerdp_settings_get_bool(context->settings, FreeRDP_SuppressOutput)) return;

    // A quick switch back should not stop and restart the graphics stream.
    if (!workspace_pause_at) workspace_pause_at = now + 300;
    if (now < workspace_pause_at) return;
    workspace_output_paused = context->update->SuppressOutput(context, FALSE, NULL);
    workspace_pause_at = now + 1000;
    log_workspace_graphics("background_graphics_pause", !workspace_output_paused);
}
#endif
#if defined(_WIN32) || defined(__APPLE__)
static int connect_mesh_socket(rdpContext *context, rdpSettings *settings, const char *host, int port, DWORD timeout) {
#ifdef _WIN32
    (void)context; (void)settings;
    int fd = windows_mesh_connect(host, port, mesh_expected_port, timeout);
#else
    int fd = mesh_connect(context, settings, host, port, timeout);
#endif
    meshTCPFailed = fd < 0;
    return fd;
}
#endif

static int verify_leaf(freerdp *rdp, const BYTE *pem, size_t length,
                       const char *host, UINT16 port, DWORD flags) {
    (void)rdp; (void)host; (void)port;
    if (flags & (VERIFY_CERT_FLAG_GATEWAY | VERIFY_CERT_FLAG_REDIRECT)) return 0;
    return probe_verify_leaf(pem, length) ? 2 : 0;
}

static BOOL paint(rdpContext *context) {
    rdpGdi *gdi = context->gdi;
    if (!gdi || !gdi->primary_buffer || gdi->width <= 0 || gdi->height <= 0 ||
#ifdef __APPLE__
        gdi->width > PROBE_DISPLAY_MAX_SIDE || gdi->height > PROBE_DISPLAY_MAX_SIDE ||
        (uint64_t)gdi->width*gdi->height > PROBE_DISPLAY_MAX_PIXELS ||
#else
        gdi->width > 4096 || gdi->height > 4096 ||
#endif
        gdi->stride < (UINT32)gdi->width * 4 || gdi->stride > 65536) return FALSE;
#ifdef CALABI_REMOTE_WORKSPACE
    // Keep processing protocol updates and ACKs, including any frames in flight.
    if (workspace_output_paused && !InterlockedCompareExchange(&workspace_selected, 0, 0)) return TRUE;
    workspace_publish(gdi->primary_buffer, (unsigned)gdi->width, (unsigned)gdi->height, gdi->stride);
#endif
    probe_frame(gdi->primary_buffer, gdi->width, gdi->height, gdi->stride);
#ifdef __APPLE__
    if(display.frameWidth!=(UINT32)gdi->width || display.frameHeight!=(UINT32)gdi->height){
        display.frameWidth=(UINT32)gdi->width;display.frameHeight=(UINT32)gdi->height;
        struct probe_display frame={0};frame.width=display.frameWidth;frame.height=display.frameHeight;
        display_log("frame_received",&frame,0);
    }
#endif
#ifdef CALABI_RDP_GFX
    if (!receivedPaint && gfx_attempt.advertised && !gfx.channel)
        gfx_log("classic_frame", 0, 0);
#endif
    if (!receivedPaint) firstFrameAt = GetTickCount64();
    receivedPaint = TRUE;
    return TRUE;
}

#if defined(_WIN32) || defined(CALABI_REMOTE_WORKSPACE)
// EndPaint may finish only one strip of a window move. Keep decoding into
// FreeRDP's primary surface; the UI owns a separate, last-presented copy.
static BOOL pendingPaint, surfaceOpen, orderOpen, batchMarkedUpdates;
static ULONGLONG firstDirty, lastDirty;
static pSurfaceFrameMarker originalSurfaceMarker;
static pFrameMarker originalOrderMarker;

static BOOL begin_update(rdpContext *context) {
    HGDI_WND wnd = context->gdi->primary->hdc->hwnd;
    wnd->invalid->null = TRUE;
    wnd->ninvalid = 0;
    return TRUE;
}

static BOOL collect_update(rdpContext *context) {
    HGDI_WND wnd = context->gdi->primary->hdc->hwnd;
    if (!wnd->invalid->null) {
        lastDirty = GetTickCount64();
        if (!pendingPaint) firstDirty = lastDirty;
        pendingPaint = TRUE;
        wnd->invalid->null = TRUE;
        wnd->ninvalid = 0;
    }
    return TRUE;
}

static BOOL present_update(rdpContext *context) {
    if (!pendingPaint || surfaceOpen || orderOpen) return TRUE;
    pendingPaint = FALSE;
    return paint(context);
}

#ifdef CALABI_RDP_GFX
static BOOL gfx_present(rdpContext *context) {
    return present_update(context);
}
#endif

static BOOL surface_marker(rdpContext *context, const SURFACE_FRAME_MARKER *marker) {
    if (originalSurfaceMarker && !originalSurfaceMarker(context, marker)) return FALSE; // includes server ACK
    if (marker->frameAction == SURFACECMD_FRAMEACTION_BEGIN) surfaceOpen = TRUE;
    if (marker->frameAction != SURFACECMD_FRAMEACTION_END) return TRUE;
    surfaceOpen = FALSE;
    return collect_update(context) && (batchMarkedUpdates || present_update(context));
}

static BOOL order_marker(rdpContext *context, const FRAME_MARKER_ORDER *marker) {
    if (originalOrderMarker && !originalOrderMarker(context, marker)) return FALSE;
    if (marker->action == FRAME_START) orderOpen = TRUE;
    if (marker->action != FRAME_END) return TRUE;
    orderOpen = FALSE;
    return collect_update(context) && (batchMarkedUpdates || present_update(context));
}

static DWORD presentation_wait(ULONGLONG now) {
    if (!pendingPaint || surfaceOpen || orderOpen) return 30;
#ifdef CALABI_RDP_GFX
    if (gfx_frame_open()) return 30;
#endif
    // An update boundary can describe a strip of a desktop repaint. Wait
    // for 16 ms of quiet, with a 50 ms limit during continuous updates.
    ULONGLONG quiet = lastDirty + 16, limit = firstDirty + 50;
    ULONGLONG due = quiet < limit ? quiet : limit;
    if (now >= due) return 0;
    ULONGLONG remaining = due - now;
    return remaining < 30 ? (DWORD)remaining : 30;
}
#endif

static BOOL connected(freerdp *rdp) {
    if (!gdi_init(rdp, PIXEL_FORMAT_BGRA32)) return FALSE;
#ifdef CALABI_REMOTE_WORKSPACE
    batchMarkedUpdates = probe_workspace_enabled();
    if (batchMarkedUpdates) workspace_register_cursor(rdp->context);
#endif
#ifndef _WIN32
    rdp->context->update->EndPaint = paint;
#ifdef __APPLE__
    rdp->context->update->DesktopResize=mac_resize_desktop;
#endif
#ifdef CALABI_REMOTE_WORKSPACE
    if (!batchMarkedUpdates) return TRUE;
#endif
#endif
#if defined(_WIN32) || defined(CALABI_REMOTE_WORKSPACE)
    rdpUpdate *updates = rdp->context->update;
    pendingPaint = surfaceOpen = orderOpen = FALSE;
    originalSurfaceMarker = updates->SurfaceFrameMarker;
    originalOrderMarker = updates->altsec->FrameMarker;
    updates->SurfaceFrameMarker = surface_marker;
    updates->altsec->FrameMarker = order_marker;
    updates->BeginPaint = begin_update;
    updates->EndPaint = collect_update;
#endif
#ifdef _WIN32
    updates->DesktopResize = resize_desktop;
    windows_waiting_for_frame();
#endif
    return TRUE;
}

#ifdef CALABI_REMOTE_WORKSPACE
static BOOL workspace_keys[512], workspace_left, workspace_right;
static UINT16 workspace_x, workspace_y;
static BOOL release_workspace_input(rdpInput *input) {
    BOOL ok=TRUE;
    for(unsigned key=0;key<512;key++)if(workspace_keys[key]){
        ok=freerdp_input_send_keyboard_event(input,KBD_FLAGS_RELEASE|(key>=256?KBD_FLAGS_EXTENDED:0),key&255) && ok;
        workspace_keys[key]=FALSE;
    }
    if(workspace_left)ok=freerdp_input_send_mouse_event(input,PTR_FLAGS_BUTTON1,workspace_x,workspace_y) && ok;
    if(workspace_right)ok=freerdp_input_send_mouse_event(input,PTR_FLAGS_BUTTON2,workspace_x,workspace_y) && ok;
    workspace_left=workspace_right=FALSE;
    return ok;
}
#endif

static BOOL send_inputs(rdpContext *context, ULONGLONG *nextWorkspaceRefresh) {
    struct probe_input event;
#ifdef CALABI_REMOTE_WORKSPACE
    const int embedded=probe_workspace_enabled();
    while (embedded ? workspace_input(&event) : probe_next_input(&event)) {
        if(embedded){
            if(!event.kind){
                if(!release_workspace_input(context->input))return FALSE;
                continue;
            }
            if(!receivedPaint)continue;
            if(event.kind==PROBE_REFRESH){
                if (workspace_output_paused) continue; // Resumed by sync_workspace_graphics.
                ULONGLONG now=GetTickCount64();
                if(now>=*nextWorkspaceRefresh){
                    *nextWorkspaceRefresh=now+250;
                    (void)request_desktop(context);
                }
                continue;
            }
            if(event.kind==PROBE_KEY_DOWN || event.kind==PROBE_KEY_UP){
                if(event.a>255 || event.b>1)continue;
                workspace_keys[event.a+256*event.b]=event.kind==PROBE_KEY_DOWN;
            }else if(event.kind>=PROBE_MOVE && event.kind<=PROBE_HWHEEL){
                workspace_x=event.a;workspace_y=event.b;
                if(event.kind==PROBE_LEFT_DOWN || event.kind==PROBE_LEFT_UP)workspace_left=event.kind==PROBE_LEFT_DOWN;
                if(event.kind==PROBE_RIGHT_DOWN || event.kind==PROBE_RIGHT_UP)workspace_right=event.kind==PROBE_RIGHT_DOWN;
            }
        }
#else
    (void)nextWorkspaceRefresh;
    while (probe_next_input(&event)) {
#endif
        rdpInput *input = context->input;
        if (event.kind >= PROBE_MOVE && event.kind <= PROBE_HWHEEL) {
            // Position first: scrolling and button transitions operate at the current pointer.
            if (!freerdp_input_send_mouse_event(input, PTR_FLAGS_MOVE, event.a, event.b)) return FALSE;
            UINT16 flags = 0;
            switch (event.kind) {
                case PROBE_MOVE: continue;
                case PROBE_LEFT_DOWN: flags = PTR_FLAGS_BUTTON1 | PTR_FLAGS_DOWN; break;
                case PROBE_LEFT_UP: flags = PTR_FLAGS_BUTTON1; break;
                case PROBE_RIGHT_DOWN: flags = PTR_FLAGS_BUTTON2 | PTR_FLAGS_DOWN; break;
                case PROBE_RIGHT_UP: flags = PTR_FLAGS_BUTTON2; break;
                case PROBE_WHEEL:
                case PROBE_HWHEEL:
                    flags = (event.kind == PROBE_WHEEL ? PTR_FLAGS_WHEEL : PTR_FLAGS_HWHEEL) |
                            ((UINT16)event.delta & WheelRotationMask);
                    break;
            }
            if (!freerdp_input_send_mouse_event(input, flags, event.a, event.b)) return FALSE;
        } else if (event.kind == PROBE_KEY_DOWN || event.kind == PROBE_KEY_UP) {
            UINT16 flags = event.b ? KBD_FLAGS_EXTENDED : 0;
            if (event.kind == PROBE_KEY_UP) flags |= KBD_FLAGS_RELEASE;
            if (!freerdp_input_send_keyboard_event(input, flags, event.a)) return FALSE;
        } else if (event.kind == PROBE_SCAN) {
            UINT16 flags = event.b ? KBD_FLAGS_EXTENDED : 0;
            if (!freerdp_input_send_keyboard_event(input, flags, event.a) ||
                !freerdp_input_send_keyboard_event(input, flags | KBD_FLAGS_RELEASE, event.a)) return FALSE;
        } else if (event.kind == PROBE_TEXT) {
            if (!freerdp_input_send_unicode_keyboard_event(input, 0, event.a) ||
                !freerdp_input_send_unicode_keyboard_event(input, KBD_FLAGS_RELEASE, event.a)) return FALSE;
        }
    }
    return TRUE;
}

static BOOL transport_failure(int result) {
    return result == FREERDP_ERROR_CONNECT_TRANSPORT_FAILED;
}

static int connect_once(const char *host, uint16_t port, const char *domain, const char *user, const char *password,
                        unsigned attempt, ARC_SC_PRIVATE_PACKET *cookie, BOOL *retryable) {
    *retryable = receivedPaint = meshTCPFailed = FALSE;
#ifdef CALABI_REMOTE_WORKSPACE
    workspace_output_paused = FALSE;
    workspace_pause_at = 0;
#endif
#ifdef CALABI_RDP_GFX
    gfx_attempt.advertised = FALSE;
    gfx_attempt.failure = NULL;
#endif
#ifdef _WIN32
    pendingPaint=surfaceOpen=orderOpen=FALSE;
    firstDirty=lastDirty=0;originalSurfaceMarker=NULL;originalOrderMarker=NULL;
#endif
    freerdp *rdp = freerdp_new();
    if (!rdp) return -1;
    if (!freerdp_context_new(rdp)) { freerdp_free(rdp); return -1; }
    int result = -1;
    rdpSettings *s = rdp->context->settings;
#ifdef _WIN32
    const rdpTransportIo *defaults = freerdp_get_io_callbacks(rdp->context);
    if (!defaults) goto cleanup;
    rdpTransportIo callbacks = *defaults;
    callbacks.TCPConnect = connect_mesh_socket;
    if (!freerdp_set_io_callbacks(rdp->context, &callbacks)) goto cleanup;
    if (!freerdp_settings_set_uint32(s, FreeRDP_OsMajorType, OSMAJORTYPE_WINDOWS) ||
        !freerdp_settings_set_uint32(s, FreeRDP_OsMinorType, OSMINORTYPE_WINDOWS_NT) ||
        !freerdp_settings_set_bool(s, FreeRDP_SupportMultitransport, FALSE) ||
        !freerdp_settings_set_uint32(s, FreeRDP_MultitransportFlags, 0)) goto cleanup;
#endif
#ifdef __APPLE__
    if (getenv("CALABI_RDP_LOCAL")) {
        const rdpTransportIo *defaults = freerdp_get_io_callbacks(rdp->context);
        if (!defaults) goto cleanup;
        rdpTransportIo callbacks = *defaults;
        callbacks.TCPConnect = connect_mesh_socket;
        if (!freerdp_set_io_callbacks(rdp->context,&callbacks)) goto cleanup;
    }
#endif
    rdp->PostConnect = connected;
#if defined(_WIN32) || defined(__APPLE__)
    if(getenv("CALABI_RDP_FILE_MESH") && getenv("CALABI_RDP_LOCAL") &&
       !freerdp_settings_set_string(s,FreeRDP_ClientAddress,getenv("CALABI_RDP_LOCAL")))goto cleanup;
#endif
    rdp->PreConnect = clipboard_start;
    rdp->LoadChannels = clipboard_load;
#if defined(_WIN32) && defined(CALABI_RDP_GFX)
    const wchar_t *log_path = _wgetenv(L"CALABI_RDP_GFX_LOG");
    if (log_path) gfx_diagnostic = _wfopen(log_path, L"a");
    if (gfx_attempt.fell_back) gfx_log("classic_retry", 0, 0);
    rdp->PreConnect = win_preconnect;
    rdp->LoadChannels = win_load_channels;
#endif
#ifdef __APPLE__
    if(!display_initialize(s))goto cleanup;
#ifdef CALABI_RDP_GFX
    if (gfx_attempt.fell_back) gfx_log("classic_retry", 0, 0);
#endif
    rdp->PreConnect=mac_preconnect;rdp->LoadChannels=mac_load_channels;
#endif
    rdp->VerifyX509Certificate = verify_leaf;
    if (attempt && (!freerdp_settings_set_uint32(s, FreeRDP_TcpConnectTimeout, 4000) ||
        (cookie->cbLen && !freerdp_settings_set_pointer_len(s, FreeRDP_ServerAutoReconnectCookie, cookie, 1))))
        goto cleanup;
    if (!freerdp_settings_set_string(s, FreeRDP_ServerHostname, host) ||
        !freerdp_settings_set_uint32(s, FreeRDP_ServerPort, port) ||
        !freerdp_settings_set_string(s, FreeRDP_Domain, domain) ||
        !freerdp_settings_set_string(s, FreeRDP_Username, user) ||
        !freerdp_settings_set_string(s, FreeRDP_Password, password) ||
        !freerdp_settings_set_bool(s, FreeRDP_AutoReconnectionEnabled, TRUE) ||
        !freerdp_settings_set_bool(s, FreeRDP_ExternalCertificateManagement, TRUE) ||
        !freerdp_settings_set_bool(s, FreeRDP_NlaSecurity, TRUE) ||
        !freerdp_settings_set_bool(s, FreeRDP_RdpSecurity, FALSE) ||
        !freerdp_settings_set_bool(s, FreeRDP_TlsSecurity, FALSE)
#ifndef __APPLE__
        ||
        !freerdp_settings_set_uint32(s, FreeRDP_DesktopWidth, 1920) ||
        !freerdp_settings_set_uint32(s, FreeRDP_DesktopHeight, 1080)
#endif
        ) goto cleanup;
    if (!freerdp_connect(rdp)) {
        result = (int)freerdp_get_last_error(rdp->context);
        const UINT32 server_error = freerdp_error_info(rdp);
#ifdef CALABI_RDP_GFX
        gfx_connection_error(server_error, (UINT32)result);
#endif
        *retryable = server_error == ERRINFO_SUCCESS &&
                     (meshTCPFailed || transport_failure(result));
        if (!result) result = -1;
        goto cleanup;
    }
    ULONGLONG activated = GetTickCount64();
    ULONGLONG nextWorkspaceRefresh = activated;
    BOOL ioFailed = FALSE;
#ifdef _WIN32
    ULONGLONG nextRefresh = activated;
    BOOL initialFocus = TRUE;
#endif
    if(getenv("CALABI_RDP_FILE_MESH") && probe_clipboard_files_enabled()){puts("rdp-copy-ready");fflush(stdout);}
#ifdef __APPLE__
    extern void mac_mesh_start(void);
    extern void mac_mesh_stop(void);
    if(getenv("CALABI_RDP_FILE_MESH") && probe_clipboard_files_enabled())mac_mesh_start();
#endif
    while (!probe_requested_stop() && !freerdp_shall_disconnect_context(rdp->context)) {
#ifdef CALABI_REMOTE_WORKSPACE
        if(workspace_stopped())break;
#endif
#ifdef __APPLE__
        const ULONGLONG now = GetTickCount64();
        display_poll_at(now);
#ifdef CALABI_RDP_GFX
        if (gfx_attempt.failure || gfx_first_frame_timed_out(receivedPaint, now - activated)) break;
        if (gfx_attempt.fell_back && !receivedPaint && now - activated >= 20000) { result = -2; break; }
#endif
        if (attempt && !receivedPaint && now - activated >= 20000) { result = -2; break; }
#endif
        clipboard_poll();
        HANDLE handles[64];
        DWORD count = freerdp_get_event_handles(rdp->context, handles, 63);
#ifdef CALABI_SHELL_RECEIVE
        extern HANDLE clipboard_shell_wake(void);
        if(count && count<64 && clipboard_shell_wake())handles[count++]=clipboard_shell_wake();
#endif
#ifdef _WIN32
        if (freerdp_focus_required(rdp) || initialFocus) {
            UINT16 locks = (GetKeyState(VK_NUMLOCK)&1 ? KBD_SYNC_NUM_LOCK : 0) |
                           (GetKeyState(VK_CAPITAL)&1 ? KBD_SYNC_CAPS_LOCK : 0) |
                           (GetKeyState(VK_SCROLL)&1 ? KBD_SYNC_SCROLL_LOCK : 0);
            if (!freerdp_input_send_focus_in_event(rdp->context->input, locks)) { ioFailed = TRUE; break; }
            initialFocus = FALSE;
        }
        ULONGLONG now = GetTickCount64();
#ifdef CALABI_RDP_GFX
        if (gfx_attempt.failure || gfx_first_frame_timed_out(receivedPaint, now - activated)) break;
#endif
        if (!receivedPaint && now - activated >= 20000) { result = -2; break; }
        if (!receivedPaint && now >= nextRefresh) {
            if (!request_desktop(rdp->context)
#ifdef CALABI_RDP_GFX
                && !gfx_attempt.advertised
#endif
            ) { ioFailed = TRUE; break; }
            nextRefresh = now + 3000;
        }
        if (!count || MsgWaitForMultipleObjectsEx(count, handles, presentation_wait(now), QS_ALLINPUT,
            MWMO_ALERTABLE | MWMO_INPUTAVAILABLE) == WAIT_FAILED) break;
        MSG msg;
        while (PeekMessageW(&msg,NULL,0,0,PM_REMOVE)) { TranslateMessage(&msg); DispatchMessageW(&msg); }
#else
        DWORD wait=30;
#ifdef CALABI_REMOTE_WORKSPACE
        if(batchMarkedUpdates)wait=presentation_wait(GetTickCount64());
#endif
        if (!count || WaitForMultipleObjects(count, handles, FALSE, wait) == WAIT_FAILED) break;
#endif
        if (!freerdp_check_event_handles(rdp->context) || !send_inputs(rdp->context, &nextWorkspaceRefresh)) { ioFailed = TRUE; break; }
#ifdef CALABI_REMOTE_WORKSPACE
        sync_workspace_graphics(rdp->context, GetTickCount64(), &nextWorkspaceRefresh);
#endif
#ifdef _WIN32
        if (!presentation_wait(GetTickCount64()) && !present_update(rdp->context)) break;
#elif defined(CALABI_REMOTE_WORKSPACE)
        if(batchMarkedUpdates && !presentation_wait(GetTickCount64()) && !present_update(rdp->context))break;
#endif
    }
    if (result != -2) result = (int)freerdp_get_last_error(rdp->context);
    const UINT32 server_error = freerdp_error_info(rdp);
#ifdef CALABI_RDP_GFX
    gfx_connection_error(server_error, (UINT32)result);
#endif
    *retryable = server_error == ERRINFO_SUCCESS &&
                 (transport_failure(result) || (!result && ioFailed) || (attempt && result == -2));
    if (*retryable) {
        const ARC_SC_PRIVATE_PACKET *server =
            freerdp_settings_get_pointer(rdp->context->settings, FreeRDP_ServerAutoReconnectCookie);
        if (server && server->cbLen == sizeof(*server)) *cookie = *server;
    }
    freerdp_disconnect(rdp);
cleanup:
#if defined(_WIN32) && defined(CALABI_RDP_GFX)
    if (gfx_diagnostic) fclose(gfx_diagnostic);
    gfx_diagnostic = NULL;
#endif
#ifdef __APPLE__
    mac_mesh_stop();
#endif
    if(getenv("CALABI_RDP_FILE_MESH")){puts("rdp-copy-end");fflush(stdout);}
    if (rdp->context->gdi) gdi_free(rdp);
    freerdp_context_free(rdp);
#ifdef __APPLE__
    display_stop();
#endif
    clipboard_stop();
    freerdp_free(rdp);
    return result;
}

static int next_reconnect_attempt(unsigned attempt, BOOL retryable, BOOL painted, ULONGLONG uptime) {
    if (!retryable || (!painted && !attempt)) return 0;
    // A flapping peer that paints one frame must not get unlimited attempts.
    if (painted && uptime >= 10000) attempt = 0;
    return attempt == PROBE_RECONNECT_LIMIT ? PROBE_RECONNECT_EXHAUSTED : (int)attempt + 1;
}

int probe_connect(const char *host, uint16_t port, const char *domain, const char *user, const char *password) {
#ifdef CALABI_REMOTE_WORKSPACE
    if(!workspace_start())return -2;
#endif
#ifdef CALABI_RDP_GFX
    const char *requested = getenv("CALABI_RDP_WORKSPACE_GFX");
    gfx_attempt.enabled = probe_workspace_enabled() && requested && !strcmp(requested, "1");
    gfx_attempt.fell_back = FALSE;
#endif
#if defined(_WIN32) || defined(__APPLE__)
    mesh_expected_port = port;
#endif
    static const unsigned delays[PROBE_RECONNECT_LIMIT] = {2000, 3000, 5000, 8000, 10000, 10000};
    ARC_SC_PRIVATE_PACKET cookie = {0};
    unsigned attempt = 0;
    int result = 0;
    while (!probe_requested_stop()) {
#ifdef CALABI_REMOTE_WORKSPACE
        if(workspace_stopped())break;
        memset(workspace_keys,0,sizeof(workspace_keys));
        workspace_left=workspace_right=FALSE;
#endif
        BOOL retryable;
        result = connect_once(host, port, domain, user, password, attempt, &cookie, &retryable);
        if (probe_requested_stop()
#ifdef CALABI_REMOTE_WORKSPACE
            || workspace_stopped()
#endif
        ) { result = 0; break; }
#ifdef CALABI_RDP_GFX
        if (gfx_take_fallback()) {
            // Keep this helper, its login state and the workspace connection.
            struct probe_input discard;
            while (workspace_input(&discard)) {}
            continue;
        }
#endif
        int next = next_reconnect_attempt(attempt, retryable, receivedPaint, GetTickCount64() - firstFrameAt);
        if (!next) break;
        if (next == PROBE_RECONNECT_EXHAUSTED) { result = next; break; }
        attempt = (unsigned)next;
        probe_reconnecting(attempt);
        for (unsigned elapsed = 0; elapsed < delays[attempt - 1] && !probe_requested_stop(); elapsed += 100) {
#ifdef CALABI_REMOTE_WORKSPACE
            struct probe_input discard;
            while(workspace_input(&discard)){}
            if(workspace_stopped())break;
#endif
            Sleep(100);
        }
    }
    SecureZeroMemory(&cookie, sizeof(cookie));
    return result;
}
