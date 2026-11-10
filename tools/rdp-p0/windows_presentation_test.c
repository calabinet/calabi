// Synthetic GDI update sequence; no server, credentials or desktop capture.
#include <assert.h>
#include "session.c"

static unsigned presents, originalEnds;
static BYTE displayed[16];
void probe_frame(const uint8_t *src,int w,int h,unsigned stride) {
    assert(w==1 && h==4 && stride==4);
    memcpy(displayed,src,sizeof(displayed));
    presents++;
}
int probe_verify_leaf(const uint8_t *p,size_t n){return 0;}
int probe_next_input(struct probe_input *e){return 0;}
void windows_waiting_for_frame(void){}
int probe_requested_stop(void){return 0;}
void probe_reconnecting(unsigned attempt){(void)attempt;}
int windows_mesh_connect(const char *h,int p,uint16_t expected,DWORD t){return -1;}
BOOL clipboard_start(freerdp *rdp){(void)rdp;return TRUE;}
BOOL clipboard_load(freerdp *rdp){(void)rdp;return TRUE;}
void clipboard_poll(void){}
void clipboard_stop(void){}
int probe_clipboard_files_enabled(void){return 0;}
static BOOL original(rdpContext *c,const SURFACE_FRAME_MARKER *m){
    if(m->frameAction==SURFACECMD_FRAMEACTION_END)originalEnds++;
    return TRUE;
}
static BOOL original_order(rdpContext *c,const FRAME_MARKER_ORDER *m){return TRUE;}

#ifdef CALABI_REMOTE_WORKSPACE
static unsigned pauses, resumes, refreshes;
static BOOL allow_resume = TRUE;

static BOOL suppress_output(rdpContext *context, BYTE allow, const RECTANGLE_16 *area) {
    (void)context;
    if (!allow) {
        assert(!area);
        pauses++;
        return TRUE;
    }
    assert(area && area->left == 0 && area->top == 0 && area->right == 0 && area->bottom == 3);
    resumes++;
    return allow_resume;
}

static BOOL refresh_output(rdpContext *context, BYTE count, const RECTANGLE_16 *areas) {
    (void)context;
    assert(count == 1 && areas && areas->right == 0 && areas->bottom == 3);
    refreshes++;
    return TRUE;
}

static void check_background_graphics(rdpContext *context) {
    rdpUpdate update = {0};
    update.SuppressOutput = suppress_output;
    update.RefreshRect = refresh_output;
    context->update = &update;
    context->settings = freerdp_settings_new(0);
    assert(context->settings);
    assert(freerdp_settings_set_bool(context->settings, FreeRDP_SuppressOutput, TRUE));
    ULONGLONG next_refresh = 0;

    receivedPaint = FALSE;
    InterlockedExchange(&workspace_selection, 1);
    sync_workspace_graphics(context, 1000, &next_refresh);
    assert(workspace_pause_at == 0 && pauses == 0);
    receivedPaint = TRUE;
    sync_workspace_graphics(context, 1500, &next_refresh);
    sync_workspace_graphics(context, 1799, &next_refresh);
    InterlockedExchange(&workspace_selected, 1);
    sync_workspace_graphics(context, 1800, &next_refresh);
    assert(workspace_pause_at == 0 && pauses == 0);

    InterlockedExchange(&workspace_selected, 0);
    sync_workspace_graphics(context, 2000, &next_refresh);
    sync_workspace_graphics(context, 2300, &next_refresh);
    sync_workspace_graphics(context, 2400, &next_refresh);
    assert(workspace_output_paused && pauses == 1);
    const unsigned before = presents;
    assert(paint(context) && presents == before);

    InterlockedExchange(&workspace_selected, 1);
    allow_resume = FALSE;
    sync_workspace_graphics(context, 2500, &next_refresh);
    sync_workspace_graphics(context, 2600, &next_refresh);
    assert(workspace_output_paused && resumes == 1 && refreshes == 0);
    allow_resume = TRUE;
    sync_workspace_graphics(context, 2750, &next_refresh);
    assert(!workspace_output_paused && resumes == 2 && refreshes == 1);
    assert(paint(context) && presents == before + 1);

    InterlockedExchange(&workspace_selected, 0);
    assert(freerdp_settings_set_bool(context->settings, FreeRDP_SuppressOutput, FALSE));
    sync_workspace_graphics(context, 2800, &next_refresh);
    sync_workspace_graphics(context, 3200, &next_refresh);
    assert(!workspace_output_paused && pauses == 1);
    freerdp_settings_free(context->settings);
}
#endif

int main(void){
    assert(next_reconnect_attempt(0,TRUE,FALSE,0)==0);
    assert(next_reconnect_attempt(0,TRUE,TRUE,0)==1);
    for(unsigned i=1;i<PROBE_RECONNECT_LIMIT;i++)
        assert(next_reconnect_attempt(i,TRUE,FALSE,0)==(int)i+1);
    assert(next_reconnect_attempt(PROBE_RECONNECT_LIMIT,TRUE,TRUE,9999)==PROBE_RECONNECT_EXHAUSTED);
    assert(next_reconnect_attempt(PROBE_RECONNECT_LIMIT,TRUE,TRUE,10000)==1);
    assert(next_reconnect_attempt(1,FALSE,FALSE,0)==0);
    assert(!transport_failure(FREERDP_ERROR_CONNECT_LOGON_FAILURE));
    assert(!transport_failure(FREERDP_ERROR_TLS_CONNECT_FAILED));
    BYTE pixels[16]={0};
    GDI_RGN region={0}; GDI_WND wnd={0}; GDI_DC dc={0}; gdiBitmap bitmap={0};
    rdpGdi gdi={0}; rdpContext ctx={0};
    wnd.invalid=&region;dc.hwnd=&wnd;bitmap.hdc=&dc;gdi.primary=&bitmap;
    gdi.primary_buffer=pixels;gdi.width=1;gdi.height=4;gdi.stride=4;ctx.gdi=&gdi;
    originalSurfaceMarker=original;originalOrderMarker=original_order;
    for(int variant=0;variant<2;variant++){
        SURFACE_FRAME_MARKER surface={0};FRAME_MARKER_ORDER order={0};
        if(variant)assert(order_marker(&ctx,&order));else assert(surface_marker(&ctx,&surface));
        for(int row=0;row<4;row++){
            assert(begin_update(&ctx));memset(pixels+row*4,variant+1,4);
            region.null=FALSE;assert(collect_update(&ctx));
            assert(presentation_wait(lastDirty+500)!=0 && presents==(unsigned)variant);
        }
        surface.frameAction=SURFACECMD_FRAMEACTION_END;order.action=FRAME_END;
        if(variant)assert(order_marker(&ctx,&order));else assert(surface_marker(&ctx,&surface));
        assert(presents==(unsigned)variant+1 && memcmp(pixels,displayed,16)==0);
    }
    assert(originalEnds==1);
    assert(begin_update(&ctx));assert(collect_update(&ctx));assert(!pendingPaint);
    region.null=FALSE;assert(collect_update(&ctx));
    assert(presentation_wait(lastDirty+15)>0 && presentation_wait(lastDirty+16)==0);
    lastDirty=firstDirty+49;
    assert(presentation_wait(firstDirty+49)>0 && presentation_wait(firstDirty+50)==0);
    assert(present_update(&ctx) && presents==3);
    // In the workspace the server may end a marked update after each strip.
    // Keep the displayed frame intact until the burst settles, but ACK every marker.
    batchMarkedUpdates=TRUE;
    for(int row=0;row<4;row++){
        SURFACE_FRAME_MARKER marker={0};
        assert(surface_marker(&ctx,&marker) && begin_update(&ctx));
        memset(pixels+row*4,4,4);
        region.null=FALSE;
        assert(collect_update(&ctx));
        marker.frameAction=SURFACECMD_FRAMEACTION_END;
        assert(surface_marker(&ctx,&marker));
        assert(presents==3 && pendingPaint);
    }
    assert(originalEnds==5 && presentation_wait(lastDirty+15)>0 && presentation_wait(lastDirty+16)==0);
    assert(present_update(&ctx) && presents==4 && memcmp(pixels,displayed,16)==0);
#ifdef CALABI_REMOTE_WORKSPACE
    check_background_graphics(&ctx);
    puts("Windows workspace graphics pause and resume passed.");
#endif
    puts("Windows presentation and bounded RDP reconnect policy passed.");
    return 0;
}
