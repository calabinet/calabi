use std::{
    ffi::c_void,
    ptr,
    sync::Arc,
    time::{Duration, Instant},
};

use tauri::WebviewWindow;

use crate::rdp_workspace::{frame_revision, Bridge};

extern "C" {
    fn calabi_rdp_view_attach(
        webview: *mut c_void,
        context: *mut c_void,
        tick: extern "C" fn(*mut c_void, *mut c_void),
        release: extern "C" fn(*mut c_void),
    ) -> bool;
    fn calabi_rdp_view_present(
        view: *mut c_void,
        owner: *mut c_void,
        pixels: *const u8,
        width: u32,
        height: u32,
    ) -> bool;
}

struct Renderer {
    active: Box<dyn Fn() -> Option<Arc<Bridge>> + Send>,
    bridge: Option<Arc<Bridge>>,
    shown: u32,
    metrics: Option<Metrics>,
}

struct Metrics {
    start: Instant,
    first: u32,
    submitted: u32,
    last: Instant,
    max_gap: Duration,
}

impl Renderer {
    fn draw(&mut self, view: *mut c_void) {
        let active = (self.active)();
        let same = match (&self.bridge, &active) {
            (Some(previous), Some(next)) => Arc::ptr_eq(previous, next),
            (None, None) => true,
            _ => false,
        };
        if !same {
            unsafe { calabi_rdp_view_present(view, ptr::null_mut(), ptr::null(), 0, 0) };
            self.bridge = active;
            self.shown = 0;
            self.metrics = None;
        }
        let Some(bridge) = &self.bridge else { return };
        let frame = bridge.latest_frame();
        let revision = frame_revision(&frame);
        if revision == 0 || revision == self.shown {
            return;
        }
        let width = u32::from_le_bytes(frame[4..8].try_into().unwrap());
        let height = u32::from_le_bytes(frame[8..12].try_into().unwrap());
        let pixels = frame[12..].as_ptr();
        // CoreGraphics owns this Arc reference until it releases the provider.
        let owner = Arc::into_raw(frame).cast_mut().cast();
        if !unsafe { calabi_rdp_view_present(view, owner, pixels, width, height) } {
            return;
        }
        self.shown = revision;
        self.record(revision, width, height);
    }

    fn record(&mut self, revision: u32, width: u32, height: u32) {
        let now = Instant::now();
        let metrics = self.metrics.get_or_insert(Metrics {
            start: now,
            first: revision,
            submitted: 0,
            last: now,
            max_gap: Duration::ZERO,
        });
        metrics.submitted += 1;
        metrics.max_gap = metrics.max_gap.max(now - metrics.last);
        metrics.last = now;
        let elapsed = now - metrics.start;
        if elapsed >= Duration::from_secs(5) {
            log::info!(
                "rdp_render mode=native size={}x{} elapsed_ms={} received={} submitted={} max_gap_ms={}",
                width, height, elapsed.as_millis(), revision.wrapping_sub(metrics.first),
                metrics.submitted - 1, metrics.max_gap.as_millis()
            );
            self.metrics = None;
        }
    }
}

extern "C" fn tick(context: *mut c_void, view: *mut c_void) {
    // AppKit invokes and destroys the context on the main thread.
    unsafe { (&mut *context.cast::<Renderer>()).draw(view) };
}

extern "C" fn release_context(context: *mut c_void) {
    unsafe { drop(Box::from_raw(context.cast::<Renderer>())) };
}

#[no_mangle]
extern "C" fn calabi_rdp_release_pixels(owner: *mut c_void) {
    unsafe { drop(Arc::from_raw(owner.cast::<Vec<u8>>())) };
}

pub async fn attach(
    window: &WebviewWindow,
    active: impl Fn() -> Option<Arc<Bridge>> + Send + 'static,
) -> bool {
    let (send, receive) = tokio::sync::oneshot::channel();
    if window
        .with_webview(move |webview| {
            let context = Box::into_raw(Box::new(Renderer {
                active: Box::new(active),
                bridge: None,
                shown: 0,
                metrics: None,
            }))
            .cast();
            let attached =
                unsafe { calabi_rdp_view_attach(webview.inner(), context, tick, release_context) };
            if !attached {
                release_context(context);
            }
            let _ = send.send(attached);
        })
        .is_err()
    {
        return false;
    }
    receive.await.unwrap_or(false)
}
