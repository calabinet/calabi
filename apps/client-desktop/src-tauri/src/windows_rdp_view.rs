use std::{
    ffi::c_void,
    ptr::{null, null_mut},
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

use tauri::WebviewWindow;
use windows_sys::{
    core::w,
    Win32::{
        Foundation::{HWND, LPARAM, LRESULT, RECT, WPARAM},
        Graphics::Gdi::{
            BeginPaint, CreateSolidBrush, DeleteObject, EndPaint, FillRect, InvalidateRect,
            RedrawWindow, SetBrushOrgEx, SetStretchBltMode, StretchDIBits, BITMAPINFO, BI_RGB,
            DIB_RGB_COLORS, GDI_ERROR, HALFTONE, HDC, PAINTSTRUCT, RDW_INVALIDATE, RDW_NOCHILDREN,
            RDW_NOERASE, RDW_UPDATENOW, SRCCOPY,
        },
        System::LibraryLoader::GetModuleHandleW,
        UI::Shell::{DefSubclassProc, RemoveWindowSubclass, SetWindowSubclass},
        UI::WindowsAndMessaging::{
            CreateWindowExW, DefWindowProcW, DestroyWindow, GetClientRect, GetParent,
            GetWindowLongPtrW, IsIconic, IsWindowVisible, KillTimer, RegisterClassW, SetTimer,
            SetWindowLongPtrW, SetWindowPos, GWLP_USERDATA, HTTRANSPARENT, HWND_BOTTOM,
            SIZE_MINIMIZED, SWP_NOACTIVATE, SWP_NOMOVE, SWP_NOREDRAW, SWP_NOZORDER, SWP_SHOWWINDOW,
            WM_ERASEBKGND, WM_NCDESTROY, WM_NCHITTEST, WM_PAINT, WM_SIZE, WM_TIMER, WNDCLASSW,
            WS_CHILD,
        },
    },
};

use crate::rdp_workspace::{frame_revision, Bridge};

const CLASS: windows_sys::core::PCWSTR = w!("CalabiRdpBackdrop");
const TIMER: usize = 1;

struct Renderer {
    active: Box<dyn Fn() -> Option<Arc<Bridge>> + Send>,
    bridge: Option<Arc<Bridge>>,
    frame: Arc<Vec<u8>>,
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
    fn update(&mut self) -> bool {
        let active = (self.active)();
        let switched = match (&self.bridge, &active) {
            (Some(old), Some(new)) => !Arc::ptr_eq(old, new),
            (None, None) => false,
            _ => true,
        };
        if switched {
            self.bridge = active;
            self.frame = Arc::default();
            self.shown = 0;
            self.metrics = None;
        }
        if let Some(bridge) = &self.bridge {
            let frame = bridge.latest_frame();
            if frame_revision(&frame) != frame_revision(&self.frame) {
                self.frame = frame;
                return true;
            }
        }
        switched
    }

    fn record(&mut self, width: i32, height: i32) {
        let revision = frame_revision(&self.frame);
        if revision == self.shown {
            return;
        }
        self.shown = revision;
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
                "rdp_render mode=native size={width}x{height} elapsed_ms={} received={} submitted={} max_gap_ms={}",
                elapsed.as_millis(),
                revision.wrapping_sub(metrics.first),
                metrics.submitted - 1,
                metrics.max_gap.as_millis()
            );
            self.metrics = None;
        }
    }

    unsafe fn paint(&mut self, dc: HDC, bounds: &RECT) {
        let (client_width, client_height) = (bounds.right, bounds.bottom);
        if self.frame.len() < 12 || client_width <= 0 || client_height <= 0 {
            fill_background(dc, bounds);
            return;
        }
        // The bridge validates dimensions and the BGRA payload before publishing it.
        let width = i32::from_le_bytes(self.frame[4..8].try_into().unwrap());
        let height = i32::from_le_bytes(self.frame[8..12].try_into().unwrap());
        let (x, y, fitted_width, fitted_height) = fit(client_width, client_height, width, height);
        if fitted_width != width || fitted_height != height {
            SetStretchBltMode(dc, HALFTONE);
            SetBrushOrgEx(dc, 0, 0, null_mut());
        }
        let mut bitmap = BITMAPINFO::default();
        bitmap.bmiHeader.biSize = std::mem::size_of_val(&bitmap.bmiHeader) as u32;
        bitmap.bmiHeader.biWidth = width;
        bitmap.bmiHeader.biHeight = -height;
        bitmap.bmiHeader.biPlanes = 1;
        bitmap.bmiHeader.biBitCount = 32;
        bitmap.bmiHeader.biCompression = BI_RGB;
        let lines = StretchDIBits(
            dc,
            x,
            y,
            fitted_width,
            fitted_height,
            0,
            0,
            width,
            height,
            self.frame[12..].as_ptr().cast::<c_void>(),
            &bitmap,
            DIB_RGB_COLORS,
            SRCCOPY,
        );
        if lines != 0 && lines != GDI_ERROR {
            // Keep the desktop pixels intact while filling any newly exposed margins.
            fill_margins(dc, bounds, x, y, fitted_width, fitted_height);
            self.record(width, height);
        }
    }
}

fn fit(client_width: i32, client_height: i32, width: i32, height: i32) -> (i32, i32, i32, i32) {
    let scale = (f64::from(client_width) / f64::from(width))
        .min(f64::from(client_height) / f64::from(height));
    let fitted_width = (f64::from(width) * scale).round() as i32;
    let fitted_height = (f64::from(height) * scale).round() as i32;
    (
        (client_width - fitted_width) / 2,
        (client_height - fitted_height) / 2,
        fitted_width.max(1),
        fitted_height.max(1),
    )
}

unsafe fn fill_background(dc: HDC, bounds: &RECT) {
    let brush = CreateSolidBrush(8 | 12 << 8 | 22 << 16);
    if !brush.is_null() {
        FillRect(dc, bounds, brush);
        DeleteObject(brush);
    }
}

unsafe fn fill_margins(dc: HDC, bounds: &RECT, x: i32, y: i32, width: i32, height: i32) {
    let right = x + width;
    let bottom = y + height;
    if x == 0 && y == 0 && right == bounds.right && bottom == bounds.bottom {
        return;
    }
    let brush = CreateSolidBrush(8 | 12 << 8 | 22 << 16);
    if brush.is_null() {
        return;
    }
    for (left, top, right, bottom) in [
        (0, 0, bounds.right, y),
        (0, bottom, bounds.right, bounds.bottom),
        (0, y, x, bottom),
        (right, y, bounds.right, bottom),
    ] {
        if left < right && top < bottom {
            FillRect(
                dc,
                &RECT {
                    left,
                    top,
                    right,
                    bottom,
                },
                brush,
            );
        }
    }
    DeleteObject(brush);
}

unsafe extern "system" fn parent_proc(
    parent: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
    id: usize,
    child: usize,
) -> LRESULT {
    if message == WM_NCDESTROY {
        RemoveWindowSubclass(parent, Some(parent_proc), id);
    }
    let result = DefSubclassProc(parent, message, wparam, lparam);
    if message == WM_SIZE && wparam != SIZE_MINIMIZED as usize {
        let child = child as HWND;
        let mut bounds = RECT::default();
        if GetClientRect(parent, &mut bounds) != 0
            && bounds.right > 0
            && bounds.bottom > 0
            && SetWindowPos(
                child,
                null_mut(),
                0,
                0,
                bounds.right,
                bounds.bottom,
                SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOZORDER | SWP_NOREDRAW,
            ) != 0
        {
            // Resize alongside WebView2 and repaint the retained frame before returning.
            RedrawWindow(
                child,
                null(),
                null_mut(),
                RDW_INVALIDATE | RDW_NOCHILDREN | RDW_NOERASE | RDW_UPDATENOW,
            );
        }
    }
    result
}

unsafe extern "system" fn window_proc(
    hwnd: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    let renderer = GetWindowLongPtrW(hwnd, GWLP_USERDATA) as *mut Renderer;
    match message {
        WM_NCHITTEST => HTTRANSPARENT as LRESULT,
        WM_ERASEBKGND => 1,
        WM_TIMER if wparam == TIMER && !renderer.is_null() => {
            let parent = GetParent(hwnd);
            if IsWindowVisible(parent) == 0 || IsIconic(parent) != 0 {
                (*renderer).metrics = None;
                return 0;
            }
            if (*renderer).update() {
                InvalidateRect(hwnd, null(), 0);
            }
            0
        }
        WM_PAINT if !renderer.is_null() => {
            let mut paint = PAINTSTRUCT::default();
            let dc = BeginPaint(hwnd, &mut paint);
            let mut bounds = RECT::default();
            if !dc.is_null() && GetClientRect(hwnd, &mut bounds) != 0 {
                (*renderer).paint(dc, &bounds);
            }
            EndPaint(hwnd, &paint);
            0
        }
        WM_NCDESTROY if !renderer.is_null() => {
            KillTimer(hwnd, TIMER);
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0);
            drop(Box::from_raw(renderer));
            DefWindowProcW(hwnd, message, wparam, lparam)
        }
        _ => DefWindowProcW(hwnd, message, wparam, lparam),
    }
}

unsafe fn create(parent: HWND, active: impl Fn() -> Option<Arc<Bridge>> + Send + 'static) -> bool {
    static REGISTERED: OnceLock<bool> = OnceLock::new();
    let instance = GetModuleHandleW(null());
    if !*REGISTERED.get_or_init(|| {
        let class = WNDCLASSW {
            lpfnWndProc: Some(window_proc),
            hInstance: instance,
            lpszClassName: CLASS,
            ..Default::default()
        };
        RegisterClassW(&class) != 0
    }) {
        return false;
    }
    let mut bounds = RECT::default();
    if GetClientRect(parent, &mut bounds) == 0 {
        return false;
    }
    let size = (bounds.right, bounds.bottom);
    let hwnd = CreateWindowExW(
        0,
        CLASS,
        null(),
        WS_CHILD,
        0,
        0,
        size.0,
        size.1,
        parent,
        null_mut(),
        instance,
        null(),
    );
    if hwnd.is_null() {
        return false;
    }
    let renderer = Box::new(Renderer {
        active: Box::new(active),
        bridge: None,
        frame: Arc::default(),
        shown: 0,
        metrics: None,
    });
    // The UI thread owns this state until the child receives WM_NCDESTROY.
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(renderer) as isize);
    if SetTimer(hwnd, TIMER, 16, None) == 0
        || SetWindowPos(
            hwnd,
            HWND_BOTTOM,
            0,
            0,
            size.0,
            size.1,
            SWP_NOACTIVATE | SWP_SHOWWINDOW,
        ) == 0
        || SetWindowSubclass(parent, Some(parent_proc), hwnd as usize, hwnd as usize) == 0
    {
        DestroyWindow(hwnd);
        return false;
    }
    true
}

pub async fn attach(
    window: &WebviewWindow,
    active: impl Fn() -> Option<Arc<Bridge>> + Send + 'static,
) -> bool {
    let (send, receive) = tokio::sync::oneshot::channel();
    let workspace = window.clone();
    if window
        .run_on_main_thread(move || {
            let attached = workspace
                .hwnd()
                .is_ok_and(|parent| unsafe { create(parent.0, active) });
            let _ = send.send(attached);
        })
        .is_err()
    {
        return false;
    }
    receive.await.unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Graphics::Gdi::{
        CreateCompatibleDC, CreateDIBSection, DeleteDC, GdiFlush, SelectObject,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{FindWindowExW, WS_POPUP};

    #[test]
    fn native_frame_fits_client_pixels() {
        assert_eq!(fit(1920, 1080, 1920, 1080), (0, 0, 1920, 1080));
        assert_eq!(fit(1024, 640, 1920, 1080), (0, 32, 1024, 576));
        assert_eq!(fit(2560, 1080, 1920, 1080), (320, 0, 1920, 1080));
    }

    #[test]
    fn native_child_resizes_in_the_parent_size_message() {
        unsafe {
            let parent = CreateWindowExW(
                0,
                w!("STATIC"),
                null(),
                WS_POPUP,
                0,
                0,
                640,
                480,
                null_mut(),
                null_mut(),
                GetModuleHandleW(null()),
                null(),
            );
            assert!(!parent.is_null());
            assert!(create(parent, || None));
            let child = FindWindowExW(parent, null_mut(), CLASS, null());
            assert!(!child.is_null());

            // No timer dispatch between SetWindowPos and the size check.
            for (width, height) in [(960, 540), (640, 480)] {
                assert_ne!(
                    SetWindowPos(
                        parent,
                        null_mut(),
                        0,
                        0,
                        width,
                        height,
                        SWP_NOACTIVATE | SWP_NOMOVE | SWP_NOZORDER,
                    ),
                    0
                );
                let mut bounds = RECT::default();
                assert_ne!(GetClientRect(child, &mut bounds), 0);
                assert_eq!((bounds.right, bounds.bottom), (width, height));
            }
            DestroyWindow(parent);
        }
    }

    #[test]
    fn native_frame_preserves_bgra_colors_and_row_order() {
        let mut bitmap = BITMAPINFO::default();
        bitmap.bmiHeader.biSize = std::mem::size_of_val(&bitmap.bmiHeader) as u32;
        bitmap.bmiHeader.biWidth = 3;
        bitmap.bmiHeader.biHeight = -2;
        bitmap.bmiHeader.biPlanes = 1;
        bitmap.bmiHeader.biBitCount = 32;
        let mut pixels = null_mut();
        unsafe {
            let dc = CreateCompatibleDC(null_mut());
            assert!(!dc.is_null());
            let dib = CreateDIBSection(dc, &bitmap, DIB_RGB_COLORS, &mut pixels, null_mut(), 0);
            assert!(!dib.is_null() && !pixels.is_null());
            let previous = SelectObject(dc, dib);
            let mut frame = Vec::new();
            for value in [1_u32, 1, 2] {
                frame.extend(value.to_le_bytes());
            }
            frame.extend([0, 0, 255, 255, 255, 0, 0, 255]);
            let mut renderer = Renderer {
                active: Box::new(|| None),
                bridge: None,
                frame: Arc::new(frame),
                shown: 0,
                metrics: None,
            };
            renderer.paint(
                dc,
                &RECT {
                    left: 0,
                    top: 0,
                    right: 3,
                    bottom: 2,
                },
            );
            GdiFlush();
            let actual = std::slice::from_raw_parts(pixels.cast::<u8>(), 24).to_vec();
            SelectObject(dc, previous);
            DeleteObject(dib);
            DeleteDC(dc);
            assert_eq!(&actual[4..7], &[0, 0, 255]);
            assert_eq!(&actual[16..19], &[255, 0, 0]);
            for offset in [0, 8, 12, 20] {
                assert_eq!(&actual[offset..offset + 3], &[22, 12, 8]);
            }
        }
    }
}
