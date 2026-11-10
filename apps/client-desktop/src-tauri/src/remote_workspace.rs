use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};

use serde::Deserialize;
use serde_json::{json, Value};
use tauri::{
    ipc::Response, Manager, State, Theme, WebviewUrl, WebviewWindow, WebviewWindowBuilder,
};

use crate::rdp_workspace::Bridge;

pub const LABEL: &str = "ssh-session-workspace";
pub const LOGIN_DISPLAY_PREFIX: &str = "remote-display ";

pub struct LoginDisplay(i32, i32);

impl LoginDisplay {
    pub fn parse(value: &str) -> Option<Self> {
        let (x, y) = value.split_once(' ')?;
        Some(Self(x.parse().ok()?, y.parse().ok()?))
    }
}

#[derive(Default)]
pub struct Workspace {
    opening: tokio::sync::Mutex<()>,
    state: Arc<Mutex<WorkspaceState>>,
    generation: AtomicU64,
}

#[derive(Default)]
struct WorkspaceState {
    generation: u64,
    url: Option<reqwest::Url>,
    active: Option<String>,
    sessions: Vec<Entry>,
    #[cfg(any(windows, all(target_os = "macos", feature = "rdp-native-macos")))]
    native_rdp: bool,
}

impl WorkspaceState {
    fn active_rdp(&self) -> Option<Arc<Bridge>> {
        self.sessions
            .iter()
            .find(|entry| Some(entry.id.as_str()) == self.active.as_deref())
            .and_then(|entry| entry.rdp.clone())
    }

    fn native_rdp(&self) -> bool {
        #[cfg(any(windows, all(target_os = "macos", feature = "rdp-native-macos")))]
        return self.native_rdp;
        #[cfg(not(any(windows, all(target_os = "macos", feature = "rdp-native-macos"))))]
        false
    }
}

struct Entry {
    id: String,
    name: String,
    rdp: Option<Arc<Bridge>>,
}

impl Entry {
    fn stop(&self, app: &tauri::AppHandle) {
        if let Some(rdp) = &self.rdp {
            rdp.stop();
        } else {
            crate::ssh::remove_session(&app.state::<crate::ssh::Windows>(), &self.id);
        }
    }
}

#[cfg(target_os = "macos")]
fn sync_rdp_viewport(window: &WebviewWindow) {
    let workspace = window.state::<Workspace>();
    let rdp = workspace.state.lock().unwrap().active_rdp();
    let Some(rdp) = rdp else { return };
    let (Ok(size), Ok(scale), Ok(fullscreen)) = (
        window.inner_size(),
        window.scale_factor(),
        window.is_fullscreen(),
    ) else {
        return;
    };
    if !scale.is_finite() || scale < 1.0 {
        return;
    }
    let logical = size.to_logical::<f64>(scale);
    if logical.width < 1.0 || logical.height < 1.0 {
        return;
    }
    rdp.resize(
        logical.width.round() as u16,
        logical.height.round() as u16,
        (scale * 100.0).round().clamp(100.0, 500.0) as i16,
        fullscreen,
    );
}

pub fn url(mut url: reqwest::Url) -> reqwest::Url {
    url.set_fragment(Some("/ssh-session"));
    url
}

pub async fn add(
    app: &tauri::AppHandle,
    url: reqwest::Url,
    id: &str,
    name: &str,
    rdp: Option<Arc<Bridge>>,
    login_display: Option<LoginDisplay>,
) -> Result<WebviewWindow, String> {
    let workspace = app.state::<Workspace>();
    let _opening = workspace.opening.lock().await;
    let window = if let Some(window) = app.get_webview_window(LABEL) {
        if workspace.state.lock().unwrap().url.as_ref() != Some(&url) {
            return Err("Remote workspace origin changed".into());
        }
        window
    } else {
        let monitor = if let Some(LoginDisplay(x, y)) = login_display {
            let (send, receive) = tokio::sync::oneshot::channel();
            let handle = app.clone();
            // The monitor's work area and scale query AppKit on macOS.
            let _ = app.run_on_main_thread(move || {
                let _ = send.send(handle.monitor_from_point(f64::from(x), f64::from(y)).ok().flatten());
            });
            receive.await.ok().flatten()
        } else {
            None
        };
        let (mut width, mut height) = (1024.0_f64, 640.0_f64);
        if let Some(monitor) = &monitor {
            let work = monitor
                .work_area()
                .size
                .to_logical::<f64>(monitor.scale_factor());
            width = width.min((work.width - 32.0).max(480.0));
            height = height.min((work.height - 48.0).max(320.0));
        }
        // Windows logical origins can overlap on mixed-DPI screens. Move the
        // hidden window in physical pixels before requesting fullscreen.
        let place_after_build = cfg!(windows) && monitor.is_some();
        let position = monitor.map(|monitor| {
            let work = monitor.work_area();
            let scale = monitor.scale_factor();
            let x = f64::from(work.position.x)
                + ((f64::from(work.size.width) - width * scale) / 2.0).max(0.0);
            let y = f64::from(work.position.y)
                + ((f64::from(work.size.height) - height * scale) / 2.0).max(0.0);
            (x, y, scale)
        });
        let build = |alpha| {
            let allowed = url.clone();
            let builder = WebviewWindowBuilder::new(app, LABEL, WebviewUrl::External(url.clone()))
                .title("Calabi")
                .inner_size(width, height)
                .min_inner_size(480.0, 320.0)
                .fullscreen(rdp.is_some() && !place_after_build)
                .theme(Some(Theme::Dark))
                .background_color(tauri::window::Color(8, 12, 22, alpha))
                .visible(false)
                .user_agent(&crate::desktop_user_agent())
                .on_navigation(move |next| next == &allowed)
                .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny);
            let builder = match position {
                Some((x, y, scale)) if !place_after_build => builder.position(x / scale, y / scale),
                _ => builder,
            };
            #[cfg(all(target_os = "macos", feature = "rdp-native-macos"))]
            let builder = builder
                .transparent(true)
                .background_color(tauri::window::Color(0, 0, 0, 0));
            builder.build().map_err(|error| error.to_string())
        };
        #[cfg(windows)]
        let (window, native_requested) = if std::env::args_os().any(|arg| arg == "--rdp-canvas-renderer") {
            (build(255)?, false)
        } else {
            match build(0) {
                Ok(window) => (window, true),
                Err(error) => {
                    log::warn!("rdp_render transparent workspace unavailable; using canvas: {error}");
                    (build(255)?, false)
                }
            }
        };
        #[cfg(not(windows))]
        let window = build(255)?;
        if let Some((x, y, scale)) = position.filter(|_| place_after_build) {
            let _ = window.set_position(tauri::PhysicalPosition::new(
                x.round() as i32,
                y.round() as i32,
            ));
            let _ = window.set_size(
                tauri::LogicalSize::new(width, height).to_physical::<u32>(scale),
            );
            if rdp.is_some() {
                let _ = window.set_fullscreen(true);
            }
        }
        let app = app.clone();
        let generation = workspace.generation.fetch_add(1, Ordering::Relaxed) + 1;
        workspace.state.lock().unwrap().generation = generation;
        window.on_window_event(move |event| {
            #[cfg(target_os = "macos")]
            if matches!(
                event,
                tauri::WindowEvent::Resized(_)
                    | tauri::WindowEvent::ScaleFactorChanged { .. }
                    | tauri::WindowEvent::Focused(true)
            ) {
                if let Some(window) = app.get_webview_window(LABEL) {
                    sync_rdp_viewport(&window);
                }
            }
            if matches!(event, tauri::WindowEvent::Destroyed) {
                let workspace = app.state::<Workspace>();
                let previous = {
                    let mut state = workspace.state.lock().unwrap();
                    if state.generation != generation {
                        return;
                    }
                    std::mem::take(&mut *state)
                };
                for entry in previous.sessions {
                    entry.stop(&app);
                }
            }
        });
        #[cfg(all(target_os = "macos", feature = "rdp-native-macos"))]
        {
            let state = Arc::clone(&workspace.state);
            let attached = crate::macos_rdp_view::attach(&window, move || {
                let state = state.lock().unwrap();
                if state.generation != generation {
                    return None;
                }
                state.active_rdp()
            })
            .await;
            let mut state = workspace.state.lock().unwrap();
            if state.generation == generation {
                state.native_rdp = attached;
            }
            if attached {
                log::info!("rdp_render native view attached");
            } else {
                log::warn!("rdp_render native view unavailable; using canvas");
            }
        }
        #[cfg(windows)]
        if native_requested {
            let state = Arc::clone(&workspace.state);
            let attached = crate::windows_rdp_view::attach(&window, move || {
                let state = state.lock().unwrap();
                if state.generation != generation {
                    return None;
                }
                state.active_rdp()
            })
            .await;
            let mut state = workspace.state.lock().unwrap();
            if state.generation == generation {
                state.native_rdp = attached;
            }
            if attached {
                log::info!("rdp_render native view attached (Win32 GDI)");
            } else {
                let _ = window.set_background_color(Some(tauri::window::Color(8, 12, 22, 255)));
                log::warn!("rdp_render native view unavailable; using canvas");
            }
        }
        window
    };
    {
        let mut state = workspace.state.lock().unwrap();
        state.url = Some(url);
        state.sessions.push(Entry {
            id: id.into(),
            name: name.into(),
            rdp,
        });
    }
    if let Err(error) = select(&window, id) {
        let _ = remove_inner(app, &workspace, id);
        return Err(error);
    }
    Ok(window)
}

pub fn select(window: &WebviewWindow, id: &str) -> Result<(), String> {
    let workspace = window.state::<Workspace>();
    let name = {
        let mut state = workspace.state.lock().unwrap();
        let entry = state
            .sessions
            .iter()
            .find(|entry| entry.id == id)
            .ok_or("Unknown remote session")?;
        let name = entry.name.clone();
        if state.active.as_deref() != Some(id) {
            if let Some(previous) = state
                .sessions
                .iter()
                .find(|entry| Some(entry.id.as_str()) == state.active.as_deref())
                .and_then(|entry| entry.rdp.as_ref())
            {
                previous.select(false)?;
            }
            state.active = None;
            if let Some(next) = state
                .sessions
                .iter()
                .find(|entry| entry.id == id)
                .and_then(|entry| entry.rdp.as_ref())
            {
                next.select(true)?;
            }
            state.active = Some(id.into());
        }
        name
    };
    let _ = window.set_title(&format!("Calabi · {name}"));
    #[cfg(target_os = "macos")]
    sync_rdp_viewport(window);
    Ok(())
}

pub async fn remove(app: &tauri::AppHandle, id: &str) -> Result<(), String> {
    let workspace = app.state::<Workspace>();
    let _opening = workspace.opening.lock().await;
    remove_inner(app, &workspace, id)
}

fn remove_inner(app: &tauri::AppHandle, workspace: &Workspace, id: &str) -> Result<(), String> {
    let (entry, next) = {
        let mut state = workspace.state.lock().unwrap();
        let Some(index) = state.sessions.iter().position(|entry| entry.id == id) else {
            return Ok(());
        };
        let entry = state.sessions.remove(index);
        let next = if state.active.as_deref() == Some(id) || state.active.is_none() {
            state.active = None;
            state
                .sessions
                .get(index)
                .or_else(|| state.sessions.last())
                .map(|entry| entry.id.clone())
        } else {
            state.active.clone()
        };
        (entry, next)
    };
    entry.stop(app);
    if let Some(window) = app.get_webview_window(LABEL) {
        if let Some(next) = next {
            select(&window, &next)?;
        } else {
            workspace.state.lock().unwrap().url = None;
            window.destroy().map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

pub fn active(window: &WebviewWindow, id: &str) -> bool {
    window
        .state::<Workspace>()
        .state
        .lock()
        .unwrap()
        .active
        .as_deref()
        == Some(id)
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Snapshot,
    Select {
        id: String,
    },
    Fullscreen {
        enabled: Option<bool>,
    },
    Close {
        id: String,
    },
    RdpInput {
        id: String,
        kind: u16,
        a: u16,
        b: u16,
        delta: i16,
    },
    RdpCanvasStats {
        id: String,
        width: u32,
        height: u32,
        elapsed_ms: u32,
        received: u32,
        submitted: u32,
        max_gap_ms: u32,
    },
}

fn workspace_origin(window: &WebviewWindow) -> Result<reqwest::Url, String> {
    if window.label() != LABEL {
        return Err("Untrusted remote workspace".into());
    }
    // Tauri resolves this getter on the native event loop. macOS can deliver
    // resize/focus callbacks there during a full-screen transition, and those
    // callbacks also need workspace state.
    window.url().map_err(|error| error.to_string())
}

fn authorize(origin: &reqwest::Url, state: &WorkspaceState) -> Result<(), String> {
    if state.url.as_ref() != Some(origin) {
        return Err("Untrusted remote workspace".into());
    }
    Ok(())
}

#[tauri::command]
pub async fn remote_workspace(
    window: WebviewWindow,
    workspace: State<'_, Workspace>,
    request: Request,
) -> Result<Value, String> {
    let _opening = workspace.opening.lock().await;
    let origin = workspace_origin(&window)?;
    authorize(&origin, &workspace.state.lock().unwrap())?;
    match request {
        Request::Snapshot => {
            let fullscreen = window.is_fullscreen().unwrap_or(false);
            let state = workspace.state.lock().unwrap();
            authorize(&origin, &state)?;
            Ok(json!({
                "active": state.active,
                "fullscreen": fullscreen,
                "nativeRdp": state.native_rdp(),
                "rdpCompare": true,
                "frameWait": cfg!(windows),
                "sessions": state.sessions.iter().map(|entry| json!({
                    "id":entry.id, "name":entry.name, "protocol": if entry.rdp.is_some() { "rdp" } else { "ssh" }
                })).collect::<Vec<_>>(),
            }))
        }
        Request::Select { id } => {
            select(&window, &id)?;
            Ok(Value::Null)
        }
        Request::Fullscreen { enabled } => {
            let enabled = match enabled {
                Some(enabled) => enabled,
                None => !window.is_fullscreen().map_err(|error| error.to_string())?,
            };
            window
                .set_fullscreen(enabled)
                .map_err(|error| error.to_string())?;
            Ok(Value::Null)
        }
        Request::Close { id } => {
            remove_inner(window.app_handle(), &workspace, &id)?;
            Ok(Value::Null)
        }
        Request::RdpInput {
            id,
            kind,
            a,
            b,
            delta,
        } => {
            let state = workspace.state.lock().unwrap();
            if state.active.as_deref() == Some(&id) {
                let bridge = state
                    .sessions
                    .iter()
                    .find(|entry| entry.id == id)
                    .and_then(|entry| entry.rdp.as_ref())
                    .ok_or("Unknown remote desktop")?;
                bridge.input(kind, a, b, delta)?;
            }
            Ok(Value::Null)
        }
        Request::RdpCanvasStats {
            id,
            width,
            height,
            elapsed_ms,
            received,
            submitted,
            max_gap_ms,
        } => {
            let state = workspace.state.lock().unwrap();
            if state.active.as_deref() == Some(&id) && !state.native_rdp()
            {
                log::info!("rdp_render mode=canvas size={width}x{height} elapsed_ms={elapsed_ms} received={received} submitted={submitted} max_gap_ms={max_gap_ms}");
            }
            Ok(Value::Null)
        }
    }
}

#[tauri::command]
pub async fn remote_frame(
    window: WebviewWindow,
    workspace: State<'_, Workspace>,
    id: String,
    revision: u32,
    cursor_revision: Option<u32>,
    thumbnail: Option<bool>,
    wait_for_update: Option<bool>,
) -> Result<Response, String> {
    let origin = workspace_origin(&window)?;
    let (bridge, native) = {
        let state = workspace.state.lock().unwrap();
        authorize(&origin, &state)?;
        if state.active.as_deref() != Some(&id) {
            return Ok(Response::new(Vec::<u8>::new()));
        }
        (
            state.active_rdp().ok_or("Unknown remote desktop")?,
            state.native_rdp(),
        )
    };
    #[cfg(windows)]
    if wait_for_update == Some(true) {
        bridge.wait_for_update(revision, cursor_revision).await;
        let state = workspace.state.lock().unwrap();
        authorize(&origin, &state)?;
        if state.active.as_deref() != Some(&id)
            || !state.active_rdp().is_some_and(|active| Arc::ptr_eq(&active, &bridge))
        {
            return Ok(Response::new(Vec::<u8>::new()));
        }
    }
    if let Some(bytes) = cursor_revision.and_then(|revision| bridge.cursor(revision)) {
        return Ok(Response::new(bytes));
    }
    #[cfg(any(windows, all(target_os = "macos", feature = "rdp-native-macos")))]
    if native {
        let frame = bridge.latest_frame();
        return Ok(Response::new(crate::rdp_workspace::frame_metadata(
            &frame,
            revision,
            thumbnail.unwrap_or(false),
        )));
    }
    let _ = (native, thumbnail, wait_for_update);
    Ok(Response::new(bridge.frame(revision)))
}

#[cfg(test)]
mod tests {
    use super::LoginDisplay;

    #[test]
    fn login_display_accepts_secondary_screen_coordinates() {
        assert!(matches!(
            LoginDisplay::parse("-960 -540"),
            Some(LoginDisplay(-960, -540))
        ));
        for value in ["none", "-960", "-960 -540 2", "2147483648 0"] {
            assert!(LoginDisplay::parse(value).is_none());
        }
    }
}
