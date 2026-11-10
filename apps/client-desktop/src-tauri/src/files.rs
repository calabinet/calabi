//! Ordinary-user file agent. Private pipes carry the desktop UI API.
use std::{collections::{HashSet, VecDeque}, sync::{Arc, atomic::Ordering}, time::{SystemTime, UNIX_EPOCH}};
use serde_json::{json, Value};
use tauri::{Manager, State, WebviewWindow};
use tokio::{io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader}, process::{Child, Command}, sync::Mutex};
use tauri_plugin_notification::NotificationExt;
use crate::{daemon::{self, Supervisor}, tray_locale};

struct Rpc {
    child: Option<Child>,
    input: Box<dyn AsyncWrite + Send + Unpin>,
    output: BufReader<Box<dyn AsyncRead + Send + Unpin>>,
    notified: HashSet<String>,
    console: String,
}

impl Rpc {
    fn new(
        console: String,
        child: Option<Child>,
        input: impl AsyncWrite + Send + Unpin + 'static,
        output: impl AsyncRead + Send + Unpin + 'static,
    ) -> Self {
        Self {
            child,
            input: Box::new(input),
            output: BufReader::new(Box::new(output)),
            notified: HashSet::new(),
            console,
        }
    }
}
pub struct FileAgent {
    rpc: Mutex<Option<Rpc>>,
    supervisor: Option<Arc<Supervisor>>,
    native_locale_path: Option<std::path::PathBuf>,
    diagnostics: std::sync::Mutex<VecDeque<Value>>,
    receipts: std::sync::Mutex<crate::file_requests::Receipts>,
    #[cfg(any(windows, target_os = "macos"))]
    rdp_windows: Mutex<RdpWindows>,
}

#[cfg(any(windows, target_os = "macos"))]
type RdpWindows = std::collections::HashMap<(String, String), tokio::sync::mpsc::Sender<()>>;

#[cfg(windows)]
pub(crate) fn focus_rdp_window(pid: u32) {
    use windows_sys::Win32::{Foundation::{HWND, LPARAM}, UI::WindowsAndMessaging::*};

    unsafe extern "system" fn focus(hwnd: HWND, pid: LPARAM) -> i32 {
        let mut owner = 0;
        GetWindowThreadProcessId(hwnd, &mut owner);
        if owner != pid as u32 || IsWindowVisible(hwnd) == 0 { return 1; }
        let mut class = [0; 32];
        let len = GetClassNameW(hwnd, class.as_mut_ptr(), class.len() as i32);
        if len <= 0 || !matches!(String::from_utf16_lossy(&class[..len as usize]).as_str(), "CalabiRdpSession" | "#32770") {
            return 1;
        }
        if IsIconic(hwnd) != 0 { ShowWindowAsync(hwnd, SW_RESTORE); }
        SetForegroundWindow(hwnd);
        0
    }

    unsafe { EnumWindows(Some(focus), pid as LPARAM); }
}

#[cfg(target_os = "macos")]
pub(crate) fn focus_rdp_window(pid: u32) {
    extern "C" { fn kill(pid: i32, signal: i32) -> i32; }
    const SIGUSR1: i32 = 30; // Darwin; the helper explicitly advertises support.
    unsafe { kill(pid as i32, SIGUSR1); }
}

pub fn supported() -> bool { cfg!(any(windows, target_os = "macos")) }

fn file_call_error(result: &Result<Value, String>) -> Option<&str> {
    match result {
        Err(error) => Some(error.as_str()),
        Ok(value) => value["error"].as_str().filter(|error| !error.is_empty()),
    }
}

impl FileAgent {
    pub async fn call(&self, action: Value) -> Result<Value, String> {
        let operation: String = action["action"].as_str().unwrap_or("unknown").chars().take(40).collect();
        let mut guard = self.rpc.lock().await;
        let result = self.call_locked(&mut guard, action).await;
        drop(guard);
        if let Some(error) = file_call_error(&result) {
            self.record_error(&operation, error);
        }
        result
    }

    fn record_error(&self, operation: &str, error: &str) {
        // Keep these private to the desktop user; never forward file paths
        // or ordinary-user agent errors to the machine daemon's log API.
        let error: String = error.chars().take(1024).collect();
        let mut entries = self.diagnostics.lock().unwrap_or_else(|e| e.into_inner());
        if entries.back().map(|row| row["action"] != operation || row["error"] != error).unwrap_or(true) {
            log::warn!("file transfer action failed: action={operation:?} error={error:?}");
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
            entries.push_back(json!({"time_unix_ms":now,"action":operation,"error":error}));
            while entries.len() > 64 { entries.pop_front(); }
        }
    }

    async fn call_locked(&self, guard: &mut Option<Rpc>, action: Value) -> Result<Value, String> {
        let supervisor = self.supervisor.as_ref().ok_or("Daemon unavailable")?;
        let console = supervisor.url();
        if let Some(rpc) = guard.as_mut() {
            let exited = rpc.child.as_mut().map(Child::try_wait).transpose()
                .map_err(|e| e.to_string())?.flatten().is_some();
            if exited || rpc.console != console { *guard = None; }
        }
        if guard.is_none() {
            *guard = Some(self.connect(supervisor, console).await?);
        }
        let mut body = serde_json::to_vec(&action).map_err(|e| e.to_string())?;
        if body.len() > 8192 { return Err("File action too large".into()); }
        body.push(b'\n');

        // Drop the connection if the exchange is cancelled so its response
        // cannot be read as the response to the next request.
        let mut rpc = guard.take().unwrap();
        rpc.input.write_all(&body).await.map_err(|e| e.to_string())?;
        let mut line = String::new();
        let read = (&mut rpc.output).take(4 * 1024 * 1024).read_line(&mut line).await.map_err(|e| e.to_string())?;
        if read == 0 { return Err("File agent stopped; reopen transfers to retry".into()); }
        if !line.ends_with('\n') { return Err("File agent response too large".into()); }
        *guard = Some(rpc);
        serde_json::from_str(&line).map_err(|e| e.to_string())
    }

    async fn connect(&self, _supervisor: &Supervisor, console: String) -> Result<Rpc, String> {
        #[cfg(windows)]
        if _supervisor.is_attached() {
            let pipe = crate::windows_file_agent::connect().await?;
            let (output, input) = tokio::io::split(pipe);
            return Ok(Rpc::new(console, None, input, output));
        }

        let binary = daemon::resolve_binary(None)?;
        let mut command = Command::new(binary);
        if let Some(path) = &self.native_locale_path { command.env("CALABI_UI_LOCALE_FILE", path); }
        command.args(["mesh", "files", "--stdio", "--console", &console]);
        command
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null()).kill_on_drop(true);
        #[cfg(windows)] command.creation_flags(0x08000000);
        let mut child = command.spawn().map_err(|e| format!("Cannot start file agent: {e}"))?;
        let input = child.stdin.take().ok_or("File agent input unavailable")?;
        let output = child.stdout.take().ok_or("File agent output unavailable")?;
        Ok(Rpc::new(console, Some(child), input, output))
    }

    pub async fn poll_notifications(self: &Arc<Self>, app: &tauri::AppHandle) {
        // Start the ordinary-user agent after desktop startup so its saved
        // reception choice can recover without opening the transfer tab.
        let Ok(snapshot) = self.call(json!({"action":"snapshot"})).await else { return; };
        let requests = crate::file_requests::pending(&snapshot);
        let live: HashSet<_> = requests.iter().map(|r| r.stamp()).collect();
        let mut to_show = vec![];
        {
            let mut guard = self.rpc.lock().await;
            let Some(rpc) = guard.as_mut() else { return; };
            rpc.notified.retain(|stamp| live.contains(stamp));
            for request in &requests {
                if rpc.notified.insert(request.stamp()) { to_show.push((request.clone(), rpc.console.clone())); }
            }
            if cfg!(target_os = "macos") {
                self.receipts.lock().unwrap_or_else(|e| e.into_inner()).update(rpc.console.clone(), requests, !to_show.is_empty());
            }
        }
        if cfg!(target_os = "macos") {
            if live.is_empty() {
                if let Some(window) = app.get_webview_window("file-requests") { let _ = window.hide(); }
            } else if !to_show.is_empty() {
                show_receipt_window(app);
            }
            wake_receipt_window(app);
            // The receipt window is the macOS file-request reminder. Do not
            // also send a system notification for the same pending batch.
            return;
        }
        for (request, console) in to_show {
            let app = app.clone();
            let agent = self.clone();
            tauri::async_runtime::spawn_blocking(move || {
                let mut notification = notify_rust::Notification::new();
                let names = request.names.iter().take(3).map(|name| name.chars().take(100).collect::<String>()).collect::<Vec<_>>().join("\n");
                let count = request.ids.len();
                let summary = tray_locale::text(&app, if count == 1 { "fileRequestOne" } else { "fileRequestOther" })
                    .replace("{{count}}", &count.to_string()).replace("{{device}}", &request.peer);
                notification.summary("Calabi").body(&format!("{summary}\n{names}"));
                // Opening a notification is never acceptance.
                notification.action("open", &tray_locale::text(&app, "fileRequestReview"))
                    .action("accept", &tray_locale::text(&app, "fileRequestAccept"))
                    .action("reject", &tray_locale::text(&app, "fileRequestReject"));
                #[cfg(windows)] notification.app_id(&app.config().identifier);
                #[cfg(target_os = "macos")] { let _ = notify_rust::set_application(&app.config().identifier); }
                match notification.show() {
                    Ok(handle) => {
                        let _ = handle.wait_for_response(move |response: &notify_rust::NotificationResponse| {
                            let accept = match response {
                                notify_rust::NotificationResponse::Action(action) if action == "accept" => Some(true),
                                notify_rust::NotificationResponse::Action(action) if action == "reject" => Some(false),
                                notify_rust::NotificationResponse::Default => { open_requests(&app); return; },
                                notify_rust::NotificationResponse::Action(action) if action == "open" => { open_requests(&app); return; },
                                _ => return,
                            };
                            tauri::async_runtime::spawn(async move {
                                if let Err(error) = agent.decide_notification(&request, &console, accept.unwrap()).await {
                                    log::warn!("file notification decision failed: {error}");
                                    let _ = app.notification().builder().title("Calabi").body(tray_locale::text(&app, "fileRequestDecisionFailed")).show();
                                    open_requests(&app);
                                }
                            });
                        });
                    }
                    Err(error) => {
                        log::warn!("actionable file notification failed: {error}");
                        let _ = app.notification().builder().title("Calabi").body(tray_locale::text(&app, "fileRequestPending")).show();
                    }
                }
            });
        }
    }

    async fn decide_notification(&self, request: &crate::file_requests::Request, console: &str, accept: bool) -> Result<(), String> {
        let mut guard = self.rpc.lock().await;
        if guard.as_ref().map(|rpc| rpc.console.as_str()) != Some(console)
            || self.supervisor.as_ref().map(|s| s.url()).as_deref() != Some(console) { return Err("File agent changed".into()); }
        let snapshot = self.call_locked(&mut guard, json!({"action":"snapshot"})).await?;
        if !crate::file_requests::pending(&snapshot).contains(request) { return Err("File request changed".into()); }
        let result = self.call_locked(&mut guard, json!({"action":"decide","ids":request.ids,"accept":accept})).await?;
        if let Some(error) = result["error"].as_str() { return Err(error.to_owned()); }
        Ok(())
    }

}

#[cfg(windows)]
pub fn start_installed_background_agent() -> std::io::Result<()> {
    let binary = std::env::current_exe()?.with_file_name("calabi.exe");
    crate::windows_file_agent::start(&binary)
}

// This window has a separate, narrowly scoped IPC capability. It cannot pick
// files, enable reception, or submit arbitrary agent actions.
#[tauri::command]
pub async fn file_receipt_action(window: WebviewWindow, supervisor: State<'_, Option<Arc<Supervisor>>>, agent: State<'_, Arc<FileAgent>>, action: String, stamp: Option<String>, stamps: Option<Vec<String>>, accept: Option<bool>, height: Option<f64>, viewport_height: Option<f64>) -> Result<Value, String> {
    if !cfg!(target_os = "macos") { return Err("Receipt window unavailable".into()); }
    let console = supervisor.inner().as_ref().ok_or("Daemon unavailable")?.url();
    let expected = reqwest::Url::parse(&console).map_err(|e| e.to_string())?;
    let current = window.url().map_err(|e| e.to_string())?;
    if window.label() != "file-requests" || current.origin() != expected.origin()
        || current.fragment() != Some("/file-requests") { return Err("Untrusted receipt UI".into()); }
    if action == "dismiss" { window.hide().map_err(|e| e.to_string())?; return Ok(json!({"ok":true})); }
    if action == "resize" || action == "ready" {
        let height = height.filter(|h| h.is_finite() && *h > 0.0).ok_or("Invalid receipt height")?;
        let maximum = window.current_monitor().ok().flatten().map(|m|
            (m.work_area().size.height as f64 / m.scale_factor() - 80.0).clamp(120.0, 560.0)
        ).unwrap_or(560.0);
        // Account for a WebView viewport smaller than the native content area.
        // The renderer reports CSS pixels; the window size is logical points.
        let viewport = viewport_height.filter(|h| h.is_finite() && *h > 0.0);
        let inset = match (viewport, window.inner_size(), window.scale_factor()) {
            (Some(viewport), Ok(size), Ok(scale)) => (size.height as f64 / scale - viewport).clamp(0.0, 80.0),
            _ => 0.0,
        };
        let height = (height + inset).clamp(120.0, maximum);
        window.set_size(tauri::LogicalSize::new(420.0, height)).map_err(|e| e.to_string())?;
        if action == "ready" {
            let mut receipts = agent.receipts.lock().unwrap_or_else(|e| e.into_inner());
            if receipts.console == console && receipts.ready(&stamps.unwrap_or_default()) {
                window.show().map_err(|e| e.to_string())?;
            }
        }
        return Ok(json!({"height":height}));
    }
    if action != "snapshot" && action != "decide" { return Err("Unsupported receipt action".into()); }
    // This is display metadata already collected by the notification poll.
    // Do not block rendering on a new RPC or start an agent from this window.
    let mut receipts = agent.receipts.lock().unwrap_or_else(|e| e.into_inner());
    if receipts.console != console { return Err("File agent changed".into()); }
    if action == "decide" {
        let accept = accept.ok_or("Missing decision")?;
        let request = receipts.claim(stamp.as_deref().ok_or("Missing request")?).ok_or("File request changed")?;
        let empty = receipts.visible().is_empty();
        drop(receipts);
        if empty {
            if let Err(error) = window.hide() { log::warn!("cannot hide file receipt window: {error}"); }
        }
        let agent = agent.inner().clone();
        let app = window.app_handle().clone();
        tauri::async_runtime::spawn(async move {
            // Only intent admission is immediate. Authorization and immutable
            // batch validation still happen against the live file agent.
            if let Err(error) = agent.decide_notification(&request, &console, accept).await {
                agent.record_error("receipt_decide", &error);
                let has_requests = {
                    let mut receipts = agent.receipts.lock().unwrap_or_else(|e| e.into_inner());
                    if receipts.console != console { return; }
                    receipts.failed(&request.stamp(), error);
                    !receipts.visible().is_empty()
                };
                if has_requests { show_receipt_window(&app); }
                else { open_requests(&app); }
            }
            wake_receipt_window(&app);
        });
        return Ok(json!({"queued":true}));
    }
    Ok(json!({"requests":receipts.visible().iter().map(|r| json!({"stamp":r.stamp(),"peer":r.peer,"names":r.names,"bytes":r.bytes})).collect::<Vec<_>>(),"error":receipts.error}))
}

fn wake_receipt_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("file-requests") {
        // Static wake-up only; private names/IDs never become script source.
        let _ = window.eval("window.dispatchEvent(new Event('calabi:file-receipts-changed'))");
    }
}

fn show_receipt_window(app: &tauri::AppHandle) {
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        let Some(supervisor) = handle.state::<Option<Arc<Supervisor>>>().inner().clone() else { return; };
        let Ok(mut url) = reqwest::Url::parse(&supervisor.url()) else { return; };
        url.set_fragment(Some("/file-requests"));
        let title = format!("Calabi · {}", tray_locale::text(&handle, "fileTransfersTitle"));
        if let Some(window) = handle.get_webview_window("file-requests") {
            let _ = window.set_title(&title);
            // A restarted daemon can choose a new console port.
            if window.url().ok().as_ref() != Some(&url) { let _ = window.navigate(url); }
            wake_receipt_window(&handle);
            return;
        }
        let origin = url.origin();
        let mut builder = tauri::WebviewWindowBuilder::new(&handle, "file-requests", tauri::WebviewUrl::External(url))
            .title(title).inner_size(420.0, 260.0)
            .resizable(false).focused(false).visible(false).skip_taskbar(true).always_on_top(true).visible_on_all_workspaces(true)
            .user_agent(&crate::desktop_user_agent())
            .on_navigation(move |next| next.origin() == origin && next.fragment() == Some("/file-requests"));
        if let Ok(Some(monitor)) = handle.primary_monitor() {
            let area = monitor.work_area();
            let scale = monitor.scale_factor();
            builder = builder.position((area.position.x as f64 + area.size.width as f64 - 440.0 * scale).max(area.position.x as f64) / scale,
                area.position.y as f64 / scale + 24.0);
        }
        match builder.build() {
            // The renderer sizes the window and signals readiness after its
            // first populated DOM commit. Never expose an empty WebView.
            Ok(_) => {}
            Err(error) => log::warn!("cannot open file receipt window: {error}"),
        }
    });
}

fn assist_peer_label(peer: &str) -> String {
    peer.bytes().map(|b| format!("{b:02x}")).collect()
}

fn url_peer(query: &str) -> Option<String> {
    let mut url = reqwest::Url::parse("http://localhost").ok()?;
    url.set_query(Some(query));
    url.query_pairs().find(|(key, _)| key == "peer").map(|(_, value)| value.into_owned())
}

#[cfg(any(windows, target_os = "macos"))]
pub(crate) fn rdp_helper() -> Result<std::path::PathBuf,String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    #[cfg(windows)]
    return Ok(exe.with_file_name("rdp").join("calabi-rdp.exe"));
    #[cfg(target_os = "macos")]
    return Ok(exe.with_file_name("calabi-rdp"));
}

#[cfg(any(windows, target_os = "macos", test))]
fn verified_rdp_pin<'a>(state: &'a Value, scope: &str, host: &str, local: &str, observed: &str) -> Option<&'a str> {
    if scope.is_empty() || state["scope"] != scope || state["host"] != host || state["local"] != local {
        return None;
    }
    let pin = state["pin"].as_str()?;
    (pin.len() == 64 && pin.bytes().all(|b| b.is_ascii_hexdigit()) && pin.eq_ignore_ascii_case(observed)).then_some(pin)
}

#[tauri::command]
pub async fn files_action(window: WebviewWindow, supervisor: State<'_, Option<Arc<Supervisor>>>, agent: State<'_, Arc<FileAgent>>, action: Value) -> Result<Value, String> {
    if !supported() { return Err("File transfers are not enabled in this build".into()); }
    let sup = supervisor.inner().as_ref().ok_or("Daemon unavailable")?;
    let current = window.url().map_err(|e| e.to_string())?;
    let expected = reqwest::Url::parse(&sup.url()).map_err(|e| e.to_string())?;
    if current.origin() != expected.origin() { return Err("Untrusted file UI origin".into()); }
    if window.label().starts_with("assist-session-") {
        let query = current.fragment().and_then(|f| f.strip_prefix("/assist-session?")).ok_or("Invalid assistance window")?;
        let peer = url_peer(query).ok_or("Missing assistance target")?;
        if !window.label().ends_with(&format!("-{}", assist_peer_label(&peer))) {
            return Err("Assistance target changed".into());
        }
        match action["action"].as_str() {
            Some("assist_window") => {
                if let Some(enabled) = action["enabled"].as_bool() {
                    window.set_fullscreen(enabled).map_err(|e| e.to_string())?;
                    return Ok(json!({"fullscreen":enabled}));
                }
                return Ok(json!({"fullscreen":window.is_fullscreen().map_err(|e| e.to_string())?}));
            }
            Some("assist_close") => {
                window.close().map_err(|e| e.to_string())?;
                return Ok(json!({}));
            }
            Some("assist") if action["peer"].as_str() == Some(peer.as_str()) => {
                let request = action["assist"]["op"] == "request";
                let reply = agent.call(action).await?;
                if request {
                    if let Some(id) = reply["id"].as_str() {
                        // Native close can destroy the WebView before pagehide IPC arrives.
                        let end = json!({"action":"assist","peer":peer,"assist":{"op":"end","id":id}});
                        let cleanup = agent.inner().clone();
                        let end_on_destroy = end.clone();
                        window.on_window_event(move |event| {
                            if matches!(event, tauri::WindowEvent::Destroyed) {
                                let cleanup = cleanup.clone();
                                let end = end_on_destroy.clone();
                                tauri::async_runtime::spawn(async move { let _ = cleanup.call(end).await; });
                            }
                        });
                        if window.app_handle().get_webview_window(window.label()).is_none() {
                            let _ = agent.call(end).await;
                        }
                    }
                }
                return Ok(reply);
            }
            _ => return Err("Unsupported assistance window action".into()),
        }
    }
    if window.label() != "main" { return Err("Untrusted file UI origin".into()); }
    #[cfg(any(windows, target_os = "macos"))]
    if action["action"] == "ssh_open" {
        return crate::ssh::open(&window, agent.inner(), expected, action).await;
    }
    #[cfg(any(windows, target_os = "macos"))]
    if action["action"] == "ssh_history" {
        return crate::ssh::history(&agent).await;
    }
    if matches!(action["action"].as_str(), Some("ssh_target" | "ssh_record")) {
        return Err("SSH targets and records require a native session".into());
    }
    if action["action"] == "rdp_record" { return Err("Remote login records require a native session".into()); }
    #[cfg(any(windows, target_os = "macos"))]
    if action["action"] == "rdp_open" {
        let key = action["peer"].as_str().ok_or("Missing RDP device")?;
        let result = agent.call(json!({"action":"rdp_target","peer":key})).await?;
        if let Some(error) = result["error"].as_str() { return Err(error.into()); }
        let host = result["host"].as_str().ok_or("RDP device unavailable")?;
        let local = result["local"].as_str().ok_or("Local mesh address unavailable")?;
        let profile = result["profile"].as_str().filter(|profile| !profile.is_empty()).ok_or("Missing RDP profile")?.to_owned();
        let credential_key = result["credential_key"].as_str().unwrap_or("");
        let window_key = (profile.clone(), key.to_owned());
        let mut windows = agent.rdp_windows.lock().await;
        if let Some(existing) = windows.get(&window_key) {
            use tokio::sync::mpsc::error::TrySendError;
            if matches!(existing.try_send(()), Ok(()) | Err(TrySendError::Full(()))) {
                return Ok(json!({}));
            }
        }
        let name: String = action["name"].as_str().unwrap_or("").chars().take(120).collect();
        let history = agent.call(json!({"action":"rdp_history","rdp_profile":profile})).await.unwrap_or(Value::Null);
        let previous = history.as_array().into_iter().flatten().find(|item| item["peer"] == key);
        let previous_account = previous.and_then(|item| item["account"].as_str()).unwrap_or("");
        let previous_port = previous.and_then(|item| item["port"].as_u64())
            .and_then(|port| u16::try_from(port).ok()).filter(|port| *port != 0).unwrap_or(3389);
        for ip in [host, local] {
            let octets = ip.parse::<std::net::Ipv4Addr>().map_err(|_| "Invalid mesh IPv4 address")?.octets();
            if octets[0] != 100 || !(64..128).contains(&octets[1]) { return Err("Expected a Calabi mesh address".into()); }
        }
        let helper = rdp_helper()?;
        let mut command = Command::new(&helper);
        let bridge = crate::rdp_workspace::Bridge::prepare(&mut command).await?;
        let session_id = format!("rdp-session-{}", uuid::Uuid::new_v4().simple());
        if let Some(path) = &agent.native_locale_path { command.env("CALABI_UI_LOCALE_FILE", path); }
        command.env("CALABI_UI_LOCALE", tray_locale::code(window.app_handle()));
        #[cfg(windows)]
        command.env("OPENSSL_MODULES", helper.with_file_name("ossl-modules"))
            .env("CALABI_RDP_PARENT_PID", std::process::id().to_string());
        #[cfg(any(windows, target_os = "macos"))]
        command.env_remove("CALABI_RDP_FILE_BRIDGE").env_remove("CALABI_RDP_FILE_STREAM").env("CALABI_RDP_FILE_MESH","1");
        #[cfg(windows)]
        if let Some(base)=std::env::var_os("LOCALAPPDATA") {
            let logs=std::path::PathBuf::from(base).join("Calabi").join("Logs");
            if std::fs::create_dir_all(&logs).is_ok() {
                command.env("CALABI_RDP_CLIP_LOG",logs.join(format!("rdp-clipboard-{host}.log")));
                command.env("CALABI_RDP_GFX_LOG",logs.join(format!("rdp-display-{host}.log")));
            }
        }
        let mut child = command.env("CALABI_P0_PEER",host).env("CALABI_RDP_LOCAL",local)
            .env("CALABI_RDP_NAME", &name)
            .env("CALABI_RDP_CREDENTIAL_KEY",credential_key)
            .env("CALABI_RDP_ACCOUNT_HINT",previous_account)
            .env("CALABI_RDP_PORT",previous_port.to_string())
            .env_remove("CALABI_P0_SHA256")
            .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn().map_err(|e|format!("Cannot open Calabi RDP window: {e}"))?;
        let mut input = child.stdin.take().ok_or("Missing RDP input pipe")?;
        let output = child.stdout.take().ok_or("Missing RDP output pipe")?;
        let mut lines = BufReader::new(output).lines();
        #[cfg(windows)]
        {
            let ready = tokio::time::timeout(std::time::Duration::from_secs(10), lines.next_line()).await;
            if !matches!(ready, Ok(Ok(Some(ref line))) if line == "rdp-login-ready") {
                return Err("Cannot prepare Calabi RDP login window".into());
            }
            if let Some(pid) = child.id() {
                unsafe { windows_sys::Win32::UI::WindowsAndMessaging::AllowSetForegroundWindow(pid); }
            }
            if input.write_all(b"rdp-login-show\n").await.is_err() {
                return Err("Cannot show Calabi RDP login window".into());
            }
        }
        let (focus, mut focus_requests) = tokio::sync::mpsc::channel(1);
        let focus_key = focus.downgrade();
        windows.insert(window_key.clone(), focus);
        drop(windows);
        let agent = agent.inner().clone();
        let (key,host,local) = (key.to_owned(),host.to_owned(),local.to_owned());
        let scope = result["scope"].as_str().unwrap_or("").to_owned();
        let workspace_url = crate::remote_workspace::url(expected);
        tauri::async_runtime::spawn(async move {
            #[cfg(windows)]
            let mut clipboard_job:Option<String>=None;
            let mut copy_session:Option<String>=None;
            let mut copy_requested = false;
            let mut copy_retry_at = tokio::time::Instant::now();
            let mut login_recorded=false;
            let mut pin_verified=false;
            let mut workspace_connected=false;
            let mut login_display = None;
            #[cfg(target_os = "macos")]
            let (mut focus_ready, mut focus_pending) = (false, false);
            let mut copy_tick=tokio::time::interval(std::time::Duration::from_secs(2));
            let mut selection = bridge.watch_selection();
            loop {
                let line=tokio::select! {
                    result=lines.next_line()=>match result {Ok(Some(line))=>line,_=>break},
                    _=selection.changed()=>{
                        copy_retry_at = tokio::time::Instant::now();
                        copy_tick.reset_immediately();
                        continue;
                    }
                    request=focus_requests.recv()=>{
                        if request.is_none() || !matches!(child.try_wait(), Ok(None)) { break; }
                        if workspace_connected {
                            if let Some(remote) = window.app_handle().get_webview_window(crate::remote_workspace::LABEL) {
                                if crate::remote_workspace::select(&remote, &session_id).is_ok() {
                                    let _ = remote.show();
                                    let _ = remote.unminimize();
                                    let _ = remote.set_focus();
                                }
                            }
                            continue;
                        }
                        #[cfg(windows)]
                        if let Some(pid) = child.id() { focus_rdp_window(pid); }
                        #[cfg(target_os = "macos")]
                        if focus_ready {
                            if let Some(pid) = child.id() { focus_rdp_window(pid); }
                        } else {
                            focus_pending = true;
                        }
                        continue;
                    }
                    _=copy_tick.tick()=>{
                        if !bridge.accepts_clipboard() {
                            if let Some(id)=copy_session.take() {
                                let _=agent.call(json!({"action":"mesh_copy_end","id":id})).await;
                            }
                        } else if let Some(id)=copy_session.as_ref() {
                            let renewed=agent.call(json!({"action":"mesh_copy_renew","id":id})).await;
                            if !matches!(renewed,Ok(ref value) if value.get("error").is_none()){
                                agent.record_error("rdp_copy","文件复制连接已中断，正在恢复");
                                copy_session=None;
                            }
                        } else if copy_requested && pin_verified && tokio::time::Instant::now() >= copy_retry_at {
                            // The old lease may still be held on the peer. Retry at a bounded rate.
                            copy_retry_at = tokio::time::Instant::now() + std::time::Duration::from_secs(4);
                            if let Ok(target) = agent.call(json!({"action":"rdp_target","peer":key})).await {
                                if target["error"].is_null() {
                                    copy_requested = target["scope"] == scope && target["profile"] == profile
                                        && target["host"] == host && target["local"] == local;
                                    if copy_requested && bridge.accepts_clipboard() {
                                        if let Ok(result) = agent.call(json!({"action":"mesh_copy_start","peer":key,"rdp_profile":profile})).await {
                                            copy_session = result["session"].as_str().filter(|id| !id.is_empty()).map(str::to_owned);
                                            if copy_session.is_some() { log::info!("RDP file copy lease established"); }
                                        }
                                    }
                                }
                            }
                        }
                        continue;
                    }
                };
                if let Some(value) = line.strip_prefix(crate::remote_workspace::LOGIN_DISPLAY_PREFIX) {
                    login_display = crate::remote_workspace::LoginDisplay::parse(value);
                    continue;
                }
                if line == "rdp-workspace-connected" && pin_verified && !workspace_connected {
                    if focus_requests.is_closed() { break; }
                    match crate::remote_workspace::add(window.app_handle(), workspace_url.clone(), &session_id, &name, Some(bridge.clone()), login_display.take()).await {
                        Ok(remote) => {
                            workspace_connected = true;
                            let _ = remote.show();
                            let _ = remote.unminimize();
                            let _ = remote.set_focus();
                        }
                        Err(error) => {
                            agent.record_error("rdp_workspace", &error);
                            break;
                        }
                    }
                    continue;
                }
                #[cfg(target_os = "macos")]
                if line == "rdp-focus-ready" {
                    focus_ready = true;
                    if std::mem::take(&mut focus_pending) && matches!(child.try_wait(), Ok(None)) {
                        if let Some(pid) = child.id() { focus_rdp_window(pid); }
                    }
                    continue;
                }
                let login = line.strip_prefix("rdp-login-ok ").map(|encoded| (0,encoded)).or_else(|| {
                    let (port, encoded) = line.strip_prefix("rdp-login-port ")?.split_once(' ')?;
                    let port = port.parse::<u16>().ok().filter(|port| *port != 0)?;
                    Some((port,encoded))
                });
                if let Some((port,encoded))=login {
                    if !login_recorded && pin_verified && !profile.is_empty() && encoded.len()<=4094
                        && encoded.len()%2==0 && encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
                        let bytes: Vec<_> = (0..encoded.len()).step_by(2)
                            .map(|i| u8::from_str_radix(&encoded[i..i+2],16).unwrap_or_default()).collect();
                        if let Ok(account)=String::from_utf8(bytes) {
                            login_recorded=true;
                            let _=agent.call(json!({"action":"rdp_record","peer":key,"rdp_profile":profile,
                                "rdp_account":account,"rdp_name":name,"rdp_port":port})).await;
                        }
                    }
                    continue;
                }
                if let Some(request)=line.strip_prefix("rdp-mesh ") {
                    let answer=if let Some(id) = copy_session.as_ref().filter(|_| request.len() <= 20000 && bridge.accepts_clipboard()) {
                        let mut action = json!({"action":"mesh_copy_rpc","copy_request":request});
                        if request == "mesh_state" { action["id"] = json!(id); }
                        match agent.call(action).await {
                            Ok(value)=>value["reply"].as_str().unwrap_or("error").to_owned(),
                            Err(_)=>"error".to_owned(),
                        }
                    } else { "none".to_owned() };
                    if input.write_all(format!("{answer}\n").as_bytes()).await.is_err(){break;}
                    continue;
                }
                if line=="rdp-copy-ready" {
                    copy_requested = true;
                    copy_retry_at = tokio::time::Instant::now();
                    copy_tick.reset_immediately();
                    continue;
                }
                if line=="rdp-copy-end" {
                    copy_requested = false;
                    if let Some(id)=copy_session.take(){let _=agent.call(json!({"action":"mesh_copy_end","id":id})).await;}
                    continue;
                }
                #[cfg(windows)]
                if let Some(encoded)=line.strip_prefix("rdp-copy ") {
                    if let Some(job)=clipboard_job.take(){let _=agent.call(json!({"action":"cancel","id":job})).await;}
                    let prepare=async {
                        if !bridge.accepts_clipboard() || encoded.is_empty() || encoded.len()>8192 || encoded.len()%2!=0 {return None;}
                        let raw:Vec<u8>=encoded.as_bytes().chunks_exact(2).map(|p| {
                            let s=std::str::from_utf8(p).ok()?;u8::from_str_radix(s,16).ok()
                        }).collect::<Option<Vec<_>>>()?;
                        if raw.last()!=Some(&0){return None;}
                        let paths:Vec<String>=raw[..raw.len()-1].split(|b|*b==0).map(|p|String::from_utf8(p.to_vec()).ok()).collect::<Option<Vec<_>>>()?;
                        if paths.is_empty() || paths.len()>32 || paths.iter().any(|s|s.is_empty()){return None;}
                        let target=agent.call(json!({"action":"rdp_target","peer":key})).await.ok()?;
                        if target["scope"]!=scope || target["host"]!=host || target["local"]!=local{return None;}
                        let reply=agent.call(json!({"action":"rdp_copy_send","peer":key,"paths":paths})).await.ok()?;
                        let job=reply["job"].as_str()?.to_owned();
                        clipboard_job=Some(job.clone());
                        for _ in 0..100 {
                            let reply=agent.call(json!({"action":"rdp_copy_status","peer":key,"id":job})).await.ok()?;
                            if let Some(token)=reply["token"].as_str(){return Some(token.to_owned());}
                            if reply.get("error").is_some(){break;}
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        }
                        let _=agent.call(json!({"action":"cancel","id":job})).await;
                        None
                    };
                    let answer=prepare.await.map(|t|format!("copy {t}\n")).unwrap_or_else(||"error\n".into());
                    if input.write_all(answer.as_bytes()).await.is_err(){break;}
                    continue;
                }
                let Some(observed) = line.strip_prefix("rdp-pin ") else { continue; };
                if observed.len()!=64 || !observed.bytes().all(|b| b.is_ascii_hexdigit()){break;}
                let lookup = async {
                    for attempt in 0..4 {
                        let state=agent.call(json!({"action":"rdp_target","peer":key})).await.ok()?;
                        if scope.is_empty() || state["scope"]!=scope || state["host"]!=host || state["local"]!=local
                            || state["profile"].as_str().unwrap_or("")!=profile {return None;}
                        if let Some(pin) = verified_rdp_pin(&state,&scope,&host,&local,observed){return Some(pin.to_owned());}
                        if attempt<3 {tokio::time::sleep(std::time::Duration::from_millis(750)).await;}
                    }
                    None
                };
                // Finish each shared stdio RPC: cancelling after the request write would
                // leave its unread response for the next desktop action.
                let pin=lookup.await.unwrap_or_default();
                pin_verified=!pin.is_empty();
                if pin.is_empty() { agent.record_error("rdp_verify","No matching authenticated RDP listener certificate for this device"); }
                if input.write_all(format!("{pin}\n").as_bytes()).await.is_err(){break;}
            }
            #[cfg(windows)]
            if let Some(job)=clipboard_job.take(){let _=agent.call(json!({"action":"cancel","id":job})).await;}
            drop(input);
            bridge.stop();
            if let Some(id)=copy_session.take(){let _=agent.call(json!({"action":"mesh_copy_end","id":id})).await;}
            if tokio::time::timeout(std::time::Duration::from_secs(4), child.wait()).await.is_err() {
                let _ = child.kill().await;
            }
            {
                let mut windows = agent.rdp_windows.lock().await;
                if windows.get(&window_key).zip(focus_key.upgrade())
                    .is_some_and(|(current, original)| current.same_channel(&original)) {
                    windows.remove(&window_key);
                }
            }
            if workspace_connected { let _ = crate::remote_workspace::remove(window.app_handle(), &session_id).await; }
        });
        return Ok(json!({}));
    }
    if action["action"] == "assist_open" {
        static OPEN: Mutex<()> = Mutex::const_new(());
        let _opening = OPEN.lock().await;
        let peer = action["peer"].as_str().filter(|p| !p.is_empty()).ok_or("Missing assistance target")?;
        let name = action["name"].as_str().unwrap_or(peer);
        let mut target = expected;
        let mut query = reqwest::Url::parse("http://localhost").unwrap();
        query.query_pairs_mut().append_pair("peer",peer).append_pair("name",name);
        target.set_fragment(Some(&format!("/assist-session?{}",query.query().unwrap())));
        if let Some(existing) = window.webview_windows().into_values().find(|w| w.label().starts_with("assist-session-")) {
            existing.unminimize().map_err(|e| e.to_string())?;
            existing.set_focus().map_err(|e| e.to_string())?;
            if existing.url().ok().as_ref() != Some(&target) { return Err("Close the current assistance session first".into()); }
            return Ok(json!({}));
        }
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let label = format!("assist-session-{}-{}",NEXT.fetch_add(1, Ordering::Relaxed), assist_peer_label(peer));
        let allowed = target.clone();
        tauri::WebviewWindowBuilder::new(window.app_handle(), label, tauri::WebviewUrl::External(target))
            .title(format!("Calabi · {name}")).inner_size(1100.0,720.0).min_inner_size(480.0,320.0)
            .user_agent(&crate::desktop_user_agent()).on_navigation(move |next| next == &allowed)
            .build().map_err(|e| e.to_string())?;
        return Ok(json!({}));
    }
    if action["action"] == "assist" { return Err("Open the assistance window first".into()); }
    if action["action"] == "supported" { return Ok(json!({"supported":true})); }
    if action["action"] == "diagnostics" {
        let mut entries: Vec<_> = agent.diagnostics.lock().unwrap_or_else(|e| e.into_inner()).iter().cloned().collect();
        if let Ok(Value::Array(handshakes)) = agent.call(json!({"action":"handshake_diagnostics"})).await {
            entries.extend(handshakes);
        }
        return Ok(json!({"entries":entries}));
    }
    if action["action"] == "revoke" {
        #[cfg(any(windows, target_os = "macos"))]
        {
            agent.rdp_windows.lock().await.clear();
            crate::ssh::close_all(window.app_handle()).await;
        }
        if agent.rpc.lock().await.is_none() { return Ok(json!({"ok":true})); }
    }
    let mut action = action;
    if let Some(object) = action.as_object_mut() { object.remove("locale"); }
    #[cfg(windows)]
    if action["action"] == "pick" || action["action"] == "save" {
        let hwnd = window.hwnd().map_err(|e| e.to_string())?;
        action["owner"] = json!(hwnd.0 as usize as u64);
    }
    #[cfg(any(windows, target_os = "macos"))]
    if action["action"] == "snapshot" {
        let mut result = agent.call(action).await?;
        let rdp_supported=rdp_helper().is_ok_and(|p| p.is_file());
        if !rdp_supported {
            if let Some(fields) = result.as_object_mut() { fields.remove("rdp_targets"); }
        }
        if let Some(fields) = result.as_object_mut() { fields.insert("rdp_supported".into(),json!(rdp_supported)); }
        if let Some(fields) = result.as_object_mut() { fields.insert("ssh_supported".into(), json!(crate::ssh::supported())); }
        return Ok(result);
    }
    agent.call(action).await
}

pub fn install(app: &tauri::App) {
    let supervisor = app.state::<Option<Arc<Supervisor>>>().inner().clone();
    let agent = Arc::new(FileAgent {
        rpc: Mutex::new(None), supervisor, native_locale_path: tray_locale::native_locale_path(app.handle()),
        diagnostics: std::sync::Mutex::new(VecDeque::new()),
        receipts: std::sync::Mutex::new(Default::default()),
        #[cfg(any(windows, target_os = "macos"))]
        rdp_windows: Mutex::new(RdpWindows::new()),
    });
    app.manage(agent.clone());
    if supported() {
        let handle = app.handle().clone();
        tauri::async_runtime::spawn(async move {
            loop { tokio::time::sleep(std::time::Duration::from_secs(2)).await; agent.poll_notifications(&handle).await; }
        });
    }
}

fn open_requests(app: &tauri::AppHandle) {
    let Some(window) = app.get_webview_window("main") else { return; };
    if let (Ok(mut url), Some(supervisor)) = (window.url(), app.state::<Option<Arc<Supervisor>>>().inner()) {
        if let Ok(expected) = reqwest::Url::parse(&supervisor.url()) {
            if url.origin() == expected.origin() {
                url.set_fragment(Some("/mesh/files?review=1"));
                let _ = window.navigate(url);
            }
        }
    }
    let _ = window.show(); let _ = window.unminimize(); let _ = window.set_focus();
}

#[cfg(test)]
mod diagnostic_tests {
    use super::file_call_error;
    use serde_json::json;

    #[test]
    fn rdp_pin_requires_current_scope_addresses_and_exact_sha256() {
        let pin = "a3".repeat(32);
        let mut state = json!({"scope":"s","host":"h","local":"l","pin":pin});
        assert!(super::verified_rdp_pin(&state,"s","h","l",&pin.to_uppercase()).is_some());
        for (scope,host,local,seen) in [("other","h","l",pin.as_str()),("s","other","l",&pin),
            ("s","h","other",&pin),("s","h","l","bad")] {
            assert!(super::verified_rdp_pin(&state,scope,host,local,seen).is_none());
        }
        state["pin"] = json!("");
        assert!(super::verified_rdp_pin(&state,"s","h","l","").is_none());
    }

    #[test]
    fn file_call_error_includes_agent_reply_errors_and_transport_errors() {
        let reply = Ok(json!({"error":"source is referenced by a task; remove its record first"}));
        assert_eq!(file_call_error(&reply), Some("source is referenced by a task; remove its record first"));
        let transport = Err("File agent stopped".to_owned());
        assert_eq!(file_call_error(&transport), Some("File agent stopped"));
        assert_eq!(file_call_error(&Ok(json!({"available":true}))), None);
        assert_eq!(file_call_error(&Ok(json!({"error":""}))), None);
    }
}
