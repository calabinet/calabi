//! Ordinary-user file agent. Its private stdin/stdout pipes carry the UI API;
//! file metadata/body are never exposed through the machine daemon's HTTP API.
use std::{collections::{HashSet, VecDeque}, sync::{Arc, atomic::{AtomicBool, Ordering}}, time::{SystemTime, UNIX_EPOCH}};
use serde_json::{json, Value};
use tauri::{Manager, State, WebviewWindow};
use tokio::{io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader}, process::{Child, ChildStdin, ChildStdout, Command}, sync::Mutex};
use tauri_plugin_notification::NotificationExt;
use crate::daemon::{self, Supervisor};

struct Rpc { child: Child, input: ChildStdin, output: BufReader<ChildStdout>, notified: HashSet<String>, console: String }
pub struct FileAgent { rpc: Mutex<Option<Rpc>>, supervisor: Option<Arc<Supervisor>>, zh: AtomicBool, diagnostics: std::sync::Mutex<VecDeque<Value>>, receipts: std::sync::Mutex<crate::file_requests::Receipts> }

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
        let console = self.supervisor.as_ref().ok_or("Daemon unavailable")?.url();
        if let Some(rpc) = guard.as_mut() {
            if rpc.child.try_wait().map_err(|e| e.to_string())?.is_some() || rpc.console != console { *guard = None; }
        }
        if guard.is_none() {
            let binary = daemon::resolve_binary(None)?;
            let mut command = Command::new(binary);
            command.args(["mesh", "files", "--stdio", "--console", &console])
                .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::null()).kill_on_drop(true);
            #[cfg(windows)] command.creation_flags(0x08000000);
            let mut child = command.spawn().map_err(|e| format!("Cannot start file agent: {e}"))?;
            let input = child.stdin.take().ok_or("File agent input unavailable")?;
            let output = BufReader::new(child.stdout.take().ok_or("File agent output unavailable")?);
            *guard = Some(Rpc { child, input, output, notified: HashSet::new(), console });
        }
        let rpc = guard.as_mut().unwrap();
        let mut body = serde_json::to_vec(&action).map_err(|e| e.to_string())?;
        if body.len() > 8192 { return Err("File action too large".into()); }
        body.push(b'\n');
        if let Err(e) = rpc.input.write_all(&body).await { *guard = None; return Err(e.to_string()); }
        let mut line = String::new();
        let read = (&mut rpc.output).take(4 * 1024 * 1024).read_line(&mut line).await;
        match read {
            Ok(0) => { *guard = None; Err("File agent stopped; reopen transfers to retry".into()) }
            Ok(_) if !line.ends_with('\n') => { *guard = None; Err("File agent response too large".into()) }
            Err(e) => { *guard = None; Err(e.to_string()) }
            Ok(_) => serde_json::from_str(&line).map_err(|e| e.to_string()),
        }
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
            let zh = self.zh.load(Ordering::Relaxed);
            tauri::async_runtime::spawn_blocking(move || {
                let mut notification = notify_rust::Notification::new();
                let names = request.names.iter().take(3).map(|name| name.chars().take(100).collect::<String>()).collect::<Vec<_>>().join("、");
                notification.summary("Calabi").body(&if zh {
                    format!("来自 {} · {} 个文件\n{}", request.peer, request.ids.len(), names)
                } else {
                    format!("From {} · {} file(s)\n{}", request.peer, request.ids.len(), names)
                });
                // Opening a notification is never acceptance.
                notification.action("open", if zh { "查看" } else { "Review" })
                    .action("accept", if zh { "接收" } else { "Accept" })
                    .action("reject", if zh { "拒绝" } else { "Reject" });
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
                                    let _ = app.notification().builder().title("Calabi").body(if zh {
                                        "请求已变化或操作未完成，请在传送中心查看。"
                                    } else { "Request changed or decision failed. Review it in File transfers." }).show();
                                    open_requests(&app);
                                }
                            });
                        });
                    }
                    Err(error) => {
                        log::warn!("actionable file notification failed: {error}");
                        let _ = app.notification().builder().title("Calabi").body(if zh {
                            "有文件等待确认，请打开传送中心。"
                        } else { "Files await confirmation. Open File transfers to review." }).show();
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
        if let Some(window) = handle.get_webview_window("file-requests") {
            // A restarted daemon can choose a new console port.
            if window.url().ok().as_ref() != Some(&url) { let _ = window.navigate(url); }
            wake_receipt_window(&handle);
            return;
        }
        let origin = url.origin();
        let mut builder = tauri::WebviewWindowBuilder::new(&handle, "file-requests", tauri::WebviewUrl::External(url))
            .title("Calabi · File transfers").inner_size(420.0, 260.0)
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

#[tauri::command]
pub async fn files_action(window: WebviewWindow, supervisor: State<'_, Option<Arc<Supervisor>>>, agent: State<'_, Arc<FileAgent>>, action: Value) -> Result<Value, String> {
    if !supported() { return Err("File transfers are not enabled in this build".into()); }
    let sup = supervisor.inner().as_ref().ok_or("Daemon unavailable")?;
    let current = window.url().map_err(|e| e.to_string())?;
    let expected = reqwest::Url::parse(&sup.url()).map_err(|e| e.to_string())?;
    if window.label() != "main" || current.origin() != expected.origin() { return Err("Untrusted file UI origin".into()); }
    if let Some(locale) = action["locale"].as_str() { agent.zh.store(locale.starts_with("zh"), Ordering::Relaxed); }
    if action["action"] == "supported" { return Ok(json!({"supported":true})); }
    if action["action"] == "diagnostics" {
        let entries = agent.diagnostics.lock().unwrap_or_else(|e| e.into_inner());
        return Ok(json!({"entries":entries.iter().cloned().collect::<Vec<_>>()}));
    }
    if action["action"] == "revoke" && agent.rpc.lock().await.is_none() { return Ok(json!({"ok":true})); }
    let mut action = action;
    if let Some(object) = action.as_object_mut() { object.remove("locale"); }
    #[cfg(windows)]
    if action["action"] == "pick" || action["action"] == "save" {
        let hwnd = window.hwnd().map_err(|e| e.to_string())?;
        action["owner"] = json!(hwnd.0 as usize as u64);
    }
    agent.call(action).await
}

pub fn install(app: &tauri::App) {
    let supervisor = app.state::<Option<Arc<Supervisor>>>().inner().clone();
    let agent = Arc::new(FileAgent { rpc: Mutex::new(None), supervisor, zh: AtomicBool::new(false), diagnostics: std::sync::Mutex::new(VecDeque::new()), receipts: std::sync::Mutex::new(Default::default()) });
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
    fn file_call_error_includes_agent_reply_errors_and_transport_errors() {
        let reply = Ok(json!({"error":"source is referenced by a task; remove its record first"}));
        assert_eq!(file_call_error(&reply), Some("source is referenced by a task; remove its record first"));
        let transport = Err("File agent stopped".to_owned());
        assert_eq!(file_call_error(&transport), Some("File agent stopped"));
        assert_eq!(file_call_error(&Ok(json!({"available":true}))), None);
        assert_eq!(file_call_error(&Ok(json!({"error":""}))), None);
    }
}
