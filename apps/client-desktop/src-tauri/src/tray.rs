use crate::daemon::{DaemonStatus, Supervisor};
use crate::tray_locale::{text as tr, Language};
use serde_json::Value;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tauri::{
    tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent},
    AppHandle, Manager,
};
use tauri_plugin_clipboard_manager::ClipboardExt;
use tauri_plugin_dialog::{DialogExt, MessageDialogButtons};
use tauri_plugin_notification::NotificationExt;

const PANEL_HEIGHT: f64 = 375.0;

struct Items {
    mesh_change: tokio::sync::Mutex<()>,
    snapshot: Mutex<Value>,
    address: Mutex<String>,
}

fn localized_snapshot(app: &AppHandle) -> Value {
    let mut value = app.state::<Items>().snapshot.lock().unwrap().clone();
    for key in ["status", "fallback_name", "fallback_org"] {
        if let Some(raw) = value[key].as_str() {
            value[key] = tr(app, raw).into();
        }
    }
    value["labels"] = crate::tray_locale::labels(app);
    value["locale"] = crate::tray_locale::code(app).into();
    value
}

fn update_tooltip(app: &AppHandle) {
    let s = localized_snapshot(app);
    let name = s["name"]
        .as_str()
        .filter(|v| !v.is_empty())
        .unwrap_or(s["fallback_name"].as_str().unwrap_or(""));
    let fallback_org = match s["org_id"].as_i64() {
        Some(id) if id > 0 => format!("{} {id}", tr(app, "组织")),
        _ => s["fallback_org"].as_str().unwrap_or("").to_owned(),
    };
    let org = s["org"]
        .as_str()
        .filter(|v| !v.is_empty())
        .unwrap_or(&fallback_org);
    if let Some(tray) = app.tray_by_id("tray") {
        let _ = tray.set_tooltip(Some(format!(
            "{}\n{}\n{}\n{}",
            name,
            org,
            s["status"].as_str().unwrap_or(""),
            s["ip"].as_str().unwrap_or("")
        )));
    }
    if let Some(window) = app.get_webview_window("tray-panel") {
        let _ = window.set_title(&tr(app, "托盘菜单"));
    }
}

#[tauri::command]
pub fn tray_set_locale(
    window: tauri::WebviewWindow,
    app: AppHandle,
    locale: String,
) -> Result<(), String> {
    let supervisor = app.state::<Option<Arc<Supervisor>>>();
    let sup = supervisor.as_ref().ok_or("Daemon unavailable")?;
    let expected = reqwest::Url::parse(&sup.url()).map_err(|e| e.to_string())?;
    if window.label() != "main"
        || window.url().map_err(|e| e.to_string())?.origin() != expected.origin()
    {
        return Err("Untrusted language UI origin".into());
    }
    let language = app.try_state::<Language>().ok_or("Tray not ready")?;
    language.set(&locale);
    crate::tray_locale::persist_native_locale(&app).map_err(|error| error.to_string())?;
    update_tooltip(&app);
    Ok(())
}

#[tauri::command]
pub fn tray_action(
    window: tauri::WebviewWindow,
    app: AppHandle,
    action: String,
) -> Result<Value, String> {
    if window.label() != "tray-panel" {
        return Err("tray window required".into());
    }
    if action == "snapshot" {
        return Ok(localized_snapshot(&app));
    }
    if action == "hide" {
        let _ = window.hide();
        return Ok(Value::Null);
    }
    if ![
        "open",
        "mesh",
        "mesh-up",
        "mesh-down",
        "files",
        "restart",
        "settings",
        "copy",
        "quit",
    ]
    .contains(&action.as_str())
    {
        return Err("unknown tray action".into());
    }
    if action == "copy" {
        let address = app.state::<Items>().address.lock().unwrap().clone();
        if address.is_empty() {
            return Err(tr(&app, "组网 IP 暂不可用"));
        }
        app.clipboard()
            .write_text(address)
            .map_err(|e| e.to_string())?;
        return Ok(Value::Null);
    }
    let _ = window.hide();
    run_action(&app, &action);
    Ok(Value::Null)
}

fn open(app: &AppHandle, route: &str) {
    if let (Some(window), Some(sup)) = (
        app.get_webview_window("main"),
        app.state::<Option<Arc<Supervisor>>>().inner(),
    ) {
        if let Ok(mut url) = reqwest::Url::parse(&sup.url()) {
            url.set_fragment(Some(route));
            let _ = window.navigate(url);
        }
        let _ = window.show();
        let _ = window.unminimize();
        let _ = window.set_focus();
    }
}

pub fn build(app: &AppHandle) -> Result<(), Box<dyn std::error::Error>> {
    app.manage(Language::default());
    app.manage(Items { mesh_change: Default::default(), snapshot: Mutex::new(serde_json::json!({"name":"", "org":"", "fallback_name":"正在读取设备信息", "fallback_org":"待读取", "status":"正在检查连接…", "ip":"", "up":false, "online":null, "files":crate::files::supported()})), address: Mutex::new(String::new()) });
    let window = tauri::WebviewWindowBuilder::new(
        app,
        "tray-panel",
        tauri::WebviewUrl::App("tray.html".into()),
    )
    .title(tr(app, "托盘菜单"))
    .inner_size(288.0, PANEL_HEIGHT)
    .decorations(false)
    .shadow(false)
    .resizable(false)
    .skip_taskbar(true)
    .always_on_top(true)
    .visible(false)
    .focused(false)
    .on_navigation(|url| url.path().ends_with("/tray.html"))
    .build()?;
    let hide_window = window.clone();
    window.on_window_event(move |event| {
        if matches!(event, tauri::WindowEvent::Focused(false)) {
            let _ = hide_window.hide();
        }
    });
    let mut builder = TrayIconBuilder::with_id("tray")
        .tooltip(tr(app, "正在检查连接…"))
        .show_menu_on_left_click(false);
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button,
                button_state: MouseButtonState::Up,
                position,
                ..
            } = event
            {
                if button != MouseButton::Left && button != MouseButton::Right {
                    return;
                }
                let app = tray.app_handle();
                if button == MouseButton::Left {
                    if let Some(window) = app.get_webview_window("tray-panel") {
                        let _ = window.hide();
                    }
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.unminimize();
                        let _ = window.set_focus();
                    }
                    return;
                }
                if let Some(window) = app.get_webview_window("tray-panel") {
                    if window.is_visible().unwrap_or(false) {
                        let _ = window.hide();
                        return;
                    }
                    let monitor = app
                        .monitor_from_point(position.x, position.y)
                        .ok()
                        .flatten()
                        .or_else(|| app.primary_monitor().ok().flatten());
                    if let Some(monitor) = monitor {
                        let area = monitor.work_area();
                        let scale = monitor.scale_factor();
                        let width = 288.0 * scale;
                        let height = PANEL_HEIGHT * scale;
                        let left = area.position.x as f64;
                        let top = area.position.y as f64;
                        let x = (position.x - width)
                            .max(left)
                            .min((left + area.size.width as f64 - width).max(left));
                        let y = (position.y - height - 8.0 * scale)
                            .max(top)
                            .min((top + area.size.height as f64 - height).max(top));
                        let _ =
                            window.set_position(tauri::PhysicalPosition::new(x as i32, y as i32));
                    }
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .build(app)?;
    Ok(())
}

fn run_action(app: &AppHandle, action: &str) {
    match action {
        "open" => open(app, "/overview"),
        "mesh" => open(app, "/mesh"),
        "files" => open(app, "/mesh/files"),
        "restart" => {
            let handle = app.clone();
            let supervisor = app.state::<Option<Arc<Supervisor>>>().inner().clone();
            tauri::async_runtime::spawn(async move {
                let result = match supervisor {
                    Some(sup) => {
                        let result = sup.restart().await;
                        let health = sup.status().await;
                        refresh(&handle, &sup, &health).await;
                        if result.is_ok() {
                            if let Some(main) = handle.get_webview_window("main") {
                                if let Ok(url) = reqwest::Url::parse(&sup.url()) {
                                    if main.url().ok().map(|u| u.origin()) != Some(url.origin()) {
                                        let _ = main.navigate(url);
                                    }
                                }
                            }
                        }
                        result
                    }
                    None => Err("Supervisor unavailable".into()),
                };
                let key = match result {
                    Ok(()) if cfg!(windows) => return,
                    Ok(()) => "服务已重启",
                    Err(error) => {
                        log::warn!("Service restart failed: {error}");
                        "服务重启失败"
                    }
                };
                handle
                    .dialog()
                    .message(tr(&handle, key))
                    .title(tr(&handle, "重启服务"))
                    .buttons(MessageDialogButtons::OkCustom(tr(&handle, "确定")))
                    .show(|_| {});
            });
        }
        "mesh-up" | "mesh-down" => {
            let handle = app.clone();
            let stop = action == "mesh-down";
            tauri::async_runtime::spawn(async move {
                let items = handle.state::<Items>();
                let Ok(_guard) = items.mesh_change.try_lock() else {
                    return;
                };
                let sup = handle.state::<Option<Arc<Supervisor>>>().inner().clone();
                if let Some(sup) = sup {
                    let result = change_mesh(&sup.url(), stop).await;
                    refresh(&handle, &sup, &sup.status().await).await;
                    match result {
                        Ok(()) => return,
                        Err(error) => log::warn!("Tray mesh change failed: {error}"),
                    }
                }
                handle
                    .dialog()
                    .message(tr(&handle, "操作失败，请重试"))
                    .title(tr(&handle, if stop { "停止组网" } else { "启动组网" }))
                    .buttons(MessageDialogButtons::OkCustom(tr(&handle, "确定")))
                    .show(|_| {});
            });
        }
        "settings" => open(app, "/settings"),
        "copy" => {
            let address = app.state::<Items>().address.lock().unwrap().clone();
            if !address.is_empty() {
                let text = if app.clipboard().write_text(address).is_ok() {
                    "已复制组网 IP"
                } else {
                    "复制失败，请重试"
                };
                let _ = app.notification().builder().title(tr(app, text)).show();
            }
        }
        "quit" => {
            let app = app.clone();
            let attached = app
                .state::<Option<Arc<Supervisor>>>()
                .inner()
                .as_ref()
                .map(|s| s.is_attached())
                .unwrap_or(true);
            let message = if attached && cfg!(windows) {
                "后台组网与端点继续运行。只要 Windows 用户保持登录，远程控制此设备时仍可双向复制文件。"
            } else if attached {
                "后台组网与端点继续运行。文件接收和进行中的传输将停止。"
            } else {
                "组网、端点和文件传输将停止。"
            };
            let handle = app.clone();
            app.dialog()
                .message(tr(&app, message))
                .title(tr(&app, "退出桌面程序？"))
                .buttons(MessageDialogButtons::OkCancelCustom(
                    tr(&app, "退出"),
                    tr(&app, "取消"),
                ))
                .show(move |yes| {
                    if yes {
                        tauri::async_runtime::spawn(async move {
                            let sup = handle.state::<Option<Arc<Supervisor>>>().inner().clone();
                            if let Some(sup) = sup {
                                let _ = sup.stop().await;
                            }
                            handle.exit(0);
                        });
                    }
                });
        }
        _ => {}
    }
}

fn mesh_action(state: &Value) -> Option<&'static str> {
    if state["paused"] == true {
        Some("mesh-up")
    } else if state["enabled"] == true {
        Some("mesh-down")
    } else {
        None
    }
}

async fn change_mesh(base: &str, stop: bool) -> Result<(), String> {
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| e.to_string())?;
    let state = get(&client, base, "/v1/mesh")
        .await
        .ok_or("Mesh unavailable")?;
    let (action, path) = if stop {
        ("mesh-down", "/v1/mesh/down")
    } else {
        ("mesh-up", "/v1/mesh/up")
    };
    if mesh_action(&state) != Some(action) {
        return Err("Mesh state changed".into());
    }
    for attempt in 0..2 {
        let auth = get(&client, base, "/v1/local-token")
            .await
            .ok_or("Local token unavailable")?;
        let token = auth["token"]
            .as_str()
            .filter(|s| !s.is_empty())
            .ok_or("Missing local token")?;
        let response = client
            .post(format!("{base}{path}"))
            .header("X-Local-Token", token)
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if attempt == 0 && response.status() == reqwest::StatusCode::UNAUTHORIZED {
            continue;
        }
        return response
            .error_for_status()
            .map(|_| ())
            .map_err(|e| e.to_string());
    }
    Err("Local authorization failed".into())
}

async fn get(client: &reqwest::Client, base: &str, path: &str) -> Option<Value> {
    client
        .get(format!("{}{path}", base.trim_end_matches('/')))
        .send()
        .await
        .ok()?
        .error_for_status()
        .ok()?
        .json()
        .await
        .ok()
}

pub async fn refresh(app: &AppHandle, sup: &Supervisor, health: &DaemonStatus) {
    let Some(items) = app.try_state::<Items>() else {
        return;
    };
    let Ok(client) = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(3))
        .build()
    else {
        return;
    };
    let base = sup.url();
    let mesh = if health.running {
        get(&client, &base, "/v1/mesh").await
    } else {
        None
    };
    let mesh = mesh.unwrap_or(Value::Null);
    let name = mesh["name"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("");
    let up = mesh["up"].as_bool() == Some(true);
    let status = if !health.running {
        "后台服务不可用"
    } else if mesh.is_null() {
        "组网状态暂不可用"
    } else if up {
        "组网已连接"
    } else if mesh["paused"] == true {
        "组网已暂停"
    } else if mesh["enabled"] == false {
        "组网未开启"
    } else {
        "组网连接中"
    };
    let ip = mesh["overlay"]
        .as_str()
        .and_then(|s| s.split('/').next())
        .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
        .unwrap_or("");
    let org_id = mesh["org_id"].as_i64().unwrap_or(0);
    let orgs = if org_id > 0 {
        get(&client, &base, "/v1/orgs").await
    } else {
        None
    };
    let org_name = orgs
        .as_ref()
        .and_then(|v| v["items"].as_array())
        .and_then(|rows| rows.iter().find(|r| r["id"].as_i64() == Some(org_id)))
        .and_then(|r| r["name"].as_str());
    let org = org_name.unwrap_or("");
    let nodes = if up {
        get(&client, &base, "/v1/mesh/nodes").await
    } else {
        None
    };
    let online = nodes
        .as_ref()
        .and_then(|v| v["items"].as_array())
        .map(|rows| {
            rows.iter()
                .filter(|r| r["online"] == true && r["overlay"].as_str() != Some(ip))
                .count()
        });
    *items.address.lock().unwrap() = ip.into();
    *items.snapshot.lock().unwrap() = serde_json::json!({"name":name,"org":org,"org_id":org_id,"fallback_name":"本机","fallback_org":"暂不可用","status":status,"ip":ip,"up":up,"mesh_action":mesh_action(&mesh),"online":online,"files":crate::files::supported()});
    update_tooltip(app);
}
