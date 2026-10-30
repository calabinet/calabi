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

struct Items {
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
        "open", "mesh", "files", "diagnose", "settings", "copy", "quit",
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
    app.manage(Items { snapshot: Mutex::new(serde_json::json!({"name":"", "org":"", "fallback_name":"正在读取设备信息", "fallback_org":"待读取", "status":"正在检查连接…", "ip":"", "up":false, "online":null, "files":crate::files::supported()})), address: Mutex::new(String::new()) });
    let window = tauri::WebviewWindowBuilder::new(
        app,
        "tray-panel",
        tauri::WebviewUrl::App("tray.html".into()),
    )
    .title(tr(app, "托盘菜单"))
    .inner_size(288.0, 340.0)
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
                        let height = 340.0 * scale;
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
        "diagnose" => {
            let handle = app.clone();
            let sup = app.state::<Option<Arc<Supervisor>>>().inner().clone();
            tauri::async_runtime::spawn(async move {
                if let Some(sup) = sup {
                    let health = sup.status().await;
                    refresh(&handle, &sup, &health).await;
                    let state = localized_snapshot(&handle)["status"]
                        .as_str()
                        .unwrap_or("未知")
                        .to_owned();
                    let hint = if cfg!(windows) {
                        "如后台服务不可用，请在管理员 PowerShell 中运行：\nRestart-Service calabi"
                    } else if cfg!(target_os = "macos") {
                        "如后台服务不可用，请在终端运行：\nsudo launchctl kickstart -k system/com.calabi.daemon"
                    } else {
                        "如后台服务不可用，请在终端运行：\nsudo calabi daemon restart"
                    };
                    handle
                        .dialog()
                        .message(format!(
                            "{}: {}\n{}: {}\n\n{}",
                            tr(&handle, "后台服务"),
                            tr(
                                &handle,
                                if health.running {
                                    "有响应"
                                } else {
                                    "无响应"
                                }
                            ),
                            tr(&handle, "组网"),
                            state,
                            tr(&handle, hint)
                        ))
                        .title(tr(&handle, "连接诊断"))
                        .buttons(MessageDialogButtons::OkCustom(tr(&handle, "确定")))
                        .show(|_| {});
                }
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
            let message = if attached {
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
    *items.snapshot.lock().unwrap() = serde_json::json!({"name":name,"org":org,"org_id":org_id,"fallback_name":"本机","fallback_org":"暂不可用","status":status,"ip":ip,"up":up,"online":online,"files":crate::files::supported()});
    update_tooltip(app);
}
