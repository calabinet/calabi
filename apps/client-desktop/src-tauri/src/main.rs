// main.rs — Tauri 2 desktop shell entry point.
//
// Responsibilities:
//   - Spawn / supervise the calabi daemon
//   - Render the main window pointed at http://127.0.0.1:7400
//   - System tray with status indicator + quick actions
//   - Single-instance guard (don't open two windows on the same machine)
//   - Update checker via tauri-plugin-updater
//
// The frontend is loaded directly from the daemon's :7400 endpoint —
// no separate JS build. shell/index.html is only used as the bundle
// "frontendDist" Tauri requires; the actual UI is the SPA the daemon
// embeds (see apps/client/internal/status/ui/).

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod daemon;
mod tray;
mod tray_locale;
mod files;
mod file_requests;

use std::sync::Arc;
use std::time::Duration;

use log::{error, info};
use tauri::{
    Emitter, Manager,
};
use tauri_plugin_notification::NotificationExt;

use crate::daemon::Supervisor;

fn main() {
    // GUI subsystem builds (release) detach stdout/stderr — env_logger
    // would write to a black hole. Pipe everything to a known file so
    // crashes can be diagnosed after the fact.
    let log_path = std::env::temp_dir().join("calabi-desktop.log");
    let mut builder = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    );
    if let Ok(f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log_path)
    {
        builder.target(env_logger::Target::Pipe(Box::new(f)));
    }
    let _ = builder.try_init();
    log::info!("=== calabi-desktop boot; logfile {}", log_path.display());
    log::info!("desktop runtime: exe={:?}, os={}, file_transfers={}",
        std::env::current_exe().ok(), std::env::consts::OS,
        files::supported());

    // GUI subsystem + Tauri's plugin-init code-path swallows panic output.
    // Install a hook that writes the panic message + backtrace to the
    // same logfile so failures inside .run() leave a trail.
    let log_path_for_panic = log_path.clone();
    std::panic::set_hook(Box::new(move |info| {
        let bt = std::backtrace::Backtrace::force_capture();
        let msg = format!("PANIC: {info}\nbacktrace:\n{bt}");
        // log!() may be wedged if logger is mid-flush; write to the
        // file directly too, belt and braces.
        log::error!("{msg}");
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path_for_panic)
        {
            use std::io::Write;
            let _ = writeln!(f, "[PANIC HOOK] {msg}");
            let _ = f.flush();
        }
    }));

    // Builder is built up step-by-step with log lines between major
    // sections so we can bisect plugin-init crashes from the logfile.
    log::info!("builder: creating");
    let app = tauri::Builder::default();
    let app = app.invoke_handler(tauri::generate_handler![files::files_action, files::file_receipt_action, tray::tray_action, tray::tray_set_locale]);
    log::info!("builder: +single_instance");
    let app = app.plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
        log::info!("single_instance: second launch detected, focusing existing");
        if let Some(w) = app.get_webview_window("main") {
            let _ = w.show();
            let _ = w.set_focus();
        }
    }));
    log::info!("builder: +shell");
    let app = app.plugin(tauri_plugin_shell::init());
    log::info!("builder: +opener");
    let app = app.plugin(tauri_plugin_opener::init());
    let app = app.plugin(tauri_plugin_dialog::init());
    let app = app.plugin(tauri_plugin_clipboard_manager::init());
    log::info!("builder: +notification");
    let app = app.plugin(tauri_plugin_notification::init());
    log::info!("builder: +autostart");
    let app = app.plugin(tauri_plugin_autostart::init(
        tauri_plugin_autostart::MacosLauncher::LaunchAgent,
        None,
    ));
    log::info!("builder: +setup");
    let app = app.setup(move |app| {
            log::info!("setup: starting");
            // Resolve + create the supervisor here (not in main) so we can ask
            // Tauri for a writable per-user dir to extract the embedded daemon
            // into. The daemon is baked into THIS exe (build.rs include_bytes);
            // resolve_binary extracts it to app-local-data/daemon and runs it.
            // Falls back to env override / sibling exe / PATH for dev builds.
            let daemon_dir = app
                .path()
                .app_local_data_dir()
                .ok()
                .map(|d| d.join("daemon"));
            // Attach-only: ALWAYS create the Supervisor — it attaches to the
            // machine-wide system service, which needs no local daemon binary.
            // resolve_binary is now just the DEBUG dev-spawn fallback, so its
            // absence is fine (None ⇒ attach-only).
            let bin = daemon::resolve_binary(daemon_dir.clone()).ok();
            let supervisor: Option<Arc<Supervisor>> = Some(Supervisor::new(bin, daemon_dir));
            app.manage(supervisor.clone());
            files::install(app);
            // Create the main window here (not in tauri.conf.json) so its
            // User-Agent can reflect the real OS. A config userAgent is a
            // single static string — it used to claim "Windows NT 10.0" on
            // every platform, which a macOS/Linux build would misreport.
            // WebviewUrl::App("index.html") reproduces the config default:
            // dev → devUrl (:7400), prod → the bundled shell/index.html.
            let ua = desktop_user_agent();
            log::info!("setup: creating main window; ua={ua}");
            tauri::WebviewWindowBuilder::new(
                app,
                "main",
                tauri::WebviewUrl::App("index.html".into()),
            )
            .title("Calabi")
            .inner_size(1100.0, 720.0)
            .min_inner_size(880.0, 560.0)
            .resizable(false)
            .maximizable(false)
            .visible(false)
            .theme(Some(tauri::Theme::Dark))
            .user_agent(&ua)
            .initialization_script(include_str!("../../shell/tray-language.js"))
            .build()?;

            log::info!("setup: building tray");
            // Build the tray immediately so the user has feedback even
            // if the daemon takes a few seconds to come up.
            if let Err(e) = tray::build(app.handle()) {
                // Don't fail the whole app if the tray can't be built —
                // we still want the window to come up so the user sees
                // something. Log and continue.
                log::error!("build_tray failed: {e}");
            } else {
                log::info!("tray ready");
            }

            // If we have a supervisor, kick off the daemon start in a
            // background task and reveal the window when /healthz answers.
            if let Some(sup) = supervisor.clone() {
                // Clone for the start-task before the move; the original
                // `sup` stays available for the tray-refresh task below.
                let sup_for_start = sup.clone();
                let handle = app.handle().clone();
                tauri::async_runtime::spawn(async move {
                    if let Err(e) = sup_for_start.start().await {
                        error!("start daemon: {e}");
                        let _ = handle
                            .notification()
                            .builder()
                            .title("Calabi failed to start")
                            .body(format!("Could not start the local daemon: {e}"))
                            .show();
                        return;
                    }
                    // Poll until healthz answers, then point the window at the
                    // daemon's ACTUAL console port and reveal it. The window
                    // starts on the bundled loading shell (shell/index.html);
                    // we redirect it here via the same cross-origin
                    // location.replace the shell used to do — except now to the
                    // port WE picked, not a hard-coded :7400 that a foreign
                    // service might own.
                    for _ in 0..40 {
                        if sup_for_start.status().await.running {
                            let url = sup_for_start.url();
                            info!("daemon up — navigating window to {url}");
                            if let Some(w) = handle.get_webview_window("main") {
                                let _ = w.eval(&format!(
                                    "window.location.replace({url:?})"
                                ));
                                let _ = w.show();
                                let _ = w.set_focus();
                            }
                            return;
                        }
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    }
                    // Still no luck — show the window with the loading shell and
                    // surface a hint instead of spinning forever.
                    if let Some(w) = handle.get_webview_window("main") {
                        let _ = w.eval(
                            "var m=document.getElementById('msg'); \
                             if(m){m.innerHTML='<span style=\\'color:#ef4444\\'>守护进程未响应</span><br>请用托盘菜单「连接诊断」检查。';}",
                        );
                        let _ = w.show();
                    }
                });

                // Tray-status refresh loop. Updates the tooltip + icon
                // variant every 5s based on /healthz.
                let handle2 = app.handle().clone();
                let sup2 = sup.clone();
                tauri::async_runtime::spawn(async move {
                    loop {
                        let st = sup2.status().await;
                        tray::refresh(&handle2, &sup2, &st).await;
                        // Emit so the frontend (if mounted) can react too.
                        let _ = handle2.emit("daemon-status", st);
                        tokio::time::sleep(Duration::from_secs(5)).await;
                    }
                });
            } else {
                // No supervisor (calabi binary not found) — still show
                // the window so the shell can render its "missing binary" hint.
                log::warn!("no supervisor; showing window for diagnostic shell");
                if let Some(w) = app.get_webview_window("main") {
                    let _ = w.show();
                }
            }

            log::info!("setup done");
            Ok(())
        });
    log::info!("builder: +on_window_event");
    let app = app.on_window_event(|window, event| {
        if let tauri::WindowEvent::CloseRequested { api, .. } = event {
            if window.label() == "main" {
                let _ = window.hide();
                api.prevent_close();
            }
        }
    });
    log::info!("builder: entering .run() — plugins init here");
    app.run(tauri::generate_context!())
        .expect("error while running tauri application");
    log::info!("builder: .run() returned (app exited cleanly)");
}

/// User-Agent for the main webview. The trailing `CalabiDesktop/<ver>` token is
/// what the daemon's status server matches to recognise the shell (see
/// desktopUAMarker in apps/client/internal/status/status.go); the rest is an
/// honest per-OS string. The old tauri.conf.json hard-coded "Windows NT 10.0"
/// on every platform, so a macOS/Linux build would have misreported itself.
fn desktop_user_agent() -> String {
    let platform = if cfg!(target_os = "macos") {
        "Macintosh; Intel Mac OS X 10_15_7"
    } else if cfg!(target_os = "windows") {
        "Windows NT 10.0; Win64; x64"
    } else {
        "X11; Linux x86_64"
    };
    format!(
        "Mozilla/5.0 ({platform}) AppleWebKit/537.36 (KHTML, like Gecko) \
         Chrome/120.0.0.0 Safari/537.36 CalabiDesktop/{}",
        env!("CARGO_PKG_VERSION")
    )
}
