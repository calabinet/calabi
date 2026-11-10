// Developer-only harness. The macOS runner links the native FreeRDP adapter.
#[cfg(target_os = "macos")]
fn main() {
    use std::time::Duration;
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
    use tauri::{Manager, RunEvent, WindowEvent};
    extern "C" {
        fn calabi_ssh_login() -> i32;
        fn calabi_ssh_confirm(prompt: *const std::ffi::c_char, directory: *const std::ffi::c_char) -> i32;
        fn calabi_rdp_prompt(window: *mut std::ffi::c_void);
        fn calabi_rdp_request_stop() -> bool;
        fn mac_mesh_cancel_files();
        fn mac_show_finder_menu_settings();
        fn calabi_rdp_finder_settings_title() -> *const std::ffi::c_char;
    }
    let mut args = std::env::args_os().skip(1);
    match args.next().as_deref() {
        Some(mode) if mode == "--ssh-login" => std::process::exit(unsafe { calabi_ssh_login() }),
        Some(mode) if mode == "--ssh-confirm" => {
            use std::ffi::CString;
            use std::os::unix::ffi::OsStrExt;
            let Some(prompt) = args.next().and_then(|arg| CString::new(arg.as_bytes()).ok()) else {
                std::process::exit(1);
            };
            let Some(directory) = args.next().and_then(|arg| CString::new(arg.as_bytes()).ok()) else {
                std::process::exit(1);
            };
            std::process::exit(unsafe { calabi_ssh_confirm(prompt.as_ptr(), directory.as_ptr()) });
        }
        _ => {}
    }
    let mut exit_pending = false;
    let mut app = tauri::Builder::default()
        .on_menu_event(|app, event| {
            match event.id().as_ref() {
                "cancel-rdp-files" => unsafe { mac_mesh_cancel_files() },
                "finder-menu-settings" => unsafe { mac_show_finder_menu_settings() },
                "quit-rdp" => app.exit(0),
                _ => {}
            }
        })
        .on_window_event(|window, event| {
            if let WindowEvent::CloseRequested { api, .. } = event {
                if !unsafe { calabi_rdp_request_stop() } {
                    api.prevent_close();
                    window.app_handle().exit(0);
                }
            }
        })
        .setup(|app| {
            let finder_settings_title = unsafe {
                std::ffi::CStr::from_ptr(calabi_rdp_finder_settings_title())
            }.to_str()?;
            let session_menu = Submenu::with_items(
                app,
                "Calabi 远程桌面",
                true,
                &[
                    &PredefinedMenuItem::hide(app, Some("隐藏远程桌面"))?,
                    &PredefinedMenuItem::hide_others(app, Some("隐藏其他应用"))?,
                    &PredefinedMenuItem::show_all(app, Some("显示全部"))?,
                    &PredefinedMenuItem::separator(app)?,
                    &MenuItem::with_id(app, "finder-menu-settings", finder_settings_title, true, None::<&str>)?,
                    &PredefinedMenuItem::separator(app)?,
                    &MenuItem::with_id(app, "quit-rdp", "结束远程桌面", true, Some("CmdOrCtrl+Q"))?,
                ],
            )?;
            let edit_menu = Submenu::with_items(
                app,
                "编辑",
                true,
                &[
                    &PredefinedMenuItem::cut(app, Some("剪切"))?,
                    &PredefinedMenuItem::copy(app, Some("复制"))?,
                    &PredefinedMenuItem::paste(app, Some("粘贴"))?,
                    &PredefinedMenuItem::select_all(app, Some("全选"))?,
                    &PredefinedMenuItem::separator(app)?,
                    &MenuItem::with_id(app,"cancel-rdp-files","取消文件接收",true,None::<&str>)?,
                ],
            )?;
            let window_menu = Submenu::with_items(
                app,
                "窗口",
                true,
                &[
                    &PredefinedMenuItem::minimize(app, Some("最小化"))?,
                    &PredefinedMenuItem::fullscreen(app, Some("切换全屏"))?,
                ],
            )?;
            app.set_menu(Menu::with_items(app, &[&session_menu, &edit_menu, &window_menu])?)?;
            let window = tauri::WindowBuilder::new(app, "rdp-p0")
                .title("Calabi · 远程登录")
                .visible(false)
                .focused(false)
                .inner_size(1024.0, 576.0)
                .build()?;
            // setup runs on the AppKit thread and Tauri owns this NSWindow.
            unsafe { calabi_rdp_prompt(window.ns_window()?) };
            Ok(())
        })
        .build(tauri::generate_context!())
        .expect("start Calabi RDP probe");
    if std::env::var_os("CALABI_RDP_WORKSPACE_PORT").is_some() {
        // Keep the login panel available without registering a separate Dock app.
        app.set_activation_policy(tauri::ActivationPolicy::Accessory);
    }
    app.run(move |app, event| {
        if let RunEvent::ExitRequested { api, code, .. } = event {
            if unsafe { calabi_rdp_request_stop() } { return; }
            api.prevent_exit();
            if exit_pending { return; }
            exit_pending = true;
            // Keep AppKit pumping while native file/clipboard cleanup drains.
            let app = app.clone();
            tauri::async_runtime::spawn(async move {
                while !unsafe { calabi_rdp_request_stop() } {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                app.exit(code.unwrap_or(0));
            });
        }
    });
}

#[cfg(not(target_os = "macos"))]
fn main() {
    panic!("This probe requires macOS and AppKit");
}
