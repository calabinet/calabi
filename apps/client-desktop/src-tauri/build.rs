use std::path::PathBuf;

fn main() {
    // tauri_build embeds the Windows .ico into the exe's resource table, but it
    // does NOT emit a cargo:rerun-if-changed for the icon files. So after you
    // swap icons/icon.ico, an incremental `cargo tauri build` relinks the exe
    // while reusing the STALE compiled resource (resource.lib) — the titlebar
    // and taskbar keep showing the old icon even though the new .ico is on disk.
    //
    // Tell cargo to re-run this build script (which recompiles the resource and
    // re-embeds the icon) whenever the icon set changes.
    println!("cargo:rerun-if-changed=icons/icon.ico");
    println!("cargo:rerun-if-changed=icons");

    embed_daemon();

    tauri_build::build()
}

/// Bake the calabi daemon binary INTO the desktop exe so the shipped
/// calabi-desktop.exe is self-contained — no sidecar file, no separate install.
///
/// We copy the staged binary (binaries/calabi[.exe], placed there by
/// build-desktop.{ps1,sh}) into OUT_DIR/embedded-daemon, which the crate
/// include_bytes!()s. If no binary is staged (e.g. a plain `cargo build` on a
/// fresh checkout) we write an EMPTY placeholder so the crate still compiles;
/// at runtime an empty payload means "fall back to a sibling/PATH calabi".
///
/// A content signature is exported as CALABI_DAEMON_SIG so the runtime extracts
/// each distinct daemon build to its own filename (a new desktop release ships a
/// new daemon → new sig → fresh extract, never a stale cached copy).
fn embed_daemon() {
    // The daemon is NO LONGER baked into the desktop exe (Option A / F3 "spawn +
    // embedded removal"): the installer delivers it — a .pkg on macOS, and the
    // NSIS installer ships calabi.exe on Windows — and the app ATTACHES to the
    // machine-wide system service. We still write an EMPTY OUT_DIR payload (+ sig)
    // so the include_bytes! in daemon.rs compiles; empty ⇒ extract_embedded_daemon
    // returns None ⇒ resolve_binary falls back to a sibling/PATH calabi, used only
    // by DEBUG dev builds. This drops ~20MB of duplicated daemon from the exe.
    // See docs/runbook/privileged-service-and-updates-plan.md.
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("embedded-daemon");
    std::fs::write(&out, b"").expect("write OUT_DIR/embedded-daemon");
    println!("cargo:rustc-env=CALABI_DAEMON_SIG=none");
}
