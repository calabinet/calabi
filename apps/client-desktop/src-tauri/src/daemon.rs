// daemon.rs — supervises the bundled calabi binary process.
//
// Lifecycle:
//   - resolve_binary(): finds the calabi(.exe) we'll exec
//   - Supervisor::start(): spawn OUR OWN daemon (never attach to a foreign one)
//   - Supervisor::stop(): kill the child (best-effort)
//   - Supervisor::status(): tail the last known /healthz
//   - Supervisor::url(): the http://127.0.0.1:<port> the webview should load
//
// Port model — why we pick the port ourselves:
//   The desktop window is just a browser pointed at the daemon's local console.
//   If we naively loaded :7400 we'd show whatever ALREADY answers there — e.g.
//   a separately-installed `calabi` Windows service running an OLD binary — and
//   the bundled daemon's UI would never appear. So the supervisor ALWAYS runs
//   its own bundled daemon and picks a free console port (7400, else 7401, 7402…
//   — same fallback the Go daemon does for multi-client machines), pins the
//   daemon to it via CALABI_STATUS_ADDR, and the window navigates to that exact
//   port. The bundled daemon and the window therefore always agree, and the app
//   coexists with anything (service / other client) squatting :7400.
//
// We intentionally don't restart automatically on crash here — the
// kardianos/service install path is the durable way to keep the daemon
// alive. This module is for the "I just clicked the icon, please start
// the daemon for this session" case.

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use log::{info, warn};
use serde::Serialize;
use which::which;

// The calabi daemon, baked into this exe at build time (build.rs copies the
// staged binaries/calabi[.exe] into OUT_DIR/embedded-daemon). Empty when no
// binary was staged — see extract_embedded_daemon. This is what makes the
// shipped calabi-desktop.exe self-contained.
const EMBEDDED_DAEMON: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/embedded-daemon"));
// Content signature of the embedded daemon (FNV-1a, or "none"). Used to name the
// extracted file so a new daemon build never reuses a stale extracted copy.
const DAEMON_SIG: &str = env!("CALABI_DAEMON_SIG");

// Console port preferences. We scan [PORT_START, PORT_START+PORT_SCAN) for the
// first bindable port; the Go daemon also falls back within this range, so the
// discovery scan below covers the (rare) case it lands one above what we picked.
const PORT_START: u16 = 7400;
const PORT_SCAN: u16 = 20;

// Release shells are attach-only (Option A): the daemon is delivered by the
// installer and we attach to the machine-wide system service. Only DEBUG dev
// builds spawn their own daemon. See docs/runbook/privileged-service-and-updates-plan.md.
const ALLOW_DEV_SPAWN: bool = cfg!(debug_assertions);

#[derive(Clone, Debug, Serialize)]
pub struct DaemonStatus {
    pub running: bool,
    pub healthy: bool,
    pub state: String,
    pub version: String,
    pub server_addr: String,
    /// /healthz service_mode: "system" for the machine-wide system service we
    /// attach to (Option A), "user" for a dev/foreground daemon, "" if unknown.
    pub service_mode: String,
    /// True when the shell attached to an existing system service rather than
    /// spawning its own daemon (so the tray "stop/restart" don't touch it).
    pub attached: bool,
    pub error: Option<String>,
}

impl Default for DaemonStatus {
    fn default() -> Self {
        Self {
            running: false,
            healthy: false,
            state: "stopped".into(),
            version: String::new(),
            server_addr: String::new(),
            service_mode: String::new(),
            attached: false,
            error: None,
        }
    }
}

pub struct Supervisor {
    // The local calabi daemon binary for the DEBUG dev-spawn fallback, or None
    // when there isn't one. A release shell is attach-only (Option A: the service
    // comes from the installer), so this is never spawned there.
    bin: Option<PathBuf>,
    child: Mutex<Option<Child>>,
    // The port we asked the daemon to bind (CALABI_STATUS_ADDR). Updated on each
    // start(); defaults to PORT_START before the first launch.
    start_port: Mutex<u16>,
    // The port the daemon actually answered /healthz on. Discovered by the first
    // successful probe and cached so the 5s tray loop hits one port, not a scan.
    bound_port: Mutex<Option<u16>>,
    // Some(port) when we ATTACHED to an existing machine-wide system service
    // (Option A) instead of spawning our own: stop() must then NOT kill it and
    // start() must NOT spawn. See docs/runbook/privileged-service-and-updates-plan.md.
    attached: Mutex<Option<u16>>,
    // Where we record the spawned daemon's PID, so a NEXT launch can reap a
    // daemon orphaned by a crash / force-kill (its single-instance lock would
    // otherwise block the new daemon from starting). None = no reaping.
    pid_file: Option<PathBuf>,
}

impl Supervisor {
    /// Construct a supervisor. `bin` is an optional local daemon for the debug
    /// dev-spawn fallback (None ⇒ attach-only). `data_dir` is a writable per-user
    /// dir for the PID file (orphan reaping); None disables.
    pub fn new(bin: Option<PathBuf>, data_dir: Option<PathBuf>) -> Arc<Self> {
        match &bin {
            Some(b) => info!("calabi daemon (dev-spawn fallback) at: {}", b.display()),
            None => info!("no local calabi daemon — attach-only"),
        }
        Arc::new(Self {
            bin,
            child: Mutex::new(None),
            // 0 = "haven't picked a port yet". status() treats this as
            // not-running and does NOT probe — critical so the tray status loop,
            // which can fire before start() runs, never scans from a default
            // 7400 and latches onto a FOREIGN service squatting :7400 (that bug
            // made the window navigate to :7400 instead of our daemon's port).
            start_port: Mutex::new(0),
            bound_port: Mutex::new(None),
            attached: Mutex::new(None),
            pid_file: data_dir.map(|d| d.join("daemon.pid")),
        })
    }

    /// The URL the webview should load: the daemon's console on the port we
    /// discovered (or, before discovery, the port we asked it to bind).
    pub fn url(&self) -> String {
        let p = self
            .bound_port
            .lock()
            .unwrap()
            .unwrap_or_else(|| *self.start_port.lock().unwrap());
        format!("http://127.0.0.1:{p}")
    }

    /// True when the shell attached to an existing machine-wide system service
    /// (Option A) rather than spawning its own daemon. The tray uses this to
    /// avoid offering "stop/restart" on a root service it can't control.
    pub fn is_attached(&self) -> bool {
        self.attached.lock().unwrap().is_some()
    }

    /// Spawn OUR daemon if we aren't already managing one. Idempotent. We never
    /// probe-and-attach to a foreign :7400 here — that's exactly what made the
    /// window show a stale service's UI. We always run the bundled binary.
    pub async fn start(&self) -> Result<(), String> {
        {
            let guard = self.child.lock().unwrap();
            if guard.is_some() {
                return Ok(());
            }
        }
        // Idempotent: already attached to a system service.
        if self.attached.lock().unwrap().is_some() {
            return Ok(());
        }
        // F2 (Option A): PREFER attaching to the machine-wide system service over
        // spawning our own. It reliably owns :7400 (starts at boot); we verify via
        // /healthz service_mode=="system", so a foreign or dev/user daemon on :7400
        // is NOT trusted — we fall through and spawn our own (dev + pre-F3
        // installer behaviour, unchanged). See
        // docs/runbook/privileged-service-and-updates-plan.md.
        if let Some(port) = discover_system_service().await {
            info!("attaching to system service on 127.0.0.1:{port} (not spawning our own)");
            *self.attached.lock().unwrap() = Some(port);
            *self.start_port.lock().unwrap() = port;
            *self.bound_port.lock().unwrap() = Some(port);
            return Ok(());
        }
        // No system service found. A release shell is ATTACH-ONLY — the installer
        // is the sole daemon delivery (spawn + embedded removed), so there's
        // nothing for us to start if the service isn't running. DEBUG builds still
        // spawn a dev daemon for ergonomics. See
        // docs/runbook/privileged-service-and-updates-plan.md.
        // Release is attach-only; only DEBUG builds spawn a dev daemon. The const
        // (vs a #[cfg]) keeps the spawn code compiled — no dead-code churn — but
        // off at runtime in release.
        if ALLOW_DEV_SPAWN {
            if let Some(bin) = self.bin.clone() {
                return self.spawn_dev_daemon(&bin);
            }
        }
        Err("no running Calabi system service found — install or start it \
             (the desktop app attaches to the machine-wide service)"
            .into())
    }

    /// Dev fallback (DEBUG only, gated by ALLOW_DEV_SPAWN): spawn our own daemon
    /// when no system service is present. A release shell is attach-only.
    fn spawn_dev_daemon(&self, bin: &std::path::Path) -> Result<(), String> {
        // Reap a daemon orphaned by a previous crash / force-kill. Its
        // single-instance lock on the shared config dir would otherwise make the
        // freshly-spawned daemon exit immediately (never binding its console).
        self.reap_stale_daemon();
        let port = pick_status_port();
        *self.start_port.lock().unwrap() = port;
        *self.bound_port.lock().unwrap() = None;

        let mut cmd = Command::new(bin);
        cmd.arg("daemon");
        // Pin the console to the free port we picked; the Go daemon honours
        // CALABI_STATUS_ADDR and status() rediscovers the real port either way.
        cmd.env("CALABI_STATUS_ADDR", format!("127.0.0.1:{port}"));
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            const CREATE_NO_WINDOW: u32 = 0x0800_0000;
            cmd.creation_flags(CREATE_NO_WINDOW);
        }
        let child = cmd
            .spawn()
            .map_err(|e| format!("spawn calabi daemon: {e}"))?;
        let pid = child.id();
        info!("spawned dev calabi daemon pid={pid} console=127.0.0.1:{port}");
        if let Some(pf) = &self.pid_file {
            if let Some(dir) = pf.parent() {
                let _ = std::fs::create_dir_all(dir);
            }
            let _ = std::fs::write(pf, pid.to_string());
        }
        *self.child.lock().unwrap() = Some(child);
        Ok(())
    }

    /// If a PID file from a previous session points at a still-running calabi
    /// daemon, kill it. Verified to be a calabi process before killing so a
    /// recycled PID can't take down something unrelated. Best-effort.
    fn reap_stale_daemon(&self) {
        let Some(pf) = &self.pid_file else { return };
        let Ok(s) = std::fs::read_to_string(pf) else {
            return;
        };
        let Ok(pid) = s.trim().parse::<u32>() else {
            let _ = std::fs::remove_file(pf);
            return;
        };
        if pid_is_calabi(pid) {
            info!("reaping orphaned daemon from previous session pid={pid}");
            kill_pid(pid);
        }
        let _ = std::fs::remove_file(pf);
    }

    /// Stop the child we spawned. If the daemon is running as an OS
    /// service (kardianos-installed), this won't touch it — the user
    /// should `calabi daemon stop` for those.
    pub async fn stop(&self) -> Result<(), String> {
        // Never kill a system service we merely attached to — it isn't ours, and
        // (it runs as root) we couldn't anyway. Just drop our view of it.
        if self.attached.lock().unwrap().take().is_some() {
            *self.bound_port.lock().unwrap() = None;
            info!("detached from system service (left it running)");
            return Ok(());
        }
        let taken = self.child.lock().unwrap().take();
        if let Some(mut child) = taken {
            let _ = child.kill();
            let _ = child.wait();
            info!("killed managed daemon");
        }
        *self.bound_port.lock().unwrap() = None;
        // Clean stop — drop the PID file so the next launch doesn't try to reap a
        // process that's already gone (or whose PID got recycled).
        if let Some(pf) = &self.pid_file {
            let _ = std::fs::remove_file(pf);
        }
        Ok(())
    }

    /// Snapshot of the latest /healthz on our daemon's console port.
    pub async fn status(&self) -> DaemonStatus {
        // Copy values out and drop the guards BEFORE awaiting — a MutexGuard
        // held across .await makes the future non-Send (tauri::spawn needs Send).
        let attached = self.attached.lock().unwrap().is_some();
        let bound = *self.bound_port.lock().unwrap();
        if let Some(p) = bound {
            let mut st = probe_healthz(p).await;
            st.attached = attached;
            return st;
        }
        // Not yet discovered: scan upward from the port we asked for. Foreign
        // daemons (e.g. a squatting service) sit on LOWER ports than the free
        // one we picked, so scanning from start_port only ever finds ours.
        // start_port==0 means start() hasn't picked a port yet — report
        // not-running rather than scanning (which would hit a foreign :7400).
        let start = *self.start_port.lock().unwrap();
        if start == 0 {
            return DaemonStatus::default();
        }
        let end = start.saturating_add(PORT_SCAN);
        for p in start..end {
            let st = probe_healthz(p).await;
            if st.running {
                *self.bound_port.lock().unwrap() = Some(p);
                return st;
            }
        }
        DaemonStatus::default()
    }
}

/// Find the first bindable console port: PORT_START, else the next few, else an
/// ephemeral port. Binding-then-dropping leaves a tiny race before the daemon
/// rebinds; status() rediscovers the real port if the daemon's own fallback
/// shifts it.
fn pick_status_port() -> u16 {
    for p in PORT_START..PORT_START.saturating_add(PORT_SCAN) {
        if std::net::TcpListener::bind(("127.0.0.1", p)).is_ok() {
            return p;
        }
    }
    std::net::TcpListener::bind(("127.0.0.1", 0))
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
        .unwrap_or(PORT_START)
}

/// Is `pid` a live process whose image is a calabi binary? Used to make orphan
/// reaping safe against PID reuse — we only kill something we recognise.
#[cfg(windows)]
fn pid_is_calabi(pid: u32) -> bool {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = Command::new("tasklist")
        .args(["/FI", &format!("PID eq {pid}"), "/NH", "/FO", "CSV"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
    match out {
        Ok(o) => String::from_utf8_lossy(&o.stdout)
            .to_lowercase()
            .contains("calabi"),
        Err(_) => false,
    }
}

#[cfg(not(windows))]
fn pid_is_calabi(pid: u32) -> bool {
    // /proc/<pid>/comm is the process's command name.
    match std::fs::read_to_string(format!("/proc/{pid}/comm")) {
        Ok(s) => s.to_lowercase().contains("calabi"),
        // No /proc (macOS): fall back to `ps -o comm=`.
        Err(_) => Command::new("ps")
            .args(["-p", &pid.to_string(), "-o", "comm="])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_lowercase().contains("calabi"))
            .unwrap_or(false),
    }
}

#[cfg(windows)]
fn kill_pid(pid: u32) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let _ = Command::new("taskkill")
        .args(["/PID", &pid.to_string(), "/F"])
        .creation_flags(CREATE_NO_WINDOW)
        .output();
}

#[cfg(not(windows))]
fn kill_pid(pid: u32) {
    let _ = Command::new("kill").args(["-9", &pid.to_string()]).output();
}

/// Resolve the calabi binary path. Order:
///   1. $CALABI_DAEMON_PATH — DEBUG BUILDS ONLY (dev override; see below)
///   2. the daemon EMBEDDED in this exe, extracted to `extract_dir`
///      (production: the self-contained single-exe path)
///   3. sibling next to the current executable (dev: target/release)
///   4. PATH lookup
///
/// The env override is compiled OUT of release builds on purpose. A shipped,
/// signed calabi-desktop.exe must never let an environment variable decide which
/// executable it launches: anything able to set CALABI_DAEMON_PATH (another
/// installer, malware, a forgotten User-scope var) could otherwise point the
/// trusted app at an arbitrary binary. That was not hypothetical — a dev machine
/// with a permanent User-scope CALABI_DAEMON_PATH silently ran its repo build
/// instead of the daemon baked into the downloaded release, because this check
/// used to run before the embedded one in every profile.
///
/// `cargo tauri dev` compiles with debug_assertions on, which is exactly the
/// workflow the override exists for, so dev ergonomics are unchanged.
pub fn resolve_binary(extract_dir: Option<PathBuf>) -> Result<PathBuf, String> {
    #[cfg(debug_assertions)]
    {
        if let Ok(p) = std::env::var("CALABI_DAEMON_PATH") {
            let pb = PathBuf::from(p);
            if pb.exists() {
                return Ok(pb);
            }
        }
    }
    if let Some(dir) = extract_dir {
        if let Some(p) = extract_embedded_daemon(&dir) {
            return Ok(p);
        }
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            for name in &["calabi", "calabi.exe"] {
                let sib = dir.join(name);
                if sib.exists() {
                    return Ok(sib);
                }
            }
        }
    }
    which("calabi").map_err(|_| {
        // Deliberately does NOT suggest CALABI_DAEMON_PATH: release builds ignore
        // it, so sending a user there would be a dead end.
        "calabi binary not found — reinstall calabi-desktop (it ships the daemon) \
         or install calabi on PATH"
            .into()
    })
}

/// Materialize the embedded daemon to `dir` and return its path. Returns None if
/// nothing was embedded (empty payload) or the write fails. The file is named
/// with the build-time content signature, so each distinct daemon build extracts
/// once and is reused on later launches; a new desktop release (new daemon →
/// new sig) extracts fresh instead of running a stale cached copy.
fn extract_embedded_daemon(dir: &Path) -> Option<PathBuf> {
    if EMBEDDED_DAEMON.is_empty() {
        return None;
    }
    let name = if cfg!(windows) {
        format!("calabi-{DAEMON_SIG}.exe")
    } else {
        format!("calabi-{DAEMON_SIG}")
    };
    let path = dir.join(&name);
    // Already extracted with the right size? Reuse — avoids rewriting ~20MB and
    // avoids "file in use" if a previous daemon from this exe is still running.
    if std::fs::metadata(&path)
        .map(|m| m.len() as usize == EMBEDDED_DAEMON.len())
        .unwrap_or(false)
    {
        return Some(path);
    }
    if let Err(e) = std::fs::create_dir_all(dir) {
        warn!("create daemon dir {}: {e}", dir.display());
        return None;
    }
    // Write to a temp name then rename into place so a concurrent launch never
    // sees a half-written exe.
    let tmp = dir.join(format!(".{name}.tmp"));
    if let Err(e) = std::fs::write(&tmp, EMBEDDED_DAEMON) {
        warn!("write embedded daemon: {e}");
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o755));
    }
    match std::fs::rename(&tmp, &path) {
        Ok(()) => {
            info!("extracted embedded daemon to {}", path.display());
            Some(path)
        }
        Err(e) => {
            // Rename can lose a race (another launch placed it first). If the
            // destination now exists at the right size, that's fine.
            let _ = std::fs::remove_file(&tmp);
            if std::fs::metadata(&path)
                .map(|m| m.len() as usize == EMBEDDED_DAEMON.len())
                .unwrap_or(false)
            {
                Some(path)
            } else {
                warn!("rename embedded daemon into place: {e}");
                None
            }
        }
    }
}

/// Probe the standard console port for an already-running machine-wide system
/// service (Option A). Returns its port iff /healthz identifies it as
/// service_mode "system" — the one daemon the shell attaches to. A dev/user
/// daemon or a foreign process on :7400 is deliberately NOT matched, so the shell
/// spawns its own instead (dev + pre-F3-installer behaviour). See
/// docs/runbook/privileged-service-and-updates-plan.md.
async fn discover_system_service() -> Option<u16> {
    let st = probe_healthz(PORT_START).await;
    if st.running && st.service_mode == "system" {
        Some(PORT_START)
    } else {
        None
    }
}

async fn probe_healthz(port: u16) -> DaemonStatus {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_millis(400))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let url = format!("http://127.0.0.1:{port}/healthz");
    match client.get(&url).send().await {
        Ok(resp) => {
            let code = resp.status();
            match resp.json::<serde_json::Value>().await {
                Ok(v) => DaemonStatus {
                    running: true,
                    healthy: code.is_success()
                        && v.get("state").and_then(|s| s.as_str()) == Some("connected"),
                    state: v
                        .get("state")
                        .and_then(|s| s.as_str())
                        .unwrap_or("unknown")
                        .into(),
                    version: v
                        .get("version")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .into(),
                    server_addr: v
                        .get("server_addr")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .into(),
                    service_mode: v
                        .get("service_mode")
                        .and_then(|s| s.as_str())
                        .unwrap_or("")
                        .into(),
                    attached: false,
                    error: None,
                },
                Err(e) => {
                    warn!("healthz body parse: {e}");
                    DaemonStatus {
                        running: true,
                        healthy: false,
                        state: "unparseable".into(),
                        error: Some(e.to_string()),
                        ..Default::default()
                    }
                }
            }
        }
        Err(_) => DaemonStatus::default(),
    }
}
