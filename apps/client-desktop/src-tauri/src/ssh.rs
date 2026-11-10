use std::{
    collections::HashMap,
    io::{Read, Write},
    net::Ipv4Addr,
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use serde::Deserialize;
use serde_json::{json, Value};
use tauri::{ipc::Response, Manager, State, WebviewWindow};
#[cfg(target_os = "macos")]
use tauri_plugin_clipboard_manager::ClipboardExt;
use tokio::{
    io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader},
    process::{Child, Command},
    sync::{mpsc, oneshot, Mutex as AsyncMutex},
};
use zeroize::Zeroizing;

use crate::{files::FileAgent, remote_workspace, ssh_auth};

#[path = "ssh_sftp.rs"]
mod sftp;

#[derive(Default)]
pub struct Windows {
    opening: AsyncMutex<()>,
    login_pid: AtomicU32,
    login_cancel: Mutex<Option<oneshot::Sender<()>>>,
    sessions: Mutex<HashMap<String, Arc<Session>>>,
}

#[derive(Clone, Deserialize, PartialEq, Eq)]
struct Target {
    profile: String,
    host_key: String,
    host: Ipv4Addr,
    local: Ipv4Addr,
}

struct Session {
    id: String,
    sequence: u64,
    peer: String,
    target: Target,
    account: String,
    port: u16,
    name: String,
    #[cfg(target_os = "macos")]
    locale: &'static str,
    url: reqwest::Url,
    password: Option<Zeroizing<String>>,
    connection: AsyncMutex<Option<Arc<Connection>>>,
    files: sftp::Transfers,
}

impl Session {
    fn matches(
        &self,
        target: &Target,
        peer: &str,
        account: Option<&str>,
        port: Option<u16>,
    ) -> bool {
        &self.target == target
            && self.peer == peer
            && account.is_none_or(|value| value == self.account)
            && port.is_none_or(|value| value == self.port)
    }
}

struct Connection {
    input: Arc<Mutex<Option<mpsc::Sender<String>>>>,
    output: AsyncMutex<mpsc::Receiver<Vec<u8>>>,
    master: Arc<Mutex<Option<Box<dyn MasterPty + Send>>>>,
    stopping: Arc<AtomicBool>,
    initial: Mutex<Vec<u8>>,
}

impl Connection {
    fn stop(&self) {
        self.stopping.store(true, Ordering::Release);
        self.input.lock().unwrap().take();
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        self.stop();
    }
}

pub(crate) fn supported() -> bool {
    login_helper().is_ok()
}

fn login_helper() -> Result<PathBuf, String> {
    crate::files::rdp_helper()
        .ok()
        .filter(|path| path.is_file())
        .ok_or_else(|| "sshNativeUnavailable".into())
}

#[cfg(windows)]
fn system_ssh() -> Result<PathBuf, String> {
    std::env::var_os("SystemRoot")
        .map(PathBuf::from)
        .map(|path| path.join("System32").join("OpenSSH").join("ssh.exe"))
        .filter(|path| path.is_absolute() && path.is_file())
        .ok_or_else(|| "sshClientMissing".into())
}

#[cfg(target_os = "macos")]
fn system_ssh() -> Result<PathBuf, String> {
    let path = PathBuf::from("/usr/bin/ssh");
    path.is_file()
        .then_some(path)
        .ok_or_else(|| "sshConnectFailed".into())
}

pub(super) fn is_host_confirmation(prompt: &str) -> bool {
    // Older OpenSSH releases can ask without setting SSH_ASKPASS_PROMPT.
    prompt.starts_with("The authenticity of host ")
        && (prompt.contains("key fingerprint is SHA256:")
            || prompt.contains("key fingerprint is: SHA256:"))
        && prompt
            .trim_end()
            .ends_with("Are you sure you want to continue connecting (yes/no/[fingerprint])?")
}

fn valid_account(account: &str) -> bool {
    !account.is_empty()
        && account.len() <= 128
        && !account.starts_with('-')
        && account.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'@' | b'$' | b'\\')
        })
}

fn mesh_address(ip: Ipv4Addr) -> bool {
    let [first, second, ..] = ip.octets();
    first == 100 && (64..128).contains(&second)
}

async fn resolve(agent: &FileAgent, peer: &str) -> Result<Target, String> {
    let reply = agent
        .call(json!({"action":"ssh_target","peer":peer}))
        .await?;
    let target: Target = serde_json::from_value(reply).map_err(|_| "sshTargetUnavailable")?;
    if target.host == target.local
        || !mesh_address(target.host)
        || !mesh_address(target.local)
        || [&target.profile, &target.host_key]
            .iter()
            .any(|key| key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()))
    {
        return Err("sshTargetUnavailable".into());
    }
    Ok(target)
}

struct Login {
    account: String,
    port: u16,
    remember: bool,
    use_saved: bool,
    password: Zeroizing<String>,
}

impl Login {
    fn parse(line: &str) -> Option<Self> {
        fn hex_text(value: &str, limit: usize) -> Option<String> {
            if value == "-" {
                return Some(String::new());
            }
            if value.len() > limit * 2 || value.len() % 2 != 0 {
                return None;
            }
            let bytes = value
                .as_bytes()
                .chunks_exact(2)
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
                .collect::<Option<Vec<_>>>()?;
            String::from_utf8(bytes).ok()
        }
        let mut fields = line.split_ascii_whitespace();
        if fields.next()? != "ssh-connect" {
            return None;
        }
        let account = hex_text(fields.next()?, 128)?;
        let port = fields.next()?.parse().ok()?;
        let flag = |value| match value {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        };
        let remember = flag(fields.next()?)?;
        let use_saved = flag(fields.next()?)?;
        let password = Zeroizing::new(hex_text(fields.next()?, ssh_auth::PASSWORD_LIMIT)?);
        if fields.next().is_some()
            || !valid_account(&account)
            || port == 0
            || password.contains(['\r', '\n', '\0'])
            || (use_saved && !password.is_empty())
        {
            return None;
        }
        Some(Self {
            account,
            port,
            remember,
            use_saved,
            password,
        })
    }
}

enum DialogOutcome {
    Closed,
    Connected(Option<String>),
}

fn existing_terminal(
    app: &tauri::AppHandle,
    target: &Target,
    peer: &str,
    account: Option<&str>,
    port: Option<u16>,
) -> Option<WebviewWindow> {
    let id = app.state::<Windows>()
        .sessions
        .lock()
        .unwrap()
        .values()
        .filter(|session| session.matches(target, peer, account, port))
        .max_by_key(|session| session.sequence)?
        .id.clone();
    let window = app.get_webview_window(remote_workspace::LABEL)?;
    remote_workspace::select(&window, &id).ok()?;
    Some(window)
}

fn show_terminal(terminal: &WebviewWindow) -> Result<(), String> {
    terminal
        .show()
        .and_then(|_| terminal.unminimize())
        .map_err(|error| error.to_string())?;
    let _ = terminal.set_focus();
    Ok(())
}

pub async fn open(
    window: &WebviewWindow,
    agent: &Arc<FileAgent>,
    url: reqwest::Url,
    action: Value,
) -> Result<Value, String> {
    let app = window.app_handle();
    let state = app.state::<Windows>();
    let Ok(_opening) = state.opening.try_lock() else {
        let pid = state.login_pid.load(Ordering::Acquire);
        if pid != 0 {
            crate::files::focus_rdp_window(pid);
        }
        return Ok(json!({}));
    };
    let (cancel, mut cancelled) = oneshot::channel();
    *state.login_cancel.lock().unwrap() = Some(cancel);
    let result = show_login(window, agent, url, action, &mut cancelled).await;
    state.login_pid.store(0, Ordering::Release);
    state.login_cancel.lock().unwrap().take();
    match result? {
        DialogOutcome::Closed => Ok(json!({})),
        DialogOutcome::Connected(warning) => Ok(json!({"warning":warning})),
    }
}

async fn show_login(
    window: &WebviewWindow,
    agent: &Arc<FileAgent>,
    url: reqwest::Url,
    action: Value,
    cancelled: &mut oneshot::Receiver<()>,
) -> Result<DialogOutcome, String> {
    let peer = action["peer"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or("sshTargetUnavailable")?;
    let target = resolve(agent, peer).await?;
    let app = window.app_handle();
    let selected_account = action["account"].as_str();
    let selected_port = action["port"]
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())
        .filter(|value| *value > 0);
    if let Some(terminal) = existing_terminal(app, &target, peer, selected_account, selected_port) {
        show_terminal(&terminal)?;
        return Ok(DialogOutcome::Connected(None));
    }
    system_ssh()?;
    let helper = login_helper()?;
    let name: String = action["name"]
        .as_str()
        .unwrap_or("Linux")
        .chars()
        .filter(|ch| !ch.is_control())
        .take(120)
        .collect();
    let history = if selected_account.is_some() {
        Value::Null
    } else {
        history(agent).await.unwrap_or(Value::Null)
    };
    let hint = history
        .as_array()
        .into_iter()
        .flatten()
        .find(|record| record["peer"] == peer);
    let account = selected_account
        .or_else(|| hint.and_then(|record| record["account"].as_str()))
        .filter(|value| valid_account(value))
        .unwrap_or("");
    let port = selected_port
        .or_else(|| {
            hint.and_then(|record| u16::try_from(record["port"].as_u64()?).ok())
                .filter(|value| *value > 0)
        })
        .unwrap_or(22);
    let mut command = Command::new(helper);
    command
        .arg("--ssh-login")
        .env("CALABI_P0_PEER", target.host.to_string())
        .env("CALABI_RDP_NAME", &name)
        .env("CALABI_RDP_CREDENTIAL_KEY", &target.host_key)
        .env("CALABI_RDP_ACCOUNT_HINT", account)
        .env("CALABI_SSH_PORT", port.to_string())
        .env("CALABI_SSH_PARENT_PID", std::process::id().to_string())
        .env("CALABI_UI_LOCALE", crate::tray_locale::code(app))
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true);
    if let Some(path) = crate::tray_locale::native_locale_path(app) {
        command.env("CALABI_UI_LOCALE_FILE", path);
    }
    let mut child = command.spawn().map_err(|_| "sshNativeUnavailable")?;
    let pid = child.id().ok_or("sshNativeUnavailable")?;
    let mut input = child.stdin.take().ok_or("sshNativeUnavailable")?;
    let mut output = BufReader::new(child.stdout.take().ok_or("sshNativeUnavailable")?);
    let mut ready = String::new();
    let mut ready_reader = (&mut output).take(64);
    tokio::select! {
        _ = &mut *cancelled => return Ok(DialogOutcome::Closed),
        result = tokio::time::timeout(Duration::from_secs(10), ready_reader.read_line(&mut ready)) => {
            if !matches!(result, Ok(Ok(_))) {
                return Err("sshNativeUnavailable".into());
            }
        }
    }
    let owner = ready
        .trim_end()
        .strip_prefix("ssh-ready ")
        .and_then(|handle| handle.parse().ok())
        .and_then(|handle| ssh_auth::PromptOwner::new(handle, pid))
        .ok_or("sshNativeUnavailable")?;
    app.state::<Windows>()
        .login_pid
        .store(pid, Ordering::Release);
    #[cfg(windows)]
    unsafe {
        windows_sys::Win32::UI::WindowsAndMessaging::AllowSetForegroundWindow(pid);
    }
    input
        .write_all(b"ssh-show\n")
        .await
        .map_err(|_| "sshNativeUnavailable")?;
    let mut login_display = None;
    loop {
        let mut line = Zeroizing::new(String::new());
        let mut request = (&mut output).take(4096);
        let count = tokio::select! {
            _ = &mut *cancelled => return Ok(DialogOutcome::Closed),
            result = request.read_line(&mut line) =>
                result.map_err(|_| "sshNativeUnavailable")?,
        };
        if count == 0 {
            return Ok(DialogOutcome::Closed);
        }
        if let Some(value) = line.trim_end().strip_prefix(remote_workspace::LOGIN_DISPLAY_PREFIX) {
            login_display = remote_workspace::LoginDisplay::parse(value);
            continue;
        }
        #[cfg(target_os = "macos")]
        if let Some(fields) = line.strip_prefix("ssh-clear ") {
            let request = Zeroizing::new(format!("ssh-connect {} 0 0 -", fields.trim_end()));
            let reply: &[u8] = match Login::parse(&request) {
                Some(login) => {
                    let key =
                        ssh_auth::credential_name(&target.host_key, login.port, &login.account);
                    match ssh_auth::clear_credential(&key) {
                        Ok(()) => b"cleared\n",
                        Err(_) => b"clear-failed\n",
                    }
                }
                None => b"invalid\n",
            };
            if input.write_all(reply).await.is_err() {
                return Ok(DialogOutcome::Closed);
            }
            continue;
        }
        let result = match Login::parse(&line) {
            Some(login) => {
                connect(
                    app,
                    agent,
                    url.clone(),
                    peer,
                    &name,
                    &target,
                    login,
                    login_display.take(),
                    owner,
                    &mut child,
                    cancelled,
                )
                .await
            }
            None => Err("sshInvalidLogin".into()),
        };
        let reply = match result {
            Ok((terminal, warning)) => {
                let _ = input.write_all(b"ok\n").await;
                let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
                show_terminal(&terminal)?;
                return Ok(DialogOutcome::Connected(warning));
            }
            Err(error) => match error.as_str() {
                "sshCancelled" => return Ok(DialogOutcome::Closed),
                "sshAuthFailed" => b"auth\n".as_slice(),
                "sshHostKeyChanged" => b"key-changed\n",
                "sshHostKeyRejected" => b"key-rejected\n",
                "sshCredentialMissing" | "sshCredentialFailed" => b"read-failed\n",
                "sshInvalidLogin" | "sshInvalidPassword" => b"invalid\n",
                "sshLoginTimeout" => b"timeout\n",
                _ => b"failed\n",
            },
        };
        if input.write_all(reply).await.is_err() {
            return Ok(DialogOutcome::Closed);
        }
    }
}

async fn connect(
    app: &tauri::AppHandle,
    agent: &Arc<FileAgent>,
    url: reqwest::Url,
    peer: &str,
    name: &str,
    expected: &Target,
    login: Login,
    login_display: Option<remote_workspace::LoginDisplay>,
    owner: ssh_auth::PromptOwner,
    child: &mut Child,
    cancelled: &mut oneshot::Receiver<()>,
) -> Result<(WebviewWindow, Option<String>), String> {
    let target = resolve(agent, peer).await?;
    if &target != expected {
        return Err("sshTargetChanged".into());
    }
    let Login {
        account,
        port,
        remember,
        use_saved,
        password,
    } = login;
    let state = app.state::<Windows>();
    if let Some(existing) = existing_terminal(app, &target, peer, Some(&account), Some(port)) {
        return Ok((existing, None));
    }
    let credential = ssh_auth::credential_name(&target.host_key, port, &account);
    let password = if use_saved {
        let saved = ssh_auth::read_credential(&credential)?;
        #[cfg(windows)]
        if saved.is_none() {
            return Err("sshCredentialMissing".into());
        }
        saved
    } else if password.is_empty() {
        None
    } else {
        Some(password)
    };
    let url = remote_workspace::url(url);
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
    let label = format!("ssh-session-{sequence}");
    let session = Arc::new(Session {
        id: label.clone(),
        sequence,
        peer: peer.to_owned(),
        target,
        account,
        port,
        name: name.to_owned(),
        #[cfg(target_os = "macos")]
        locale: crate::tray_locale::code(app),
        url: url.clone(),
        password,
        connection: AsyncMutex::new(None),
        files: sftp::Transfers::default(),
    });
    let initial_size = size(32, 100)?;
    let connection = tokio::select! {
        biased;
        _ = &mut *cancelled => return Err("sshCancelled".into()),
        _ = child.wait() => return Err("sshCancelled".into()),
        result = authenticate(&session, initial_size, owner) => result?,
    };
    if resolve(agent, peer).await? != session.target {
        return Err("sshTargetChanged".into());
    }
    if child
        .try_wait()
        .map_err(|error| error.to_string())?
        .is_some()
    {
        return Err("sshCancelled".into());
    }
    *session.connection.lock().await = Some(Arc::new(connection));
    state
        .sessions
        .lock()
        .unwrap()
        .insert(label.clone(), session.clone());
    let terminal = match remote_workspace::add(app, url, &label, &session.name, None, login_display).await {
        Ok(terminal) => terminal,
        Err(error) => {
            remove_session(&state, &label);
            return Err(error);
        }
    };
    let mut warning = None;
    if remember && !use_saved {
        if let Some(password) = &session.password {
            if let Err(error) = ssh_auth::save_credential(&credential, password) {
                warning = Some(error);
            }
        }
    }
    let record = agent
        .call(json!({
            "action":"ssh_record","peer":session.peer,"rdp_profile":session.target.profile,
            "rdp_name":session.name,"rdp_account":session.account,"ssh_port":session.port
        }))
        .await;
    if !matches!(record, Ok(ref reply) if reply.get("error").is_none()) && warning.is_none() {
        warning = Some("sshHistoryFailed".into());
    }
    Ok((terminal, warning))
}

pub async fn history(agent: &FileAgent) -> Result<Value, String> {
    let mut reply = agent.call(json!({"action":"ssh_history"})).await?;
    let records = reply["records"].as_array_mut().ok_or("sshHistoryFailed")?;
    Ok(json!(std::mem::take(records)))
}

pub async fn close_all(app: &tauri::AppHandle) {
    let state = app.state::<Windows>();
    if let Some(cancel) = state.login_cancel.lock().unwrap().take() {
        let _ = cancel.send(());
    }
    let _opening = state.opening.lock().await;
    let sessions: Vec<_> = state.sessions.lock().unwrap().drain().map(|(_, session)| session).collect();
    for session in sessions {
        session.files.close();
        if let Some(connection) = session.connection.lock().await.take() {
            connection.stop();
        }
    }
    if let Some(window) = app.get_webview_window(remote_workspace::LABEL) {
        let _ = window.destroy();
    }
}

pub(crate) fn remove_session(state: &Windows, id: &str) {
    if let Some(session) = state.sessions.lock().unwrap().remove(id) {
        session.files.close();
        tauri::async_runtime::spawn(async move {
            if let Some(connection) = session.connection.lock().await.take() {
                connection.stop();
            }
        });
    }
}

fn session_for(window: &WebviewWindow, state: &Windows, id: &str) -> Result<Arc<Session>, String> {
    let session = state
        .sessions
        .lock()
        .unwrap()
        .get(id)
        .cloned()
        .ok_or("Unknown SSH window")?;
    if window.label() != remote_workspace::LABEL || window.url().ok().as_ref() != Some(&session.url) {
        return Err("Untrusted SSH window origin".into());
    }
    Ok(session)
}

fn size(rows: u16, cols: u16) -> Result<PtySize, String> {
    if !(1..=500).contains(&rows) || !(2..=500).contains(&cols) {
        return Err("Invalid terminal size".into());
    }
    Ok(PtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    })
}

fn ssh_command(executable: PathBuf, session: &Session, terminal: bool) -> CommandBuilder {
    let mut command = CommandBuilder::new(executable);
    // Ignore SSH config routing overrides. The daemon resolves the target
    // device and OpenSSH binds the connection to the current mesh address.
    let alias = format!(
        "HostKeyAlias=calabi-{}-{}",
        session.target.host_key, session.port
    );
    command.args([
        "-F",
        "none",
        "-4",
        if terminal { "-t" } else { "-T" },
        "-b",
        &session.target.local.to_string(),
        "-l",
        &session.account,
        "-p",
        &session.port.to_string(),
        "-o",
        &alias,
        "-o",
        if terminal {
            "StrictHostKeyChecking=ask"
        } else {
            "StrictHostKeyChecking=yes"
        },
        "-o",
        "ConnectTimeout=10",
        "-o",
        "ServerAliveInterval=15",
    ]);
    command.env("TERM", "xterm-256color");
    #[cfg(target_os = "macos")]
    command.env("CALABI_UI_LOCALE", session.locale);
    command
}

async fn authenticate(
    session: &Session,
    size: PtySize,
    owner: ssh_auth::PromptOwner,
) -> Result<Connection, String> {
    let helper = std::env::current_exe().map_err(|error| error.to_string())?;
    authenticate_command(
        ssh_command(system_ssh()?, session, true),
        session.password.as_ref().map(|p| p.as_str()),
        session.target.host,
        size,
        &helper,
        Some(owner),
    )
    .await
}

async fn authenticate_command(
    mut command: CommandBuilder,
    password: Option<&str>,
    host: Ipv4Addr,
    size: PtySize,
    helper: &std::path::Path,
    owner: Option<ssh_auth::PromptOwner>,
) -> Result<Connection, String> {
    let attempt = ssh_auth::Attempt::configure(&mut command, password, helper, owner)?;
    command.args([
        "-o",
        "PermitLocalCommand=yes",
        "-o",
        &format!("LocalCommand=echo {}", attempt.marker),
    ]);
    command.arg(host.to_string());
    let connection = spawn_terminal(command, size)?;
    let mut output = connection.output.lock().await;
    let input = connection
        .input
        .lock()
        .unwrap()
        .clone()
        .ok_or("sshConnectFailed")?;
    let mut bytes = Vec::new();
    let marker = attempt.marker.as_bytes();
    let mut cursor_reported = false;
    let result = tokio::time::timeout(Duration::from_secs(90), async {
        while let Some(chunk) = output.recv().await {
            bytes.extend(chunk);
            if !cursor_reported && bytes.windows(4).any(|part| part == b"\x1b[6n") {
                input
                    .send("\x1b[1;1R".into())
                    .await
                    .map_err(|_| "sshConnectFailed")?;
                cursor_reported = true;
            }
            if let Some(at) = bytes.windows(marker.len()).position(|part| part == marker) {
                let rest = &bytes[at + marker.len()..];
                *connection.initial.lock().unwrap() = rest
                    .iter()
                    .copied()
                    .skip_while(|b| matches!(b, b'\r' | b'\n'))
                    .collect();
                return Ok(());
            }
            if bytes.len() > 65536 {
                bytes.drain(..bytes.len() - 32768);
            }
        }
        let diagnostic = String::from_utf8_lossy(&bytes);
        Err(if diagnostic.contains("Permission denied") {
            "sshAuthFailed"
        } else if diagnostic.contains("REMOTE HOST IDENTIFICATION HAS CHANGED") {
            "sshHostKeyChanged"
        } else if diagnostic.contains("Host key verification failed") {
            "sshHostKeyRejected"
        } else {
            "sshConnectFailed"
        })
    })
    .await
    .map_err(|_| "sshLoginTimeout")?;
    result?;
    drop(output);
    Ok(connection)
}

fn spawn_terminal(command: CommandBuilder, size: PtySize) -> Result<Connection, String> {
    let pair = native_pty_system()
        .openpty(size)
        .map_err(|e| e.to_string())?;
    let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
    let mut writer = pair.master.take_writer().map_err(|e| e.to_string())?;
    let mut child = pair
        .slave
        .spawn_command(command)
        .map_err(|e| e.to_string())?;
    drop(pair.slave);
    let master = Arc::new(Mutex::new(Some(pair.master)));
    let stopping = Arc::new(AtomicBool::new(false));
    let (output, recv) = mpsc::channel(8);
    let (input, mut keys) = mpsc::channel::<String>(8);
    let input = Arc::new(Mutex::new(Some(input)));

    thread::spawn(move || {
        let mut buffer = [0; 8192];
        while let Ok(count) = reader.read(&mut buffer) {
            if count == 0 {
                break;
            }
            // Drain the ConPTY pipe even when the WebView has closed.
            let _ = output.blocking_send(buffer[..count].to_vec());
        }
    });
    thread::spawn(move || {
        while let Some(data) = keys.blocking_recv() {
            if writer.write_all(data.as_bytes()).is_err() {
                break;
            }
        }
    });
    let worker_master = master.clone();
    let worker_stop = stopping.clone();
    let worker_input = input.clone();
    thread::spawn(move || {
        while !worker_stop.load(Ordering::Acquire) {
            match child.try_wait() {
                Ok(None) => thread::sleep(Duration::from_millis(75)),
                _ => break,
            }
        }
        if !matches!(child.try_wait(), Ok(Some(_))) {
            let _ = child.kill();
            let _ = child.wait();
        }
        worker_input.lock().unwrap().take();
        let pty = worker_master.lock().unwrap().take();
        drop(pty);
    });
    Ok(Connection {
        input,
        output: AsyncMutex::new(recv),
        master,
        stopping,
        initial: Mutex::new(Vec::new()),
    })
}

#[derive(Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Info,
    Start {
        rows: u16,
        cols: u16,
    },
    Resize {
        rows: u16,
        cols: u16,
    },
    Input {
        data: String,
    },
    #[cfg(target_os = "macos")]
    ClipboardRead,
    #[cfg(target_os = "macos")]
    ClipboardWrite {
        text: String,
    },
    Files {
        action: sftp::Action,
    },
}

#[tauri::command]
pub async fn ssh_session(
    window: WebviewWindow,
    state: State<'_, Windows>,
    agent: State<'_, Arc<FileAgent>>,
    session_id: String,
    request: Request,
) -> Result<Value, String> {
    let session = session_for(&window, &state, &session_id)?;
    match request {
        Request::Files { action } => sftp::dispatch(&window, &agent, &session, action).await,
        Request::Info => Ok(json!({
            "name":session.name, "host":session.target.host, "port":session.port, "account":session.account,
            "native_clipboard": cfg!(target_os = "macos"),
        })),
        #[cfg(target_os = "macos")]
        Request::ClipboardRead => {
            if !remote_workspace::active(&window, &session_id) || !window.is_focused().unwrap_or(false) {
                return Err("Clipboard requires the focused SSH window".into());
            }
            let text = window
                .clipboard()
                .read_text()
                .map_err(|_| "Clipboard unavailable")?;
            if text.len() > 2 * 1024 * 1024 {
                return Err("Clipboard text is too large".into());
            }
            Ok(json!(text))
        }
        #[cfg(target_os = "macos")]
        Request::ClipboardWrite { text } => {
            if !remote_workspace::active(&window, &session_id) || !window.is_focused().unwrap_or(false) {
                return Err("Clipboard requires the focused SSH window".into());
            }
            if text.len() > 2 * 1024 * 1024 {
                return Err("Clipboard text is too large".into());
            }
            window
                .clipboard()
                .write_text(text)
                .map_err(|_| "Clipboard unavailable")?;
            Ok(Value::Null)
        }
        Request::Start { rows, cols } => {
            let size = size(rows, cols)?;
            let mut connection = session.connection.lock().await;
            if connection.is_none() {
                if resolve(&agent, &session.peer).await? != session.target {
                    return Err("sshTargetChanged".into());
                }
                session_for(&window, &state, &session_id)?;
                #[cfg(windows)]
                let handle = window.hwnd().map_err(|_| "sshConnectFailed")?.0 as usize;
                #[cfg(target_os = "macos")]
                let handle = 0;
                let owner = ssh_auth::PromptOwner::new(handle, std::process::id())
                    .ok_or("sshConnectFailed")?;
                *connection = Some(Arc::new(authenticate(&session, size, owner).await?));
            }
            Ok(Value::Null)
        }
        Request::Resize { rows, cols } => {
            let size = size(rows, cols)?;
            let master = session
                .connection
                .lock()
                .await
                .as_ref()
                .map(|c| c.master.clone());
            if let Some(master) = master {
                tauri::async_runtime::spawn_blocking(move || {
                    if let Some(pty) = master.lock().unwrap().as_ref() {
                        pty.resize(size).map_err(|e| e.to_string())?;
                    }
                    Ok::<_, String>(())
                })
                .await
                .map_err(|e| e.to_string())??;
            }
            Ok(Value::Null)
        }
        Request::Input { data } => {
            if !remote_workspace::active(&window, &session_id) {
                return Ok(Value::Null);
            }
            if data.len() > 64 * 1024 {
                return Err("Terminal input is too large".into());
            }
            let input = session
                .connection
                .lock()
                .await
                .as_ref()
                .and_then(|c| c.input.lock().unwrap().clone());
            if let Some(input) = input {
                input.send(data).await.map_err(|_| "SSH session ended")?;
            }
            Ok(Value::Null)
        }
    }
}

#[tauri::command]
pub async fn ssh_read(
    window: WebviewWindow,
    state: State<'_, Windows>,
    session_id: String,
) -> Result<Response, String> {
    let session = session_for(&window, &state, &session_id)?;
    let Some(connection) = session.connection.lock().await.clone() else {
        return Ok(Response::new(Vec::<u8>::new()));
    };
    let initial = std::mem::take(&mut *connection.initial.lock().unwrap());
    if !initial.is_empty() {
        return Ok(Response::new(initial));
    }
    let data = connection.output.lock().await.recv().await;
    if data.is_none() {
        let mut active = session.connection.lock().await;
        if active
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, &connection))
        {
            active.take();
            session.files.interrupt();
        }
    }
    Ok(Response::new(data.unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn account_and_endpoint_are_passed_as_distinct_ssh_arguments() {
        for invalid in ["", "-oProxyCommand=bad", "a b", "a\nb", "a%h", "a&b"] {
            assert!(!valid_account(invalid), "{invalid:?}");
        }
        assert!(valid_account("user@realm"));
        let session = Session {
            id: "ssh-session-test".into(),
            sequence: 0,
            peer: "peer".into(),
            target: Target {
                profile: "a".repeat(64),
                host_key: "b".repeat(64),
                host: "100.64.0.2".parse().unwrap(),
                local: "100.64.0.1".parse().unwrap(),
            },
            account: "user@realm".into(),
            port: 2222,
            name: "Linux".into(),
            #[cfg(target_os = "macos")]
            locale: "en",
            url: "http://127.0.0.1:7400/#/ssh-session".parse().unwrap(),
            password: None,
            connection: AsyncMutex::new(None),
            files: sftp::Transfers::default(),
        };
        assert!(session.matches(&session.target, "peer", None, None));
        assert!(session.matches(&session.target, "peer", Some("user@realm"), Some(2222)));
        assert!(!session.matches(&session.target, "peer", Some("another-account"), None));
        assert!(!session.matches(&session.target, "peer", None, Some(22)));
        assert!(!session.matches(&session.target, "other-peer", None, None));
        let mut another_scope = session.target.clone();
        another_scope.profile = "c".repeat(64);
        assert!(!session.matches(&another_scope, "peer", None, None));
        let command = ssh_command(PathBuf::from("ssh.exe"), &session, true);
        let argv = command.get_argv();
        assert_eq!(
            &argv[1..11],
            [
                "-F",
                "none",
                "-4",
                "-t",
                "-b",
                "100.64.0.1",
                "-l",
                "user@realm",
                "-p",
                "2222"
            ]
        );
        assert!(argv.iter().any(|arg| arg == "StrictHostKeyChecking=ask"));
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn conpty_forwards_input_and_drains_after_close() {
        let mut command = CommandBuilder::new(std::env::var_os("ComSpec").unwrap());
        command.args(["/D", "/Q", "/E:ON"]);
        let connection = spawn_terminal(command, size(24, 80).unwrap()).unwrap();
        let mut output = connection.output.lock().await;
        let mut bytes = Vec::new();
        let input = connection.input.lock().unwrap().clone().unwrap();
        let mut reported_cursor = false;
        let ready = tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(chunk) = output.recv().await {
                bytes.extend(chunk);
                if !reported_cursor && bytes.windows(4).any(|part| part == b"\x1b[6n") {
                    input.send("\x1b[1;1R".into()).await.unwrap();
                    reported_cursor = true;
                }
                if bytes.contains(&b'>') {
                    return true;
                }
            }
            false
        })
        .await;
        assert_eq!(
            ready,
            Ok(true),
            "cmd.exe output: {:?}",
            String::from_utf8_lossy(&bytes)
        );
        input
            .send("echo CALABI_%COMSPEC:~-7%\r".into())
            .await
            .unwrap();
        bytes.clear();
        let echo = tokio::time::timeout(Duration::from_secs(10), async {
            while let Some(chunk) = output.recv().await {
                bytes.extend(chunk);
                if String::from_utf8_lossy(&bytes)
                    .to_ascii_lowercase()
                    .contains("calabi_cmd.exe")
                {
                    return true;
                }
            }
            false
        })
        .await;
        assert_eq!(
            echo,
            Ok(true),
            "cmd.exe output: {:?}",
            String::from_utf8_lossy(&bytes)
        );
        drop(input);
        connection.stop();
        tokio::time::timeout(Duration::from_secs(5), async {
            while output.recv().await.is_some() {}
        })
        .await
        .expect("ConPTY pipe stayed open after close");
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn conpty_can_close_before_the_window_answers_the_cursor_query() {
        let command = CommandBuilder::new(std::env::var_os("ComSpec").unwrap());
        let connection = spawn_terminal(command, size(24, 80).unwrap()).unwrap();
        connection.stop();
        let mut output = connection.output.lock().await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while output.recv().await.is_some() {}
        })
        .await
        .expect("ConPTY pipe stayed open before cursor reply");
    }

    #[tokio::test]
    #[ignore = "requires the local SSH fixture and a built Calabi desktop executable"]
    async fn windows_openssh_password_login_fixture() {
        let port = std::env::var("CALABI_SSH_TEST_PORT").unwrap();
        let hosts = std::env::var("CALABI_SSH_TEST_KNOWN_HOSTS").unwrap();
        let helper = PathBuf::from(std::env::var_os("CALABI_SSH_TEST_DESKTOP").unwrap());
        let command = || {
            let mut command = CommandBuilder::new(system_ssh().unwrap());
            command.args([
                "-F",
                "none",
                "-t",
                "-l",
                "password-fixture",
                "-p",
                &port,
                "-o",
                &format!("UserKnownHostsFile=\"{hosts}\""),
                "-o",
                "StrictHostKeyChecking=yes",
            ]);
            command
        };
        let rejected = authenticate_command(
            command(),
            Some("fixture-incorrect"),
            Ipv4Addr::LOCALHOST,
            size(32, 100).unwrap(),
            &helper,
            None,
        )
        .await;
        assert_eq!(rejected.err().as_deref(), Some("sshAuthFailed"));
        let session = authenticate_command(
            command(),
            Some("calabi-fixture-only"),
            Ipv4Addr::LOCALHOST,
            size(32, 100).unwrap(),
            &helper,
            None,
        )
        .await
        .unwrap();
        let mut buffer = std::mem::take(&mut *session.initial.lock().unwrap());
        let mut output = session.output.lock().await;
        tokio::time::timeout(Duration::from_secs(5), async {
            while let Some(data) = output.recv().await {
                buffer.extend(data);
            }
        })
        .await
        .unwrap();
        assert!(String::from_utf8_lossy(&buffer).contains("CALABI_SSH_FIXTURE_SHELL"));

        let name =
            ssh_auth::credential_name(&uuid::Uuid::new_v4().simple().to_string(), 22, "fixture");
        struct DeleteCredential(String);
        impl Drop for DeleteCredential {
            fn drop(&mut self) {
                let _ = ssh_auth::clear_credential(&self.0);
            }
        }
        let guard = DeleteCredential(name);
        assert!(ssh_auth::read_credential(&guard.0).unwrap().is_none());
        ssh_auth::save_credential(&guard.0, "calabi-fixture-only").unwrap();
        assert_eq!(
            ssh_auth::read_credential(&guard.0)
                .unwrap()
                .unwrap()
                .as_str(),
            "calabi-fixture-only"
        );
        ssh_auth::clear_credential(&guard.0).unwrap();
        assert!(ssh_auth::read_credential(&guard.0).unwrap().is_none());
    }
}
