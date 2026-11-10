use std::{
    collections::{HashSet, VecDeque},
    future::Future,
    io,
    path::{Path, PathBuf},
    process::Stdio,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use futures_util::{pin_mut, stream, StreamExt};
use openssh_sftp_client::{
    error::SftpErrorKind,
    file::TokioCompatFile,
    fs::Fs,
    metadata::{MetaData, MetaDataBuilder, Permissions},
    Error, Sftp,
};
use portable_pty::CommandBuilder;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tauri::WebviewWindow;
use tauri_plugin_dialog::{DialogExt, FilePath, MessageDialogButtons, MessageDialogKind};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    process::{Child, Command},
    sync::oneshot,
};
use tokio_util::sync::CancellationToken;
#[cfg(windows)]
use windows_sys::Win32::Foundation::{
    ERROR_DISK_FULL, ERROR_HANDLE_DISK_FULL, ERROR_LOCK_VIOLATION, ERROR_SHARING_VIOLATION,
};

use super::{resolve, session_for, ssh_auth, ssh_command, system_ssh, FileAgent, Session, Windows};
use tauri::Manager;

const TIMEOUT: Duration = Duration::from_secs(25);
const LIST_LIMIT: usize = 2000;
const USER_CANCELLED: u8 = 1;
const SESSION_INTERRUPTED: u8 = 2;

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Action {
    List {
        path: Option<String>,
    },
    Upload {
        dir: String,
        confirm: Confirmation,
        #[serde(default)]
        detailed: bool,
    },
    Download {
        #[serde(alias = "path")]
        paths: DownloadPaths,
        confirm: Confirmation,
        #[serde(default)]
        detailed: bool,
    },
    Delete {
        dir: String,
        names: Vec<String>,
        confirm: Confirmation,
    },
    Progress,
    Cancel,
}

#[derive(Deserialize)]
#[serde(untagged)]
pub enum DownloadPaths {
    Multiple(Vec<String>),
    Single(String),
}

#[derive(Deserialize)]
pub struct Confirmation {
    title: String,
    message: String,
    replace: String,
    cancel: String,
    skip: Option<String>,
}

#[derive(Default)]
pub(super) struct Transfers {
    closed: CancellationToken,
    active: Mutex<Option<Arc<Job>>>,
    pending_parts: Mutex<VecDeque<PendingPart>>,
}

struct Job {
    cancel: CancellationToken,
    reason: AtomicU8,
    progress: Mutex<TransferProgress>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum FileState {
    Pending,
    Transferring,
    Completed,
    Skipped,
    Cancelled,
    Failed,
}

#[derive(Clone, Serialize)]
struct TransferFile {
    name: String,
    done: u64,
    total: Option<u64>,
    state: FileState,
}

#[derive(Clone, Default, Serialize)]
struct TransferProgress {
    files: Vec<TransferFile>,
    current: Option<usize>,
}

impl TransferProgress {
    fn current_file(&mut self) -> Option<&mut TransferFile> {
        self.current.map(|index| &mut self.files[index])
    }

    fn snapshot(&self) -> Value {
        let current = self.current.map(|index| (index, &self.files[index]));
        json!({
            "done": current.map_or(0, |(_, file)| file.done),
            "total": current.and_then(|(_, file)| file.total).unwrap_or_default(),
            "file": current.map(|(index, file)| json!({"name": file.name, "index": index + 1, "count": self.files.len()})),
            "transfer": self,
        })
    }
}

#[derive(Serialize)]
struct BatchResult {
    count: usize,
    completed: usize,
    skipped: usize,
    error: Option<String>,
    failed_file: Option<String>,
    transfer: TransferProgress,
}

impl BatchResult {
    fn response(self, detailed: bool) -> Result<Value, String> {
        if !detailed && self.count == 1 {
            if let Some(error) = self.error {
                return Err(error);
            }
        }
        Ok(json!(self))
    }
}

#[derive(Clone)]
struct PendingPart {
    path: String,
    uid: u32,
    gid: u32,
    permissions: Permissions,
}

impl PendingPart {
    fn verified(path: String, metadata: MetaData) -> Option<Self> {
        Some(Self {
            path,
            uid: metadata.uid()?,
            gid: metadata.gid()?,
            permissions: metadata.permissions()?,
        })
    }

    async fn inspect(
        path: &str,
        metadata: impl Future<Output = Result<MetaData, Error>>,
    ) -> Option<Self> {
        let metadata = tokio::time::timeout(Duration::from_secs(2), metadata)
            .await
            .ok()?
            .ok()?;
        Self::verified(path.to_owned(), metadata)
    }

    fn matches(&self, metadata: MetaData) -> bool {
        metadata.file_type().is_some_and(|kind| kind.is_file())
            && metadata.uid() == Some(self.uid)
            && metadata.gid() == Some(self.gid)
            && metadata.permissions() == Some(self.permissions)
    }
}

struct Running<'a> {
    state: &'a Transfers,
    job: Arc<Job>,
}

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.state.active.lock().unwrap().take();
    }
}

impl Transfers {
    fn begin(&self) -> Result<Running<'_>, String> {
        let mut active = self.active.lock().unwrap();
        if active.is_some() {
            return Err("sftpBusy".into());
        }
        let job = Arc::new(Job {
            cancel: self.closed.child_token(),
            reason: AtomicU8::new(0),
            progress: Mutex::new(TransferProgress::default()),
        });
        job.check()?;
        *active = Some(job.clone());
        Ok(Running { state: self, job })
    }

    pub(super) fn close(&self) {
        self.closed.cancel();
    }

    pub(super) fn cancel(&self) {
        self.stop(USER_CANCELLED);
    }

    pub(super) fn interrupt(&self) {
        self.stop(SESSION_INTERRUPTED);
    }

    fn stop(&self, reason: u8) {
        if let Some(job) = self.active.lock().unwrap().as_ref() {
            let _ = job
                .reason
                .compare_exchange(0, reason, Ordering::AcqRel, Ordering::Acquire);
            job.cancel.cancel();
        }
    }

    fn remember_part(&self, part: PendingPart) {
        let mut parts = self.pending_parts.lock().unwrap();
        if parts.len() == 8 {
            parts.pop_front();
        }
        parts.push_back(part);
    }

    async fn remove_pending_parts(&self, sftp: &Sftp) {
        let mut fs = sftp.fs();
        let _ = tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                let Some(part) = self.pending_parts.lock().unwrap().front().cloned() else {
                    break;
                };
                match fs.symlink_metadata(&part.path).await {
                    Ok(metadata) if part.matches(metadata) => {
                        if fs.remove_file(&part.path).await.is_err() {
                            break;
                        }
                    }
                    Ok(_) | Err(Error::SftpError(SftpErrorKind::NoSuchFile, _)) => {}
                    Err(_) => break,
                }
                self.pending_parts.lock().unwrap().pop_front();
            }
        })
        .await;
    }
}

impl Job {
    fn set_total(&self, total: u64) {
        if let Some(file) = self.progress.lock().unwrap().current_file() {
            file.total = Some(total);
        }
    }

    fn set_done(&self, done: u64) {
        if let Some(file) = self.progress.lock().unwrap().current_file() {
            file.done = done;
        }
    }

    fn stop_error(&self) -> String {
        if self.reason.load(Ordering::Acquire) == SESSION_INTERRUPTED {
            "sftpInterrupted"
        } else {
            "sftpCancelled"
        }
        .into()
    }

    fn check(&self) -> Result<(), String> {
        if self.cancel.is_cancelled() {
            return Err(self.stop_error());
        }
        Ok(())
    }

    async fn wait<T>(&self, future: impl Future<Output = T>) -> Result<T, String> {
        tokio::select! {
            biased;
            _ = self.cancel.cancelled() => Err(self.stop_error()),
            result = tokio::time::timeout(TIMEOUT, future) => result.map_err(|_| "sftpTimeout".into()),
        }
    }

    async fn remote<T>(
        &self,
        future: impl Future<Output = Result<T, Error>>,
        fallback: &'static str,
    ) -> Result<T, String> {
        self.wait(future)
            .await?
            .map_err(|error| remote_error(&error, fallback).into())
    }
}

fn network_error(error: &io::Error) -> Option<&'static str> {
    use io::ErrorKind::*;
    match error.kind() {
        BrokenPipe | UnexpectedEof | ConnectionAborted | ConnectionReset | NotConnected
        | NetworkDown | NetworkUnreachable | HostUnreachable => Some("sftpInterrupted"),
        TimedOut => Some("sftpTimeout"),
        _ => None,
    }
}

fn remote_status(kind: SftpErrorKind, message: &str, fallback: &'static str) -> &'static str {
    match kind {
        SftpErrorKind::PermDenied if fallback == "sftpRemoteWrite" => "sftpRemoteWriteDenied",
        SftpErrorKind::PermDenied => "sftpPermission",
        SftpErrorKind::NoSuchFile => "sftpMissing",
        SftpErrorKind::OpUnsupported => "sftpUnsupported",
        _ if [
            "no space left on device",
            "disk quota exceeded",
            "disk full",
        ]
        .iter()
        .any(|text| message.trim().eq_ignore_ascii_case(text)) =>
        {
            "sftpRemoteSpace"
        }
        _ => fallback,
    }
}

fn remote_error(error: &Error, fallback: &'static str) -> &'static str {
    match error {
        Error::SftpError(kind, message) => remote_status(*kind, message.get().0, fallback),
        Error::UnsupportedExtension(_) => "sftpUnsupported",
        Error::IOError(error) => network_error(error).unwrap_or(fallback),
        Error::BackgroundTaskFailure(_) => "sftpInterrupted",
        _ => fallback,
    }
}

fn local_error(error: &io::Error, fallback: &'static str) -> &'static str {
    #[cfg(windows)]
    match error.raw_os_error().map(|code| code as u32) {
        Some(ERROR_HANDLE_DISK_FULL | ERROR_DISK_FULL) => return "sftpLocalSpace",
        Some(ERROR_SHARING_VIOLATION | ERROR_LOCK_VIOLATION) => return "sftpLocalBusy",
        _ => {}
    }
    match error.kind() {
        io::ErrorKind::StorageFull => "sftpLocalSpace",
        io::ErrorKind::NotFound if fallback == "sftpLocalRead" => "sftpSourceChanged",
        _ => fallback,
    }
}

fn remote_read_error(error: &io::Error, fallback: &'static str) -> &'static str {
    if let Some(error) = error
        .get_ref()
        .and_then(|error| error.downcast_ref::<Error>())
    {
        return remote_error(error, fallback);
    }
    network_error(error).unwrap_or(fallback)
}

struct Channel {
    sftp: Sftp,
    _process: Child,
}

impl Channel {
    async fn open(job: &Job, session: &Session) -> Result<Self, String> {
        let helper = std::env::current_exe().map_err(|_| "sftpConnect")?;
        let builder = ssh_command(system_ssh()?, session, false);
        let channel = Self::open_command(
            job,
            builder,
            session.password.as_deref().map(String::as_str),
            &helper,
            session.target.host,
        )
        .await?;
        session.files.remove_pending_parts(&channel.sftp).await;
        job.check()?;
        Ok(channel)
    }

    async fn open_command(
        job: &Job,
        mut builder: CommandBuilder,
        password: Option<&str>,
        helper: &Path,
        host: std::net::Ipv4Addr,
    ) -> Result<Self, String> {
        let _askpass = ssh_auth::Attempt::configure(&mut builder, password, helper, None)?;
        builder.args(["-s", &host.to_string(), "sftp"]);
        let args = builder.get_argv();
        let mut command = Command::new(&args[0]);
        #[cfg(windows)]
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW
        let mut process = command
            .args(&args[1..])
            .envs(builder.iter_extra_env_as_str())
            .env_remove(ssh_auth::OWNER_ENV)
            .env_remove("SSH_ASKPASS_PROMPT")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .spawn()
            .map_err(|_| "sftpConnect")?;
        let input = process.stdin.take().ok_or("sftpConnect")?;
        let output = process.stdout.take().ok_or("sftpConnect")?;
        let diagnostic = process.stderr.take().ok_or("sftpConnect")?;
        let stderr = tokio::spawn(async move {
            let mut text = Vec::new();
            let _ = diagnostic.take(8192).read_to_end(&mut text).await;
            text
        });
        match job
            .wait(Sftp::new(input, output, Default::default()))
            .await?
        {
            Ok(sftp) => Ok(Self {
                sftp,
                _process: process,
            }),
            Err(_) => {
                let text = tokio::time::timeout(Duration::from_millis(500), stderr)
                    .await
                    .ok()
                    .and_then(Result::ok)
                    .unwrap_or_default();
                let text = String::from_utf8_lossy(&text);
                Err(if text.contains("REMOTE HOST IDENTIFICATION HAS CHANGED") {
                    "sshHostKeyChanged"
                } else if text.contains("Host key verification failed") {
                    "sshHostKeyRejected"
                } else if text.contains("Permission denied") {
                    "sshAuthFailed"
                } else if text.contains("subsystem request failed") {
                    "sftpUnavailable"
                } else {
                    "sftpConnect"
                }
                .into())
            }
        }
    }
}

fn name_is_valid(name: &str) -> bool {
    !name.is_empty()
        && !matches!(name, "." | "..")
        && !name.contains(['/', '\\'])
        && !name.chars().any(char::is_control)
}

fn remote_path(path: &str) -> Result<&str, String> {
    if path == "/"
        || (path.len() <= 4096 && path.starts_with('/') && path[1..].split('/').all(name_is_valid))
    {
        return Ok(path);
    }
    Err("sftpInvalidPath".into())
}

fn join(dir: &str, name: &str) -> String {
    format!("{}/{}", dir.trim_end_matches('/'), name)
}

fn validate_delete(dir: &str, names: &[String]) -> Result<(), String> {
    remote_path(dir)?;
    let mut unique = HashSet::new();
    if names.is_empty()
        || names.len() > LIST_LIMIT
        || !names
            .iter()
            .all(|name| name_is_valid(name) && join(dir, name).len() <= 4096 && unique.insert(name))
    {
        return Err("sftpInvalidPath".into());
    }
    Ok(())
}

async fn list(job: &Job, sftp: &Sftp, path: Option<&str>) -> Result<Value, String> {
    let mut fs = sftp.fs();
    let directory = job
        .remote(
            fs.canonicalize(path.map(remote_path).transpose()?.unwrap_or(".")),
            "sftpRemoteList",
        )
        .await?;
    let dir = remote_path(directory.to_str().ok_or("sftpInvalidPath")?)?;
    let stream = job
        .remote(fs.open_dir(dir), "sftpRemoteList")
        .await?
        .read_dir();
    pin_mut!(stream);
    let mut entries = Vec::new();
    let mut partial = false;
    while let Some(entry) = job.wait(stream.next()).await? {
        let entry = entry.map_err(|error| remote_error(&error, "sftpRemoteList"))?;
        let Some(name) = entry.filename().to_str() else {
            partial = true;
            continue;
        };
        if matches!(name, "." | "..") {
            continue;
        }
        if !name_is_valid(name) || dir.len() + name.len() + 1 > 4096 {
            partial = true;
            continue;
        }
        if entries.len() == LIST_LIMIT {
            partial = true;
            break;
        }
        let kind = match entry.file_type() {
            Some(kind) if kind.is_dir() => "directory",
            Some(kind) if kind.is_file() => "file",
            _ => "other",
        };
        entries.push(json!({"name":name, "kind":kind, "size":entry.metadata().len()}));
    }
    Ok(json!({"path":dir, "entries":entries, "partial":partial}))
}

async fn pick(window: &WebviewWindow, job: &Job, folder: bool) -> Result<Vec<PathBuf>, String> {
    let (send, receive) = oneshot::channel();
    let dialog = window.dialog().file().set_parent(window);
    if folder {
        dialog.pick_folder(move |value| {
            let _ = send.send(value.map(|path| vec![path]));
        });
    } else {
        dialog.pick_files(move |value: Option<Vec<FilePath>>| {
            let _ = send.send(value);
        });
    }
    let result = tokio::select! {
        _ = job.cancel.cancelled() => return Err(job.stop_error()),
        result = receive => result.map_err(|_| "sftpLocal")?,
    };
    result
        .ok_or("sftpCancelled")?
        .into_iter()
        .map(|path| path.into_path().map_err(|_| "sftpLocal".into()))
        .collect()
}

async fn confirm(
    window: &WebviewWindow,
    job: &Job,
    labels: &Confirmation,
    multiple: bool,
    destination: &str,
) -> Result<(), String> {
    job.check()?;
    let skip = labels.skip.as_deref().filter(|_| multiple);
    let decline = skip.unwrap_or(&labels.cancel);
    if [&labels.title, &labels.message, &labels.replace, decline]
        .iter()
        .any(|s| s.len() > 512)
    {
        return Err("sftpFailed".into());
    }
    let (send, receive) = oneshot::channel();
    window
        .dialog()
        .message(format!("{}\n\n{destination}", labels.message))
        .parent(window)
        .title(&labels.title)
        .kind(MessageDialogKind::Warning)
        .buttons(MessageDialogButtons::OkCancelCustom(
            labels.replace.clone(),
            decline.to_owned(),
        ))
        .show(move |confirmed| {
            let _ = send.send(confirmed);
        });
    tokio::select! {
        biased;
        _ = job.cancel.cancelled() => Err(job.stop_error()),
        result = receive => match result {
            Ok(true) => Ok(()),
            Ok(false) if skip.is_some() => Err("sftpSkipped".into()),
            _ => Err("sftpCancelled".into()),
        }
    }
}

async fn transfer_batch<T: Clone, P, F>(
    job: &Job,
    files: Vec<(String, T)>,
    mut size: impl FnMut(T) -> P,
    mut transfer: impl FnMut(T, bool) -> F,
) -> BatchResult
where
    P: Future<Output = Option<u64>>,
    F: Future<Output = Result<(), String>>,
{
    let count = files.len();
    job.progress.lock().unwrap().files = files
        .iter()
        .map(|(name, _)| TransferFile {
            name: name.clone(),
            done: 0,
            total: None,
            state: FileState::Pending,
        })
        .collect();
    // File sizes are only used for display. Keep the normal transfer checks even if a probe fails.
    let probes: Vec<_> = files.iter().map(|(_, file)| size(file.clone())).collect();
    tokio::select! {
        _ = job.cancel.cancelled() => {},
        _ = tokio::time::timeout(Duration::from_secs(2), async {
            let sizes = stream::iter(probes.into_iter().enumerate())
                .map(|(index, probe)| async move { (index, probe.await) }).buffer_unordered(8);
            pin_mut!(sizes);
            while let Some((index, total)) = sizes.next().await {
                job.progress.lock().unwrap().files[index].total = total;
            }
        }) => {},
    }
    let mut result = BatchResult {
        count,
        completed: 0,
        skipped: 0,
        error: None,
        failed_file: None,
        transfer: TransferProgress::default(),
    };
    for (index, (name, file)) in files.into_iter().enumerate() {
        if let Err(error) = job.check() {
            result.error = Some(error);
            break;
        }
        {
            let mut progress = job.progress.lock().unwrap();
            progress.current = Some(index);
            progress.files[index].state = FileState::Transferring;
        }
        let state = match transfer(file, count > 1).await {
            Ok(()) => {
                result.completed += 1;
                FileState::Completed
            }
            Err(error) if error == "sftpSkipped" => {
                result.skipped += 1;
                FileState::Skipped
            }
            Err(error) => {
                let cancelled = error == "sftpCancelled";
                if !cancelled {
                    result.failed_file = Some(name);
                }
                result.error = Some(error);
                if cancelled {
                    FileState::Cancelled
                } else {
                    FileState::Failed
                }
            }
        };
        job.progress.lock().unwrap().files[index].state = state;
        if result.error.is_some() {
            break;
        }
    }
    result.transfer = job.progress.lock().unwrap().clone();
    result
}

async fn check_session(
    window: &WebviewWindow,
    agent: &FileAgent,
    session: &Session,
) -> Result<(), String> {
    if resolve(agent, &session.peer).await? != session.target {
        return Err("sshTargetChanged".into());
    }
    session_for(window, &window.state::<Windows>(), &session.id)?;
    if session.connection.lock().await.is_none() {
        return Err("sftpDisconnected".into());
    }
    Ok(())
}

async fn copy(
    job: &Job,
    mut source: impl AsyncRead + Unpin,
    mut destination: impl AsyncWrite + Unpin,
    total: u64,
    read_error: &'static str,
    write_error: &'static str,
) -> Result<(), String> {
    job.set_total(total);
    let mut buffer = vec![0; 64 * 1024];
    let mut done = 0;
    loop {
        let count = job
            .wait(source.read(&mut buffer))
            .await?
            .map_err(|error| remote_read_error(&error, read_error))?;
        if count == 0 {
            break;
        }
        done += count as u64;
        if done > total {
            return Err("sftpSourceChanged".into());
        }
        job.wait(destination.write_all(&buffer[..count]))
            .await?
            .map_err(|error| local_error(&error, write_error))?;
        job.set_done(done);
    }
    if done != total {
        return Err("sftpSourceChanged".into());
    }
    job.wait(destination.flush())
        .await?
        .map_err(|error| local_error(&error, write_error))?;
    Ok(())
}

async fn remote_entry(
    job: &Job,
    fs: &mut Fs,
    path: &str,
    fallback: &'static str,
) -> Result<Option<MetaData>, String> {
    match job.wait(fs.symlink_metadata(path)).await? {
        Ok(metadata) if metadata.file_type().is_some_and(|kind| kind.is_file()) => {
            Ok(Some(metadata))
        }
        Ok(_) => Err("sftpNotFile".into()),
        Err(Error::SftpError(SftpErrorKind::NoSuchFile, _)) => Ok(None),
        Err(error) => Err(remote_error(&error, fallback).into()),
    }
}

async fn delete_files(
    job: &Job,
    sftp: &Sftp,
    dir: &str,
    names: &[String],
) -> Result<Value, String> {
    let mut fs = sftp.fs();
    let resolved = job.remote(fs.canonicalize(dir), "sftpDeleteFailed").await?;
    if resolved.to_str() != Some(dir) {
        return Err("sftpChanged".into());
    }
    let mut deleted = 0;
    let mut failures = Vec::new();
    for name in names {
        let path = join(dir, name);
        let result: Result<(), String> = async {
            remote_entry(job, &mut fs, &path, "sftpDeleteFailed")
                .await?
                .ok_or("sftpMissing")?;
            job.check()?;
            // Once dispatched, a lost response cannot tell us whether the server unlinked the file.
            match tokio::time::timeout(TIMEOUT, fs.remove_file(&path)).await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(error)) => match remote_error(&error, "sftpDeleteFailed") {
                    "sftpInterrupted" | "sftpTimeout" => Err("sftpDeleteUnknown".into()),
                    code => Err(code.into()),
                },
                Err(_) => Err("sftpDeleteUnknown".into()),
            }
        }
        .await;
        match result {
            Ok(()) => deleted += 1,
            Err(error) => {
                let interrupted = matches!(
                    error.as_str(),
                    "sftpCancelled" | "sftpInterrupted" | "sftpTimeout" | "sftpDeleteUnknown"
                );
                failures.push(json!({"name": name, "error": error}));
                if interrupted {
                    break;
                }
            }
        }
    }
    Ok(json!({
        "deleted": deleted,
        "remaining": names.len() - deleted - failures.len(),
        "failures": failures,
    }))
}

async fn commit_remote(operation: impl Future<Output = Result<(), Error>>) -> Result<(), String> {
    tokio::time::timeout(TIMEOUT, operation)
        .await
        .map_err(|_| "sftpCommitUnknown")?
        .map_err(|error| {
            match remote_error(&error, "sftpRemoteCommit") {
                "sftpInterrupted" | "sftpTimeout" => "sftpCommitUnknown",
                "sftpPermission" | "sftpMissing" => "sftpRemoteCommit",
                other => other,
            }
            .into()
        })
}

async fn upload_error(job: &Job, sftp: &Sftp, dir: &str, error: String) -> String {
    if error == "sftpRemoteWrite" && sftp.support_statvfs() {
        if let Ok(Ok(space)) =
            tokio::time::timeout(Duration::from_secs(2), sftp.fs().statvfs(dir)).await
        {
            let remaining = job
                .progress
                .lock()
                .unwrap()
                .current_file()
                .and_then(|file| file.total.map(|total| total.saturating_sub(file.done)))
                .unwrap_or_default();
            if (space.frsize != 0 && space.frsize.saturating_mul(space.bfree) < remaining)
                || (space.files != 0 && space.ffree == 0)
            {
                return "sftpRemoteSpace".into();
            }
        }
    }
    error
}

fn same_remote(before: MetaData, after: MetaData) -> bool {
    before.len() == after.len()
        && before.modified() == after.modified()
        && before.permissions() == after.permissions()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
}

async fn upload(
    window: &WebviewWindow,
    job: &Job,
    sftp: &Sftp,
    transfers: &Transfers,
    local: PathBuf,
    dir: &str,
    labels: &Confirmation,
    multiple: bool,
) -> Result<(), String> {
    let name = local
        .file_name()
        .and_then(|n| n.to_str())
        .filter(|n| name_is_valid(n))
        .ok_or("sftpInvalidPath")?;
    let target = join(dir, name);
    remote_path(&target)?;
    let mut fs = sftp.fs();
    let previous = remote_entry(job, &mut fs, &target, "sftpRemoteWrite").await?;
    if previous.is_some() {
        if !sftp.support_posix_rename() {
            return Err("sftpUnsupported".into());
        }
        confirm(window, job, labels, multiple, &target).await?;
    } else if sftp.support_posix_rename() && !sftp.support_hardlink() {
        return Err("sftpUnsupported".into());
    }
    let mut local_file = tokio::fs::File::open(&local)
        .await
        .map_err(|error| local_error(&error, "sftpLocalRead"))?;
    let before = local_file
        .metadata()
        .await
        .map_err(|error| local_error(&error, "sftpLocalRead"))?;
    if !before.is_file() {
        return Err("sftpNotFile".into());
    }
    let temporary = join(
        dir,
        &format!(".calabi-upload-{}.part", uuid::Uuid::new_v4().simple()),
    );
    job.set_total(before.len());
    job.check()?;
    let mut file = tokio::time::timeout(
        TIMEOUT,
        sftp.options().write(true).create_new(true).open(&temporary),
    )
    .await
    .map_err(|_| "sftpTimeout")?
    .map_err(|error| remote_error(&error, "sftpRemoteWrite"))?;
    let mut pending_part = None;
    let result = async {
        job.remote(
            file.set_metadata(MetaDataBuilder::new().permissions(0o600.into()).create()),
            "sftpRemoteWrite",
        )
        .await?;
        pending_part = PendingPart::inspect(&temporary, file.metadata()).await;
        let total = before.len();
        let mut buffer = vec![0; 64 * 1024];
        let mut done = 0;
        loop {
            let count = job
                .wait(local_file.read(&mut buffer))
                .await?
                .map_err(|error| local_error(&error, "sftpLocalRead"))?;
            if count == 0 {
                break;
            }
            done += count as u64;
            if done > total {
                return Err("sftpSourceChanged".into());
            }
            job.remote(file.write_all(&buffer[..count]), "sftpRemoteWrite")
                .await?;
            job.set_done(done);
        }
        let after = local_file
            .metadata()
            .await
            .map_err(|error| local_error(&error, "sftpLocalRead"))?;
        if done != total
            || before.len() != after.len()
            || before.modified().ok() != after.modified().ok()
        {
            return Err("sftpSourceChanged".into());
        }
        if let Some(previous) = previous {
            let current = remote_entry(job, &mut fs, &target, "sftpRemoteCommit")
                .await?
                .ok_or("sftpDestinationChanged")?;
            if !same_remote(previous, current) {
                return Err("sftpDestinationChanged".into());
            }
            let mut metadata = MetaDataBuilder::new();
            if let (Some(uid), Some(gid)) = (previous.uid(), previous.gid()) {
                metadata.id((uid, gid));
            }
            if let Some(permissions) = previous.permissions() {
                metadata.permissions(permissions);
            }
            job.remote(file.set_metadata(metadata.create()), "sftpRemoteCommit")
                .await?;
            pending_part = PendingPart::inspect(&temporary, file.metadata())
                .await
                .or(pending_part.take());
        }
        job.remote(file.close(), "sftpRemoteWrite").await?;
        // Cancellation is accepted until commit. A dispatched rename or link can still take effect.
        job.check()?;
        if previous.is_none() && sftp.support_posix_rename() {
            commit_remote(fs.hard_link(&temporary, &target)).await?;
        } else {
            commit_remote(fs.rename(&temporary, &target)).await?;
        }
        Ok(())
    }
    .await;
    match tokio::time::timeout(Duration::from_secs(3), fs.remove_file(&temporary)).await {
        Ok(Ok(())) | Ok(Err(Error::SftpError(SftpErrorKind::NoSuchFile, _))) => {}
        _ => {
            if let Some(part) = pending_part {
                transfers.remember_part(part);
            }
        }
    }
    result
}

#[cfg(windows)]
fn download_name(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or_default();
    let name: String = name
        .chars()
        .map(|ch| {
            if matches!(ch, '<' | '>' | ':' | '"' | '\\' | '|' | '?' | '*') {
                '_'
            } else {
                ch
            }
        })
        .collect();
    let name = name.trim_end_matches(['.', ' ']);
    let stem = name
        .split('.')
        .next()
        .unwrap_or("")
        .trim_end_matches(' ')
        .to_ascii_uppercase();
    let reserved_port = stem
        .strip_prefix("COM")
        .or_else(|| stem.strip_prefix("LPT"))
        .is_some_and(|number| {
            matches!(
                number,
                "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        });
    if name.is_empty()
        || matches!(
            stem.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        )
        || reserved_port
    {
        return format!("download_{name}");
    }
    name.to_owned()
}

#[cfg(target_os = "macos")]
fn download_name(path: &str) -> String {
    path.rsplit('/').next().unwrap_or_default().to_owned()
}

async fn download(
    window: &WebviewWindow,
    job: &Job,
    sftp: &Sftp,
    path: &str,
    folder: &Path,
    labels: &Confirmation,
    multiple: bool,
) -> Result<(), String> {
    let path = remote_path(path)?;
    let mut fs = sftp.fs();
    let before = remote_entry(job, &mut fs, path, "sftpRemoteRead")
        .await?
        .ok_or("sftpMissing")?;
    let target = folder.join(download_name(path));
    let previous = match tokio::fs::symlink_metadata(&target).await {
        Ok(metadata) if metadata.is_file() => {
            confirm(window, job, labels, multiple, &target.to_string_lossy()).await?;
            Some(metadata)
        }
        Ok(_) => return Err("sftpNotFile".into()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(local_error(&error, "sftpLocalWrite").into()),
    };
    let temporary = tempfile::NamedTempFile::new_in(folder)
        .map_err(|error| local_error(&error, "sftpLocalWrite"))?;
    let mut destination = tokio::fs::File::from_std(
        temporary
            .reopen()
            .map_err(|error| local_error(&error, "sftpLocalWrite"))?,
    );
    let mut source = job.remote(sftp.open(path), "sftpRemoteRead").await?;
    let opened = job.remote(source.metadata(), "sftpRemoteRead").await?;
    if !same_remote(before, opened) {
        return Err("sftpSourceChanged".into());
    }
    let mut reader = Box::pin(TokioCompatFile::new(source));
    copy(
        job,
        reader.as_mut(),
        &mut destination,
        before.len().ok_or("sftpNotFile")?,
        "sftpRemoteRead",
        "sftpLocalWrite",
    )
    .await?;
    if !same_remote(
        before,
        job.remote(reader.as_mut().as_mut_file().metadata(), "sftpRemoteRead")
            .await?,
    ) {
        return Err("sftpSourceChanged".into());
    }
    drop(destination);
    if let Some(previous) = &previous {
        let current = tokio::fs::symlink_metadata(&target)
            .await
            .map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    "sftpDestinationChanged"
                } else {
                    local_error(&error, "sftpLocalCommit")
                }
            })?;
        if !current.is_file()
            || previous.len() != current.len()
            || previous.modified().ok() != current.modified().ok()
        {
            return Err("sftpDestinationChanged".into());
        }
    }
    job.check()?;
    save_download(temporary, &target, previous.is_some())
}

fn save_download(
    temporary: tempfile::NamedTempFile,
    target: &Path,
    overwrite: bool,
) -> Result<(), String> {
    if overwrite {
        temporary.persist(target)
    } else {
        temporary.persist_noclobber(target)
    }
    .map_err(|error| {
        if error.error.kind() == std::io::ErrorKind::AlreadyExists {
            "sftpDestinationChanged"
        } else {
            local_error(&error.error, "sftpLocalCommit")
        }
    })?;
    Ok(())
}

pub(super) async fn dispatch(
    window: &WebviewWindow,
    agent: &FileAgent,
    session: &Session,
    action: Action,
) -> Result<Value, String> {
    match action {
        Action::Progress => {
            let active = session.files.active.lock().unwrap();
            return Ok(active
                .as_ref()
                .map(|job| job.progress.lock().unwrap().snapshot())
                .unwrap_or(Value::Null));
        }
        Action::Cancel => {
            session.files.cancel();
            return Ok(Value::Null);
        }
        _ => {}
    }
    let operation = session.files.begin()?;
    let job = &operation.job;
    check_session(window, agent, session).await?;
    match action {
        Action::List { path } => {
            let channel = Channel::open(job, session).await?;
            list(job, &channel.sftp, path.as_deref()).await
        }
        Action::Delete {
            dir,
            names,
            confirm: labels,
        } => {
            validate_delete(&dir, &names)?;
            let mut details = dir.clone();
            for name in names.iter().take(5) {
                details.push('\n');
                details.push_str(name);
            }
            if names.len() > 5 {
                details.push_str("\n…");
            }
            confirm(window, job, &labels, false, &details).await?;
            check_session(window, agent, session).await?;
            let channel = Channel::open(job, session).await?;
            delete_files(job, &channel.sftp, &dir, &names).await
        }
        Action::Upload {
            dir,
            confirm,
            detailed,
        } => {
            let dir = remote_path(&dir)?;
            let files = pick(window, job, false).await?;
            if files.is_empty() {
                return Err("sftpCancelled".into());
            }
            check_session(window, agent, session).await?;
            job.check()?;
            let channel = Channel::open(job, session).await?;
            let sftp = &channel.sftp;
            let transfers = &session.files;
            let confirm = &confirm;
            let files = files
                .into_iter()
                .map(|path| {
                    let name = path
                        .file_name()
                        .unwrap_or(path.as_os_str())
                        .to_string_lossy()
                        .into_owned();
                    (name, path)
                })
                .collect();
            transfer_batch(
                job,
                files,
                |local| async move {
                    tokio::fs::metadata(local)
                        .await
                        .ok()
                        .filter(|file| file.is_file())
                        .map(|file| file.len())
                },
                |local, multiple| async move {
                    match upload(window, job, sftp, transfers, local, dir, confirm, multiple).await
                    {
                        Ok(()) => Ok(()),
                        Err(error) => Err(upload_error(job, sftp, dir, error).await),
                    }
                },
            )
            .await
            .response(detailed)
        }
        Action::Download {
            paths,
            confirm,
            detailed,
        } => {
            let paths = match paths {
                DownloadPaths::Single(path) => vec![path],
                DownloadPaths::Multiple(paths) => paths,
            };
            if paths.is_empty() || paths.len() > LIST_LIMIT {
                return Err("sftpInvalidPath".into());
            }
            let files = paths
                .iter()
                .map(|path| {
                    let path = remote_path(path)?;
                    let name = path.rsplit('/').next().unwrap_or_default();
                    if name.is_empty() {
                        return Err("sftpNotFile".to_owned());
                    }
                    Ok((name.to_owned(), path))
                })
                .collect::<Result<Vec<_>, String>>()?;
            let mut folders = pick(window, job, true).await?;
            let folder = folders.pop().ok_or("sftpCancelled")?;
            check_session(window, agent, session).await?;
            job.check()?;
            let channel = Channel::open(job, session).await?;
            let sftp = &channel.sftp;
            transfer_batch(
                job,
                files,
                |path| async move {
                    let meta = sftp.fs().symlink_metadata(path).await.ok()?;
                    meta.file_type().filter(|kind| kind.is_file())?;
                    meta.len()
                },
                |path, multiple| {
                    download(
                        window,
                        job,
                        &channel.sftp,
                        path,
                        &folder,
                        &confirm,
                        multiple,
                    )
                },
            )
            .await
            .response(detailed)
        }
        Action::Progress | Action::Cancel => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_accepts_only_distinct_children_of_the_listed_directory() {
        assert!(validate_delete("/", &["配置.txt".into(), "readme.txt".into()]).is_ok());
        for invalid in [
            "..",
            ".",
            "/tmp/other",
            "sub/file",
            "sub\\file",
            "line\nbreak",
        ] {
            assert!(validate_delete("/home/fixture", &[invalid.into()]).is_err());
        }
        assert!(validate_delete("/home/fixture", &["same".into(), "same".into()]).is_err());
        assert!(validate_delete("/home/fixture", &[]).is_err());
        assert!(validate_delete("/home/fixture", &["a".repeat(4096)]).is_err());
    }

    #[tokio::test]
    async fn batch_skips_declined_overwrites_and_stops_on_failure() {
        let transfers = Transfers::default();
        let operation = transfers.begin().unwrap();
        let job = &operation.job;
        let files = ["original", "saved", "failed", "untouched"]
            .map(|name| (name.to_owned(), name))
            .to_vec();
        let mut visited = Vec::new();
        let result = transfer_batch(
            job,
            files,
            |_| std::future::ready(Some(9)),
            |name, multiple| {
                assert!(multiple);
                assert_eq!(job.progress.lock().unwrap().snapshot()["done"], 0);
                visited.push(name);
                if name == "saved" {
                    job.set_done(9);
                }
                if name == "failed" {
                    job.set_done(3);
                }
                std::future::ready(match name {
                    "original" => Err("sftpSkipped".into()),
                    "failed" => Err("sftpLocalSpace".into()),
                    _ => Ok(()),
                })
            },
        )
        .await;
        assert_eq!(visited, ["original", "saved", "failed"]);
        assert_eq!(job.progress.lock().unwrap().snapshot()["file"]["index"], 3);
        assert_eq!(
            result.response(true).unwrap(),
            json!({
                "count": 4, "completed": 1, "skipped": 1,
                "error": "sftpLocalSpace", "failed_file": "failed",
                "transfer": {"current": 2, "files": [
                    {"name": "original", "done": 0, "total": 9, "state": "skipped"},
                    {"name": "saved", "done": 9, "total": 9, "state": "completed"},
                    {"name": "failed", "done": 3, "total": 9, "state": "failed"},
                    {"name": "untouched", "done": 0, "total": 9, "state": "pending"},
                ]},
            })
        );
    }

    #[tokio::test]
    async fn cancelling_between_files_preserves_completed_count() {
        let transfers = Transfers::default();
        let operation = transfers.begin().unwrap();
        let files = [("first".into(), "first"), ("second".into(), "second")].to_vec();
        let result = transfer_batch(
            &operation.job,
            files,
            |_| std::future::ready(None),
            |name, _| {
                assert_eq!(name, "first");
                transfers.cancel();
                std::future::ready(Ok(()))
            },
        )
        .await;
        assert_eq!(result.completed, 1);
        assert_eq!(result.error.as_deref(), Some("sftpCancelled"));
        assert!(result.failed_file.is_none());
    }

    #[test]
    fn transport_and_storage_failures_keep_their_causes() {
        let disconnected = Error::IOError(io::Error::from(io::ErrorKind::BrokenPipe));
        assert_eq!(
            remote_error(&disconnected, "sftpRemoteWrite"),
            "sftpInterrupted"
        );
        let read_error = io::Error::other(disconnected);
        assert_eq!(
            remote_read_error(&read_error, "sftpRemoteRead"),
            "sftpInterrupted"
        );
        assert_eq!(
            remote_status(SftpErrorKind::Failure, "Failure", "sftpRemoteWrite"),
            "sftpRemoteWrite"
        );
        assert_eq!(
            remote_status(
                SftpErrorKind::Failure,
                "Disk quota exceeded",
                "sftpRemoteWrite"
            ),
            "sftpRemoteSpace"
        );
        assert_eq!(
            remote_status(
                SftpErrorKind::PermDenied,
                "Permission denied",
                "sftpRemoteWrite"
            ),
            "sftpRemoteWriteDenied"
        );
        #[cfg(windows)]
        assert_eq!(
            local_error(
                &io::Error::from_raw_os_error(ERROR_DISK_FULL as i32),
                "sftpLocalWrite"
            ),
            "sftpLocalSpace"
        );
        #[cfg(windows)]
        assert_eq!(
            local_error(
                &io::Error::from_raw_os_error(ERROR_SHARING_VIOLATION as i32),
                "sftpLocalCommit"
            ),
            "sftpLocalBusy"
        );
    }

    #[tokio::test]
    async fn disconnect_is_distinct_from_user_cancel_and_unconfirmed_commit() {
        let transfers = Transfers::default();
        let operation = transfers.begin().unwrap();
        transfers.interrupt();
        transfers.cancel();
        assert_eq!(operation.job.check().unwrap_err(), "sftpInterrupted");
        drop(operation);
        let operation = transfers.begin().unwrap();
        transfers.cancel();
        transfers.interrupt();
        assert_eq!(operation.job.check().unwrap_err(), "sftpCancelled");
        let result = commit_remote(async {
            Err(Error::IOError(io::Error::from(io::ErrorKind::BrokenPipe)))
        })
        .await;
        assert_eq!(result.unwrap_err(), "sftpCommitUnknown");
    }

    #[test]
    fn failed_download_commit_preserves_existing_file() {
        use std::io::Write;
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("report.txt");
        std::fs::write(&target, b"original").unwrap();
        let mut partial = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        partial.write_all(b"replacement").unwrap();
        let temporary = partial.path().to_owned();
        assert_eq!(
            save_download(partial, &target, false).unwrap_err(),
            "sftpDestinationChanged"
        );
        assert_eq!(std::fs::read(target).unwrap(), b"original");
        assert!(!temporary.exists());
    }

    #[test]
    fn remote_and_local_paths_keep_their_own_filesystem_rules() {
        assert_eq!(join("/", "配置.json"), "/配置.json");
        assert!(remote_path("/var/log/app.log").is_ok());
        for invalid in ["home", "/tmp/../home", "/tmp//file", "/a\\b", "/a\nb"] {
            assert!(remote_path(invalid).is_err(), "{invalid:?}");
        }
        assert_eq!(download_name("/logs/common.txt"), "common.txt");
        #[cfg(windows)]
        {
            assert_eq!(download_name("/logs/COM¹.txt"), "download_COM¹.txt");
            assert_eq!(download_name("/logs/CONOUT$"), "download_CONOUT$");
            assert_eq!(download_name("/logs/data:summary.txt"), "data_summary.txt");
        }
        #[cfg(target_os = "macos")]
        assert_eq!(download_name("/logs/COM¹.txt"), "COM¹.txt");
    }

    #[tokio::test]
    async fn transfers_are_exclusive_cancellable_and_verify_the_size() {
        let transfers = Transfers::default();
        let operation = transfers.begin().unwrap();
        assert!(transfers.begin().is_err());
        let mut bytes = Vec::new();
        copy(
            &operation.job,
            &b"sample"[..],
            &mut bytes,
            6,
            "read",
            "write",
        )
        .await
        .unwrap();
        assert_eq!(bytes, b"sample");
        let result = copy(
            &operation.job,
            &b"short"[..],
            &mut Vec::new(),
            8,
            "read",
            "write",
        )
        .await;
        assert_eq!(result.unwrap_err(), "sftpSourceChanged");
        transfers.cancel();
        let result = copy(
            &operation.job,
            &b"x"[..],
            &mut Vec::new(),
            1,
            "read",
            "write",
        )
        .await;
        assert_eq!(result.unwrap_err(), "sftpCancelled");
        drop(operation);
        assert!(transfers.begin().is_ok());
        transfers.close();
        assert!(transfers.begin().is_err());
    }

    #[tokio::test]
    #[ignore = "requires a localhost OpenSSH-compatible SFTP fixture"]
    async fn windows_openssh_sftp_fixture() {
        let port = std::env::var("CALABI_SFTP_TEST_PORT").unwrap();
        let hosts = std::env::var("CALABI_SFTP_TEST_KNOWN_HOSTS").unwrap();
        let helper = PathBuf::from(std::env::var_os("CALABI_SFTP_TEST_DESKTOP").unwrap());
        let mut command = CommandBuilder::new(system_ssh().unwrap());
        command.args([
            "-F",
            "none",
            "-T",
            "-l",
            "fixture",
            "-p",
            &port,
            "-o",
            &format!("UserKnownHostsFile=\"{hosts}\""),
            "-o",
            "StrictHostKeyChecking=yes",
        ]);
        let transfers = Transfers::default();
        let operation = transfers.begin().unwrap();
        let job = &operation.job;
        let channel = Channel::open_command(
            job,
            command,
            Some("fixture-password"),
            &helper,
            std::net::Ipv4Addr::LOCALHOST,
        )
        .await
        .unwrap();
        let dir = list(job, &channel.sftp, None).await.unwrap();
        assert_eq!(dir["path"], "/home/fixture");
        assert!(dir["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["name"] == "配置.txt"));
        let path = "/home/fixture/配置.txt";
        let file = channel.sftp.open(path).await.unwrap();
        let mut reader = Box::pin(TokioCompatFile::new(file));
        let mut output = Vec::new();
        copy(job, reader.as_mut(), &mut output, 13, "read", "write")
            .await
            .unwrap();
        assert_eq!(output, b"sftp-fixture\n");
        let mut file = channel
            .sftp
            .options()
            .write(true)
            .create_new(true)
            .open("/home/fixture/upload.txt")
            .await
            .unwrap();
        file.write_all(b"upload-fixture\n").await.unwrap();
        file.close().await.unwrap();
        assert!(channel
            .sftp
            .options()
            .write(true)
            .create_new(true)
            .open("/home/fixture/upload.txt")
            .await
            .is_err());
        let mut fs = channel.sftp.fs();
        let denied = job
            .remote(fs.open_dir("/home/fixture/denied"), "sftpRemoteList")
            .await;
        assert!(matches!(denied, Err(code) if code == "sftpPermission"));
        let part = "/home/fixture/.calabi-upload-fixture.part";
        fs.rename("/home/fixture/upload.txt", part).await.unwrap();
        transfers.remember_part(
            PendingPart::verified(part.into(), fs.symlink_metadata(part).await.unwrap()).unwrap(),
        );
        let mut changed =
            PendingPart::verified(path.into(), fs.symlink_metadata(path).await.unwrap()).unwrap();
        changed.uid = changed.uid.wrapping_add(1);
        transfers.remember_part(changed);
        transfers.remove_pending_parts(&channel.sftp).await;
        assert!(transfers.pending_parts.lock().unwrap().is_empty());
        assert!(matches!(
            fs.symlink_metadata(part).await,
            Err(Error::SftpError(SftpErrorKind::NoSuchFile, _))
        ));
        assert!(fs.symlink_metadata(path).await.is_ok());
        drop(reader);
        let names = [
            "blocked.txt",
            "missing.txt",
            "folder",
            "link",
            "配置.txt",
            "remove.txt",
        ]
        .map(String::from);
        assert_eq!(
            delete_files(job, &channel.sftp, "/home/fixture/moved", &names)
                .await
                .unwrap_err(),
            "sftpChanged"
        );
        let result = delete_files(job, &channel.sftp, "/home/fixture", &names)
            .await
            .unwrap();
        assert_eq!(
            result,
            json!({
                "deleted": 2, "remaining": 0, "failures": [
                    {"name": "blocked.txt", "error": "sftpPermission"},
                    {"name": "missing.txt", "error": "sftpMissing"},
                    {"name": "folder", "error": "sftpNotFile"},
                    {"name": "link", "error": "sftpNotFile"},
                ],
            })
        );
        let remaining = list(job, &channel.sftp, None).await.unwrap();
        let remaining = remaining["entries"].as_array().unwrap();
        assert!(remaining.iter().any(|entry| entry["name"] == "keep.txt"));
        assert!(remaining.iter().any(|entry| entry["name"] == "blocked.txt"));
        assert!(!remaining
            .iter()
            .any(|entry| entry["name"] == "配置.txt" || entry["name"] == "remove.txt"));
    }
}
