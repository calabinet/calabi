use std::{
    fs::{File, OpenOptions},
    io,
    os::windows::{
        fs::OpenOptionsExt,
        io::{AsRawHandle, IntoRawHandle},
        process::CommandExt,
    },
    path::Path,
    ptr::null_mut,
    time::Duration,
};
use tokio::{io::AsyncWriteExt, net::windows::named_pipe::NamedPipeClient};
use windows_sys::Win32::{
    Foundation::{LocalFree, ERROR_FILE_NOT_FOUND, ERROR_PIPE_BUSY},
    Security::{
        Authorization::{ConvertSidToStringSidW, GetSecurityInfo, SE_KERNEL_OBJECT},
        EqualSid, OWNER_SECURITY_INFORMATION, TOKEN_USER,
    },
    Storage::FileSystem::{
        FILE_FLAG_OVERLAPPED, FILE_READ_ATTRIBUTES, FILE_READ_DATA, FILE_WRITE_DATA, READ_CONTROL,
        SECURITY_IDENTIFICATION, SYNCHRONIZE,
    },
    System::{
        Pipes::GetNamedPipeServerProcessId,
        RemoteDesktop::ProcessIdToSessionId,
        Threading::{GetCurrentProcess, CREATE_NO_WINDOW},
    },
};

// Match the installed Go agent's SID-scoped pipe and desktop client byte.
const PIPE_PREFIX: &str = r"\\.\pipe\Calabi.DesktopFiles.v1.";
const DESKTOP_CLIENT: u8 = 0;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(12);
const RETRY_INTERVAL: Duration = Duration::from_millis(100);

struct Endpoint {
    path: String,
    user: Vec<usize>,
    session: u32,
}

impl Endpoint {
    fn current() -> io::Result<Self> {
        let session = session_id(std::process::id())?;
        if session == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "File agent requires an interactive Windows session",
            ));
        }
        let user = crate::windows_service::process_user(unsafe { GetCurrentProcess() })?;
        let path = unsafe {
            let sid = (*user.as_ptr().cast::<TOKEN_USER>()).User.Sid;
            let mut text = null_mut();
            if ConvertSidToStringSidW(sid, &mut text) == 0 {
                return Err(io::Error::last_os_error());
            }
            let len = (0..).take_while(|&i| *text.add(i) != 0).count();
            let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, len));
            LocalFree(text.cast());
            format!("{PIPE_PREFIX}{sid}")
        };
        Ok(Self {
            path,
            user,
            session,
        })
    }

    fn open(&self) -> io::Result<File> {
        // Do not request generic write, which includes the right to create a
        // server pipe instance. Allow identity checks but not impersonation.
        OpenOptions::new()
            .access_mode(
                FILE_READ_DATA
                    | FILE_WRITE_DATA
                    | FILE_READ_ATTRIBUTES
                    | SYNCHRONIZE
                    | READ_CONTROL,
            )
            .share_mode(0)
            .custom_flags(FILE_FLAG_OVERLAPPED)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(&self.path)
    }

    async fn open_desktop(&self, file: File) -> io::Result<NamedPipeClient> {
        let handle = file.as_raw_handle();
        unsafe {
            let mut owner = null_mut();
            let mut descriptor = null_mut();
            let status = GetSecurityInfo(
                handle,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                null_mut(),
                null_mut(),
                &mut descriptor,
            );
            if status != 0 {
                return Err(io::Error::from_raw_os_error(status as i32));
            }
            let sid = (*self.user.as_ptr().cast::<TOKEN_USER>()).User.Sid;
            let same_owner = !owner.is_null() && EqualSid(owner, sid) != 0;
            LocalFree(descriptor.cast());
            if !same_owner {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "File agent pipe is not owned by the current user",
                ));
            }
            let mut pid = 0;
            if GetNamedPipeServerProcessId(handle, &mut pid) == 0 {
                return Err(io::Error::last_os_error());
            }
            if session_id(pid)? != self.session {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "File agent belongs to another Windows sign-in session",
                ));
            }
        }
        // The file was opened for overlapped I/O. Tokio takes ownership.
        let mut pipe = unsafe { NamedPipeClient::from_raw_handle(file.into_raw_handle()) }?;
        pipe.write_all(&[DESKTOP_CLIENT]).await?;
        Ok(pipe)
    }
}

fn session_id(pid: u32) -> io::Result<u32> {
    let mut session = 0;
    if unsafe { ProcessIdToSessionId(pid, &mut session) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(session)
}

pub(super) fn start(binary: &Path) -> io::Result<()> {
    // The login task and the desktop only launch the agent. Its lifetime is
    // managed by the Windows user session and is independent of either caller.
    std::process::Command::new(binary)
        .args(["mesh", "files", "--background"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()?;
    Ok(())
}

pub(super) async fn connect() -> Result<NamedPipeClient, String> {
    let connection = tokio::time::timeout(CONNECT_TIMEOUT, async {
        let endpoint = Endpoint::current().map_err(|error| error.to_string())?;
        let mut started = false;
        loop {
            match endpoint.open() {
                Ok(file) => {
                    return endpoint
                        .open_desktop(file)
                        .await
                        .map_err(|error| error.to_string())
                }
                Err(error) => match error.raw_os_error().map(|code| code as u32) {
                    Some(ERROR_FILE_NOT_FOUND) => {
                        if !started {
                            let binary = crate::daemon::resolve_binary(None)?;
                            start(&binary)
                                .map_err(|error| format!("Cannot start file agent: {error}"))?;
                            started = true;
                        }
                    }
                    Some(ERROR_PIPE_BUSY) => {}
                    _ => return Err(error.to_string()),
                },
            }
            tokio::time::sleep(RETRY_INTERVAL).await;
        }
    });
    connection
        .await
        .map_err(|_| "Timed out connecting to the Windows file agent".to_owned())?
        .map_err(|error| format!("Cannot connect to the Windows file agent: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::AsyncReadExt,
        net::windows::named_pipe::{NamedPipeServer, ServerOptions},
    };
    use windows_sys::Win32::Security::{
        Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
        SECURITY_ATTRIBUTES,
    };

    fn fixture() -> Endpoint {
        let mut endpoint = Endpoint::current().unwrap();
        endpoint
            .path
            .push_str(&format!(".test.{}", uuid::Uuid::new_v4()));
        endpoint
    }

    fn listen(endpoint: &Endpoint, first: bool) -> NamedPipeServer {
        let suffix = endpoint.path.strip_prefix(PIPE_PREFIX).unwrap();
        let (sid, _) = suffix.split_once(".test.").unwrap();
        let sddl: Vec<_> = format!("O:{sid}D:P(A;;GA;;;{sid})")
            .encode_utf16()
            .chain([0])
            .collect();
        unsafe {
            let mut descriptor = null_mut();
            assert_ne!(
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    sddl.as_ptr(),
                    SDDL_REVISION_1,
                    &mut descriptor,
                    null_mut(),
                ),
                0
            );
            let mut attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: descriptor,
                bInheritHandle: 0,
            };
            let server = ServerOptions::new()
                .first_pipe_instance(first)
                .reject_remote_clients(true)
                .create_with_security_attributes_raw(
                    &endpoint.path,
                    (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
                );
            LocalFree(descriptor.cast());
            server.unwrap()
        }
    }

    #[tokio::test]
    async fn desktop_pipe_reconnects_without_stopping_server() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let endpoint = fixture();
            let mut server = listen(&endpoint, true);
            for reconnect in [true, false] {
                let ((), mut client) = tokio::try_join!(server.connect(), async {
                    endpoint.open_desktop(endpoint.open()?).await
                })
                .unwrap();
                assert_eq!(server.read_u8().await.unwrap(), DESKTOP_CLIENT);
                const REQUEST: &[u8] = b"{\"action\":\"snapshot\"}\n";
                client.write_all(REQUEST).await.unwrap();
                let mut received = [0; REQUEST.len()];
                server.read_exact(&mut received).await.unwrap();
                assert_eq!(&received, REQUEST);
                server.write_all(b"{}\n").await.unwrap();
                let mut response = [0; 3];
                client.read_exact(&mut response).await.unwrap();
                assert_eq!(&response, b"{}\n");
                // Like the Go listener, create a new server instance for the
                // next client while the named pipe is still available.
                let next = reconnect.then(|| listen(&endpoint, false));
                drop(client);
                assert_eq!(server.read(&mut response).await.unwrap(), 0);
                if let Some(next) = next {
                    server = next;
                }
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn desktop_pipe_rejects_another_session() {
        let mut endpoint = fixture();
        let _server = listen(&endpoint, true);
        endpoint.session = 0;
        let error = endpoint
            .open_desktop(endpoint.open().unwrap())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error
            .to_string()
            .contains("another Windows sign-in session"));
    }
}
