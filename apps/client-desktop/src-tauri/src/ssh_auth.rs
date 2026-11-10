use std::{
    ffi::OsStr,
    io::{Read, Write},
    os::windows::ffi::OsStrExt,
    path::Path,
};

use crate::ssh::is_host_confirmation;
use portable_pty::CommandBuilder;
use tokio::{io::AsyncWriteExt, net::windows::named_pipe::ServerOptions, task::JoinHandle};
use uuid::Uuid;
use windows_sys::Win32::{
    Foundation::{GetLastError, LocalFree, ERROR_NOT_FOUND, HWND},
    Security::{
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            SDDL_REVISION_1,
        },
        Credentials::{
            CredDeleteW, CredFree, CredReadW, CredWriteW, CREDENTIALW, CRED_PERSIST_LOCAL_MACHINE,
            CRED_TYPE_GENERIC,
        },
        SECURITY_ATTRIBUTES, TOKEN_USER,
    },
    System::Threading::GetCurrentProcess,
    UI::WindowsAndMessaging::{
        GetWindowThreadProcessId, MessageBoxW, IDYES, MB_DEFBUTTON2, MB_ICONWARNING,
        MB_SETFOREGROUND, MB_YESNO,
    },
};
use zeroize::{Zeroize, Zeroizing};

const PIPE_ENV: &str = "CALABI_SSH_ASKPASS_PIPE";
const PIPE_PREFIX: &str = r"\\.\pipe\calabi-ssh-";
pub(super) const OWNER_ENV: &str = "CALABI_SSH_ASKPASS_OWNER";
pub const PASSWORD_LIMIT: usize = 1000; // OpenSSH askpass reads at most 1023 bytes.

#[derive(Clone, Copy)]
pub struct PromptOwner {
    handle: usize,
    pid: u32,
}

impl PromptOwner {
    pub fn new(handle: usize, pid: u32) -> Option<Self> {
        let mut actual = 0;
        let thread = unsafe { GetWindowThreadProcessId(handle as HWND, &mut actual) };
        (thread != 0 && pid != 0 && actual == pid).then_some(Self { handle, pid })
    }

    fn from_env() -> Option<Self> {
        let value = std::env::var(OWNER_ENV).ok()?;
        let (handle, pid) = value.split_once(':')?;
        Self::new(handle.parse().ok()?, pid.parse().ok()?)
    }
}

fn wide(value: &str) -> Vec<u16> {
    OsStr::new(value).encode_wide().chain([0]).collect()
}

fn password_pipe(name: &str) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
    // The default named pipe DACL grants read access to other local users.
    // Use an explicit DACL tied to the ordinary user running the desktop shell.
    unsafe {
        let user = crate::windows_service::process_user(GetCurrentProcess())?;
        let user = &*user.as_ptr().cast::<TOKEN_USER>();
        let mut sid = std::ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut sid) == 0 {
            return Err(std::io::Error::last_os_error());
        }
        let mut len = 0;
        while *sid.add(len) != 0 {
            len += 1;
        }
        let text = String::from_utf16_lossy(std::slice::from_raw_parts(sid, len));
        LocalFree(sid.cast());
        let sddl = wide(&format!("O:{text}D:P(A;;GA;;;{text})"));
        let mut descriptor = std::ptr::null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let mut attributes = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let result = ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .access_inbound(false)
            .create_with_security_attributes_raw(
                name,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            );
        LocalFree(descriptor);
        result
    }
}

pub fn credential_name(host_key: &str, port: u16, account: &str) -> String {
    format!("Calabi/SSH/{host_key}/{port}/{account}")
}

pub fn read_credential(name: &str) -> Result<Option<Zeroizing<String>>, String> {
    let name = wide(name);
    let mut entry = std::ptr::null_mut();
    unsafe {
        if CredReadW(name.as_ptr(), CRED_TYPE_GENERIC, 0, &mut entry) == 0 {
            return if GetLastError() == ERROR_NOT_FOUND {
                Ok(None)
            } else {
                Err("sshCredentialFailed".into())
            };
        }
        let data = &*entry;
        let result = if data.CredentialBlobSize == 0
            || data.CredentialBlobSize as usize > PASSWORD_LIMIT
        {
            Err("sshCredentialFailed".into())
        } else {
            let bytes = std::slice::from_raw_parts_mut(
                data.CredentialBlob,
                data.CredentialBlobSize as usize,
            );
            let password = std::str::from_utf8(bytes).map(|value| Zeroizing::new(value.to_owned()));
            bytes.zeroize();
            password.map(Some).map_err(|_| "sshCredentialFailed".into())
        };
        CredFree(entry.cast());
        result
    }
}

pub fn save_credential(name: &str, password: &str) -> Result<(), String> {
    let mut name = wide(name);
    let mut data = Zeroizing::new(password.as_bytes().to_vec());
    let mut entry = CREDENTIALW {
        Type: CRED_TYPE_GENERIC,
        TargetName: name.as_mut_ptr(),
        CredentialBlobSize: data.len() as u32,
        CredentialBlob: data.as_mut_ptr(),
        Persist: CRED_PERSIST_LOCAL_MACHINE,
        ..Default::default()
    };
    if unsafe { CredWriteW(&mut entry, 0) } == 0 {
        return Err("sshCredentialFailed".into());
    }
    Ok(())
}

pub fn clear_credential(name: &str) -> Result<(), String> {
    let name = wide(name);
    unsafe {
        if CredDeleteW(name.as_ptr(), CRED_TYPE_GENERIC, 0) == 0
            && GetLastError() != ERROR_NOT_FOUND
        {
            return Err("sshCredentialFailed".into());
        }
    }
    Ok(())
}

pub struct Attempt {
    pub marker: String,
    broker: Option<JoinHandle<()>>,
}

impl Drop for Attempt {
    fn drop(&mut self) {
        if let Some(broker) = &self.broker {
            broker.abort();
        }
    }
}

impl Attempt {
    pub fn configure(
        command: &mut CommandBuilder,
        password: Option<&str>,
        executable: &Path,
        owner: Option<PromptOwner>,
    ) -> Result<Self, String> {
        let nonce = Uuid::new_v4().simple().to_string();
        let name = format!("{PIPE_PREFIX}{nonce}");
        let marker = format!("CALABI_SSH_AUTH_{nonce}");
        let broker = if let Some(password) = password {
            let mut pipe = password_pipe(&name).map_err(|e| e.to_string())?;
            let password = Zeroizing::new(password.as_bytes().to_vec());
            Some(tokio::spawn(async move {
                if pipe.connect().await.is_ok() {
                    let _ = pipe.write_all(&password).await;
                    let _ = pipe.write_all(b"\n").await;
                    // The helper reads a full line and closes its pipe handle.
                    // Keep the server alive until OpenSSH reports the result.
                    std::future::pending::<()>().await;
                }
            }))
        } else {
            None
        };
        command.env(PIPE_ENV, name);
        command.env("SSH_ASKPASS", executable);
        command.env("SSH_ASKPASS_REQUIRE", "force");
        command.env_remove("SSH_ASKPASS_PROMPT");
        if let Some(owner) = owner {
            command.env(OWNER_ENV, format!("{}:{}", owner.handle, owner.pid));
        } else {
            command.env_remove(OWNER_ENV);
        }
        command.args([
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            if password.is_some() {
                "PreferredAuthentications=password"
            } else {
                "PreferredAuthentications=publickey"
            },
        ]);
        Ok(Self { marker, broker })
    }
}

pub fn askpass() -> Option<i32> {
    let name = std::env::var(PIPE_ENV).ok()?;
    let nonce = name.strip_prefix(PIPE_PREFIX)?;
    if nonce.len() != 32 || !nonce.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Some(1);
    }
    let mut args = std::env::args_os().skip(1);
    let prompt = args.next()?.to_string_lossy().into_owned();
    if args.next().is_some() {
        return Some(1);
    }
    if is_host_confirmation(&prompt) {
        let Some(owner) = PromptOwner::from_env() else {
            return Some(1);
        };
        let title = wide("Calabi SSH");
        let text = wide(&prompt);
        let yes = unsafe {
            MessageBoxW(
                owner.handle as HWND,
                text.as_ptr(),
                title.as_ptr(),
                MB_YESNO | MB_ICONWARNING | MB_DEFBUTTON2 | MB_SETFOREGROUND,
            )
        } == IDYES;
        return Some(if yes && std::io::stdout().write_all(b"yes\n").is_ok() {
            0
        } else {
            1
        });
    }
    if !prompt.trim_end().ends_with("'s password:") {
        return Some(1);
    }
    let result = (|| -> std::io::Result<()> {
        let mut reader = std::io::BufReader::new(std::fs::File::open(&name)?);
        let mut password = Zeroizing::new(Vec::new());
        use std::io::BufRead;
        reader
            .by_ref()
            .take((PASSWORD_LIMIT + 1) as u64)
            .read_until(b'\n', &mut password)?;
        if password.last() != Some(&b'\n') {
            return Err(std::io::Error::other("Invalid SSH password response"));
        }
        std::io::stdout().write_all(&password)
    })();
    Some(if result.is_ok() { 0 } else { 1 })
}

#[cfg(test)]
mod tests {
    use super::is_host_confirmation;

    #[test]
    fn matches_openssh_95_first_use_prompt_without_an_environment_hint() {
        let prompt = "The authenticity of host '127.0.0.1 (127.0.0.1)' can't be established.\r\nED25519 key fingerprint is SHA256:abcdefgh.\r\nAre you sure you want to continue connecting (yes/no/[fingerprint])? ";
        assert!(is_host_confirmation(prompt));
        assert!(is_host_confirmation(
            &prompt.replace("fingerprint is ", "fingerprint is: ")
        ));
        assert!(!is_host_confirmation("root@127.0.0.1's password: "));
        assert!(!is_host_confirmation("Warning: the host key differs. Are you sure you want to continue connecting (yes/no)? "));
    }
}
