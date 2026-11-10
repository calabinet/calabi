use std::{
    ffi::c_void,
    io::{BufRead, BufReader, Read, Write},
    os::unix::net::UnixStream,
    path::Path,
    ptr,
    time::Duration,
};

use portable_pty::CommandBuilder;
use tokio::{io::AsyncWriteExt, net::UnixListener, task::JoinHandle};
use zeroize::{Zeroize, Zeroizing};

const SOCKET_ENV: &str = "CALABI_SSH_ASKPASS_SOCKET";
pub(super) const OWNER_ENV: &str = "CALABI_SSH_ASKPASS_OWNER";
pub const PASSWORD_LIMIT: usize = 1000;

#[derive(Clone, Copy)]
pub struct PromptOwner;

impl PromptOwner {
    pub fn new(handle: usize, pid: u32) -> Option<Self> {
        (handle == 0 && pid != 0).then_some(Self)
    }
}

pub struct Attempt {
    pub marker: String,
    broker: Option<JoinHandle<()>>,
    _directory: tempfile::TempDir,
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
        let marker = format!("CALABI_SSH_AUTH_{}", uuid::Uuid::new_v4().simple());
        // Unix socket paths are short on Darwin. The temporary directory is private
        // to the desktop user and also controls the lifetime of the confirmation alert.
        let directory = tempfile::Builder::new()
            .prefix("calabi-ssh-")
            .tempdir_in("/tmp")
            .map_err(|_| "sshConnectFailed")?;
        let socket = directory.path().join("askpass");
        let listener = UnixListener::bind(&socket).map_err(|_| "sshConnectFailed")?;
        let broker = password.map(|password| {
            let password = Zeroizing::new(password.as_bytes().to_vec());
            tokio::spawn(async move {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let _ = stream.write_all(&password).await;
                    let _ = stream.write_all(b"\n").await;
                }
            })
        });
        command.env(SOCKET_ENV, &socket);
        command.env("SSH_ASKPASS", executable);
        command.env("SSH_ASKPASS_REQUIRE", "force");
        command.env_remove("SSH_ASKPASS_PROMPT");
        command.env("LC_ALL", "C");
        if owner.is_some() {
            command.env(OWNER_ENV, "1");
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
        Ok(Self {
            marker,
            broker,
            _directory: directory,
        })
    }
}

pub fn askpass() -> Option<i32> {
    let socket = std::env::var_os(SOCKET_ENV)?;
    let socket = Path::new(&socket);
    let directory = socket.parent()?;
    if directory.parent() != Some(Path::new("/tmp"))
        || !directory.file_name()?.to_str()?.starts_with("calabi-ssh-")
        || socket.file_name()? != "askpass"
    {
        return Some(1);
    }
    let mut args = std::env::args_os().skip(1);
    let prompt = args.next()?;
    let prompt = prompt.to_str()?;
    if args.next().is_some() {
        return Some(1);
    }
    if crate::ssh::is_host_confirmation(prompt) {
        let accepted = std::env::var(OWNER_ENV).is_ok_and(|value| value == "1")
            && crate::files::rdp_helper().ok().is_some_and(|helper| {
                std::process::Command::new(helper)
                    .arg("--ssh-confirm")
                    .arg(prompt)
                    .arg(directory)
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .is_ok_and(|status| status.success())
            });
        return Some(
            if accepted && std::io::stdout().write_all(b"yes\n").is_ok() {
                0
            } else {
                1
            },
        );
    }
    if !prompt.trim_end().ends_with("'s password:") {
        return Some(1);
    }
    let result = (|| -> std::io::Result<()> {
        let stream = UnixStream::connect(socket)?;
        stream.set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut password = Zeroizing::new(Vec::new());
        BufReader::new(stream)
            .take((PASSWORD_LIMIT + 1) as u64)
            .read_until(b'\n', &mut password)?;
        if password.last() != Some(&b'\n') {
            return Err(std::io::Error::other("Invalid SSH password response"));
        }
        std::io::stdout().write_all(&password)
    })();
    Some(if result.is_ok() { 0 } else { 1 })
}

pub fn credential_name(host_key: &str, port: u16, account: &str) -> String {
    format!("Calabi/SSH/{host_key}/{port}/{account}")
}

const NOT_FOUND: i32 = -25300; // errSecItemNotFound
const USER_DOMAIN: u32 = 0; // kSecPreferencesDomainUser
const KEYCHAIN_ACCOUNT: &[u8] = b"calabi";

#[link(name = "Security", kind = "framework")]
extern "C" {
    fn SecKeychainCopyDomainDefault(domain: u32, keychain: *mut *mut c_void) -> i32;
    fn SecKeychainFindGenericPassword(
        keychain: *mut c_void,
        service_len: u32,
        service: *const u8,
        account_len: u32,
        account: *const u8,
        size: *mut u32,
        data: *mut *mut c_void,
        item: *mut *mut c_void,
    ) -> i32;
    fn SecKeychainAddGenericPassword(
        keychain: *mut c_void,
        service_len: u32,
        service: *const u8,
        account_len: u32,
        account: *const u8,
        size: u32,
        data: *const u8,
        item: *mut *mut c_void,
    ) -> i32;
    fn SecKeychainItemModifyAttributesAndData(
        item: *mut c_void,
        attributes: *const c_void,
        size: u32,
        data: *const u8,
    ) -> i32;
    fn SecKeychainItemDelete(item: *mut c_void) -> i32;
    fn SecKeychainItemFreeContent(attributes: *mut c_void, data: *mut c_void) -> i32;
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFRelease(value: *const c_void);
}

struct KeychainRef(*mut c_void);

impl Drop for KeychainRef {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) };
        }
    }
}

fn keychain() -> Result<KeychainRef, String> {
    let mut keychain = KeychainRef(ptr::null_mut());
    let status = unsafe { SecKeychainCopyDomainDefault(USER_DOMAIN, &mut keychain.0) };
    (status == 0 && !keychain.0.is_null())
        .then_some(keychain)
        .ok_or_else(|| "sshCredentialFailed".into())
}

fn find(
    keychain: &KeychainRef,
    name: &str,
    size: *mut u32,
    data: *mut *mut c_void,
) -> Result<Option<KeychainRef>, String> {
    let mut item = KeychainRef(ptr::null_mut());
    let status = unsafe {
        SecKeychainFindGenericPassword(
            keychain.0,
            name.len() as u32,
            name.as_ptr(),
            KEYCHAIN_ACCOUNT.len() as u32,
            KEYCHAIN_ACCOUNT.as_ptr(),
            size,
            data,
            &mut item.0,
        )
    };
    match status {
        0 if !item.0.is_null() => Ok(Some(item)),
        NOT_FOUND => Ok(None),
        _ => Err("sshCredentialFailed".into()),
    }
}

pub fn read_credential(name: &str) -> Result<Option<Zeroizing<String>>, String> {
    let keychain = keychain()?;
    let mut size = 0;
    let mut data = ptr::null_mut();
    let found = find(&keychain, name, &mut size, &mut data);
    let mut password = Err("sshCredentialFailed".to_owned());
    if !data.is_null() {
        let bytes = unsafe { std::slice::from_raw_parts_mut(data.cast::<u8>(), size as usize) };
        if !bytes.is_empty() && bytes.len() <= PASSWORD_LIMIT {
            password = std::str::from_utf8(bytes)
                .ok()
                .filter(|value| !value.contains(['\r', '\n', '\0']))
                .map(|value| Zeroizing::new(value.to_owned()))
                .ok_or_else(|| "sshCredentialFailed".into());
        }
        bytes.zeroize();
        unsafe { SecKeychainItemFreeContent(ptr::null_mut(), data) };
    }
    match found? {
        Some(_) => password.map(Some),
        None => Ok(None),
    }
}

pub fn save_credential(name: &str, password: &str) -> Result<(), String> {
    let keychain = keychain()?;
    let item = find(&keychain, name, ptr::null_mut(), ptr::null_mut())?;
    let size = password.len() as u32;
    let status = unsafe {
        if let Some(ref item) = item {
            SecKeychainItemModifyAttributesAndData(item.0, ptr::null(), size, password.as_ptr())
        } else {
            SecKeychainAddGenericPassword(
                keychain.0,
                name.len() as u32,
                name.as_ptr(),
                KEYCHAIN_ACCOUNT.len() as u32,
                KEYCHAIN_ACCOUNT.as_ptr(),
                size,
                password.as_ptr(),
                ptr::null_mut(),
            )
        }
    };
    (status == 0)
        .then_some(())
        .ok_or_else(|| "sshCredentialFailed".into())
}

pub fn clear_credential(name: &str) -> Result<(), String> {
    let keychain = keychain()?;
    let Some(item) = find(&keychain, name, ptr::null_mut(), ptr::null_mut())? else {
        return Ok(());
    };
    let status = unsafe { SecKeychainItemDelete(item.0) };
    (status == 0 || status == NOT_FOUND)
        .then_some(())
        .ok_or_else(|| "sshCredentialFailed".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn password_broker_is_private_and_removed_with_the_attempt() {
        use std::os::unix::fs::PermissionsExt;

        let mut command = CommandBuilder::new("/usr/bin/ssh");
        let attempt = Attempt::configure(
            &mut command,
            Some("fixture-password"),
            Path::new("/tmp/calabi-desktop-fixture"),
            None,
        )
        .unwrap();
        let directory = attempt._directory.path().to_owned();
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o077,
            0
        );
        let mut stream = tokio::net::UnixStream::connect(directory.join("askpass"))
            .await
            .unwrap();
        let mut password = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut password))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(password, b"fixture-password\n");
        drop(attempt);
        assert!(!directory.exists());
    }
}
