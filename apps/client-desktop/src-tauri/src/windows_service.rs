use std::{
    io,
    ptr::{null, null_mut},
    time::{Duration, Instant},
};
use windows_sys::{
    core::w,
    Win32::{
        Foundation::{
            CloseHandle, LocalFree, ERROR_SERVICE_ALREADY_RUNNING, ERROR_SERVICE_NOT_ACTIVE,
        },
        Security::{Authorization::*, *},
        System::{
            Services::*,
            Threading::{OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION},
        },
        UI::WindowsAndMessaging::{GetShellWindow, GetWindowThreadProcessId},
    },
};

const RESTART_RIGHTS: u32 = SERVICE_QUERY_STATUS | SERVICE_START | SERVICE_STOP;

struct Service(SC_HANDLE);
impl Drop for Service {
    fn drop(&mut self) {
        unsafe {
            CloseServiceHandle(self.0);
        }
    }
}

fn open(access: u32) -> io::Result<Service> {
    unsafe {
        let manager = OpenSCManagerW(null(), null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            return Err(io::Error::last_os_error());
        }
        let manager = Service(manager);
        let service = OpenServiceW(manager.0, w!("calabi"), access);
        if service.is_null() {
            return Err(io::Error::last_os_error());
        }
        Ok(Service(service))
    }
}

fn check(code: u32) -> io::Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(code as i32))
    }
}

// Identify only the current desktop's shell owner, including when another
// account supplied the installer's elevation credentials. Session-0 installs
// without an interactive shell leave existing service permissions untouched.
fn desktop_user() -> io::Result<Option<Vec<usize>>> {
    unsafe {
        let shell = GetShellWindow();
        if shell.is_null() {
            return Ok(None);
        }
        let mut pid = 0;
        if GetWindowThreadProcessId(shell, &mut pid) == 0 {
            return Err(io::Error::last_os_error());
        }
        let process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if process.is_null() {
            return Err(io::Error::last_os_error());
        }
        let user = process_user(process);
        CloseHandle(process);
        user.map(Some)
    }
}

pub fn process_user(process: windows_sys::Win32::Foundation::HANDLE) -> io::Result<Vec<usize>> {
    unsafe {
        let mut token = null_mut();
        let opened = OpenProcessToken(process, TOKEN_QUERY, &mut token);
        if opened == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut bytes = 0;
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut bytes);
        let mut buffer = vec![0usize; (bytes as usize).div_ceil(std::mem::size_of::<usize>())];
        let read = GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            bytes,
            &mut bytes,
        );
        let error = io::Error::last_os_error();
        CloseHandle(token);
        if read == 0 {
            return Err(error);
        }
        Ok(buffer)
    }
}

// The service may already exist on upgrade. Update its visible metadata
// through SCM without reinstalling it or altering its startup configuration.
pub fn configure_installed_service() -> io::Result<()> {
    let service = open(SERVICE_CHANGE_CONFIG)?;
    unsafe {
        if ChangeServiceConfigW(
            service.0,
            SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE,
            SERVICE_NO_CHANGE,
            null(),
            null(),
            null_mut(),
            null(),
            null(),
            null(),
            w!("Calabi Client Service"),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
        let description = SERVICE_DESCRIPTIONW {
            lpDescription: w!("Runs Calabi network connections and endpoints in the background.")
                .cast_mut(),
        };
        if ChangeServiceConfig2W(
            service.0,
            SERVICE_CONFIG_DESCRIPTION,
            (&description as *const SERVICE_DESCRIPTIONW).cast(),
        ) == 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    configure_restart_access()
}

// Only the elevated installer calls this fixed operation. The ACL and
// descriptor are managed by Windows; pass back only the modified DACL.
fn configure_restart_access() -> io::Result<()> {
    let Some(buffer) = desktop_user()? else {
        return Ok(());
    };
    let principal = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    const READ_CONTROL: u32 = 0x20000;
    const WRITE_DAC: u32 = 0x40000;
    let service = open(READ_CONTROL | WRITE_DAC)?;
    unsafe {
        let mut acl = null_mut();
        let mut descriptor = null_mut();
        check(GetSecurityInfo(
            service.0,
            SE_SERVICE,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut acl,
            null_mut(),
            &mut descriptor,
        ))?;
        let result = if acl.is_null() {
            Ok(())
        } else {
            grant_restart(service.0, acl, principal)
        };
        LocalFree(descriptor);
        result
    }
}

unsafe fn grant_restart(service: SC_HANDLE, acl: *mut ACL, sid: PSID) -> io::Result<()> {
    for index in 0..(*acl).AceCount {
        let mut raw = null_mut();
        if GetAce(acl, index.into(), &mut raw) == 0 {
            return Err(io::Error::last_os_error());
        }
        let header = &*raw.cast::<ACE_HEADER>();
        if header.AceType == 0 && header.AceFlags == 0 {
            // ACCESS_ALLOWED_ACE_TYPE
            let ace = &*raw.cast::<ACCESS_ALLOWED_ACE>();
            if ace.Mask & RESTART_RIGHTS == RESTART_RIGHTS
                && EqualSid(sid, std::ptr::addr_of!(ace.SidStart) as PSID) != 0
            {
                return Ok(());
            }
        }
    }
    let mut entry = EXPLICIT_ACCESS_W::default();
    entry.grfAccessPermissions = RESTART_RIGHTS;
    entry.grfAccessMode = GRANT_ACCESS;
    entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    entry.Trustee.TrusteeType = TRUSTEE_IS_USER;
    entry.Trustee.ptstrName = sid.cast();
    let mut merged = null_mut();
    check(SetEntriesInAclW(1, &entry, acl, &mut merged))?;
    let result = check(SetSecurityInfo(
        service,
        SE_SERVICE,
        DACL_SECURITY_INFORMATION,
        null_mut(),
        null_mut(),
        merged,
        null(),
    ));
    LocalFree(merged.cast());
    result
}

pub fn restart() -> io::Result<()> {
    let service = open(RESTART_RIGHTS)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut stop_sent = false;
    loop {
        let mut status = SERVICE_STATUS::default();
        if unsafe { QueryServiceStatus(service.0, &mut status) } == 0 {
            return Err(io::Error::last_os_error());
        }
        match status.dwCurrentState {
            SERVICE_STOPPED => break,
            SERVICE_RUNNING | SERVICE_PAUSED if !stop_sent => {
                if unsafe { ControlService(service.0, SERVICE_CONTROL_STOP, &mut status) } == 0 {
                    let error = io::Error::last_os_error();
                    if error.raw_os_error() != Some(ERROR_SERVICE_NOT_ACTIVE as i32) {
                        return Err(error);
                    }
                }
                stop_sent = true;
            }
            _ => {}
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "Timed out waiting for calabi to stop",
            ));
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    if unsafe { StartServiceW(service.0, 0, null()) } == 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(ERROR_SERVICE_ALREADY_RUNNING as i32) {
            return Err(error);
        }
    }
    Ok(())
}
