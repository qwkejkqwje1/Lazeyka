//! Windows: the service entry point, installation/uninstallation (elevated) and
//! service control used by the UI.
//!
//! Portable layout: the program runs from the folder it was unpacked to (its "home").
//! The service is registered with lazeyka.exe from that folder and every file the
//! program writes lives in <home>\data. Installation does not copy anything into
//! Program Files or ProgramData; it only closes the folder for changes by ordinary
//! users, because the service runs lazeyka.exe and mihomo.exe as SYSTEM.

use crate::sys::wide;
use anyhow::{Context, bail};
use lazeyka_core::{engine::Engine, ipc, store::Paths};
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, LUID, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ProgressInvokeNever, SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
    TreeResetNamedSecurityInfoW,
};
use windows::Win32::Security::{
    ACL, AdjustTokenPrivileges, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation,
    LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SE_PRIVILEGE_ENABLED, SE_RESTORE_NAME, SE_TAKE_OWNERSHIP_NAME, TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY,
    TokenElevation, UNPROTECTED_DACL_SECURITY_INFORMATION,
};
use windows::Win32::Storage::FileSystem::{GetDriveTypeW, GetVolumeInformationW, GetVolumePathNameW, MOVEFILE_DELAY_UNTIL_REBOOT, MoveFileExW};
use windows::Win32::System::Registry::{HKEY_LOCAL_MACHINE, RegDeleteTreeW};
use windows::Win32::System::Services::{SC_HANDLE, SetServiceObjectSecurity};
use windows::Win32::System::Threading::{GetCurrentProcess, GetExitCodeProcess, INFINITE, OpenProcessToken, WaitForSingleObject};
use windows::Win32::UI::Shell::{SEE_MASK_NOASYNC, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW};
use windows::Win32::UI::WindowsAndMessaging::{IDYES, MB_ICONINFORMATION, MB_ICONQUESTION, MB_OK, MB_YESNO, MessageBoxW, SW_HIDE};
use windows::core::{PCWSTR, w};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceControl, ServiceControlAccept, ServiceErrorControl, ServiceExitCode,
    ServiceFailureActions, ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceStatus, ServiceType,
};
use windows_service::service_control_handler::{self, ServiceControlHandlerResult};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_service::{define_windows_service, service_dispatcher};

pub const SERVICE: &str = "Lazeyka";
const DISPLAY: &str = "Лазейка VPN";
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Files of the program: (name, required). An update copies them into the home folder.
const FILES: [(&str, bool); 6] = [
    ("lazeyka.exe", true),
    ("mihomo.exe", true),
    ("dbip-country-lite.mmdb", false),
    ("LICENSE.txt", false),
    ("THIRD-PARTY.txt", false),
    ("README.txt", false),
];
/// 0.1 installed itself into Program Files, kept data in ProgramData and registered
/// a Start menu shortcut and an "Apps & features" entry.
const LEGACY_UNINSTALL_KEY: &str = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Lazeyka";
const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_REMOTE: u32 = 4;
const DRIVE_CDROM: u32 = 5;
const FILE_PERSISTENT_ACLS: u32 = 8;

fn env_dir(var: &str, fallback: &str) -> PathBuf {
    std::env::var_os(var).map(PathBuf::from).unwrap_or_else(|| PathBuf::from(fallback))
}

/// Folder of the running exe.
pub fn exe_dir() -> PathBuf {
    std::env::current_exe().ok().and_then(|p| p.parent().map(Path::to_path_buf)).unwrap_or_else(|| PathBuf::from("."))
}

/// Settings, servers and logs: "data" next to lazeyka.exe (SYSTEM and Administrators only).
pub fn data_dir() -> PathBuf {
    exe_dir().join("data")
}

fn legacy_program_dir() -> PathBuf {
    let base = std::env::var_os("ProgramW6432").or_else(|| std::env::var_os("ProgramFiles")).map(PathBuf::from);
    base.unwrap_or_else(|| PathBuf::from("C:\\Program Files")).join("Lazeyka")
}

fn legacy_data_dir() -> PathBuf {
    env_dir("ProgramData", "C:\\ProgramData").join("Lazeyka")
}

fn legacy_start_menu_link() -> PathBuf {
    env_dir("ProgramData", "C:\\ProgramData").join("Microsoft\\Windows\\Start Menu\\Programs\\Лазейка.lnk")
}

/// Normalised path for comparisons without touching the disk.
fn path_key(p: &Path) -> String {
    let s = p.to_string_lossy().replace('/', "\\");
    let s = s.strip_prefix("\\\\?\\").unwrap_or(&s).to_string();
    s.trim_end_matches('\\').to_lowercase()
}

/// `a` is `b` or lies inside it.
fn within(a: &Path, b: &Path) -> bool {
    let (a, b) = (path_key(a), path_key(b));
    !b.is_empty() && (a == b || a.starts_with(&format!("{b}\\")))
}

pub fn same_path(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(x), Ok(y)) => x == y,
        _ => path_key(a) == path_key(b),
    }
}

/// `"C:\x\lazeyka.exe" --service` → `C:\x\lazeyka.exe`.
fn command_exe(cmd: &str) -> PathBuf {
    let c = cmd.trim();
    if let Some(rest) = c.strip_prefix('"') {
        return PathBuf::from(rest.split('"').next().unwrap_or(""));
    }
    match c.to_ascii_lowercase().find(".exe") {
        Some(i) => PathBuf::from(&c[..i + 4]),
        None => PathBuf::from(c.split(' ').next().unwrap_or("")),
    }
}

/// The exe the service is registered with (None if there is no service).
pub fn service_exe() -> Option<PathBuf> {
    let m = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT).ok()?;
    let s = m.open_service(SERVICE, ServiceAccess::QUERY_CONFIG).ok()?;
    let cfg = s.query_config().ok()?;
    Some(command_exe(&cfg.executable_path.to_string_lossy()))
}

/// The 0.1 layout: the service runs from Program Files and keeps its data in ProgramData.
fn is_legacy(exe: &Path) -> bool {
    within(exe, &legacy_program_dir()) && !exe.parent().is_some_and(|d| d.join("data").is_dir())
}

/// Folder the installed program runs from.
pub fn home_dir() -> Option<PathBuf> {
    service_exe().filter(|e| !is_legacy(e) && e.exists()).and_then(|e| e.parent().map(Path::to_path_buf))
}

/// The installed exe (the one the service and autostart use), if it is in place.
pub fn home_exe() -> Option<PathBuf> {
    service_exe().filter(|e| !is_legacy(e) && e.exists())
}

/// Folder `--install` will use and whether it becomes the home for the first time
/// (the UI then checks that the place is suitable).
pub fn planned_home() -> (PathBuf, bool) {
    match home_dir() {
        Some(h) => (h, false),
        None => (exe_dir(), true),
    }
}

/// Is a folder a good home for the program?
#[derive(Debug, Default)]
pub struct Place {
    /// Installation is not possible there.
    pub blocker: Option<String>,
    /// Possible, but the user should know.
    pub risks: Vec<String>,
}

/// Entries of `dir` that do not belong to Лазейка.
fn foreign_entries(dir: &Path) -> Vec<String> {
    let me = std::env::current_exe().ok().and_then(|p| p.file_name().map(|n| n.to_string_lossy().to_lowercase()));
    let stems: Vec<String> = FILES.iter().map(|(n, _)| n.split('.').next().unwrap_or("").to_lowercase()).collect();
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else { return out };
    for e in rd.flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        let l = name.to_lowercase();
        let stem = l.split('.').next().unwrap_or("");
        let ours = l == "data"
            || me.as_deref() == Some(l.as_str())
            || stems.iter().any(|s| s == stem)
            || l.starts_with("lazeyka")
            || l == "desktop.ini"
            || l == "thumbs.db";
        if !ours {
            out.push(name);
        }
    }
    out.sort();
    out
}

fn volume_root(dir: &Path) -> Option<Vec<u16>> {
    let p = wide(&dir.to_string_lossy());
    let mut buf = [0u16; 600];
    unsafe { GetVolumePathNameW(PCWSTR(p.as_ptr()), &mut buf) }.ok()?;
    let n = buf.iter().position(|&c| c == 0)?;
    Some(buf[..=n].to_vec())
}

pub fn assess(dir: &Path) -> Place {
    let shown = {
        let s = dir.display().to_string();
        s.strip_prefix("\\\\?\\").map(str::to_string).unwrap_or(s)
    };
    let blocked = |m: String| Place { blocker: Some(m), risks: Vec::new() };
    let hint = "например C:\\Lazeyka";
    let raw = dir.to_string_lossy().replace('/', "\\");
    if raw.starts_with("\\\\") && !raw.starts_with("\\\\?\\") {
        return blocked(format!("Программа запущена из сетевой папки ({shown}). Служба не может работать оттуда: скопируйте папку Лазейки на этот компьютер, {hint}, и запустите lazeyka.exe оттуда."));
    }
    let mut risks = Vec::new();
    if let Some(root) = volume_root(dir) {
        let t = unsafe { GetDriveTypeW(PCWSTR(root.as_ptr())) };
        match t {
            DRIVE_REMOTE => {
                return blocked(format!("Программа запущена с сетевого диска ({shown}). Служба не может работать оттуда: скопируйте папку Лазейки на этот компьютер, {hint}, и запустите lazeyka.exe оттуда."));
            }
            DRIVE_CDROM => {
                return blocked(format!("Программа запущена с диска только для чтения ({shown}). Скопируйте папку Лазейки на этот компьютер, {hint}, и запустите lazeyka.exe оттуда."));
            }
            DRIVE_REMOVABLE => risks.push("Папка на съёмном диске: без него VPN не запустится.".to_string()),
            _ => {}
        }
        let root_s = String::from_utf16_lossy(&root[..root.len() - 1]);
        if path_key(dir) == path_key(Path::new(&root_s)) {
            return blocked(format!("Программа лежит прямо в корне диска ({shown}). Создайте для неё отдельную папку, {hint}, перенесите туда файлы Лазейки и запустите lazeyka.exe оттуда."));
        }
        let mut flags = 0u32;
        let mut fs = [0u16; 64];
        if unsafe { GetVolumeInformationW(PCWSTR(root.as_ptr()), None, None, None, Some(&mut flags), Some(&mut fs)) }.is_ok() && flags & FILE_PERSISTENT_ACLS == 0 {
            let n = fs.iter().position(|&c| c == 0).unwrap_or(fs.len());
            risks.push(format!(
                "Диск отформатирован в {} — без прав доступа к файлам: любая программа сможет подменить файлы службы.",
                String::from_utf16_lossy(&fs[..n])
            ));
        }
    }
    if !dir.join("mihomo.exe").exists() {
        return blocked(format!("Рядом с lazeyka.exe нет файла mihomo.exe. Похоже, программа запущена прямо из архива: распакуйте его целиком («Извлечь всё…») в отдельную папку, {hint}, и запустите lazeyka.exe оттуда."));
    }
    let foreign = foreign_entries(dir);
    if !foreign.is_empty() {
        let list: Vec<String> = foreign.iter().take(3).map(|n| format!("«{n}»")).collect();
        let more = if foreign.len() > 3 { format!(" и ещё {}", foreign.len() - 3) } else { String::new() };
        return blocked(format!(
            "В папке {shown} есть посторонние файлы: {}{more}. Лазейке нужна отдельная папка — после установки её смогут менять только администраторы. Перенесите файлы Лазейки в пустую папку, {hint}, и запустите lazeyka.exe оттуда.",
            list.join(", ")
        ));
    }
    let users = std::env::var_os("USERPROFILE").map(PathBuf::from).and_then(|p| p.parent().map(Path::to_path_buf)).unwrap_or_else(|| PathBuf::from("C:\\Users"));
    let temp = std::env::temp_dir();
    if within(dir, &users) || within(dir, &temp) {
        risks.push("Папка находится в профиле пользователя. Программы, запущенные от вашего имени, смогут переместить её и подменить файлы службы, которая работает с правами системы.".to_string());
    }
    Place { blocker: None, risks }
}

// ------------------------------------------------------------------ service

define_windows_service!(ffi_service_main, service_main);

pub fn run_service() -> anyhow::Result<()> {
    service_dispatcher::start(SERVICE, ffi_service_main).context("service dispatcher")?;
    Ok(())
}

fn service_main(_args: Vec<OsString>) {
    if let Err(e) = service_body() {
        let _ = std::fs::create_dir_all(data_dir());
        let _ = std::fs::write(data_dir().join("service-error.log"), format!("{e:#}"));
    }
}

fn service_body() -> anyhow::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<()>();
    let handler = move |c: ServiceControl| -> ServiceControlHandlerResult {
        match c {
            ServiceControl::Stop | ServiceControl::Shutdown | ServiceControl::Preshutdown => {
                let _ = tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };
    let h = service_control_handler::register(SERVICE, handler)?;
    let status = |state: ServiceState, accept: ServiceControlAccept, wait: Duration| ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: state,
        controls_accepted: accept,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: wait,
        process_id: None,
    };
    h.set_service_status(status(ServiceState::Running, ServiceControlAccept::STOP | ServiceControlAccept::SHUTDOWN, Duration::ZERO))?;
    let data = data_dir();
    std::fs::create_dir_all(&data)?;
    let _ = set_private_dacl(&data);
    let bin = exe_dir();
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    rt.block_on(async {
        lazeyka_core::init();
        let engine = Engine::new(Paths { data, bin }, VERSION);
        engine.start();
        let e2 = engine.clone();
        let srv = tokio::spawn(async move { ipc::serve(e2, ipc::DEFAULT_PATH).await });
        tokio::select! {
            _ = rx.recv() => {}
            r = srv => engine.log(&format!("IPC остановлен: {r:?}")),
        }
        let _ = h.set_service_status(status(ServiceState::StopPending, ServiceControlAccept::empty(), Duration::from_secs(10)));
        engine.shutdown().await;
    });
    h.set_service_status(status(ServiceState::Stopped, ServiceControlAccept::empty(), Duration::ZERO))?;
    Ok(())
}

// ------------------------------------------------------------------ service control (UI side)

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Svc {
    Missing,
    Stopped,
    Pending,
    Running,
    Unknown,
}

pub fn service_state() -> Svc {
    let Ok(m) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) else { return Svc::Unknown };
    match m.open_service(SERVICE, ServiceAccess::QUERY_STATUS) {
        Ok(s) => match s.query_status().map(|st| st.current_state) {
            Ok(ServiceState::Running) => Svc::Running,
            Ok(ServiceState::Stopped) => Svc::Stopped,
            Ok(_) => Svc::Pending,
            Err(_) => Svc::Unknown,
        },
        Err(windows_service::Error::Winapi(e)) if e.raw_os_error() == Some(1060) => Svc::Missing,
        Err(_) => Svc::Unknown,
    }
}

/// Starts the installed service (allowed for interactive users by the service DACL).
pub fn start_service() -> anyhow::Result<()> {
    let m = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)?;
    let s = m.open_service(SERVICE, ServiceAccess::START | ServiceAccess::QUERY_STATUS)?;
    if s.query_status()?.current_state != ServiceState::Running {
        s.start(&[] as &[&OsStr])?;
    }
    Ok(())
}

pub fn is_elevated() -> bool {
    unsafe {
        let mut tok = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok).is_err() {
            return false;
        }
        let mut el = TOKEN_ELEVATION::default();
        let mut len = 0u32;
        let ok = GetTokenInformation(tok, TokenElevation, Some(&mut el as *mut _ as *mut _), std::mem::size_of::<TOKEN_ELEVATION>() as u32, &mut len).is_ok();
        let _ = CloseHandle(tok);
        ok && el.TokenIsElevated != 0
    }
}

/// Runs this exe elevated (UAC prompt) and waits. Err("cancelled") if the user declined.
pub fn run_elevated(params: &str) -> Result<u32, String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let file = wide(&exe.to_string_lossy());
    let p = wide(params);
    let mut sei = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC,
        lpVerb: w!("runas"),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(p.as_ptr()),
        nShow: SW_HIDE.0,
        ..Default::default()
    };
    unsafe {
        if let Err(e) = ShellExecuteExW(&mut sei) {
            return Err(if e.code().0 as u32 & 0xFFFF == 1223 { "cancelled".into() } else { e.message() });
        }
        if sei.hProcess.is_invalid() {
            return Err("no process".into());
        }
        WaitForSingleObject(sei.hProcess, INFINITE);
        let mut code = 1u32;
        let _ = GetExitCodeProcess(sei.hProcess, &mut code);
        let _ = CloseHandle(sei.hProcess);
        Ok(code)
    }
}

// ------------------------------------------------------------------ security helpers

struct Sd(PSECURITY_DESCRIPTOR);
impl Drop for Sd {
    fn drop(&mut self) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(self.0.0)));
        }
    }
}

fn sd_from_sddl(sddl: &str) -> anyhow::Result<Sd> {
    let w = wide(sddl);
    let mut sd = PSECURITY_DESCRIPTOR::default();
    unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(w.as_ptr()), SDDL_REVISION_1, &mut sd, None) }.context("SDDL")?;
    Ok(Sd(sd))
}

/// The DACL of `sd`; never NULL (a NULL DACL would mean "full access for everyone").
fn dacl_of(sd: &Sd) -> anyhow::Result<*mut ACL> {
    let mut present = Default::default();
    let mut defaulted = Default::default();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    unsafe { GetSecurityDescriptorDacl(sd.0, &mut present, &mut dacl, &mut defaulted) }.context("dacl")?;
    if !present.as_bool() || dacl.is_null() {
        bail!("пустой DACL");
    }
    Ok(dacl)
}

fn owner_of(sd: &Sd) -> anyhow::Result<PSID> {
    let mut owner = PSID::default();
    let mut defaulted = Default::default();
    unsafe { GetSecurityDescriptorOwner(sd.0, &mut owner, &mut defaulted) }.context("owner")?;
    if owner.is_invalid() {
        bail!("нет владельца");
    }
    Ok(owner)
}

/// SYSTEM and Administrators only (server credentials, the WARP key). Owner: Administrators.
pub fn set_private_dacl(path: &Path) -> anyhow::Result<()> {
    let sd = sd_from_sddl("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")?;
    let (owner, dacl) = (owner_of(&sd)?, dacl_of(&sd)?);
    let p = wide(&path.to_string_lossy());
    let info = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
    let mut r = unsafe { SetNamedSecurityInfoW(PCWSTR(p.as_ptr()), SE_FILE_OBJECT, info | OWNER_SECURITY_INFORMATION, Some(owner), None, Some(dacl), None) };
    if r.is_err() {
        r = unsafe { SetNamedSecurityInfoW(PCWSTR(p.as_ptr()), SE_FILE_OBJECT, info, None, None, Some(dacl), None) };
    }
    if r.is_err() {
        bail!("SetNamedSecurityInfo: {}", r.0);
    }
    Ok(())
}

/// The service runs files from the home folder as SYSTEM, so only administrators may
/// change them: owner Administrators, users read and execute, nothing inherited from
/// the parent (e.g. "Authenticated Users: modify" of folders created in C:\).
fn protect_home(home: &Path, data: &Path) -> anyhow::Result<()> {
    let sd = sd_from_sddl("O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)")?;
    let (owner, dacl) = (owner_of(&sd)?, dacl_of(&sd)?);
    let p = wide(&home.to_string_lossy());
    let r = unsafe {
        TreeResetNamedSecurityInfoW(
            PCWSTR(p.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            Some(owner),
            None,
            Some(dacl),
            None,
            false,
            None,
            ProgressInvokeNever,
            None,
        )
    };
    if r.is_err() {
        bail!("код ошибки {}", r.0);
    }
    set_private_dacl(data)
}

/// Undoes `protect_home`: the folder and its files inherit the parent's permissions again.
fn unprotect_home(home: &Path) -> anyhow::Result<()> {
    // an empty (not NULL) DACL: with UNPROTECTED only the inherited entries remain
    let sd = sd_from_sddl("D:")?;
    let dacl = dacl_of(&sd)?;
    let p = wide(&home.to_string_lossy());
    let r = unsafe {
        TreeResetNamedSecurityInfoW(
            PCWSTR(p.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(dacl),
            None,
            false,
            None,
            ProgressInvokeNever,
            None,
        )
    };
    if r.is_err() {
        bail!("код ошибки {}", r.0);
    }
    Ok(())
}

/// Lets an elevated administrator take over files owned by someone else.
fn enable_privileges() {
    unsafe {
        let mut tok = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &mut tok).is_err() {
            return;
        }
        for name in [SE_TAKE_OWNERSHIP_NAME, SE_RESTORE_NAME] {
            let mut luid = LUID::default();
            if LookupPrivilegeValueW(PCWSTR::null(), name, &mut luid).is_ok() {
                let tp = TOKEN_PRIVILEGES { PrivilegeCount: 1, Privileges: [LUID_AND_ATTRIBUTES { Luid: luid, Attributes: SE_PRIVILEGE_ENABLED }] };
                let _ = AdjustTokenPrivileges(tok, false, Some(&tp), 0, None, None);
            }
        }
        let _ = CloseHandle(tok);
    }
}

/// Lets interactive users start the service and query it (no stop/config rights).
fn set_service_dacl(h: SC_HANDLE) -> anyhow::Result<()> {
    let sd = sd_from_sddl("D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWRPLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)")?;
    unsafe { SetServiceObjectSecurity(h, DACL_SECURITY_INFORMATION, sd.0) }.context("SetServiceObjectSecurity")?;
    Ok(())
}

// ------------------------------------------------------------------ install / uninstall

fn wait_state(s: &windows_service::service::Service, want: ServiceState, t: Duration) -> bool {
    let until = Instant::now() + t;
    while Instant::now() < until {
        if s.query_status().map(|st| st.current_state == want).unwrap_or(false) {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

fn delete_later(p: &Path) {
    let o = wide(&p.to_string_lossy());
    unsafe {
        let _ = MoveFileExW(PCWSTR(o.as_ptr()), PCWSTR::null(), MOVEFILE_DELAY_UNTIL_REBOOT);
    }
}

/// Replaces `to` with `from`. A locked target (running exe) is renamed away first.
fn replace_file(from: &Path, to: &Path) -> anyhow::Result<()> {
    let tmp = to.with_extension("new");
    std::fs::copy(from, &tmp).with_context(|| format!("копирование {}", from.display()))?;
    if to.exists() && std::fs::remove_file(to).is_err() {
        let old = to.with_extension(format!("old{}", std::process::id()));
        std::fs::rename(to, &old).with_context(|| format!("файл занят: {}", to.display()))?;
        if std::fs::remove_file(&old).is_err() {
            delete_later(&old);
        }
    }
    std::fs::rename(&tmp, to).with_context(|| format!("замена {}", to.display()))?;
    Ok(())
}

/// Removes a folder; files still in use (e.g. a window of another user) go after a reboot.
fn remove_dir_now_or_later(dir: &Path) {
    if std::fs::remove_dir_all(dir).is_ok() || !dir.exists() {
        return;
    }
    fn walk(d: &Path) {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let p = e.path();
                if e.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                    walk(&p);
                } else if std::fs::remove_file(&p).is_err() {
                    delete_later(&p);
                }
            }
        }
        if std::fs::remove_dir(d).is_err() {
            delete_later(d);
        }
    }
    walk(dir);
}

/// 0.1 → 0.2: settings, servers and the WARP account move from ProgramData into the
/// new data folder (unless it already has its own).
fn migrate_legacy_data(data: &Path) -> bool {
    let old = legacy_data_dir();
    if !old.is_dir() || data.join("settings.json").exists() || data.join("servers.json").exists() {
        return false;
    }
    let mut any = false;
    for f in ["settings.json", "servers.json", "warp.json", "sources.json"] {
        let from = old.join(f);
        if from.is_file() && std::fs::copy(&from, data.join(f)).is_ok() {
            any = true;
        }
    }
    any
}

/// Leftovers of the 0.1 installation: Program Files copy, ProgramData, Start menu
/// shortcut and the "Apps & features" entry.
fn remove_legacy(home: &Path) {
    let _ = std::fs::remove_file(legacy_start_menu_link());
    let k = wide(LEGACY_UNINSTALL_KEY);
    unsafe {
        let _ = RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(k.as_ptr()));
    }
    let data = legacy_data_dir();
    if data.exists() && !within(home, &data) {
        remove_dir_now_or_later(&data);
    }
    let prog = legacy_program_dir();
    if prog.exists() && !within(home, &prog) {
        remove_dir_now_or_later(&prog);
    }
}

/// `--install [--result FILE]`: registers (or updates) the service. An update started
/// from a new copy of the program copies its files into the folder the service already
/// runs from; otherwise the folder of this exe becomes the program's home.
/// Exit code 0 — done, 3 — done with a warning (text in FILE), 1 — error (text in FILE).
pub fn install(args: &[String]) -> i32 {
    let result = args.iter().position(|a| a == "--result").and_then(|i| args.get(i + 1)).cloned();
    let write = |text: String| {
        if let Some(f) = &result {
            let _ = std::fs::write(f, text);
        }
    };
    match install_inner() {
        Ok(warn) if warn.is_empty() => 0,
        Ok(warn) => {
            write(warn.join("\n"));
            3
        }
        Err(e) => {
            write(format!("{e:#}"));
            1
        }
    }
}

fn install_inner() -> anyhow::Result<Vec<String>> {
    if !is_elevated() {
        bail!("нужны права администратора");
    }
    enable_privileges();
    let mut warn = Vec::new();
    let src_exe = std::env::current_exe()?;
    let src_dir = src_exe.parent().map(Path::to_path_buf).context("папка программы")?;
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE)?;
    let access = ServiceAccess::QUERY_STATUS
        | ServiceAccess::QUERY_CONFIG
        | ServiceAccess::START
        | ServiceAccess::STOP
        | ServiceAccess::CHANGE_CONFIG
        | ServiceAccess::WRITE_DAC
        | ServiceAccess::READ_CONTROL;
    let existing = mgr.open_service(SERVICE, access).ok();
    let old_exe = existing.as_ref().and_then(|s| s.query_config().ok()).map(|c| command_exe(&c.executable_path.to_string_lossy()));
    // where the program lives from now on
    let target = match &old_exe {
        Some(e) if !is_legacy(e) && e.exists() && !same_path(e, &src_exe) => Some(e.clone()),
        _ => None,
    };
    let (home, exe) = match &target {
        Some(e) => (e.parent().map(Path::to_path_buf).context("папка программы")?, e.clone()),
        None => (src_dir.clone(), src_exe.clone()),
    };
    let copy = target.is_some() && !same_path(&home, &src_dir);
    if !copy {
        if let Some(b) = assess(&home).blocker {
            bail!("{b}");
        }
    }
    if let Some(s) = &existing {
        if s.query_status().map(|st| st.current_state != ServiceState::Stopped).unwrap_or(false) {
            let _ = s.stop();
            wait_state(s, ServiceState::Stopped, Duration::from_secs(20));
            std::thread::sleep(Duration::from_millis(500));
        }
    }
    if copy {
        for (name, required) in FILES {
            let (from, to) = if name == "lazeyka.exe" { (src_exe.clone(), exe.clone()) } else { (src_dir.join(name), home.join(name)) };
            if !from.exists() {
                if required && !to.exists() {
                    bail!("рядом с программой нет файла {name}");
                }
                continue;
            }
            replace_file(&from, &to)?;
        }
    }
    let data = home.join("data");
    std::fs::create_dir_all(&data).context("папка данных")?;
    migrate_legacy_data(&data);
    if let Err(e) = protect_home(&home, &data) {
        warn.push(format!("Служба установлена, но папку программы не удалось закрыть от изменений ({e:#})."));
    }
    let info = ServiceInfo {
        name: SERVICE.into(),
        display_name: DISPLAY.into(),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: exe.clone(),
        launch_arguments: vec!["--service".into()],
        dependencies: vec![],
        account_name: None,
        account_password: None,
    };
    let svc = match existing {
        Some(s) => {
            s.change_config(&info)?;
            s
        }
        None => mgr.create_service(&info, access)?,
    };
    let _ = svc.set_description("Служба VPN-клиента «Лазейка»: туннель, проверка серверов и раздельное туннелирование.");
    let _ = svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(Duration::from_secs(86400)),
        reboot_msg: None,
        command: None,
        actions: Some(vec![
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(2) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(10) },
            ServiceAction { action_type: ServiceActionType::Restart, delay: Duration::from_secs(60) },
        ]),
    });
    let _ = svc.set_failure_actions_on_non_crash_failures(true);
    set_service_dacl(SC_HANDLE(svc.raw_handle() as *mut _))?;
    svc.start(&[] as &[&OsStr]).context("запуск службы")?;
    if !wait_state(&svc, ServiceState::Running, Duration::from_secs(15)) {
        bail!("служба не запустилась");
    }
    remove_legacy(&home);
    Ok(warn)
}

fn message(text: &str, flags: windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_STYLE) -> windows::Win32::UI::WindowsAndMessaging::MESSAGEBOX_RESULT {
    let t = wide(text);
    unsafe { MessageBoxW(None, PCWSTR(t.as_ptr()), w!("Лазейка"), flags) }
}

/// `--uninstall [--quiet]`: removes the service, autostart and all data, and gives the
/// folder its usual permissions back. The program files stay where they are.
pub fn uninstall(args: &[String]) -> i32 {
    let quiet = args.iter().any(|a| a == "--quiet");
    if !is_elevated() {
        return match run_elevated(if quiet { "--uninstall --quiet" } else { "--uninstall" }) {
            Ok(c) => c as i32,
            Err(_) => 1,
        };
    }
    if !quiet
        && message(
            "Удалить Лазейку?\nVPN будет отключён, служба удалена, настройки и список серверов стёрты. Файлы программы останутся в папке.",
            MB_YESNO | MB_ICONQUESTION,
        ) != IDYES
    {
        return 2;
    }
    enable_privileges();
    crate::sys::signal_quit();
    let svc_exe = service_exe();
    let home = svc_exe.as_ref().filter(|e| !is_legacy(e)).and_then(|e| e.parent().map(Path::to_path_buf)).unwrap_or_else(exe_dir);
    if let Ok(mgr) = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT) {
        if let Ok(s) = mgr.open_service(SERVICE, ServiceAccess::QUERY_STATUS | ServiceAccess::STOP | ServiceAccess::DELETE) {
            if s.query_status().map(|st| st.current_state != ServiceState::Stopped).unwrap_or(false) {
                let _ = s.stop();
                wait_state(&s, ServiceState::Stopped, Duration::from_secs(20));
            }
            let _ = s.delete();
        }
    }
    crate::sys::set_autostart(false, Path::new(""));
    std::thread::sleep(Duration::from_millis(500));
    let data = home.join("data");
    let ours = data.is_dir() || svc_exe.as_ref().is_some_and(|e| within(e, &home));
    for _ in 0..6 {
        if !data.exists() || std::fs::remove_dir_all(&data).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    let mut ok = !data.exists();
    if ours && foreign_entries(&home).is_empty() && !within(&home, &legacy_program_dir()) {
        ok &= unprotect_home(&home).is_ok();
    }
    remove_legacy(&home);
    if !quiet {
        message(&format!("Лазейка удалена.\nФайлы программы остались в папке {} — её можно удалить.", home.display()), MB_OK | MB_ICONINFORMATION);
    }
    if ok { 0 } else { 1 }
}
