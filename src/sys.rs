//! Small platform helpers used by the UI: clipboard, file dialogs, process list,
//! autostart, single instance, local time. Windows is the real target; the Unix
//! versions exist for development.

use std::path::PathBuf;

#[cfg_attr(not(windows), allow(dead_code))]
pub const APP: &str = "Lazeyka";

/// Local time offset from UTC in seconds.
pub fn local_offset() -> i64 {
    imp::local_offset()
}

pub use imp::*;

#[cfg(windows)]
mod imp {
    use super::*;
    use windows::Win32::Foundation::{CloseHandle, ERROR_ALREADY_EXISTS, GetLastError, HANDLE, HGLOBAL, HWND, LPARAM};
    use windows::Win32::System::DataExchange::{CloseClipboard, EmptyClipboard, GetClipboardData, OpenClipboard, SetClipboardData};
    use windows::Win32::System::Diagnostics::ToolHelp::{CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW, TH32CS_SNAPPROCESS};
    use windows::Win32::System::Memory::{GMEM_MOVEABLE, GlobalAlloc, GlobalLock, GlobalUnlock};
    use windows::Win32::System::Registry::{
        HKEY, HKEY_CURRENT_USER, KEY_QUERY_VALUE, KEY_SET_VALUE, REG_SZ, RegCloseKey, RegDeleteValueW, RegOpenKeyExW, RegQueryValueExW, RegSetValueExW,
    };
    use windows::Win32::System::Threading::{CreateEventW, CreateMutexW, EVENT_MODIFY_STATE, INFINITE, OpenEventW, SetEvent, WaitForMultipleObjects, WaitForSingleObject};
    use windows::Win32::Foundation::{WAIT_ABANDONED, WAIT_OBJECT_0};
    use windows::Win32::UI::Controls::Dialogs::{
        GetOpenFileNameW, GetSaveFileNameW, OFN_EXPLORER, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR, OFN_OVERWRITEPROMPT, OFN_PATHMUSTEXIST, OPENFILENAMEW,
    };
    use windows::Win32::UI::Shell::ShellExecuteW;
    use windows::Win32::UI::WindowsAndMessaging::{EnumWindows, GetWindowThreadProcessId, IsIconic, SW_RESTORE, SW_SHOWNORMAL, SetForegroundWindow, ShowWindow};
    use windows::core::{BOOL, PCWSTR, PWSTR, w};

    const CF_UNICODETEXT: u32 = 13;

    pub fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }

    pub fn local_offset() -> i64 {
        use windows::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
        let mut tz = TIME_ZONE_INFORMATION::default();
        let r = unsafe { GetTimeZoneInformation(&mut tz) };
        let mut bias = tz.Bias as i64;
        if r == 2 {
            bias += tz.DaylightBias as i64;
        } else if r == 1 {
            bias += tz.StandardBias as i64;
        }
        -bias * 60
    }

    pub fn clipboard_get() -> Option<String> {
        unsafe {
            OpenClipboard(None).ok()?;
            let out = (|| {
                let h = GetClipboardData(CF_UNICODETEXT).ok()?;
                let g = HGLOBAL(h.0);
                let p = GlobalLock(g) as *const u16;
                if p.is_null() {
                    return None;
                }
                let mut n = 0usize;
                while *p.add(n) != 0 && n < 32 << 20 {
                    n += 1;
                }
                let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, n));
                let _ = GlobalUnlock(g);
                Some(s)
            })();
            let _ = CloseClipboard();
            out
        }
    }

    pub fn clipboard_set(text: &str) -> bool {
        let w: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
        unsafe {
            if OpenClipboard(None).is_err() {
                return false;
            }
            let ok = (|| {
                EmptyClipboard().ok()?;
                let g = GlobalAlloc(GMEM_MOVEABLE, w.len() * 2).ok()?;
                let p = GlobalLock(g) as *mut u16;
                if p.is_null() {
                    return None;
                }
                std::ptr::copy_nonoverlapping(w.as_ptr(), p, w.len());
                let _ = GlobalUnlock(g);
                SetClipboardData(CF_UNICODETEXT, Some(HANDLE(g.0))).ok()?;
                Some(())
            })()
            .is_some();
            let _ = CloseClipboard();
            ok
        }
    }

    fn filter_string(filters: &[(&str, &str)]) -> Vec<u16> {
        let mut v = Vec::new();
        for (name, pat) in filters {
            v.extend(name.encode_utf16());
            v.push(0);
            v.extend(pat.encode_utf16());
            v.push(0);
        }
        v.push(0);
        v
    }

    /// Modal "open file" dialog. Call from a worker thread.
    pub fn open_file(title: &str, filters: &[(&str, &str)]) -> Option<PathBuf> {
        let mut buf = vec![0u16; 4096];
        let f = filter_string(filters);
        let t = wide(title);
        let mut ofn = OPENFILENAMEW {
            lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
            lpstrFilter: PCWSTR(f.as_ptr()),
            lpstrFile: PWSTR(buf.as_mut_ptr()),
            nMaxFile: buf.len() as u32,
            lpstrTitle: PCWSTR(t.as_ptr()),
            Flags: OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
            ..Default::default()
        };
        let ok = unsafe { GetOpenFileNameW(&mut ofn) };
        if !ok.as_bool() {
            return None;
        }
        let n = buf.iter().position(|&c| c == 0).unwrap_or(0);
        Some(PathBuf::from(String::from_utf16_lossy(&buf[..n])))
    }

    pub fn save_file(title: &str, name: &str, filters: &[(&str, &str)], ext: &str) -> Option<PathBuf> {
        let mut buf = vec![0u16; 4096];
        for (i, c) in name.encode_utf16().take(4000).enumerate() {
            buf[i] = c;
        }
        let f = filter_string(filters);
        let t = wide(title);
        let e = wide(ext);
        let mut ofn = OPENFILENAMEW {
            lStructSize: std::mem::size_of::<OPENFILENAMEW>() as u32,
            lpstrFilter: PCWSTR(f.as_ptr()),
            lpstrFile: PWSTR(buf.as_mut_ptr()),
            nMaxFile: buf.len() as u32,
            lpstrTitle: PCWSTR(t.as_ptr()),
            lpstrDefExt: PCWSTR(e.as_ptr()),
            Flags: OFN_EXPLORER | OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
            ..Default::default()
        };
        let ok = unsafe { GetSaveFileNameW(&mut ofn) };
        if !ok.as_bool() {
            return None;
        }
        let n = buf.iter().position(|&c| c == 0).unwrap_or(0);
        Some(PathBuf::from(String::from_utf16_lossy(&buf[..n])))
    }

    const SYSTEM_PROCS: &[&str] = &[
        "[system process]", "system", "registry", "smss.exe", "csrss.exe", "wininit.exe", "services.exe", "lsass.exe", "winlogon.exe", "svchost.exe",
        "fontdrvhost.exe", "dwm.exe", "conhost.exe", "sihost.exe", "ctfmon.exe", "runtimebroker.exe", "dllhost.exe", "taskhostw.exe", "searchhost.exe",
        "startmenuexperiencehost.exe", "shellexperiencehost.exe", "textinputhost.exe", "wmiprvse.exe", "spoolsv.exe", "securityhealthservice.exe",
        "securityhealthsystray.exe", "msmpeng.exe", "nissrv.exe", "audiodg.exe", "smartscreen.exe", "lazeyka.exe", "mihomo.exe", "memory compression",
        "secure system", "lsaiso.exe", "wudfhost.exe", "sgrmbroker.exe", "mousocoreworker.exe", "searchindexer.exe", "searchprotocolhost.exe",
        "searchfilterhost.exe", "backgroundtaskhost.exe", "applicationframehost.exe", "systemsettings.exe", "useroobebroker.exe", "lockapp.exe",
        "widgets.exe", "widgetservice.exe", "phoneexperiencehost.exe", "crossdeviceresume.exe", "msedgewebview2.exe", "unsecapp.exe", "wlanext.exe",
        "dashost.exe", "uhssvc.exe", "compattelrunner.exe", "settingsynchost.exe", "smss", "idle", "aggregatorhost.exe", "openconsole.exe",
        "windowsterminal.exe", "cmd.exe", "powershell.exe", "pwsh.exe", "mpdefendercoreservice.exe", "presentationfontcache.exe",
    ];

    pub fn process_names() -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        unsafe {
            let Ok(snap) = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) else { return out };
            let mut e = PROCESSENTRY32W { dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32, ..Default::default() };
            let mut ok = Process32FirstW(snap, &mut e).is_ok();
            while ok {
                let n = e.szExeFile.iter().position(|&c| c == 0).unwrap_or(e.szExeFile.len());
                let name = String::from_utf16_lossy(&e.szExeFile[..n]).to_lowercase();
                if name.ends_with(".exe") && !SYSTEM_PROCS.contains(&name.as_str()) && !out.contains(&name) {
                    out.push(name);
                }
                ok = Process32NextW(snap, &mut e).is_ok();
            }
            let _ = CloseHandle(snap);
        }
        out.sort();
        out
    }

    const RUN_KEY: PCWSTR = w!("Software\\Microsoft\\Windows\\CurrentVersion\\Run");

    pub fn autostart_enabled() -> bool {
        unsafe {
            let mut k = HKEY::default();
            if RegOpenKeyExW(HKEY_CURRENT_USER, RUN_KEY, None, KEY_QUERY_VALUE, &mut k).is_err() {
                return false;
            }
            let name = wide(APP);
            let r = RegQueryValueExW(k, PCWSTR(name.as_ptr()), None, None, None, None);
            let _ = RegCloseKey(k);
            r.is_ok()
        }
    }

    pub fn set_autostart(on: bool, exe: &std::path::Path) -> bool {
        unsafe {
            let mut k = HKEY::default();
            if RegOpenKeyExW(HKEY_CURRENT_USER, RUN_KEY, None, KEY_SET_VALUE, &mut k).is_err() {
                return false;
            }
            let name = wide(APP);
            let r = if on {
                let cmd = format!("\"{}\" --tray", exe.display());
                let v: Vec<u16> = cmd.encode_utf16().chain(Some(0)).collect();
                let bytes = std::slice::from_raw_parts(v.as_ptr() as *const u8, v.len() * 2);
                RegSetValueExW(k, PCWSTR(name.as_ptr()), None, REG_SZ, Some(bytes)).is_ok()
            } else {
                let r = RegDeleteValueW(k, PCWSTR(name.as_ptr()));
                r.is_ok() || r.0 == 2
            };
            let _ = RegCloseKey(k);
            r
        }
    }

    #[allow(dead_code)]
    pub fn open_url(url: &str) {
        let u = wide(url);
        unsafe {
            ShellExecuteW(None, w!("open"), PCWSTR(u.as_ptr()), None, None, SW_SHOWNORMAL);
        }
    }

    /// Whether part of the window was invalidated by the system and awaits painting.
    pub fn has_update_region(hwnd: isize) -> bool {
        unsafe { windows::Win32::Graphics::Gdi::GetUpdateRect(HWND(hwnd as *mut core::ffi::c_void), None, false) }.as_bool()
    }

    /// Brings the visible top-level window of this process to the front.
    pub fn focus_own_window() {
        unsafe extern "system" fn cb(hwnd: HWND, _l: LPARAM) -> BOOL {
            let mut pid = 0u32;
            unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
            if pid == std::process::id() && unsafe { windows::Win32::UI::WindowsAndMessaging::IsWindowVisible(hwnd) }.as_bool() {
                unsafe {
                    if IsIconic(hwnd).as_bool() {
                        let _ = ShowWindow(hwnd, SW_RESTORE);
                    }
                    let _ = SetForegroundWindow(hwnd);
                }
                return BOOL(0);
            }
            BOOL(1)
        }
        unsafe {
            let _ = EnumWindows(Some(cb), LPARAM(0));
        }
    }

    pub const SHOW_EVENT: &str = "Local\\Lazeyka.UI.Show";
    pub const QUIT_EVENT: &str = "Local\\Lazeyka.UI.Quit";

    fn signal(name: &str) {
        let n = wide(name);
        unsafe {
            if let Ok(ev) = OpenEventW(EVENT_MODIFY_STATE, false, PCWSTR(n.as_ptr())) {
                let _ = SetEvent(ev);
                let _ = CloseHandle(ev);
            }
        }
    }

    /// Returns false if another UI instance runs (it is asked to show its window).
    /// With `takeover` the running instance is asked to exit instead and this one
    /// continues (a newer copy started from another folder replaces the old one).
    /// The first instance gets `on_show`/`on_quit` callbacks from other processes.
    pub fn single_instance(takeover: bool, on_show: impl Fn() + Send + 'static, on_quit: impl Fn() + Send + 'static) -> bool {
        unsafe {
            let Ok(m) = CreateMutexW(None, true, w!("Local\\Lazeyka.UI")) else { return true };
            if GetLastError() == ERROR_ALREADY_EXISTS {
                if !takeover {
                    signal(SHOW_EVENT);
                    let _ = CloseHandle(m);
                    return false;
                }
                signal(QUIT_EVENT);
                let r = WaitForSingleObject(m, 8000);
                if r != WAIT_OBJECT_0 && r != WAIT_ABANDONED {
                    let _ = CloseHandle(m);
                    return false;
                }
            }
            let _ = m; // keep the mutex handle open for the lifetime of the process
            let sn = wide(SHOW_EVENT);
            let qn = wide(QUIT_EVENT);
            let (Ok(show), Ok(quit)) = (CreateEventW(None, false, false, PCWSTR(sn.as_ptr())), CreateEventW(None, false, false, PCWSTR(qn.as_ptr()))) else {
                return true;
            };
            let (s, q) = (show.0 as usize, quit.0 as usize);
            std::thread::spawn(move || {
                let hs = [HANDLE(s as *mut _), HANDLE(q as *mut _)];
                loop {
                    let r = WaitForMultipleObjects(&hs, false, INFINITE);
                    match r.0 {
                        0 => on_show(),
                        1 => {
                            on_quit();
                            break;
                        }
                        _ => break,
                    }
                }
            });
            true
        }
    }

    /// Asks a running UI (same session) to exit, e.g. before uninstalling.
    pub fn signal_quit() {
        signal(QUIT_EVENT);
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;

    pub fn local_offset() -> i64 {
        std::process::Command::new("date")
            .arg("+%z")
            .output()
            .ok()
            .and_then(|o| {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                let sign = if s.starts_with('-') { -1 } else { 1 };
                let d: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
                let v: i64 = d.parse().ok()?;
                Some(sign * ((v / 100) * 3600 + (v % 100) * 60))
            })
            .unwrap_or(0)
    }

    pub fn clipboard_get() -> Option<String> {
        None
    }
    pub fn clipboard_set(_text: &str) -> bool {
        false
    }
    fn zenity(args: &[&str]) -> Option<PathBuf> {
        let o = std::process::Command::new("zenity").args(args).output().ok()?;
        let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
        if o.status.success() && !s.is_empty() { Some(PathBuf::from(s)) } else { None }
    }
    pub fn open_file(title: &str, _filters: &[(&str, &str)]) -> Option<PathBuf> {
        zenity(&["--file-selection", "--title", title])
    }
    pub fn save_file(title: &str, name: &str, _filters: &[(&str, &str)], _ext: &str) -> Option<PathBuf> {
        zenity(&["--file-selection", "--save", "--title", title, "--filename", name])
    }
    pub fn process_names() -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if let Ok(rd) = std::fs::read_dir("/proc") {
            for e in rd.flatten() {
                if let Ok(c) = std::fs::read_to_string(e.path().join("comm")) {
                    let c = c.trim().to_string();
                    if !c.is_empty() && !out.contains(&c) {
                        out.push(c);
                    }
                }
            }
        }
        out.sort();
        out
    }
    pub fn autostart_enabled() -> bool {
        false
    }
    pub fn set_autostart(_on: bool, _exe: &std::path::Path) -> bool {
        false
    }
    #[allow(dead_code)]
    pub fn open_url(url: &str) {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
    pub fn focus_own_window() {}
    pub fn single_instance(_takeover: bool, _on_show: impl Fn() + Send + 'static, _on_quit: impl Fn() + Send + 'static) -> bool {
        true
    }
    #[allow(dead_code)]
    pub fn signal_quit() {}
}
