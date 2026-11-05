//! Лазейка — one executable with several roles:
//!   (no args)       window + tray icon
//!   --tray          start hidden in the tray (autostart)
//!   --replace       take over from a running window (after an update)
//!   --service       Windows service: the VPN engine (LocalSystem)
//!   --install       install/update the service (elevated, called by the UI)
//!   --uninstall     remove everything (elevated)
//!   --engine        run the engine in the foreground (development)
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(feature = "headless")]
mod headless;
mod sys;
mod ui;
#[cfg(windows)]
mod win;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let has = |a: &str| args.iter().skip(1).any(|x| x == a);
    #[cfg(windows)]
    {
        if has("--service") {
            if let Err(e) = win::run_service() {
                let dir = win::data_dir();
                let _ = std::fs::create_dir_all(&dir);
                let _ = std::fs::write(dir.join("service-error.log"), format!("{e:#}"));
                std::process::exit(1);
            }
            return;
        }
        if has("--install") {
            std::process::exit(win::install(&args));
        }
        if has("--uninstall") {
            std::process::exit(win::uninstall(&args));
        }
    }
    if has("--engine") {
        std::process::exit(run_engine());
    }
    if let Err(e) = ui::run(has("--tray"), has("--replace")) {
        fatal(&format!("Не удалось запустить интерфейс: {e:#}"));
        std::process::exit(1);
    }
}

/// Foreground engine + IPC server (development and diagnostics).
/// LAZEYKA_DATA, LAZEYKA_BIN (dir with mihomo and the geo database), LAZEYKA_SOCK.
fn run_engine() -> i32 {
    use lazeyka_core::{engine::Engine, ipc, store::Paths};
    let exe_dir = std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.to_path_buf())).unwrap_or_default();
    #[cfg(windows)]
    let default_data = win::data_dir();
    #[cfg(not(windows))]
    let default_data = std::path::PathBuf::from("/tmp/lazeyka-data");
    let data = std::env::var_os("LAZEYKA_DATA").map(Into::into).unwrap_or(default_data);
    let bin = std::env::var_os("LAZEYKA_BIN").map(Into::into).unwrap_or(exe_dir);
    let sock = std::env::var("LAZEYKA_SOCK").unwrap_or_else(|_| ipc::DEFAULT_PATH.into());
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            fatal(&format!("tokio: {e}"));
            return 1;
        }
    };
    rt.block_on(async move {
        lazeyka_core::init();
        let e = Engine::new(Paths { data, bin }, env!("CARGO_PKG_VERSION"));
        e.start();
        let e2 = e.clone();
        let srv = tokio::spawn(async move { ipc::serve(e2, &sock).await });
        let code = tokio::select! {
            r = srv => {
                eprintln!("IPC остановлен: {r:?}");
                1
            }
            _ = stop_signal() => 0,
        };
        e.shutdown().await;
        code
    })
}

/// Ctrl+C everywhere, plus SIGTERM on Unix (dev mode), so mihomo is stopped cleanly.
async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

fn fatal(msg: &str) {
    eprintln!("{msg}");
    #[cfg(windows)]
    {
        use windows::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
        use windows::core::{PCWSTR, w};
        let t = sys::wide(msg);
        unsafe {
            MessageBoxW(None, PCWSTR(t.as_ptr()), w!("Лазейка"), MB_OK | MB_ICONERROR);
        }
    }
}
