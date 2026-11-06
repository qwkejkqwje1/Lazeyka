//! Local IPC between the UI (user session) and the engine (service, LocalSystem).
//!
//! Transport: a Windows named pipe protected by an explicit DACL (SYSTEM and
//! Administrators full access, active interactive console user read/write; remote
//! clients rejected), or a Unix socket (mode 0600) for development on Linux.
//! Protocol: one JSON object per line. Request `{"rid":N,"cmd":"…",…}` (`rid` so that it
//! never clashes with command fields such as `id`), response `{"rid":N,"ok":true,"data":…}` or
//! `{"rid":N,"ok":false,"error":"…"}`.

use crate::engine::{Engine, Req};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{Semaphore, mpsc, oneshot};

#[cfg(windows)]
pub const DEFAULT_PATH: &str = r"\\.\pipe\Lazeyka";
#[cfg(not(windows))]
pub const DEFAULT_PATH: &str = "/tmp/lazeyka.sock";

/// Largest accepted message (4 MiB — sufficient for large subscription imports while preventing memory abuse).
pub const MAX_LINE: usize = 4 << 20;

/// Maximum concurrent requests processed on a single IPC connection.
pub const MAX_CONCURRENT_REQS: usize = 16;

/// Bounded response channel capacity per connection.
pub const IPC_QUEUE_CAP: usize = 64;

/// Maximum mutating commands per 5-second window per connection.
pub const MAX_MUTATING_PER_WINDOW: u32 = 40;

/// Default SDDL of the pipe when no specific interactive user SID is resolved:
/// SYSTEM and Administrators — full access; Creator Owner + Interactive session — read/write.
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;CO)(A;;GRGW;;;IU)";

/// Builds a pipe SDDL restricted to SYSTEM, Administrators, and a specific interactive user SID when known.
pub fn build_pipe_sddl(user_sid: Option<&str>) -> String {
    match user_sid.map(str::trim).filter(|s| s.starts_with("S-1-5-") && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')) {
        Some(sid) => format!("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{sid})"),
        None => PIPE_SDDL.to_string(),
    }
}

/// True when `cmd` only reads engine state without modifying configuration or connections.
pub fn is_read_only_cmd(cmd: &str) -> bool {
    matches!(
        cmd,
        "ping" | "status" | "servers" | "settings" | "routes" | "route_presets" | "route_explain" | "route_export" | "list_export" | "sources" | "logs"
    )
}

pub const NOT_CONNECTED: &str = "нет связи со службой Лазейки";

/// Reads one '\n'-terminated line with a size cap. Ok(None) on EOF.
async fn read_line_capped<R: AsyncRead + Unpin>(r: &mut BufReader<R>, buf: &mut Vec<u8>) -> std::io::Result<Option<()>> {
    buf.clear();
    loop {
        let chunk = r.fill_buf().await?;
        if chunk.is_empty() {
            return Ok(if buf.is_empty() { None } else { Some(()) });
        }
        if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
            if buf.len() + pos > MAX_LINE {
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "message too large"));
            }
            buf.extend_from_slice(&chunk[..pos]);
            r.consume(pos + 1);
            return Ok(Some(()));
        }
        let n = chunk.len();
        if buf.len() + n > MAX_LINE {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "message too large"));
        }
        buf.extend_from_slice(chunk);
        r.consume(n);
    }
}

// ---------------------------------------------------------------- server

/// Serves one client connection with bounded queues, concurrency cap, and rate limiting.
pub async fn serve_conn<S>(stream: S, engine: Arc<Engine>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (rd, mut wr) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<String>(IPC_QUEUE_CAP);
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_REQS));
    let writer = tokio::spawn(async move {
        while let Some(mut line) = rx.recv().await {
            line.push('\n');
            if wr.write_all(line.as_bytes()).await.is_err() {
                break;
            }
            let _ = wr.flush().await;
        }
    });
    let mut rd = BufReader::with_capacity(64 * 1024, rd);
    let mut buf = Vec::new();
    let mut win_start = Instant::now();
    let mut mutating_count: u32 = 0;

    while let Ok(Some(())) = read_line_capped(&mut rd, &mut buf).await {
        let v: Value = match serde_json::from_slice(&buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let id = v.get("rid").cloned().unwrap_or(Value::Null);
        let cmd = v.get("cmd").and_then(|c| c.as_str()).unwrap_or("");
        if !is_read_only_cmd(cmd) {
            if win_start.elapsed() > Duration::from_secs(5) {
                win_start = Instant::now();
                mutating_count = 0;
            }
            mutating_count += 1;
            if mutating_count > MAX_MUTATING_PER_WINDOW {
                let err = json!({ "rid": id, "ok": false, "error": "слишком много команд подряд — подождите пару секунд" });
                let _ = tx.try_send(err.to_string());
                continue;
            }
        }
        let Ok(permit) = sem.clone().try_acquire_owned() else {
            let err = json!({ "rid": id, "ok": false, "error": "служба занята обработкой предыдущих запросов" });
            let _ = tx.try_send(err.to_string());
            continue;
        };
        let tx = tx.clone();
        let engine = engine.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let resp = match serde_json::from_value::<Req>(v) {
                Ok(req) => match tokio::time::timeout(Duration::from_secs(120), engine.handle(req)).await {
                    Ok(Ok(data)) => json!({ "rid": id, "ok": true, "data": data }),
                    Ok(Err(e)) => json!({ "rid": id, "ok": false, "error": e }),
                    Err(_) => json!({ "rid": id, "ok": false, "error": "превышено время выполнения команды" }),
                },
                Err(e) => json!({ "rid": id, "ok": false, "error": format!("неизвестная команда: {e}") }),
            };
            let _ = tx.send(resp.to_string()).await;
        });
    }
    drop(tx);
    let _ = writer.await;
}

#[cfg(windows)]
mod winsec {
    use windows::Win32::Foundation::{HLOCAL, LocalFree};
    use windows::Win32::Security::Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1};
    use windows::Win32::Security::{PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES};
    use windows::core::PCWSTR;

    /// SECURITY_ATTRIBUTES built from an SDDL string (freed on drop).
    pub struct SecAttrs {
        sd: PSECURITY_DESCRIPTOR,
        attrs: SECURITY_ATTRIBUTES,
    }

    unsafe impl Send for SecAttrs {}
    unsafe impl Sync for SecAttrs {}

    impl SecAttrs {
        pub fn new(sddl: &str) -> std::io::Result<Box<SecAttrs>> {
            let w: Vec<u16> = sddl.encode_utf16().chain(Some(0)).collect();
            let mut sd = PSECURITY_DESCRIPTOR::default();
            unsafe { ConvertStringSecurityDescriptorToSecurityDescriptorW(PCWSTR(w.as_ptr()), SDDL_REVISION_1, &mut sd, None) }
                .map_err(|e| std::io::Error::other(e.message()))?;
            let attrs = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: sd.0,
                bInheritHandle: false.into(),
            };
            Ok(Box::new(SecAttrs { sd, attrs }))
        }

        /// Pointer for CreateNamedPipe. A method (not a field access) so that closures
        /// capture the whole `Send` wrapper rather than the raw attributes.
        pub fn ptr(&mut self) -> *mut std::ffi::c_void {
            &mut self.attrs as *mut SECURITY_ATTRIBUTES as *mut std::ffi::c_void
        }
    }

    impl Drop for SecAttrs {
        fn drop(&mut self) {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.sd.0)));
            }
        }
    }
}

#[cfg(windows)]
pub use winsec::SecAttrs;

/// Accepts clients forever. Fails if the pipe/socket cannot be created
/// (e.g. another process already owns the pipe name).
#[cfg(windows)]
pub async fn serve(engine: Arc<Engine>, path: &str) -> std::io::Result<()> {
    use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};
    let custom_sid = std::env::var("LAZEYKA_ALLOWED_SID").ok();
    let sddl = build_pipe_sddl(custom_sid.as_deref());
    let mut sa = SecAttrs::new(&sddl)?;
    let mut create = |first: bool| -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeServer> {
        let mut o = ServerOptions::new();
        o.first_pipe_instance(first).reject_remote_clients(true).pipe_mode(PipeMode::Byte).in_buffer_size(64 * 1024).out_buffer_size(64 * 1024);
        unsafe { o.create_with_security_attributes_raw(path, sa.ptr()) }
    };
    let mut server = create(true)?;
    loop {
        server.connect().await?;
        let conn = server;
        server = create(false)?;
        tokio::spawn(serve_conn(conn, engine.clone()));
    }
}

#[cfg(unix)]
pub async fn serve(engine: Arc<Engine>, path: &str) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let p = std::path::Path::new(path);
    if p.exists() {
        // only a stale socket of ours may be replaced
        use std::os::unix::fs::FileTypeExt;
        if std::fs::symlink_metadata(p)?.file_type().is_socket() {
            if std::os::unix::net::UnixStream::connect(p).is_ok() {
                return Err(std::io::Error::new(std::io::ErrorKind::AddrInUse, "engine already running"));
            }
            std::fs::remove_file(p)?;
        } else {
            return Err(std::io::Error::new(std::io::ErrorKind::AlreadyExists, "path exists and is not a socket"));
        }
    }
    let l = tokio::net::UnixListener::bind(p)?;
    let mode = std::env::var("LAZEYKA_SOCK_MODE").ok().and_then(|m| u32::from_str_radix(&m, 8).ok()).unwrap_or(0o600);
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))?;
    loop {
        let (s, _) = l.accept().await?;
        tokio::spawn(serve_conn(s, engine.clone()));
    }
}

// ---------------------------------------------------------------- client

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Result<Value, String>>>>>;

struct Call {
    req: Value,
    resp: oneshot::Sender<Result<Value, String>>,
}

/// Async client with lazy (re)connection. Cheap to clone. Must be created inside a
/// Tokio runtime.
#[derive(Clone)]
pub struct Client {
    tx: mpsc::UnboundedSender<Call>,
    connected: Arc<AtomicBool>,
}

#[cfg(windows)]
async fn connect(path: &str) -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use tokio::net::windows::named_pipe::ClientOptions;
    const ERROR_PIPE_BUSY: i32 = 231;
    let mut tries = 0;
    loop {
        match ClientOptions::new().open(path) {
            Ok(c) => return Ok(c),
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && tries < 40 => {
                tries += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(unix)]
async fn connect(path: &str) -> std::io::Result<tokio::net::UnixStream> {
    tokio::net::UnixStream::connect(path).await
}

impl Client {
    pub fn new(path: &str) -> Client {
        let (tx, rx) = mpsc::unbounded_channel();
        let connected = Arc::new(AtomicBool::new(false));
        tokio::spawn(run_client(path.to_string(), rx, connected.clone()));
        Client { tx, connected }
    }

    /// True while a connection to the engine is established.
    pub fn is_connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    pub async fn call(&self, req: Value) -> Result<Value, String> {
        self.call_timeout(req, Duration::from_secs(20)).await
    }

    pub async fn call_timeout(&self, req: Value, t: Duration) -> Result<Value, String> {
        let (resp, rx) = oneshot::channel();
        self.tx.send(Call { req, resp }).map_err(|_| NOT_CONNECTED.to_string())?;
        match tokio::time::timeout(t, rx).await {
            Ok(Ok(r)) => r,
            Ok(Err(_)) => Err(NOT_CONNECTED.into()),
            Err(_) => Err("служба не отвечает".into()),
        }
    }
}

async fn run_client(path: String, mut rx: mpsc::UnboundedReceiver<Call>, connected: Arc<AtomicBool>) {
    let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
    let next = AtomicU64::new(1);
    let mut writer: Option<Box<dyn AsyncWrite + Unpin + Send>> = None;
    let alive = Arc::new(AtomicBool::new(false));
    while let Some(call) = rx.recv().await {
        if !alive.load(Ordering::SeqCst) {
            writer = None;
        }
        if writer.is_none() {
            match connect(&path).await {
                Ok(s) => {
                    let (rd, wr) = tokio::io::split(s);
                    writer = Some(Box::new(wr));
                    alive.store(true, Ordering::SeqCst);
                    connected.store(true, Ordering::Relaxed);
                    let pending = pending.clone();
                    let alive = alive.clone();
                    let connected = connected.clone();
                    tokio::spawn(async move {
                        let mut rd = BufReader::with_capacity(64 * 1024, rd);
                        let mut buf = Vec::new();
                        while let Ok(Some(())) = read_line_capped(&mut rd, &mut buf).await {
                            let Ok(v) = serde_json::from_slice::<Value>(&buf) else { continue };
                            let Some(id) = v.get("rid").and_then(|x| x.as_u64()) else { continue };
                            let Some(tx) = pending.lock().unwrap().remove(&id) else { continue };
                            let r = if v.get("ok").and_then(|x| x.as_bool()) == Some(true) {
                                Ok(v.get("data").cloned().unwrap_or(Value::Null))
                            } else {
                                Err(v.get("error").and_then(|x| x.as_str()).unwrap_or("ошибка").to_string())
                            };
                            let _ = tx.send(r);
                        }
                        alive.store(false, Ordering::SeqCst);
                        connected.store(false, Ordering::Relaxed);
                        // fail everything still waiting
                        for (_, tx) in pending.lock().unwrap().drain() {
                            let _ = tx.send(Err(NOT_CONNECTED.into()));
                        }
                    });
                }
                Err(_) => {
                    let _ = call.resp.send(Err(NOT_CONNECTED.into()));
                    continue;
                }
            }
        }
        let id = next.fetch_add(1, Ordering::Relaxed);
        let mut req = call.req;
        if let Some(m) = req.as_object_mut() {
            m.insert("rid".into(), id.into());
        }
        pending.lock().unwrap().insert(id, call.resp);
        let mut line = req.to_string();
        line.push('\n');
        let wr = writer.as_mut().unwrap();
        if wr.write_all(line.as_bytes()).await.is_err() || wr.flush().await.is_err() {
            alive.store(false, Ordering::SeqCst);
            connected.store(false, Ordering::Relaxed);
            writer = None;
            if let Some(tx) = pending.lock().unwrap().remove(&id) {
                let _ = tx.send(Err(NOT_CONNECTED.into()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sddl_builder_restricts_sid() {
        assert_eq!(
            build_pipe_sddl(Some("S-1-5-21-100-200-300-1001")),
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;S-1-5-21-100-200-300-1001)"
        );
        // Invalid or injected SDDL falls back to safe default
        assert_eq!(build_pipe_sddl(Some("invalid);(A;;GA;;;WD)")), PIPE_SDDL);
        assert_eq!(build_pipe_sddl(None), PIPE_SDDL);
    }

    #[test]
    fn command_classification() {
        assert!(is_read_only_cmd("status"));
        assert!(is_read_only_cmd("servers"));
        assert!(!is_read_only_cmd("connect"));
        assert!(!is_read_only_cmd("set_settings"));
    }
}