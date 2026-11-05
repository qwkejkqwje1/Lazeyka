//! Local IPC between the UI (user session) and the engine (service, LocalSystem).
//!
//! Transport: a Windows named pipe protected by an explicit DACL (SYSTEM and
//! Administrators full access, interactive users read/write; remote clients rejected),
//! or a Unix socket (mode 0600) for development on Linux.
//! Protocol: one JSON object per line. Request `{"rid":N,"cmd":"…",…}` (`rid` so that it
//! never clashes with command fields such as `id`), response `{"rid":N,"ok":true,"data":…}` or
//! `{"rid":N,"ok":false,"error":"…"}`.

use crate::engine::{Engine, Req};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{mpsc, oneshot};

#[cfg(windows)]
pub const DEFAULT_PATH: &str = r"\\.\pipe\Lazeyka";
#[cfg(not(windows))]
pub const DEFAULT_PATH: &str = "/tmp/lazeyka.sock";

/// Largest accepted message (imports of big subscription texts).
pub const MAX_LINE: usize = 16 << 20;

/// SDDL of the pipe: protected DACL; SYSTEM and Administrators — full access;
/// interactive users — read/write (no WRITE_DAC/WRITE_OWNER, cannot create instances).
#[cfg(windows)]
pub const PIPE_SDDL: &str = "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;IU)";

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
            buf.extend_from_slice(&chunk[..pos]);
            r.consume(pos + 1);
            return Ok(Some(()));
        }
        let n = chunk.len();
        buf.extend_from_slice(chunk);
        r.consume(n);
        if buf.len() > MAX_LINE {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "message too large"));
        }
    }
}

// ---------------------------------------------------------------- server

/// Serves one client connection: requests are handled concurrently, responses are
/// written as they complete (matched by id on the client side).
pub async fn serve_conn<S>(stream: S, engine: Arc<Engine>)
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let (rd, mut wr) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::unbounded_channel::<String>();
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
    while let Ok(Some(())) = read_line_capped(&mut rd, &mut buf).await {
        let v: Value = match serde_json::from_slice(&buf) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let id = v.get("rid").cloned().unwrap_or(Value::Null);
        let tx = tx.clone();
        let engine = engine.clone();
        tokio::spawn(async move {
            let resp = match serde_json::from_value::<Req>(v) {
                Ok(req) => match engine.handle(req).await {
                    Ok(data) => json!({ "rid": id, "ok": true, "data": data }),
                    Err(e) => json!({ "rid": id, "ok": false, "error": e }),
                },
                Err(e) => json!({ "rid": id, "ok": false, "error": format!("неизвестная команда: {e}") }),
            };
            let _ = tx.send(resp.to_string());
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
    let mut sa = SecAttrs::new(PIPE_SDDL)?;
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
                    connected.store(false, Ordering::Relaxed);
                    let _ = call.resp.send(Err(NOT_CONNECTED.into()));
                    continue;
                }
            }
        }
        let id = next.fetch_add(1, Ordering::Relaxed);
        let mut req = call.req;
        if let Some(o) = req.as_object_mut() {
            o.insert("rid".into(), Value::from(id));
        }
        pending.lock().unwrap().insert(id, call.resp);
        let mut line = req.to_string();
        line.push('\n');
        let w = writer.as_mut().unwrap();
        if w.write_all(line.as_bytes()).await.is_err() || w.flush().await.is_err() {
            writer = None;
            alive.store(false, Ordering::SeqCst);
            connected.store(false, Ordering::Relaxed);
            if let Some(tx) = pending.lock().unwrap().remove(&id) {
                let _ = tx.send(Err(NOT_CONNECTED.into()));
            }
        }
    }
}