//! Development runner: engine + IPC server in the console.
//! LAZEYKA_DATA (data dir), LAZEYKA_BIN (dir with mihomo + mmdb), LAZEYKA_SOCK.
use lazeyka_core::{engine::Engine, ipc, store::Paths};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    lazeyka_core::init();
    let data = std::env::var("LAZEYKA_DATA").unwrap_or_else(|_| "/tmp/lazeyka-data".into());
    let bin = std::env::var("LAZEYKA_BIN").unwrap_or_else(|_| ".".into());
    let sock = std::env::var("LAZEYKA_SOCK").unwrap_or_else(|_| ipc::DEFAULT_PATH.into());
    let e = Engine::new(Paths { data: data.into(), bin: bin.into() }, env!("CARGO_PKG_VERSION"));
    e.start();
    let srv = tokio::spawn(ipc::serve(e.clone(), Box::leak(sock.into_boxed_str())));
    tokio::select! {
        r = srv => eprintln!("ipc stopped: {r:?}"),
        _ = tokio::signal::ctrl_c() => {}
    }
    e.shutdown().await;
}
