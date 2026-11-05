//! Sends JSON requests (args) to the engine and prints responses.
use lazeyka_core::ipc;
use std::time::Duration;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let sock = std::env::var("LAZEYKA_SOCK").unwrap_or_else(|_| ipc::DEFAULT_PATH.into());
    let c = ipc::Client::new(&sock);
    for a in std::env::args().skip(1) {
        let v: serde_json::Value = serde_json::from_str(&a).expect("json");
        match c.call_timeout(v, Duration::from_secs(120)).await {
            Ok(d) => println!("{}", serde_json::to_string_pretty(&d).unwrap()),
            Err(e) => println!("ERROR: {e}"),
        }
    }
}
