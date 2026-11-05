//! Dev tool: register WARP and test its variants through the lab.
use lazeyka_core::{geo::Geo, scan, warp};
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    lazeyka_core::init();
    let a: Vec<String> = std::env::args().collect();
    let c = lazeyka_core::probe::client(None, std::time::Duration::from_secs(20)).unwrap();
    let acc_path = "/tmp/lz-scan/warp.json";
    let acc: warp::Account = match std::fs::read_to_string(acc_path).ok().and_then(|t| serde_json::from_str(&t).ok()) {
        Some(a) => a,
        None => {
            let acc = warp::register(&c).await.expect("register");
            std::fs::write(acc_path, serde_json::to_string(&acc).unwrap()).unwrap();
            acc
        }
    };
    println!("account id={}… v4={} v6={} reserved={:?}", &acc.id[..6.min(acc.id.len())], acc.v4, acc.v6, acc.reserved);
    let list = warp::servers(&acc);
    let env = scan::Env {
        mihomo: a[1].clone().into(),
        dir: "/tmp/lz-scan/lab-warp".into(),
        geo: Geo::open(std::path::Path::new(&a[2])).ok().map(Arc::new),
        interface: None,
        cancel: Arc::new(AtomicBool::new(false)),
        progress: Arc::new(Mutex::new(scan::Progress::default())),
    };
    let mut net = scan::NetInfo::default();
    let res = scan::check_sequential(&env, list, &scan::Opts::default(), &mut net, 99).await;
    for s in &res {
        let p = s.probe.as_ref().unwrap();
        println!("{:55} ok={} {:?} cc={:?} lat={:?} udp={:?} svc={:04b} speed={:?} err={:?}", s.name, p.ok, p.exit_ip, p.exit_cc, p.latency, p.udp, p.services, p.speed, p.error);
    }
}
