//! Dev tool: real scan of public sources through the lab mihomo.
//! usage: scan <mihomo> <mmdb> [limit] [tier]
use lazeyka_core::{geo::Geo, import, model::*, scan, sources};
use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Mutex};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    lazeyka_core::init();
    let a: Vec<String> = std::env::args().collect();
    let limit: usize = a.get(3).and_then(|s| s.parse().ok()).unwrap_or(300);
    let max_tier: u8 = a.get(4).and_then(|s| s.parse().ok()).unwrap_or(1);
    let geo = Geo::open(std::path::Path::new(&a[2])).ok().map(Arc::new);
    let cache = std::path::Path::new("/tmp/lz-scan/cache");
    let c = sources::fetch_client();
    let cat = sources::catalog();
    let mut all: Vec<Server> = Vec::new();
    let t0 = std::time::Instant::now();
    for d in cat.iter().filter(|d| d.tier <= max_tier && d.enabled) {
        match sources::fetch(&c, d, cache, 1800).await {
            Ok(t) => {
                let r = import::parse_text(&t);
                let n = r.items.len();
                for p in r.items {
                    if let Ok(s) = Server::new(&p.name, p.proxy, Origin::Free, &d.id) {
                        all.push(s);
                    }
                }
                println!("{:22} parsed {:4} errors {:3}", d.id, n, r.errors.len());
            }
            Err(e) => println!("{:22} FAIL {e}", d.id),
        }
    }
    all.sort_by(|a, b| a.id.cmp(&b.id));
    all.dedup_by(|a, b| a.id == b.id);
    println!("unique {} in {:?}", all.len(), t0.elapsed());
    let plan = scan::plan(&all, &cat, &HashMap::new(), limit, lazeyka_core::util::now(), &|_| true);
    println!("planned {}", plan.len());
    let env = scan::Env {
        mihomo: a[1].clone().into(),
        dir: "/tmp/lz-scan/lab".into(),
        geo: geo.clone(),
        interface: None,
        cancel: Arc::new(AtomicBool::new(false)),
        progress: Arc::new(Mutex::new(scan::Progress::default())),
    };
    let opts = scan::Opts { target_good: 0, ..Default::default() };
    let mut net = scan::NetInfo::default();
    let t1 = std::time::Instant::now();
    let res = scan::check(&env, plan, &opts, &mut net, |b| println!("batch done: {} ({} good)", b.len(), b.iter().filter(|s| s.good()).count())).await;
    println!("net: {:?}", net);
    println!("checked {} in {:?}; progress {:?}", res.len(), t1.elapsed(), env.progress.lock().unwrap());
    let mut errs: HashMap<String, usize> = HashMap::new();
    for s in &res {
        if let Some(p) = &s.probe {
            if !p.ok {
                *errs.entry(p.error.clone().unwrap_or_default()).or_default() += 1;
            }
        }
    }
    println!("errors: {errs:?}");
    let none = std::collections::HashSet::new();
    let pool = scan::pool(&res, &scan::PoolOpts { size: 12, countries: &none, warp: true, selected: None });
    for s in &pool {
        let p = s.probe.as_ref().unwrap();
        println!(
            "{:13} {:9} {:18} {:2} {:>5}ms udp={:?} svc={:04b} speed={:?} src={} score={}",
            s.id,
            s.proto.label(),
            s.transport,
            p.exit_cc.clone().unwrap_or_default(),
            p.latency.unwrap_or(0),
            p.udp,
            p.services,
            p.speed,
            s.source,
            scan::score(s)
        );
    }
    let mut by_cc: HashMap<String, usize> = HashMap::new();
    for s in res.iter().filter(|s| s.good()) {
        *by_cc.entry(s.country().unwrap_or("?").to_string()).or_default() += 1;
    }
    println!("good by country: {by_cc:?}");
    std::fs::write("/tmp/lz-scan/result.json", serde_json::to_string(&res).unwrap()).unwrap();
}
