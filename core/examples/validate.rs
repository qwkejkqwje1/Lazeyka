//! Dev tool: parse sample lists, build lab + main configs and validate them with `mihomo -t`.
use lazeyka_core::mihomo::{RoutePlan, Spare, Via};
use lazeyka_core::{import, mihomo, model::*, split};
use std::path::Path;

fn main() {
    let bin = std::env::args().nth(1).expect("mihomo path");
    let dir = Path::new("/tmp/lz-validate");
    let _ = std::fs::create_dir_all(dir);
    let mut servers = Vec::new();
    let mut texts: Vec<String> = std::fs::read_dir("/data/vpn/research/src")
        .map(|rd| rd.flatten().map(|e| std::fs::read_to_string(e.path()).unwrap_or_default()).collect())
        .unwrap_or_default();
    if texts.is_empty() {
        // synthetic samples (documentation addresses)
        texts.push(
            [
                "trojan://pass@198.51.100.1:443?sni=example.com#t1",
                "vless://11111111-2222-3333-4444-555555555555@198.51.100.2:443?security=reality&sni=www.example.com&pbk=Q9o8Zc0Lr1Uq3vJb4V5w6x7y8z9A0B1C2D3E4F5G6H7&sid=ab&fp=chrome&type=tcp&flow=xtls-rprx-vision#r1",
                "ss://YWVzLTI1Ni1nY206cGFzcw@198.51.100.3:8388#s1",
                "hy2://pass@198.51.100.4:443?sni=example.com#h1",
                "vmess://eyJ2IjoiMiIsInBzIjoidm0iLCJhZGQiOiIxOTguNTEuMTAwLjUiLCJwb3J0IjoiNDQzIiwiaWQiOiIxMTExMTExMS0yMjIyLTMzMzMtNDQ0NC01NTU1NTU1NTU1NTUiLCJhaWQiOiIwIiwibmV0Ijoid3MiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiJleGFtcGxlLmNvbSIsInBhdGgiOiIvIiwidGxzIjoidGxzIn0=",
            ]
            .join("\n"),
        );
    }
    for t in texts {
        let r = import::parse_text(&t);
        for p in r.items {
            if let Ok(s) = Server::new(&p.name, p.proxy, Origin::Free, "sample") {
                servers.push(s);
            }
        }
    }
    servers.sort_by(|a, b| a.id.cmp(&b.id));
    servers.dedup_by(|a, b| a.id == b.id);
    println!("servers: {}", servers.len());
    let refs: Vec<&Server> = servers.iter().collect();
    let ports = mihomo::free_ports(refs.len());
    let listeners = refs
        .iter()
        .zip(ports)
        .map(|(s, port)| mihomo::Listener { proxy: s.id.clone(), port, user: "u".into(), pass: "p".into() })
        .collect();
    let lab = mihomo::lab_config(&refs, &mihomo::LabOpts { api_port: 9090, secret: "x".into(), interface: None, listeners });
    std::fs::write(dir.join("lab.json"), lab.to_string()).unwrap();
    let out = std::process::Command::new(&bin).arg("-t").arg("-d").arg(dir).arg("-f").arg(dir.join("lab.json")).output().unwrap();
    println!("lab -t: {} {}", out.status, String::from_utf8_lossy(&out.stdout).lines().rev().take(3).collect::<Vec<_>>().join(" / "));
    // a two-level chain over the first samples, wired like the engine's planner does
    let copy = |s: &Server, lvl: usize| {
        let mut p = s.mihomo_proxy();
        p["name"] = serde_json::Value::from(format!("{}~eeee5555-{lvl}", s.id));
        p
    };
    let chains = if refs.len() > 1 {
        vec![mihomo::ChainPlan { id: "eeee5555".into(), levels: vec![vec![copy(refs[0], 1)], vec![copy(refs[1], 2)]] }]
    } else {
        vec![]
    };
    let main = mihomo::main_config(&mihomo::MainOpts {
        api_port: 9091,
        secret: "y".into(),
        default_direct: false,
        default_chain: None,
        http_policy: None,
        routes: vec![
            RoutePlan { id: "aaaa1111".into(), via: Via::Direct, spare: Spare::Vpn, strategy: Default::default() },
            RoutePlan {
                id: "bbbb2222".into(),
                via: Via::Servers(refs.iter().skip(10).take(3).map(|s| s.id.clone()).chain([refs[0].id.clone()]).collect()),
                spare: Spare::Vpn,
                strategy: Default::default(),
            },
            RoutePlan { id: "cccc3333".into(), via: Via::Block, spare: Spare::Vpn, strategy: Default::default() },
            RoutePlan { id: "dddd4444".into(), via: Via::Vpn, spare: Spare::Vpn, strategy: Default::default() },
            RoutePlan { id: "ffff6666".into(), via: Via::Chain("eeee5555".into()), spare: Spare::Vpn, strategy: Default::default() },
        ],
        chains,
        hops: vec![],
        stack: "gvisor".into(),
        strict_route: true,
        ipv6: true,
        tun_name: "Lazeyka".into(),
        proxy_port: None,
    });
    std::fs::write(dir.join("main.json"), main.to_string()).unwrap();
    std::fs::write(dir.join("pool.yaml"), mihomo::pool_file(&refs[..refs.len().min(10)])).unwrap();
    std::fs::write(dir.join("extra.yaml"), mihomo::extra_file(&refs[refs.len().min(10)..refs.len().min(13)])).unwrap();
    let (d, i, a) = split::provider_texts(&["example.com".into(), "1.2.3.0/24".into()], &["chrome.exe".into()]);
    let _ = std::fs::create_dir_all(dir.join("routes"));
    for id in ["aaaa1111", "bbbb2222", "cccc3333", "dddd4444"] {
        std::fs::write(dir.join(format!("routes/{id}-sites.txt")), &d).unwrap();
        std::fs::write(dir.join(format!("routes/{id}-ips.txt")), &i).unwrap();
        std::fs::write(dir.join(format!("routes/{id}-apps.txt")), &a).unwrap();
    }
    let out = std::process::Command::new(&bin).arg("-t").arg("-d").arg(dir).arg("-f").arg(dir.join("main.json")).output().unwrap();
    println!("main -t: {} {}", out.status, String::from_utf8_lossy(&out.stdout).lines().rev().take(3).collect::<Vec<_>>().join(" / "));
}
