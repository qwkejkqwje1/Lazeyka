//! Dev tool: prints the main mihomo configuration for routes given as JSON on stdin:
//! {"api_port":9097,"proxy_port":7899,"default_direct":false,
//!  "routes":[{"id":"r1","via":"direct"|"vpn"|"block"|"chain:<id>"|["id1","id2"]}],
//!  "chains":[{"id":"c1","levels":[[<proxy>,...],...]}],
//!  "default_chain":"c1"}
use lazeyka_core::mihomo::{self, RoutePlan, Via};
use serde_json::Value;
use std::io::Read;

fn main() {
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).unwrap();
    let v: Value = serde_json::from_str(&s).unwrap();
    let routes = v["routes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|r| RoutePlan {
            id: r["id"].as_str().unwrap().to_string(),
            via: match &r["via"] {
                Value::String(x) if x == "direct" => Via::Direct,
                Value::String(x) if x == "block" => Via::Block,
                Value::String(x) if x.starts_with("chain:") => Via::Chain(x["chain:".len()..].to_string()),
                Value::Array(a) => Via::Servers(a.iter().map(|x| x.as_str().unwrap().to_string()).collect()),
                _ => Via::Vpn,
            },
        })
        .collect();
    let chains = v["chains"]
        .as_array()
        .map(|a| {
            a.iter()
                .map(|c| mihomo::ChainPlan {
                    id: c["id"].as_str().unwrap().to_string(),
                    levels: c["levels"].as_array().unwrap().iter().map(|l| l.as_array().unwrap().clone()).collect(),
                })
                .collect()
        })
        .unwrap_or_default();
    let cfg = mihomo::main_config(&mihomo::MainOpts {
        api_port: v["api_port"].as_u64().unwrap() as u16,
        secret: "test".into(),
        default_direct: v["default_direct"].as_bool().unwrap_or(false),
        default_chain: v["default_chain"].as_str().map(str::to_string),
        routes,
        chains,
        stack: "gvisor".into(),
        strict_route: true,
        ipv6: false,
        tun_name: "Lazeyka".into(),
        proxy_port: v["proxy_port"].as_u64().map(|p| p as u16),
    });
    println!("{cfg}");
}
