//! mihomo sidecar: config builders (main TUN instance and scanner "lab"),
//! process supervision and the REST API client.

use crate::model::Server;
use serde_json::{Value, json};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};

pub const TEST_URL: &str = "https://www.gstatic.com/generate_204";
/// Second opinion before declaring a server dead (a server may block one test site).
pub const ALT_TEST_URL: &str = "https://cp.cloudflare.com/generate_204";

/// Networks that always bypass the tunnel.
pub const LAN: &[&str] = &[
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "224.0.0.0/4",
    "255.255.255.255/32",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
];

const FAKE_IP_FILTER: &[&str] = &[
    "*.lan",
    "*.local",
    "*.localdomain",
    "*.home.arpa",
    "+.msftconnecttest.com",
    "+.msftncsi.com",
    "time.windows.com",
    "time.*.com",
    "ntp.*.com",
    "+.pool.ntp.org",
    "+.stun.*.*",
    "+.stun.*.*.*",
    "stun.*.*",
    "+.xboxlive.com",
    "+.srv.nintendo.net",
    "+.stun.playstation.net",
    "localhost.ptlogin2.qq.com",
    "WORKGROUP",
];

/// How the traffic of one route leaves.
#[derive(Clone, Debug, PartialEq)]
pub enum Via {
    Direct,
    Vpn,
    Block,
    /// Through these servers (proxy names, in order of preference); the VPN is the spare.
    Servers(Vec<String>),
    /// Through a named chain of hops; the VPN is the spare.
    Chain(String),
}

/// What a route falls back to when its own servers are not available.
#[derive(Clone, Debug, PartialEq, Default)]
pub enum Spare {
    /// The VPN group (best working pool server).
    #[default]
    Vpn,
    Direct,
    Block,
    /// These WARP servers first, then the VPN.
    Warp(Vec<String>),
}

/// One active route: its rule lists are `./routes/<id>-{apps,sites,ips}.txt`.
#[derive(Clone, Debug, PartialEq)]
pub struct RoutePlan {
    pub id: String,
    pub via: Via,
    pub spare: Spare,
    /// How a country route picks among its servers.
    pub strategy: crate::routes::Strategy,
}

impl RoutePlan {
    /// Rule target (outbound or group name).
    pub fn outbound(&self) -> String {
        match &self.via {
            Via::Direct => "DIRECT".into(),
            Via::Vpn => "VPN".into(),
            Via::Block => "REJECT".into(),
            Via::Servers(_) => route_group(&self.id),
            Via::Chain(_) => route_group(&self.id),
        }
    }
}

/// The fallback tail of a route group, in order. A WARP spare adds its own group (to `groups`).
fn spare_chain(r: &RoutePlan, groups: &mut Vec<Value>) -> Vec<String> {
    match &r.spare {
        Spare::Vpn => vec!["VPN".into()],
        Spare::Direct => vec!["DIRECT".into()],
        Spare::Block => vec!["REJECT".into()],
        Spare::Warp(ids) if ids.is_empty() => vec!["VPN".into()],
        Spare::Warp(ids) => {
            let filter = format!("^(?:{})$", ids.iter().map(|i| regex_escape(i)).collect::<Vec<_>>().join("|"));
            groups.push(json!({
                "name": route_warp_group(&r.id),
                "type": "fallback",
                "use": ["pool", "extra"],
                "filter": filter,
                "url": TEST_URL,
                "interval": 300,
                "lazy": true,
                "timeout": 5000,
                "max-failed-times": 2,
                "expected-status": "204",
                "empty-fallback": "REJECT"
            }));
            vec![route_warp_group(&r.id), "VPN".into()]
        }
    }
}

/// Exit group of a compiled chain; a route (or the default) points here.
pub fn chain_group(id: &str) -> String {
    format!("CH-{id}")
}
/// Group of one chain level (1-based); each level dials through the previous one.
pub fn chain_level_group(id: &str, level: usize) -> String {
    format!("CH-{id}-{level}")
}

/// A named chain compiled for the config: one list of proxy definitions per hop.
/// The definitions carry their final names; an empty level means the hop is the
/// VPN group itself. `main_config` wires every level through the previous one
/// (`dialer-proxy`), so the last level is the exit.
#[derive(Clone, Debug, PartialEq)]
pub struct ChainPlan {
    pub id: String,
    pub levels: Vec<Vec<Value>>,
}

/// Group of a route with its own servers: those servers first, then the VPN.
pub fn route_group(id: &str) -> String {
    format!("R-{id}")
}
/// The route's servers only (never empty: an empty filter result means REJECT, not DIRECT).
pub fn route_servers_group(id: &str) -> String {
    format!("R-{id}-s")
}
/// The route's WARP spare (a group of the WARP servers only).
pub fn route_warp_group(id: &str) -> String {
    format!("R-{id}-w")
}
pub fn route_provider(id: &str, part: &str) -> String {
    format!("rt-{id}-{part}")
}
pub const ROUTE_PARTS: [&str; 3] = ["apps", "sites", "ips"];

fn regex_escape(s: &str) -> String {
    let mut o = String::new();
    for c in s.chars() {
        if "\\.+*?()|[]{}^$#&-~ ".contains(c) {
            o.push('\\');
        }
        o.push(c);
    }
    o
}

#[derive(Clone, Debug)]
pub struct MainOpts {
    pub api_port: u16,
    pub secret: String,
    /// Traffic that no route matches goes directly instead of through the VPN.
    pub default_direct: bool,
    /// The default target is this chain (id) when it could be built.
    pub default_chain: Option<String>,
    pub routes: Vec<RoutePlan>,
    /// Chains referenced by the routes or the default target.
    pub chains: Vec<ChainPlan>,
    /// Working servers that relay servers of the pool dial through (copies named `hop:<id>`).
    pub hops: Vec<Server>,
    /// "gvisor" (default on Windows: no firewall prompts), "mixed", "system".
    pub stack: String,
    pub strict_route: bool,
    pub ipv6: bool,
    pub tun_name: String,
    /// Development only: no TUN, a local mixed (HTTP+SOCKS) port instead.
    pub proxy_port: Option<u16>,
}

/// Main instance: TUN + fake-ip DNS + pool provider + route rules.
pub fn main_config(o: &MainOpts) -> Value {
    let mut rules: Vec<String> = LAN
        .iter()
        .map(|c| format!("{},{c},DIRECT,no-resolve", if c.contains(':') { "IP-CIDR6" } else { "IP-CIDR" }))
        .collect();
    rules.push("DOMAIN-SUFFIX,local,DIRECT".into());
    rules.push("DOMAIN-SUFFIX,lan,DIRECT".into());
    // Teredo (Windows IPv6 tunnelling) only produces failing UDP noise through a VPN
    rules.push("AND,((NETWORK,UDP),(DST-PORT,3544)),REJECT".into());
    let mut rule_providers = serde_json::Map::new();
    let mut groups = vec![
        json!({
            "name": "AUTO",
            "type": "fallback",
            "use": ["pool"],
            "url": TEST_URL,
            "interval": 180,
            "lazy": false,
            "timeout": 5000,
            "max-failed-times": 2,
            "expected-status": "204",
            "empty-fallback": "REJECT"
        }),
        json!({ "name": "VPN", "type": "select", "proxies": ["AUTO"], "use": ["pool"] }),
    ];
    // Chains: every level is a fallback group of suffixed proxy copies; a copy of
    // level N dials through the group of level N-1, so traffic enters level 1 and
    // leaves through the last level. An empty level is the VPN group itself.
    let mut chain_proxies: Vec<Value> = Vec::new();
    for h in &o.hops {
        let mut p = h.mihomo_proxy();
        p["name"] = Value::from(crate::model::hop_name(&h.id));
        if let Some(m) = p.as_object_mut() {
            m.remove("dialer-proxy");
        }
        chain_proxies.push(p);
    }
    for c in &o.chains {
        let last = c.levels.len();
        for (i, level) in c.levels.iter().enumerate() {
            let lvl = i + 1;
            let members: Vec<Value> = if level.is_empty() {
                vec![Value::from("VPN")]
            } else {
                level
                    .iter()
                    .map(|p| {
                        let mut p = p.clone();
                        if lvl > 1 {
                            p["dialer-proxy"] = Value::from(chain_level_group(&c.id, lvl - 1));
                        }
                        let name = p["name"].clone();
                        chain_proxies.push(p);
                        name
                    })
                    .collect()
            };
            groups.push(json!({
                "name": chain_level_group(&c.id, lvl),
                "type": "fallback",
                "proxies": members,
                "url": TEST_URL,
                "interval": 300,
                "lazy": true,
                "timeout": 5000,
                "max-failed-times": 2,
                "expected-status": "204",
                "empty-fallback": "REJECT"
            }));
        }
        if last > 0 {
            groups.push(json!({ "name": chain_group(&c.id), "type": "select", "proxies": [chain_level_group(&c.id, last)] }));
        }
    }
    for r in &o.routes {
        let out = r.outbound();
        for part in ROUTE_PARTS {
            let name = route_provider(&r.id, part);
            rule_providers.insert(
                name.clone(),
                json!({ "type": "file", "behavior": "classical", "format": "text", "path": format!("./routes/{}-{part}.txt", r.id) }),
            );
            rules.push(if part == "ips" { format!("RULE-SET,{name},{out},no-resolve") } else { format!("RULE-SET,{name},{out}") });
        }
        if let Via::Servers(ids) = &r.via {
            let filter = format!("^(?:{})$", ids.iter().map(|i| regex_escape(i)).collect::<Vec<_>>().join("|"));
            let mut g = json!({
                "name": route_servers_group(&r.id),
                "type": "fallback",
                "use": ["pool", "extra"],
                "filter": filter,
                "url": TEST_URL,
                "interval": 300,
                "lazy": true,
                "timeout": 5000,
                "max-failed-times": 2,
                "expected-status": "204",
                "empty-fallback": "REJECT"
            });
            match r.strategy {
                crate::routes::Strategy::Failover => {}
                crate::routes::Strategy::Fastest => {
                    g["type"] = Value::from("url-test");
                    // do not jump between servers for a few milliseconds
                    g["tolerance"] = Value::from(50);
                }
                crate::routes::Strategy::Balance => {
                    g["type"] = Value::from("load-balance");
                    g["strategy"] = Value::from("consistent-hashing");
                }
            }
            groups.push(g);
            let mut chain_of = vec![route_servers_group(&r.id)];
            chain_of.extend(spare_chain(r, &mut groups));
            groups.push(json!({
                "name": route_group(&r.id),
                "type": "fallback",
                "proxies": chain_of,
                "url": TEST_URL,
                "interval": 180,
                "lazy": false,
                "timeout": 5000,
                "max-failed-times": 2,
                "expected-status": "204"
            }));
        }
        if let Via::Chain(cid) = &r.via {
            let mut chain_of = vec![chain_group(cid)];
            chain_of.extend(spare_chain(r, &mut groups));
            groups.push(json!({
                "name": route_group(&r.id),
                "type": "fallback",
                "proxies": chain_of,
                "url": TEST_URL,
                "interval": 180,
                "lazy": false,
                "timeout": 5000,
                "max-failed-times": 2,
                "expected-status": "204"
            }));
        }
    }
    let default_out = match &o.default_chain {
        Some(cid) => chain_group(cid),
        None if o.default_direct => "DIRECT".to_string(),
        None => "VPN".to_string(),
    };
    rules.push(format!("MATCH,{default_out}"));
    // Real lookups (UDP to domains, rule matching) go through the tunnel: the network may
    // block or tamper with DNS. Only proxy server names are resolved directly.
    let doh_vpn = json!(["https://1.1.1.1/dns-query#VPN", "https://8.8.8.8/dns-query#VPN"]);
    let mut v = json!({
        "mode": "rule",
        "log-level": "warning",
        "ipv6": o.ipv6,
        "allow-lan": false,
        "bind-address": "127.0.0.1",
        "unified-delay": true,
        "tcp-concurrent": true,
        "find-process-mode": "strict",
        "geodata-mode": false,
        "geo-auto-update": false,
        "external-controller": format!("127.0.0.1:{}", o.api_port),
        "secret": o.secret,
        "profile": { "store-selected": false, "store-fake-ip": true },
        "keep-alive-idle": 600,
        "keep-alive-interval": 30,
        "tun": {
            "enable": true,
            "device": o.tun_name,
            "stack": o.stack,
            "auto-route": true,
            "auto-detect-interface": true,
            "strict-route": o.strict_route,
            "dns-hijack": ["any:53", "tcp://any:53"],
            "route-exclude-address": LAN,
        },
        "sniffer": {
            "enable": true,
            "force-dns-mapping": true,
            "parse-pure-ip": true,
            "override-destination": true,
            "sniff": {
                "HTTP": { "ports": [80, 8080] },
                "TLS": { "ports": [443, 8443] },
                "QUIC": { "ports": [443, 8443] }
            },
            "skip-domain": ["+.lan", "+.local"]
        },
        "dns": {
            "enable": true,
            "ipv6": false,
            "enhanced-mode": "fake-ip",
            "fake-ip-range": "198.18.0.1/16",
            "fake-ip-filter": FAKE_IP_FILTER,
            "default-nameserver": ["77.88.8.8", "1.1.1.1", "8.8.8.8"],
            "nameserver": doh_vpn,
            // proxy hostnames: DoH, plus plain DNS in case DoH is blocked
            "proxy-server-nameserver": ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "77.88.8.8"],
            // excluded (direct) domains: the network's own resolver gives the nearest CDN
            "direct-nameserver": ["system://", "77.88.8.8"],
        },
        "proxy-providers": {
            "pool": {
                "type": "file",
                "path": "./pool.yaml",
                "health-check": { "enable": true, "url": TEST_URL, "interval": 600, "lazy": true, "timeout": 5000, "expected-status": "204" }
            },
            // servers that only routes use (each server lives in exactly one provider:
            // two copies of one WireGuard key would fight over the same session)
            "extra": { "type": "file", "path": "./extra.yaml" }
        },
        "proxy-groups": groups,
        "rule-providers": rule_providers,
        "rules": rules,
    });
    if !chain_proxies.is_empty() {
        v["proxies"] = Value::Array(chain_proxies);
    }
    if let Some(port) = o.proxy_port {
        v["tun"]["enable"] = Value::from(false);
        v["mixed-port"] = Value::from(port);
        v["dns"]["listen"] = Value::from("127.0.0.1:1053");
    }
    v
}

/// Proxy-provider file content (JSON is valid YAML).
pub fn pool_file(servers: &[&Server]) -> String {
    let list: Vec<Value> = servers.iter().map(|s| s.mihomo_proxy()).collect();
    json!({ "proxies": list }).to_string()
}

/// Name of the placeholder that keeps the "extra" provider valid (mihomo refuses an empty
/// provider file). It rejects and no group selects it.
pub const PLACEHOLDER: &str = "lazeyka-none";

/// The "extra" provider: route-only servers plus the placeholder.
pub fn extra_file(servers: &[&Server]) -> String {
    let mut list: Vec<Value> = servers.iter().map(|s| s.mihomo_proxy()).collect();
    list.push(json!({ "name": PLACEHOLDER, "type": "reject" }));
    json!({ "proxies": list }).to_string()
}

#[derive(Clone, Debug)]
pub struct Listener {
    /// Proxy name (server id) or "DIRECT".
    pub proxy: String,
    pub port: u16,
    pub user: String,
    pub pass: String,
}

#[derive(Clone, Debug)]
pub struct LabOpts {
    pub api_port: u16,
    pub secret: String,
    /// Physical NIC to bind to while the main TUN is up.
    pub interface: Option<String>,
    pub listeners: Vec<Listener>,
}

/// Scanner instance: every server gets its own authenticated SOCKS listener on 127.0.0.1.
pub fn lab_config(servers: &[&Server], o: &LabOpts) -> Value {
    let proxies: Vec<Value> = servers.iter().map(|s| s.mihomo_proxy()).collect();
    let names: Vec<Value> = servers.iter().map(|s| Value::String(s.id.clone())).collect();
    let listeners: Vec<Value> = o
        .listeners
        .iter()
        .enumerate()
        .map(|(i, l)| {
            json!({
                "name": format!("l{i}"),
                "type": "socks",
                "listen": "127.0.0.1",
                "port": l.port,
                "udp": true,
                "proxy": l.proxy,
                "users": [{ "username": l.user, "password": l.pass }]
            })
        })
        .collect();
    let doh = json!(["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query"]);
    let mut cfg = json!({
        "mode": "rule",
        "log-level": "error",
        "ipv6": true,
        "allow-lan": false,
        "bind-address": "127.0.0.1",
        "unified-delay": true,
        "tcp-concurrent": true,
        "geodata-mode": false,
        "geo-auto-update": false,
        "external-controller": format!("127.0.0.1:{}", o.api_port),
        "secret": o.secret,
        "profile": { "store-selected": false, "store-fake-ip": false },
        "dns": {
            "enable": true,
            "ipv6": false,
            "enhanced-mode": "redir-host",
            "default-nameserver": ["1.1.1.1", "8.8.8.8"],
            "nameserver": doh,
            "proxy-server-nameserver": doh,
        },
        "proxies": proxies,
        "proxy-groups": [{ "name": "ALL", "type": "select", "proxies": if names.is_empty() { vec![Value::from("DIRECT")] } else { names } }],
        "listeners": listeners,
        "rules": ["MATCH,DIRECT"],
    });
    if let Some(i) = &o.interface {
        cfg["interface-name"] = Value::String(i.clone());
    }
    cfg
}

// ---------------- REST API ----------------

#[derive(Clone)]
pub struct Api {
    base: String,
    secret: String,
    http: reqwest::Client,
}

fn enc(s: &str) -> String {
    percent_encoding::utf8_percent_encode(s, percent_encoding::NON_ALPHANUMERIC).to_string()
}

impl Api {
    pub fn new(port: u16, secret: &str) -> Api {
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(crate::probe::tls_config())
            .no_proxy()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(2)
            .build()
            .expect("http client");
        Api { base: format!("http://127.0.0.1:{port}"), secret: secret.to_string(), http }
    }

    async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>, timeout: Duration) -> Result<Value, String> {
        let mut rq = self
            .http
            .request(method, format!("{}{}", self.base, path))
            .bearer_auth(&self.secret)
            .timeout(timeout);
        if let Some(b) = body {
            rq = rq.header("content-type", "application/json").body(b.to_string());
        }
        let r = rq.send().await.map_err(|e| format!("mihomo API: {e}"))?;
        let st = r.status();
        let text = r.text().await.unwrap_or_default();
        if !st.is_success() {
            return Err(format!("mihomo API {path}: {st} {}", crate::util::clip(&text, 200)));
        }
        if text.is_empty() {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_str(&text).unwrap_or(Value::String(text)))
    }

    pub async fn version(&self) -> Result<String, String> {
        let v = self.call(reqwest::Method::GET, "/version", None, Duration::from_secs(2)).await?;
        Ok(v.get("version").and_then(|v| v.as_str()).unwrap_or("").to_string())
    }

    pub async fn reload_proxy_provider(&self, name: &str) -> Result<(), String> {
        self.call(reqwest::Method::PUT, &format!("/providers/proxies/{}", enc(name)), None, Duration::from_secs(10)).await.map(|_| ())
    }

    /// Re-reads the configuration file mihomo was started with, in place: the TUN stays up
    /// when its settings are unchanged; groups, rules and providers are rebuilt.
    pub async fn reload_config(&self) -> Result<(), String> {
        self.call(reqwest::Method::PUT, "/configs?force=false", Some(json!({ "path": "", "payload": "" })), Duration::from_secs(30))
            .await
            .map(|_| ())
    }

    pub async fn reload_rule_provider(&self, name: &str) -> Result<(), String> {
        self.call(reqwest::Method::PUT, &format!("/providers/rules/{}", enc(name)), None, Duration::from_secs(10)).await.map(|_| ())
    }

    pub async fn select(&self, group: &str, name: &str) -> Result<(), String> {
        self.call(reqwest::Method::PUT, &format!("/proxies/{}", enc(group)), Some(json!({ "name": name })), Duration::from_secs(5))
            .await
            .map(|_| ())
    }

    /// Currently used proxy of a group (follows nested groups one level: VPN → AUTO → node).
    pub async fn now(&self, group: &str) -> Option<String> {
        let v = self.call(reqwest::Method::GET, &format!("/proxies/{}", enc(group)), None, Duration::from_secs(3)).await.ok()?;
        v.get("now").and_then(|v| v.as_str()).map(|s| s.to_string())
    }

    pub async fn proxy_delay(&self, name: &str, url: &str, timeout_ms: u32) -> Option<u32> {
        let p = format!("/proxies/{}/delay?url={}&timeout={timeout_ms}", enc(name), enc(url));
        let v = self
            .call(reqwest::Method::GET, &p, None, Duration::from_millis(timeout_ms as u64 + 3000))
            .await
            .ok()?;
        v.get("delay").and_then(|d| d.as_u64()).filter(|d| *d > 0).map(|d| d as u32)
    }

    /// Tests all members of a group concurrently inside mihomo. Returns name → delay for alive ones.
    pub async fn group_delay(&self, group: &str, url: &str, timeout_ms: u32) -> HashMap<String, u32> {
        let p = format!("/group/{}/delay?url={}&timeout={timeout_ms}", enc(group), enc(url));
        let mut out = HashMap::new();
        if let Ok(Value::Object(m)) = self
            .call(reqwest::Method::GET, &p, None, Duration::from_millis(timeout_ms as u64 * 3 + 10_000))
            .await
        {
            for (k, v) in m {
                if let Some(d) = v.as_u64().filter(|d| *d > 0) {
                    out.insert(k, d as u32);
                }
            }
        }
        out
    }

    pub async fn close_connections(&self) {
        let _ = self.call(reqwest::Method::DELETE, "/connections", None, Duration::from_secs(5)).await;
    }

    /// (upload total, download total, active connections)
    pub async fn totals(&self) -> Option<(u64, u64, usize)> {
        let v = self.call(reqwest::Method::GET, "/connections", None, Duration::from_secs(3)).await.ok()?;
        Some((
            v.get("uploadTotal").and_then(|x| x.as_u64()).unwrap_or(0),
            v.get("downloadTotal").and_then(|x| x.as_u64()).unwrap_or(0),
            v.get("connections").and_then(|x| x.as_array()).map(|a| a.len()).unwrap_or(0),
        ))
    }

    pub async fn memory(&self) -> Option<u64> {
        // /memory is a stream; read the first line only
        let r = self
            .http
            .get(format!("{}/memory", self.base))
            .bearer_auth(&self.secret)
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .ok()?;
        let mut r = r;
        let chunk = r.chunk().await.ok()??;
        let v: Value = serde_json::from_slice(chunk.split(|b| *b == b'\n').next()?).ok()?;
        v.get("inuse").and_then(|x| x.as_u64())
    }
}

// ---------------- process ----------------

pub type LogBuf = Arc<Mutex<VecDeque<String>>>;

pub struct Process {
    child: tokio::process::Child,
    pub api: Api,
    pub log: LogBuf,
    pub dir: PathBuf,
}

pub struct Spawn<'a> {
    pub bin: &'a Path,
    pub dir: &'a Path,
    pub config_file: &'a str,
    pub api_port: u16,
    pub secret: &'a str,
    /// GOMEMLIMIT in MiB.
    pub mem_mb: u32,
}

/// Work dir as passed to mihomo: without a Windows extended-length `\\?\`
/// prefix. mihomo (Go) cannot open its cache file when that prefix meets
/// its `/` separator (observed on a real install:
/// `\\?\D:\2\Lazeyka\data\run/cache.db` — "filename syntax is
/// incorrect"). Rust itself handles the prefix fine, so only the dir
/// handed to mihomo is stripped. Harmless elsewhere: such a prefix never
/// occurs in a normal Unix path.
pub fn plain_work_dir(dir: &Path) -> PathBuf {
    let s = dir.to_string_lossy();
    PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s))
}

impl Process {
    pub async fn start(s: Spawn<'_>) -> Result<Process, String> {
        let mut cmd = tokio::process::Command::new(s.bin);
        let dir = plain_work_dir(s.dir);
        cmd.arg("-d").arg(&dir).arg("-f").arg(dir.join(s.config_file));
        cmd.env("GOMEMLIMIT", format!("{}MiB", s.mem_mb));
        cmd.env("GOGC", "50");
        cmd.env("DISABLE_LOOPBACK_DETECTOR", "1");
        cmd.env_remove("HTTP_PROXY").env_remove("HTTPS_PROXY").env_remove("ALL_PROXY");
        cmd.stdin(std::process::Stdio::null());
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.kill_on_drop(true);
        #[cfg(windows)]
        {
            cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        }
        kill_stale(s.dir);
        let mut child = cmd.spawn().map_err(|e| format!("не удалось запустить mihomo: {e}"))?;
        #[cfg(windows)]
        winproc::adopt(&child);
        if let Some(pid) = child.id() {
            let _ = std::fs::write(s.dir.join(PID_FILE), pid.to_string());
        }
        let log: LogBuf = Arc::new(Mutex::new(VecDeque::with_capacity(64)));
        for stream in [child.stdout.take().map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>), child.stderr.take().map(|s| Box::new(s) as Box<dyn tokio::io::AsyncRead + Unpin + Send>)].into_iter().flatten() {
            let log = log.clone();
            tokio::spawn(async move {
                let mut lines = BufReader::new(stream).lines();
                while let Ok(Some(l)) = lines.next_line().await {
                    let mut g = log.lock().unwrap();
                    if g.len() >= 200 {
                        g.pop_front();
                    }
                    g.push_back(strip_ansi(&l));
                }
            });
        }
        let api = Api::new(s.api_port, s.secret);
        let mut p = Process { child, api, log, dir: s.dir.to_path_buf() };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        loop {
            if let Ok(Some(st)) = p.child.try_wait() {
                tokio::time::sleep(Duration::from_millis(100)).await;
                return Err(format!("mihomo завершился ({st}): {}", p.last_log(6)));
            }
            if p.api.version().await.is_ok() {
                return Ok(p);
            }
            if tokio::time::Instant::now() > deadline {
                let msg = p.last_log(6);
                p.stop().await;
                return Err(format!("mihomo не отвечает: {msg}"));
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
    }

    pub fn last_log(&self, n: usize) -> String {
        let g = self.log.lock().unwrap();
        g.iter().rev().take(n).rev().cloned().collect::<Vec<_>>().join(" | ")
    }

    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.id()
    }

    pub async fn stop(&mut self) {
        // Unix: let mihomo remove its routes/rules first. Windows: the TUN adapter and
        // WFP filters are owned by the process and vanish with it.
        #[cfg(unix)]
        if let Some(pid) = self.child.id() {
            let _ = std::process::Command::new("kill").arg("-TERM").arg(pid.to_string()).status();
            if tokio::time::timeout(Duration::from_secs(3), self.child.wait()).await.is_ok() {
                let _ = std::fs::remove_file(self.dir.join(PID_FILE));
                return;
            }
        }
        let _ = self.child.start_kill();
        let _ = tokio::time::timeout(Duration::from_secs(5), self.child.wait()).await;
        let _ = std::fs::remove_file(self.dir.join(PID_FILE));
    }
}

const PID_FILE: &str = "mihomo.pid";

/// Kills a mihomo left over from a crashed engine in this working dir (pid file),
/// verifying the image name first.
pub fn kill_stale(dir: &Path) {
    let Ok(t) = std::fs::read_to_string(dir.join(PID_FILE)) else { return };
    let _ = std::fs::remove_file(dir.join(PID_FILE));
    let Ok(pid) = t.trim().parse::<u32>() else { return };
    #[cfg(unix)]
    {
        let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
        let is_mihomo = exe.as_ref().and_then(|p| p.file_name()).map(|n| n.to_string_lossy().starts_with("mihomo")).unwrap_or(false);
        if is_mihomo {
            let _ = std::process::Command::new("kill").arg("-TERM").arg(pid.to_string()).status();
            for _ in 0..30 {
                if !Path::new(&format!("/proc/{pid}")).exists() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            let _ = std::process::Command::new("kill").arg("-KILL").arg(pid.to_string()).status();
        }
    }
    #[cfg(windows)]
    winproc::kill_if_mihomo(pid);
}

#[cfg(windows)]
mod winproc {
    use std::sync::OnceLock;
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, QueryFullProcessImageNameW, TerminateProcess,
        WaitForSingleObject,
    };
    use windows::core::PWSTR;

    struct Job(HANDLE);
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    /// Job object that kills all children when the engine process ends (even on crash).
    fn job() -> Option<&'static Job> {
        static JOB: OnceLock<Option<Job>> = OnceLock::new();
        JOB.get_or_init(|| unsafe {
            let h = CreateJobObjectW(None, None).ok()?;
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            SetInformationJobObject(
                h,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const std::ffi::c_void,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
            .ok()?;
            Some(Job(h))
        })
        .as_ref()
    }

    pub fn adopt(child: &tokio::process::Child) {
        if let (Some(j), Some(h)) = (job(), child.raw_handle()) {
            unsafe {
                let _ = AssignProcessToJobObject(j.0, HANDLE(h));
            }
        }
    }

    pub fn kill_if_mihomo(pid: u32) {
        unsafe {
            let Ok(h) = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE, false, pid) else { return };
            let mut buf = [0u16; 1024];
            let mut len = buf.len() as u32;
            if QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, PWSTR(buf.as_mut_ptr()), &mut len).is_ok() {
                let path = String::from_utf16_lossy(&buf[..len as usize]).to_lowercase();
                if path.rsplit('\\').next().map(|n| n.starts_with("mihomo")).unwrap_or(false) {
                    let _ = TerminateProcess(h, 1);
                    let _ = WaitForSingleObject(h, 3000);
                }
            }
            let _ = CloseHandle(h);
        }
    }
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        if c == '\u{1b}' {
            for d in it.by_ref() {
                if d.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Picks a free TCP port on 127.0.0.1.
pub fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").and_then(|l| l.local_addr()).map(|a| a.port()).unwrap_or(0)
}

/// Picks `n` distinct free ports (kept bound until all are chosen).
pub fn free_ports(n: usize) -> Vec<u16> {
    let ls: Vec<std::net::TcpListener> = (0..n).filter_map(|_| std::net::TcpListener::bind("127.0.0.1:0").ok()).collect();
    ls.iter().filter_map(|l| l.local_addr().ok()).map(|a| a.port()).collect()
}

/// Writes a file atomically (tmp + rename).
pub fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts() -> MainOpts {
        MainOpts {
            api_port: 9090,
            secret: "s".into(),
            default_direct: false,
            default_chain: None,
            routes: vec![],
            chains: vec![],
            hops: vec![],
            stack: "gvisor".into(),
            strict_route: true,
            ipv6: true,
            tun_name: "lazeyka".into(),
            proxy_port: Some(7899),
        }
    }

    fn ss(name: &str, port: u64) -> Value {
        json!({ "name": name, "type": "ss", "server": "127.0.0.1", "port": port, "cipher": "aes-128-gcm", "password": "x" })
    }

    #[test]
    fn strategy_and_hops_config() {
        let mk = |host: &str| {
            let m: serde_json::Map<String, Value> = serde_json::from_value(ss("x", 8388)).unwrap();
            let mut m = m;
            m.insert("server".into(), Value::from(host));
            Server::new(host, m, crate::model::Origin::Free, "t").unwrap()
        };
        let hop = mk("1.1.1.1");
        let mut relay = mk("2.2.2.2");
        relay.relay = Some(hop.id.clone());
        let mut o = opts();
        o.hops = vec![hop.clone()];
        o.routes = vec![RoutePlan { id: "r1".into(), via: Via::Servers(vec![relay.id.clone()]), spare: Spare::Vpn, strategy: crate::routes::Strategy::Fastest }];
        let cfg = main_config(&o);
        let groups = cfg["proxy-groups"].as_array().unwrap();
        let g = groups.iter().find(|g| g["name"] == route_servers_group("r1")).unwrap();
        assert_eq!(g["type"], "url-test");
        assert_eq!(g["tolerance"], 50);
        o.routes[0].strategy = crate::routes::Strategy::Balance;
        let cfg = main_config(&o);
        let g = cfg["proxy-groups"].as_array().unwrap().iter().find(|g| g["name"] == route_servers_group("r1")).unwrap().clone();
        assert_eq!(g["type"], "load-balance");
        assert_eq!(g["strategy"], "consistent-hashing");
        // the hop is a config-level proxy; the relay server in the pool dials through it
        let names: Vec<&str> = cfg["proxies"].as_array().unwrap().iter().map(|p| p["name"].as_str().unwrap()).collect();
        assert_eq!(names, [format!("hop:{}", hop.id)]);
        let pool: Value = serde_json::from_str(&pool_file(&[&relay])).unwrap();
        assert_eq!(pool["proxies"][0]["dialer-proxy"], format!("hop:{}", hop.id));
    }

    #[test]
    fn plain_work_dir_strips_extended_prefix() {
        assert_eq!(plain_work_dir(Path::new(r"\\?\D:\2\Lazeyka\data\run")), PathBuf::from(r"D:\2\Lazeyka\data\run"));
        assert_eq!(plain_work_dir(Path::new("/tmp/lazeyka-data/run")), PathBuf::from("/tmp/lazeyka-data/run"));
    }

    #[test]
    fn chain_config_wires_levels() {
        let mut o = opts();
        // hop 1: the VPN itself; hop 2: one server; hop 3: two servers
        o.chains = vec![ChainPlan {
            id: "c1".into(),
            levels: vec![vec![], vec![ss("nb~c1-2", 1002)], vec![ss("nc~c1-3", 1003), ss("nd~c1-3", 1004)]],
        }];
        o.default_chain = Some("c1".into());
        o.routes = vec![RoutePlan { id: "r1".into(), via: Via::Chain("c1".into()), spare: Spare::Vpn, strategy: Default::default() }];
        let v = main_config(&o);
        let groups: Vec<&Value> = v["proxy-groups"].as_array().unwrap().iter().collect();
        let by_name = |n: &str| groups.iter().find(|g| g["name"] == n).cloned().cloned();
        // level 1 is the VPN group itself, the exit group points at the last level
        assert_eq!(by_name("CH-c1-1").unwrap()["proxies"], json!(["VPN"]));
        assert_eq!(by_name("CH-c1").unwrap()["proxies"], json!(["CH-c1-3"]));
        // the route group: the chain first, the VPN as the spare
        assert_eq!(by_name("R-r1").unwrap()["proxies"], json!(["CH-c1", "VPN"]));
        // copies: level 2 dials through level 1, level 3 through level 2
        let proxies = v["proxies"].as_array().unwrap();
        assert_eq!(proxies.len(), 3);
        let dialer = |n: &str| proxies.iter().find(|p| p["name"] == n).and_then(|p| p.get("dialer-proxy")).cloned();
        assert_eq!(dialer("nb~c1-2"), Some(Value::from("CH-c1-1")));
        assert_eq!(dialer("nc~c1-3"), Some(Value::from("CH-c1-2")));
        assert_eq!(dialer("nd~c1-3"), Some(Value::from("CH-c1-2")));
        // the default target is the chain
        let rules = v["rules"].as_array().unwrap();
        assert_eq!(rules.last().unwrap(), "MATCH,CH-c1");
    }

    #[test]
    fn plain_config_has_no_chain_bits() {
        let v = main_config(&opts());
        assert!(v.get("proxies").is_none());
        let rules = v["rules"].as_array().unwrap();
        assert_eq!(rules.last().unwrap(), "MATCH,VPN");
    }
}
