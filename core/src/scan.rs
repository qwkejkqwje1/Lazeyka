//! Scanner: plans candidates from sources, tests them in batches through a "lab" mihomo
//! instance (one authenticated SOCKS listener per node), applies geo/exclusion rules,
//! measures speed of the best ones and ranks servers for the AUTO pool.

use crate::geo::Geo;
use crate::mihomo::{self, Listener};
use crate::model::*;
use crate::probe;
use crate::sources::SourceDef;
use crate::util;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Progress {
    pub running: bool,
    pub stage: String,
    pub total: usize,
    pub done: usize,
    pub good: usize,
    pub started: u64,
    pub finished: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

pub struct Env {
    pub mihomo: PathBuf,
    pub dir: PathBuf,
    pub geo: Option<Arc<Geo>>,
    pub interface: Option<String>,
    pub cancel: Arc<AtomicBool>,
    pub progress: Arc<Mutex<Progress>>,
}

impl Env {
    fn stage(&self, s: &str) {
        self.progress.lock().unwrap().stage = s.to_string();
    }
    fn cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Debug)]
pub struct Opts {
    pub batch: usize,
    pub parallel: usize,
    /// Stop after this many good servers (0 = test everything).
    pub target_good: usize,
    pub services: bool,
    pub udp: bool,
    pub speed_top: usize,
    pub delay_timeout_ms: u32,
    /// Only servers exiting in these countries count towards `target_good` (empty = all).
    pub want_cc: HashSet<String>,
    /// Cheap first stage: a plain TCP connect to servers that speak TCP; the closed ones
    /// never reach the (expensive) lab. Only valid when probes go out directly.
    pub prefilter: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts { batch: 256, parallel: 64, target_good: 12, services: true, udp: true, speed_top: 4, delay_timeout_ms: 5000, want_cc: HashSet::new(), prefilter: false }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct NetInfo {
    pub direct_ip: Option<IpAddr>,
    pub user_cc: Option<String>,
    pub at: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SourceStat {
    pub fetched: u64,
    pub parsed: usize,
    pub tested: u32,
    pub good: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl SourceStat {
    /// Smoothed success ratio (Laplace), used to order sources inside a tier.
    pub fn ratio(&self) -> f64 {
        (self.good as f64 + 1.0) / (self.tested as f64 + 4.0)
    }
}

/// Lower = more DPI-resistant / preferable.
pub fn proto_rank(s: &Server) -> u8 {
    let p = &s.proxy;
    let reality = p.contains_key("reality-opts");
    let tls = p.get("tls").and_then(|v| v.as_bool()).unwrap_or(false);
    let net = p.get("network").and_then(|v| v.as_str()).unwrap_or("tcp");
    match s.proto {
        Proto::Vless if reality => 0,
        Proto::Vless if tls && net == "xhttp" => 1,
        Proto::Hysteria2 | Proto::Anytls | Proto::Tuic | Proto::Awg => 1,
        Proto::Trojan => 2,
        Proto::Vless if tls => 2,
        Proto::Vmess if tls => 3,
        Proto::Ss if p.get("cipher").and_then(|v| v.as_str()).is_some_and(|c| c.starts_with("2022-")) || p.contains_key("plugin") => 4,
        Proto::Ss => 5,
        Proto::Vmess => 5,
        Proto::Openvpn => 5,
        Proto::Wireguard => 6,
        Proto::Vless => 7,
    }
}

/// Free servers we never use: unencrypted VLESS, SS without cipher.
pub fn insecure(s: &Server) -> bool {
    let p = &s.proxy;
    match s.proto {
        Proto::Vless => {
            !p.get("tls").and_then(|v| v.as_bool()).unwrap_or(false) && p.get("encryption").and_then(|v| v.as_str()).unwrap_or("none") == "none"
        }
        Proto::Ss => p.get("cipher").and_then(|v| v.as_str()) == Some("none"),
        _ => false,
    }
}

/// Added to the score of servers that answer only through an entry hop.
pub const RELAY_TIER: i64 = 100_000;

/// Ranking score for AUTO order; lower is better. Non-working servers get i64::MAX.
pub fn score(s: &Server) -> i64 {
    let Some(p) = s.probe.as_ref().filter(|p| p.ok) else { return i64::MAX };
    let mut sc = p.latency.unwrap_or(1500).min(5000) as i64;
    if p.udp == Some(false) {
        sc += 250;
    }
    if p.services & SVC_YOUTUBE == 0 {
        sc += 400;
    }
    if p.services & SVC_TELEGRAM == 0 {
        sc += 100;
    }
    if p.services & SVC_DISCORD == 0 {
        sc += 50;
    }
    if let Some(sp) = p.speed {
        sc -= (sp as i64 / 50).min(400);
    }
    sc += proto_rank(s) as i64 * 40;
    // two hops: slower and one more thing that can break. A reserve tier: every
    // direct server ranks above every relay one.
    if s.relay.is_some() {
        sc += RELAY_TIER;
    }
    sc -= (s.oks.min(20) as i64) * 5;
    // flaky servers sink: 75% of checks passed → +100
    if s.hist_n >= 4 {
        if let Some(st) = s.stability() {
            sc += (100 - st as i64) * 4;
        }
    }
    match s.origin {
        Origin::Mine => sc - 1_000_000,
        Origin::Warp => sc + 300,
        Origin::Free => sc,
    }
}

/// Whether a background cycle may re-test this server now. A WireGuard-family
/// "check" is a real tunnel: free profiles share one key and client address with
/// every other user, so testers keep stealing the session from each other and the
/// result proves little — yet the tunnel costs traffic and can knock out a live
/// session on the same profile. Background cycles therefore refresh WireGuard at
/// most once a day; first checks and on-demand checks are unaffected.
pub fn bg_recheck(s: &Server, now: u64) -> bool {
    if !matches!(s.proto, Proto::Wireguard | Proto::Awg) {
        return true;
    }
    match &s.probe {
        None => true,
        Some(p) => now.saturating_sub(p.at) > 24 * 3600,
    }
}

/// How long a failing public server rests before it is tried again. Free servers flap
/// (overloaded, rotated, rate-limited), so there is no long ban: the rest grows
/// 20 min → 40 → 80 … capped at 6 h, and servers that worked at least once rest half as long.
pub fn cooldown(s: &Server) -> u64 {
    if s.fails < 2 {
        return 0;
    }
    let c = ((20u64 * 60) << (s.fails - 2).min(5)).min(6 * 3600);
    if s.oks > 0 { c / 2 } else { c }
}

/// Picks candidates to test, round-robin across sources (tier order, then source success),
/// best protocols first, skipping recently failed and insecure ones. Candidates for which
/// `prefer` holds (e.g. entry IP in the chosen countries) are all taken before the others.
pub fn plan(
    all: &[Server],
    sources: &[SourceDef],
    stats: &HashMap<String, SourceStat>,
    limit: usize,
    now: u64,
    prefer: &dyn Fn(&Server) -> bool,
) -> Vec<Server> {
    let mut by_src: HashMap<&str, Vec<&Server>> = HashMap::new();
    for s in all {
        if s.origin != Origin::Free || insecure(s) {
            continue;
        }
        let recent = s.probe.as_ref().map(|p| now.saturating_sub(p.at)).unwrap_or(u64::MAX);
        if recent < cooldown(s) {
            continue;
        }
        by_src.entry(s.source.as_str()).or_default().push(s);
    }
    let mut srcs: Vec<&SourceDef> = sources.iter().filter(|d| d.enabled && by_src.contains_key(d.id.as_str())).collect();
    srcs.sort_by(|a, b| {
        a.tier.cmp(&b.tier).then_with(|| {
            let ra = stats.get(&a.id).map(|s| s.ratio()).unwrap_or(0.25);
            let rb = stats.get(&b.id).map(|s| s.ratio()).unwrap_or(0.25);
            rb.partial_cmp(&ra).unwrap_or(std::cmp::Ordering::Equal)
        })
    });
    let mut queues: Vec<(u8, std::collections::VecDeque<&Server>)> = Vec::new();
    let mut later: Vec<(u8, std::collections::VecDeque<&Server>)> = Vec::new();
    for d in &srcs {
        let mut v = by_src.remove(d.id.as_str()).unwrap_or_default();
        // previously good first, then protocol rank, then shuffle-ish by id
        // previously good first; then servers that appeared in the last day (fresh entries
        // of a list live longest and have not been blocked yet); then DPI resistance
        v.sort_by_key(|s| {
            let fresh = now.saturating_sub(s.added) < 24 * 3600;
            (if s.good() { 0 } else { 1 }, if fresh { 0 } else { 1 }, proto_rank(s), s.fails, std::cmp::Reverse(s.added), s.id.clone())
        });
        v.truncate(d.cap);
        let (a, b): (Vec<&Server>, Vec<&Server>) = v.into_iter().partition(|s| prefer(s));
        queues.push((d.tier, a.into_iter().collect()));
        later.push((d.tier, b.into_iter().collect()));
    }
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for qs in [&mut queues, &mut later] {
        for tier in 1..=3u8 {
            loop {
                let mut progressed = false;
                for (t, q) in qs.iter_mut() {
                    if *t != tier {
                        continue;
                    }
                    if let Some(s) = q.pop_front() {
                        progressed = true;
                        if seen.insert(s.id.clone()) {
                            out.push(s.clone());
                            if out.len() >= limit {
                                return out;
                            }
                        }
                    }
                }
                if !progressed {
                    break;
                }
            }
        }
    }
    out
}

/// Why servers were rejected: "не отвечает ×1400, таймаут ×120 …", most frequent first.
pub fn reasons(list: &[Server]) -> String {
    let mut m: HashMap<String, usize> = HashMap::new();
    let mut ok = 0usize;
    for s in list {
        match s.probe.as_ref() {
            Some(p) if p.ok => ok += 1,
            Some(p) => *m.entry(p.error.clone().unwrap_or_else(|| "без причины".into())).or_default() += 1,
            None => {}
        }
    }
    let mut v: Vec<(String, usize)> = m.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
    let rest: Vec<String> = v.iter().take(6).map(|(k, n)| format!("{k} ×{n}")).collect();
    format!("рабочих {ok}; отказы: {}", if rest.is_empty() { "нет".to_string() } else { rest.join(", ") })
}

/// Working servers that can carry another server's connection. Priority: the user's own
/// and starred servers (a WireGuard / AmneziaWG of theirs included — if any of them works,
/// only they are used), then Reality, then the rest by score. Different hosts, no relay
/// servers themselves, no WARP (its single key must not be shared), no free WireGuard
/// profiles (shared keys), nothing in `avoid` (keys that are already open elsewhere).
pub fn relay_hops(all: &[Server], n: usize, avoid: &HashSet<String>) -> Vec<Server> {
    let own = |s: &Server| s.origin == Origin::Mine || s.fav;
    let wg = |s: &Server| matches!(s.proto, Proto::Wireguard | Proto::Awg);
    let mut v: Vec<&Server> = all
        .iter()
        .filter(|s| s.good() && s.relay.is_none() && s.origin != Origin::Warp && !insecure(s) && !avoid.contains(&s.id) && (!wg(s) || own(s)))
        .collect();
    if v.iter().any(|s| own(s)) {
        v.retain(|s| own(s));
    }
    v.sort_by_key(|s| (!own(s), proto_rank(s) != 0, score(s), s.id.clone()));
    let mut hosts = HashSet::new();
    v.into_iter().filter(|s| hosts.insert(s.host.clone())).take(n).cloned().collect()
}

/// Servers worth a second look through a hop: TCP-based, failed from here because the
/// way to them is closed (port closed / no answer), not tried through a hop lately.
pub fn relay_candidates(all: &[Server], now: u64, limit: usize, retry_after: u64) -> Vec<Server> {
    let unreachable = |e: &str| e.starts_with("порт закрыт") || e.starts_with("не отвечает");
    let mut v: Vec<&Server> = all
        .iter()
        .filter(|s| s.origin != Origin::Warp && s.relay.is_none() && !insecure(s) && !is_udp_proto(s))
        .filter(|s| now.saturating_sub(s.relay_at) >= retry_after)
        .filter(|s| s.probe.as_ref().is_some_and(|p| !p.ok && p.error.as_deref().is_some_and(unreachable)))
        .collect();
    v.sort_by_key(|s| {
        let fresh = now.saturating_sub(s.added) < 24 * 3600;
        (if s.origin == Origin::Mine || s.fav { 0 } else { 1 }, if s.oks > 0 { 0 } else { 1 }, if fresh { 0 } else { 1 }, proto_rank(s), s.id.clone())
    });
    v.into_iter().take(limit).cloned().collect()
}

/// Tests servers through working entry hops. In one lab: the hops themselves and, for
/// every candidate, a copy that dials through its hop (the one in `relay` when it is
/// among `hops`, else round-robin). Successes come back with `relay` set and a fresh
/// probe; failures only get `relay_at` (their direct failure was already counted).
pub async fn check_relay(env: &Env, list: Vec<Server>, hops: Vec<Server>, o: &Opts, net: &mut NetInfo, mut on_batch: impl FnMut(&[Server])) -> Vec<Server> {
    let mut done: Vec<Server> = Vec::new();
    if hops.is_empty() || list.is_empty() {
        return done;
    }
    env.progress.lock().unwrap().total += list.len();
    let nh = hops.len();
    let mut queue: std::collections::VecDeque<Server> = list.into_iter().collect();
    while !queue.is_empty() && !env.cancelled() {
        env.stage("Проверка через входное звено");
        let n = o.batch.min(queue.len());
        let mut batch: Vec<Server> = queue.drain(..n).collect();
        let mut lab = None;
        let mut variants: Vec<Server> = Vec::new();
        let mut hop_ids: Vec<String> = Vec::new();
        for _ in 0..6 {
            variants.clear();
            hop_ids.clear();
            for (i, s) in batch.iter().enumerate() {
                let hop = s.relay.as_ref().and_then(|r| hops.iter().find(|h| &h.id == r)).unwrap_or(&hops[i % nh]);
                let mut v = s.clone();
                v.id = format!("{}~r", s.id);
                v.relay = None;
                v.proxy.insert("dialer-proxy".into(), serde_json::Value::String(hop.id.clone()));
                variants.push(v);
                hop_ids.push(hop.id.clone());
            }
            let mut refs: Vec<&Server> = hops.iter().collect();
            refs.extend(variants.iter());
            match start_lab(env, &refs).await {
                Ok(l) => {
                    lab = Some(l);
                    break;
                }
                Err(e) => {
                    if let Some(i) = bad_proxy_index(&e).filter(|i| *i >= nh && *i - nh < batch.len()) {
                        let mut bad = batch.remove(i - nh);
                        bad.relay_at = util::now();
                        done.push(bad);
                        env.progress.lock().unwrap().done += 1;
                        continue;
                    }
                    env.progress.lock().unwrap().error = Some(e);
                    break;
                }
            }
        }
        let Some(mut lab) = lab else { break };
        let alive = lab.proc.api.group_delay("ALL", mihomo::TEST_URL, o.delay_timeout_ms * 2).await;
        let sem = Arc::new(tokio::sync::Semaphore::new(o.parallel.max(1)));
        let mut js = tokio::task::JoinSet::new();
        let mut results: Vec<Option<(Probe, Option<probe::Trace>)>> = vec![None; batch.len()];
        let mut skipped = 0usize;
        for (i, v) in variants.iter().enumerate() {
            if !alive.contains_key(&v.id) {
                skipped += 1;
                continue;
            }
            let l = &lab.nodes[nh + i];
            let nc = probe::NodeCheck { port: l.port, user: l.user.clone(), pass: l.pass.clone(), udp: false, services: o.services };
            let sem = sem.clone();
            js.spawn(async move {
                let _permit = sem.acquire_owned().await;
                (i, probe::check_node(&nc).await)
            });
        }
        env.progress.lock().unwrap().done += skipped;
        while let Some(r) = js.join_next().await {
            if env.cancelled() {
                js.abort_all();
                break;
            }
            if let Ok((i, res)) = r {
                results[i] = Some(res);
                env.progress.lock().unwrap().done += 1;
            }
        }
        lab.proc.stop().await;
        let now = util::now();
        let mut finished = Vec::new();
        let mut good = 0usize;
        for ((mut s, r), hop) in batch.into_iter().zip(results).zip(hop_ids) {
            let was_relay = s.relay.is_some();
            s.relay_at = now;
            if let Some((p, t)) = r.clone().filter(|(p, _)| p.ok) {
                let mut checked = s.clone();
                finalize(&mut checked, p, t, net, env.geo.as_deref());
                if checked.good() {
                    checked.relay = Some(hop);
                    checked.relay_at = now;
                    good += 1;
                    finished.push(checked);
                    continue;
                }
            }
            if was_relay {
                // a recheck of a relay server: the failure counts; after three it is
                // tried directly again like everyone else
                let (p, t) = r.unwrap_or_else(|| (Probe { at: now, error: Some("не отвечает (через звено)".into()), ..Default::default() }, None));
                finalize(&mut s, p, t, net, env.geo.as_deref());
                if s.fails >= 3 {
                    s.relay = None;
                }
            }
            finished.push(s);
        }
        env.progress.lock().unwrap().good += good;
        on_batch(&finished);
        done.extend(finished);
    }
    done
}

/// A relay server is only usable while the hop it dials through works.
pub fn relay_ok(all: &[Server], s: &Server) -> bool {
    s.relay.as_ref().is_none_or(|r| all.iter().any(|h| &h.id == r && h.good() && h.relay.is_none()))
}

/// Server exits in one of `cc` (an empty set matches everything).
pub fn in_countries(s: &Server, cc: &HashSet<String>) -> bool {
    cc.is_empty() || s.country().is_some_and(|c| cc.contains(c))
}

/// True when the country choice can be honoured (some server there works).
pub fn countries_usable(all: &[Server], cc: &HashSet<String>) -> bool {
    cc.is_empty() || all.iter().any(|s| s.good() && in_countries(s, cc))
}

pub struct PoolOpts<'a> {
    /// How many public / WARP servers to keep.
    pub size: usize,
    pub countries: &'a HashSet<String>,
    /// Keep the best working WARP variant as a spare.
    pub warp: bool,
    /// Manually chosen server: always present.
    pub selected: Option<&'a str>,
}

/// Hot pool for AUTO; the order is the fallback priority: working favourites, working own
/// servers, the best other servers (distinct hosts), a WARP spare, then own servers that are
/// not checked yet and, as a last resort, own/favourite servers that failed their last check.
/// With chosen countries only servers exiting there are used — unless none of them works.
pub fn pool(all: &[Server], o: &PoolOpts) -> Vec<Server> {
    let restrict = !o.countries.is_empty() && countries_usable(all, o.countries);
    let cc_ok = |s: &Server| !restrict || in_countries(s, o.countries);
    let sorted = |f: &dyn Fn(&Server) -> bool| {
        let mut v: Vec<&Server> = all.iter().filter(|s| f(s)).collect();
        v.sort_by_key(|s| score(s));
        v
    };
    let mut out: Vec<Server> = Vec::new();
    let push = |s: &Server, out: &mut Vec<Server>| {
        if !out.iter().any(|x| x.id == s.id) {
            out.push(s.clone());
        }
    };
    for s in sorted(&|s| s.fav && s.good() && cc_ok(s)) {
        push(s, &mut out);
    }
    for s in sorted(&|s| !s.fav && s.origin == Origin::Mine && s.good() && cc_ok(s)) {
        push(s, &mut out);
    }
    let mut hosts: HashSet<String> = out.iter().map(|s| s.host.clone()).collect();
    let mut n = 0;
    for s in sorted(&|s| !s.fav && s.origin == Origin::Free && s.good() && cc_ok(s)) {
        if n >= o.size {
            break;
        }
        if hosts.insert(s.host.clone()) {
            push(s, &mut out);
            n += 1;
        }
    }
    if o.warp && !out.iter().any(|s| s.origin == Origin::Warp) {
        if let Some(w) = sorted(&|s| s.origin == Origin::Warp && s.good() && cc_ok(s)).first() {
            push(w, &mut out);
        }
    }
    if !restrict {
        for s in all.iter().filter(|s| s.origin == Origin::Mine && s.probe.is_none()) {
            push(s, &mut out);
        }
        let mut dead: Vec<&Server> = all.iter().filter(|s| (s.origin == Origin::Mine || s.fav) && s.probe.as_ref().is_some_and(|p| !p.ok)).collect();
        dead.sort_by_key(|s| std::cmp::Reverse(s.last_ok));
        for s in dead {
            push(s, &mut out);
        }
    }
    if let Some(sel) = o.selected {
        if let Some(s) = all.iter().find(|s| s.id == sel) {
            push(s, &mut out);
        }
    }
    out
}

struct Lab {
    proc: mihomo::Process,
    nodes: Vec<Listener>,
    direct: Listener,
}

async fn start_lab(env: &Env, servers: &[&Server]) -> Result<Lab, String> {
    let ports = mihomo::free_ports(servers.len() + 2);
    if ports.len() < servers.len() + 2 {
        return Err("нет свободных портов".into());
    }
    let user = util::random_token(10);
    let pass = util::random_token(20);
    let nodes: Vec<Listener> = servers
        .iter()
        .zip(ports[2..].iter())
        .map(|(s, p)| Listener { proxy: s.id.clone(), port: *p, user: user.clone(), pass: pass.clone() })
        .collect();
    let direct = Listener { proxy: "DIRECT".into(), port: ports[1], user: user.clone(), pass: pass.clone() };
    let mut all = nodes.clone();
    all.push(direct.clone());
    let secret = util::random_token(24);
    let cfg = mihomo::lab_config(servers, &mihomo::LabOpts { api_port: ports[0], secret: secret.clone(), interface: env.interface.clone(), listeners: all });
    std::fs::create_dir_all(&env.dir).map_err(|e| e.to_string())?;
    mihomo::write_atomic(&env.dir.join("lab.json"), cfg.to_string().as_bytes()).map_err(|e| e.to_string())?;
    let proc = mihomo::Process::start(mihomo::Spawn {
        bin: &env.mihomo,
        dir: &env.dir,
        config_file: "lab.json",
        api_port: ports[0],
        secret: &secret,
        mem_mb: 160,
    })
    .await?;
    Ok(Lab { proc, nodes, direct })
}

/// Extracts the failing proxy index from a mihomo parse error ("proxy 12: ...").
fn bad_proxy_index(err: &str) -> Option<usize> {
    let i = err.find("proxy ")?;
    let rest = &err[i + 6..];
    let num: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if rest[num.len()..].starts_with(':') { num.parse().ok() } else { None }
}

/// Detects direct (real) IP and user country through the lab DIRECT listener.
pub async fn netinfo(l: &Listener, geo: Option<&Geo>) -> NetInfo {
    let mut n = NetInfo { at: util::now(), ..Default::default() };
    let Ok(c) = probe::client(Some((l.port, &l.user, &l.pass)), Duration::from_secs(8)) else { return n };
    if let Ok((t, _)) = probe::exit_ip(&c).await {
        n.direct_ip = t.ip;
        n.user_cc = t.ip.and_then(|ip| geo.and_then(|g| g.country(ip))).or(t.loc);
    }
    n
}

/// E2E test hook (debug builds only): a local test server exits with the machine's own
/// IP, which the direct-traffic check in `finalize` would reject. With
/// LAZEYKA_TEST_LOCAL_EXIT=1 a loopback server may pass; release builds compile
/// this out entirely.
fn test_local_exit(s: &Server) -> bool {
    cfg!(debug_assertions)
        && std::env::var_os("LAZEYKA_TEST_LOCAL_EXIT").is_some_and(|v| v == "1")
        && s.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn finalize(s: &mut Server, p: Probe, trace: Option<probe::Trace>, net: &NetInfo, geo: Option<&Geo>) {
    finalize_with(s, p, trace, net, geo, true)
}

/// `count` = false: the failure is not the server's fault (our network or lab was down),
/// so neither its failure counter nor its stability history is touched.
fn finalize_with(s: &mut Server, mut p: Probe, trace: Option<probe::Trace>, net: &NetInfo, geo: Option<&Geo>, count: bool) {
    if let Some(ip) = p.exit_ip.as_deref().and_then(|x| x.parse::<IpAddr>().ok()) {
        p.exit_cc = geo.and_then(|g| g.country(ip)).or_else(|| trace.as_ref().and_then(|t| t.loc.clone()));
        if p.ok && net.direct_ip == Some(ip) && !test_local_exit(s) {
            p.ok = false;
            p.error = Some("трафик идёт напрямую".into());
        }
    }
    if p.ok && s.origin == Origin::Free {
        if let (Some(cc), Some(ucc)) = (&p.exit_cc, &net.user_cc) {
            if cc == ucc {
                p.ok = false;
                p.error = Some(format!("выход в вашей стране ({cc})"));
            }
        }
    }
    if p.ok {
        s.oks = s.oks.saturating_add(1);
        s.fails = 0;
        s.last_ok = p.at;
    } else if count {
        s.fails = s.fails.saturating_add(1);
    }
    if count || p.ok {
        s.record(p.ok);
    }
    // keep a previously measured speed for a day
    if p.speed.is_none() && p.ok {
        if let Some(old) = &s.probe {
            let at = if old.speed_at > 0 { old.speed_at } else { old.at };
            if old.speed.is_some() && p.at.saturating_sub(at) < 24 * 3600 {
                p.speed = old.speed;
                p.speed_at = at;
            }
        }
    }
    s.probe = Some(p);
}

pub(crate) fn is_udp_proto(s: &Server) -> bool {
    matches!(s.proto, Proto::Hysteria2 | Proto::Tuic | Proto::Wireguard | Proto::Awg)
        || s.proxy.get("network").and_then(|v| v.as_str()).is_some_and(|n| n == "quic" || n == "kcp")
}

/// Splits a batch into (worth testing, port closed). UDP-based protocols cannot be judged
/// by a TCP connect and pass. If (almost) nothing answers the network itself is suspect:
/// then nobody is dropped and the lab decides.
async fn tcp_prefilter(batch: Vec<Server>) -> (Vec<Server>, Vec<Server>) {
    let sem = Arc::new(tokio::sync::Semaphore::new(200));
    let mut js = tokio::task::JoinSet::new();
    let total = batch.len();
    for (i, s) in batch.iter().enumerate() {
        if is_udp_proto(s) {
            continue;
        }
        let (host, port, sem) = (s.host.clone(), s.port, sem.clone());
        js.spawn(async move {
            let _p = sem.acquire_owned().await;
            let ok = matches!(tokio::time::timeout(Duration::from_millis(3500), tokio::net::TcpStream::connect((host.as_str(), port))).await, Ok(Ok(_)));
            (i, ok)
        });
    }
    let mut closed: HashSet<usize> = HashSet::new();
    let mut tested = 0usize;
    while let Some(r) = js.join_next().await {
        if let Ok((i, ok)) = r {
            tested += 1;
            if !ok {
                closed.insert(i);
            }
        }
    }
    if tested >= 8 && closed.len() * 100 >= tested * 98 {
        return (batch, Vec::new());
    }
    let _ = total;
    let mut keep = Vec::new();
    let mut dead = Vec::new();
    for (i, s) in batch.into_iter().enumerate() {
        if closed.contains(&i) { dead.push(s) } else { keep.push(s) }
    }
    (keep, dead)
}

/// Tests `list` in batches. Calls `on_batch` with each finished batch (for incremental saving).
pub async fn check(env: &Env, list: Vec<Server>, o: &Opts, net: &mut NetInfo, mut on_batch: impl FnMut(&[Server])) -> Vec<Server> {
    {
        let mut pg = env.progress.lock().unwrap();
        pg.total += list.len();
    }
    let mut done: Vec<Server> = Vec::new();
    let mut good_total = 0usize;
    // WARP variants share one device key: they must be tested one at a time.
    let (warp, list): (Vec<Server>, Vec<Server>) = list.into_iter().partition(|s| s.origin == Origin::Warp);
    if !warp.is_empty() && !env.cancelled() {
        let w = check_sequential(env, warp, o, net, 2).await;
        good_total += w.iter().filter(|s| s.good()).count();
        on_batch(&w);
        done.extend(w);
    }
    let mut queue: std::collections::VecDeque<Server> = list.into_iter().collect();
    while !queue.is_empty() {
        if env.cancelled() {
            break;
        }
        let n = o.batch.min(queue.len());
        let mut batch: Vec<Server> = queue.drain(..n).collect();
        if o.prefilter && batch.len() >= 8 {
            env.stage("Быстрый отсев по TCP");
            let (keep, dead) = tcp_prefilter(batch).await;
            if !dead.is_empty() {
                let mut pg = env.progress.lock().unwrap();
                pg.done += dead.len();
                drop(pg);
                let mut fin = Vec::new();
                for mut s in dead {
                    finalize(&mut s, Probe { at: util::now(), error: Some("порт закрыт (TCP)".into()), ..Default::default() }, None, net, None);
                    fin.push(s);
                }
                on_batch(&fin);
                done.extend(fin);
            }
            batch = keep;
            if batch.is_empty() {
                continue;
            }
        }
        env.stage("Проверка серверов");
        // start lab, dropping proxies mihomo refuses to parse
        let mut lab = None;
        for _ in 0..6 {
            let refs: Vec<&Server> = batch.iter().collect();
            match start_lab(env, &refs).await {
                Ok(l) => {
                    lab = Some(l);
                    break;
                }
                Err(e) => {
                    if let Some(i) = bad_proxy_index(&e).filter(|i| *i < batch.len()) {
                        let mut bad = batch.remove(i);
                        finalize(&mut bad, Probe { at: util::now(), error: Some("некорректная конфигурация".into()), ..Default::default() }, None, net, None);
                        done.push(bad);
                        continue;
                    }
                    env.progress.lock().unwrap().error = Some(e);
                    break;
                }
            }
        }
        let Some(mut lab) = lab else {
            // could not start: mark nothing, stop scanning (likely environment problem)
            break;
        };
        if net.direct_ip.is_none() || util::now().saturating_sub(net.at) > 600 {
            *net = netinfo(&lab.direct, env.geo.as_deref()).await;
        }
        let mut alive = lab.proc.api.group_delay("ALL", mihomo::TEST_URL, o.delay_timeout_ms).await;
        // Suspiciously few answers: the test URL may be blocked or the machine overloaded.
        // Second chance through another URL and a longer timeout before anyone is blamed.
        let mut env_down = false;
        if batch.len() >= 32 && alive.len() * 100 < batch.len() * 3 {
            env.stage("Повторная проверка");
            let again = lab.proc.api.group_delay("ALL", mihomo::ALT_TEST_URL, o.delay_timeout_ms * 2).await;
            for (k, v) in again {
                alive.entry(k).or_insert(v);
            }
            if alive.len() * 100 < batch.len() {
                *net = netinfo(&lab.direct, env.geo.as_deref()).await;
                env_down = net.direct_ip.is_none();
            }
        }
        let sem = Arc::new(tokio::sync::Semaphore::new(o.parallel.max(1)));
        let mut js = tokio::task::JoinSet::new();
        let mut results: Vec<Option<(Probe, Option<probe::Trace>)>> = vec![None; batch.len()];
        for (i, s) in batch.iter().enumerate() {
            if !alive.contains_key(&s.id) {
                results[i] = Some((Probe { at: util::now(), error: Some("не отвечает".into()), ..Default::default() }, None));
                continue;
            }
            let l = &lab.nodes[i];
            let nc = probe::NodeCheck { port: l.port, user: l.user.clone(), pass: l.pass.clone(), udp: o.udp, services: o.services };
            let sem = sem.clone();
            js.spawn(async move {
                let _permit = sem.acquire_owned().await;
                (i, probe::check_node(&nc).await)
            });
        }
        {
            let mut pg = env.progress.lock().unwrap();
            pg.done += batch.len() - alive.len().min(batch.len());
        }
        while let Some(r) = js.join_next().await {
            if env.cancelled() {
                js.abort_all();
                break;
            }
            if let Ok((i, res)) = r {
                results[i] = Some(res);
                env.progress.lock().unwrap().done += 1;
            }
        }
        lab.proc.stop().await;
        let mut finished = Vec::new();
        if env_down {
            // no internet from the lab itself: results say nothing about the servers
            env.progress.lock().unwrap().error = Some("нет доступа в интернет — проверка прервана, серверы не наказаны".into());
        }
        for (mut s, r) in batch.into_iter().zip(results) {
            let Some((p, t)) = r else { continue };
            finalize_with(&mut s, p, t, net, env.geo.as_deref(), !env_down);
            if s.good() && in_countries(&s, &o.want_cc) {
                good_total += 1;
            }
            finished.push(s);
        }
        {
            let mut pg = env.progress.lock().unwrap();
            pg.good += finished.iter().filter(|s| s.good()).count();
        }
        on_batch(&finished);
        done.extend(finished);
        if env_down || (o.target_good > 0 && good_total >= o.target_good) {
            break;
        }
    }
    if o.speed_top > 0 && !env.cancelled() {
        speed_stage(env, &mut done, o.speed_top).await;
    }
    done
}

/// Tests servers one by one (shared credentials, e.g. WARP); stops after `want` good ones.
pub async fn check_sequential(env: &Env, list: Vec<Server>, o: &Opts, net: &mut NetInfo, want: usize) -> Vec<Server> {
    env.stage("Проверка WARP");
    let refs: Vec<&Server> = list.iter().collect();
    let mut lab = match start_lab(env, &refs).await {
        Ok(l) => l,
        Err(e) => {
            env.progress.lock().unwrap().error = Some(e);
            return Vec::new();
        }
    };
    if net.direct_ip.is_none() || util::now().saturating_sub(net.at) > 600 {
        *net = netinfo(&lab.direct, env.geo.as_deref()).await;
    }
    let mut out = Vec::new();
    let mut good = 0;
    for (i, mut s) in list.clone().into_iter().enumerate() {
        if env.cancelled() || good >= want {
            break;
        }
        let alive = lab.proc.api.proxy_delay(&s.id, mihomo::TEST_URL, o.delay_timeout_ms).await;
        let (p, t) = if alive.is_some() {
            let l = &lab.nodes[i];
            let nc = probe::NodeCheck { port: l.port, user: l.user.clone(), pass: l.pass.clone(), udp: o.udp, services: o.services };
            probe::check_node(&nc).await
        } else {
            (Probe { at: util::now(), error: Some("не отвечает".into()), ..Default::default() }, None)
        };
        finalize(&mut s, p, t, net, env.geo.as_deref());
        if s.good() {
            good += 1;
        }
        env.progress.lock().unwrap().done += 1;
        out.push(s);
    }
    lab.proc.stop().await;
    env.progress.lock().unwrap().good += good;
    out
}

/// Measures download speed of the best few servers, one at a time (capped downloads).
/// Returns how many were measured.
pub async fn speed_stage(env: &Env, done: &mut [Server], top: usize) -> usize {
    let mut idx: Vec<usize> = (0..done.len()).filter(|i| done[*i].good()).collect();
    idx.sort_by_key(|i| score(&done[*i]));
    idx.truncate(top);
    if idx.is_empty() {
        return 0;
    }
    env.stage("Замер скорости");
    {
        let mut pg = env.progress.lock().unwrap();
        pg.total += idx.len();
    }
    let refs: Vec<&Server> = idx.iter().map(|i| &done[*i]).collect();
    let mut lab = match start_lab(env, &refs).await {
        Ok(l) => l,
        Err(e) => {
            env.progress.lock().unwrap().error = Some(e);
            return 0;
        }
    };
    let mut speeds = Vec::new();
    for l in &lab.nodes {
        if env.cancelled() {
            break;
        }
        let sp = match probe::client(Some((l.port, &l.user, &l.pass)), Duration::from_secs(20)) {
            Ok(c) => probe::speed(&c, probe::SPEED_BYTES, Duration::from_secs(5)).await,
            Err(_) => None,
        };
        speeds.push(sp);
        env.progress.lock().unwrap().done += 1;
    }
    lab.proc.stop().await;
    let now = util::now();
    let mut n = 0;
    for (k, sp) in speeds.into_iter().enumerate() {
        if let (Some(sp), Some(p)) = (sp, done[idx[k]].probe.as_mut()) {
            p.speed = Some(sp);
            p.speed_at = now;
            n += 1;
        }
    }
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srv(host: &str, origin: Origin, ok: Option<(u32, &str)>) -> Server {
        let p: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(&format!(r#"{{"type":"trojan","server":"{host}","port":443,"password":"x"}}"#)).unwrap();
        let mut s = Server::new(host, p, origin, "t").unwrap();
        if let Some((lat, cc)) = ok {
            s.probe = Some(Probe { at: 1, ok: lat > 0, latency: Some(lat), exit_cc: Some(cc.into()), services: 7, udp: Some(true), ..Default::default() });
        }
        s
    }

    #[test]
    fn pool_order() {
        let fast = srv("fast", Origin::Free, Some((50, "NL")));
        let slow = srv("slow", Origin::Free, Some((400, "DE")));
        let mut fav = srv("fav", Origin::Free, Some((300, "FI")));
        fav.fav = true;
        let mine_ok = srv("mine-ok", Origin::Mine, Some((600, "US")));
        let mine_dead = srv("mine-dead", Origin::Mine, Some((0, "US")));
        let mine_new = srv("mine-new", Origin::Mine, None);
        let dead_free = srv("dead-free", Origin::Free, Some((0, "NL")));
        let all = vec![slow.clone(), dead_free.clone(), mine_dead.clone(), fast.clone(), mine_new.clone(), fav.clone(), mine_ok.clone()];
        let none = HashSet::new();
        let ids = |v: Vec<Server>| v.into_iter().map(|s| s.host).collect::<Vec<_>>();
        let p = pool(&all, &PoolOpts { size: 8, countries: &none, warp: true, selected: None });
        assert_eq!(ids(p), ["fav", "mine-ok", "fast", "slow", "mine-new", "mine-dead"]);
        // countries: only NL servers (and the manual choice); own dead/untested ones are not used
        let nl: HashSet<String> = ["NL".to_string()].into();
        let p = pool(&all, &PoolOpts { size: 8, countries: &nl, warp: true, selected: Some(&slow.id) });
        assert_eq!(ids(p), ["fast", "slow"]);
        // a country without working servers is ignored
        let jp: HashSet<String> = ["JP".to_string()].into();
        assert!(!countries_usable(&all, &jp));
        let p = pool(&all, &PoolOpts { size: 1, countries: &jp, warp: true, selected: None });
        assert_eq!(ids(p), ["fav", "mine-ok", "fast", "mine-new", "mine-dead"]);
    }

    #[test]
    fn relay_selection() {
        let mut dead = srv("9.9.9.9", Origin::Free, Some((0, "NL")));
        dead.probe.as_mut().unwrap().error = Some("порт закрыт (TCP)".into());
        let mut weird = srv("8.8.8.8", Origin::Free, Some((0, "NL")));
        weird.probe.as_mut().unwrap().error = Some("подмена содержимого".into());
        let mut tried = dead.clone();
        tried.host = "7.7.7.7".into();
        tried.id = "tried".into();
        tried.relay_at = 1000;
        let good_a = srv("1.1.1.1", Origin::Free, Some((50, "DE")));
        let good_b = srv("1.1.1.1", Origin::Free, Some((60, "DE")));
        let all = vec![dead.clone(), weird, tried, good_a.clone(), good_b];
        let c = relay_candidates(&all, 1100, 10, 600);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].host, "9.9.9.9");
        // the "tried" one comes back after the pause
        assert_eq!(relay_candidates(&all, 1700, 10, 600).len(), 2);
        // hops: good servers, one per host
        let none = HashSet::new();
        let h = relay_hops(&all, 3, &none);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].host, "1.1.1.1");
        // relay servers rank below the same server reached directly
        let mut r = good_a.clone();
        let direct = score(&r);
        r.relay = Some("x".into());
        assert!(score(&r) > direct);
        assert_eq!(r.mihomo_proxy()["dialer-proxy"], "hop:x");
        // a relay server ranks below even a slow direct one
        let mut slow = srv("5.5.5.5", Origin::Free, Some((4000, "DE")));
        slow.probe.as_mut().unwrap().services = 0;
        assert!(score(&r) > score(&slow));
        // avoid: keys already open elsewhere are not taken
        let avoid: HashSet<String> = [good_a.id.clone()].into_iter().collect();
        assert!(relay_hops(&all, 3, &avoid).is_empty());
        // the user's own WireGuard beats everything while it works; free WireGuard is never a hop
        let mut wg = srv("wg.example", Origin::Mine, Some((300, "NL")));
        wg.proto = Proto::Wireguard;
        let mut freewg = srv("freewg", Origin::Free, Some((10, "NL")));
        freewg.proto = Proto::Wireguard;
        let mut all2 = all.clone();
        all2.push(freewg);
        assert_eq!(relay_hops(&all2, 3, &none)[0].host, "1.1.1.1");
        all2.push(wg.clone());
        let h = relay_hops(&all2, 3, &none);
        assert_eq!(h.len(), 1);
        assert_eq!(h[0].host, "wg.example");
        let avoid: HashSet<String> = [wg.id.clone()].into_iter().collect();
        assert_eq!(relay_hops(&all2, 3, &avoid)[0].host, "1.1.1.1");
    }

    #[test]
    fn plan_prefers() {
        let a = srv("1.1.1.1", Origin::Free, None);
        let b = srv("2.2.2.2", Origin::Free, None);
        let c = srv("3.3.3.3", Origin::Free, None);
        let src = SourceDef { id: "t".into(), name: "t".into(), tier: 1, cap: 100, urls: vec![], enabled: true };
        let p = plan(&[a, b, c], &[src], &HashMap::new(), 10, 100, &|s: &Server| s.host == "3.3.3.3");
        assert_eq!(p[0].host, "3.3.3.3");
        assert_eq!(p.len(), 3);
    }

    #[test]
    fn wg_background_recheck_is_daily() {
        let p: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{"type":"wireguard","server":"wg","port":51820,"private-key":"a","public-key":"b"}"#).unwrap();
        let mut s = Server::new("wg", p, Origin::Free, "t").unwrap();
        let now = 2_000_000;
        assert!(bg_recheck(&s, now)); // never tested: the first check is fine
        s.probe = Some(Probe { at: now - 3600, ok: true, ..Default::default() });
        assert!(!bg_recheck(&s, now)); // an hour ago: the background leaves it alone
        s.probe = Some(Probe { at: now - 25 * 3600, ok: true, ..Default::default() });
        assert!(bg_recheck(&s, now)); // a day ago: one refresh is allowed
        let t = srv("plain", Origin::Free, Some((10, "US")));
        assert!(bg_recheck(&t, now)); // other protocols re-test freely
    }

    #[test]
    fn cooldown_grows_and_caps() {
        let mut s = srv("a", Origin::Free, None);
        assert_eq!(cooldown(&s), 0);
        s.fails = 1;
        assert_eq!(cooldown(&s), 0);
        s.fails = 2;
        assert_eq!(cooldown(&s), 20 * 60);
        s.fails = 3;
        assert_eq!(cooldown(&s), 40 * 60);
        s.fails = 100;
        assert_eq!(cooldown(&s), 6 * 3600);
        s.oks = 1;
        assert_eq!(cooldown(&s), 3 * 3600);
    }

    #[test]
    fn fresh_first_in_plan() {
        let mut old = srv("1.1.1.1", Origin::Free, None);
        let mut new = srv("2.2.2.2", Origin::Free, None);
        old.added = 1_000;
        new.added = 1_000_000;
        let src = SourceDef { id: "t".into(), name: "t".into(), tier: 1, cap: 100, urls: vec![], enabled: true };
        let p = plan(&[old, new], &[src], &HashMap::new(), 10, 1_000_100, &|_| false);
        assert_eq!(p[0].host, "2.2.2.2");
    }

    #[test]
    fn reasons_summary() {
        let mut a = srv("a", Origin::Free, Some((50, "NL")));
        let mut b = srv("b", Origin::Free, None);
        let mut c = srv("c", Origin::Free, None);
        b.probe = Some(Probe { at: 1, ok: false, error: Some("таймаут".into()), ..Default::default() });
        c.probe = Some(Probe { at: 1, ok: false, error: Some("таймаут".into()), ..Default::default() });
        a.probe.as_mut().unwrap().ok = true;
        assert_eq!(reasons(&[a, b, c]), "рабочих 1; отказы: таймаут ×2");
    }

    #[test]
    fn bad_index() {
        assert_eq!(bad_proxy_index("Parse config error: proxy 12: missing uuid"), Some(12));
        assert_eq!(bad_proxy_index("proxy group 1: x"), None);
    }
}
