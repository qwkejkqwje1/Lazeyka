//! Engine: owns the state, the main mihomo instance (TUN), the scanner and background
//! maintenance. Runs inside the Windows service (or a console process for development)
//! and is driven by JSON requests from the UI over IPC.

use crate::geo::Geo;
use crate::mihomo::{RoutePlan, Via};
use crate::model::*;
use crate::routes::{Routes, Target};
use crate::scan::{self, NetInfo, Progress};
use crate::store::{self, Paths, Settings, Subscription};
use crate::{import, mihomo, netif, sources, util, warp};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

mod route_ops;

pub const TUN: &str = "Lazeyka";

const NO_SERVERS: &str = "Серверы не отвечают — ищем новые…";
const NOT_RESPONDING: &str = "Сервер не отвечает…";

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum ConnState {
    #[default]
    Off,
    Connecting,
    On,
    Error,
}

#[derive(Default)]
struct Conn {
    state: ConnState,
    since: u64,
    error: Option<String>,
    message: Option<String>,
    current: Option<String>,
}

#[derive(Default)]
struct Traffic {
    last: Option<(Instant, u64, u64)>,
    up: u64,
    down: u64,
    up_total: u64,
    down_total: u64,
}

struct State {
    settings: Settings,
    servers: Vec<Server>,
    stats: store::Stats,
    warp: Option<warp::Account>,
    net: NetInfo,
    conn: Conn,
    traffic: Traffic,
    last_full: u64,
    last_pool_check: u64,
    last_subs: u64,
    log: VecDeque<String>,
    /// Last event worth showing to the user (id grows with every notice).
    notice: (u64, String),
    /// Routes whose own servers do not answer: their traffic uses the VPN for now.
    route_spare: HashSet<String>,
    last_route_check: u64,
}

/// What the running mihomo was given (to rebuild the configuration in place).
#[derive(Default)]
struct Applied {
    opts: Option<mihomo::MainOpts>,
    pool: Vec<String>,
    extra: Vec<String>,
}

/// Connection watchdog state (maintenance loop).
#[derive(Default)]
struct Health {
    /// Confirmed failures of a manually chosen server in a row.
    manual_fails: u32,
}

pub struct Engine {
    pub paths: Paths,
    pub version: String,
    st: Mutex<State>,
    op: tokio::sync::Mutex<()>,
    main: tokio::sync::Mutex<Option<mihomo::Process>>,
    api: Mutex<Option<mihomo::Api>>,
    scanning: AtomicBool,
    cancel: Arc<AtomicBool>,
    progress: Arc<Mutex<Progress>>,
    core_version: Mutex<String>,
    /// Bumped by every connect/disconnect request; a connect attempt aborts when it changes.
    generation: AtomicU64,
    last_scan_try: AtomicU64,
    measuring: tokio::sync::Mutex<()>,
    applied: Mutex<Applied>,
}

#[derive(Deserialize, Debug, Clone, Copy, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Site,
    App,
}

#[derive(Deserialize, Debug)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum Req {
    Ping,
    Status,
    Connect {
        #[serde(default)]
        server: Option<String>,
    },
    Disconnect,
    Scan {
        #[serde(default)]
        full: bool,
    },
    CancelScan,
    Servers,
    Select {
        #[serde(default)]
        server: Option<String>,
    },
    Import {
        text: String,
        /// Name for a single unnamed config (e.g. the file name of a .conf).
        #[serde(default)]
        name: String,
    },
    RemoveServer {
        id: String,
    },
    RenameServer {
        id: String,
        name: String,
    },
    SetFavorite {
        id: String,
        fav: bool,
    },
    /// Full check + speed test of one server (manual "Замерить").
    Measure {
        id: String,
    },
    SetCountries {
        countries: Vec<String>,
    },
    AddSubscription {
        url: String,
        #[serde(default)]
        name: String,
    },
    RemoveSubscription {
        id: String,
    },
    RefreshSubscriptions,
    Settings,
    SetSettings {
        patch: Value,
    },
    /// Routes with their state; also the countries and servers a route can use.
    Routes,
    /// Where traffic without a route goes: "vpn" or "direct".
    RouteDefault {
        target: String,
    },
    RouteAdd {
        #[serde(default)]
        name: String,
        target: String,
        #[serde(default)]
        sites: Vec<String>,
        #[serde(default)]
        apps: Vec<String>,
    },
    RouteUpdate {
        id: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        enabled: Option<bool>,
        #[serde(default)]
        target: Option<String>,
        /// Full set of attached entry-list ids, when given.
        #[serde(default)]
        lists: Option<Vec<String>>,
    },
    RouteRemove {
        id: String,
    },
    /// Moves a route up (-1) or down (+1): the first matching route wins.
    RouteMove {
        id: String,
        delta: i32,
    },
    RouteEntryAdd {
        id: String,
        kind: Kind,
        value: String,
    },
    RouteEntryRemove {
        id: String,
        kind: Kind,
        value: String,
    },
    RouteImport {
        id: String,
        kind: Kind,
        text: String,
    },
    RouteExport {
        id: String,
        kind: Kind,
    },
    /// Creates a named chain of 1–3 hops ("vpn", "country:XX", "server:<id>").
    ChainAdd {
        #[serde(default)]
        name: String,
        #[serde(default)]
        hops: Vec<String>,
    },
    ChainUpdate {
        id: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        hops: Option<Vec<String>>,
    },
    ChainRemove {
        id: String,
    },
    /// Creates a named entry list (a "folder" of sites and apps for routes).
    ListAdd {
        #[serde(default)]
        name: String,
    },
    ListUpdate {
        id: String,
        #[serde(default)]
        name: Option<String>,
        /// The list's own direction: absent = unchanged, "" = clear, code = set.
        #[serde(default)]
        target: Option<String>,
    },
    ListRemove {
        id: String,
    },
    ListEntryAdd {
        id: String,
        kind: Kind,
        value: String,
    },
    ListEntryRemove {
        id: String,
        kind: Kind,
        value: String,
    },
    ListImport {
        id: String,
        kind: Kind,
        text: String,
    },
    ListExport {
        id: String,
        kind: Kind,
    },
    Sources,
    SetSource {
        id: String,
        enabled: bool,
    },
    AddSource {
        url: String,
        #[serde(default)]
        name: String,
    },
    RemoveSource {
        id: String,
    },
    Warp {
        enable: bool,
    },
    Logs,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
#[serde(default)]
pub struct ServerView {
    pub id: String,
    pub name: String,
    pub proto: String,
    pub transport: String,
    pub host: String,
    pub port: u16,
    pub origin: Origin,
    pub source: String,
    pub cc: String,
    pub ok: bool,
    pub tested: bool,
    pub latency: u32,
    pub speed: u32,
    pub udp: bool,
    pub services: u8,
    pub error: String,
    pub at: u64,
    pub in_pool: bool,
    pub fav: bool,
    /// Share of successful checks, percent; -1 = not enough checks yet.
    pub stab: i32,
    /// Number of checks behind `stab`.
    pub checks: u32,
    pub speed_at: u64,
}

pub fn view(s: &Server, in_pool: bool) -> ServerView {
    let p = s.probe.clone().unwrap_or_default();
    ServerView {
        id: s.id.clone(),
        name: {
            let n = util::display_name(&s.name);
            if n.is_empty() { format!("{} {}", s.proto.label(), s.host) } else { n }
        },
        proto: s.proto.label().to_string(),
        transport: s.transport.clone(),
        host: s.host.clone(),
        port: s.port,
        origin: s.origin,
        source: s.source.clone(),
        cc: p.exit_cc.clone().unwrap_or_default(),
        ok: p.ok,
        tested: s.probe.is_some(),
        latency: p.latency.unwrap_or(0),
        speed: p.speed.unwrap_or(0),
        udp: p.udp.unwrap_or(false),
        services: p.services,
        error: p.error.unwrap_or_default(),
        at: p.at,
        in_pool,
        fav: s.fav,
        stab: s.stability().map(|v| v as i32).unwrap_or(-1),
        checks: s.hist_n as u32,
        speed_at: p.speed_at,
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(default)]
pub struct StatusView {
    pub state: ConnState,
    pub since: u64,
    pub error: Option<String>,
    pub message: Option<String>,
    pub server: Option<ServerView>,
    pub auto: bool,
    pub scan: Progress,
    pub pool: usize,
    pub good: usize,
    pub mine: usize,
    pub up: u64,
    pub down: u64,
    pub up_total: u64,
    pub down_total: u64,
    pub user_cc: Option<String>,
    /// "vpn" or "direct": where traffic without a route goes.
    pub routes_default: String,
    /// Routes that take part in routing (enabled, not empty).
    pub routes_on: usize,
    /// Active routes that go through the VPN for now (their servers do not answer).
    pub routes_spare: usize,
    pub version: String,
    pub core: String,
    pub warp: bool,
    /// Chosen exit countries (empty = any).
    pub countries: Vec<String>,
    /// False when none of the chosen countries has a working server (AUTO uses all).
    pub countries_ok: bool,
    pub notice_id: u64,
    pub notice: String,
}

fn is_wg(s: &Server) -> bool {
    matches!(s.proto, Proto::Wireguard | Proto::Awg)
}

impl Engine {
    pub fn new(paths: Paths, version: &str) -> Arc<Engine> {
        let _ = std::fs::create_dir_all(&paths.data);
        let mut settings: Settings = store::load(&paths.settings());
        if settings.migrate() {
            let _ = store::save(&paths.settings(), &settings);
        }
        let servers: Vec<Server> = store::load(&paths.servers());
        let stats: store::Stats = store::load(&paths.stats());
        let warp: Option<warp::Account> = store::load(&paths.warp());
        let e = Arc::new(Engine {
            paths,
            version: version.to_string(),
            st: Mutex::new(State {
                settings,
                servers,
                stats,
                warp,
                net: NetInfo::default(),
                conn: Conn::default(),
                traffic: Traffic::default(),
                last_full: 0,
                last_pool_check: 0,
                last_subs: util::now(),
                log: VecDeque::new(),
                notice: (0, String::new()),
                route_spare: HashSet::new(),
                last_route_check: 0,
            }),
            op: tokio::sync::Mutex::new(()),
            main: tokio::sync::Mutex::new(None),
            api: Mutex::new(None),
            scanning: AtomicBool::new(false),
            cancel: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(Mutex::new(Progress::default())),
            core_version: Mutex::new(String::new()),
            generation: AtomicU64::new(0),
            last_scan_try: AtomicU64::new(0),
            measuring: tokio::sync::Mutex::new(()),
            applied: Mutex::new(Applied::default()),
        });
        e.log(&format!("Лазейка {version} запущена"));
        e
    }

    /// Starts background maintenance; restores the connection if configured.
    pub fn start(self: &Arc<Self>) {
        let me = self.clone();
        tokio::spawn(async move { me.maintenance().await });
        let restore = {
            let st = self.st.lock().unwrap();
            st.settings.connect_on_start || st.settings.was_connected
        };
        if restore {
            let me = self.clone();
            tokio::spawn(async move { me.connect_task(None).await });
        }
    }

    pub fn log(&self, msg: &str) {
        let line = format!("{} {msg}", util::now());
        {
            let mut st = self.st.lock().unwrap();
            if st.log.len() >= 300 {
                st.log.pop_front();
            }
            st.log.push_back(line.clone());
        }
        let p = self.paths.log();
        if std::fs::metadata(&p).map(|m| m.len() > 1_000_000).unwrap_or(false) {
            let _ = std::fs::rename(&p, p.with_extension("old.log"));
        }
        use std::io::Write;
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&p) {
            let _ = writeln!(f, "{line}");
        }
    }

    /// Logs an event and shows it to the user (the UI displays new notices once).
    fn notice(&self, msg: &str) {
        self.log(msg);
        let mut st = self.st.lock().unwrap();
        st.notice.0 += 1;
        st.notice.1 = msg.to_string();
    }

    fn save_servers(&self) {
        let (servers, stats) = {
            let mut st = self.st.lock().unwrap();
            store::prune(&mut st.servers, util::now());
            (st.servers.clone(), st.stats.clone())
        };
        let _ = store::save(&self.paths.servers(), &servers);
        let _ = store::save(&self.paths.stats(), &stats);
    }

    fn save_settings(&self) {
        let s = self.st.lock().unwrap().settings.clone();
        let _ = store::save(&self.paths.settings(), &s);
    }

    fn set_conn(&self, state: ConnState, message: Option<&str>, error: Option<String>) {
        let mut st = self.st.lock().unwrap();
        if state == ConnState::On && st.conn.state != ConnState::On {
            st.conn.since = util::now();
        }
        st.conn.state = state;
        st.conn.message = message.map(|s| s.to_string());
        st.conn.error = error;
    }

    fn connected(&self) -> bool {
        matches!(self.st.lock().unwrap().conn.state, ConnState::On | ConnState::Connecting)
    }

    /// Merges checked servers into the state (keeps user names/origins of existing entries).
    fn merge(&self, list: &[Server]) {
        self.merge_with(list, true)
    }

    fn merge_with(&self, list: &[Server], count: bool) {
        let mut st = self.st.lock().unwrap();
        let idx: HashMap<String, usize> = st.servers.iter().enumerate().map(|(i, s)| (s.id.clone(), i)).collect();
        for s in list {
            match idx.get(&s.id) {
                Some(&i) => {
                    let e = &mut st.servers[i];
                    e.probe = s.probe.clone();
                    e.oks = s.oks;
                    e.fails = s.fails;
                    e.last_ok = s.last_ok;
                    e.hist = s.hist;
                    e.hist_n = s.hist_n;
                }
                None => st.servers.push(s.clone()),
            }
            if count && s.origin == Origin::Free {
                let stt = st.stats.entry(s.source.clone()).or_default();
                stt.tested += 1;
                if s.good() {
                    stt.good += 1;
                }
            }
        }
    }

    /// Adds newly parsed servers that are not known yet.
    fn add_new(&self, list: Vec<Server>) -> usize {
        let mut st = self.st.lock().unwrap();
        let known: HashSet<String> = st.servers.iter().map(|s| s.id.clone()).collect();
        let mut n = 0;
        for s in list {
            if !known.contains(&s.id) {
                st.servers.push(s);
                n += 1;
            }
        }
        n
    }

    fn countries(st: &State) -> HashSet<String> {
        st.settings.countries.iter().cloned().collect()
    }

    /// The AUTO pool in fallback order. The server AUTO uses now stays first while it works
    /// and nothing of a higher class (favourite, own server) is available: a better search
    /// result must not move a working connection to another exit.
    fn pool(&self) -> Vec<Server> {
        let st = self.st.lock().unwrap();
        let cc = Self::countries(&st);
        let mut p = scan::pool(
            &st.servers,
            &scan::PoolOpts { size: st.settings.pool_size, countries: &cc, warp: st.settings.warp, selected: st.settings.selected.as_deref() },
        );
        let class = |s: &Server| if s.fav { 0 } else if s.origin == Origin::Mine { 1 } else { 2 };
        let auto_on = st.settings.selected.is_none() && st.conn.state == ConnState::On;
        if let (true, Some(cur)) = (auto_on, st.conn.current.as_deref()) {
            if let Some(i) = p.iter().position(|s| s.id == cur && s.good()) {
                if i > 0 && class(&p[i]) <= class(&p[0]) {
                    let s = p.remove(i);
                    p.insert(0, s);
                }
            }
        }
        p
    }

    fn usable_count(&self) -> usize {
        self.pool().iter().filter(|s| s.good() || (s.origin == Origin::Mine && s.probe.is_none())).count()
    }

    // ---------------- requests ----------------

    pub async fn handle(self: &Arc<Self>, req: Req) -> Result<Value, String> {
        match req {
            Req::Ping => Ok(json!({ "version": self.version })),
            Req::Status => Ok(serde_json::to_value(self.status().await).unwrap_or(Value::Null)),
            Req::Connect { server } => {
                let me = self.clone();
                tokio::spawn(async move { me.connect_task(server).await });
                Ok(Value::Null)
            }
            Req::Disconnect => {
                self.disconnect().await;
                Ok(Value::Null)
            }
            Req::Scan { full } => {
                if self.scanning.load(Ordering::Relaxed) {
                    return Err("поиск уже идёт".into());
                }
                let me = self.clone();
                tokio::spawn(async move { me.scan_task(full, true).await });
                Ok(Value::Null)
            }
            Req::CancelScan => {
                self.cancel.store(true, Ordering::Relaxed);
                Ok(Value::Null)
            }
            Req::Servers => {
                let pool: HashSet<String> = self.pool().into_iter().map(|s| s.id).collect();
                let st = self.st.lock().unwrap();
                // own, WARP and starred servers always; public ones only while they work
                let mut v: Vec<&Server> = st.servers.iter().filter(|s| s.origin != Origin::Free || s.good() || s.fav).collect();
                v.sort_by_key(|s| scan::score(s));
                let list: Vec<ServerView> = v.iter().take(400).map(|s| view(s, pool.contains(&s.id))).collect();
                Ok(json!({ "servers": list, "selected": st.settings.selected }))
            }
            Req::Select { server } => {
                {
                    let mut st = self.st.lock().unwrap();
                    st.settings.selected = server.clone();
                }
                self.save_settings();
                if self.connected() {
                    self.apply_pool().await;
                    let api = self.api.lock().unwrap().clone();
                    if let Some(api) = api {
                        let target = server.clone().unwrap_or_else(|| "AUTO".into());
                        api.select("VPN", &target).await?;
                        api.close_connections().await;
                    }
                    self.st.lock().unwrap().conn.current = server;
                    Ok(Value::Null)
                } else {
                    let me = self.clone();
                    tokio::spawn(async move { me.connect_task(None).await });
                    Ok(Value::Null)
                }
            }
            Req::Import { text, name } => self.import(&text, "manual", &name).await,
            Req::RemoveServer { id } => {
                {
                    let mut st = self.st.lock().unwrap();
                    st.servers.retain(|s| !(s.id == id && s.origin == Origin::Mine));
                    if st.settings.selected.as_deref() == Some(id.as_str()) {
                        st.settings.selected = None;
                    }
                }
                self.save_servers();
                self.save_settings();
                if self.connected() {
                    self.apply_pool().await;
                }
                Ok(Value::Null)
            }
            Req::RenameServer { id, name } => {
                {
                    let mut st = self.st.lock().unwrap();
                    if let Some(s) = st.servers.iter_mut().find(|s| s.id == id) {
                        s.name = util::clip(&name, 60);
                    }
                }
                self.save_servers();
                Ok(Value::Null)
            }
            Req::SetFavorite { id, fav } => {
                let found = {
                    let mut st = self.st.lock().unwrap();
                    st.servers.iter_mut().find(|s| s.id == id).map(|s| s.fav = fav).is_some()
                };
                if !found {
                    return Err("сервер не найден".into());
                }
                self.save_servers();
                if self.connected() {
                    self.apply_pool().await;
                }
                Ok(Value::Null)
            }
            Req::Measure { id } => self.measure(&id).await,
            Req::SetCountries { countries } => {
                let mut list: Vec<String> = Vec::new();
                for c in countries {
                    let c = c.trim().to_ascii_uppercase();
                    if c.len() == 2 && c.chars().all(|x| x.is_ascii_alphabetic()) && !list.contains(&c) {
                        list.push(c);
                    }
                }
                let usable = {
                    let mut st = self.st.lock().unwrap();
                    st.settings.countries = list.clone();
                    scan::countries_usable(&st.servers, &list.iter().cloned().collect())
                };
                self.save_settings();
                if self.connected() {
                    let before = self.st.lock().unwrap().conn.current.clone();
                    self.apply_pool().await;
                    let api = self.api.lock().unwrap().clone();
                    let auto = self.st.lock().unwrap().settings.selected.is_none();
                    if let (Some(api), true) = (api, auto) {
                        let now = api.now("AUTO").await;
                        if now.is_some() && now != before {
                            api.close_connections().await;
                            self.st.lock().unwrap().conn.current = now;
                        }
                    }
                }
                if !usable && !self.scanning.load(Ordering::Relaxed) {
                    let me = self.clone();
                    tokio::spawn(async move { me.scan_task(false, true).await });
                }
                Ok(json!({ "usable": usable }))
            }
            Req::AddSubscription { url, name } => self.add_subscription(&url, &name).await,
            Req::RemoveSubscription { id } => {
                {
                    let mut st = self.st.lock().unwrap();
                    st.settings.subscriptions.retain(|s| s.id != id);
                    let src = format!("sub:{id}");
                    st.servers.retain(|s| s.source != src);
                }
                self.save_settings();
                self.save_servers();
                Ok(Value::Null)
            }
            Req::RefreshSubscriptions => {
                let me = self.clone();
                tokio::spawn(async move { me.refresh_subscriptions().await });
                Ok(Value::Null)
            }
            Req::Settings => {
                let st = self.st.lock().unwrap();
                Ok(serde_json::to_value(&st.settings).unwrap_or(Value::Null))
            }
            Req::SetSettings { patch } => self.set_settings(patch).await,
            Req::Routes => Ok(self.routes_view()),
            Req::RouteDefault { target } => self.route_default(&target).await,
            Req::RouteAdd { name, target, sites, apps } => self.route_add(&name, &target, &sites, &apps).await,
            Req::RouteUpdate { id, name, enabled, target, lists } => self.route_update(&id, name, enabled, target, lists).await,
            Req::RouteRemove { id } => self.route_remove(&id).await,
            Req::RouteMove { id, delta } => self.route_move(&id, delta).await,
            Req::RouteEntryAdd { id, kind, value } => self.route_entry_add(&id, kind, &value).await,
            Req::RouteEntryRemove { id, kind, value } => self.route_entry_remove(&id, kind, &value).await,
            Req::RouteImport { id, kind, text } => self.route_import(&id, kind, &text).await,
            Req::RouteExport { id, kind } => self.route_export(&id, kind),
            Req::ListAdd { name } => self.list_add(&name).await,
            Req::ListUpdate { id, name, target } => self.list_update(&id, name, target).await,
            Req::ListRemove { id } => self.list_remove(&id).await,
            Req::ListEntryAdd { id, kind, value } => self.list_entry_add(&id, kind, &value).await,
            Req::ListEntryRemove { id, kind, value } => self.list_entry_remove(&id, kind, &value).await,
            Req::ListImport { id, kind, text } => self.list_import(&id, kind, &text).await,
            Req::ListExport { id, kind } => self.list_export(&id, kind),
            Req::ChainAdd { name, hops } => self.chain_add(&name, &hops).await,
            Req::ChainUpdate { id, name, hops } => self.chain_update(&id, name, hops).await,
            Req::ChainRemove { id } => self.chain_remove(&id).await,
            Req::Sources => {
                let st = self.st.lock().unwrap();
                let list: Vec<Value> = st
                    .settings
                    .sources()
                    .into_iter()
                    .map(|d| {
                        let s = st.stats.get(&d.id).cloned().unwrap_or_default();
                        json!({ "id": d.id, "name": d.name, "tier": d.tier, "enabled": d.enabled, "url": d.urls.first(), "custom": d.id.starts_with("user-"), "stat": s })
                    })
                    .collect();
                let subs = st.settings.subscriptions.clone();
                Ok(json!({ "sources": list, "subscriptions": subs }))
            }
            Req::SetSource { id, enabled } => {
                {
                    let mut st = self.st.lock().unwrap();
                    if let Some(c) = st.settings.custom_sources.iter_mut().find(|d| d.id == id) {
                        c.enabled = enabled;
                    } else {
                        st.settings.source_toggles.insert(id, enabled);
                    }
                }
                self.save_settings();
                Ok(Value::Null)
            }
            Req::AddSource { url, name } => {
                let url = url.trim().to_string();
                if !url.starts_with("https://") && !url.starts_with("http://") {
                    return Err("нужна ссылка http(s)://".into());
                }
                let id = format!("user-{}", &crate::model::proxy_id(&serde_json::Map::from_iter([("u".to_string(), Value::from(url.clone()))]))[1..9]);
                {
                    let mut st = self.st.lock().unwrap();
                    if !st.settings.custom_sources.iter().any(|d| d.urls.first() == Some(&url)) {
                        let name = if name.trim().is_empty() { url.clone() } else { name };
                        st.settings.custom_sources.push(sources::SourceDef { id, name, tier: 1, cap: 300, urls: vec![url], enabled: true });
                    }
                }
                self.save_settings();
                Ok(Value::Null)
            }
            Req::RemoveSource { id } => {
                {
                    let mut st = self.st.lock().unwrap();
                    st.settings.custom_sources.retain(|d| d.id != id);
                }
                self.save_settings();
                Ok(Value::Null)
            }
            Req::Warp { enable } => {
                {
                    let mut st = self.st.lock().unwrap();
                    st.settings.warp = enable;
                }
                self.save_settings();
                if enable {
                    let me = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = me.ensure_warp().await {
                            me.log(&e);
                        }
                    });
                } else if self.connected() {
                    self.apply_pool().await;
                }
                Ok(Value::Null)
            }
            Req::Logs => {
                let st = self.st.lock().unwrap();
                let mut lines: Vec<String> = st.log.iter().cloned().collect();
                drop(st);
                if let Ok(g) = self.main.try_lock() {
                    if let Some(p) = g.as_ref() {
                        lines.push("--- mihomo ---".into());
                        lines.extend(p.log.lock().unwrap().iter().cloned());
                    }
                }
                Ok(json!({ "lines": lines }))
            }
        }
    }

    pub async fn status(self: &Arc<Self>) -> StatusView {
        let api = self.api.lock().unwrap().clone();
        let connected = self.connected();
        if let (Some(api), true) = (api, connected) {
            if let Some((u, d, _)) = api.totals().await {
                let mut st = self.st.lock().unwrap();
                let now = Instant::now();
                if let Some((t, lu, ld)) = st.traffic.last {
                    let dt = now.duration_since(t).as_secs_f64().max(0.2);
                    st.traffic.up = ((u.saturating_sub(lu)) as f64 / dt) as u64;
                    st.traffic.down = ((d.saturating_sub(ld)) as f64 / dt) as u64;
                }
                st.traffic.last = Some((now, u, d));
                st.traffic.up_total = u;
                st.traffic.down_total = d;
            }
        }
        let pool = self.pool();
        let st = self.st.lock().unwrap();
        let countries_ok = scan::countries_usable(&st.servers, &Self::countries(&st));
        let cur = st.conn.current.clone().or_else(|| st.settings.selected.clone());
        let server = cur.and_then(|id| st.servers.iter().find(|s| s.id == id)).map(|s| view(s, true));
        let routes = &st.settings.routes;
        StatusView {
            state: st.conn.state,
            since: st.conn.since,
            error: st.conn.error.clone(),
            message: st.conn.message.clone(),
            server,
            auto: st.settings.selected.is_none(),
            scan: self.progress.lock().unwrap().clone(),
            pool: pool.iter().filter(|s| s.good()).count(),
            good: st.servers.iter().filter(|s| s.good()).count(),
            mine: st.servers.iter().filter(|s| s.origin == Origin::Mine).count(),
            up: if connected { st.traffic.up } else { 0 },
            down: if connected { st.traffic.down } else { 0 },
            up_total: st.traffic.up_total,
            down_total: st.traffic.down_total,
            user_cc: st.net.user_cc.clone(),
            routes_default: if routes.default == Target::Direct { "direct".into() } else { "vpn".into() },
            routes_on: routes.units().len(),
            routes_spare: if connected { routes.units().iter().filter(|r| st.route_spare.contains(&r.id)).count() } else { 0 },
            version: self.version.clone(),
            core: self.core_version.lock().unwrap().clone(),
            warp: st.settings.warp,
            countries: st.settings.countries.clone(),
            countries_ok,
            notice_id: st.notice.0,
            notice: st.notice.1.clone(),
        }
    }

    // ---------------- connection ----------------

    pub async fn connect_task(self: Arc<Self>, server: Option<String>) {
        let my = self.generation.fetch_add(1, Ordering::SeqCst) + 1;
        let alive = || self.generation.load(Ordering::SeqCst) == my;
        if let Some(s) = server {
            self.st.lock().unwrap().settings.selected = Some(s);
            self.save_settings();
        }
        self.set_conn(ConnState::Connecting, Some("Готовим подключение…"), None);
        let _g = self.op.lock().await;
        if !alive() {
            return;
        }
        self.set_conn(ConnState::Connecting, Some("Запускаем туннель…"), None);
        if self.usable_count() == 0 {
            // Start (or join) a search and connect as soon as a few servers work;
            // the search goes on in the background and refreshes the pool when done.
            self.set_conn(ConnState::Connecting, Some("Ищем рабочие серверы…"), None);
            if !self.scanning.load(Ordering::SeqCst) {
                let me = self.clone();
                tokio::spawn(async move { me.scan_task(false, false).await });
                tokio::time::sleep(Duration::from_millis(300)).await;
            }
            let mut first_ok: Option<Instant> = None;
            loop {
                if !alive() {
                    return;
                }
                let n = self.usable_count();
                let scanning = self.scanning.load(Ordering::SeqCst);
                if n > 0 && first_ok.is_none() {
                    first_ok = Some(Instant::now());
                }
                if n >= 3 || !scanning || first_ok.map(|t| t.elapsed() > Duration::from_secs(8)).unwrap_or(false) {
                    break;
                }
                let p = self.progress.lock().unwrap().clone();
                let msg = if p.total > 0 { format!("Ищем рабочие серверы… {}/{}", p.done, p.total) } else { "Ищем рабочие серверы…".to_string() };
                self.set_conn(ConnState::Connecting, Some(&msg), None);
                tokio::time::sleep(Duration::from_millis(400)).await;
            }
        }
        if !alive() {
            return;
        }
        if self.usable_count() == 0 {
            let msg = if self.cancel.load(Ordering::Relaxed) { "Поиск остановлен" } else { "Не удалось найти рабочие серверы. Проверьте интернет или добавьте свой сервер." };
            self.set_conn(ConnState::Error, None, Some(msg.into()));
            return;
        }
        match self.start_main().await {
            Ok(()) => {
                {
                    let mut st = self.st.lock().unwrap();
                    st.settings.was_connected = true;
                    st.traffic = Traffic::default();
                }
                self.save_settings();
                self.log("подключено");
            }
            Err(e) => {
                self.log(&format!("ошибка подключения: {e}"));
                self.set_conn(ConnState::Error, None, Some(e));
            }
        }
    }

    fn write_extra(&self, extra: &[Server]) -> Result<(), String> {
        let refs: Vec<&Server> = extra.iter().collect();
        mihomo::write_atomic(&self.paths.run().join("extra.yaml"), mihomo::extra_file(&refs).as_bytes()).map_err(|e| e.to_string())
    }

    /// pool.yaml, extra.yaml (route-only servers) and the rule lists of active routes.
    fn write_run_files(&self, pool: &[Server], extra: &[Server]) -> Result<(), String> {
        let run = self.paths.run();
        std::fs::create_dir_all(&run).map_err(|e| e.to_string())?;
        let refs: Vec<&Server> = pool.iter().collect();
        mihomo::write_atomic(&run.join("pool.yaml"), mihomo::pool_file(&refs).as_bytes()).map_err(|e| e.to_string())?;
        self.write_extra(extra)?;
        let ids: Vec<String> = self.st.lock().unwrap().settings.routes.units().iter().map(|r| r.id.clone()).collect();
        self.write_route_lists(&ids)?;
        // lists of removed or disabled routes
        if let Ok(rd) = std::fs::read_dir(run.join("routes")) {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if !ids.iter().any(|id| name.starts_with(&format!("{id}-"))) {
                    let _ = std::fs::remove_file(e.path());
                }
            }
        }
        Ok(())
    }

    async fn start_main(self: &Arc<Self>) -> Result<(), String> {
        let pool = self.pool();
        if pool.is_empty() {
            return Err("нет серверов".into());
        }
        let (plans, extra, chains, default_chain) = self.route_plans(&pool);
        self.write_run_files(&pool, &extra)?;
        let (opts, selected) = {
            let st = self.st.lock().unwrap();
            let s = &st.settings;
            (
                mihomo::MainOpts {
                    api_port: mihomo::free_port(),
                    secret: util::random_token(24),
                    default_direct: s.routes.default == Target::Direct,
                    default_chain,
                    routes: plans,
                    chains,
                    stack: s.stack.clone(),
                    strict_route: s.strict_route,
                    ipv6: s.ipv6,
                    tun_name: TUN.into(),
                    proxy_port: std::env::var("LAZEYKA_NO_TUN").ok().and_then(|p| p.parse().ok()),
                },
                s.selected.clone(),
            )
        };
        let cfg = mihomo::main_config(&opts);
        let run = self.paths.run();
        mihomo::write_atomic(&run.join("config.json"), cfg.to_string().as_bytes()).map_err(|e| e.to_string())?;
        {
            let mut g = self.main.lock().await;
            if let Some(mut p) = g.take() {
                p.stop().await;
            }
            *self.api.lock().unwrap() = None;
            let p = mihomo::Process::start(mihomo::Spawn {
                bin: &self.paths.mihomo(),
                dir: &run,
                config_file: "config.json",
                api_port: opts.api_port,
                secret: &opts.secret,
                mem_mb: 48,
            })
            .await?;
            if let Ok(v) = p.api.version().await {
                *self.core_version.lock().unwrap() = v;
            }
            *self.api.lock().unwrap() = Some(p.api.clone());
            *g = Some(p);
        }
        {
            let mut a = self.applied.lock().unwrap();
            a.opts = Some(opts.clone());
            a.pool = pool.iter().map(|s| s.id.clone()).collect();
            a.extra = extra.iter().map(|s| s.id.clone()).collect();
        }
        self.st.lock().unwrap().route_spare.clear();
        let api = self.api.lock().unwrap().clone().ok_or("mihomo не запущен")?;
        let target = selected.clone().filter(|id| pool.iter().any(|s| &s.id == id)).unwrap_or_else(|| "AUTO".into());
        let _ = api.select("VPN", &target).await;
        self.set_conn(ConnState::On, Some("Проверяем соединение…"), None);
        let mut ok = None;
        for i in 0..3 {
            ok = api.proxy_delay("VPN", mihomo::TEST_URL, 5000).await;
            if ok.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500 * (i + 1))).await;
        }
        let current = if target == "AUTO" { api.now("AUTO").await } else { Some(target) };
        {
            let mut st = self.st.lock().unwrap();
            st.conn.current = current;
            st.conn.message = if ok.is_some() { None } else { Some("Сервер не отвечает — ищем другой…".into()) };
        }
        if ok.is_none() {
            let me = self.clone();
            tokio::spawn(async move { me.pool_check().await });
        }
        Ok(())
    }

    async fn restart_main(self: &Arc<Self>) -> Result<(), String> {
        let _g = self.op.lock().await;
        self.set_conn(ConnState::Connecting, Some("Применяем настройки…"), None);
        match self.start_main().await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.set_conn(ConnState::Error, None, Some(e.clone()));
                Err(e)
            }
        }
    }

    pub async fn disconnect(&self) {
        self.generation.fetch_add(1, Ordering::SeqCst);
        // a search started by the connect attempt would hold the lock: stop it
        if self.st.lock().unwrap().conn.state == ConnState::Connecting {
            self.cancel.store(true, Ordering::Relaxed);
        }
        let _g = self.op.lock().await;
        let mut g = self.main.lock().await;
        if let Some(mut p) = g.take() {
            p.stop().await;
        }
        *self.api.lock().unwrap() = None;
        {
            let mut st = self.st.lock().unwrap();
            st.conn = Conn::default();
            st.settings.was_connected = false;
            st.traffic.up = 0;
            st.traffic.down = 0;
        }
        self.save_settings();
        self.log("отключено");
    }

    pub async fn shutdown(&self) {
        self.cancel.store(true, Ordering::Relaxed);
        let mut g = self.main.lock().await;
        if let Some(mut p) = g.take() {
            p.stop().await;
        }
    }

    /// Rewrites pool.yaml (and the route-only servers) and hot-reloads the providers.
    /// When the servers of a route change, the configuration is rebuilt in place.
    async fn apply_pool(self: &Arc<Self>) {
        let pool = self.pool();
        let (plans, extra, chains, default_chain) = self.route_plans(&pool);
        let (same_plan, old_pool, old_extra) = {
            let a = self.applied.lock().unwrap();
            (a.opts.as_ref().map(|o| o.routes == plans && o.chains == chains && o.default_chain == default_chain).unwrap_or(true), a.pool.clone(), a.extra.clone())
        };
        if !same_plan && self.connected() {
            let _ = self.reload_main().await;
            return;
        }
        let api = self.api.lock().unwrap().clone();
        let with_extra = !extra.is_empty() || !old_extra.is_empty();
        if let (Some(api), true) = (api.as_ref(), with_extra) {
            // A route server moving between the providers must not vanish from its group
            // for a moment (an empty group rejects): first keep in "extra" every route server
            // that is not in the pool both before and after the change.
            let stay: HashSet<&String> = old_pool.iter().filter(|id| pool.iter().any(|s| &s.id == *id)).collect();
            let wanted: Vec<String> = plans
                .iter()
                .filter_map(|p| if let Via::Servers(ids) = &p.via { Some(ids.clone()) } else { None })
                .flatten()
                .filter(|id| !stay.contains(id))
                .collect();
            let transit: Vec<Server> = {
                let st = self.st.lock().unwrap();
                let mut v: Vec<Server> = Vec::new();
                for id in &wanted {
                    if let Some(s) = st.servers.iter().find(|s| &s.id == id) {
                        if !v.iter().any(|x| x.id == s.id) {
                            v.push(s.clone());
                        }
                    }
                }
                v
            };
            if self.write_extra(&transit).is_ok() {
                let _ = api.reload_proxy_provider("extra").await;
            }
        }
        if self.write_run_files(&pool, &extra).is_err() {
            return;
        }
        {
            let mut a = self.applied.lock().unwrap();
            a.pool = pool.iter().map(|s| s.id.clone()).collect();
            a.extra = extra.iter().map(|s| s.id.clone()).collect();
        }
        if let Some(api) = api {
            let _ = api.reload_proxy_provider("pool").await;
            if with_extra {
                let _ = api.reload_proxy_provider("extra").await;
            }
            let sel = self.st.lock().unwrap().settings.selected.clone();
            let target = sel.filter(|id| pool.iter().any(|s| &s.id == id)).unwrap_or_else(|| "AUTO".into());
            let _ = api.select("VPN", &target).await;
        }
    }

    async fn set_settings(self: &Arc<Self>, patch: Value) -> Result<Value, String> {
        let restart = {
            let mut st = self.st.lock().unwrap();
            let s = &mut st.settings;
            let before = (s.stack.clone(), s.strict_route, s.ipv6);
            if let Some(v) = patch.get("connect_on_start").and_then(|v| v.as_bool()) {
                s.connect_on_start = v;
            }
            if let Some(v) = patch.get("stack").and_then(|v| v.as_str()) {
                if matches!(v, "gvisor" | "mixed" | "system") {
                    s.stack = v.to_string();
                }
            }
            if let Some(v) = patch.get("strict_route").and_then(|v| v.as_bool()) {
                s.strict_route = v;
            }
            if let Some(v) = patch.get("ipv6").and_then(|v| v.as_bool()) {
                s.ipv6 = v;
            }
            if let Some(v) = patch.get("scan_target").and_then(|v| v.as_u64()) {
                s.scan_target = (v as usize).clamp(3, 50);
            }
            if let Some(v) = patch.get("pool_size").and_then(|v| v.as_u64()) {
                s.pool_size = (v as usize).clamp(2, 30);
            }
            if let Some(v) = patch.get("sort").and_then(|v| v.as_str()) {
                if matches!(v, "best" | "ping" | "speed" | "stable") {
                    s.sort = v.to_string();
                }
            }
            before != (s.stack.clone(), s.strict_route, s.ipv6)
        };
        self.save_settings();
        if restart && self.connected() {
            self.restart_main().await?;
        }
        Ok(Value::Null)
    }

    // ---------------- import / subscriptions ----------------

    async fn import(self: &Arc<Self>, text: &str, source: &str, name_hint: &str) -> Result<Value, String> {
        let t = text.trim();
        if (t.starts_with("https://") || t.starts_with("http://")) && !t.contains('\n') {
            return self.add_subscription(t, name_hint).await;
        }
        let rep = import::parse_text(t);
        let single = rep.items.len() == 1;
        let mut added = Vec::new();
        for p in rep.items {
            let name = if single && p.name.trim().is_empty() { util::clip(name_hint.trim(), 60) } else { p.name };
            if let Ok(s) = Server::new(&name, p.proxy, Origin::Mine, source) {
                added.push(s);
            }
        }
        if added.is_empty() {
            return Err(rep.errors.first().cloned().unwrap_or_else(|| "не найдено поддерживаемых конфигураций".into()));
        }
        let n = added.len();
        {
            let mut st = self.st.lock().unwrap();
            for s in &added {
                if let Some(e) = st.servers.iter_mut().find(|x| x.id == s.id) {
                    e.origin = Origin::Mine;
                    e.source = s.source.clone();
                    if !s.name.is_empty() {
                        e.name = s.name.clone();
                    }
                } else {
                    st.servers.push(s.clone());
                }
            }
        }
        self.save_servers();
        let me = self.clone();
        let ids: Vec<String> = added.iter().map(|s| s.id.clone()).collect();
        tokio::spawn(async move { me.check_ids(ids).await });
        Ok(json!({ "added": n, "errors": rep.errors.len() }))
    }

    async fn add_subscription(self: &Arc<Self>, url: &str, name: &str) -> Result<Value, String> {
        let url = url.trim().to_string();
        let id = crate::model::proxy_id(&serde_json::Map::from_iter([("sub".to_string(), Value::from(url.clone()))]))[1..9].to_string();
        let sub = Subscription { id: id.clone(), name: if name.trim().is_empty() { host_of(&url) } else { name.trim().to_string() }, url, updated: 0, count: 0, error: None };
        {
            let mut st = self.st.lock().unwrap();
            if !st.settings.subscriptions.iter().any(|s| s.id == id) {
                st.settings.subscriptions.push(sub.clone());
            }
        }
        self.save_settings();
        let n = self.update_subscription(&id).await?;
        Ok(json!({ "added": n }))
    }

    async fn update_subscription(self: &Arc<Self>, id: &str) -> Result<usize, String> {
        let sub = self.st.lock().unwrap().settings.subscriptions.iter().find(|s| s.id == id).cloned().ok_or("нет подписки")?;
        let c = sources::fetch_client();
        let res = sources::get_capped(&c, &sub.url, sources::MAX_SIZE).await;
        let src = format!("sub:{id}");
        let r = match res {
            Ok(text) => {
                let rep = import::parse_text(&text);
                let list: Vec<Server> = rep.items.into_iter().filter_map(|p| Server::new(&p.name, p.proxy, Origin::Mine, &src).ok()).collect();
                if list.is_empty() {
                    Err(rep.errors.first().cloned().unwrap_or_else(|| "подписка пуста".into()))
                } else {
                    Ok(list)
                }
            }
            Err(e) => Err(e),
        };
        let out = match r {
            Ok(list) => {
                let n = list.len();
                let ids: Vec<String> = list.iter().map(|s| s.id.clone()).collect();
                {
                    let mut st = self.st.lock().unwrap();
                    let keep: HashSet<String> = ids.iter().cloned().collect();
                    // remove servers that disappeared from the subscription
                    st.servers.retain(|s| s.source != src || keep.contains(&s.id));
                    for s in list {
                        if let Some(e) = st.servers.iter_mut().find(|x| x.id == s.id) {
                            e.origin = Origin::Mine;
                            e.source = src.clone();
                            e.name = s.name;
                        } else {
                            st.servers.push(s);
                        }
                    }
                    if let Some(sb) = st.settings.subscriptions.iter_mut().find(|s| s.id == id) {
                        sb.updated = util::now();
                        sb.count = n;
                        sb.error = None;
                    }
                }
                let me = self.clone();
                tokio::spawn(async move { me.check_ids(ids).await });
                Ok(n)
            }
            Err(e) => {
                let mut st = self.st.lock().unwrap();
                if let Some(sb) = st.settings.subscriptions.iter_mut().find(|s| s.id == id) {
                    sb.error = Some(e.clone());
                }
                Err(e)
            }
        };
        self.save_settings();
        self.save_servers();
        out
    }

    async fn refresh_subscriptions(self: Arc<Self>) {
        let ids: Vec<String> = self.st.lock().unwrap().settings.subscriptions.iter().map(|s| s.id.clone()).collect();
        for id in ids {
            let _ = self.update_subscription(&id).await;
        }
        self.st.lock().unwrap().last_subs = util::now();
        if self.connected() {
            self.apply_pool().await;
        }
    }

    // ---------------- scanning ----------------

    fn scan_env(&self) -> scan::Env {
        let geo = Geo::open(&self.paths.mmdb()).ok().map(Arc::new);
        // Probes must bypass our TUN. On Windows binding is always safe; on Linux it needs
        // root, which the engine only has when it can run the TUN anyway.
        let interface = if cfg!(windows) || self.connected() { netif::physical(TUN) } else { None };
        scan::Env {
            mihomo: self.paths.mihomo(),
            dir: self.paths.lab(),
            geo,
            interface,
            cancel: self.cancel.clone(),
            progress: self.progress.clone(),
        }
    }

    /// Servers that must not be probed now: the active WireGuard-family server (same key
    /// from a second socket would steal the session) and all WARP variants if WARP is active.
    fn busy_ids(&self) -> HashSet<String> {
        let st = self.st.lock().unwrap();
        let mut out = HashSet::new();
        if !matches!(st.conn.state, ConnState::On | ConnState::Connecting) {
            return out;
        }
        if let Some(cur) = st.conn.current.as_ref().and_then(|id| st.servers.iter().find(|s| &s.id == id)) {
            if is_wg(cur) {
                out.insert(cur.id.clone());
            }
            if cur.origin == Origin::Warp {
                out.extend(st.servers.iter().filter(|s| s.origin == Origin::Warp).map(|s| s.id.clone()));
            }
        }
        out
    }

    async fn check_ids(self: Arc<Self>, ids: Vec<String>) {
        if self.scanning.swap(true, Ordering::SeqCst) {
            return;
        }
        let busy = self.busy_ids();
        let list: Vec<Server> = {
            let st = self.st.lock().unwrap();
            st.servers.iter().filter(|s| ids.contains(&s.id) && !busy.contains(&s.id)).cloned().collect()
        };
        if !list.is_empty() {
            self.reset_progress("Проверка серверов");
            let env = self.scan_env();
            let mut net = self.st.lock().unwrap().net.clone();
            let opts = scan::Opts { target_good: 0, speed_top: 2, ..Default::default() };
            let res = scan::check(&env, list, &opts, &mut net, |b| self.merge(b)).await;
            // speeds are measured after the batch callback
            self.merge_with(&res, false);
            self.st.lock().unwrap().net = net;
            self.save_servers();
            if self.connected() {
                self.apply_pool().await;
            }
            self.finish_progress();
        }
        self.scanning.store(false, Ordering::SeqCst);
    }

    fn reset_progress(&self, stage: &str) {
        self.cancel.store(false, Ordering::Relaxed);
        *self.progress.lock().unwrap() = Progress { running: true, stage: stage.into(), started: util::now(), ..Default::default() };
    }

    fn finish_progress(&self) {
        let mut p = self.progress.lock().unwrap();
        p.running = false;
        p.finished = util::now();
    }

    async fn ensure_warp(self: &Arc<Self>) -> Result<(), String> {
        let have = self.st.lock().unwrap().warp.clone();
        let acc = match have {
            Some(a) => a,
            None => {
                let c = crate::probe::client(None, Duration::from_secs(20))?;
                let a = warp::register(&c).await?;
                let _ = store::save(&self.paths.warp(), &Some(a.clone()));
                self.st.lock().unwrap().warp = Some(a.clone());
                self.log("WARP: устройство зарегистрировано");
                a
            }
        };
        let list = warp::servers(&acc);
        self.add_new(list);
        Ok(())
    }

    pub async fn scan_task(self: Arc<Self>, full: bool, interactive: bool) {
        if self.scanning.swap(true, Ordering::SeqCst) {
            return;
        }
        self.reset_progress("Загрузка списков");
        let env = self.scan_env();
        let busy = self.busy_ids();
        let (settings, mut net) = {
            let st = self.st.lock().unwrap();
            (st.settings.clone(), st.net.clone())
        };
        let target = settings.scan_target;
        let want: HashSet<String> = settings.countries.iter().cloned().collect();
        let base = scan::Opts { target_good: 0, speed_top: 0, want_cc: want.clone(), ..Default::default() };
        // 1. user's own and starred servers
        let mine: Vec<Server> = {
            let st = self.st.lock().unwrap();
            st.servers.iter().filter(|s| (s.origin == Origin::Mine || (s.fav && s.origin == Origin::Free)) && !busy.contains(&s.id)).cloned().collect()
        };
        if !mine.is_empty() {
            scan::check(&env, mine, &base, &mut net, |b| self.merge(b)).await;
        }
        // 2. WARP
        if settings.warp && !env.cancel.load(Ordering::Relaxed) {
            match self.ensure_warp().await {
                Ok(()) => {
                    let w: Vec<Server> = {
                        let st = self.st.lock().unwrap();
                        let mut v: Vec<Server> = st.servers.iter().filter(|s| s.origin == Origin::Warp && !busy.contains(&s.id)).cloned().collect();
                        // previously working variants first
                        v.sort_by_key(|s| scan::score(s));
                        v
                    };
                    // all variants share one device key: while one of them works,
                    // testing the rest only fights its session — re-test when none works
                    if !w.is_empty() && !w.iter().any(|s| s.good()) {
                        scan::check(&env, w, &base, &mut net, |b| self.merge(b)).await;
                    }
                }
                Err(e) => self.log(&e),
            }
        }
        // 3. known working public servers whose last check is old: after an outage the
        // stored "good" marks can be stale, and the search below trusts them
        if !full && !env.cancel.load(Ordering::Relaxed) {
            let now = util::now();
            let stale: Vec<Server> = {
                let st = self.st.lock().unwrap();
                st.servers
                    .iter()
                    .filter(|s| s.origin == Origin::Free && !s.fav && s.good() && !busy.contains(&s.id))
                    .filter(|s| s.probe.as_ref().is_some_and(|p| now.saturating_sub(p.at) > if is_wg(s) { 24 * 3600 } else { 15 * 60 }))
                    .cloned()
                    .collect()
            };
            if !stale.is_empty() {
                scan::check(&env, stale, &base, &mut net, |b| self.merge_with(b, false)).await;
                self.save_servers();
            }
        }
        // 4. public sources, tier by tier until enough good servers
        let srcs = settings.sources();
        let fc = sources::fetch_client();
        for tier in 1..=3u8 {
            if env.cancel.load(Ordering::Relaxed) {
                break;
            }
            // with chosen countries only servers there count
            let good_free = || self.st.lock().unwrap().servers.iter().filter(|s| s.origin == Origin::Free && s.good() && scan::in_countries(s, &want)).count();
            if !full && good_free() >= target {
                break;
            }
            env.progress.lock().unwrap().stage = "Загрузка списков".into();
            let defs: Vec<sources::SourceDef> = srcs.iter().filter(|d| d.tier == tier && d.enabled).cloned().collect();
            let mut js = tokio::task::JoinSet::new();
            for d in defs.clone() {
                let c = fc.clone();
                let cache = self.paths.cache();
                js.spawn(async move {
                    let r = sources::fetch(&c, &d, &cache, 1800).await;
                    (d, r)
                });
            }
            while let Some(Ok((d, r))) = js.join_next().await {
                match r {
                    Ok(text) => {
                        let rep = import::parse_text(&text);
                        let list: Vec<Server> = rep.items.into_iter().filter_map(|p| Server::new(&p.name, p.proxy, Origin::Free, &d.id).ok()).collect();
                        let mut st = self.st.lock().unwrap();
                        let e = st.stats.entry(d.id.clone()).or_default();
                        e.fetched = util::now();
                        e.parsed = list.len();
                        e.error = None;
                        drop(st);
                        self.add_new(list);
                    }
                    Err(e) => {
                        let mut st = self.st.lock().unwrap();
                        st.stats.entry(d.id.clone()).or_default().error = Some(e);
                    }
                }
            }
            let tier_ids: HashSet<String> = defs.iter().map(|d| d.id.clone()).collect();
            // servers whose entry IP is in a chosen country are tested first
            let geo = env.geo.clone();
            let prefer = |s: &Server| {
                want.is_empty()
                    || s.host.parse::<std::net::IpAddr>().ok().and_then(|ip| geo.as_ref().and_then(|g| g.country(ip))).is_some_and(|c| want.contains(&c))
            };
            let plan = {
                let st = self.st.lock().unwrap();
                let cands: Vec<Server> = st.servers.iter().filter(|s| tier_ids.contains(&s.source) && !busy.contains(&s.id)).cloned().collect();
                scan::plan(&cands, &srcs, &st.stats, if full { 1500 } else { 700 }, util::now(), &prefer)
            };
            let need = if full { 0 } else { target.saturating_sub(good_free()).max(1) };
            let opts = scan::Opts { target_good: need, ..base.clone() };
            scan::check(&env, plan, &opts, &mut net, |b| {
                self.merge(b);
            })
            .await;
            self.save_servers();
            if self.connected() {
                self.apply_pool().await;
            }
        }
        // 5. speed of the five best (the ones AUTO will use). Background searches only
        // refresh measurements older than 12 hours: each test downloads a few megabytes.
        if !env.cancel.load(Ordering::Relaxed) {
            let now = util::now();
            let mut best: Vec<Server> = self.pool().into_iter().filter(|s| s.good() && !busy.contains(&s.id)).take(5).collect();
            if !interactive {
                // background: no speed tests through WireGuard either (a real tunnel
                // and megabytes of traffic for a number a shared profile makes moot)
                best.retain(|s| !is_wg(s) && s.fresh_speed(now, 12 * 3600).is_none());
            }
            if !best.is_empty() {
                scan::speed_stage(&env, &mut best, 5).await;
                let mut st = self.st.lock().unwrap();
                for b in best {
                    if let (Some(e), Some(bp)) = (st.servers.iter_mut().find(|x| x.id == b.id), b.probe) {
                        if let Some(ep) = e.probe.as_mut() {
                            if bp.speed_at >= ep.speed_at {
                                ep.speed = bp.speed;
                                ep.speed_at = bp.speed_at;
                            }
                        }
                    }
                }
            }
        }
        {
            let mut st = self.st.lock().unwrap();
            st.net = net;
            st.last_full = util::now();
            st.last_pool_check = util::now();
        }
        self.save_servers();
        if self.connected() {
            self.apply_pool().await;
        }
        let good = self.st.lock().unwrap().servers.iter().filter(|s| s.good()).count();
        self.log(&format!("поиск завершён: рабочих серверов {good}"));
        self.finish_progress();
        self.scanning.store(false, Ordering::SeqCst);
    }

    /// Rechecks the current pool (fast, no speed test) and refreshes the provider.
    async fn pool_check(self: Arc<Self>) {
        if self.scanning.swap(true, Ordering::SeqCst) {
            return;
        }
        let busy = self.busy_ids();
        let now = util::now();
        let mut list: Vec<Server> = self.pool().into_iter().filter(|s| !busy.contains(&s.id) && scan::bg_recheck(s, now)).collect();
        // servers of routes too: a country route needs to know which of them still work
        let extra: Vec<Server> = {
            let ids = self.route_server_ids();
            let st = self.st.lock().unwrap();
            st.servers.iter().filter(|s| ids.contains(&s.id) && !busy.contains(&s.id) && scan::bg_recheck(s, now) && !list.iter().any(|x| x.id == s.id)).cloned().collect()
        };
        list.extend(extra);
        if !list.is_empty() {
            let env = self.scan_env();
            let mut net = self.st.lock().unwrap().net.clone();
            let opts = scan::Opts { target_good: 0, speed_top: 0, services: true, ..Default::default() };
            scan::check(&env, list, &opts, &mut net, |b| self.merge(b)).await;
            self.st.lock().unwrap().net = net;
            self.save_servers();
        }
        self.st.lock().unwrap().last_pool_check = util::now();
        self.scanning.store(false, Ordering::SeqCst);
        if self.connected() {
            self.apply_pool().await;
            self.verify().await;
        }
    }

    /// Tests the active route and updates the status message.
    async fn verify(&self) {
        let api = self.api.lock().unwrap().clone();
        let Some(api) = api else { return };
        let ok = api.proxy_delay("VPN", mihomo::TEST_URL, 5000).await;
        let auto = self.st.lock().unwrap().settings.selected.is_none();
        let now = if auto { api.now("AUTO").await } else { None };
        let mut st = self.st.lock().unwrap();
        if st.conn.state == ConnState::On && ok.is_some() {
            // the "no servers" note is cleared by the watchdog, which also tells the user
            if st.conn.message.as_deref() != Some(NO_SERVERS) {
                st.conn.message = None;
            }
            if let Some(n) = now {
                st.conn.current = Some(n);
            }
        }
    }

    /// Manual check + speed test of one server in its own lab (does not wait for a search).
    async fn measure(self: &Arc<Self>, id: &str) -> Result<Value, String> {
        if self.busy_ids().contains(id) {
            return Err("Через этот сервер идёт подключение — замерить его отдельно нельзя".into());
        }
        let Ok(_g) = self.measuring.try_lock() else { return Err("Замер уже идёт".into()) };
        let server = self.st.lock().unwrap().servers.iter().find(|s| s.id == id).cloned().ok_or("сервер не найден")?;
        let base = self.scan_env();
        let env = scan::Env {
            dir: self.paths.data.join("lab-measure"),
            cancel: Arc::new(AtomicBool::new(false)),
            progress: Arc::new(Mutex::new(Progress::default())),
            ..base
        };
        let mut net = self.st.lock().unwrap().net.clone();
        let opts = scan::Opts { target_good: 0, speed_top: 1, ..Default::default() };
        let res = scan::check(&env, vec![server], &opts, &mut net, |_| {}).await;
        let Some(s) = res.into_iter().next() else { return Err("не удалось проверить сервер".into()) };
        self.merge_with(std::slice::from_ref(&s), false);
        self.st.lock().unwrap().net = net;
        self.save_servers();
        if self.connected() {
            self.apply_pool().await;
        }
        let in_pool = self.pool().iter().any(|x| x.id == s.id);
        let v = {
            let st = self.st.lock().unwrap();
            st.servers.iter().find(|x| x.id == s.id).map(|x| view(x, in_pool))
        };
        Ok(serde_json::to_value(v).unwrap_or(Value::Null))
    }

    fn server_name(&self, id: Option<&str>) -> String {
        let st = self.st.lock().unwrap();
        id.and_then(|id| st.servers.iter().find(|s| s.id == id)).map(|s| view(s, false).name).unwrap_or_else(|| "сервер".into())
    }

    /// A server that stopped working during the session: demote it until it is checked again.
    fn mark_failed(&self, id: &str) {
        let mut st = self.st.lock().unwrap();
        if let Some(s) = st.servers.iter_mut().find(|s| s.id == id) {
            if let Some(p) = s.probe.as_mut() {
                if p.ok {
                    p.ok = false;
                    p.error = Some("перестал отвечать".into());
                    p.at = util::now();
                }
            }
            s.fails = s.fails.saturating_add(1);
            s.record(false);
        }
    }

    /// No server of the pool answers. The tunnel stays up, so nothing goes around the VPN
    /// (except the user's exclusions); new servers are searched right away.
    fn no_servers(self: &Arc<Self>) {
        let first = {
            let mut st = self.st.lock().unwrap();
            let was = st.conn.message.as_deref() == Some(NO_SERVERS);
            st.conn.message = Some(NO_SERVERS.into());
            !was
        };
        if first {
            self.notice("Все серверы перестали отвечать. Ищем новые; до этого трафик не пойдёт мимо VPN.");
        }
        let now = util::now();
        if !self.scanning.load(Ordering::Relaxed) && now.saturating_sub(self.last_scan_try.load(Ordering::Relaxed)) > 60 {
            self.last_scan_try.store(now, Ordering::Relaxed);
            let me = self.clone();
            tokio::spawn(async move { me.scan_task(false, false).await });
        }
    }

    /// Watchdog: checks the route through the tunnel and, when it fails, switches to a
    /// working server within seconds (mihomo's own fallback reacts in minutes).
    async fn health(self: &Arc<Self>, h: &mut Health) {
        let Some(api) = self.api.lock().unwrap().clone() else { return };
        if self.st.lock().unwrap().conn.state != ConnState::On {
            return;
        }
        self.route_health(&api).await;
        let mut ok = api.proxy_delay("VPN", mihomo::TEST_URL, 4000).await.is_some();
        if !ok {
            // a lost probe or one blocked test site is not an outage
            tokio::time::sleep(Duration::from_millis(1500)).await;
            ok = api.proxy_delay("VPN", mihomo::ALT_TEST_URL, 4000).await.is_some();
        }
        let auto = self.st.lock().unwrap().settings.selected.is_none();
        if ok {
            h.manual_fails = 0;
            let now = if auto { api.now("AUTO").await } else { None };
            let restored = {
                let mut st = self.st.lock().unwrap();
                if st.conn.state != ConnState::On {
                    return;
                }
                if let Some(n) = now {
                    st.conn.current = Some(n);
                }
                let r = st.conn.message.as_deref() == Some(NO_SERVERS);
                st.conn.message = None;
                r.then(|| st.conn.current.clone())
            };
            if let Some(cur) = restored {
                self.notice(&format!("Связь восстановлена: {}", self.server_name(cur.as_deref())));
            }
            return;
        }
        if self.st.lock().unwrap().conn.state != ConnState::On {
            return;
        }
        let cur = self.st.lock().unwrap().conn.current.clone();
        // re-test every pool member inside mihomo: the AUTO fallback then takes the first alive
        let alive = api.group_delay("AUTO", mihomo::TEST_URL, 4000).await;
        if let Some(c) = cur.as_deref() {
            if !alive.contains_key(c) {
                self.mark_failed(c);
                self.save_servers();
            }
        }
        if alive.is_empty() {
            self.no_servers();
            return;
        }
        if auto {
            let now = api.now("AUTO").await;
            if now.is_some() && now != cur {
                api.close_connections().await;
                let msg = format!("{} не отвечает — переключились на {}", self.server_name(cur.as_deref()), self.server_name(now.as_deref()));
                self.st.lock().unwrap().conn.current = now;
                self.notice(&msg);
            }
            self.st.lock().unwrap().conn.message = None;
        } else {
            h.manual_fails += 1;
            if h.manual_fails >= 2 {
                // the chosen server is down for ~20 s: keep the user online via AUTO
                h.manual_fails = 0;
                self.st.lock().unwrap().settings.selected = None;
                self.save_settings();
                let _ = api.select("VPN", "AUTO").await;
                api.close_connections().await;
                let now = api.now("AUTO").await;
                let msg = format!("{} не отвечает — включён автовыбор: {}", self.server_name(cur.as_deref()), self.server_name(now.as_deref()));
                {
                    let mut st = self.st.lock().unwrap();
                    st.conn.current = now;
                    st.conn.message = None;
                }
                self.notice(&msg);
            } else {
                self.st.lock().unwrap().conn.message = Some(NOT_RESPONDING.into());
            }
        }
        // re-probe the pool soon: the order should reflect what works now
        self.st.lock().unwrap().last_pool_check = 0;
    }

    async fn maintenance(self: Arc<Self>) {
        let mut tick: u64 = 0;
        let mut health = Health::default();
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            tick += 1;
            if !self.connected() {
                health = Health::default();
                continue;
            }
            // supervise the main instance
            let dead = {
                match self.main.try_lock() {
                    Ok(mut g) => g.as_mut().map(|p| !p.alive()).unwrap_or(false),
                    Err(_) => false,
                }
            };
            if dead && self.st.lock().unwrap().conn.state == ConnState::On {
                self.log("mihomo завершился — перезапуск");
                let _ = self.restart_main().await;
                continue;
            }
            if tick % 2 == 0 {
                self.health(&mut health).await;
            }
            let (last_pool, last_full, last_subs, has_subs) = {
                let st = self.st.lock().unwrap();
                (st.last_pool_check, st.last_full, st.last_subs, !st.settings.subscriptions.is_empty())
            };
            let now = util::now();
            if self.scanning.load(Ordering::Relaxed) {
                continue;
            }
            let last_try = self.last_scan_try.load(Ordering::Relaxed);
            if (self.usable_count() < 3 && now.saturating_sub(last_try) > 300) || now.saturating_sub(last_full) > 6 * 3600 {
                self.last_scan_try.store(now, Ordering::Relaxed);
                let me = self.clone();
                tokio::spawn(async move { me.scan_task(false, false).await });
            } else if now.saturating_sub(last_pool) > 600 {
                let me = self.clone();
                tokio::spawn(async move { me.pool_check().await });
            } else if has_subs && now.saturating_sub(last_subs) > 12 * 3600 {
                let me = self.clone();
                tokio::spawn(async move { me.refresh_subscriptions().await });
            }
        }
    }
}

fn host_of(url: &str) -> String {
    url.split("://").nth(1).unwrap_or(url).split(['/', '?']).next().unwrap_or(url).to_string()
}
