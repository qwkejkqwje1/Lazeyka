//! Persistent state: settings, known servers, WARP account, source statistics.

use crate::model::{Origin, Server};
use crate::routes::Routes;
use crate::scan::SourceStat;
use crate::sources::SourceDef;
use crate::split::Split;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Paths {
    /// Writable data dir (the "data" folder next to lazeyka.exe on Windows).
    pub data: PathBuf,
    /// Dir with mihomo and the geo database.
    pub bin: PathBuf,
}

impl Paths {
    pub fn settings(&self) -> PathBuf {
        self.data.join("settings.json")
    }
    pub fn servers(&self) -> PathBuf {
        self.data.join("servers.json")
    }
    pub fn warp(&self) -> PathBuf {
        self.data.join("warp.json")
    }
    pub fn warp_retry(&self) -> PathBuf {
        self.data.join("warp-retry.json")
    }
    pub fn grave(&self) -> PathBuf {
        self.data.join("graveyard.json")
    }
    pub fn stats(&self) -> PathBuf {
        self.data.join("sources.json")
    }
    /// What the network blocks (`nettest`), for the network it was measured on.
    pub fn netprofile(&self) -> PathBuf {
        self.data.join("netprofile.json")
    }
    pub fn cache(&self) -> PathBuf {
        self.data.join("cache")
    }
    pub fn run(&self) -> PathBuf {
        self.data.join("run")
    }
    pub fn lab(&self) -> PathBuf {
        self.data.join("lab")
    }
    pub fn log(&self) -> PathBuf {
        self.data.join("lazeyka.log")
    }
    pub fn mihomo(&self) -> PathBuf {
        if let Ok(p) = std::env::var("LAZEYKA_MIHOMO") {
            return p.into();
        }
        self.bin.join(if cfg!(windows) { "mihomo.exe" } else { "mihomo" })
    }
    pub fn mmdb(&self) -> PathBuf {
        if let Ok(p) = std::env::var("LAZEYKA_MMDB") {
            return p.into();
        }
        let d = self.data.join("dbip-country-lite.mmdb");
        if d.exists() { d } else { self.bin.join("dbip-country-lite.mmdb") }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Subscription {
    pub id: String,
    pub name: String,
    pub url: String,
    #[serde(default)]
    pub updated: u64,
    #[serde(default)]
    pub count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

fn t() -> bool {
    true
}
fn gvisor() -> String {
    "gvisor".into()
}
fn twelve() -> usize {
    12
}
fn eight() -> usize {
    8
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Settings {
    /// 0.1–0.2 split tunneling; read once and turned into `routes`.
    #[serde(default, skip_serializing)]
    pub split: Option<Split>,
    #[serde(default)]
    pub routes: Routes,
    /// Server chosen by the user; None = automatic choice.
    #[serde(default)]
    pub selected: Option<String>,
    #[serde(default = "t")]
    pub warp: bool,
    #[serde(default)]
    pub connect_on_start: bool,
    #[serde(default)]
    pub was_connected: bool,
    #[serde(default = "gvisor")]
    pub stack: String,
    #[serde(default = "t")]
    pub strict_route: bool,
    #[serde(default = "t")]
    pub ipv6: bool,
    /// Built-in sources toggled against their default.
    #[serde(default)]
    pub source_toggles: HashMap<String, bool>,
    #[serde(default)]
    pub custom_sources: Vec<SourceDef>,
    #[serde(default)]
    pub subscriptions: Vec<Subscription>,
    #[serde(default = "twelve")]
    pub scan_target: usize,
    #[serde(default = "eight")]
    pub pool_size: usize,
    /// Exit countries chosen by the user (ISO codes): AUTO uses only them, the search
    /// checks servers there first. Empty = any country.
    #[serde(default)]
    pub countries: Vec<String>,
    /// Traffic through the VPN over all sessions, bytes (counted from mihomo's own counters).
    #[serde(default)]
    pub traffic_up: u64,
    #[serde(default)]
    pub traffic_down: u64,
    /// Test servers that do not answer directly through a working entry hop.
    #[serde(default = "t")]
    pub relay_scan: bool,
    /// Protect TCP port 80 from public-list servers: route via a trusted server or block (REJECT)
    /// unless `http_allow_direct` is explicitly enabled.
    #[serde(default = "t")]
    pub https_only_free: bool,
    /// Allow unencrypted HTTP (TCP/80) to go directly outside the VPN when no trusted server
    /// is available. Disabled by default to prevent ISP DPI/IP leaks.
    #[serde(default)]
    pub http_allow_direct: bool,
    /// Check for new versions of the program and mihomo; mihomo is installed by itself.
    #[serde(default = "t")]
    pub auto_update: bool,
    /// Server list order in the UI: "best", "ping", "speed", "stable".
    #[serde(default = "best")]
    pub sort: String,
}

fn best() -> String {
    "best".into()
}

impl Default for Settings {
    fn default() -> Self {
        serde_json::from_str("{}").expect("defaults")
    }
}

impl Settings {
    /// Converts settings of older versions. Returns true when something changed.
    pub fn migrate(&mut self) -> bool {
        let split = match self.split.take() {
            Some(sp) if self.routes == Routes::default() => {
                self.routes = Routes::from_split(&sp);
                true
            }
            Some(_) => true,
            None => false,
        };
        let lists = self.routes.lists_to_routes();
        split || lists
    }

    /// Effective source list: built-in catalog with toggles + user-added lists.
    pub fn sources(&self) -> Vec<SourceDef> {
        let mut v = crate::sources::catalog();
        for d in v.iter_mut() {
            if let Some(on) = self.source_toggles.get(&d.id) {
                d.enabled = *on;
            }
        }
        v.extend(self.custom_sources.iter().cloned());
        v
    }
}

pub fn load<T: DeserializeOwned + Default>(p: &Path) -> T {
    match std::fs::read(p) {
        Ok(b) => serde_json::from_slice(&b).unwrap_or_else(|_| {
            // keep the broken file for diagnostics
            let _ = std::fs::rename(p, p.with_extension("broken"));
            T::default()
        }),
        Err(_) => T::default(),
    }
}

pub fn save<T: Serialize>(p: &Path, v: &T) -> std::io::Result<()> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
    }
    let data = serde_json::to_vec(v).map_err(std::io::Error::other)?;
    crate::mihomo::write_atomic(p, &data)
}

/// Loads a WARP account from disk, transparently decrypting protected private_key / token fields.
pub fn load_warp(p: &Path) -> Option<crate::warp::Account> {
    let bytes = std::fs::read(p).ok()?;
    let mut acc: crate::warp::Account = serde_json::from_slice(&bytes).ok()?;
    if let Some(pk) = crate::providers::unprotect_secret(&acc.private_key, p) {
        acc.private_key = pk;
    }
    if !acc.token.is_empty() {
        if let Some(tok) = crate::providers::unprotect_secret(&acc.token, p) {
            acc.token = tok;
        }
    }
    if acc.usable() { Some(acc) } else { None }
}

/// Saves a WARP account to disk with protected private_key and token fields.
pub fn save_warp(p: &Path, acc: &crate::warp::Account) -> std::io::Result<()> {
    let mut stored = acc.clone();
    stored.private_key = crate::providers::protect_secret(&acc.private_key, p);
    if !acc.token.is_empty() {
        stored.token = crate::providers::protect_secret(&acc.token, p);
    }
    save(p, &stored)
}

pub type Stats = HashMap<String, SourceStat>;

/// Ids of removed dead servers → when they were buried. Sources keep listing the same
/// corpses; the graveyard stops them from coming back (and being re-tested) for a while.
pub type Grave = HashMap<String, u64>;

/// A server that has not worked — neither directly nor through an entry hop — for this
/// long (and keeps failing) is removed.
pub const DEAD_AFTER: u64 = 3 * 86400;
/// Never-working servers get a shorter leash.
pub const NEVER_AFTER: u64 = 2 * 86400;
/// Untested servers are only judged by age.
pub const UNTESTED_AFTER: u64 = 7 * 86400;
/// A server that the entry-hop scan has not looked at yet is spared for this long.
const RELAY_GRACE: u64 = 7 * 86400;
/// How long a buried server is refused when a source lists it again.
pub const GRAVE_TTL: u64 = 21 * 86400;
const GRAVE_MAX: usize = 40_000;
/// Free (non-starred) servers kept in the database at most; the worst go first.
pub const MAX_FREE: usize = 1500;

/// Failed because the way to it is closed from here — the entry-hop scan may still revive it.
fn unreachable_here(s: &Server) -> bool {
    !crate::scan::is_udp_proto(s)
        && s.probe.as_ref().is_some_and(|p| !p.ok && p.error.as_deref().is_some_and(crate::scan::is_path_blocked_err))
}

/// Dead: failed at least three checks in a row and has not worked (directly or through
/// a hop) for three days — two if it never worked since it was added. A server that
/// is unreachable from here is first given a try through an entry hop (up to a week).
/// Untested ones are only judged by age. Favourites, own servers, disabled/auth-blocked
/// servers and WARP are never dead.
pub fn is_dead(s: &Server, now: u64) -> bool {
    if s.origin != Origin::Free || s.fav || s.disabled || s.auth_error {
        return false;
    }
    if s.probe.is_none() {
        return now.saturating_sub(s.added) > UNTESTED_AFTER;
    }
    if s.fails < 3 || s.good() {
        return false;
    }
    if s.relay_at == 0 && unreachable_here(s) && now.saturating_sub(s.added) < RELAY_GRACE {
        return false;
    }
    if s.last_ok > 0 {
        now.saturating_sub(s.last_ok) > DEAD_AFTER
    } else {
        now.saturating_sub(s.added) > NEVER_AFTER
    }
}

/// What `prune` removed: `dead` failed for days (buried for `GRAVE_TTL`), `trimmed`
/// were tested, failing and pushed out by the size cap (buried briefly: they may simply
/// have been unlucky), `dropped` were never tested (not buried at all — the next fetch of
/// their list may bring them back and they deserve a test).
#[derive(Default, Debug)]
pub struct Pruned {
    pub dead: Vec<String>,
    pub trimmed: Vec<String>,
    pub dropped: Vec<String>,
}

impl Pruned {
    pub fn len(&self) -> usize {
        self.dead.len() + self.trimmed.len() + self.dropped.len()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// How long a server pushed out by the size cap is refused.
pub const TRIM_TTL: u64 = 2 * 86400;

/// Drops free servers that are dead or stale (not seen working for a week and not checked
/// for three days), then trims the database to `MAX_FREE` free servers: failing ones go
/// first (the longest-failing first), untested ones next, working ones never. Favourites
/// are kept.
pub fn prune_ex(servers: &mut Vec<Server>, now: u64) -> Pruned {
    let mut out = Pruned::default();
    servers.retain(|s| {
        if s.origin != Origin::Free || s.fav || s.disabled || s.auth_error {
            return true;
        }
        let checked = s.probe.as_ref().map(|p| p.at).unwrap_or(s.added);
        let fresh = now.saturating_sub(checked) < 3 * 86400;
        let worked = now.saturating_sub(s.last_ok) < 7 * 86400;
        let keep = (fresh || worked) && !is_dead(s, now);
        if !keep {
            if s.probe.is_some() { out.dead.push(s.id.clone()) } else { out.dropped.push(s.id.clone()) }
        }
        keep
    });
    let free = |s: &Server| s.origin == Origin::Free && !s.fav && !s.disabled && !s.auth_error;
    let n = servers.iter().filter(|s| free(s)).count();
    if n > MAX_FREE {
        // rank for removal: failing (0) before untested (1); within a class the oldest success first
        let mut cand: Vec<(u8, u64, u64, String)> = servers
            .iter()
            .filter(|s| free(s) && !s.good())
            .map(|s| (if s.probe.is_some() { 0 } else { 1 }, s.last_ok, s.added, s.id.clone()))
            .collect();
        cand.sort();
        let drop: Vec<(u8, u64, u64, String)> = cand.into_iter().take(n - MAX_FREE).collect();
        let ids: HashSet<String> = drop.iter().map(|c| c.3.clone()).collect();
        servers.retain(|s| !ids.contains(&s.id));
        for (class, _, _, id) in drop {
            if class == 0 { out.trimmed.push(id) } else { out.dropped.push(id) }
        }
    }
    out
}

/// `prune_ex` flattened to the removed ids.
pub fn prune(servers: &mut Vec<Server>, now: u64) -> Vec<String> {
    let p = prune_ex(servers, now);
    p.dead.into_iter().chain(p.trimmed).chain(p.dropped).collect()
}

/// Buries ids for `ttl` seconds instead of the full `GRAVE_TTL` (the stored time is
/// backdated, so the file format stays the same).
pub fn bury_for(grave: &mut Grave, ids: &[String], now: u64, ttl: u64) {
    let t = now.saturating_sub(GRAVE_TTL.saturating_sub(ttl));
    for id in ids {
        let e = grave.entry(id.clone()).or_insert(t);
        *e = (*e).max(t);
    }
}

/// Records buried ids and forgets old graves (and the oldest ones beyond the cap).
pub fn bury(grave: &mut Grave, ids: &[String], now: u64) {
    for id in ids {
        grave.insert(id.clone(), now);
    }
    grave.retain(|_, t| now.saturating_sub(*t) < GRAVE_TTL);
    if grave.len() > GRAVE_MAX {
        let mut v: Vec<(String, u64)> = grave.drain().collect();
        v.sort_by_key(|(_, t)| std::cmp::Reverse(*t));
        v.truncate(GRAVE_MAX);
        grave.extend(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::Target;

    fn free(fails: u32, last_ok: u64, added: u64, checked: Option<u64>) -> Server {
        let p: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{"type":"trojan","server":"1.2.3.4","port":443,"password":"x"}"#).unwrap();
        let mut s = Server::new("t", p, Origin::Free, "t").unwrap();
        s.added = added;
        s.fails = fails;
        s.last_ok = last_ok;
        s.probe = checked.map(|at| crate::model::Probe { at, ok: false, ..Default::default() });
        s
    }

    #[test]
    fn dead_servers_are_pruned_and_buried() {
        let day = 86400;
        let now = 100 * day;
        // keeps failing for weeks although it is "checked" every day
        let corpse = free(9, now - 30 * day, now - 60 * day, Some(now - 1000));
        // worked 2 days ago: only flapping
        let flaky = free(5, now - 2 * day, now - 60 * day, Some(now - 1000));
        // never worked, added 10 days ago
        let never = free(6, 0, now - 10 * day, Some(now - 1000));
        // never worked but added yesterday
        let newcomer = free(2, 0, now - day, Some(now - 1000));
        // untested for a month
        let forgotten = free(0, 0, now - 30 * day, None);
        let mut fav = free(9, 0, now - 90 * day, Some(now - 1000));
        fav.fav = true;
        let mut auth_blocked = free(9, 0, now - 90 * day, Some(now - 1000));
        auth_blocked.auth_error = true;
        assert!(is_dead(&corpse, now) && is_dead(&never, now) && is_dead(&forgotten, now));
        assert!(!is_dead(&flaky, now) && !is_dead(&newcomer, now) && !is_dead(&fav, now) && !is_dead(&auth_blocked, now));
        let mut all = vec![corpse, flaky, never, newcomer, forgotten, fav];
        for (i, x) in all.iter_mut().enumerate() {
            x.id = format!("s{i}");
        }
        let gone = prune(&mut all, now);
        assert_eq!(gone, ["s0", "s2", "s4"]);
        assert_eq!(all.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(), ["s1", "s3", "s5"]);
        // unreachable from here and not yet tried through a hop: spared; tried: dead
        let mut closed = free(5, now - 20 * day, now - 4 * day, Some(now - 1000));
        closed.probe.as_mut().unwrap().error = Some("порт закрыт (TCP)".into());
        assert!(!is_dead(&closed, now));
        closed.relay_at = now - 100;
        assert!(is_dead(&closed, now));
        let mut g = Grave::new();
        bury(&mut g, &gone, now);
        assert_eq!(g.len(), 3);
        // old graves expire
        bury(&mut g, &[], now + GRAVE_TTL + 1);
        assert!(g.is_empty());
    }

    #[test]
    fn database_is_capped() {
        let day = 86400;
        let now = 100 * day;
        let mut all: Vec<Server> = Vec::new();
        for i in 0..(MAX_FREE + 100) {
            // all failing but recently seen working, so only the cap removes them
            let mut s = free(1, now - day - i as u64, now - 50 * day, Some(now - 1000));
            s.id = format!("f{i}");
            all.push(s);
        }
        let mut good = free(0, now - 10, now - 50 * day, Some(now - 10));
        good.id = "good".into();
        good.probe.as_mut().unwrap().ok = true;
        good.probe.as_mut().unwrap().exit_ip = Some("203.0.113.5".into());
        good.probe.as_mut().unwrap().latency = Some(100);
        all.push(good);
        let gone = prune(&mut all, now);
        assert_eq!(gone.len(), 101);
        assert_eq!(all.len(), MAX_FREE);
        assert!(all.iter().any(|s| s.id == "good"));
        // the longest-failing (smallest last_ok) went first
        assert!(gone.contains(&format!("f{}", MAX_FREE + 99)));
        assert!(!all.iter().any(|s| s.id == format!("f{}", MAX_FREE + 99)));
    }

    #[test]
    fn split_settings_become_routes() {
        let old = r#"{"split":{"mode":"exclude","exclude":{"sites":["sber.ru"],"apps":["game.exe"]},"include":{"sites":[],"apps":[]}},"warp":false}"#;
        let mut s: Settings = serde_json::from_str(old).unwrap();
        assert!(s.migrate());
        assert_eq!(s.routes.default, Target::Vpn);
        assert_eq!(s.routes.list.len(), 1);
        assert_eq!(s.routes.list[0].target, Target::Direct);
        assert_eq!(s.routes.list[0].sites, ["sber.ru"]);
        assert!(!s.warp);
        let saved = serde_json::to_string(&s).unwrap();
        assert!(!saved.contains("\"split\""));
        let mut again: Settings = serde_json::from_str(&saved).unwrap();
        assert!(!again.migrate());
        assert_eq!(again.routes, s.routes);
        let mut fresh = Settings::default();
        assert!(!fresh.migrate());
        assert_eq!(fresh.routes, Routes::default());
        assert!(!fresh.http_allow_direct);
    }

    #[test]
    fn cap_does_not_bury_untested() {
        let now = 100 * 86400;
        let mut all = Vec::new();
        for i in 0..(MAX_FREE + 10) {
            let mut s = Server::new(&format!("u{i}"), serde_json::from_value(serde_json::json!({"type":"trojan","server":format!("10.0.{}.{}", i / 250, i % 250),"port":443,"password":"x"})).unwrap(), Origin::Free, "t").unwrap();
            s.added = now;
            all.push(s);
        }
        let p = prune_ex(&mut all, now);
        assert_eq!(all.len(), MAX_FREE);
        assert_eq!(p.dropped.len(), 10);
        assert!(p.dead.is_empty() && p.trimmed.is_empty());
        let mut g = Grave::new();
        bury_for(&mut g, &["a".to_string()], now, TRIM_TTL);
        let t = g["a"];
        assert!(now - t < GRAVE_TTL && now + TRIM_TTL - t >= GRAVE_TTL);
    }
}
