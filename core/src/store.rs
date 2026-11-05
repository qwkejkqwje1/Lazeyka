//! Persistent state: settings, known servers, WARP account, source statistics.

use crate::model::{Origin, Server};
use crate::scan::SourceStat;
use crate::sources::SourceDef;
use crate::routes::Routes;
use crate::split::Split;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::collections::HashMap;
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
    pub fn grave(&self) -> PathBuf {
        self.data.join("graveyard.json")
    }
    pub fn stats(&self) -> PathBuf {
        self.data.join("sources.json")
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
        match self.split.take() {
            Some(sp) if self.routes == Routes::default() => {
                self.routes = Routes::from_split(&sp);
                true
            }
            Some(_) => true,
            None => false,
        }
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

pub type Stats = HashMap<String, SourceStat>;

/// Ids of removed dead servers → when they were buried. Sources keep listing the same
/// corpses; the graveyard stops them from coming back (and being re-tested) for a while.
pub type Grave = HashMap<String, u64>;

/// A server that has not worked for this long (and keeps failing) is removed.
pub const DEAD_AFTER: u64 = 14 * 86400;
/// Never-working servers get a shorter leash.
pub const NEVER_AFTER: u64 = 7 * 86400;
/// How long a buried server is refused when a source lists it again.
pub const GRAVE_TTL: u64 = 21 * 86400;
const GRAVE_MAX: usize = 40_000;

/// Dead for weeks: it failed at least three checks in a row and has not worked within
/// the period (or never worked since it was added a week ago). Untested ones are only
/// judged by age. Favourites, own servers and WARP are never dead.
pub fn is_dead(s: &Server, now: u64) -> bool {
    if s.origin != Origin::Free || s.fav {
        return false;
    }
    if s.probe.is_none() {
        return now.saturating_sub(s.added) > DEAD_AFTER;
    }
    if s.fails < 3 || s.good() {
        return false;
    }
    if s.last_ok > 0 {
        now.saturating_sub(s.last_ok) > DEAD_AFTER
    } else {
        now.saturating_sub(s.added) > NEVER_AFTER
    }
}

/// Drops free servers that are dead for weeks or stale (not seen working for a week and
/// not checked for three days). Favourites are kept. Returns the removed ids.
pub fn prune(servers: &mut Vec<Server>, now: u64) -> Vec<String> {
    let mut gone = Vec::new();
    servers.retain(|s| {
        if s.origin != Origin::Free || s.fav {
            return true;
        }
        let checked = s.probe.as_ref().map(|p| p.at).unwrap_or(s.added);
        let fresh = now.saturating_sub(checked) < 3 * 86400;
        let worked = now.saturating_sub(s.last_ok) < 7 * 86400;
        let keep = (fresh || worked) && !is_dead(s, now);
        if !keep {
            gone.push(s.id.clone());
        }
        keep
    });
    gone
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
        // worked 3 days ago: only flapping
        let flaky = free(5, now - 3 * day, now - 60 * day, Some(now - 1000));
        // never worked, added 10 days ago
        let never = free(6, 0, now - 10 * day, Some(now - 1000));
        // never worked but added yesterday
        let newcomer = free(2, 0, now - day, Some(now - 1000));
        // untested for a month
        let forgotten = free(0, 0, now - 30 * day, None);
        let mut fav = free(9, 0, now - 90 * day, Some(now - 1000));
        fav.fav = true;
        assert!(is_dead(&corpse, now) && is_dead(&never, now) && is_dead(&forgotten, now));
        assert!(!is_dead(&flaky, now) && !is_dead(&newcomer, now) && !is_dead(&fav, now));
        let mut all = vec![corpse, flaky, never, newcomer, forgotten, fav];
        for (i, x) in all.iter_mut().enumerate() {
            x.id = format!("s{i}");
        }
        let gone = prune(&mut all, now);
        assert_eq!(gone, ["s0", "s2", "s4"]);
        assert_eq!(all.iter().map(|x| x.id.as_str()).collect::<Vec<_>>(), ["s1", "s3", "s5"]);
        let mut g = Grave::new();
        bury(&mut g, &gone, now);
        assert_eq!(g.len(), 3);
        // old graves expire
        bury(&mut g, &[], now + GRAVE_TTL + 1);
        assert!(g.is_empty());
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
    }
}
