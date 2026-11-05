//! Persistent state: settings, known servers, WARP account, source statistics.

use crate::model::Server;
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

/// Drops free servers that are stale (not seen working for 3 days and not recently checked).
/// Favourites are kept.
pub fn prune(servers: &mut Vec<Server>, now: u64) {
    servers.retain(|s| {
        if s.origin != crate::model::Origin::Free || s.fav {
            return true;
        }
        let checked = s.probe.as_ref().map(|p| p.at).unwrap_or(s.added);
        let fresh = now.saturating_sub(checked) < 3 * 86400;
        let worked = now.saturating_sub(s.last_ok) < 7 * 86400;
        fresh || worked
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::Target;

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
