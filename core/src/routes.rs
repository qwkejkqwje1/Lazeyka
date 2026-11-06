//! Routes: the user's rules for chosen sites and programs — directly, through the VPN,
//! through servers of one country, one server or WARP, or blocked. Checked top to
//! bottom, the first match wins; everything else follows the default (VPN or direct).

use crate::split::{Split, SplitMode};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub const MAX_ROUTES: usize = 30;
pub const MAX_LISTS: usize = 50;
pub const MAX_CHAINS: usize = 20;
pub const MAX_HOPS: usize = 3;
pub const MAX_NAME: usize = 40;

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum Target {
    Direct,
    #[default]
    Vpn,
    Warp,
    /// Working servers exiting in this country (ISO code), best first.
    Country(String),
    /// One server (id).
    Server(String),
    Block,
    /// A named chain of hops (id in [`Routes::chains`]).
    Chain(String),
}

impl Target {
    pub fn parse(s: &str) -> Result<Target, String> {
        let s = s.trim();
        Ok(match s {
            "direct" => Target::Direct,
            "vpn" => Target::Vpn,
            "warp" => Target::Warp,
            "block" => Target::Block,
            _ => {
                if let Some(cc) = s.strip_prefix("country:") {
                    let cc = cc.trim().to_ascii_uppercase();
                    if cc.len() != 2 || !cc.bytes().all(|b| b.is_ascii_alphabetic()) {
                        return Err("некорректный код страны".into());
                    }
                    Target::Country(cc)
                } else if let Some(id) = s.strip_prefix("server:") {
                    let id = id.trim();
                    if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                        return Err("некорректный сервер".into());
                    }
                    Target::Server(id.to_string())
                } else if let Some(id) = s.strip_prefix("chain:") {
                    let id = id.trim();
                    if id.is_empty() || id.len() > 128 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
                        return Err("некорректная цепочка".into());
                    }
                    Target::Chain(id.to_string())
                } else {
                    return Err("неизвестное направление".into());
                }
            }
        })
    }

    pub fn code(&self) -> String {
        match self {
            Target::Direct => "direct".into(),
            Target::Vpn => "vpn".into(),
            Target::Warp => "warp".into(),
            Target::Block => "block".into(),
            Target::Country(cc) => format!("country:{cc}"),
            Target::Server(id) => format!("server:{id}"),
            Target::Chain(id) => format!("chain:{id}"),
        }
    }

    /// Goes through a set of servers of its own (with the VPN as a spare).
    pub fn uses_servers(&self) -> bool {
        matches!(self, Target::Warp | Target::Country(_) | Target::Server(_) | Target::Chain(_))
    }
}

/// What a route does when none of its own servers works (no server in the country yet,
/// all of them down). Free servers come and go, so this is a real decision:
/// `Fastest` — the best working VPN server right now (the default, never leaks);
/// `Warp` — Cloudflare WARP first, then the fastest VPN (keeps access to blocked sites
/// open while the search for the right country goes on — the exit country differs);
/// `Direct` — straight out; `Block` — nothing leaves (strict geo-rules).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Fallback {
    #[default]
    Fastest,
    Warp,
    Direct,
    Block,
}

impl Fallback {
    pub fn code(self) -> &'static str {
        match self {
            Fallback::Fastest => "fastest",
            Fallback::Warp => "warp",
            Fallback::Direct => "direct",
            Fallback::Block => "block",
        }
    }
    pub fn parse(s: &str) -> Result<Fallback, String> {
        Ok(match s.trim() {
            "fastest" | "vpn" => Fallback::Fastest,
            "warp" => Fallback::Warp,
            "direct" => Fallback::Direct,
            "block" => Fallback::Block,
            _ => return Err("неизвестный запасной вариант".into()),
        })
    }
}

impl Serialize for Fallback {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.code())
    }
}

impl<'de> Deserialize<'de> for Fallback {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Fallback::parse(&s).unwrap_or_default())
    }
}

/// How a country route picks among its servers: `Failover` keeps the first working one
/// (stable exit, the default), `Fastest` follows the lowest latency, `Balance` spreads
/// connections over all of them (one site keeps one server).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Strategy {
    #[default]
    Failover,
    Fastest,
    Balance,
}

impl Strategy {
    pub fn code(self) -> &'static str {
        match self {
            Strategy::Failover => "failover",
            Strategy::Fastest => "fastest",
            Strategy::Balance => "balance",
        }
    }
    pub fn parse(s: &str) -> Result<Strategy, String> {
        Ok(match s.trim() {
            "failover" | "fallback" => Strategy::Failover,
            "fastest" | "url-test" => Strategy::Fastest,
            "balance" | "load-balance" => Strategy::Balance,
            _ => return Err("неизвестная стратегия".into()),
        })
    }
}

impl Serialize for Strategy {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.code())
    }
}

impl<'de> Deserialize<'de> for Strategy {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Strategy::parse(&s).unwrap_or_default())
    }
}

/// One hop of a chain. Traffic enters the first hop and leaves through the last
/// one, so the exit country of a chain is the country of its last hop.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hop {
    /// The VPN as it is on the main screen (the pool pick or the chosen server).
    Auto,
    /// Working servers exiting in this country (ISO code), best first.
    Country(String),
    /// One server (id).
    Server(String),
    /// Cloudflare WARP — usually the last hop: "VPN → WARP" exits with a clean
    /// Cloudflare address and gets through where WARP itself is blocked.
    Warp,
}

impl Hop {
    /// Same mini-language as [`Target`], minus the terminal kinds.
    pub fn parse(s: &str) -> Result<Hop, String> {
        match Target::parse(s)? {
            Target::Vpn => Ok(Hop::Auto),
            Target::Country(cc) => Ok(Hop::Country(cc)),
            Target::Server(id) => Ok(Hop::Server(id)),
            Target::Warp => Ok(Hop::Warp),
            _ => Err("звено цепочки — сервер, страна, WARP или VPN".into()),
        }
    }

    pub fn code(&self) -> String {
        match self {
            Hop::Auto => "vpn".into(),
            Hop::Country(cc) => format!("country:{cc}"),
            Hop::Server(id) => format!("server:{id}"),
            Hop::Warp => "warp".into(),
        }
    }
}

impl Serialize for Hop {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.code())
    }
}

impl<'de> Deserialize<'de> for Hop {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Ok(Hop::parse(&s).unwrap_or(Hop::Auto))
    }
}

/// A named, reusable chain of 1–[`MAX_HOPS`] hops. Routes and the default target
/// reference a chain by id (`chain:<id>`); the same chain can carry one route or
/// all the traffic that goes through the VPN.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Chain {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub hops: Vec<Hop>,
}

impl Chain {
    pub fn new(name: &str, hops: Vec<Hop>) -> Chain {
        Chain { id: new_id(), name: clean_name(name), hops }
    }

    /// A chain the engine can build: 1–3 hops, not just the VPN itself (that is
    /// simply the VPN), and no two neighbouring hops alike (a hop through itself
    /// is a loop).
    pub fn validate(&self) -> Result<(), String> {
        if self.hops.is_empty() || self.hops.len() > MAX_HOPS {
            return Err(format!("В цепочке от 1 до {MAX_HOPS} звеньев"));
        }
        if self.hops.iter().all(|h| *h == Hop::Auto) {
            return Err("Цепочка только из VPN — это просто VPN".into());
        }
        if self.hops.windows(2).any(|w| w[0] == w[1]) {
            return Err("Соседние звенья цепочки совпадают — получится петля".into());
        }
        Ok(())
    }
}

impl Serialize for Target {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.code())
    }
}

impl<'de> Deserialize<'de> for Target {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        // lenient: a broken value must not make the whole settings file unreadable,
        // while Route::validate_raw surfaces any unknown target string in diagnostics.
        let s = String::deserialize(d)?;
        Ok(Target::parse(&s).unwrap_or(Target::Vpn))
    }
}

fn yes() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Route {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default)]
    pub target: Target,
    /// What happens when the target's own servers are not available.
    #[serde(default)]
    pub fallback: Fallback,
    /// How the servers of a country are chosen (country targets only).
    #[serde(default)]
    pub strategy: Strategy,
    /// Domains (with subdomains), IPs and CIDRs, normalized by `split::normalize_site`.
    #[serde(default)]
    pub sites: Vec<String>,
    /// Executable names, normalized by `split::normalize_app`.
    #[serde(default)]
    pub apps: Vec<String>,
    /// Attached named lists ([`EntryList`] ids): their entries join the route's own.
    #[serde(default)]
    pub lists: Vec<String>,
}

impl Route {
    pub fn new(name: &str, target: Target) -> Route {
        Route { id: new_id(), name: clean_name(name), enabled: true, target, fallback: Fallback::default(), strategy: Strategy::default(), sites: vec![], apps: vec![], lists: vec![] }
    }
    pub fn list_mut(&mut self, apps: bool) -> &mut Vec<String> {
        if apps { &mut self.apps } else { &mut self.sites }
    }
    pub fn list(&self, apps: bool) -> &Vec<String> {
        if apps { &self.apps } else { &self.sites }
    }
    pub fn entries(&self) -> usize {
        self.sites.len() + self.apps.len()
    }
}

/// A named list of sites and programs — a folder the user keeps once and attaches
/// to any number of routes. Editing the list updates every route that uses it.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EntryList {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub sites: Vec<String>,
    #[serde(default)]
    pub apps: Vec<String>,
    /// The list's own direction: with one set, the list routes by itself (as a
    /// unit after the routes) without being attached anywhere.
    #[serde(default)]
    pub target: Option<Target>,
    #[serde(default)]
    pub fallback: Fallback,
    #[serde(default)]
    pub strategy: Strategy,
}

impl EntryList {
    pub fn new(name: &str) -> EntryList {
        EntryList { id: new_id(), name: clean_name(name), sites: vec![], apps: vec![], target: None, fallback: Fallback::default(), strategy: Strategy::default() }
    }
    pub fn list_mut(&mut self, apps: bool) -> &mut Vec<String> {
        if apps { &mut self.apps } else { &mut self.sites }
    }
    pub fn list(&self, apps: bool) -> &Vec<String> {
        if apps { &self.apps } else { &self.sites }
    }
    pub fn entries(&self) -> usize {
        self.sites.len() + self.apps.len()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct Routes {
    /// Everything not matched by a route: `Vpn` or `Direct`.
    #[serde(default)]
    pub default: Target,
    #[serde(default)]
    pub list: Vec<Route>,
    /// Named reusable chains; routes and the default target point at them by id.
    #[serde(default)]
    pub chains: Vec<Chain>,
    /// Named entry lists ("folders"); routes attach them by id.
    #[serde(default)]
    pub lists: Vec<EntryList>,
}

impl Routes {
    /// The 0.1–0.2 split tunneling settings as routes: the active list becomes an enabled
    /// route, the other mode's list is kept as a disabled one.
    pub fn from_split(sp: &Split) -> Routes {
        let mut r = Routes { default: if sp.mode == SplitMode::Include { Target::Direct } else { Target::Vpn }, list: vec![], chains: vec![], lists: vec![] };
        let mut add = |name: &str, target: Target, enabled: bool, l: &crate::split::SplitList| {
            if l.sites.is_empty() && l.apps.is_empty() {
                return;
            }
            let mut x = Route::new(name, target);
            x.enabled = enabled;
            x.sites = l.sites.clone();
            x.apps = l.apps.clone();
            r.list.push(x);
        };
        let ex = sp.mode == SplitMode::Exclude;
        add("Напрямую", Target::Direct, ex, &sp.exclude);
        add("Через VPN", Target::Vpn, !ex, &sp.include);
        r
    }

    /// Lists that carried their own direction (0.5–0.6) become ordinary routes with
    /// the list attached: one place decides where traffic goes, lists are just folders.
    /// The new routes go last, where the lists used to route. True when anything moved.
    pub fn lists_to_routes(&mut self) -> bool {
        let mut changed = false;
        for l in self.lists.iter_mut() {
            let Some(t) = l.target.take() else { continue };
            changed = true;
            if self.list.len() >= MAX_ROUTES {
                continue;
            }
            let mut r = Route::new(&l.name, t);
            if r.name.is_empty() {
                r.name = "Список".into();
            }
            r.fallback = l.fallback;
            r.strategy = l.strategy;
            r.lists = vec![l.id.clone()];
            self.list.push(r);
        }
        changed
    }

    pub fn chain(&self, id: &str) -> Option<&Chain> {
        self.chains.iter().find(|c| c.id == id)
    }
    pub fn chain_mut(&mut self, id: &str) -> Option<&mut Chain> {
        self.chains.iter_mut().find(|c| c.id == id)
    }

    pub fn entry_list(&self, id: &str) -> Option<&EntryList> {
        self.lists.iter().find(|l| l.id == id)
    }
    pub fn entry_list_mut(&mut self, id: &str) -> Option<&mut EntryList> {
        self.lists.iter_mut().find(|l| l.id == id)
    }

    /// Entries a route actually routes with: its own first, then the attached
    /// lists' (a missing list is skipped, duplicates collapse).
    pub fn eff_list(&self, r: &Route, apps: bool) -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        for v in r.list(apps) {
            if !out.contains(v) {
                out.push(v.clone());
            }
        }
        for id in &r.lists {
            if let Some(l) = self.entry_list(id) {
                for v in l.list(apps) {
                    if !out.contains(v) {
                        out.push(v.clone());
                    }
                }
            }
        }
        out
    }

    /// Effective entry count of a route (own + attached lists).
    pub fn eff_entries(&self, r: &Route) -> usize {
        self.eff_list(r, false).len() + self.eff_list(r, true).len()
    }

    pub fn get(&self, id: &str) -> Option<&Route> {
        self.list.iter().find(|r| r.id == id)
    }
    pub fn get_mut(&mut self, id: &str) -> Option<&mut Route> {
        self.list.iter_mut().find(|r| r.id == id)
    }

    /// Adds an entry to a route, taking it out of the others (one site goes one way).
    /// Returns the names of the routes it was moved from.
    pub fn add_entry(&mut self, id: &str, apps: bool, value: &str) -> Result<Vec<String>, String> {
        if self.get(id).is_none() {
            return Err("маршрут не найден".into());
        }
        let mut moved = vec![];
        for r in self.list.iter_mut() {
            if r.id == id {
                let l = r.list_mut(apps);
                if !l.iter().any(|x| x == value) {
                    l.push(value.to_string());
                }
            } else {
                let l = r.list_mut(apps);
                let n = l.len();
                l.retain(|x| x != value);
                if l.len() != n {
                    moved.push(r.name.clone());
                }
            }
        }
        Ok(moved)
    }

    /// Routes that take part in routing: enabled and not empty (own entries or
    /// attached lists), in order.
    pub fn active(&self) -> impl Iterator<Item = &Route> {
        self.list.iter().filter(|r| r.enabled && safe_id(&r.id) && self.eff_entries(r) > 0)
    }

    /// Ids of routing units whose effective lists changed between two states
    /// (hot-reloadable): an entry edit, an attach/detach, or an edit of an
    /// attached or self-routing list all show up here.
    pub fn changed_lists(&self, before: &Routes) -> Vec<String> {
        let prev = before.units();
        self.units()
            .into_iter()
            .filter(|u| {
                prev.iter().find(|b| b.id == u.id).is_none_or(|b| {
                    self.eff_list(u, false) != before.eff_list(b, false) || self.eff_list(u, true) != before.eff_list(b, true)
                })
            })
            .map(|u| u.id)
            .collect()
    }

    /// Everything that needs a new mihomo configuration (not just new rule lists).
    /// Routing unit id of a self-routing list: "l" + the list's id (lowercase,
    /// so it passes `safe_id`; route ids are 8 chars, unit ids 9 — no collisions).
    pub fn unit_id(list_id: &str) -> String {
        format!("l{list_id}")
    }

    /// Everything that routes, in precedence order: the active routes first,
    /// then the lists carrying their own target (materialized as routes whose
    /// entries are the list's own). Only non-empty units come back.
    pub fn units(&self) -> Vec<Route> {
        let mut out: Vec<Route> = self.active().cloned().collect();
        for l in self.lists.iter() {
            if let Some(t) = &l.target {
                if l.entries() > 0 {
                    out.push(Route { id: Self::unit_id(&l.id), name: l.name.clone(), enabled: true, target: t.clone(), fallback: l.fallback, strategy: l.strategy, sites: l.sites.clone(), apps: l.apps.clone(), lists: vec![] });
                }
            }
        }
        out
    }

    pub fn shape(&self) -> Vec<(String, Target)> {
        let mut v: Vec<(String, Target)> = vec![(String::new(), self.default.clone())];
        for r in self.units() {
            // the fallback policy is part of the configuration; the default adds nothing
            if r.fallback != Fallback::Fastest {
                v.push((format!("fb:{}", r.id), Target::Chain(r.fallback.code().into())));
            }
            if r.strategy != Strategy::Failover {
                v.push((format!("st:{}", r.id), Target::Chain(r.strategy.code().into())));
            }
            v.push((r.id, r.target));
        }
        // a chain's hops are part of the configuration even though routes only
        // name the chain: the hop codes ride in the Chain payload as a fingerprint
        v.extend(self.chains.iter().map(|c| {
            let hops = c.hops.iter().map(|h| h.code()).collect::<Vec<_>>().join("+");
            (format!("chain:{}", c.id), Target::Chain(hops))
        }));
        v
    }
}

pub fn new_id() -> String {
    crate::util::random_token(8).to_ascii_lowercase()
}

pub fn clean_name(s: &str) -> String {
    let t: String = s.chars().filter(|c| !c.is_control()).collect();
    let t = t.trim();
    if t.chars().count() > MAX_NAME { t.chars().take(MAX_NAME).collect::<String>().trim_end().to_string() } else { t.to_string() }
}

/// Valid rule-provider / group name part (ids are generated, but settings can be edited).
pub fn safe_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::split::SplitList;

    #[test]
    fn targets() {
        for t in [Target::Direct, Target::Vpn, Target::Warp, Target::Block, Target::Country("DE".into()), Target::Server("abc123".into()), Target::Chain("c1".into())] {
            assert_eq!(Target::parse(&t.code()).unwrap(), t);
        }
        assert_eq!(Target::parse("country:de").unwrap(), Target::Country("DE".into()));
        assert!(Target::parse("country:DEU").is_err());
        assert!(Target::parse("server:a/b").is_err());
        assert!(Target::parse("chain:a/b").is_err());
        assert!(Target::parse("x").is_err());
        for h in [Hop::Auto, Hop::Country("NL".into()), Hop::Server("s1".into())] {
            assert_eq!(Hop::parse(&h.code()).unwrap(), h);
        }
        assert!(Hop::parse("direct").is_err());
        assert_eq!(Hop::parse("warp").unwrap(), Hop::Warp);
        let r: Route = serde_json::from_str(r#"{"id":"a1","target":"bogus"}"#).unwrap();
        assert_eq!(r.target, Target::Vpn);
        assert!(r.enabled);
    }

    #[test]
    fn migrate() {
        let sp = Split {
            mode: SplitMode::Include,
            exclude: SplitList { sites: vec!["a.ru".into()], apps: vec![] },
            include: SplitList { sites: vec!["youtube.com".into()], apps: vec!["chrome.exe".into()] },
        };
        let r = Routes::from_split(&sp);
        assert_eq!(r.default, Target::Direct);
        assert_eq!(r.list.len(), 2);
        assert!(!r.list[0].enabled && r.list[0].target == Target::Direct && r.list[0].sites == ["a.ru"]);
        assert!(r.list[1].enabled && r.list[1].target == Target::Vpn && r.list[1].apps == ["chrome.exe"]);
        assert!(r.list.iter().all(|x| safe_id(&x.id)));
        let empty = Routes::from_split(&Split::default());
        assert_eq!(empty, Routes { default: Target::Vpn, list: vec![], chains: vec![], lists: vec![] });
    }

    #[test]
    fn chains_validate_and_shape() {
        let mut r = Routes::default();
        let mut c = Chain::new("Двойка", vec![Hop::Auto, Hop::Country("NL".into())]);
        assert!(c.validate().is_ok());
        assert!(Chain::new("x", vec![]).validate().is_err());
        assert!(Chain::new("x", vec![Hop::Auto]).validate().is_err());
        assert!(Chain::new("x", vec![Hop::Server("a".into()), Hop::Server("a".into())]).validate().is_err());
        assert!(Chain::new("x", vec![Hop::Auto, Hop::Auto, Hop::Server("a".into()), Hop::Server("b".into())]).validate().is_err());
        let cid = c.id.clone();
        r.chains.push(c.clone());
        let s1 = r.shape();
        // changing the hops changes the configuration shape even though the id stays
        r.chain_mut(&cid).unwrap().hops = vec![Hop::Server("s9".into()), Hop::Country("NL".into())];
        assert_ne!(r.shape(), s1);
        // a saved chain survives a settings round trip
        let j = serde_json::to_string(&r).unwrap();
        let back: Routes = serde_json::from_str(&j).unwrap();
        assert_eq!(back.chain(&cid).unwrap().hops.len(), 2);
        c.hops = vec![Hop::Auto, Hop::Country("NL".into())];
        assert_eq!(Target::parse(&Target::Chain(cid.clone()).code()).unwrap(), Target::Chain(cid));
    }

    #[test]
    fn folders_feed_routes() {
        let mut r = Routes::default();
        let mut bank = EntryList::new("Банки");
        bank.sites = vec!["bank.ru".into(), "shared.com".into()];
        bank.apps = vec!["bank.exe".into()];
        let bid = bank.id.clone();
        r.lists.push(bank);
        let mut a = Route::new("A", Target::Direct);
        a.sites.push("shared.com".into());
        a.lists.push(bid.clone());
        let aid = a.id.clone();
        r.list.push(a);
        // union, own first, duplicates collapse
        let a = r.get(&aid).unwrap();
        assert_eq!(r.eff_list(a, false), ["shared.com", "bank.ru"]);
        assert_eq!(r.eff_list(a, true), ["bank.exe"]);
        assert_eq!(r.eff_entries(a), 3);
        // a route fed only by a folder is active
        let mut b = Route::new("B", Target::Vpn);
        b.lists.push(bid.clone());
        let bid2 = b.id.clone();
        r.list.push(b);
        assert_eq!(r.active().count(), 2);
        // editing the folder is a list change for every route using it
        let before = r.clone();
        r.entry_list_mut(&bid).unwrap().sites.push("newbank.ru".into());
        assert_eq!(r.changed_lists(&before), [aid.clone(), bid2.clone()]);
        // a dangling attachment is skipped, not fatal
        r.lists.clear();
        let a = r.get(&aid).unwrap();
        assert_eq!(r.eff_list(a, false), ["shared.com"]);
        // old settings without the new fields still load
        let old: Routes = serde_json::from_str(r#"{"list":[{"id":"x1","target":"vpn","sites":["a.com"]}]}"#).unwrap();
        assert_eq!(old.list[0].lists.len(), 0);
        assert_eq!(old.lists.len(), 0);
    }

    #[test]
    fn list_with_target_routes_by_itself() {
        let mut r = Routes::default();
        let mut ai = EntryList::new("ИИ");
        ai.sites = vec!["chat.example.com".into()];
        ai.target = Some(Target::Country("US".into()));
        let aid = ai.id.clone();
        r.lists.push(ai);
        // no target or empty -> not a unit; with a target and entries -> a unit after the routes
        let mut plain = EntryList::new("Обычный");
        plain.sites = vec!["plain.example".into()];
        r.lists.push(plain);
        let mut route = Route::new("Маршрут", Target::Vpn);
        route.sites.push("r.example".into());
        r.list.push(route);
        let units = r.units();
        assert_eq!(units.len(), 2);
        assert_eq!(units[1].id, Routes::unit_id(&aid));
        assert_eq!(units[1].target, Target::Country("US".into()));
        assert_eq!(units[1].sites, ["chat.example.com"]);
        // the unit is part of the shape: setting or clearing the target reloads
        let before = r.clone();
        assert!(r.shape() != Routes::default().shape());
        // an entry edit inside a self-routing list is a hot-reloadable change
        r.entry_list_mut(&aid).unwrap().sites.push("more.example.com".into());
        assert_eq!(r.changed_lists(&before), [Routes::unit_id(&aid)]);
        // old settings without a target still load, target-less
        let old: Routes = serde_json::from_str(r#"{"lists":[{"id":"l1","name":"X","sites":["a.com"]}]}"#).unwrap();
        assert_eq!(old.lists[0].target, None);
        assert!(old.units().is_empty());
    }

    #[test]
    fn strategy_policy() {
        assert_eq!(Strategy::parse("url-test").unwrap(), Strategy::Fastest);
        assert!(Strategy::parse("x").is_err());
        let old: Route = serde_json::from_str(r#"{"id":"a1"}"#).unwrap();
        assert_eq!(old.strategy, Strategy::Failover);
        let mut r = Routes::default();
        let mut rt = Route::new("DE", Target::Country("DE".into()));
        rt.sites.push("a.com".into());
        let id = rt.id.clone();
        r.list.push(rt);
        let s1 = r.shape();
        r.get_mut(&id).unwrap().strategy = Strategy::Balance;
        assert_ne!(r.shape(), s1, "a new strategy needs a new configuration");
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains(r#""strategy":"balance""#));
        assert_eq!(serde_json::from_str::<Routes>(&j).unwrap().get(&id).unwrap().strategy, Strategy::Balance);
    }

    #[test]
    fn fallback_policy() {
        assert_eq!(Fallback::parse("warp").unwrap(), Fallback::Warp);
        assert!(Fallback::parse("x").is_err());
        let old: Route = serde_json::from_str(r#"{"id":"a1","target":"country:US"}"#).unwrap();
        assert_eq!(old.fallback, Fallback::Fastest);
        let bad: Route = serde_json::from_str(r#"{"id":"a1","fallback":"bogus"}"#).unwrap();
        assert_eq!(bad.fallback, Fallback::Fastest);
        let mut r = Routes::default();
        let mut x = Route::new("X", Target::Country("US".into()));
        x.sites.push("a.com".into());
        let id = x.id.clone();
        r.list.push(x);
        let s1 = r.shape();
        r.get_mut(&id).unwrap().fallback = Fallback::Warp;
        assert_ne!(r.shape(), s1, "a new fallback needs a new configuration");
        let j = serde_json::to_string(&r).unwrap();
        assert!(j.contains(r#""fallback":"warp""#));
        let back: Routes = serde_json::from_str(&j).unwrap();
        assert_eq!(back.get(&id).unwrap().fallback, Fallback::Warp);
    }

    #[test]
    fn entries_move() {
        let mut r = Routes::default();
        let mut a = Route::new("A", Target::Direct);
        a.sites.push("x.com".into());
        let b = Route::new("B", Target::Vpn);
        let (ia, ib) = (a.id.clone(), b.id.clone());
        r.list = vec![a, b];
        let before = r.clone();
        let moved = r.add_entry(&ib, false, "x.com").unwrap();
        assert_eq!(moved, vec!["A".to_string()]);
        assert!(r.get(&ia).unwrap().sites.is_empty());
        assert_eq!(r.get(&ib).unwrap().sites, ["x.com"]);
        // A became empty (inactive), B got its first entry: a new configuration is needed
        assert_eq!(r.changed_lists(&before), vec![ib.clone()]);
        assert_ne!(r.shape(), before.shape());
        let before2 = r.clone();
        r.add_entry(&ib, false, "y.com").unwrap();
        assert_eq!(r.shape(), before2.shape());
        assert_eq!(r.changed_lists(&before2), vec![ib.clone()]);
        assert!(r.add_entry("nope", false, "y.com").is_err());
        assert_eq!(clean_name("  Очень длинное название маршрута, которое не помещается никуда  ").chars().count(), MAX_NAME);
    }

    #[test]
    fn list_directions_become_routes() {
        let mut r = Routes::default();
        let mut l = EntryList::new("Игры");
        l.sites = vec!["steampowered.com".into()];
        l.target = Some(Target::Direct);
        let id = l.id.clone();
        r.lists.push(l);
        r.lists.push(EntryList::new("Без направления"));
        assert!(r.lists_to_routes());
        assert_eq!(r.list.len(), 1);
        assert_eq!(r.list[0].target, Target::Direct);
        assert_eq!(r.list[0].lists, vec![id]);
        assert!(r.lists.iter().all(|l| l.target.is_none()));
        assert_eq!(r.eff_entries(&r.list[0]), 1);
        assert!(!r.lists_to_routes());
    }
}
