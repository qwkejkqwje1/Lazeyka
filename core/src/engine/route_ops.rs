//! Routes inside the engine: requests, the plan given to mihomo, in-place reloads and the
//! watch over route servers.

use super::*;
use crate::routes::{self, Chain, EntryList, Fallback, Hop, Route, MAX_CHAINS, MAX_LISTS, MAX_ROUTES};
use crate::{countries, smart, split};

/// Servers of a country route (distinct hosts, best first).
const COUNTRY_SERVERS: usize = 5;
const WARP_SERVERS: usize = 3;

fn label(st: &State, t: &Target) -> String {
    match t {
        Target::Direct => "Напрямую".into(),
        Target::Vpn => "Через VPN".into(),
        Target::Warp => "Через WARP".into(),
        Target::Block => "Блокировать".into(),
        Target::Country(cc) => format!("Через страну: {}", countries::name(cc).map(str::to_string).unwrap_or_else(|| cc.clone())),
        Target::Server(id) => match st.servers.iter().find(|s| &s.id == id) {
            Some(s) => format!("Через сервер: {}", view(s, false).name),
            None => "Через сервер (удалён)".into(),
        },
        Target::Chain(id) => match st.settings.routes.chain(id) {
            Some(c) => format!("Через цепочку: {}", c.name),
            None => "Через цепочку (удалена)".into(),
        },
    }
}

fn hop_label(st: &State, h: &Hop) -> String {
    match h {
        Hop::Auto => "VPN".into(),
        Hop::Country(cc) => countries::name(cc).map(str::to_string).unwrap_or_else(|| cc.clone()),
        Hop::Server(id) => match st.servers.iter().find(|s| &s.id == id) {
            Some(s) => view(s, false).name,
            None => "удалён".into(),
        },
    }
}

impl Engine {
    /// Servers a route target goes through, best first; empty = the VPN instead.
    fn route_servers(st: &State, t: &Target) -> Vec<Server> {
        let class = |s: &Server| if s.fav { 0 } else if s.origin == Origin::Mine { 1 } else { 2 };
        match t {
            Target::Server(id) => st.servers.iter().filter(|s| &s.id == id).cloned().collect(),
            Target::Country(cc) => {
                let mut v: Vec<&Server> = st.servers.iter().filter(|s| s.good() && s.country() == Some(cc.as_str()) && scan::relay_ok(&st.servers, s)).collect();
                v.sort_by_key(|s| (class(s), scan::score(s)));
                let mut hosts = HashSet::new();
                v.into_iter().filter(|s| hosts.insert(s.host.clone())).take(COUNTRY_SERVERS).cloned().collect()
            }
            Target::Warp => {
                let mut v: Vec<&Server> = st.servers.iter().filter(|s| s.origin == Origin::Warp && s.good()).collect();
                if v.is_empty() {
                    // not checked yet: the route group finds out itself, the VPN is the spare
                    v = st.servers.iter().filter(|s| s.origin == Origin::Warp && s.probe.is_none()).collect();
                }
                v.sort_by_key(|s| scan::score(s));
                v.into_iter().take(WARP_SERVERS).cloned().collect()
            }
            Target::Chain(id) => {
                let Some(c) = st.settings.routes.chain(id) else { return vec![] };
                let mut out: Vec<Server> = Vec::new();
                for h in &c.hops {
                    for s in Self::hop_servers(st, h) {
                        if !out.iter().any(|x| x.id == s.id) {
                            out.push(s);
                        }
                    }
                }
                out
            }
            _ => vec![],
        }
    }

    /// Servers of one chain hop, best first (the VPN hop has none of its own).
    fn hop_servers(st: &State, h: &Hop) -> Vec<Server> {
        match h {
            Hop::Auto => vec![],
            Hop::Country(cc) => Self::route_servers(st, &Target::Country(cc.clone())),
            Hop::Server(id) => Self::route_servers(st, &Target::Server(id.clone())),
        }
    }

    /// Compiles a chain into per-level proxy copies for the config. `None` when
    /// some hop has no server left to go through (a server already used by an
    /// earlier hop cannot serve again — a chain through itself is a loop); the
    /// caller then falls back to the VPN, never to a direct connection.
    fn chain_plan(st: &State, chain: &Chain) -> Option<mihomo::ChainPlan> {
        let mut used: HashSet<String> = HashSet::new();
        let mut levels: Vec<Vec<Value>> = Vec::new();
        for (i, h) in chain.hops.iter().enumerate() {
            match h {
                Hop::Auto => levels.push(vec![]),
                _ => {
                    let cands: Vec<Server> = Self::hop_servers(st, h).into_iter().filter(|s| used.insert(s.id.clone())).collect();
                    if cands.is_empty() {
                        return None;
                    }
                    levels.push(
                        cands
                            .iter()
                            .map(|s| {
                                let mut p = s.mihomo_proxy();
                                p["name"] = Value::from(format!("{}~{}-{}", s.id, chain.id, i + 1));
                                p
                            })
                            .collect(),
                    );
                }
            }
        }
        if levels.iter().all(|l| l.is_empty()) {
            return None;
        }
        Some(mihomo::ChainPlan { id: chain.id.clone(), levels })
    }

    /// What mihomo gets for the active routes, the route servers missing from
    /// `pool`, the compiled chains and the default chain (when the default target
    /// is a chain that could be built; otherwise the plain VPN carries it).
    pub(super) fn route_plans(&self, pool: &[Server]) -> (Vec<RoutePlan>, Vec<Server>, Vec<mihomo::ChainPlan>, Option<String>) {
        let st = self.st.lock().unwrap();
        let mut plans = Vec::new();
        let mut extra: Vec<Server> = Vec::new();
        let mut chains: Vec<mihomo::ChainPlan> = Vec::new();
        let add_chain = |chains: &mut Vec<mihomo::ChainPlan>, cid: &str| -> bool {
            let Some(p) = st.settings.routes.chain(cid).and_then(|c| Self::chain_plan(&st, c)) else { return false };
            if !chains.iter().any(|x| x.id == p.id) {
                chains.push(p);
            }
            true
        };
        // WARP servers a route may fall back to (best first), shared by all routes
        let warp_ids: Vec<String> = {
            let mut v: Vec<&Server> = st.servers.iter().filter(|s| s.origin == Origin::Warp && s.good()).collect();
            v.sort_by_key(|s| scan::score(s));
            v.into_iter().take(WARP_SERVERS).map(|s| s.id.clone()).collect()
        };
        for r in st.settings.routes.units() {
            let spare = match r.fallback {
                Fallback::Fastest => mihomo::Spare::Vpn,
                Fallback::Direct => mihomo::Spare::Direct,
                Fallback::Block => mihomo::Spare::Block,
                Fallback::Warp => mihomo::Spare::Warp(warp_ids.clone()),
            };
            let mut need_warp = matches!(spare, mihomo::Spare::Warp(_));
            // what the route does when it has nothing of its own to go through
            let none_via = || match &spare {
                mihomo::Spare::Direct => Via::Direct,
                mihomo::Spare::Block => Via::Block,
                _ => Via::Vpn,
            };
            let via = match &r.target {
                Target::Direct => {
                    need_warp = false;
                    Via::Direct
                }
                Target::Vpn => {
                    need_warp = false;
                    Via::Vpn
                }
                Target::Block => {
                    need_warp = false;
                    Via::Block
                }
                Target::Chain(cid) => {
                    if add_chain(&mut chains, cid) {
                        Via::Chain(cid.clone())
                    } else {
                        none_via()
                    }
                }
                t => {
                    let list = Self::route_servers(&st, t);
                    if list.is_empty() {
                        // no own servers: WARP (if wanted and working) stands in, else the policy
                        match (&spare, warp_ids.is_empty()) {
                            (mihomo::Spare::Warp(_), false) => {
                                for id in &warp_ids {
                                    if let Some(s) = st.servers.iter().find(|s| &s.id == id) {
                                        if !pool.iter().any(|x| x.id == s.id) && !extra.iter().any(|x| x.id == s.id) {
                                            extra.push(s.clone());
                                        }
                                    }
                                }
                                Via::Servers(warp_ids.clone())
                            }
                            _ => none_via(),
                        }
                    } else {
                        let ids = list.iter().map(|s| s.id.clone()).collect();
                        for s in list {
                            if !pool.iter().any(|x| x.id == s.id) && !extra.iter().any(|x| x.id == s.id) {
                                extra.push(s);
                            }
                        }
                        Via::Servers(ids)
                    }
                }
            };
            if need_warp {
                for id in &warp_ids {
                    if let Some(s) = st.servers.iter().find(|s| &s.id == id) {
                        if !pool.iter().any(|x| x.id == s.id) && !extra.iter().any(|x| x.id == s.id) {
                            extra.push(s.clone());
                        }
                    }
                }
            }
            plans.push(RoutePlan { id: r.id.clone(), via, spare, strategy: r.strategy });
        }
        let mut default_chain = None;
        if let Target::Chain(cid) = &st.settings.routes.default {
            if add_chain(&mut chains, cid) {
                default_chain = Some(cid.clone());
            }
        }
        (plans, extra, chains, default_chain)
    }

    /// Ids of servers routes would use (kept fresh by the pool check).
    pub(super) fn route_server_ids(&self) -> Vec<String> {
        let st = self.st.lock().unwrap();
        let mut ids: Vec<String> = Vec::new();
        for r in st.settings.routes.units() {
            for s in Self::route_servers(&st, &r.target) {
                if !ids.contains(&s.id) {
                    ids.push(s.id);
                }
            }
        }
        ids
    }

    pub(super) fn write_route_lists(&self, ids: &[String]) -> Result<(), String> {
        let dir = self.paths.run().join("routes");
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let st = self.st.lock().unwrap();
        let units = st.settings.routes.units();
        for id in ids {
            let Some(r) = units.iter().find(|u| &u.id == id) else { continue };
            if !routes::safe_id(&r.id) {
                continue;
            }
            let eff_sites = st.settings.routes.eff_list(r, false);
            let eff_apps = st.settings.routes.eff_list(r, true);
            let (d, i, a) = split::provider_texts(&eff_sites, &eff_apps);
            for (part, text) in [("sites", d), ("ips", i), ("apps", a)] {
                mihomo::write_atomic(&dir.join(format!("{}-{part}.txt", r.id)), text.as_bytes()).map_err(|e| e.to_string())?;
            }
        }
        Ok(())
    }

    /// Rebuilds the configuration of the running mihomo in place (the tunnel stays up);
    /// restarts it when that fails. Boxed: start → pool check → reload → start is a cycle.
    pub(super) fn reload_main(self: &Arc<Self>) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), String>> + Send + '_>> {
        Box::pin(self.reload_main_inner())
    }

    async fn reload_main_inner(self: &Arc<Self>) -> Result<(), String> {
        if !self.connected() {
            return Ok(());
        }
        let _g = self.op.lock().await;
        if !self.connected() {
            return Ok(());
        }
        let api = self.api.lock().unwrap().clone();
        let opts = self.applied.lock().unwrap().opts.clone();
        let pool = self.pool();
        let in_place = match (api, opts, pool.is_empty()) {
            (Some(api), Some(mut opts), false) => {
                let (plans, extra, chains, default_chain) = self.route_plans(&pool);
                opts.routes = plans;
                opts.chains = chains;
                opts.default_chain = default_chain;
                opts.hops = self.relay_hop_servers(&[&pool, &extra]);
                opts.default_direct = self.st.lock().unwrap().settings.routes.default == Target::Direct;
                let written = self.write_run_files(&pool, &extra).and_then(|_| {
                    let cfg = mihomo::main_config(&opts);
                    mihomo::write_atomic(&self.paths.run().join("config.json"), cfg.to_string().as_bytes()).map_err(|e| e.to_string())
                });
                match written {
                    Ok(()) => match api.reload_config().await {
                        Ok(()) => {
                            {
                                let mut a = self.applied.lock().unwrap();
                                a.opts = Some(opts);
                                a.pool = pool.iter().map(|s| s.id.clone()).collect();
                                a.extra = extra.iter().map(|s| s.id.clone()).collect();
                            }
                            self.st.lock().unwrap().route_spare.clear();
                            let sel = self.st.lock().unwrap().settings.selected.clone();
                            let target = sel.filter(|id| pool.iter().any(|s| &s.id == id)).unwrap_or_else(|| "AUTO".into());
                            let _ = api.select("VPN", &target).await;
                            api.close_connections().await;
                            true
                        }
                        Err(e) => {
                            self.log(&format!("настройки не применились на лету: {e}"));
                            false
                        }
                    },
                    Err(e) => {
                        self.log(&format!("не удалось записать настройки: {e}"));
                        false
                    }
                }
            }
            _ => false,
        };
        if in_place {
            self.log("маршруты применены");
            return Ok(());
        }
        self.set_conn(ConnState::Connecting, Some("Применяем настройки…"), None);
        match self.start_main().await {
            Ok(()) => Ok(()),
            Err(e) => {
                self.set_conn(ConnState::Error, None, Some(e.clone()));
                Err(e)
            }
        }
    }

    /// New lists of these routes: rewrite and hot-reload their rule providers.
    async fn apply_route_lists(&self, ids: &[String]) {
        if ids.is_empty() || self.write_route_lists(ids).is_err() {
            return;
        }
        let api = self.api.lock().unwrap().clone();
        if let Some(api) = api {
            for id in ids {
                for part in mihomo::ROUTE_PARTS {
                    let _ = api.reload_rule_provider(&mihomo::route_provider(id, part)).await;
                }
            }
            // open connections keep their old way otherwise
            api.close_connections().await;
        }
    }

    /// Saves the routes and applies the change to a running connection.
    async fn routes_changed(self: &Arc<Self>, before: &Routes) -> Result<(), String> {
        self.save_settings();
        if !self.connected() {
            return Ok(());
        }
        let after = self.st.lock().unwrap().settings.routes.clone();
        if after.shape() != before.shape() {
            return self.reload_main().await;
        }
        let ids = after.changed_lists(before);
        self.apply_route_lists(&ids).await;
        Ok(())
    }

    /// Why a unit with this target currently falls back to the VPN ("" = fine).
    fn target_warn(st: &State, r: &Route, connected: bool) -> String {
        let warn = if !r.enabled || st.settings.routes.eff_entries(r) == 0 {
            String::new()
        } else {
            match &r.target {
                Target::Server(id) => match st.servers.iter().find(|s| &s.id == id) {
                    None => "Сервер удалён — трафик идёт через VPN".into(),
                    Some(s) if s.probe.as_ref().is_some_and(|p| !p.ok) => "Сервер не отвечает — трафик идёт через VPN".into(),
                    _ => String::new(),
                },
                Target::Chain(cid) => match st.settings.routes.chain(cid) {
                    None => "Цепочка удалена — трафик идёт через VPN".into(),
                    Some(c) if Self::chain_plan(st, c).is_none() => "Цепочка не собралась — трафик идёт через VPN".into(),
                    _ => String::new(),
                },
                t if t.uses_servers() && Self::route_servers(st, t).is_empty() => match t {
                    Target::Warp => "WARP пока недоступен — трафик идёт через VPN".into(),
                    _ => match r.fallback {
                        Fallback::Fastest => "В этой стране нет рабочих серверов — трафик идёт через самый быстрый VPN".into(),
                        Fallback::Warp => "В этой стране нет рабочих серверов — пока идёт через WARP, затем через VPN".into(),
                        Fallback::Direct => "В этой стране нет рабочих серверов — трафик идёт напрямую".into(),
                        Fallback::Block => "В этой стране нет рабочих серверов — трафик заблокирован".into(),
                    },
                },
                _ => String::new(),
            }
        };
        if warn.is_empty() && connected && st.route_spare.contains(&r.id) {
            "Серверы маршрута не отвечают — пока трафик идёт через VPN".to_string()
        } else {
            warn
        }
    }

    fn route_json(st: &State, r: &Route, connected: bool) -> Value {
        let warn = Self::target_warn(st, r, connected);
        let linked = st.settings.routes.eff_entries(r) - r.entries();
        json!({
            "id": r.id,
            "name": r.name,
            "enabled": r.enabled,
            "target": r.target.code(),
            "fallback": r.fallback.code(),
            "strategy": r.strategy.code(),
            "label": label(st, &r.target),
            "warn": warn,
            "sites": r.sites,
            "apps": r.apps,
            "lists": r.lists,
            "linked": linked,
        })
    }

    fn chain_json(st: &State, c: &Chain) -> Value {
        let hops: Vec<Value> = c.hops.iter().map(|h| json!({ "code": h.code(), "label": hop_label(st, h) })).collect();
        let path = c.hops.iter().map(|h| hop_label(st, h)).collect::<Vec<_>>().join(" → ");
        let warn = if Self::chain_plan(st, c).is_none() { "Не собралась — её трафик пойдёт через VPN" } else { "" };
        json!({
            "id": c.id,
            "name": c.name,
            "hops": hops,
            "label": if path.is_empty() { c.name.clone() } else { path },
            "warn": warn,
        })
    }

    pub(super) fn routes_view(&self) -> Value {
        let connected = self.connected();
        let st = self.st.lock().unwrap();
        let list: Vec<Value> = st.settings.routes.list.iter().map(|r| Self::route_json(&st, r, connected)).collect();
        let chains: Vec<Value> = st.settings.routes.chains.iter().map(|c| Self::chain_json(&st, c)).collect();
        // countries a route can go through: working servers there
        let mut cc: HashMap<String, usize> = HashMap::new();
        for s in st.servers.iter().filter(|s| s.good()) {
            if let Some(c) = s.country() {
                *cc.entry(c.to_string()).or_default() += 1;
            }
        }
        let mut countries: Vec<Value> = cc
            .into_iter()
            .map(|(c, n)| json!({ "cc": c, "name": countries::name(&c).unwrap_or(&c), "count": n }))
            .collect();
        countries.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
        let warp = st.servers.iter().any(|s| s.origin == Origin::Warp);
        let lists: Vec<Value> = st.settings.routes.lists.iter().map(|l| Self::list_json(&st, l, connected)).collect();
        json!({
            "default": st.settings.routes.default.code(),
            "routes": list,
            "chains": chains,
            "lists": lists,
            "issues": smart::lint(&st.settings.routes).into_iter().map(|i| i.text).collect::<Vec<_>>(),
            "countries": countries,
            "warp": warp,
        })
    }

    fn parse_target(t: &str) -> Result<Target, String> {
        let t = Target::parse(t)?;
        Ok(t)
    }

    /// Makes sure WARP servers exist when a route wants them.
    fn want_warp(self: &Arc<Self>, t: &Target) {
        if *t != Target::Warp || self.st.lock().unwrap().servers.iter().any(|s| s.origin == Origin::Warp) {
            return;
        }
        let me = self.clone();
        tokio::spawn(async move {
            match me.ensure_warp().await {
                Ok(()) => {
                    let ids: Vec<String> = me.st.lock().unwrap().servers.iter().filter(|s| s.origin == Origin::Warp).map(|s| s.id.clone()).collect();
                    me.clone().check_ids(ids).await;
                }
                Err(e) => me.log(&format!("WARP: {e}")),
            }
        });
    }

    pub(super) async fn route_default(self: &Arc<Self>, target: &str) -> Result<Value, String> {
        let t = Self::parse_target(target)?;
        match &t {
            Target::Vpn | Target::Direct => {}
            Target::Chain(cid) => {
                if self.st.lock().unwrap().settings.routes.chain(cid).is_none() {
                    return Err("цепочка не найдена".into());
                }
            }
            _ => return Err("остальной трафик идёт через VPN, напрямую или по цепочке".into()),
        }
        let before = {
            let mut st = self.st.lock().unwrap();
            let b = st.settings.routes.clone();
            st.settings.routes.default = t;
            b
        };
        self.routes_changed(&before).await?;
        Ok(Value::Null)
    }

    fn parse_hops(hops: &[String]) -> Result<Vec<Hop>, String> {
        hops.iter().map(|h| Hop::parse(h)).collect()
    }

    pub(super) async fn chain_add(self: &Arc<Self>, name: &str, hops: &[String]) -> Result<Value, String> {
        let hops = Self::parse_hops(hops)?;
        let mut c = Chain::new(name, hops);
        if c.name.is_empty() {
            c.name = "Цепочка".into();
        }
        c.validate()?;
        let (before, id) = {
            let mut st = self.st.lock().unwrap();
            if st.settings.routes.chains.len() >= MAX_CHAINS {
                return Err(format!("Можно создать не больше {MAX_CHAINS} цепочек"));
            }
            let before = st.settings.routes.clone();
            let id = c.id.clone();
            st.settings.routes.chains.push(c);
            (before, id)
        };
        self.routes_changed(&before).await?;
        let st = self.st.lock().unwrap();
        let c = st.settings.routes.chain(&id).cloned().ok_or("цепочка не найдена")?;
        Ok(Self::chain_json(&st, &c))
    }

    pub(super) async fn chain_update(self: &Arc<Self>, id: &str, name: Option<String>, hops: Option<Vec<String>>) -> Result<Value, String> {
        let hops = hops.map(|h| Self::parse_hops(&h)).transpose()?;
        let before = {
            let mut st = self.st.lock().unwrap();
            let before = st.settings.routes.clone();
            let c = st.settings.routes.chain_mut(id).ok_or("цепочка не найдена")?;
            // validate the result before touching the live state
            let mut next = c.clone();
            if let Some(n) = name {
                let n = routes::clean_name(&n);
                if !n.is_empty() {
                    next.name = n;
                }
            }
            if let Some(h) = hops {
                next.hops = h;
            }
            next.validate()?;
            *c = next;
            before
        };
        self.routes_changed(&before).await?;
        Ok(Value::Null)
    }

    pub(super) async fn chain_remove(self: &Arc<Self>, id: &str) -> Result<Value, String> {
        let before = {
            let mut st = self.st.lock().unwrap();
            let before = st.settings.routes.clone();
            st.settings.routes.chains.retain(|c| c.id != id);
            before
        };
        // routes that pointed at the chain keep the dangling target: the planner
        // carries their traffic through the VPN and the list shows a warning
        self.routes_changed(&before).await?;
        Ok(Value::Null)
    }

    fn list_json(st: &State, l: &EntryList, connected: bool) -> Value {
        let (target, lbl, warn) = match &l.target {
            Some(t) => {
                let unit = Route { id: routes::Routes::unit_id(&l.id), name: l.name.clone(), enabled: true, target: t.clone(), sites: l.sites.clone(), apps: l.apps.clone(), lists: vec![], fallback: l.fallback, strategy: l.strategy };
                (t.code(), label(st, t), Self::target_warn(st, &unit, connected))
            }
            None => (String::new(), String::new(), String::new()),
        };
        json!({ "id": l.id, "name": l.name, "sites": l.sites, "apps": l.apps, "target": target, "label": lbl, "warn": warn })
    }

    pub(super) async fn list_add(self: &Arc<Self>, name: &str) -> Result<Value, String> {
        let mut l = EntryList::new(name);
        if l.name.is_empty() {
            l.name = "Список".into();
        }
        let (before, id) = {
            let mut st = self.st.lock().unwrap();
            if st.settings.routes.lists.len() >= MAX_LISTS {
                return Err(format!("Можно создать не больше {MAX_LISTS} списков"));
            }
            let before = st.settings.routes.clone();
            let id = l.id.clone();
            st.settings.routes.lists.push(l);
            (before, id)
        };
        self.routes_changed(&before).await?;
        let connected = self.connected();
        let st = self.st.lock().unwrap();
        let l = st.settings.routes.entry_list(&id).cloned().ok_or("список не найден")?;
        Ok(Self::list_json(&st, &l, connected))
    }

    /// `target`: None leaves the direction alone, Some("") clears it, Some(code) sets it.
    pub(super) async fn list_update(self: &Arc<Self>, id: &str, name: Option<String>, target: Option<String>) -> Result<Value, String> {
        let target = match target.as_deref() {
            None => None,
            Some("") => Some(None),
            Some(c) => Some(Some(Self::parse_target(c)?)),
        };
        let before = {
            let mut st = self.st.lock().unwrap();
            let before = st.settings.routes.clone();
            let l = st.settings.routes.entry_list_mut(id).ok_or("список не найден")?;
            if let Some(n) = name {
                let n = routes::clean_name(&n);
                if !n.is_empty() {
                    l.name = n;
                }
            }
            if let Some(t) = target {
                l.target = t;
            }
            before
        };
        self.routes_changed(&before).await?;
        Ok(Value::Null)
    }

    pub(super) async fn list_remove(self: &Arc<Self>, id: &str) -> Result<Value, String> {
        let before = {
            let mut st = self.st.lock().unwrap();
            let before = st.settings.routes.clone();
            st.settings.routes.lists.retain(|l| l.id != id);
            // detach everywhere: a route keeps only its own entries
            for r in st.settings.routes.list.iter_mut() {
                r.lists.retain(|x| x != id);
            }
            before
        };
        self.routes_changed(&before).await?;
        Ok(Value::Null)
    }

    pub(super) async fn list_entry_add(self: &Arc<Self>, id: &str, kind: Kind, value: &str) -> Result<Value, String> {
        let apps = kind == Kind::App;
        let v = if apps { split::normalize_app(value)? } else { split::normalize_site(value)? };
        let before = {
            let mut st = self.st.lock().unwrap();
            let before = st.settings.routes.clone();
            let l = st.settings.routes.entry_list_mut(id).ok_or("список не найден")?;
            let list = l.list_mut(apps);
            if !list.contains(&v) {
                list.push(v.clone());
            }
            before
        };
        self.routes_changed(&before).await?;
        Ok(json!({ "value": v }))
    }

    pub(super) async fn list_entry_remove(self: &Arc<Self>, id: &str, kind: Kind, value: &str) -> Result<Value, String> {
        let before = {
            let mut st = self.st.lock().unwrap();
            let before = st.settings.routes.clone();
            let l = st.settings.routes.entry_list_mut(id).ok_or("список не найден")?;
            l.list_mut(kind == Kind::App).retain(|x| x != value);
            before
        };
        self.routes_changed(&before).await?;
        Ok(Value::Null)
    }

    pub(super) async fn list_import(self: &Arc<Self>, id: &str, kind: Kind, text: &str) -> Result<Value, String> {
        let apps = kind == Kind::App;
        let (before, added, bad) = {
            let mut st = self.st.lock().unwrap();
            let before = st.settings.routes.clone();
            if st.settings.routes.entry_list(id).is_none() {
                return Err("список не найден".into());
            }
            let mut found = Vec::new();
            let (_, bad) = split::import_lines(&mut found, text, apps);
            let mut added = 0;
            let l = st.settings.routes.entry_list_mut(id).ok_or("список не найден")?;
            for v in &found {
                let list = l.list_mut(apps);
                if !list.contains(v) {
                    list.push(v.clone());
                    added += 1;
                }
            }
            (before, added, bad)
        };
        self.routes_changed(&before).await?;
        Ok(json!({ "added": added, "rejected": bad }))
    }

    pub(super) fn list_export(&self, id: &str, kind: Kind) -> Result<Value, String> {
        let st = self.st.lock().unwrap();
        let l = st.settings.routes.entry_list(id).ok_or("список не найден")?;
        let v = l.list(kind == Kind::App);
        Ok(json!({ "text": v.join("\n") + "\n" }))
    }

    pub(super) async fn route_add(self: &Arc<Self>, name: &str, target: &str, sites: &[String], apps: &[String]) -> Result<Value, String> {
        let t = Self::parse_target(target)?;
        let mut r = Route::new(name, t.clone());
        if r.name.is_empty() {
            r.name = "Новый маршрут".into();
        }
        let (before, id) = {
            let mut st = self.st.lock().unwrap();
            if st.settings.routes.list.len() >= MAX_ROUTES {
                return Err(format!("Можно создать не больше {MAX_ROUTES} маршрутов"));
            }
            let before = st.settings.routes.clone();
            let id = r.id.clone();
            st.settings.routes.list.push(r);
            for (apps_kind, list) in [(false, sites), (true, apps)] {
                for v in list {
                    let n = if apps_kind { split::normalize_app(v) } else { split::normalize_site(v) };
                    if let Ok(n) = n {
                        let _ = st.settings.routes.add_entry(&id, apps_kind, &n);
                    }
                }
            }
            (before, id)
        };
        self.want_warp(&t);
        self.routes_changed(&before).await?;
        // `connected()` locks `st` itself: ask before taking the guard, a std
        // mutex is not reentrant and locking it twice deadlocks the engine.
        let connected = self.connected();
        let st = self.st.lock().unwrap();
        let r = st.settings.routes.get(&id).cloned().ok_or("маршрут не найден")?;
        Ok(Self::route_json(&st, &r, connected))
    }

    pub(super) async fn route_update(self: &Arc<Self>, id: &str, name: Option<String>, enabled: Option<bool>, target: Option<String>, lists: Option<Vec<String>>, fallback: Option<String>, strategy: Option<String>) -> Result<Value, String> {
        let target = target.map(|t| Self::parse_target(&t)).transpose()?;
        let strategy = strategy.map(|f| routes::Strategy::parse(&f)).transpose()?;
        let fallback = fallback.map(|f| Fallback::parse(&f)).transpose()?;
        let mut want_warp_spare = false;
        let before = {
            let mut st = self.st.lock().unwrap();
            let before = st.settings.routes.clone();
            // attachments: keep only lists that exist, once each
            let lists = lists.map(|ls| {
                let mut out: Vec<String> = Vec::new();
                for l in ls {
                    if st.settings.routes.entry_list(&l).is_some() && !out.contains(&l) {
                        out.push(l);
                    }
                }
                out
            });
            let r = st.settings.routes.get_mut(id).ok_or("маршрут не найден")?;
            if let Some(n) = name {
                let n = routes::clean_name(&n);
                if !n.is_empty() {
                    r.name = n;
                }
            }
            if let Some(f) = fallback {
                r.fallback = f;
                want_warp_spare = f == Fallback::Warp;
            }
            if let Some(x) = strategy {
                r.strategy = x;
            }
            if let Some(e) = enabled {
                r.enabled = e;
            }
            if let Some(t) = target.clone() {
                r.target = t;
            }
            if let Some(ls) = lists {
                r.lists = ls;
            }
            before
        };
        if let Some(t) = &target {
            self.want_warp(t);
        }
        if want_warp_spare {
            self.want_warp(&Target::Warp);
        }
        self.routes_changed(&before).await?;
        Ok(Value::Null)
    }

    /// Countries that routes ask for but where no server works yet: the search looks
    /// there first.
    pub(super) fn missing_route_countries(&self) -> HashSet<String> {
        let st = self.st.lock().unwrap();
        let mut want: HashSet<String> = HashSet::new();
        let mut add = |cc: &str| {
            want.insert(cc.to_string());
        };
        for r in st.settings.routes.units() {
            match &r.target {
                Target::Country(cc) => add(cc),
                Target::Chain(id) => {
                    if let Some(c) = st.settings.routes.chain(id) {
                        for h in &c.hops {
                            if let Hop::Country(cc) = h {
                                add(cc);
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        want.retain(|cc| !st.servers.iter().any(|s| s.good() && s.country() == Some(cc.as_str())));
        want
    }

    pub(super) async fn route_remove(self: &Arc<Self>, id: &str) -> Result<Value, String> {
        let before = {
            let mut st = self.st.lock().unwrap();
            let before = st.settings.routes.clone();
            st.settings.routes.list.retain(|r| r.id != id);
            before
        };
        self.routes_changed(&before).await?;
        Ok(Value::Null)
    }

    pub(super) async fn route_move(self: &Arc<Self>, id: &str, delta: i32) -> Result<Value, String> {
        let before = {
            let mut st = self.st.lock().unwrap();
            let before = st.settings.routes.clone();
            let l = &mut st.settings.routes.list;
            let i = l.iter().position(|r| r.id == id).ok_or("маршрут не найден")?;
            let j = (i as i64 + delta as i64).clamp(0, l.len() as i64 - 1) as usize;
            let r = l.remove(i);
            l.insert(j, r);
            before
        };
        self.routes_changed(&before).await?;
        Ok(Value::Null)
    }

    pub(super) async fn route_entry_add(self: &Arc<Self>, id: &str, kind: Kind, value: &str) -> Result<Value, String> {
        let apps = kind == Kind::App;
        let v = if apps { split::normalize_app(value)? } else { split::normalize_site(value)? };
        let (before, moved) = {
            let mut st = self.st.lock().unwrap();
            let before = st.settings.routes.clone();
            let moved = st.settings.routes.add_entry(id, apps, &v)?;
            (before, moved)
        };
        self.routes_changed(&before).await?;
        Ok(json!({ "value": v, "moved": moved }))
    }

    pub(super) async fn route_entry_remove(self: &Arc<Self>, id: &str, kind: Kind, value: &str) -> Result<Value, String> {
        let before = {
            let mut st = self.st.lock().unwrap();
            let before = st.settings.routes.clone();
            let r = st.settings.routes.get_mut(id).ok_or("маршрут не найден")?;
            r.list_mut(kind == Kind::App).retain(|x| x != value);
            before
        };
        self.routes_changed(&before).await?;
        Ok(Value::Null)
    }

    pub(super) async fn route_import(self: &Arc<Self>, id: &str, kind: Kind, text: &str) -> Result<Value, String> {
        let apps = kind == Kind::App;
        let (before, added, bad) = {
            let mut st = self.st.lock().unwrap();
            let before = st.settings.routes.clone();
            if st.settings.routes.get(id).is_none() {
                return Err("маршрут не найден".into());
            }
            let mut found = Vec::new();
            let (_, bad) = split::import_lines(&mut found, text, apps);
            let mut added = 0;
            for v in &found {
                let had = st.settings.routes.get(id).is_some_and(|r| r.list(apps).contains(v));
                let _ = st.settings.routes.add_entry(id, apps, v);
                if !had {
                    added += 1;
                }
            }
            (before, added, bad)
        };
        self.routes_changed(&before).await?;
        Ok(json!({ "added": added, "rejected": bad }))
    }

    /// The pack catalog: what each pack holds and whether a route of that name exists.
    pub(super) fn route_presets(&self) -> Value {
        let st = self.st.lock().unwrap();
        let list: Vec<Value> = smart::PRESETS
            .iter()
            .map(|p| {
                let have = st.settings.routes.list.iter().find(|r| r.name == p.name);
                json!({
                    "id": p.id,
                    "name": p.name,
                    "desc": p.desc,
                    "hint": p.hint,
                    "hint_label": Target::parse(p.hint).map(|t| label(&st, &t)).unwrap_or_default(),
                    "count": p.sites.len() + p.apps.len(),
                    "added": have.is_some(),
                })
            })
            .collect();
        json!({ "presets": list })
    }

    /// A pack becomes a route (or tops up and redirects the route of the same name).
    pub(super) async fn route_preset_add(self: &Arc<Self>, preset: &str, target: &str) -> Result<Value, String> {
        let p = smart::preset(preset).ok_or("набор не найден")?;
        let target = if target.is_empty() { p.hint } else { target };
        let (sites, apps) = p.entries();
        let existing = {
            let st = self.st.lock().unwrap();
            st.settings.routes.list.iter().find(|r| r.name == p.name).map(|r| r.id.clone())
        };
        match existing {
            None => self.route_add(p.name, target, &sites, &apps).await,
            Some(id) => {
                let (before, moved) = {
                    let mut st = self.st.lock().unwrap();
                    let before = st.settings.routes.clone();
                    let mut moved: Vec<String> = Vec::new();
                    for (is_app, list) in [(false, &sites), (true, &apps)] {
                        for v in list.iter() {
                            for m in st.settings.routes.add_entry(&id, is_app, v).unwrap_or_default() {
                                if !moved.contains(&m) {
                                    moved.push(m);
                                }
                            }
                        }
                    }
                    (before, moved)
                };
                self.routes_changed(&before).await?;
                self.route_update(&id, None, Some(true), Some(target.to_string()), None, None, None).await?;
                let connected = self.connected();
                let st = self.st.lock().unwrap();
                let r = st.settings.routes.get(&id).cloned().ok_or("маршрут не найден")?;
                let mut v = Self::route_json(&st, &r, connected);
                v["moved"] = json!(moved);
                Ok(v)
            }
        }
    }

    /// Adds pasted text of any shape to a route.
    pub(super) async fn route_bulk(self: &Arc<Self>, id: &str, text: &str) -> Result<Value, String> {
        let b = smart::parse_bulk(text);
        let (before, added, moved) = {
            let mut st = self.st.lock().unwrap();
            if st.settings.routes.get(id).is_none() {
                return Err("маршрут не найден".into());
            }
            let before = st.settings.routes.clone();
            let mut added = 0usize;
            let mut moved: Vec<String> = Vec::new();
            for (is_app, list) in [(false, &b.sites), (true, &b.apps)] {
                for v in list {
                    let had = st.settings.routes.get(id).is_some_and(|r| r.list(is_app).contains(v));
                    for m in st.settings.routes.add_entry(id, is_app, v).unwrap_or_default() {
                        if !moved.contains(&m) {
                            moved.push(m);
                        }
                    }
                    if !had {
                        added += 1;
                    }
                }
            }
            (before, added, moved)
        };
        self.routes_changed(&before).await?;
        Ok(json!({ "added": added, "found": b.sites.len() + b.apps.len(), "rejected": b.rejected.len(), "rejected_sample": b.rejected.iter().take(3).collect::<Vec<_>>(), "moved": moved }))
    }

    /// Reorders the routes so that specific rules win over the general ones.
    pub(super) async fn route_sort(self: &Arc<Self>) -> Result<Value, String> {
        let (before, moved) = {
            let mut st = self.st.lock().unwrap();
            let before = st.settings.routes.clone();
            let Some(order) = smart::autosort(&st.settings.routes) else { return Ok(json!({ "moved": 0 })) };
            let mut list = std::mem::take(&mut st.settings.routes.list);
            let moved = order.iter().zip(list.iter()).filter(|(a, b)| **a != b.id).count();
            list.sort_by_key(|r| order.iter().position(|x| *x == r.id).unwrap_or(usize::MAX));
            st.settings.routes.list = list;
            (before, moved)
        };
        self.routes_changed(&before).await?;
        Ok(json!({ "moved": moved }))
    }

    /// "Where will this go?" in plain words.
    pub(super) fn route_explain(&self, query: &str) -> Value {
        let st = self.st.lock().unwrap();
        let ex = smart::explain(&st.settings.routes, query);
        let what = match &ex.subject {
            smart::Subject::Site(s) => s.clone(),
            smart::Subject::App(a) => a.clone(),
            smart::Subject::Invalid => return json!({ "ok": false, "text": "Не похоже на адрес сайта или имя программы" }),
        };
        let mut lines: Vec<String> = Vec::new();
        match ex.winner() {
            Some(h) => {
                let why = if h.entry == what { format!("«{}»", h.name) } else { format!("«{}» (правило {})", h.name, h.entry) };
                lines.push(format!("{what} → {}. Решает маршрут {why}.", label(&st, &h.target)));
                for o in ex.hits.iter().skip(1) {
                    lines.push(format!("Также подходит «{}» ({}), но он ниже по списку — не сработает.", o.name, label(&st, &o.target)));
                }
            }
            None => lines.push(format!("{what} → {}. Ни один маршрут не подошёл — действует «Остальной трафик».", label(&st, &ex.default))),
        }
        json!({ "ok": true, "text": lines.join("\n"), "target": ex.target().code() })
    }

    pub(super) fn route_export(&self, id: &str, kind: Kind) -> Result<Value, String> {
        let st = self.st.lock().unwrap();
        let r = st.settings.routes.get(id).ok_or("маршрут не найден")?;
        let v = r.list(kind == Kind::App);
        Ok(json!({ "text": v.join("\n") + "\n" }))
    }

    /// Watch over routes with their own servers (from the watchdog): which of them use
    /// the VPN as a spare right now; their servers are re-tested so they come back.
    pub(super) async fn route_health(&self, api: &mihomo::Api) {
        let plans = self.applied.lock().unwrap().opts.as_ref().map(|o| o.routes.clone()).unwrap_or_default();
        let watched: Vec<&RoutePlan> = plans.iter().filter(|p| matches!(p.via, Via::Servers(_) | Via::Chain(_))).collect();
        if watched.is_empty() {
            self.st.lock().unwrap().route_spare.clear();
            return;
        }
        let now = util::now();
        let due = {
            let st = self.st.lock().unwrap();
            now.saturating_sub(st.last_route_check) >= 60
        };
        let mut spare = HashSet::new();
        for p in &watched {
            let id = &p.id;
            let g = mihomo::route_group(id);
            if api.now(&g).await.as_deref() == Some("VPN") {
                spare.insert(id.clone());
                if due {
                    // re-test the route's own path, then let the route group pick again
                    let inner = match &p.via {
                        Via::Servers(_) => mihomo::route_servers_group(id),
                        Via::Chain(cid) => mihomo::chain_group(cid),
                        _ => unreachable!(),
                    };
                    let alive = api.group_delay(&inner, mihomo::TEST_URL, 4000).await;
                    if !alive.is_empty() {
                        let _ = api.group_delay(&g, mihomo::TEST_URL, 4000).await;
                        if api.now(&g).await.as_deref() != Some("VPN") {
                            spare.remove(id);
                        }
                    }
                }
            }
        }
        let mut st = self.st.lock().unwrap();
        if due {
            st.last_route_check = now;
        }
        let newly: Vec<String> = spare.difference(&st.route_spare).cloned().collect();
        st.route_spare = spare;
        let names: Vec<String> = newly
            .iter()
            .filter_map(|id| {
                st.settings.routes.get(id).map(|r| r.name.clone()).or_else(|| {
                    id.strip_prefix('l').and_then(|lid| st.settings.routes.entry_list(lid)).map(|l| l.name.clone())
                })
            })
            .collect();
        drop(st);
        if !names.is_empty() {
            self.log(&format!("маршрут на запасном пути (через VPN): {}", names.join(", ")));
        }
    }
}
