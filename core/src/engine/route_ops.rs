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
        Hop::Warp => "WARP".into(),
    }
}

/// Human-readable full hop path for the route analyzer: `Компьютер → ... → Интернет`.
fn explain_path(st: &State, t: &Target) -> String {
    match t {
        Target::Direct => "Компьютер → Прямое соединение (мимо VPN) → Интернет".into(),
        Target::Block => "Компьютер → Блокировка (REJECT)".into(),
        Target::Vpn => {
            if let Some(cur) = st.conn.current.as_ref().and_then(|id| st.servers.iter().find(|s| &s.id == id)) {
                let v = view_with(cur, true, &st.servers);
                if !v.relay_name.is_empty() {
                    return format!("Компьютер → {} (входное звено) → {} ({}) → Интернет", v.relay_name, v.name, v.cc);
                }
                return format!("Компьютер → {} ({}) → Интернет", v.name, if v.cc.is_empty() { "VPN" } else { &v.cc });
            }
            "Компьютер → Основной пул VPN (AUTO) → Интернет".into()
        }
        Target::Warp => "Компьютер → Cloudflare WARP → Интернет".into(),
        Target::Country(cc) => {
            let cname = countries::name(cc).unwrap_or(cc);
            let srvs = Engine::route_servers(st, t);
            if let Some(best) = srvs.first() {
                let v = view_with(best, false, &st.servers);
                if !v.relay_name.is_empty() {
                    return format!("Компьютер → {} (входное звено) → {} ({cname}) → Интернет", v.relay_name, v.name);
                }
                return format!("Компьютер → {} ({cname}) → Интернет", v.name);
            }
            format!("Компьютер → Страна: {cname} (резерв: VPN) → Интернет")
        }
        Target::Server(id) => match st.servers.iter().find(|s| &s.id == id) {
            Some(s) => {
                let v = view_with(s, false, &st.servers);
                if !v.relay_name.is_empty() {
                    format!("Компьютер → {} (входное звено) → {} → Интернет", v.relay_name, v.name)
                } else {
                    format!("Компьютер → {} → Интернет", v.name)
                }
            }
            None => "Компьютер → Основной пул VPN (сервер удалён) → Интернет".into(),
        },
        Target::Chain(id) => match st.settings.routes.chain(id) {
            Some(c) => {
                let hops: Vec<String> = c.hops.iter().map(|h| hop_label(st, h)).collect();
                format!("Компьютер → {} → Интернет", hops.join(" → "))
            }
            None => "Компьютер → Основной пул VPN (цепочка удалена) → Интернет".into(),
        },
    }
}

impl Engine {
    /// Servers a route target goes through, best first; empty = the VPN instead.
    /// Excludes disabled, auth-blocked, or circuit-broken servers so dead nodes (like
    /// `95.213.245.84:443` in `R-__default-s`) are immediately evicted.
    fn route_servers(st: &State, t: &Target) -> Vec<Server> {
        let now = util::now();
        let usable = |s: &Server| !s.disabled && !s.auth_error && !s.circuit_open(now);
        let class = |s: &Server| if s.fav { 0 } else if s.origin == Origin::Mine { 1 } else { 2 };
        match t {
            Target::Server(id) => st
                .servers
                .iter()
                .filter(|s| &s.id == id && usable(s) && s.probe.as_ref().is_none_or(|p| p.ok))
                .cloned()
                .collect(),
            Target::Country(cc) => {
                let mut v: Vec<&Server> = st
                    .servers
                    .iter()
                    .filter(|s| usable(s) && s.good() && s.country() == Some(cc.as_str()) && scan::relay_ok(&st.servers, s))
                    .collect();
                v.sort_by_key(|s| (class(s), scan::score(s)));
                let mut hosts = HashSet::new();
                v.into_iter().filter(|s| hosts.insert(s.host.clone())).take(COUNTRY_SERVERS).cloned().collect()
            }
            Target::Warp => {
                let mut v: Vec<&Server> = st.servers.iter().filter(|s| s.origin == Origin::Warp && usable(s) && s.good()).collect();
                if v.is_empty() {
                    // not checked yet: the route group finds out itself, the VPN is the spare
                    v = st.servers.iter().filter(|s| s.origin == Origin::Warp && usable(s) && s.probe.is_none()).collect();
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
        let now = util::now();
        match h {
            Hop::Auto => vec![],
            Hop::Country(cc) => Self::route_servers(st, &Target::Country(cc.clone())),
            Hop::Server(id) => Self::route_servers(st, &Target::Server(id.clone())),
            // One variant only: they all share one key, and a fallback group health-checks
            // every member — several of them would knock each other's session out. Through
            // an earlier hop WARP often works where it is blocked directly, so a variant
            // that failed from here still qualifies (best record first).
            Hop::Warp => {
                let mut v: Vec<&Server> = st.servers.iter().filter(|s| s.origin == Origin::Warp && !s.disabled && !s.auth_error && !s.circuit_open(now)).collect();
                v.sort_by_key(|s| (!s.good(), scan::score(s), s.fails, s.id.clone()));
                v.into_iter().take(1).cloned().collect()
            }
        }
    }

    /// Compiles a chain into per-level proxy copies for the config. `None` when
    /// some hop has no server left to go through (a server already used by an
    /// earlier hop cannot serve again — a chain through itself is a loop); the
    /// caller then falls back to the VPN, never to a direct connection.
    fn chain_plan(st: &State, chain: &Chain) -> Option<mihomo::ChainPlan> {
        // A manually selected WARP is already using this device key; a chain copy
        // must not open a second concurrent session for the same account.
        if chain.hops.contains(&Hop::Warp) {
            let units = st.settings.routes.units();
            let direct_warp = st.settings.routes.default == Target::Warp || units.iter().any(|r| r.target == Target::Warp || (r.target.uses_servers() && r.fallback == Fallback::Warp));
            if direct_warp || st.settings.selected.as_ref().is_some_and(|id| st.servers.iter().any(|s| &s.id == id && s.origin == Origin::Warp)) { return None; }
            // Different WARP chains would create different sessions with one key.
            // Prefer the default chain, then the first active route's chain.
            let warp_chain = |t: &Target| match t {
                Target::Chain(id) if st.settings.routes.chain(id).is_some_and(|c| c.hops.contains(&Hop::Warp)) => Some(id.clone()),
                _ => None,
            };
            let first = warp_chain(&st.settings.routes.default).or_else(|| units.iter().find_map(|r| warp_chain(&r.target)));
            if first.as_ref().is_some_and(|id| id != &chain.id) { return None; }
        }
        let mut used: HashSet<String> = HashSet::new();
        let mut levels: Vec<Vec<Value>> = Vec::new();
        for (i, h) in chain.hops.iter().enumerate() {
            match h {
                Hop::Auto if i == 0 => levels.push(vec![]),
                Hop::Auto => {
                    // A later VPN hop must dial through the previous hop. Referring to
                    // the ordinary VPN group here would bypass all previous levels.
                    let cc = Self::countries(st);
                    let candidates = scan::pool(&st.servers, &scan::PoolOpts { size: st.settings.pool_size, countries: &cc, warp: false, selected: st.settings.selected.as_deref() });
                    let candidates: Vec<Server> = candidates.into_iter().filter(|s| s.origin != Origin::Warp && !is_wg(s) && s.relay.is_none() && used.insert(s.id.clone())).collect();
                    if candidates.is_empty() { return None; }
                    levels.push(candidates.iter().map(|s| {
                        let mut p = s.mihomo_proxy();
                        p["name"] = Value::from(format!("{}~{}-{}", s.id, chain.id, i + 1));
                        p
                    }).collect());
                }
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
        // A virtual route shares the same fallback group machinery as normal routes,
        // but has no rule providers: MATCH points to it instead.
        if matches!(&st.settings.routes.default, Target::Country(_) | Target::Server(_) | Target::Warp) {
            let list = Self::route_servers(&st, &st.settings.routes.default);
            if !list.is_empty() {
                let ids = list.iter().map(|s| s.id.clone()).collect();
                for s in list {
                    if !pool.iter().any(|x| x.id == s.id) && !extra.iter().any(|x| x.id == s.id) { extra.push(s); }
                }
                plans.push(RoutePlan { id: mihomo::DEFAULT_ROUTE.into(), via: Via::Servers(ids), spare: mihomo::Spare::Vpn, strategy: Default::default() });
            }
        }
        (plans, extra, chains, default_chain)
    }

    /// Ids of servers routes would use (kept fresh by the pool check).
    pub(super) fn route_server_ids(&self) -> Vec<String> {
        let st = self.st.lock().unwrap();
        let mut ids: Vec<String> = Vec::new();
        for s in Self::route_servers(&st, &st.settings.routes.default) { if !ids.contains(&s.id) { ids.push(s.id); } }
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
                opts.http_policy = self.http_policy(&pool, &extra, &opts.chains);
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
        // Specific rules must sit above the general ones that would hide them: the order
        // is fixed by itself after every edit except a deliberate move by the user.
        {
            let mut st = self.st.lock().unwrap();
            let r = &st.settings.routes;
            let mut a: Vec<&Route> = r.list.iter().collect();
            let mut b: Vec<&Route> = before.list.iter().collect();
            a.sort_by(|x, y| x.id.cmp(&y.id));
            b.sort_by(|x, y| x.id.cmp(&y.id));
            let only_moved = a == b;
            if !only_moved {
                if let Some(order) = smart::autosort(r) {
                    let mut list = std::mem::take(&mut st.settings.routes.list);
                    list.sort_by_key(|x| order.iter().position(|i| *i == x.id).unwrap_or(usize::MAX));
                    st.settings.routes.list = list;
                }
            }
        }
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
        let now = util::now();
        let warn = if !r.enabled || st.settings.routes.eff_entries(r) == 0 {
            String::new()
        } else {
            match &r.target {
                Target::Server(id) => match st.servers.iter().find(|s| &s.id == id) {
                    None => "Сервер удалён — трафик идёт через VPN".into(),
                    Some(s) if s.disabled => "Сервер отключён — трафик идёт через VPN".into(),
                    Some(s) if s.auth_error => "Требуется авторизация на сервере — трафик идёт через VPN".into(),
                    Some(s) if s.circuit_open(now) || s.probe.as_ref().is_some_and(|p| !p.ok) => "Сервер не отвечает — трафик идёт через VPN".into(),
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

    fn route_json(st: &State, r: &Route, priority: usize, connected: bool) -> Value {
        let warn = Self::target_warn(st, r, connected);
        let linked = st.settings.routes.eff_entries(r) - r.entries();
        json!({
            "id": r.id,
            "priority": priority,
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
        let list: Vec<Value> = st
            .settings
            .routes
            .list
            .iter()
            .enumerate()
            .map(|(idx, r)| Self::route_json(&st, r, idx + 1, connected))
            .collect();
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
            "default_label": label(&st, &st.settings.routes.default),
            "default_warn": if match &st.settings.routes.default {
                Target::Chain(id) => st.settings.routes.chain(id).is_none_or(|c| Self::chain_plan(&st, c).is_none()),
                t if t.uses_servers() => Self::route_servers(&st, t).is_empty(),
                _ => false,
            } || (connected && st.route_spare.contains(mihomo::DEFAULT_ROUTE)) { "Выбранное направление недоступно — пока используется VPN" } else { "" },
            "routes": list,
            "chains": chains,
            "lists": lists,
            "issues": smart::lint(&st.settings.routes).into_iter().map(|i| i.text).collect::<Vec<_>>(),
            "countries": countries,
            "warp": warp,
            "warp_good": st.servers.iter().any(|s| s.origin == Origin::Warp && s.good()),
            "warp_note": super::warp_note(&st),
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
                    let paused_or_blocked = { let st = me.st.lock().unwrap(); st.warp_retry > util::now() || st.netp.as_ref().is_some_and(NetProfile::cf_blocked) };
                    if !paused_or_blocked {
                        let ids: Vec<String> = me.st.lock().unwrap().servers.iter().filter(|s| s.origin == Origin::Warp).map(|s| s.id.clone()).collect();
                        me.clone().check_ids(ids).await;
                    }
                }
                Err(e) => me.log(&format!("WARP: {e}")),
            }
        });
    }

    pub(super) async fn route_default(self: &Arc<Self>, target: &str) -> Result<Value, String> {
        let t = Self::parse_target(target)?;
        match &t {
            Target::Vpn | Target::Direct | Target::Country(_) | Target::Warp => {}
            Target::Server(id) => { if !self.st.lock().unwrap().servers.iter().any(|s| &s.id == id) { return Err("сервер не найден".into()); } }
            Target::Chain(cid) => {
                if self.st.lock().unwrap().settings.routes.chain(cid).is_none() {
                    return Err("цепочка не найдена".into());
                }
            }
            Target::Block => return Err("остальной трафик нельзя заблокировать этим выбором".into()),
        }
        self.want_warp(&t);
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

    /// A chain with a WARP hop needs the WARP device registered.
    fn want_warp_hops(self: &Arc<Self>, hops: &[Hop]) {
        if hops.contains(&Hop::Warp) {
            self.want_warp(&Target::Warp);
        }
    }

    pub(super) async fn chain_add(self: &Arc<Self>, name: &str, hops: &[String]) -> Result<Value, String> {
        let hops = Self::parse_hops(hops)?;
        self.want_warp_hops(&hops);
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
        if let Some(h) = &hops {
            self.want_warp_hops(h);
        }
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
            None => {
                // a plain folder: tell where it is used instead
                let used: Vec<String> = st.settings.routes.list.iter().filter(|r| r.lists.contains(&l.id)).map(|r| format!("«{}» ({})", r.name, label(st, &r.target))).collect();
                (String::new(), if used.is_empty() { String::new() } else { format!("В маршрутах: {}", used.join(", ")) }, String::new())
            }
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
            // a direction for a list means a route with the list attached
            st.settings.routes.lists_to_routes();
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
        let connected = self.connected();
        let st = self.st.lock().unwrap();
        let idx = st.settings.routes.list.iter().position(|r| r.id == id).unwrap_or(0);
        let r = st.settings.routes.get(&id).cloned().ok_or("маршрут не найден")?;
        Ok(Self::route_json(&st, &r, idx + 1, connected))
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
                let idx = st.settings.routes.list.iter().position(|r| r.id == id).unwrap_or(0);
                let r = st.settings.routes.get(&id).cloned().ok_or("маршрут не найден")?;
                let mut v = Self::route_json(&st, &r, idx + 1, connected);
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

    /// "Where will this go?" in plain words, including rule priority, hop sequence, and availability.
    pub(super) fn route_explain(&self, query: &str) -> Value {
        let connected = self.connected();
        let st = self.st.lock().unwrap();
        let ex = smart::explain(&st.settings.routes, query);
        let what = match &ex.subject {
            smart::Subject::Site(s) => match ex.port {
                Some(p) => format!("{s}:{p}"),
                None => s.clone(),
            },
            smart::Subject::App(a) => a.clone(),
            smart::Subject::Invalid => return json!({ "ok": false, "text": "Не похоже на адрес сайта, IP или имя программы (.exe)" }),
        };
        let mut lines: Vec<String> = Vec::new();
        let chosen_target = ex.target();
        match ex.winner() {
            Some(h) => {
                let why = if Some(&h.entry) == match &ex.subject { smart::Subject::Site(s) => Some(s), smart::Subject::App(a) => Some(a), _ => None } {
                    format!("«{}» (Приоритет № {})", h.name, h.priority)
                } else {
                    format!("«{}» (Приоритет № {}, совпадение: {})", h.name, h.priority, h.entry)
                };
                lines.push(format!("{what} → {}. Решает маршрут {why}.", label(&st, &h.target)));
                lines.push(format!("Цепочка прохождения: {}.", explain_path(&st, &h.target)));
                if let Some(unit) = st.settings.routes.units().into_iter().find(|u| u.id == h.unit_id) {
                    let w = Self::target_warn(&st, &unit, connected);
                    if !w.is_empty() {
                        lines.push(format!("Внимание: {w}."));
                    }
                }
                for o in ex.hits.iter().skip(1) {
                    lines.push(format!("Также подходит маршрут № {} «{}» ({}), но он ниже по приоритету — не сработает.", o.priority, o.name, label(&st, &o.target)));
                }
            }
            None => {
                lines.push(format!("{what} → {}. Ни один специальный маршрут не подошёл — действует правило «Остальной трафик».", label(&st, &ex.default)));
                lines.push(format!("Цепочка прохождения: {}.", explain_path(&st, &ex.default)));
            }
        }
        if ex.port == Some(80) && st.settings.https_only_free {
            let mode = if st.settings.http_allow_direct { "напрямую (мимо публичных серверов)" } else { "только через свой сервер/WARP или блокируется (защита от перехвата HTTP)" };
            lines.push(format!("Порт 80 (нешифрованный HTTP): {mode}."));
        }
        json!({ "ok": true, "text": lines.join("\n"), "target": chosen_target.code() })
    }

    /// One-step rule: `value` (a site or a program) goes to `target`. The route that
    /// already has that direction takes it (the first enabled one; a disabled one is
    /// switched on only when it is the sole candidate), else a new route named after the
    /// direction appears. The entry leaves every other route.
    pub(super) async fn route_quick(self: &Arc<Self>, value: &str, target: &str) -> Result<Value, String> {
        let t = Self::parse_target(target)?;
        let v = value.trim();
        let app = smart::looks_app(v);
        let entry = if app { split::normalize_app(v)? } else { split::normalize_site(v)? };
        let (before, id, name, created) = {
            let mut st = self.st.lock().unwrap();
            let before = st.settings.routes.clone();
            let found = st.settings.routes.list.iter().find(|r| r.enabled && r.target == t).or_else(|| st.settings.routes.list.iter().find(|r| r.target == t)).map(|r| r.id.clone());
            let (id, created) = match found {
                Some(id) => (id, false),
                None => {
                    if st.settings.routes.list.len() >= MAX_ROUTES {
                        return Err(format!("Можно создать не больше {MAX_ROUTES} маршрутов"));
                    }
                    let name = match &t {
                        Target::Country(cc) => countries::name(cc).map(str::to_string).unwrap_or_else(|| cc.clone()),
                        Target::Block => "Блокировка".into(),
                        other => label(&st, other),
                    };
                    let r = Route::new(&name, t.clone());
                    let id = r.id.clone();
                    st.settings.routes.list.push(r);
                    (id, true)
                }
            };
            st.settings.routes.add_entry(&id, app, &entry)?;
            if let Some(r) = st.settings.routes.get_mut(&id) {
                r.enabled = true;
            }
            let name = st.settings.routes.get(&id).map(|r| r.name.clone()).unwrap_or_default();
            (before, id, name, created)
        };
        self.want_warp(&t);
        self.routes_changed(&before).await?;
        let st = self.st.lock().unwrap();
        let text = format!("{entry} → {} (маршрут «{name}»{})", label(&st, &t), if created { ", создан" } else { "" });
        Ok(json!({ "id": id, "name": name, "created": created, "text": text }))
    }

    pub(super) fn route_export(&self, id: &str, kind: Kind) -> Result<Value, String> {
        let st = self.st.lock().unwrap();
        let r = st.settings.routes.get(id).ok_or("маршрут не найден")?;
        let v = r.list(kind == Kind::App);
        Ok(json!({ "text": v.join("\n") + "\n" }))
    }

    /// Watch over routes with their own servers (from the watchdog): which of them use
    /// the VPN as a spare right now; their servers are re-tested and dead servers are
    /// marked failed + circuit-broken so mihomo stops hammering dead IPs in `R-<id>-s`.
    pub(super) async fn route_health(self: &Arc<Self>, api: &mihomo::Api) {
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
        let mut evicted_any = false;
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
                    if let Via::Servers(sids) = &p.via {
                        for sid in sids {
                            if !alive.contains_key(sid) {
                                self.mark_failed(sid);
                                evicted_any = true;
                            }
                        }
                    }
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
        if evicted_any {
            self.save_servers();
            self.apply_pool().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(host: &str, origin: Origin) -> Server {
        let p = serde_json::json!({"type":"trojan","server":host,"port":443,"password":"x"});
        let mut s = Server::new(host, p.as_object().unwrap().clone(), origin, "test").unwrap();
        s.probe = Some(Probe { ok: true, latency: Some(20), exit_ip: Some("203.0.113.9".into()), exit_cc: Some("NL".into()), ..Default::default() });
        s
    }

    #[test]
    fn warp_chain_reuses_neither_pool_key_nor_later_vpn_as_direct() {
        let path = std::env::temp_dir().join(format!("lazeyka-chain-test-{}", util::random_token(10)));
        let e = Engine::new(Paths { data: path.clone(), bin: path.clone() }, "test");
        let free = server("198.51.100.2", Origin::Free);
        let warp = server("198.51.100.3", Origin::Warp);
        let chain = Chain::new("WARP → VPN", vec![Hop::Warp, Hop::Auto]);
        {
            let mut st = e.st.lock().unwrap();
            st.servers = vec![free.clone(), warp.clone()];
            st.settings.routes.chains.push(chain.clone());
            st.settings.routes.default = Target::Chain(chain.id.clone());
        }
        assert!(!e.pool().iter().any(|s| s.origin == Origin::Warp));
        {
            let mut st = e.st.lock().unwrap();
            let plan = Engine::chain_plan(&st, &chain).unwrap();
            assert!(plan.levels[0][0]["name"].as_str().unwrap().starts_with(&warp.id));
            assert!(plan.levels[1][0]["name"].as_str().unwrap().starts_with(&free.id));
            st.settings.selected = Some(warp.id.clone());
            assert!(Engine::chain_plan(&st, &chain).is_none());
            st.settings.selected = None;
            let mut r = Route::new("direct warp", Target::Warp);
            r.sites.push("example.com".into());
            st.settings.routes.list.push(r);
            assert!(Engine::chain_plan(&st, &chain).is_none());
        }
        let _ = std::fs::remove_dir_all(path);
    }

    #[test]
    fn default_server_gets_virtual_plan_and_evicts_dead_server() {
        let path = std::env::temp_dir().join(format!("lazeyka-default-test-{}", util::random_token(10)));
        let e = Engine::new(Paths { data: path.clone(), bin: path.clone() }, "test");
        let s = server("95.213.245.84", Origin::Free);
        {
            let mut st = e.st.lock().unwrap();
            st.servers.push(s.clone());
            st.settings.routes.default = Target::Server(s.id.clone());
        }
        let (plans, extra, _, _) = e.route_plans(&[]);
        assert!(plans.iter().any(|p| p.id == mihomo::DEFAULT_ROUTE && p.via == Via::Servers(vec![s.id.clone()])));
        assert!(extra.iter().any(|x| x.id == s.id));

        // When 95.213.245.84 fails, mark_failed evicts it from R-__default-s so it is no longer hammered
        e.mark_failed(&s.id);
        let (plans2, extra2, _, _) = e.route_plans(&[]);
        assert!(plans2.iter().all(|p| p.id != mihomo::DEFAULT_ROUTE));
        assert!(extra2.is_empty());
        let _ = std::fs::remove_dir_all(path);
    }
}
