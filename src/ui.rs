//! UI process: the main window and the tray icon. The VPN itself runs in the engine
//! (a Windows service); the UI only talks to it over the local pipe and never needs
//! administrator rights except for the one-time service installation.

use crate::sys;
use lazeyka_core::engine::{ConnState, ServerView, StatusView};
use lazeyka_core::model::{Origin, SVC_DISCORD, SVC_TELEGRAM, SVC_YOUTUBE};
use lazeyka_core::{countries, ipc, smart, util};
use serde_json::{Value, json};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering::Relaxed};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

slint::include_modules!();

const VERSION: &str = env!("CARGO_PKG_VERSION");
const STACKS: [&str; 3] = ["gvisor", "mixed", "system"];
const SORTS: [&str; 4] = ["best", "ping", "speed", "stable"];
const AUTO_SUB: &str = "Лучший сервер, переключение при сбое";
const MAX_ROWS: usize = 250;

// ------------------------------------------------------------------ formatting

fn ss(s: impl AsRef<str>) -> SharedString {
    s.as_ref().into()
}

fn dec1(v: f64) -> String {
    format!("{v:.1}").replace('.', ",")
}

pub fn fmt_bytes(b: u64) -> String {
    const U: [&str; 5] = ["Б", "КБ", "МБ", "ГБ", "ТБ"];
    if b < 1000 {
        return format!("{b} Б");
    }
    let mut v = b as f64;
    let mut i = 0;
    while v >= 1000.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if v < 10.0 { format!("{} {}", dec1(v), U[i]) } else { format!("{v:.0} {}", U[i]) }
}

pub fn fmt_rate(bps: u64) -> String {
    format!("{}/с", fmt_bytes(bps))
}

/// Download speed in kbit/s → "94 Мбит/с".
pub fn fmt_speed(kbit: u32) -> String {
    match kbit {
        0 => String::new(),
        1..1000 => format!("{kbit} кбит/с"),
        _ => {
            let m = kbit as f64 / 1000.0;
            if m < 10.0 { format!("{} Мбит/с", dec1(m)) } else { format!("{m:.0} Мбит/с") }
        }
    }
}

pub fn fmt_duration(secs: u64) -> String {
    format!("{:02}:{:02}:{:02}", secs / 3600, secs / 60 % 60, secs % 60)
}

/// Local "дд.мм.гггг чч:мм" for a unix time.
pub fn fmt_date(ts: u64) -> String {
    let t = ts as i64 + sys::local_offset();
    let (days, sec) = (t.div_euclid(86400), t.rem_euclid(86400));
    // civil from days (H. Hinnant)
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{d:02}.{m:02}.{y} {:02}:{:02}", sec / 3600, sec / 60 % 60)
}

/// Russian plural: plural(5, "сервер", "сервера", "серверов").
pub fn plural<'a>(n: usize, one: &'a str, few: &'a str, many: &'a str) -> &'a str {
    let (d, h) = (n % 10, n % 100);
    if d == 1 && h != 11 {
        one
    } else if (2..=4).contains(&d) && !(12..=14).contains(&h) {
        few
    } else {
        many
    }
}

fn country(cc: &str) -> String {
    if cc.is_empty() {
        return String::new();
    }
    countries::name(cc).map(str::to_string).unwrap_or_else(|| cc.to_ascii_uppercase())
}

fn version_parts(v: &str) -> Vec<u32> {
    v.split(|c: char| !c.is_ascii_digit()).filter_map(|x| x.parse().ok()).collect()
}

/// True if version `a` is newer than `b`.
pub fn newer(a: &str, b: &str) -> bool {
    version_parts(a) > version_parts(b)
}

/// A route as the engine reports it (`routes` request).
#[derive(serde::Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default)]
struct RouteJs {
    id: String,
    name: String,
    enabled: bool,
    target: String,
    /// "fastest" | "warp" | "direct" | "block".
    fallback: String,
    strategy: String,
    label: String,
    warn: String,
    sites: Vec<String>,
    apps: Vec<String>,
    /// Attached entry-list ids.
    lists: Vec<String>,
    /// Entries the attached lists add on top of the route's own.
    linked: usize,
}

/// A chain as the engine reports it (`routes` request).
#[derive(serde::Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default)]
struct ChainJs {
    id: String,
    name: String,
    label: String,
    warn: String,
    hops: Vec<HopJs>,
}

#[derive(serde::Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default)]
struct HopJs {
    code: String,
    label: String,
}

/// An entry list ("folder") as the engine reports it.
#[derive(serde::Deserialize, Default, Clone, Debug, PartialEq)]
#[serde(default)]
struct ListJs {
    id: String,
    name: String,
    sites: Vec<String>,
    apps: Vec<String>,
    /// The list's own direction code ("" = routes only).
    target: String,
    label: String,
    warn: String,
}

/// Badge kind and country code of a route target.
fn route_kind(target: &str) -> (&'static str, String) {
    match target {
        "direct" => ("direct", String::new()),
        "vpn" => ("vpn", String::new()),
        "warp" => ("warp", String::new()),
        "block" => ("block", String::new()),
        t => {
            if let Some(cc) = t.strip_prefix("country:") {
                ("country", cc.to_string())
            } else if t.starts_with("chain:") {
                ("chain", String::new())
            } else {
                ("server", String::new())
            }
        }
    }
}

/// Display label of one chain hop code.
fn hop_label(sh: &Shared, code: &str) -> String {
    if code == "vpn" {
        return "VPN".into();
    }
    if code == "warp" {
        return "WARP".into();
    }
    if let Some(cc) = code.strip_prefix("country:") {
        return country(cc);
    }
    if let Some(id) = code.strip_prefix("server:") {
        return sh.servers.iter().find(|s| s.id == id).map(|s| util::clip(&s.name, 26)).unwrap_or_else(|| "удалён".into());
    }
    code.to_string()
}

fn route_summary(r: &RouteJs) -> String {
    let (s, a) = (r.sites.len(), r.apps.len());
    let sites = format!("{s} {}", plural(s, "сайт", "сайта", "сайтов"));
    let apps = format!("{a} {}", plural(a, "программа", "программы", "программ"));
    let base = match (s, a) {
        (0, 0) => {
            if r.linked > 0 {
                return format!("{} из списков", plural(r.linked, "запись", "записи", "записей"));
            }
            "пока пусто".into()
        }
        (_, 0) => sites,
        (0, _) => apps,
        _ => format!("{sites} · {apps}"),
    };
    if r.linked > 0 {
        format!("{base} · +{} из списков", r.linked)
    } else {
        base
    }
}

fn route_item(r: &RouteJs, i: usize, n: usize) -> RouteItem {
    let (kind, cc) = route_kind(&r.target);
    RouteItem {
        id: ss(&r.id),
        name: ss(&r.name),
        enabled: r.enabled,
        target: ss(&r.target),
        kind: ss(kind),
        cc: ss(cc),
        label: ss(&r.label),
        summary: ss(route_summary(r)),
        warn: ss(&r.warn),
        fallback: ss(if r.fallback.is_empty() { "fastest" } else { &r.fallback }),
        strategy: ss(if r.strategy.is_empty() { "failover" } else { &r.strategy }),
        first: i == 0,
        last: i + 1 >= n,
    }
}

fn kind_name(k: i32) -> &'static str {
    if k == 1 { "app" } else { "site" }
}

fn item(s: &ServerView, selected: Option<&str>) -> ServerItem {
    ServerItem {
        id: ss(&s.id),
        name: ss(&s.name),
        cc: ss(&s.cc),
        country: ss(country(&s.cc)),
        proto: ss(&s.proto),
        transport: ss(&s.transport),
        latency: s.latency as i32,
        speed: ss(fmt_speed(s.speed)),
        ok: s.ok,
        tested: s.tested,
        udp: s.udp,
        yt: s.services & SVC_YOUTUBE != 0,
        dc: s.services & SVC_DISCORD != 0,
        tg: s.services & SVC_TELEGRAM != 0,
        mine: s.origin == Origin::Mine,
        warp: s.origin == Origin::Warp,
        selected: selected == Some(s.id.as_str()),
        in_pool: s.in_pool,
        error: ss(&s.error),
        fav: s.fav,
        stability: ss(if s.stab >= 0 { format!("{}%", s.stab) } else { String::new() }),
        checks: ss(if s.checks > 0 {
            format!("{} {}", s.checks, plural(s.checks as usize, "проверка", "проверки", "проверок"))
        } else {
            String::new()
        }),
        address: ss(match (s.host.as_str(), s.port) {
            ("", _) => String::new(),
            (h, p) if h.contains(':') => format!("[{h}]:{p}"),
            (h, p) => format!("{h}:{p}"),
        }),
        checked: ss(if s.at > 0 { fmt_date(s.at) } else { String::new() }),
    }
}

/// Order of the visible list: favourites first, then the chosen sorting. The engine
/// already sends the list in "best" order (the same score the automatic choice uses).
fn sort_servers(v: &mut [&ServerView], sort: i32) {
    use std::cmp::Reverse;
    match sort {
        1 => v.sort_by_key(|s| (!s.ok, if s.ok { s.latency } else { u32::MAX })),
        2 => v.sort_by_key(|s| (!s.ok, Reverse(s.speed), s.latency)),
        3 => v.sort_by_key(|s| (!s.ok, Reverse(s.stab), Reverse(s.checks), s.latency)),
        _ => {}
    }
    v.sort_by_key(|s| !s.fav);
}

/// Text of the country picker: "Все страны", "Нидерланды", "NL, DE", "NL, DE +2".
fn countries_text(cc: &[String]) -> String {
    match cc.len() {
        0 => "Все страны".into(),
        1 => country(&cc[0]),
        2 => format!("{}, {}", cc[0], cc[1]),
        n => format!("{}, {} +{}", cc[0], cc[1], n - 2),
    }
}

/// Subtitle of "Автовыбор" (and whether it is a warning).
pub fn auto_sub(cc: &[String], usable: bool) -> (String, bool) {
    let names = if cc.len() <= 2 { cc.iter().map(|c| country(c)).collect::<Vec<_>>().join(", ") } else { cc.join(", ") };
    match (cc.is_empty(), usable) {
        (true, _) => (AUTO_SUB.into(), false),
        (false, true) => (format!("Только {names}"), false),
        (false, false) => (format!("Нет рабочих в {} — используем любые", cc.join(", ")), true),
    }
}

fn source_stat(v: &Value) -> String {
    let n = |k: &str| v.get(k).and_then(Value::as_u64).unwrap_or(0) as usize;
    if let Some(e) = v.get("error").and_then(Value::as_str) {
        return format!("ошибка: {}", util::clip(e, 60));
    }
    let (parsed, tested, good) = (n("parsed"), n("tested"), n("good"));
    if tested > 0 {
        format!("{parsed} в списке · рабочих {good} из {tested} проверенных")
    } else if parsed > 0 {
        format!("{parsed} {} в списке", plural(parsed, "сервер", "сервера", "серверов"))
    } else {
        "ещё не загружался".into()
    }
}

// ------------------------------------------------------------------ models (UI thread)

struct Models {
    servers: Rc<VecModel<ServerItem>>,
    routes: Rc<VecModel<RouteItem>>,
    presets: Rc<VecModel<PresetItem>>,
    target_countries: Rc<VecModel<TargetItem>>,
    target_servers: Rc<VecModel<TargetItem>>,
    target_chains: Rc<VecModel<TargetItem>>,
    chain_hops: Rc<VecModel<TargetItem>>,
    lists: Rc<VecModel<ListItem>>,
    search_hits: Rc<VecModel<HitItem>>,
    sites: Rc<VecModel<SharedString>>,
    apps: Rc<VecModel<SharedString>>,
    sources: Rc<VecModel<SourceItem>>,
    subs: Rc<VecModel<SubItem>>,
    logs: Rc<VecModel<SharedString>>,
    procs: Rc<VecModel<SharedString>>,
    countries: Rc<VecModel<CountryItem>>,
}

thread_local! {
    static MODELS: RefCell<Option<Models>> = const { RefCell::new(None) };
}

fn with_models(f: impl FnOnce(&Models)) {
    MODELS.with(|m| {
        if let Some(m) = m.borrow().as_ref() {
            f(m)
        }
    });
}

/// Updates a model in place when the length is unchanged (keeps scroll position).
fn sync<T: Clone + PartialEq + 'static>(m: &VecModel<T>, items: Vec<T>) {
    if m.row_count() == items.len() {
        for (i, it) in items.into_iter().enumerate() {
            if m.row_data(i).as_ref() != Some(&it) {
                m.set_row_data(i, it);
            }
        }
    } else {
        m.set_vec(items);
    }
}

fn strings(v: &[String]) -> Vec<SharedString> {
    v.iter().map(ss).collect()
}

fn rgba(bytes: &[u8], size: u32) -> slint::Image {
    slint::Image::from_rgba8(slint::SharedPixelBuffer::<slint::Rgba8Pixel>::clone_from_slice(bytes, size, size))
}

// ------------------------------------------------------------------ controller

#[derive(Default)]
struct Shared {
    status: Option<StatusView>,
    servers: Vec<ServerView>,
    selected: Option<String>,
    routes: Vec<RouteJs>,
    chains: Vec<ChainJs>,
    lists: Vec<ListJs>,
    /// The default target code as the engine reports it ("vpn", "direct", "chain:<id>").
    route_default_code: String,
    /// Folder open in the list editor.
    list_open: Option<String>,
    /// Chain editor draft: (id, hop codes); an empty id means a new chain.
    chain_draft: Option<(String, Vec<String>)>,
    /// Hop slot the hop picker is filling (== hop count appends).
    hop_pick: Option<usize>,
    /// Route open in the editor.
    route_open: Option<String>,
    /// Countries with working servers: (code, name, count).
    route_countries: Vec<(String, String, usize)>,
    /// When the user last switched the default (status replies in flight may be older).
    route_default_at: Option<Instant>,
    procs: Vec<String>,
    proc_filter: String,
    link_up: bool,
    want_connect: bool,
    installing: bool,
    user_scan: bool,
    was_scanning: bool,
    list_key: String,
    list_at: Option<Instant>,
    /// Countries for the automatic choice and the list filter.
    countries: Vec<String>,
    /// When the user last changed them (status replies in flight may still be older).
    countries_at: Option<Instant>,
    /// Last engine notice shown (None until the first status).
    notice_id: Option<u64>,
    /// Installation waiting for the answer of the "folder" dialog: (connect after, update).
    pending_install: Option<(bool, bool)>,
    /// The user agreed to install into a folder with a warning.
    location_ok: bool,
}

pub struct Ctl {
    rt: tokio::runtime::Handle,
    client: ipc::Client,
    ui: slint::Weak<AppWindow>,
    tray: Option<slint::Weak<Tray>>,
    poke: tokio::sync::Notify,
    visible: AtomicBool,
    page: AtomicI32,
    filter: AtomicI32,
    sort: AtomicI32,
    sh: Mutex<Shared>,
}

impl Ctl {
    fn go(&self, f: impl Future<Output = ()> + Send + 'static) {
        self.rt.spawn(f);
    }

    /// Runs `f` on the UI thread with the window.
    fn ui(&self, f: impl FnOnce(&AppWindow) + Send + 'static) {
        let _ = self.ui.upgrade_in_event_loop(move |w| f(&w));
    }

    fn tray(&self, f: impl FnOnce(&Tray) + Send + 'static) {
        if let Some(t) = &self.tray {
            let _ = t.upgrade_in_event_loop(move |t| f(&t));
        }
    }

    fn toast(&self, msg: impl Into<String>) {
        let m: String = msg.into();
        self.ui(move |w| w.global::<App>().set_toast(ss(m)));
    }

    async fn call(&self, req: Value) -> Result<Value, String> {
        self.client.call(req).await
    }

    /// Request whose failure is reported as a toast.
    async fn act(&self, req: Value) -> Option<Value> {
        match self.call(req).await {
            Ok(v) => Some(v),
            Err(e) => {
                // A stale service answers new commands (chains, lists, the
                // rest-traffic switch) with raw protocol errors such as
                // "unknown variant". That is not a broken command, it is a
                // service that predates it: say so in plain words instead.
                let stale = self.sh.lock().unwrap().status.as_ref().filter(|st| newer(VERSION, &st.version)).map(|st| st.version.clone());
                match stale {
                    Some(v) => self.toast(format!("Служба Лазейки устарела (версия {v}). Обновите её на вкладке «Главная» кнопкой «Обновить» — после этого команда заработает.")),
                    None => self.toast(e),
                }
                None
            }
        }
    }

    fn link_up(&self) -> bool {
        self.sh.lock().unwrap().link_up
    }

    // ---------------- status

    async fn status_loop(self: Arc<Self>) {
        loop {
            self.refresh().await;
            let ms = if self.visible.load(Relaxed) { 1000 } else { 4000 };
            let _ = tokio::time::timeout(Duration::from_millis(ms), self.poke.notified()).await;
        }
    }

    async fn refresh(self: &Arc<Self>) {
        match self.client.call_timeout(json!({ "cmd": "status" }), Duration::from_secs(6)).await {
            Ok(v) => match serde_json::from_value::<StatusView>(v) {
                Ok(st) => self.on_status(st).await,
                Err(e) => self.on_link_down(format!("неожиданный ответ службы: {e}")).await,
            },
            Err(e) => self.on_link_down(e).await,
        }
    }

    async fn on_status(self: &Arc<Self>, st: StatusView) {
        let first = {
            let mut sh = self.sh.lock().unwrap();
            let f = !sh.link_up;
            sh.link_up = true;
            f
        };
        if first {
            self.load_settings().await;
            self.load_routes().await;
            self.load_sources().await;
            self.load_servers().await;
        }
        let want = std::mem::take(&mut self.sh.lock().unwrap().want_connect);
        if want && matches!(st.state, ConnState::Off | ConnState::Error) {
            let _ = self.call(json!({ "cmd": "connect" })).await;
        }
        let (svc, svc_text) = if newer(VERSION, &st.version) {
            (4, format!("Служба Лазейки устарела (версия {}). Обновите её до {VERSION}.", st.version))
        } else {
            (0, String::new())
        };
        // live list on the servers page
        let key = format!(
            "{}|{}|{}|{}|{:?}|{}|{:?}",
            st.good,
            st.mine,
            st.scan.done,
            st.scan.running,
            st.server.as_ref().map(|s| &s.id),
            st.auto,
            st.state
        );
        let mut countries_changed = false;
        let mut notice = None;
        let (reload, scan_done_toast) = {
            let mut sh = self.sh.lock().unwrap();
            let on_page = self.page.load(Relaxed) == 1 && self.visible.load(Relaxed);
            let due = sh.list_at.is_none_or(|t| t.elapsed() > Duration::from_secs(2));
            let reload = on_page && sh.list_key != key && due;
            if reload {
                sh.list_key = key;
            }
            let finished = sh.was_scanning && !st.scan.running;
            sh.was_scanning = st.scan.running;
            let fresh = sh.countries_at.is_some_and(|t| t.elapsed() < Duration::from_secs(4));
            if !fresh && sh.countries != st.countries {
                sh.countries = st.countries.clone();
                countries_changed = true;
            }
            let last = sh.notice_id.replace(st.notice_id);
            if last.is_some_and(|l| l != st.notice_id) && !st.notice.is_empty() {
                notice = Some(st.notice.clone());
            }
            let toast = if finished && std::mem::take(&mut sh.user_scan) {
                Some(match &st.scan.error {
                    Some(e) => format!("Поиск прерван: {e}"),
                    None => format!("Поиск завершён: рабочих серверов — {}", st.good),
                })
            } else {
                None
            };
            sh.status = Some(st.clone());
            (reload || finished, toast)
        };
        self.apply_status(st, svc, svc_text);
        if countries_changed {
            self.push_countries();
            self.push_servers();
        }
        if let Some(t) = scan_done_toast.or(notice) {
            self.toast(t);
        }
        if reload {
            self.load_servers().await;
        }
    }

    fn apply_status(&self, st: StatusView, svc: i32, svc_text: String) {
        let now = util::now();
        let state = match st.state {
            ConnState::Off => 0,
            ConnState::Connecting => 1,
            ConnState::On => 2,
            ConnState::Error => 3,
        };
        let state_text = ["Отключено", "Подключение…", "Подключено", "Ошибка"][state as usize];
        let message = match st.state {
            ConnState::Error => st.error.clone().or(st.message.clone()).unwrap_or_default(),
            ConnState::Connecting => st.message.clone().unwrap_or_else(|| "Ищем рабочий сервер…".into()),
            ConnState::On => st.message.clone().unwrap_or_default(),
            ConnState::Off => st.message.clone().unwrap_or_else(|| "Нажмите кнопку, чтобы подключиться".into()),
        };
        let timer = if state == 2 && st.since > 0 { fmt_duration(now.saturating_sub(st.since)) } else { String::new() };
        let (cur_name, cur_cc, cur_detail, cur_warp) = match &st.server {
            Some(s) => {
                let mut parts: Vec<String> = Vec::new();
                if st.auto {
                    parts.push("Автовыбор".into());
                }
                let c = country(&s.cc);
                if !c.is_empty() {
                    parts.push(c);
                }
                parts.push(s.proto.clone());
                if s.ok && s.latency > 0 {
                    parts.push(format!("{} мс", s.latency));
                }
                (s.name.clone(), s.cc.clone(), parts.join(" · "), s.origin == Origin::Warp)
            }
            None => {
                let detail = if st.good > 0 {
                    format!("Лучший из {} {}", st.good, plural(st.good, "рабочего сервера", "рабочих серверов", "рабочих серверов"))
                } else {
                    "Лучший из доступных серверов".into()
                };
                ("Автовыбор".into(), String::new(), detail, false)
            }
        };
        let p = &st.scan;
        let progress = if p.total > 0 { p.done as f32 / p.total as f32 } else { 0.0 };
        let stage = if p.stage.is_empty() { "Поиск серверов" } else { p.stage.as_str() };
        let scan_text = if p.total > 0 {
            format!("{stage}: {} из {} · найдено {}", p.done, p.total, p.good)
        } else {
            format!("{stage}…")
        };
        let tip = match st.state {
            ConnState::On => format!("Лазейка — подключено: {cur_name}"),
            ConnState::Connecting => "Лазейка — подключение…".into(),
            ConnState::Error => "Лазейка — ошибка подключения".into(),
            ConnState::Off => "Лазейка — VPN выключен".into(),
        };
        let (down, up) = (fmt_rate(st.down), fmt_rate(st.up));
        let totals = format!("↓ {} · ↑ {}", fmt_bytes(st.down_total), fmt_bytes(st.up_total));
        let totals_all = if st.down_all + st.up_all == 0 { String::new() } else { format!("Всего через VPN: ↓ {} · ↑ {}", fmt_bytes(st.down_all), fmt_bytes(st.up_all)) };
        let (upd_program, upd_mihomo) = (st.update_program.clone(), st.update_mihomo.clone());
        let route_default = if st.routes_default == "direct" { 1 } else { 0 };
        let set_default = self.sh.lock().unwrap().route_default_at.is_none_or(|t| t.elapsed() > Duration::from_secs(3));
        let (routes_on, routes_spare) = (st.routes_on as i32, st.routes_spare as i32);
        let (scanning, good, mine, auto, core) = (p.running, st.good as i32, st.mine as i32, st.auto, st.core.clone());
        let (auto_text, auto_warn) = auto_sub(&st.countries, st.countries_ok);
        self.ui(move |w| {
            let a = w.global::<App>();
            a.set_service(svc);
            a.set_service_text(ss(svc_text));
            a.set_state(state);
            a.set_state_text(ss(state_text));
            a.set_message(ss(message));
            a.set_timer(ss(timer));
            a.set_cur_name(ss(cur_name));
            a.set_cur_cc(ss(cur_cc));
            a.set_cur_detail(ss(cur_detail));
            a.set_cur_warp(cur_warp);
            a.set_auto(auto);
            a.set_down(ss(down));
            a.set_up(ss(up));
            a.set_totals(ss(totals));
            a.set_totals_all(ss(totals_all));
            a.set_upd_program(ss(upd_program));
            a.set_upd_mihomo(ss(upd_mihomo));
            a.set_scanning(scanning);
            a.set_scan_progress(progress);
            a.set_scan_text(ss(scan_text));
            a.set_good_count(good);
            a.set_mine_count(mine);
            if set_default {
                a.set_route_default(route_default);
            }
            a.set_routes_on(routes_on);
            a.set_routes_spare(routes_spare);
            a.set_auto_sub(ss(auto_text));
            a.set_auto_warn(auto_warn);
            if !core.is_empty() {
                a.set_core_version(ss(core));
            }
        });
        self.tray(move |t| {
            t.set_connected(state == 2);
            t.set_busy(state == 1);
            t.set_tip(ss(tip));
        });
    }

    async fn on_link_down(self: &Arc<Self>, _err: String) {
        let installing = {
            let mut sh = self.sh.lock().unwrap();
            sh.link_up = false;
            sh.status = None;
            sh.installing
        };
        let (svc, text) = if installing { (3, "Устанавливаем службу Лазейки…".to_string()) } else { self.service_hint().await };
        self.ui(move |w| {
            let a = w.global::<App>();
            a.set_service(svc);
            a.set_service_text(ss(text));
            a.set_state(0);
            a.set_state_text(ss("Отключено"));
            a.set_message(ss(""));
            a.set_timer(ss(""));
            a.set_scanning(false);
        });
        self.tray(|t| {
            t.set_connected(false);
            t.set_busy(false);
            t.set_tip(ss("Лазейка — служба недоступна"));
        });
    }

    #[cfg(windows)]
    async fn service_hint(&self) -> (i32, String) {
        use crate::win::{Svc, service_state};
        match tokio::task::spawn_blocking(service_state).await.unwrap_or(Svc::Unknown) {
            Svc::Missing => (
                1,
                "Для работы VPN нужна служба Лазейки. Нажмите кнопку подключения — Windows один раз попросит разрешение администратора.".into(),
            ),
            Svc::Stopped => (2, "Служба Лазейки остановлена.".into()),
            Svc::Pending => (2, "Служба Лазейки запускается…".into()),
            _ => (2, "Нет связи со службой Лазейки.".into()),
        }
    }

    #[cfg(not(windows))]
    async fn service_hint(&self) -> (i32, String) {
        (2, "Движок не запущен. Запустите «lazeyka --engine» с правами root.".into())
    }

    // ---------------- service installation / start (Windows)

    /// Makes the engine reachable: installs or starts the service as needed.
    async fn ensure_service(self: &Arc<Self>, connect_after: bool) {
        #[cfg(windows)]
        {
            use crate::win::{Svc, service_state, start_service};
            match tokio::task::spawn_blocking(service_state).await.unwrap_or(Svc::Unknown) {
                Svc::Missing => self.install(connect_after, false).await,
                Svc::Stopped => {
                    self.sh.lock().unwrap().want_connect |= connect_after;
                    match tokio::task::spawn_blocking(start_service).await {
                        Ok(Ok(())) => {
                            self.ui(|w| {
                                let a = w.global::<App>();
                                a.set_service_text(ss("Служба Лазейки запускается…"));
                            });
                            self.poke.notify_one();
                        }
                        // e.g. the service configuration got damaged: reinstall
                        _ => self.install(connect_after, true).await,
                    }
                }
                Svc::Pending => {
                    self.sh.lock().unwrap().want_connect |= connect_after;
                    self.toast("Служба Лазейки запускается, подождите несколько секунд");
                }
                _ => self.toast("Нет связи со службой Лазейки. Попробуйте ещё раз через несколько секунд."),
            }
        }
        #[cfg(not(windows))]
        {
            let _ = connect_after;
            self.toast("Движок не запущен. Запустите «lazeyka --engine».");
        }
    }

    #[cfg(windows)]
    async fn install(self: &Arc<Self>, connect_after: bool, update: bool) {
        if self.sh.lock().unwrap().installing {
            return;
        }
        // the folder becomes the program's home for the first time: is it a good place?
        let (home, new_home) = tokio::task::spawn_blocking(crate::win::planned_home).await.unwrap_or_else(|_| (std::path::PathBuf::new(), false));
        if new_home && !std::mem::take(&mut self.sh.lock().unwrap().location_ok) {
            let h = home.clone();
            let place = tokio::task::spawn_blocking(move || crate::win::assess(&h)).await.unwrap_or_default();
            if place.blocker.is_some() || !place.risks.is_empty() {
                let blocked = place.blocker.is_some();
                let text = match place.blocker {
                    Some(b) => b,
                    None => format!(
                        "Лазейка будет работать прямо из этой папки:\n{}\n\n{}\n\nНадёжнее перенести папку Лазейки, например, в C:\\Lazeyka и запустить программу оттуда. Продолжить установку здесь?",
                        home.display(),
                        place.risks.join("\n")
                    ),
                };
                self.sh.lock().unwrap().pending_install = Some((connect_after, update));
                self.ui(move |w| {
                    let a = w.global::<App>();
                    a.set_location_text(ss(text));
                    a.set_location_blocked(blocked);
                    a.set_dialog(ss("location"));
                });
                return;
            }
        }
        {
            let mut sh = self.sh.lock().unwrap();
            if sh.installing {
                return;
            }
            sh.installing = true;
            sh.want_connect |= connect_after;
        }
        let busy_text = if update { "Обновляем службу Лазейки…" } else { "Устанавливаем службу Лазейки…" };
        self.ui(move |w| {
            let a = w.global::<App>();
            a.set_service(3);
            a.set_service_text(ss(busy_text));
        });
        let result_file = std::env::temp_dir().join(format!("lazeyka-install-{}-{}.txt", std::process::id(), util::now()));
        let rf = result_file.clone();
        let r = tokio::task::spawn_blocking(move || crate::win::run_elevated(&format!("--install --result \"{}\"", rf.display())))
            .await
            .unwrap_or_else(|e| Err(e.to_string()));
        let read = || std::fs::read_to_string(&result_file).map(|s| s.trim().to_string()).ok().filter(|s| !s.is_empty());
        let (failure, warning) = match r {
            Ok(0) => (None, None),
            Ok(3) => (None, read()),
            Ok(_) => (Some(read().unwrap_or_else(|| "неизвестная ошибка".into())), None),
            Err(e) if e == "cancelled" => (Some("установка отменена".into()), None),
            Err(e) => (Some(e), None),
        };
        let _ = std::fs::remove_file(&result_file);
        let mut hand_over = None;
        if failure.is_none() {
            let home_exe = tokio::task::spawn_blocking(crate::win::home_exe).await.ok().flatten();
            let me = std::env::current_exe().ok();
            let target = home_exe.clone().or(me.clone()).unwrap_or_default();
            if !update || sys::autostart_enabled() {
                let ok = sys::set_autostart(true, &target);
                self.ui(move |w| w.global::<App>().set_autostart(ok));
            }
            let dir = target.parent().map(|d| d.display().to_string()).unwrap_or_default();
            self.ui(move |w| w.global::<App>().set_home_dir(ss(dir)));
            // wait until the service answers
            for _ in 0..40 {
                if self.client.call_timeout(json!({ "cmd": "ping" }), Duration::from_secs(2)).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            // this copy only brought an update for the program in another folder
            if let (Some(h), Some(m)) = (home_exe, me) {
                if !crate::win::same_path(&h, &m) {
                    hand_over = Some(h);
                }
            }
        }
        {
            let mut sh = self.sh.lock().unwrap();
            sh.installing = false;
            if failure.is_some() {
                sh.want_connect = false;
            }
        }
        if let Some(h) = hand_over {
            if std::mem::take(&mut self.sh.lock().unwrap().want_connect) {
                let _ = self.call(json!({ "cmd": "connect" })).await;
            }
            if std::process::Command::new(&h).arg("--replace").spawn().is_ok() {
                self.quit(false);
                return;
            }
        }
        match (failure, warning) {
            (Some(e), _) => self.toast(format!("Служба не установлена: {e}")),
            (None, Some(w)) => self.toast(w),
            (None, None) if update => self.toast("Служба обновлена"),
            (None, None) => self.toast("Служба установлена. Лазейка работает из этой папки — не удаляйте и не перемещайте её"),
        }
        self.poke.notify_one();
    }

    #[cfg(not(windows))]
    async fn install(self: &Arc<Self>, _connect_after: bool, _update: bool) {
        self.toast("Установка службы доступна только в Windows");
    }

    // ---------------- loaders

    async fn load_settings(self: &Arc<Self>) {
        let Ok(v) = self.call(json!({ "cmd": "settings" })).await else { return };
        let b = |k: &str, d: bool| v.get(k).and_then(Value::as_bool).unwrap_or(d);
        let (cos, warp, strict, ipv6) = (b("connect_on_start", false), b("warp", true), b("strict_route", true), b("ipv6", true));
        let (auto_update, relay_scan) = (b("auto_update", true), b("relay_scan", true));
        let net_summary = v.get("net_summary").and_then(Value::as_str).unwrap_or("").to_string();
        let warp_note = v.get("warp_note").and_then(Value::as_str).unwrap_or("").to_string();
        let stack = v.get("stack").and_then(Value::as_str).and_then(|s| STACKS.iter().position(|x| *x == s)).unwrap_or(0) as i32;
        let sort = v.get("sort").and_then(Value::as_str).and_then(|s| SORTS.iter().position(|x| *x == s)).unwrap_or(0) as i32;
        let countries: Vec<String> =
            v.get("countries").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
        let autostart = sys::autostart_enabled();
        let resort = self.sort.swap(sort, Relaxed) != sort;
        {
            let mut sh = self.sh.lock().unwrap();
            if sh.countries_at.is_none_or(|t| t.elapsed() > Duration::from_secs(4)) {
                sh.countries = countries;
            }
        }
        self.push_countries();
        if resort {
            self.push_servers();
        }
        self.ui(move |w| {
            let a = w.global::<App>();
            a.set_connect_on_start(cos);
            a.set_warp(warp);
            a.set_warp_note(ss(warp_note));
            a.set_net_summary(ss(net_summary));
            a.set_strict_route(strict);
            a.set_ipv6(ipv6);
            a.set_auto_update(auto_update);
            a.set_relay_scan(relay_scan);
            a.set_stack(stack);
            a.set_autostart(autostart);
            a.set_sort(sort);
        });
    }

    async fn load_routes(self: &Arc<Self>) {
        let Ok(v) = self.call(json!({ "cmd": "routes" })).await else { return };
        let list: Vec<RouteJs> = v.get("routes").cloned().and_then(|x| serde_json::from_value(x).ok()).unwrap_or_default();
        let chains: Vec<ChainJs> = v.get("chains").cloned().and_then(|x| serde_json::from_value(x).ok()).unwrap_or_default();
        let lists: Vec<ListJs> = v.get("lists").cloned().and_then(|x| serde_json::from_value(x).ok()).unwrap_or_default();
        let default_code = v.get("default").and_then(Value::as_str).unwrap_or("vpn").to_string();
        let countries: Vec<(String, String, usize)> = v
            .get("countries")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|c| {
                        (
                            c["cc"].as_str().unwrap_or("").to_string(),
                            c["name"].as_str().unwrap_or("").to_string(),
                            c["count"].as_u64().unwrap_or(0) as usize,
                        )
                    })
                    .collect()
            })
            .unwrap_or_default();
        let default = if default_code == "direct" { 1 } else { 0 };
        let default_chain = default_code
            .strip_prefix("chain:")
            .and_then(|id| chains.iter().find(|c| c.id == id))
            .map(|c| c.name.clone())
            .unwrap_or_default();
        let has_chains = !chains.is_empty();
        let issues: Vec<String> = v.get("issues").and_then(|x| serde_json::from_value(x.clone()).ok()).unwrap_or_default();
        let issues_text = issues.iter().take(4).map(|t| format!("• {t}")).collect::<Vec<_>>().join("\n");
        let warp_note = v.get("warp_note").and_then(Value::as_str).unwrap_or("").to_string();
        let set_default = {
            let mut sh = self.sh.lock().unwrap();
            sh.routes = list.clone();
            sh.chains = chains;
            sh.lists = lists;
            sh.route_default_code = default_code;
            sh.route_countries = countries;
            if sh.route_open.as_ref().is_some_and(|id| !list.iter().any(|r| &r.id == id)) {
                sh.route_open = None;
            }
            if sh.list_open.as_ref().is_some_and(|id| !sh.lists.iter().any(|l| &l.id == id)) {
                sh.list_open = None;
            }
            sh.route_default_at.is_none_or(|t| t.elapsed() > Duration::from_secs(3))
        };
        let n = list.len();
        let items: Vec<RouteItem> = list.iter().enumerate().map(|(i, r)| route_item(r, i, n)).collect();
        self.ui(move |w| {
            let a = w.global::<App>();
            if set_default {
                a.set_route_default(default);
            }
            a.set_has_chains(has_chains);
            a.set_route_issues(ss(issues_text));
            a.set_warp_note(ss(warp_note));
            a.set_default_chain_name(ss(default_chain));
            with_models(|m| sync(&m.routes, items));
        });
        self.push_route();
        self.push_lists();
        if self.sh.lock().unwrap().list_open.is_some() {
            self.push_list();
        }
        self.push_procs();
    }

    /// Shows the open route in the editor (or the list when it is gone).
    fn push_route(&self) {
        let (route, open, folder_open) = {
            let sh = self.sh.lock().unwrap();
            let n = sh.routes.len();
            let r = match sh.route_open.as_ref().and_then(|id| sh.routes.iter().position(|r| &r.id == id)) {
                Some(i) => (Some((route_item(&sh.routes[i], i, n), strings(&sh.routes[i].sites), strings(&sh.routes[i].apps))), true),
                None => (None, false),
            };
            (r.0, r.1, sh.list_open.is_some())
        };
        self.ui(move |w| {
            let a = w.global::<App>();
            match route {
                Some((item, sites, apps)) => {
                    a.set_route(item);
                    // While the folder editor is open, sites/apps show the folder's entries.
                    if !folder_open {
                        with_models(|m| {
                            sync(&m.sites, sites);
                            sync(&m.apps, apps);
                        });
                    }
                }
                None => {
                    if !open {
                        a.set_route_open(false);
                    }
                }
            }
        });
    }

    /// Choices of the direction picker: countries with working servers and the servers.
    fn push_targets(&self) {
        let (countries, servers, chains) = {
            let sh = self.sh.lock().unwrap();
            let chains: Vec<TargetItem> = sh
                .chains
                .iter()
                .map(|c| TargetItem {
                    code: ss(format!("chain:{}", c.id)),
                    title: ss(&c.name),
                    subtitle: ss(if c.warn.is_empty() { c.label.clone() } else { c.warn.clone() }),
                    cc: ss(""),
                    warp: false,
                    ok: c.warn.is_empty(),
                })
                .collect();
            let countries: Vec<TargetItem> = sh
                .route_countries
                .iter()
                .map(|(cc, name, n)| TargetItem {
                    code: ss(format!("country:{cc}")),
                    title: ss(name),
                    subtitle: ss(format!("{n} {}", plural(*n, "рабочий сервер", "рабочих сервера", "рабочих серверов"))),
                    cc: ss(cc),
                    warp: false,
                    ok: true,
                })
                .collect();
            let mut v: Vec<&ServerView> = sh.servers.iter().filter(|s| s.ok || s.fav || s.origin == Origin::Mine).collect();
            v.sort_by_key(|s| (!s.fav, s.origin != Origin::Mine, !s.ok, if s.latency == 0 { u32::MAX } else { s.latency }));
            let servers: Vec<TargetItem> = v
                .iter()
                .take(80)
                .map(|s| {
                    let mut parts: Vec<String> = Vec::new();
                    if !s.cc.is_empty() {
                        parts.push(country(&s.cc));
                    }
                    parts.push(s.proto.clone());
                    if s.ok && s.latency > 0 {
                        parts.push(format!("{} мс", s.latency));
                    }
                    if !s.ok {
                        parts.push("не отвечает".into());
                    }
                    TargetItem {
                        code: ss(format!("server:{}", s.id)),
                        title: ss(if s.fav { format!("★ {}", s.name) } else { s.name.clone() }),
                        subtitle: ss(parts.join(" · ")),
                        cc: ss(&s.cc),
                        warp: s.origin == Origin::Warp,
                        ok: s.ok,
                    }
                })
                .collect();
            (countries, servers, chains)
        };
        self.ui(move |_| {
            with_models(|m| {
                sync(&m.target_countries, countries);
                sync(&m.target_servers, servers);
                sync(&m.target_chains, chains);
            })
        });
    }

    /// The folders model: all entry lists, with the attach state of the open route.
    fn push_lists(&self) {
        let items: Vec<ListItem> = {
            let sh = self.sh.lock().unwrap();
            let attached: Vec<String> = sh
                .route_open
                .as_ref()
                .and_then(|id| sh.routes.iter().find(|r| &r.id == id))
                .map(|r| r.lists.clone())
                .unwrap_or_default();
            sh.lists
                .iter()
                .map(|l| {
                    let (s, a) = (l.sites.len(), l.apps.len());
                    let mut info = match (s, a) {
                        (0, 0) => "пусто".to_string(),
                        (_, 0) => format!("{s} {}", plural(s, "сайт", "сайта", "сайтов")),
                        (0, _) => format!("{a} {}", plural(a, "программа", "программы", "программ")),
                        _ => format!("{s} {} · {a} {}", plural(s, "сайт", "сайта", "сайтов"), plural(a, "программа", "программы", "программ")),
                    };
                    if !l.warn.is_empty() {
                        info = format!("{info} · {}", l.warn);
                    } else if !l.target.is_empty() {
                        info = format!("{info} · {}", l.label);
                    }
                    ListItem { id: ss(&l.id), name: ss(&l.name), info: ss(info), on: attached.contains(&l.id) }
                })
                .collect()
        };
        self.ui(move |_| with_models(|m| sync(&m.lists, items)));
    }

    /// The open folder in its editor: name and entries into the shared models.
    fn push_list(&self) {
        let data = {
            let sh = self.sh.lock().unwrap();
            sh.list_open.as_ref().and_then(|id| sh.lists.iter().find(|l| &l.id == id)).map(|l| {
                let (kind, cc) = if l.target.is_empty() { (String::new(), String::new()) } else { let (k, c) = route_kind(&l.target); (k.to_string(), c) };
                (l.id.clone(), l.name.clone(), strings(&l.sites), strings(&l.apps), kind, cc, l.label.clone())
            })
        };
        self.ui(move |w| {
            let a = w.global::<App>();
            match data {
                Some((id, name, sites, apps, kind, cc, label)) => {
                    a.set_list_id(ss(id));
                    a.set_list_name(ss(name));
                    a.set_list_kind(ss(kind));
                    a.set_list_cc(ss(cc));
                    a.set_list_target_label(ss(label));
                    with_models(|m| {
                        sync(&m.sites, sites);
                        sync(&m.apps, apps);
                    });
                }
                None => a.set_dialog(ss("lists")),
            }
        });
    }

    /// Search across folders and routes (own entries).
    fn push_hits(&self, q: &str) {
        let q = q.trim().to_lowercase();
        let hits: Vec<HitItem> = if q.is_empty() {
            Vec::new()
        } else {
            let sh = self.sh.lock().unwrap();
            let mut out: Vec<HitItem> = Vec::new();
            for l in &sh.lists {
                for v in l.sites.iter().chain(l.apps.iter()) {
                    if v.to_lowercase().contains(&q) {
                        out.push(HitItem { text: ss(v), r#where: ss(format!("список «{}»", l.name)) });
                    }
                }
            }
            for r in &sh.routes {
                for v in r.sites.iter().chain(r.apps.iter()) {
                    if v.to_lowercase().contains(&q) {
                        out.push(HitItem { text: ss(v), r#where: ss(format!("маршрут «{}»", r.name)) });
                    }
                }
            }
            out.truncate(100);
            out
        };
        self.ui(move |_| with_models(|m| sync(&m.search_hits, hits)));
    }

    fn open_route(self: &Arc<Self>, id: String) {
        self.sh.lock().unwrap().route_open = Some(id);
        self.ui(|w| {
            let a = w.global::<App>();
            a.set_list_tab(0);
            a.set_route_open(true);
        });
        self.push_route();
        self.push_lists();
        self.push_procs();
    }

    fn route_id(&self) -> Option<String> {
        self.sh.lock().unwrap().route_open.clone()
    }

    /// Name for a new route from its direction ("Германия", "Напрямую"…), unique.
    fn route_name(&self, target: &str) -> String {
        let sh = self.sh.lock().unwrap();
        let base = match route_kind(target) {
            ("direct", _) => "Напрямую".to_string(),
            ("vpn", _) => "Через VPN".to_string(),
            ("warp", _) => "WARP".to_string(),
            ("block", _) => "Блокировка".to_string(),
            ("country", cc) => country(&cc),
            ("chain", _) => {
                let id = target.strip_prefix("chain:").unwrap_or("");
                sh.chains.iter().find(|c| c.id == id).map(|c| util::clip(&c.name, 30)).unwrap_or_else(|| "Цепочка".into())
            }
            _ => {
                let id = target.strip_prefix("server:").unwrap_or("");
                sh.servers.iter().find(|s| s.id == id).map(|s| util::clip(&s.name, 30)).unwrap_or_else(|| "Сервер".into())
            }
        };
        let taken = |n: &str| sh.routes.iter().any(|r| r.name == n);
        if !taken(&base) {
            return base;
        }
        (2..100).map(|i| format!("{base} {i}")).find(|n| !taken(n)).unwrap_or(base)
    }

    /// Direction chosen in the picker: for a new route (`for_id` empty) or an existing one.
    fn pick_target(self: &Arc<Self>, code: String, for_id: String) {
        let me = self.clone();
        self.ui(|w| w.global::<App>().set_dialog(ss("")));
        self.go(async move {
            if let Some(value) = for_id.strip_prefix("@quick:") {
                me.route_quick(value.to_string(), code);
                return;
            }
            if let Some(preset) = for_id.strip_prefix("@preset:") {
                if let Some(v) = me.act(json!({ "cmd": "route_preset_add", "preset": preset, "target": code })).await {
                    let id = v.get("id").and_then(Value::as_str).unwrap_or("").to_string();
                    let name = v.get("name").and_then(Value::as_str).unwrap_or("").to_string();
                    me.toast(format!("Добавлено: «{name}»"));
                    me.load_routes().await;
                    if !id.is_empty() {
                        me.open_route(id);
                    }
                }
            } else if let Some(list_id) = for_id.strip_prefix("@list:") {
                // a list's own direction; an empty code clears it
                me.act(json!({ "cmd": "list_update", "id": list_id, "target": code })).await;
                me.load_routes().await;
                me.ui(|w| w.global::<App>().set_dialog(ss("list-edit")));
                me.push_list();
            } else if for_id == "@default" {
                me.act(json!({ "cmd": "route_default", "target": code })).await;
                me.load_routes().await;
            } else if for_id.is_empty() {
                let name = me.route_name(&code);
                if let Some(v) = me.act(json!({ "cmd": "route_add", "name": name, "target": code })).await {
                    let id = v.get("id").and_then(Value::as_str).unwrap_or("").to_string();
                    me.load_routes().await;
                    if !id.is_empty() {
                        me.open_route(id);
                    }
                }
            } else {
                me.act(json!({ "cmd": "route_update", "id": for_id, "target": code })).await;
                me.load_routes().await;
            }
            me.poke.notify_one();
        });
    }

    /// Quick rule: the typed site or program goes to `code`; the explanation refreshes.
    fn route_quick(self: &Arc<Self>, value: String, code: String) {
        if value.trim().is_empty() {
            return;
        }
        let me = self.clone();
        self.go(async move {
            match me.call(json!({ "cmd": "route_quick", "value": value, "target": code })).await {
                Ok(v) => {
                    let text = v.get("text").and_then(Value::as_str).unwrap_or("").to_string();
                    me.toast(text);
                    me.load_routes().await;
                    let ex = me.call(json!({ "cmd": "route_explain", "query": value })).await.ok().and_then(|v| v.get("text").and_then(Value::as_str).map(str::to_string)).unwrap_or_default();
                    me.ui(move |w| w.global::<App>().set_explain_text(ss(ex)));
                }
                Err(e) => me.toast(e),
            }
            me.poke.notify_one();
        });
    }

    // -------------------------------------------------------------- chains

    fn chain_new(self: &Arc<Self>) {
        self.sh.lock().unwrap().chain_draft = Some((String::new(), Vec::new()));
        self.ui(|w| {
            let a = w.global::<App>();
            a.set_chain_name(ss(""));
            a.set_dialog(ss("chain-edit"));
        });
        self.push_chain_draft();
    }

    fn chain_edit(self: &Arc<Self>, id: String) {
        let draft = {
            let sh = self.sh.lock().unwrap();
            sh.chains.iter().find(|c| c.id == id).map(|c| (c.id.clone(), c.hops.iter().map(|h| h.code.clone()).collect::<Vec<String>>(), c.name.clone()))
        };
        let Some((id, hops, name)) = draft else { return };
        self.sh.lock().unwrap().chain_draft = Some((id, hops));
        self.ui(move |w| {
            let a = w.global::<App>();
            a.set_chain_name(ss(name));
            a.set_dialog(ss("chain-edit"));
        });
        self.push_chain_draft();
    }

    fn chain_delete(self: &Arc<Self>, id: String) {
        let me = self.clone();
        self.go(async move {
            me.act(json!({ "cmd": "chain_remove", "id": id })).await;
            me.load_routes().await;
            me.poke.notify_one();
        });
    }

    fn chain_save(self: &Arc<Self>, name: String) {
        let Some((id, hops)) = self.sh.lock().unwrap().chain_draft.clone() else { return };
        let me = self.clone();
        self.go(async move {
            let v = if id.is_empty() {
                me.act(json!({ "cmd": "chain_add", "name": name, "hops": hops })).await
            } else {
                me.act(json!({ "cmd": "chain_update", "id": id, "name": name, "hops": hops })).await
            };
            if v.is_some() {
                me.sh.lock().unwrap().chain_draft = None;
                me.ui(|w| w.global::<App>().set_dialog(ss("chains")));
                me.load_routes().await;
            }
            me.poke.notify_one();
        });
    }

    fn chain_hop_open(self: &Arc<Self>, idx: usize) {
        self.sh.lock().unwrap().hop_pick = Some(idx);
        self.ui(|w| {
            let a = w.global::<App>();
            a.set_hop_step(0);
            a.set_dialog(ss("hop"));
        });
        self.push_targets();
    }

    fn chain_hop_add(self: &Arc<Self>) {
        let idx = self.sh.lock().unwrap().chain_draft.as_ref().map(|(_, h)| h.len()).unwrap_or(0);
        if idx < 3 {
            self.chain_hop_open(idx);
        }
    }

    fn chain_hop_remove(self: &Arc<Self>, i: usize) {
        {
            let mut sh = self.sh.lock().unwrap();
            if let Some((_, hops)) = sh.chain_draft.as_mut() {
                if i < hops.len() {
                    hops.remove(i);
                }
            }
        }
        self.push_chain_draft();
    }

    fn pick_hop(self: &Arc<Self>, code: String) {
        {
            let mut sh = self.sh.lock().unwrap();
            if let (Some(idx), Some((_, hops))) = (sh.hop_pick.take(), sh.chain_draft.as_mut()) {
                if idx >= hops.len() {
                    hops.push(code);
                } else {
                    hops[idx] = code;
                }
            }
        }
        self.ui(|w| w.global::<App>().set_dialog(ss("chain-edit")));
        self.push_chain_draft();
    }

    fn push_chain_draft(&self) {
        let items: Vec<TargetItem> = {
            let sh = self.sh.lock().unwrap();
            match &sh.chain_draft {
                Some((_, hops)) => hops
                    .iter()
                    .enumerate()
                    .map(|(i, code)| TargetItem {
                        code: ss(code),
                        title: ss(hop_label(&sh, code)),
                        subtitle: ss(format!("Звено {}", i + 1)),
                        cc: ss(""),
                        warp: false,
                        ok: true,
                    })
                    .collect(),
                None => Vec::new(),
            }
        };
        self.ui(move |_| with_models(|m| sync(&m.chain_hops, items)));
    }

    /// The direction picker's context for `target-for`: (code, kind, country).
    fn picker_of(&self, for_id: &str) -> (String, String, String) {
        let sh = self.sh.lock().unwrap();
        let code = if let Some(id) = for_id.strip_prefix("@preset:") {
            smart::preset(id).map(|p| p.hint.to_string()).unwrap_or_default()
        } else if let Some(id) = for_id.strip_prefix("@list:") {
            sh.lists.iter().find(|l| l.id == id).map(|l| l.target.clone()).unwrap_or_default()
        } else if for_id == "@default" {
            sh.route_default_code.clone()
        } else if for_id.starts_with("@quick:") {
            String::new()
        } else if for_id.is_empty() {
            String::new()
        } else {
            sh.routes.iter().find(|r| &r.id == for_id).map(|r| r.target.clone()).unwrap_or_default()
        };
        if code.is_empty() {
            return (code, String::new(), String::new());
        }
        let (kind, cc) = route_kind(&code);
        (code, kind.to_string(), cc)
    }

    fn open_default_chain(self: &Arc<Self>) {
        let (code, kind, cc) = self.picker_of("@default");
        self.ui(move |w| {
            let a = w.global::<App>();
            a.set_picker_target(ss(code));
            a.set_picker_kind(ss(kind));
            a.set_picker_cc(ss(cc));
            a.set_target_for(ss("@default"));
            a.set_target_step(3);
            a.set_dialog(ss("target"));
        });
        self.push_targets();
    }

    fn clear_default_chain(self: &Arc<Self>) {
        let me = self.clone();
        self.go(async move {
            me.act(json!({ "cmd": "route_default", "target": "vpn" })).await;
            me.load_routes().await;
            me.poke.notify_one();
        });
    }

    // -------------------------------------------------------------- folders

    fn lists_open(self: &Arc<Self>) {
        self.ui(|w| {
            let a = w.global::<App>();
            a.set_list_search(ss(""));
            a.set_dialog(ss("lists"));
        });
        self.push_lists();
        self.push_hits("");
    }

    fn list_new(self: &Arc<Self>) {
        let me = self.clone();
        self.go(async move {
            if let Some(v) = me.act(json!({ "cmd": "list_add", "name": "Список" })).await {
                let id = v.get("id").and_then(Value::as_str).unwrap_or("").to_string();
                me.load_routes().await;
                if !id.is_empty() {
                    me.list_edit(id);
                }
            }
            me.poke.notify_one();
        });
    }

    fn list_edit(self: &Arc<Self>, id: String) {
        self.sh.lock().unwrap().list_open = Some(id);
        self.ui(|w| {
            let a = w.global::<App>();
            a.set_list_tab(0);
            a.set_dialog(ss("list-edit"));
        });
        self.push_list();
    }

    fn list_delete(self: &Arc<Self>, id: String) {
        let me = self.clone();
        self.go(async move {
            me.act(json!({ "cmd": "list_remove", "id": id })).await;
            me.load_routes().await;
            me.poke.notify_one();
        });
    }

    fn list_rename(self: &Arc<Self>, id: String, name: String) {
        let me = self.clone();
        self.go(async move {
            me.act(json!({ "cmd": "list_update", "id": id, "name": name })).await;
            me.load_routes().await;
            let back = if me.sh.lock().unwrap().list_open.as_ref() == Some(&id) { "list-edit" } else { "lists" };
            me.ui(move |w| w.global::<App>().set_dialog(ss(back)));
            me.poke.notify_one();
        });
    }

    fn list_toggle(self: &Arc<Self>, id: String, on: bool) {
        let Some(rid) = self.route_id() else { return };
        let set: Vec<String> = {
            let sh = self.sh.lock().unwrap();
            let mut v: Vec<String> = sh.routes.iter().find(|r| r.id == rid).map(|r| r.lists.clone()).unwrap_or_default();
            if on {
                if !v.contains(&id) {
                    v.push(id.clone());
                }
            } else {
                v.retain(|x| x != &id);
            }
            v
        };
        let me = self.clone();
        self.go(async move {
            me.act(json!({ "cmd": "route_update", "id": rid, "lists": set })).await;
            me.load_routes().await;
            me.poke.notify_one();
        });
    }

    fn list_add_entry(self: &Arc<Self>, kind: i32, value: String) {
        let Some(id) = self.sh.lock().unwrap().list_open.clone() else { return };
        let me = self.clone();
        self.go(async move {
            if me.act(json!({ "cmd": "list_entry_add", "id": id, "kind": kind_name(kind), "value": value })).await.is_some() {
                me.load_routes().await;
            }
            me.poke.notify_one();
        });
    }

    fn list_remove_entry(self: &Arc<Self>, kind: i32, value: String) {
        let Some(id) = self.sh.lock().unwrap().list_open.clone() else { return };
        let me = self.clone();
        self.go(async move {
            me.act(json!({ "cmd": "list_entry_remove", "id": id, "kind": kind_name(kind), "value": value })).await;
            me.load_routes().await;
            me.poke.notify_one();
        });
    }

    fn list_import(self: &Arc<Self>, kind: i32) {
        let Some(id) = self.sh.lock().unwrap().list_open.clone() else { return };
        let me = self.clone();
        self.go(async move {
            let picked = tokio::task::spawn_blocking(|| sys::open_file("Импорт списка", &[("Текстовые файлы", "*.txt;*.lst;*.list;*.csv"), ("Все файлы", "*.*")]))
                .await
                .ok()
                .flatten();
            let Some(path) = picked else { return };
            let text = match read_text(&path) {
                Ok(t) => t,
                Err(e) => return me.toast(e),
            };
            if let Some(v) = me.act(json!({ "cmd": "list_import", "id": id, "kind": kind_name(kind), "text": text })).await {
                let added = v.get("added").and_then(Value::as_u64).unwrap_or(0);
                let bad = v.get("rejected").and_then(Value::as_u64).unwrap_or(0);
                me.toast(if bad > 0 { format!("Добавлено: {added}, пропущено строк: {bad}") } else { format!("Добавлено: {added}") });
                me.load_routes().await;
                me.poke.notify_one();
            }
        });
    }

    fn list_export(self: &Arc<Self>, kind: i32) {
        let Some(id) = self.sh.lock().unwrap().list_open.clone() else { return };
        let me = self.clone();
        self.go(async move {
            let Some(v) = me.act(json!({ "cmd": "list_export", "id": id, "kind": kind_name(kind) })).await else { return };
            let text = v.get("text").and_then(Value::as_str).unwrap_or("").to_string();
            let file = if kind == 1 { "lazeyka-programs.txt" } else { "lazeyka-sites.txt" };
            let picked = tokio::task::spawn_blocking(move || sys::save_file("Экспорт списка", file, &[("Текстовые файлы", "*.txt")], "txt")).await.ok().flatten();
            let Some(path) = picked else { return };
            let text = if cfg!(windows) { text.replace('\n', "\r\n") } else { text };
            match std::fs::write(&path, text) {
                Ok(()) => me.toast("Список сохранён"),
                Err(e) => me.toast(format!("Не удалось сохранить: {e}")),
            }
        });
    }

    fn route_cmd(self: &Arc<Self>, req: Value) {
        let me = self.clone();
        self.go(async move {
            me.act(req).await;
            me.load_routes().await;
            me.poke.notify_one();
        });
    }

    async fn load_sources(self: &Arc<Self>) {
        let Ok(v) = self.call(json!({ "cmd": "sources" })).await else { return };
        let empty = Vec::new();
        let sources: Vec<SourceItem> = v
            .get("sources")
            .and_then(Value::as_array)
            .unwrap_or(&empty)
            .iter()
            .map(|s| SourceItem {
                id: ss(s.get("id").and_then(Value::as_str).unwrap_or("")),
                name: ss(s.get("name").and_then(Value::as_str).unwrap_or("")),
                tier: s.get("tier").and_then(Value::as_i64).unwrap_or(1) as i32,
                enabled: s.get("enabled").and_then(Value::as_bool).unwrap_or(false),
                stat: ss(source_stat(s.get("stat").unwrap_or(&Value::Null))),
                custom: s.get("custom").and_then(Value::as_bool).unwrap_or(false),
            })
            .collect();
        let subs: Vec<SubItem> = v
            .get("subscriptions")
            .and_then(Value::as_array)
            .unwrap_or(&empty)
            .iter()
            .map(|s| {
                let url = s.get("url").and_then(Value::as_str).unwrap_or("");
                let name = s.get("name").and_then(Value::as_str).filter(|n| !n.trim().is_empty()).map(str::to_string).unwrap_or_else(|| {
                    url.split("://").nth(1).unwrap_or(url).split(['/', '?']).next().unwrap_or(url).to_string()
                });
                let count = s.get("count").and_then(Value::as_u64).unwrap_or(0) as usize;
                let updated = s.get("updated").and_then(Value::as_u64).unwrap_or(0);
                let err = s.get("error").and_then(Value::as_str);
                let info = match err {
                    Some(e) => format!("ошибка: {}", util::clip(e, 80)),
                    None if updated > 0 => format!("{count} {} · обновлено {}", plural(count, "сервер", "сервера", "серверов"), fmt_date(updated)),
                    None => "ещё не загружалась".into(),
                };
                SubItem { id: ss(s.get("id").and_then(Value::as_str).unwrap_or("")), name: ss(name), info: ss(info), error: err.is_some() }
            })
            .collect();
        self.ui(move |_| {
            with_models(|m| {
                sync(&m.sources, sources);
                sync(&m.subs, subs);
            })
        });
    }

    async fn load_servers(self: &Arc<Self>) {
        let Ok(v) = self.call(json!({ "cmd": "servers" })).await else { return };
        let list: Vec<ServerView> = v.get("servers").cloned().and_then(|x| serde_json::from_value(x).ok()).unwrap_or_default();
        {
            let mut sh = self.sh.lock().unwrap();
            sh.servers = list;
            sh.selected = v.get("selected").and_then(Value::as_str).map(str::to_string);
            sh.list_at = Some(Instant::now());
        }
        self.push_servers();
        self.push_countries();
    }

    /// Rebuilds the visible server list from the cache (filter, selection).
    fn push_servers(&self) {
        let filter = self.filter.load(Relaxed);
        let sort = self.sort.load(Relaxed);
        let (items, note) = {
            let sh = self.sh.lock().unwrap();
            let sel = sh.selected.as_deref();
            let cc = &sh.countries;
            let mut v: Vec<&ServerView> = sh
                .servers
                .iter()
                .filter(|s| if filter == 1 { s.origin == Origin::Mine } else { (s.ok || s.fav) && (cc.is_empty() || cc.contains(&s.cc)) })
                .collect();
            sort_servers(&mut v, sort);
            let items: Vec<ServerItem> = v.iter().take(MAX_ROWS).map(|s| item(s, sel)).collect();
            let finished = sh.status.as_ref().map(|s| s.scan.finished).unwrap_or(0);
            let note = if v.len() > items.len() {
                format!("Показаны {} из {}", items.len(), v.len())
            } else if filter == 0 && finished > 0 && !items.is_empty() {
                format!("Последний поиск: {}", fmt_date(finished))
            } else {
                String::new()
            };
            (items, note)
        };
        self.ui(move |w| {
            with_models(|m| sync(&m.servers, items));
            w.global::<App>().set_list_note(ss(note));
        });
    }

    /// Country picker: every country with known servers (working ones counted) plus the chosen ones.
    fn push_countries(&self) {
        let (items, text, any) = {
            let sh = self.sh.lock().unwrap();
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for s in sh.servers.iter().filter(|s| !s.cc.is_empty()) {
                *counts.entry(s.cc.as_str()).or_default() += usize::from(s.ok);
            }
            for c in &sh.countries {
                counts.entry(c.as_str()).or_default();
            }
            let mut v: Vec<(String, String, usize)> = counts.into_iter().map(|(c, n)| (c.to_string(), country(c), n)).collect();
            v.sort_by(|a, b| b.2.cmp(&a.2).then_with(|| a.1.cmp(&b.1)));
            let items: Vec<CountryItem> = v
                .into_iter()
                .map(|(cc, name, n)| CountryItem { on: sh.countries.contains(&cc), cc: ss(cc), name: ss(name), count: n as i32 })
                .collect();
            (items, countries_text(&sh.countries), !sh.countries.is_empty())
        };
        self.ui(move |w| {
            let a = w.global::<App>();
            a.set_countries_text(ss(text));
            a.set_countries_any(any);
            with_models(|m| sync(&m.countries, items));
        });
    }

    fn push_procs(&self) {
        let items: Vec<SharedString> = {
            let sh = self.sh.lock().unwrap();
            let f = sh.proc_filter.to_lowercase();
            let open = sh.route_open.as_ref().and_then(|id| sh.routes.iter().find(|r| &r.id == id));
            let added: Vec<String> = open.map(|r| r.apps.iter().map(|a| a.to_lowercase()).collect()).unwrap_or_default();
            sh.procs
                .iter()
                .filter(|p| {
                    let l = p.to_lowercase();
                    (f.is_empty() || l.contains(&f)) && !added.contains(&l)
                })
                .map(ss)
                .collect()
        };
        self.ui(move |_| with_models(|m| sync(&m.procs, items)));
    }

    async fn load_logs(self: &Arc<Self>) {
        let Ok(v) = self.call(json!({ "cmd": "logs" })).await else { return };
        let mut lines: Vec<String> = v.get("lines").and_then(Value::as_array).map(|a| a.iter().filter_map(|x| x.as_str().map(str::to_string)).collect()).unwrap_or_default();
        if lines.len() > 500 {
            lines.drain(..lines.len() - 500);
        }
        let items = strings(&lines);
        self.ui(move |_| with_models(|m| m.logs.set_vec(items)));
    }

    // ---------------- actions

    fn toggle(self: &Arc<Self>) {
        let me = self.clone();
        self.go(async move {
            if !me.link_up() {
                me.ensure_service(true).await;
                return;
            }
            let state = me.sh.lock().unwrap().status.as_ref().map(|s| s.state).unwrap_or_default();
            if matches!(state, ConnState::On | ConnState::Connecting) {
                me.ui(|w| {
                    let a = w.global::<App>();
                    a.set_state(0);
                    a.set_state_text(ss("Отключение…"));
                    a.set_message(ss(""));
                });
                me.act(json!({ "cmd": "disconnect" })).await;
            } else {
                me.ui(|w| {
                    let a = w.global::<App>();
                    a.set_state(1);
                    a.set_state_text(ss("Подключение…"));
                    a.set_message(ss("Ищем рабочий сервер…"));
                });
                me.act(json!({ "cmd": "connect" })).await;
            }
            me.poke.notify_one();
        });
    }

    fn quit(self: &Arc<Self>, disconnect: bool) {
        let me = self.clone();
        self.go(async move {
            if disconnect && me.link_up() {
                let connected = me.sh.lock().unwrap().status.as_ref().is_some_and(|s| s.state != ConnState::Off);
                if connected {
                    let _ = me.client.call_timeout(json!({ "cmd": "disconnect" }), Duration::from_secs(4)).await;
                }
            }
            let _ = slint::invoke_from_event_loop(|| {
                let _ = slint::quit_event_loop();
            });
        });
    }

    fn select(self: &Arc<Self>, id: String) {
        {
            let mut sh = self.sh.lock().unwrap();
            sh.selected = if id.is_empty() { None } else { Some(id.clone()) };
        }
        self.push_servers();
        let auto = id.is_empty();
        self.ui(move |w| w.global::<App>().set_auto(auto));
        let me = self.clone();
        self.go(async move {
            if !me.link_up() {
                me.ensure_service(false).await;
                return;
            }
            let server = if id.is_empty() { Value::Null } else { Value::from(id) };
            me.act(json!({ "cmd": "select", "server": server })).await;
            me.poke.notify_one();
            me.load_servers().await;
        });
    }

    fn import(self: &Arc<Self>, text: String, name: String) {
        let text = text.trim().to_string();
        if text.is_empty() {
            return;
        }
        self.ui(|w| w.global::<App>().set_busy(true));
        let me = self.clone();
        self.go(async move {
            let is_sub = (text.starts_with("https://") || text.starts_with("http://")) && !text.contains('\n');
            let r = me.client.call_timeout(json!({ "cmd": "import", "text": text, "name": name }), Duration::from_secs(90)).await;
            match r {
                Ok(v) => {
                    let n = v.get("added").and_then(Value::as_u64).unwrap_or(0) as usize;
                    let bad = v.get("errors").and_then(Value::as_u64).unwrap_or(0);
                    let msg = if is_sub {
                        format!("Подписка добавлена: {n} {}", plural(n, "сервер", "сервера", "серверов"))
                    } else if bad > 0 {
                        format!("Добавлено: {n}, не распознано: {bad}")
                    } else {
                        format!("Добавлено: {n} {}", plural(n, "сервер", "сервера", "серверов"))
                    };
                    me.filter.store(1, Relaxed);
                    me.ui(move |w| {
                        let a = w.global::<App>();
                        a.set_busy(false);
                        a.set_dialog(ss(""));
                        a.set_import_text(ss(""));
                        a.set_filter(1);
                        a.set_page(1);
                        a.set_toast(ss(msg));
                    });
                    me.page.store(1, Relaxed);
                    me.load_servers().await;
                    me.load_sources().await;
                    me.poke.notify_one();
                    // the engine checks new servers in the background
                    for _ in 0..3 {
                        tokio::time::sleep(Duration::from_secs(6)).await;
                        me.load_servers().await;
                    }
                }
                Err(e) => me.ui(move |w| {
                    let a = w.global::<App>();
                    a.set_busy(false);
                    a.set_toast(ss(e));
                }),
            }
        });
    }

    fn import_file(self: &Arc<Self>) {
        let me = self.clone();
        self.go(async move {
            let picked = tokio::task::spawn_blocking(|| {
                sys::open_file(
                    "Импорт конфигурации",
                    &[("Конфигурации VPN", "*.conf;*.ovpn;*.yaml;*.yml;*.txt;*.json;*.vpn"), ("Все файлы", "*.*")],
                )
            })
            .await
            .ok()
            .flatten();
            let Some(path) = picked else { return };
            match read_text(&path) {
                Ok(text) => {
                    let name = path.file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                    me.import(text, name);
                }
                Err(e) => me.toast(e),
            }
        });
    }

    fn route_add_entry(self: &Arc<Self>, kind: i32, value: String) {
        let value = value.trim().to_string();
        let Some(id) = self.route_id() else { return };
        if value.is_empty() {
            return;
        }
        let me = self.clone();
        // several entries, a URL list or a program among sites: the smart parser takes it
        if value.contains(|c: char| c.is_whitespace() || c == ',' || c == ';') && !(kind == 1 && value.contains('\\')) {
            self.bulk_add(id, value);
            return;
        }
        self.go(async move {
            if let Some(v) = me.act(json!({ "cmd": "route_entry_add", "id": id, "kind": kind_name(kind), "value": value })).await {
                let name = v.get("value").and_then(Value::as_str).unwrap_or("").to_string();
                let moved: Vec<String> = v.get("moved").and_then(|m| serde_json::from_value(m.clone()).ok()).unwrap_or_default();
                if !moved.is_empty() {
                    me.toast(format!("{name}: перенесено из «{}»", moved.join("», «")));
                } else if kind == 1 {
                    me.toast(format!("Добавлено: {name}"));
                }
                me.load_routes().await;
                me.poke.notify_one();
            }
        });
    }

    /// Pasted text of any shape: sites and programs are recognised automatically.
    fn bulk_add(self: &Arc<Self>, id: String, text: String) {
        let me = self.clone();
        self.go(async move {
            if let Some(v) = me.act(json!({ "cmd": "route_bulk", "id": id, "text": text })).await {
                let added = v.get("added").and_then(Value::as_u64).unwrap_or(0);
                let bad = v.get("rejected").and_then(Value::as_u64).unwrap_or(0);
                let moved: Vec<String> = v.get("moved").and_then(|m| serde_json::from_value(m.clone()).ok()).unwrap_or_default();
                let mut msg = format!("Добавлено: {added}");
                if bad > 0 {
                    msg.push_str(&format!(", не распознано: {bad}"));
                }
                if !moved.is_empty() {
                    msg.push_str(&format!(". Часть перенесена из «{}»", moved.join("», «")));
                }
                me.toast(msg);
                me.load_routes().await;
                me.poke.notify_one();
            }
        });
    }

    async fn load_presets(self: &Arc<Self>) {
        let Ok(v) = self.call(json!({ "cmd": "route_presets" })).await else { return };
        let items: Vec<PresetItem> = v
            .get("presets")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .map(|p| PresetItem {
                        id: ss(p["id"].as_str().unwrap_or("")),
                        name: ss(p["name"].as_str().unwrap_or("")),
                        desc: ss(p["desc"].as_str().unwrap_or("")),
                        hint: ss(p["hint_label"].as_str().unwrap_or("")),
                        count: p["count"].as_i64().unwrap_or(0) as i32,
                        added: p["added"].as_bool().unwrap_or(false),
                    })
                    .collect()
            })
            .unwrap_or_default();
        self.ui(move |_| with_models(|m| sync(&m.presets, items)));
    }

    fn route_import(self: &Arc<Self>, kind: i32) {
        let Some(id) = self.route_id() else { return };
        let me = self.clone();
        self.go(async move {
            let picked = tokio::task::spawn_blocking(|| sys::open_file("Импорт списка", &[("Текстовые файлы", "*.txt;*.lst;*.list;*.csv"), ("Все файлы", "*.*")]))
                .await
                .ok()
                .flatten();
            let Some(path) = picked else { return };
            let text = match read_text(&path) {
                Ok(t) => t,
                Err(e) => return me.toast(e),
            };
            if let Some(v) = me.act(json!({ "cmd": "route_import", "id": id, "kind": kind_name(kind), "text": text })).await {
                let added = v.get("added").and_then(Value::as_u64).unwrap_or(0);
                let bad = v.get("rejected").and_then(Value::as_u64).unwrap_or(0);
                me.toast(if bad > 0 { format!("Добавлено: {added}, пропущено строк: {bad}") } else { format!("Добавлено: {added}") });
                me.load_routes().await;
                me.poke.notify_one();
            }
        });
    }

    fn route_export(self: &Arc<Self>, kind: i32) {
        let Some(id) = self.route_id() else { return };
        let me = self.clone();
        self.go(async move {
            let Some(v) = me.act(json!({ "cmd": "route_export", "id": id, "kind": kind_name(kind) })).await else { return };
            let text = v.get("text").and_then(Value::as_str).unwrap_or("").to_string();
            let file = if kind == 1 { "lazeyka-programs.txt" } else { "lazeyka-sites.txt" };
            let picked = tokio::task::spawn_blocking(move || sys::save_file("Экспорт списка", file, &[("Текстовые файлы", "*.txt")], "txt")).await.ok().flatten();
            let Some(path) = picked else { return };
            let text = if cfg!(windows) { text.replace('\n', "\r\n") } else { text };
            match std::fs::write(&path, text) {
                Ok(()) => me.toast("Список сохранён"),
                Err(e) => me.toast(format!("Не удалось сохранить: {e}")),
            }
        });
    }

    fn set_flag(self: &Arc<Self>, key: String, on: bool) {
        if key == "autostart" {
            let exe = autostart_exe();
            let ok = sys::set_autostart(on, &exe);
            let now = sys::autostart_enabled();
            self.ui(move |w| w.global::<App>().set_autostart(now));
            if !ok {
                self.toast("Не удалось изменить автозапуск");
            }
            return;
        }
        let me = self.clone();
        self.go(async move {
            let req = if key == "warp" {
                json!({ "cmd": "warp", "enable": on })
            } else {
                json!({ "cmd": "set_settings", "patch": { key: on } })
            };
            if me.act(req).await.is_none() {
                me.load_settings().await;
            }
            me.poke.notify_one();
        });
    }

    fn set_upd_text(&self, text: impl Into<String>, busy: bool) {
        let t: String = text.into();
        self.ui(move |w| {
            let a = w.global::<App>();
            a.set_upd_text(ss(t));
            a.set_upd_busy(busy);
        });
    }

    fn check_updates(self: &Arc<Self>) {
        let me = self.clone();
        self.go(async move {
            me.set_upd_text("Проверяем…", true);
            match me.call(json!({ "cmd": "update_check" })).await {
                Ok(v) => {
                    let prog = v.get("program").is_some_and(|x| !x.is_null());
                    let mih = v.get("mihomo").is_some_and(|x| !x.is_null());
                    let text = if prog || mih { "Есть обновления" } else { "Установлена последняя версия" };
                    me.set_upd_text(text, false);
                }
                Err(e) => {
                    me.set_upd_text("", false);
                    me.toast(e);
                }
            }
            me.poke.notify_one();
        });
    }

    fn install_mihomo_update(self: &Arc<Self>) {
        let me = self.clone();
        self.go(async move {
            me.set_upd_text("Устанавливаем mihomo…", true);
            let r = me.client.call_timeout(json!({ "cmd": "update_mihomo" }), Duration::from_secs(1000)).await;
            match r {
                Ok(_) => {
                    me.set_upd_text("mihomo обновлён", false);
                    me.toast("mihomo обновлён. Применится при следующем подключении");
                }
                Err(e) => {
                    me.set_upd_text("", false);
                    me.toast(e);
                }
            }
            me.poke.notify_one();
        });
    }

    /// Downloads the new package through the service and starts its `lazeyka.exe`: a copy
    /// from another folder replaces this window and updates the service by itself.
    fn install_program_update(self: &Arc<Self>) {
        let me = self.clone();
        self.go(async move {
            me.set_upd_text("Загружаем…", true);
            let r = me.client.call_timeout(json!({ "cmd": "update_program" }), Duration::from_secs(1000)).await;
            let v = match r {
                Ok(v) => v,
                Err(e) => {
                    me.set_upd_text("", false);
                    me.toast(e);
                    return;
                }
            };
            let exe = std::path::PathBuf::from(v.get("exe").and_then(Value::as_str).unwrap_or(""));
            let want = v.get("sha256").and_then(Value::as_str).unwrap_or("").to_string();
            // the file must still be what the service unpacked
            let ok = tokio::task::spawn_blocking({
                let exe = exe.clone();
                move || lazeyka_core::update::sha256_file(&exe).map(|h| h == want).unwrap_or(false)
            })
            .await
            .unwrap_or(false);
            if !ok {
                me.set_upd_text("", false);
                me.toast("Файл обновления не прошёл проверку — установка отменена");
                return;
            }
            me.set_upd_text("Запускаем установку…", true);
            if cfg!(windows) {
                if std::process::Command::new(&exe).spawn().is_err() {
                    me.set_upd_text("", false);
                    me.toast("Не удалось запустить установщик обновления");
                }
            } else {
                me.set_upd_text("", false);
                me.toast(format!("Обновление скачано: {}", exe.display()));
            }
        });
    }

    async fn load_net_test(self: &Arc<Self>, force: bool) {
        self.ui(move |w| w.global::<App>().set_net_busy(force));
        let result = self.client.call_timeout(json!({"cmd":"net_test", "force":force}), Duration::from_secs(90)).await;
        match result {
            Ok(v) => {
                let summary = v.get("summary").and_then(Value::as_str).unwrap_or("").to_string();
                let lines: Vec<(String,String,i32,String)> = v.get("lines").and_then(Value::as_array).map(|a| a.iter().map(|v| (
                    v["title"].as_str().unwrap_or("").to_string(), v["value"].as_str().unwrap_or("").to_string(), v["state"].as_i64().unwrap_or(0) as i32, v["note"].as_str().unwrap_or("").to_string()
                )).collect()).unwrap_or_default();
                self.ui(move |w| {
                    let a = w.global::<App>();
                    a.set_net_summary(ss(summary));
                    let rows = lines.into_iter().map(|(title,value,state,note)| NetLine { title:ss(title), value:ss(value), state, note:ss(note) }).collect::<Vec<_>>();
                    a.set_net_lines(ModelRc::from(Rc::new(VecModel::from(rows))));
                    a.set_net_busy(false);
                });
            }
            Err(e) => { self.ui(|w| w.global::<App>().set_net_busy(false)); self.toast(format!("Проверка сети: {e}")); }
        }
    }

    fn open_dialog(self: &Arc<Self>, name: String) {
        let me = self.clone();
        if name == "target" {
            let me2 = self.clone();
            self.ui(move |w| {
                let a = w.global::<App>();
                let for_id = a.get_target_for().to_string();
                let (code, kind, cc) = me2.picker_of(&for_id);
                a.set_picker_target(ss(code));
                a.set_picker_kind(ss(kind));
                a.set_picker_cc(ss(cc));
            });
        }
        let n = name.clone();
        self.ui(move |w| w.global::<App>().set_dialog(ss(n)));
        self.go(async move {
            match name.as_str() {
                "sources" | "subs" => me.load_sources().await,
                "presets" => me.load_presets().await,
                "log" => me.load_logs().await,
                "net-test" => me.load_net_test(false).await,
                "target" => {
                    me.push_targets();
                    me.load_routes().await;
                    me.load_servers().await;
                    me.push_targets();
                }
                "apps" => {
                    me.sh.lock().unwrap().proc_filter.clear();
                    let procs = tokio::task::spawn_blocking(sys::process_names).await.unwrap_or_default();
                    me.sh.lock().unwrap().procs = procs;
                    me.push_procs();
                }
                _ => {}
            }
        });
    }

    fn page_changed(self: &Arc<Self>, page: i32, filter: i32) {
        self.page.store(page, Relaxed);
        let old = self.filter.swap(filter, Relaxed);
        if page == 1 && old != filter {
            self.push_servers();
        }
        let me = self.clone();
        self.go(async move {
            match page {
                1 => me.load_servers().await,
                2 => me.load_routes().await,
                3 => {
                    me.load_settings().await;
                    me.load_sources().await;
                }
                _ => {}
            }
        });
    }

    fn service_action(self: &Arc<Self>, svc: i32) {
        let me = self.clone();
        self.go(async move {
            match svc {
                4 => me.install(false, true).await,
                1 => me.install(false, false).await,
                _ => me.ensure_service(false).await,
            }
        });
    }

    #[cfg(windows)]
    fn uninstall(self: &Arc<Self>) {
        let me = self.clone();
        self.ui(|w| w.global::<App>().set_dialog(ss("")));
        self.go(async move {
            let r = tokio::task::spawn_blocking(|| crate::win::run_elevated("--uninstall --quiet")).await.unwrap_or_else(|e| Err(e.to_string()));
            match r {
                Ok(0) => {
                    sys::set_autostart(false, std::path::Path::new(""));
                    me.quit(false);
                }
                Ok(_) => me.toast("Не удалось удалить Лазейку полностью"),
                Err(e) if e == "cancelled" => me.toast("Удаление отменено"),
                Err(e) => me.toast(e),
            }
        });
    }

    #[cfg(not(windows))]
    fn uninstall(self: &Arc<Self>) {
        self.toast("Удаление доступно только в Windows");
    }
}

impl Ctl {
    fn set_sort(self: &Arc<Self>, i: i32) {
        let i = i.clamp(0, SORTS.len() as i32 - 1);
        self.sort.store(i, Relaxed);
        self.ui(move |w| w.global::<App>().set_sort(i));
        self.push_servers();
        let me = self.clone();
        self.go(async move {
            let _ = me.call(json!({ "cmd": "set_settings", "patch": { "sort": SORTS[i as usize] } })).await;
        });
    }

    fn set_countries(self: &Arc<Self>, list: Vec<String>) {
        {
            let mut sh = self.sh.lock().unwrap();
            sh.countries = list.clone();
            sh.countries_at = Some(Instant::now());
        }
        self.push_countries();
        self.push_servers();
        let me = self.clone();
        self.go(async move {
            if !me.link_up() {
                return;
            }
            if let Some(v) = me.act(json!({ "cmd": "set_countries", "countries": list })).await {
                if !list.is_empty() && v.get("usable").and_then(Value::as_bool) == Some(false) {
                    me.toast("В выбранных странах пока нет рабочих серверов — ищем их");
                }
            }
            me.poke.notify_one();
        });
    }

    fn toggle_country(self: &Arc<Self>, cc: String) {
        let mut list = self.sh.lock().unwrap().countries.clone();
        match list.iter().position(|c| *c == cc) {
            Some(i) => {
                list.remove(i);
            }
            None => list.push(cc),
        }
        self.set_countries(list);
    }

    fn open_server(&self, id: String) {
        let found = {
            let sh = self.sh.lock().unwrap();
            sh.servers.iter().find(|s| s.id == id).map(|s| item(s, sh.selected.as_deref()))
        };
        let Some(it) = found else { return };
        self.ui(move |w| {
            let a = w.global::<App>();
            a.set_edit_id(it.id.clone());
            a.set_edit_name(it.name.clone());
            a.set_detail(it);
            a.set_dialog(ss("server"));
        });
    }

    /// Updates a server in the cache and in an open details dialog.
    fn update_cached(&self, sv: ServerView) {
        let it = {
            let mut sh = self.sh.lock().unwrap();
            let sel = sh.selected.clone();
            match sh.servers.iter_mut().find(|x| x.id == sv.id) {
                Some(x) => *x = sv.clone(),
                None => sh.servers.push(sv.clone()),
            }
            item(&sv, sel.as_deref())
        };
        self.push_servers();
        self.ui(move |w| {
            let a = w.global::<App>();
            if a.get_detail().id == it.id {
                a.set_detail(it);
            }
        });
    }

    fn set_favorite(self: &Arc<Self>, id: String, fav: bool) {
        let cur = self.sh.lock().unwrap().servers.iter().find(|s| s.id == id).cloned();
        if let Some(mut sv) = cur {
            sv.fav = fav;
            self.update_cached(sv);
        }
        let me = self.clone();
        self.go(async move {
            if me.act(json!({ "cmd": "set_favorite", "id": id, "fav": fav })).await.is_some() {
                me.toast(if fav { "Добавлено в избранное: автовыбор попробует этот сервер первым" } else { "Убрано из избранного" });
            }
            me.load_servers().await;
        });
    }

    fn measure(self: &Arc<Self>, id: String) {
        if id.is_empty() {
            return;
        }
        self.ui(|w| w.global::<App>().set_measuring(true));
        let me = self.clone();
        self.go(async move {
            let r = me.client.call_timeout(json!({ "cmd": "measure", "id": id }), Duration::from_secs(150)).await;
            let view = r
                .and_then(|v| serde_json::from_value::<Option<ServerView>>(v).map_err(|e| e.to_string()))
                .and_then(|o| o.ok_or_else(|| "сервер не найден".to_string()));
            me.ui(|w| w.global::<App>().set_measuring(false));
            match view {
                Ok(sv) => {
                    let msg = if !sv.ok {
                        if sv.error.is_empty() { format!("{} не отвечает", sv.name) } else { format!("{} не отвечает: {}", sv.name, sv.error) }
                    } else if sv.speed > 0 {
                        format!("{}: пинг {} мс, скорость {}", sv.name, sv.latency, fmt_speed(sv.speed))
                    } else {
                        format!("{}: пинг {} мс, скорость замерить не удалось", sv.name, sv.latency)
                    };
                    me.update_cached(sv);
                    me.toast(msg);
                }
                Err(e) => me.toast(e),
            }
        });
    }

    fn confirm_install(self: &Arc<Self>, ok: bool) {
        self.ui(|w| w.global::<App>().set_dialog(ss("")));
        let pending = self.sh.lock().unwrap().pending_install.take();
        let Some((connect_after, update)) = pending else { return };
        if ok {
            self.sh.lock().unwrap().location_ok = true;
            let me = self.clone();
            self.go(async move { me.install(connect_after, update).await });
        } else {
            self.toast("Установка отменена");
        }
    }
}

fn read_text(path: &std::path::Path) -> Result<String, String> {
    let meta = std::fs::metadata(path).map_err(|e| e.to_string())?;
    if meta.len() > 8 << 20 {
        return Err("файл слишком большой".into());
    }
    let b = std::fs::read(path).map_err(|e| e.to_string())?;
    // UTF-16 LE with BOM (Notepad "Unicode")
    if b.len() >= 2 && b[0] == 0xFF && b[1] == 0xFE {
        let u: Vec<u16> = b[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        return Ok(String::from_utf16_lossy(&u));
    }
    Ok(String::from_utf8_lossy(&b).trim_start_matches('\u{feff}').to_string())
}

/// The exe autostart should launch: the installed program, else this one.
fn autostart_exe() -> std::path::PathBuf {
    #[cfg(windows)]
    if let Some(e) = crate::win::home_exe() {
        return e;
    }
    std::env::current_exe().unwrap_or_default()
}

/// Folder of the program (portable: settings and data live there too).
fn home_dir_text() -> String {
    #[cfg(windows)]
    return crate::win::planned_home().0.display().to_string();
    #[allow(unreachable_code)]
    std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.display().to_string())).unwrap_or_default()
}

fn ipc_path() -> String {
    std::env::var("LAZEYKA_SOCK").unwrap_or_else(|_| ipc::DEFAULT_PATH.to_string())
}

/// True when this copy runs from somewhere else than the installed program
/// (a newly downloaded version): it then replaces an already running UI.
fn is_foreign_copy() -> bool {
    #[cfg(windows)]
    {
        return match (std::env::current_exe().ok(), crate::win::service_exe()) {
            (Some(me), Some(installed)) => !crate::win::same_path(&me, &installed),
            _ => false,
        };
    }
    #[allow(unreachable_code)]
    false
}

thread_local! {
    static WINDOW: RefCell<Option<slint::Weak<AppWindow>>> = const { RefCell::new(None) };
    static CTL: RefCell<Option<Arc<Ctl>>> = const { RefCell::new(None) };
}

fn show_main_window() {
    let (w, c) = (WINDOW.with(|w| w.borrow().clone()), CTL.with(|c| c.borrow().clone()));
    if let (Some(w), Some(c)) = (w.and_then(|w| w.upgrade()), c) {
        let _ = w.show();
        w.window().set_minimized(false);
        c.visible.store(true, Relaxed);
        c.poke.notify_one();
        sys::focus_own_window();
    }
}

/// Windows may throw away what was drawn into the window (restore from minimized, unlock,
/// display changes) while the software renderer only repaints the parts that changed, which
/// left "holes" showing whatever is behind the window. Repaint everything when the system asks
/// for it, after a restore and on focus (so a click always fixes the picture).
fn guard_repaint(w: &AppWindow) {
    use slint::winit_030::winit::event::WindowEvent;
    use slint::winit_030::{EventResult, WinitWindowAccessor};
    let weak = w.as_weak();
    let mut minimized = false;
    w.window().on_winit_window_event(move |win, ev| {
        let full = match ev {
            WindowEvent::RedrawRequested => os_invalidated(win),
            WindowEvent::Resized(s) => {
                let was = minimized;
                minimized = s.width == 0 || s.height == 0;
                was && !minimized
            }
            WindowEvent::Focused(true) | WindowEvent::Occluded(false) => true,
            _ => false,
        };
        if full && let Some(w) = weak.upgrade() {
            let a = w.global::<App>();
            a.set_repaint(!a.get_repaint());
        }
        EventResult::Propagate
    });
}

/// True when the window has an update region, i.e. the system (not the app) invalidated it.
/// Redraws requested by the app itself come without one.
fn os_invalidated(win: &slint::Window) -> bool {
    #[cfg(windows)]
    {
        use slint::winit_030::WinitWindowAccessor;
        use slint::winit_030::winit::raw_window_handle::{HasWindowHandle, RawWindowHandle};
        return win
            .with_winit_window(|ww| match ww.window_handle().map(|h| h.as_raw()) {
                Ok(RawWindowHandle::Win32(h)) => sys::has_update_region(h.hwnd.get()),
                _ => false,
            })
            .unwrap_or(false);
    }
    #[allow(unreachable_code)]
    {
        let _ = win;
        false
    }
}

// ------------------------------------------------------------------ entry

pub fn run(start_hidden: bool, replace: bool) -> anyhow::Result<()> {
    let primary = sys::single_instance(
        replace || is_foreign_copy(),
        || {
            let _ = slint::invoke_from_event_loop(show_main_window);
        },
        || {
            let _ = slint::invoke_from_event_loop(|| {
                let _ = slint::quit_event_loop();
            });
        },
    );
    if !primary {
        return Ok(());
    }

    #[cfg(feature = "headless")]
    let headless = crate::headless::install();
    #[cfg(not(feature = "headless"))]
    let headless = false;

    let w = AppWindow::new()?;
    guard_repaint(&w);
    let tray = if headless {
        None
    } else {
        match Tray::new() {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("tray: {e}");
                None
            }
        }
    };
    w.set_app_icon(rgba(include_bytes!("../assets/app-64.rgba"), 64));
    if let Some(t) = &tray {
        t.set_icon_off(rgba(include_bytes!("../assets/tray-off.rgba"), 32));
        t.set_icon_on(rgba(include_bytes!("../assets/tray-on.rgba"), 32));
        t.set_icon_busy(rgba(include_bytes!("../assets/tray-busy.rgba"), 32));
    }

    // models
    let models = Models {
        servers: Rc::new(VecModel::default()),
        routes: Rc::new(VecModel::default()),
        presets: Rc::new(VecModel::default()),
        target_countries: Rc::new(VecModel::default()),
        target_servers: Rc::new(VecModel::default()),
        target_chains: Rc::new(VecModel::default()),
        chain_hops: Rc::new(VecModel::default()),
        lists: Rc::new(VecModel::default()),
        search_hits: Rc::new(VecModel::default()),
        sites: Rc::new(VecModel::default()),
        apps: Rc::new(VecModel::default()),
        sources: Rc::new(VecModel::default()),
        subs: Rc::new(VecModel::default()),
        logs: Rc::new(VecModel::default()),
        procs: Rc::new(VecModel::default()),
        countries: Rc::new(VecModel::default()),
    };
    {
        let a = w.global::<App>();
        a.set_servers(ModelRc::from(models.servers.clone()));
        a.set_routes(ModelRc::from(models.routes.clone()));
        a.set_presets(ModelRc::from(models.presets.clone()));
        a.set_target_countries(ModelRc::from(models.target_countries.clone()));
        a.set_target_servers(ModelRc::from(models.target_servers.clone()));
        a.set_target_chains(ModelRc::from(models.target_chains.clone()));
        a.set_chain_hops(ModelRc::from(models.chain_hops.clone()));
        a.set_lists(ModelRc::from(models.lists.clone()));
        a.set_search_hits(ModelRc::from(models.search_hits.clone()));
        a.set_sites(ModelRc::from(models.sites.clone()));
        a.set_apps(ModelRc::from(models.apps.clone()));
        a.set_sources(ModelRc::from(models.sources.clone()));
        a.set_subs(ModelRc::from(models.subs.clone()));
        a.set_log_lines(ModelRc::from(models.logs.clone()));
        a.set_processes(ModelRc::from(models.procs.clone()));
        a.set_countries(ModelRc::from(models.countries.clone()));
        a.set_home_dir(ss(home_dir_text()));
        a.set_version(ss(VERSION));
        a.set_can_uninstall(cfg!(windows));
        a.set_autostart(sys::autostart_enabled());
        a.set_service(0);
        a.set_message(ss("Подключаемся к службе…"));
    }
    MODELS.with(|m| *m.borrow_mut() = Some(models));

    // IPC runtime on its own thread
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    let handle = rt.handle().clone();
    std::thread::Builder::new().name("lazeyka-ipc".into()).spawn(move || rt.block_on(std::future::pending::<()>()))?;
    let client = {
        let _g = handle.enter();
        ipc::Client::new(&ipc_path())
    };
    let ctl = Arc::new(Ctl {
        rt: handle,
        client,
        ui: w.as_weak(),
        tray: tray.as_ref().map(|t| t.as_weak()),
        poke: tokio::sync::Notify::new(),
        visible: AtomicBool::new(!start_hidden),
        page: AtomicI32::new(0),
        filter: AtomicI32::new(0),
        sort: AtomicI32::new(0),
        sh: Mutex::new(Shared::default()),
    });
    WINDOW.with(|x| *x.borrow_mut() = Some(w.as_weak()));
    CTL.with(|x| *x.borrow_mut() = Some(ctl.clone()));

    wire(&w, &ctl);

    if let Some(t) = &tray {
        let c = ctl.clone();
        t.on_show_window(show_main_window);
        t.on_toggle(move || c.toggle());
        let c = ctl.clone();
        t.on_quit(move || c.quit(true));
        t.show()?;
    }
    {
        let c = ctl.clone();
        let has_tray = tray.is_some();
        w.window().on_close_requested(move || {
            c.visible.store(false, Relaxed);
            if !has_tray {
                c.quit(false);
            }
            slint::CloseRequestResponse::HideWindow
        });
    }

    ctl.go(ctl.clone().status_loop());
    if !start_hidden || tray.is_none() {
        w.show()?;
    }
    slint::run_event_loop_until_quit()?;
    let _ = w.hide();
    drop(tray);
    Ok(())
}

fn wire(w: &AppWindow, ctl: &Arc<Ctl>) {
    let a = w.global::<App>();
    let weak = w.as_weak();

    let c = ctl.clone();
    a.on_toggle_connect(move || c.toggle());
    let c = ctl.clone();
    a.on_select_server(move |id| c.select(id.to_string()));
    let c = ctl.clone();
    a.on_scan(move || {
        let c2 = c.clone();
        c.sh.lock().unwrap().user_scan = true;
        c.ui(|w| {
            let a = w.global::<App>();
            a.set_scanning(true);
            a.set_scan_progress(0.0);
            a.set_scan_text(ss("Загрузка списков…"));
        });
        c.go(async move {
            if !c2.link_up() {
                c2.ensure_service(false).await;
                return;
            }
            if c2.act(json!({ "cmd": "scan", "full": true })).await.is_none() {
                c2.sh.lock().unwrap().user_scan = false;
            }
            c2.poke.notify_one();
        });
    });
    let c = ctl.clone();
    a.on_cancel_scan(move || {
        let c2 = c.clone();
        c.go(async move {
            c2.act(json!({ "cmd": "cancel_scan" })).await;
            c2.poke.notify_one();
        });
    });
    let c = ctl.clone();
    a.on_import_text_submit(move |t| c.import(t.to_string(), String::new()));
    let wk = weak.clone();
    let c = ctl.clone();
    a.on_paste_clipboard(move || match sys::clipboard_get().filter(|t| !t.trim().is_empty()) {
        Some(t) => {
            if let Some(w) = wk.upgrade() {
                w.global::<App>().set_import_text(ss(t));
            }
        }
        None => c.toast("Буфер обмена пуст"),
    });
    let c = ctl.clone();
    a.on_import_file(move || c.import_file());
    let c = ctl.clone();
    a.on_remove_server(move |id| {
        let c2 = c.clone();
        c.ui(|w| w.global::<App>().set_dialog(ss("")));
        c.go(async move {
            if c2.act(json!({ "cmd": "remove_server", "id": id.to_string() })).await.is_some() {
                c2.toast("Сервер удалён");
            }
            c2.load_servers().await;
            c2.poke.notify_one();
        });
    });
    let c = ctl.clone();
    a.on_rename_server(move |id, name| {
        let c2 = c.clone();
        let name = name.trim().to_string();
        c.ui(|w| w.global::<App>().set_dialog(ss("")));
        if name.is_empty() {
            return;
        }
        c.go(async move {
            c2.act(json!({ "cmd": "rename_server", "id": id.to_string(), "name": name })).await;
            c2.load_servers().await;
            c2.poke.notify_one();
        });
    });
    let c = ctl.clone();
    a.on_set_route_default(move |i| {
        c.sh.lock().unwrap().route_default_at = Some(Instant::now());
        c.route_cmd(json!({ "cmd": "route_default", "target": if i == 1 { "direct" } else { "vpn" } }));
    });
    let c = ctl.clone();
    a.on_open_route(move |id| c.open_route(id.to_string()));
    let c = ctl.clone();
    a.on_preset_pick(move |id| {
        let code = smart::preset(&id).map(|p| p.hint.to_string()).unwrap_or_default();
        let (kind, cc) = if code.is_empty() { (String::new(), String::new()) } else { let (k, cc) = route_kind(&code); (k.to_string(), cc) };
        let target_for = format!("@preset:{id}");
        c.ui(move |w| {
            let a = w.global::<App>();
            a.set_target_for(ss(target_for));
            a.set_target_step(0);
            a.set_picker_target(ss(code));
            a.set_picker_kind(ss(kind));
            a.set_picker_cc(ss(cc));
        });
        c.open_dialog("target".into());
    });
    let c = ctl.clone();
    a.on_explain_route(move |q| {
        let q = q.to_string();
        let qv = q.trim().to_string();
        c.ui(move |w| w.global::<App>().set_quick_value(ss(qv)));
        let c2 = c.clone();
        c.go(async move {
            let text = match c2.call(json!({ "cmd": "route_explain", "query": q })).await {
                Ok(v) => v.get("text").and_then(Value::as_str).unwrap_or("").to_string(),
                Err(e) => e,
            };
            c2.ui(move |w| w.global::<App>().set_explain_text(ss(text)));
        });
    });
    let c = ctl.clone();
    a.on_route_quick(move |value, code| c.route_quick(value.to_string(), code.to_string()));
    let c = ctl.clone();
    a.on_paste_bulk(move || match (sys::clipboard_get().filter(|t| !t.trim().is_empty()), c.route_id()) {
        (Some(t), Some(id)) => c.bulk_add(id, t),
        (None, _) => c.toast("Буфер обмена пуст"),
        _ => {}
    });
    let c = ctl.clone();
    a.on_new_route(move || {
        c.ui(|w| {
            let a = w.global::<App>();
            a.set_target_for(ss(""));
            a.set_target_step(0);
        });
        c.open_dialog("target".into());
    });
    let c = ctl.clone();
    let wk = weak.clone();
    a.on_pick_target(move |code| {
        let for_id = wk.upgrade().map(|w| w.global::<App>().get_target_for().to_string()).unwrap_or_default();
        c.pick_target(code.to_string(), for_id);
    });
    // chains
    let c = ctl.clone();
    a.on_edit_chains(move || c.ui(|w| w.global::<App>().set_dialog(ss("chains"))));
    let c = ctl.clone();
    a.on_chain_new(move || c.chain_new());
    let c = ctl.clone();
    a.on_chain_edit(move |id| c.chain_edit(id.to_string()));
    let c = ctl.clone();
    a.on_chain_delete(move |id| c.chain_delete(id.to_string()));
    let c = ctl.clone();
    let wk = weak.clone();
    a.on_chain_save(move || {
        let name = wk.upgrade().map(|w| w.global::<App>().get_chain_name().to_string()).unwrap_or_default();
        c.chain_save(name);
    });
    let c = ctl.clone();
    a.on_chain_hop_add(move || c.chain_hop_add());
    let c = ctl.clone();
    a.on_chain_hop_pick(move |i| c.chain_hop_open(i as usize));
    let c = ctl.clone();
    a.on_chain_hop_remove(move |i| c.chain_hop_remove(i as usize));
    let c = ctl.clone();
    a.on_pick_hop(move |code| c.pick_hop(code.to_string()));
    let c = ctl.clone();
    a.on_open_default_chain(move || c.open_default_chain());
    let c = ctl.clone();
    a.on_clear_default_chain(move || c.clear_default_chain());
    // folders
    let c = ctl.clone();
    a.on_lists_open(move || c.lists_open());
    let c = ctl.clone();
    a.on_list_new(move || c.list_new());
    let c = ctl.clone();
    a.on_list_edit(move |id| c.list_edit(id.to_string()));
    let c = ctl.clone();
    a.on_list_delete(move |id| c.list_delete(id.to_string()));
    let c = ctl.clone();
    a.on_list_rename(move |id, name| {
        let name = name.trim().to_string();
        if !name.is_empty() {
            c.list_rename(id.to_string(), name);
        }
    });
    let c = ctl.clone();
    a.on_list_toggle(move |id, on| c.list_toggle(id.to_string(), on));
    let c = ctl.clone();
    a.on_list_add_entry(move |k, v| {
        let v = v.trim().to_string();
        if !v.is_empty() {
            c.list_add_entry(k, v);
        }
    });
    let c = ctl.clone();
    a.on_list_remove_entry(move |k, v| c.list_remove_entry(k, v.to_string()));
    let c = ctl.clone();
    a.on_list_import(move |k| c.list_import(k));
    let c = ctl.clone();
    a.on_list_export(move |k| c.list_export(k));
    let c = ctl.clone();
    a.on_search_lists(move |q| c.push_hits(&q.to_string()));
    let c = ctl.clone();
    a.on_route_toggle(move |id, on| c.route_cmd(json!({ "cmd": "route_update", "id": id.to_string(), "enabled": on })));
    let c = ctl.clone();
    a.on_route_fallback(move |id, fb| c.route_cmd(json!({ "cmd": "route_update", "id": id.to_string(), "fallback": fb.to_string() })));
    let c = ctl.clone();
    a.on_route_strategy(move |id, st| c.route_cmd(json!({ "cmd": "route_update", "id": id.to_string(), "strategy": st.to_string() })));
    let c = ctl.clone();
    a.on_check_updates(move || c.check_updates());
    let c = ctl.clone();
    a.on_install_program_update(move || c.install_program_update());
    let c = ctl.clone();
    a.on_install_mihomo_update(move || c.install_mihomo_update());
    let c = ctl.clone();
    a.on_route_sort(move || c.route_cmd(json!({ "cmd": "route_sort" })));
    let c = ctl.clone();
    a.on_route_move(move |id, d| c.route_cmd(json!({ "cmd": "route_move", "id": id.to_string(), "delta": d })));
    let c = ctl.clone();
    a.on_route_rename(move |id, name| {
        c.ui(|w| w.global::<App>().set_dialog(ss("")));
        let name = name.trim().to_string();
        if !name.is_empty() {
            c.route_cmd(json!({ "cmd": "route_update", "id": id.to_string(), "name": name }));
        }
    });
    let c = ctl.clone();
    a.on_route_delete(move |id| {
        c.ui(|w| {
            let a = w.global::<App>();
            a.set_dialog(ss(""));
            a.set_route_open(false);
        });
        c.sh.lock().unwrap().route_open = None;
        c.toast("Маршрут удалён");
        c.route_cmd(json!({ "cmd": "route_remove", "id": id.to_string() }));
    });
    let c = ctl.clone();
    a.on_route_add_entry(move |k, v| c.route_add_entry(k, v.to_string()));
    let c = ctl.clone();
    a.on_route_remove_entry(move |k, v| {
        if let Some(id) = c.route_id() {
            c.route_cmd(json!({ "cmd": "route_entry_remove", "id": id, "kind": kind_name(k), "value": v.to_string() }));
        }
    });
    let c = ctl.clone();
    a.on_route_import(move |k| c.route_import(k));
    let c = ctl.clone();
    a.on_route_export(move |k| c.route_export(k));
    let c = ctl.clone();
    a.on_load_processes(move || c.open_dialog("apps".into()));
    let c = ctl.clone();
    a.on_filter_processes(move |t| {
        c.sh.lock().unwrap().proc_filter = t.to_string();
        c.push_procs();
    });
    let c = ctl.clone();
    a.on_pick_exe(move || {
        let c2 = c.clone();
        c.go(async move {
            let picked = tokio::task::spawn_blocking(|| sys::open_file("Выберите программу", &[("Программы", "*.exe"), ("Все файлы", "*.*")])).await.ok().flatten();
            if let Some(p) = picked {
                let name = p.file_name().map(|s| s.to_string_lossy().to_string()).unwrap_or_default();
                c2.route_add_entry(1, name);
            }
        });
    });
    let c = ctl.clone();
    a.on_set_flag(move |k, v| c.set_flag(k.to_string(), v));
    let c = ctl.clone();
    a.on_set_stack(move |i| {
        let c2 = c.clone();
        let stack = STACKS.get(i as usize).copied().unwrap_or("gvisor");
        c.ui(move |w| w.global::<App>().set_stack(i));
        c.go(async move {
            if c2.act(json!({ "cmd": "set_settings", "patch": { "stack": stack } })).await.is_none() {
                c2.load_settings().await;
            }
        });
    });
    let c = ctl.clone();
    a.on_set_source(move |id, on| {
        let c2 = c.clone();
        c.go(async move {
            c2.act(json!({ "cmd": "set_source", "id": id.to_string(), "enabled": on })).await;
            c2.load_sources().await;
        });
    });
    let c = ctl.clone();
    a.on_add_source(move |url| {
        let c2 = c.clone();
        let url = url.trim().to_string();
        if url.is_empty() {
            return;
        }
        c.go(async move {
            if c2.act(json!({ "cmd": "add_source", "url": url, "name": "" })).await.is_some() {
                c2.toast("Источник добавлен — он будет использован при следующем поиске");
            }
            c2.load_sources().await;
        });
    });
    let c = ctl.clone();
    a.on_remove_source(move |id| {
        let c2 = c.clone();
        c.go(async move {
            c2.act(json!({ "cmd": "remove_source", "id": id.to_string() })).await;
            c2.load_sources().await;
        });
    });
    let c = ctl.clone();
    a.on_refresh_subs(move || {
        let c2 = c.clone();
        c.go(async move {
            if c2.act(json!({ "cmd": "refresh_subscriptions" })).await.is_some() {
                c2.toast("Обновляем подписки…");
                tokio::time::sleep(Duration::from_secs(8)).await;
                c2.load_sources().await;
                c2.load_servers().await;
            }
        });
    });
    let c = ctl.clone();
    a.on_remove_sub(move |id| {
        let c2 = c.clone();
        c.go(async move {
            if c2.act(json!({ "cmd": "remove_subscription", "id": id.to_string() })).await.is_some() {
                c2.toast("Подписка удалена вместе с её серверами");
            }
            c2.load_sources().await;
            c2.load_servers().await;
            c2.poke.notify_one();
        });
    });
    let c = ctl.clone();
    a.on_open_dialog(move |n| c.open_dialog(n.to_string()));
    let c = ctl.clone();
    a.on_net_test(move || { let me = c.clone(); c.go(async move { me.load_net_test(true).await; }); });
    let c = ctl.clone();
    a.on_copy_log(move || {
        let mut text = String::new();
        with_models(|m| {
            for l in m.logs.iter() {
                text.push_str(&l);
                text.push_str(if cfg!(windows) { "\r\n" } else { "\n" });
            }
        });
        c.toast(if sys::clipboard_set(&text) { "Журнал скопирован" } else { "Не удалось скопировать" });
    });
    let c = ctl.clone();
    a.on_uninstall(move || c.uninstall());
    let c = ctl.clone();
    a.on_set_sort(move |i| c.set_sort(i));
    let c = ctl.clone();
    a.on_toggle_country(move |cc| c.toggle_country(cc.to_string()));
    let c = ctl.clone();
    a.on_clear_countries(move || c.set_countries(Vec::new()));
    let c = ctl.clone();
    a.on_set_favorite(move |id, fav| c.set_favorite(id.to_string(), fav));
    let c = ctl.clone();
    a.on_measure(move |id| c.measure(id.to_string()));
    let c = ctl.clone();
    a.on_open_server(move |id| c.open_server(id.to_string()));
    let c = ctl.clone();
    a.on_confirm_install(move |ok| c.confirm_install(ok));
    let c = ctl.clone();
    let wk = weak.clone();
    a.on_page_changed(move |p| {
        let filter = wk.upgrade().map(|w| w.global::<App>().get_filter()).unwrap_or(0);
        c.page_changed(p, filter);
    });
    let c = ctl.clone();
    let wk = weak;
    a.on_service_action(move || {
        let svc = wk.upgrade().map(|w| w.global::<App>().get_service()).unwrap_or(2);
        c.service_action(svc);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        assert_eq!(fmt_bytes(512), "512 Б");
        assert_eq!(fmt_bytes(1536), "1,5 КБ");
        assert_eq!(fmt_bytes(15 * 1024 * 1024), "15 МБ");
        assert_eq!(fmt_rate(0), "0 Б/с");
        assert_eq!(fmt_speed(0), "");
        assert_eq!(fmt_speed(800), "800 кбит/с");
        assert_eq!(fmt_speed(4500), "4,5 Мбит/с");
        assert_eq!(fmt_speed(94_000), "94 Мбит/с");
        assert_eq!(fmt_duration(3725), "01:02:05");
        assert_eq!(plural(1, "a", "b", "c"), "a");
        assert_eq!(plural(3, "a", "b", "c"), "b");
        assert_eq!(plural(11, "a", "b", "c"), "c");
        assert_eq!(plural(22, "a", "b", "c"), "b");
        assert!(newer("0.2.0", "0.1.9"));
        assert!(!newer("0.1.0", "0.1.0"));
        assert!(!newer("0.1.0", "0.10.0"));
    }

    #[test]
    fn dates() {
        // 2024-02-29 12:34 UTC
        let ts = 1709210040u64;
        let s = fmt_date((ts as i64 - sys::local_offset()) as u64);
        assert_eq!(s, "29.02.2024 12:34");
    }
}
