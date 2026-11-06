//! Renders UI screens to PNG with the software renderer (design check without a display).
//! cargo run --example shot -- out_dir [scale]
use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::Rgb8Pixel;
use slint::platform::{Platform, WindowAdapter};
use slint::{ComponentHandle, Model, ModelRc, SharedString, VecModel};
use std::rc::Rc;

slint::include_modules!();

struct Shot {
    window: Rc<MinimalSoftwareWindow>,
    start: std::time::Instant,
}

impl Platform for Shot {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, slint::PlatformError> {
        Ok(self.window.clone())
    }
    fn duration_since_start(&self) -> core::time::Duration {
        self.start.elapsed()
    }
}

fn item(name: &str, cc: &str, proto: &str, tr: &str, lat: i32, speed: &str, mine: bool, warp: bool, sel: bool) -> ServerItem {
    ServerItem {
        id: name.into(),
        name: name.into(),
        cc: cc.into(),
        country: "".into(),
        proto: proto.into(),
        transport: tr.into(),
        latency: lat,
        speed: speed.into(),
        ok: lat > 0,
        tested: true,
        udp: lat % 2 == 0,
        yt: lat > 0,
        dc: lat % 3 != 0,
        tg: lat > 0,
        mine,
        warp,
        selected: sel,
        in_pool: true,
        error: if lat > 0 { "".into() } else { "таймаут подключения".into() },
        fav: name.starts_with("Germany") || name.starts_with("Мой"),
        stability: if lat > 0 { format!("{}%", 100 - lat % 17).into() } else { "".into() },
        checks: if lat > 0 { "24 проверки".into() } else { "3 проверки".into() },
        address: format!("{}.example.net:443", cc.to_lowercase()).into(),
        checked: "04.11.2026 18:42".into(),
        relay: "".into(),
        exit_ip: if lat > 0 { "203.0.113.42".into() } else { "".into() },
        state_label: if lat > 0 { "Страна подтверждена".into() } else { "Временно недоступен".into() },
        trust_label: if mine { "Свой сервер".into() } else if warp { "Официальный бесплатный".into() } else { "Публичный узел".into() },
        trust_warning: "".into(),
        limits_note: "".into(),
    }
}

fn route(id: &str, name: &str, kind: &str, cc: &str, label: &str, summary: &str, warn: &str, enabled: bool, first: bool, last: bool) -> RouteItem {
    RouteItem {
        id: id.into(),
        priority: 1,
        name: name.into(),
        enabled,
        target: kind.into(),
        kind: kind.into(),
        cc: cc.into(),
        label: label.into(),
        summary: summary.into(),
        warn: warn.into(),
        fallback: "fastest".into(),
        strategy: "failover".into(),
        first,
        last,
    }
}

fn target(code: &str, title: &str, subtitle: &str, cc: &str, ok: bool) -> TargetItem {
    TargetItem { code: code.into(), title: title.into(), subtitle: subtitle.into(), cc: cc.into(), warp: code == "warp", ok }
}

fn save(window: &MinimalSoftwareWindow, w: u32, h: u32, path: &str) {
    slint::platform::update_timers_and_animations();
    let mut buf = vec![Rgb8Pixel::default(); (w * h) as usize];
    window.request_redraw();
    window.draw_if_needed(|r| {
        r.render(&mut buf, w as usize);
    });
    let mut ppm = format!("P6\n{w} {h}\n255\n").into_bytes();
    for p in &buf {
        ppm.extend_from_slice(&[p.r, p.g, p.b]);
    }
    let tmp = format!("{path}.ppm");
    std::fs::write(&tmp, ppm).unwrap();
    let st = std::process::Command::new("convert").arg(&tmp).arg(path).status().unwrap();
    assert!(st.success());
    std::fs::remove_file(&tmp).unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = args.get(1).cloned().unwrap_or_else(|| "/tmp/shots".into());
    let scale: f32 = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1.0);
    std::fs::create_dir_all(&out).unwrap();
    let window = MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer);
    slint::platform::set_platform(Box::new(Shot { window: window.clone(), start: std::time::Instant::now() })).unwrap();
    let ui = AppWindow::new().unwrap();
    let (w, h) = ((400.0 * scale) as u32, (700.0 * scale) as u32);
    window.dispatch_event(slint::platform::WindowEvent::ScaleFactorChanged { scale_factor: scale });
    window.set_size(slint::PhysicalSize::new(w, h));
    ui.show().unwrap();
    let app = ui.global::<App>();
    app.set_version("0.8.0".into());
    app.set_core_version("v1.19.33".into());
    app.set_good_count(56);
    app.set_mine_count(2);
    app.set_routes_on(3);
    let routes = vec![
        route("r1", "Банки и госуслуги", "direct", "", "Напрямую", "6 сайтов", "", true, true, false),
        route("r2", "YouTube", "country", "NL", "Через страну: Нидерланды", "4 сайта", "", true, false, false),
        route("r3", "Работа", "server", "", "Через сервер: Мой сервер — Нидерланды", "2 сайта · 1 программа", "Сервер не отвечает — трафик идёт через VPN", true, false, false),
        route("r4", "Игры", "direct", "", "Напрямую", "2 программы", "", false, false, false),
        route("r5", "Реклама", "block", "", "Блокировать", "12 сайтов", "", true, false, true),
    ];
    let editing = routes[1].clone();
    let editing_warn = routes[2].clone();
    app.set_routes(ModelRc::new(VecModel::from(routes)));
    app.set_target_countries(ModelRc::new(VecModel::from(vec![
        target("country:DE", "Германия", "12 рабочих серверов", "DE", true),
        target("country:NL", "Нидерланды", "18 рабочих серверов", "NL", true),
        target("country:FI", "Финляндия", "7 рабочих серверов", "FI", true),
        target("country:US", "США", "3 рабочих сервера", "US", true),
    ])));
    app.set_target_servers(ModelRc::new(VecModel::from(vec![
        target("server:a", "★ Мой сервер — Нидерланды", "Нидерланды · VLESS · 48 мс", "NL", true),
        target("server:b", "★ Germany, Frankfurt am Main", "Германия · VLESS · 98 мс", "DE", true),
        target("warp", "Cloudflare WARP", "AmneziaWG · 18 мс", "", true),
        target("server:c", "Старый сервер", "WireGuard · не отвечает", "", false),
    ])));
    let servers = vec![
        item("Мой сервер — Нидерланды", "NL", "VLESS", "Reality·Vision", 48, "94 Мбит/с", true, false, false),
        item("Germany, Frankfurt am Main", "DE", "VLESS", "Reality·Vision", 98, "34 Мбит/с", false, false, true),
        item("Cloudflare WARP", "", "AmneziaWG", "v1.5", 18, "", false, true, false),
        item("The Netherlands, Amsterdam", "NL", "Hysteria2", "QUIC", 190, "12 Мбит/с", false, false, false),
        item("Sweden — #94", "SE", "VLESS", "TLS·WS", 173, "", false, false, false),
        item("Austria — #4", "AT", "Trojan", "TLS·gRPC", 412, "", false, false, false),
        item("Старый сервер", "", "WireGuard", "", 0, "", true, false, false),
    ];
    let detail = servers[1].clone();
    let mine = servers[0].clone();
    app.set_servers(ModelRc::new(VecModel::from(servers)));
    app.set_countries(ModelRc::new(VecModel::from(vec![
        CountryItem { cc: "NL".into(), name: "Нидерланды".into(), count: 18, on: true },
        CountryItem { cc: "DE".into(), name: "Германия".into(), count: 12, on: true },
        CountryItem { cc: "FI".into(), name: "Финляндия".into(), count: 7, on: false },
        CountryItem { cc: "SE".into(), name: "Швеция".into(), count: 4, on: false },
        CountryItem { cc: "US".into(), name: "США".into(), count: 3, on: false },
        CountryItem { cc: "JP".into(), name: "Япония".into(), count: 0, on: false },
    ])));
    app.set_home_dir("C:\\Lazeyka".into());
    app.set_sites(ModelRc::new(VecModel::from(vec![SharedString::from("gosuslugi.ru"), "sberbank.ru".into(), "10.0.0.0/8".into()])));
    app.set_apps(ModelRc::new(VecModel::from(vec![SharedString::from("steam.exe"), "qbittorrent.exe".into()])));
    app.set_processes(ModelRc::new(VecModel::from(vec![SharedString::from("chrome.exe"), "discord.exe".into(), "steam.exe".into(), "telegram.exe".into()])));
    app.set_sources(ModelRc::new(VecModel::from(vec![
        SourceItem { id: "a".into(), name: "igareck: VLESS (RU)".into(), tier: 1, enabled: true, stat: "рабочих 116 из 287 · обновлено 5 мин назад".into(), custom: false },
        SourceItem { id: "b".into(), name: "kort0881: Hysteria2".into(), tier: 2, enabled: true, stat: "рабочих 12 из 90".into(), custom: false },
        SourceItem { id: "c".into(), name: "Мой список".into(), tier: 1, enabled: false, stat: "ещё не загружен".into(), custom: true },
    ])));
    app.set_log_lines(ModelRc::new(VecModel::from(vec![SharedString::from("12:00:01 Лазейка 0.8.0 запущена"), "12:00:05 поиск завершён: рабочих серверов 56".into(), "--- mihomo ---".into(), "level=warning msg=...".into()])));

    let shots: Vec<(&str, Box<dyn Fn(&App)>)> = vec![
        ("01-home-off", Box::new(|a: &App| { a.set_page(0); a.set_state(0); a.set_state_text("Отключено".into()); a.set_message("Нажмите, чтобы подключиться".into()); })),
        ("02-home-connecting", Box::new(|a: &App| { a.set_state(1); a.set_state_text("Подключение…".into()); a.set_message("Ищем рабочие серверы… 120/700".into()); a.set_scanning(true); a.set_scan_progress(0.35); a.set_scan_text("Проверка серверов: 245 из 700 · найдено 6".into()); })),
        ("03-home-on", Box::new(|a: &App| { a.set_state(2); a.set_state_text("Защищено".into()); a.set_message("".into()); a.set_timer("00:12:34".into()); a.set_scanning(false); a.set_auto(true); a.set_cur_name("Германия · Germany, Frankfurt am Main".into()); a.set_cur_cc("DE".into()); a.set_cur_detail("Автовыбор · VLESS Reality · 98 мс".into()); a.set_down("1,4 МБ/с".into()); a.set_up("86 КБ/с".into()); })),
        ("04-home-noservice", Box::new(|a: &App| { a.set_state(0); a.set_state_text("Отключено".into()); a.set_message("".into()); a.set_service(1); a.set_service_text("При первом подключении Лазейка установит службу VPN — Windows попросит разрешение.".into()); })),
        ("05-servers", Box::new(|a: &App| { a.set_service(0); a.set_page(1); a.set_auto(false); a.set_list_note("Проверено 5 мин назад".into()); })),
        ("06-routes", Box::new(|a: &App| { a.set_page(2); })),
        ("07-route-edit", Box::new(move |a: &App| { a.set_route(editing.clone()); a.set_route_open(true); })),
        ("07b-route-apps-warn", Box::new(move |a: &App| { a.set_route(editing_warn.clone()); a.set_list_tab(1); })),
        ("08-settings", Box::new(|a: &App| { a.set_page(3); a.set_autostart(true); a.set_can_uninstall(true); })),
        ("09-add", Box::new(|a: &App| { a.set_page(1); a.set_dialog("add".into()); })),
        ("10-sources", Box::new(|a: &App| { a.set_dialog("sources".into()); })),
        ("11-apps", Box::new(|a: &App| { a.set_page(2); a.set_dialog("apps".into()); })),
        ("11b-target-new", Box::new(|a: &App| { a.set_route_open(false); a.set_target_for("".into()); a.set_target_step(0); a.set_dialog("target".into()); })),
        ("11c-target-country", Box::new(|a: &App| { a.set_target_for("r2".into()); a.set_target_step(1); })),
        ("11d-target-server", Box::new(|a: &App| { a.set_target_step(2); })),
        ("11e-route-delete", Box::new(|a: &App| { a.set_dialog("route-delete".into()); })),
        ("11f-routes-empty", Box::new(|a: &App| { a.set_dialog("".into()); a.set_routes(ModelRc::new(VecModel::from(Vec::<RouteItem>::new()))); a.set_route_default(1); })),
        ("12-toast", Box::new(|a: &App| { a.set_dialog("".into()); a.set_page(0); a.set_toast("Добавлено серверов: 3".into()); })),
        ("13-servers-filtered", Box::new(|a: &App| { a.set_toast("".into()); a.set_page(1); a.set_auto(true); a.set_sort(3); a.set_countries_text("NL, DE".into()); a.set_countries_any(true); a.set_auto_sub("Только Нидерланды, Германия".into()); })),
        ("14-details", Box::new(move |a: &App| { a.set_detail(detail.clone()); a.set_dialog("server".into()); })),
        ("15-details-mine", Box::new(move |a: &App| { a.set_detail(mine.clone()); a.set_edit_name(mine.name.clone()); a.set_measuring(true); a.set_dialog("server".into()); })),
        ("16-sort", Box::new(|a: &App| { a.set_measuring(false); a.set_dialog("sort".into()); })),
        ("17-countries", Box::new(|a: &App| { a.set_dialog("countries".into()); })),
        ("18-location", Box::new(|a: &App| { a.set_location_blocked(false); a.set_location_text("Лазейка будет работать прямо из этой папки:\nC:\\Users\\Иван\\Downloads\\Lazeyka\n\nПапка находится в профиле пользователя. Программы, запущенные от вашего имени, смогут переместить её и подменить файлы службы, которая работает с правами системы.\n\nНадёжнее перенести папку Лазейки, например, в C:\\Lazeyka и запустить программу оттуда. Продолжить установку здесь?".into()); a.set_dialog("location".into()); })),
        ("19-location-blocked", Box::new(|a: &App| { a.set_location_blocked(true); a.set_location_text("Рядом с lazeyka.exe нет файла mihomo.exe. Похоже, программа запущена прямо из архива: распакуйте его целиком («Извлечь всё…») в отдельную папку, например C:\\Lazeyka, и запустите lazeyka.exe оттуда.".into()); a.set_dialog("location".into()); })),
        ("20-auto-warn", Box::new(|a: &App| { a.set_dialog("".into()); a.set_auto_warn(true); a.set_auto_sub("В NL, DE, FI пока нет рабочих серверов — нажмите «Найти»".into()); a.set_countries_text("NL, DE +1".into()); })),
        ("21-about", Box::new(|a: &App| { a.set_page(3); a.set_dialog("about".into()); })),
        ("22-uninstall", Box::new(|a: &App| { a.set_dialog("uninstall".into()); })),
    ];
    for (name, f) in shots {
        f(&app);
        // let animations settle
        for _ in 0..30 {
            slint::platform::update_timers_and_animations();
            std::thread::sleep(std::time::Duration::from_millis(12));
        }
        save(&window, w, h, &format!("{out}/{name}.png"));
        println!("{name}");
    }
    let _ = app.get_servers().row_count();
}
