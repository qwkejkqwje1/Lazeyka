//! The "smart" layer over routes: a catalog of ready-made packs (AI services, Gemini,
//! messengers, banks …), forgiving bulk input (hosts files, Clash/v2ray lines, URLs,
//! program paths), an explainer ("where will this site go and why") and a linter that
//! finds duplicates, shadowed entries and broken references. Pure functions, no I/O.

use crate::routes::{Route, Routes, Target};
use crate::split::{is_ip_entry, normalize_app, normalize_site};
use std::net::IpAddr;

// ------------------------------------------------------------------ catalog

pub struct Preset {
    pub id: &'static str,
    pub name: &'static str,
    pub desc: &'static str,
    /// Suggested direction, in `Target` code form ("country:US", "direct", "vpn").
    pub hint: &'static str,
    pub sites: &'static [&'static str],
    pub apps: &'static [&'static str],
}

pub const PRESETS: &[Preset] = &[
    Preset {
        id: "gemini",
        name: "Google Gemini",
        desc: "Gemini, AI Studio, NotebookLM, API — только через выбранную страну",
        hint: "country:US",
        sites: &[
            "gemini.google.com", "aistudio.google.com", "makersuite.google.com", "bard.google.com", "notebooklm.google.com",
            "notebooklm.google", "generativelanguage.googleapis.com", "ai.google.dev", "labs.google", "deepmind.google",
            "proactivebackend-pa.googleapis.com", "geminiweb-pa.clients6.google.com",
        ],
        apps: &[],
    },
    Preset {
        id: "ai",
        name: "ИИ-сервисы",
        desc: "ChatGPT, Claude, Perplexity, Copilot, Grok, Mistral, Hugging Face и др.",
        hint: "country:US",
        sites: &[
            "openai.com", "chatgpt.com", "oaistatic.com", "oaiusercontent.com", "sora.com", "anthropic.com", "claude.ai", "claude.com",
            "perplexity.ai", "copilot.microsoft.com", "bing.com", "x.ai", "grok.com", "poe.com", "mistral.ai", "huggingface.co",
            "midjourney.com", "character.ai", "cursor.com", "cursor.sh", "meta.ai", "elevenlabs.io", "suno.com", "runwayml.com",
        ],
        apps: &[],
    },
    Preset {
        id: "youtube",
        name: "YouTube",
        desc: "Видео, превью и API YouTube",
        hint: "vpn",
        sites: &["youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "ggpht.com", "youtube-nocookie.com", "youtubei.googleapis.com"],
        apps: &[],
    },
    Preset {
        id: "social",
        name: "Соцсети",
        desc: "Instagram, Facebook, Threads, X/Twitter, LinkedIn, Reddit, TikTok",
        hint: "vpn",
        sites: &[
            "instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net", "fb.com", "threads.net", "x.com", "twitter.com", "twimg.com",
            "t.co", "linkedin.com", "licdn.com", "reddit.com", "redd.it", "redditmedia.com", "redditstatic.com", "tiktok.com", "tiktokcdn.com",
        ],
        apps: &[],
    },
    Preset {
        id: "messengers",
        name: "Мессенджеры и голос",
        desc: "Telegram, Discord, WhatsApp, Signal",
        hint: "vpn",
        sites: &[
            "telegram.org", "t.me", "telegram.me", "telesco.pe", "tdesktop.com", "discord.com", "discord.gg", "discordapp.com", "discordapp.net",
            "discord.media", "whatsapp.com", "whatsapp.net", "signal.org", "signal.me",
        ],
        apps: &["Telegram.exe", "Discord.exe", "WhatsApp.exe", "Signal.exe"],
    },
    Preset {
        id: "streaming",
        name: "Стриминг",
        desc: "Netflix, Spotify, Twitch, Disney+, Max, Prime Video",
        hint: "vpn",
        sites: &[
            "netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com", "nflxso.net", "spotify.com", "scdn.co", "spotifycdn.com", "twitch.tv",
            "ttvnw.net", "jtvnw.net", "disneyplus.com", "disney-plus.net", "bamgrid.com", "max.com", "hbomax.com", "primevideo.com",
        ],
        apps: &["Spotify.exe"],
    },
    Preset {
        id: "dev",
        name: "Разработка",
        desc: "GitHub, npm, PyPI, crates.io, Docker, Stack Overflow, JetBrains",
        hint: "vpn",
        sites: &[
            "github.com", "githubusercontent.com", "githubassets.com", "github.io", "npmjs.org", "npmjs.com", "pypi.org", "pythonhosted.org",
            "crates.io", "rust-lang.org", "docker.com", "docker.io", "stackoverflow.com", "stackexchange.com", "jetbrains.com", "golang.org", "go.dev",
        ],
        apps: &[],
    },
    Preset {
        id: "games",
        name: "Игры",
        desc: "Steam, Epic, Riot, Blizzard, EA, Ubisoft",
        hint: "direct",
        sites: &[
            "steampowered.com", "steamcommunity.com", "steamstatic.com", "steamcontent.com", "epicgames.com", "unrealengine.com", "riotgames.com",
            "leagueoflegends.com", "blizzard.com", "battle.net", "ea.com", "ubisoft.com", "ubi.com",
        ],
        apps: &["steam.exe", "EpicGamesLauncher.exe", "Battle.net.exe", "RiotClientServices.exe"],
    },
    Preset {
        id: "ru",
        name: "Российские сервисы",
        desc: "Домены .ru, .рф, .su, Яндекс, VK, банки — всегда напрямую",
        hint: "direct",
        sites: &[
            "ru", "рф", "su", "yandex.net", "yandex.com", "yastatic.net", "ya.ru", "vk.com", "vk.me", "userapi.com", "vkuser.net", "mycdn.me",
            "sberbank.com", "tbank.ru", "tinkoff.ru",
        ],
        apps: &[],
    },
    Preset {
        id: "lan",
        name: "Локальная сеть",
        desc: "Домашняя сеть, роутер, принтеры, NAS — никогда через VPN",
        hint: "direct",
        sites: &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fc00::/7", "fe80::/10"],
        apps: &[],
    },
    Preset {
        id: "updates",
        name: "Обновления и тяжёлые загрузки",
        desc: "Windows Update и магазин — не тратят трафик VPN",
        hint: "direct",
        sites: &["windowsupdate.com", "update.microsoft.com", "delivery.mp.microsoft.com", "download.windowsupdate.com", "tlu.dl.delivery.mp.microsoft.com"],
        apps: &[],
    },
    Preset {
        id: "torrent",
        name: "Торренты",
        desc: "Торрент-клиенты — напрямую (или блокировать через VPN)",
        hint: "direct",
        sites: &[],
        apps: &["qbittorrent.exe", "utorrent.exe", "bittorrent.exe", "transmission-qt.exe", "deluge.exe"],
    },
];

pub fn preset(id: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|p| p.id == id)
}

impl Preset {
    /// Normalized entries (the catalog is plain text; normalization is applied here
    /// so a typo in the catalog can never reach the configuration).
    pub fn entries(&self) -> (Vec<String>, Vec<String>) {
        let mut sites: Vec<String> = Vec::new();
        for s in self.sites {
            if let Ok(n) = normalize_site(s) {
                if !sites.contains(&n) {
                    sites.push(n);
                }
            }
        }
        let mut apps: Vec<String> = Vec::new();
        for a in self.apps {
            if let Ok(n) = normalize_app(a) {
                if !apps.contains(&n) {
                    apps.push(n);
                }
            }
        }
        (sites, apps)
    }
}

// --------------------------------------------------------------- bulk input

#[derive(Debug, Default, PartialEq)]
pub struct Bulk {
    pub sites: Vec<String>,
    pub apps: Vec<String>,
    /// Pieces that could not be understood (shortened), for the user to see.
    pub rejected: Vec<String>,
}

const MAX_BULK: usize = 20_000;

fn looks_like_app(t: &str) -> bool {
    let l = t.to_ascii_lowercase();
    l.ends_with(".exe") || ((t.contains('\\') || t.starts_with("\"")) && (l.trim_end_matches('"').ends_with(".exe") || l.contains(".exe\"")))
}

fn push_unique(v: &mut Vec<String>, x: String) {
    if !v.contains(&x) {
        v.push(x);
    }
}

fn is_unspecified_host(t: &str) -> bool {
    t.parse::<IpAddr>().is_ok_and(|ip| ip.is_unspecified() || ip.is_loopback()) && !t.contains('/')
}

/// Understands what people actually paste: one entry per line, several per line separated by
/// spaces/commas/semicolons, `hosts` lines, URLs, `*.example.com`, `+.example.com`, Clash
/// rules (`DOMAIN-SUFFIX,x.com`, `IP-CIDR,1.2.3.0/24`, `PROCESS-NAME,a.exe`), v2ray prefixes
/// (`domain:`, `full:`), AdBlock `||x.com^`, comments (`#`, `//`), and program paths.
pub fn parse_bulk(text: &str) -> Bulk {
    let mut out = Bulk::default();
    let mut seen = 0usize;
    for raw in text.lines() {
        let mut line = raw.trim().trim_start_matches('\u{feff}');
        if let Some(i) = line.find(" #").or_else(|| line.find("\t#")) {
            line = line[..i].trim();
        }
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") || line.starts_with(';') || line.starts_with('!') {
            continue;
        }
        // Clash-style rule: KEYWORD,value[,options]
        if let Some((kw, rest)) = line.split_once(',') {
            let k = kw.trim().to_ascii_uppercase();
            let val = rest.split(',').next().unwrap_or("").trim();
            match k.as_str() {
                "DOMAIN" | "DOMAIN-SUFFIX" | "IP-CIDR" | "IP-CIDR6" => {
                    seen += 1;
                    match normalize_site(val) {
                        Ok(n) => push_unique(&mut out.sites, n),
                        Err(_) => out.rejected.push(clip(line)),
                    }
                    continue;
                }
                "PROCESS-NAME" | "PROCESS-PATH" => {
                    seen += 1;
                    match normalize_app(val) {
                        Ok(n) => push_unique(&mut out.apps, n),
                        Err(_) => out.rejected.push(clip(line)),
                    }
                    continue;
                }
                "DOMAIN-KEYWORD" | "DOMAIN-REGEX" | "GEOSITE" | "GEOIP" | "RULE-SET" | "MATCH" | "FINAL" | "AND" | "OR" | "NOT" | "SRC-IP-CIDR" | "DST-PORT" => {
                    out.rejected.push(clip(line));
                    continue;
                }
                _ => {}
            }
        }
        // a whole line that is a program path (may contain spaces)
        if looks_like_app(line) && !line.contains(',') {
            seen += 1;
            match normalize_app(line) {
                Ok(n) => push_unique(&mut out.apps, n),
                Err(_) => out.rejected.push(clip(line)),
            }
            continue;
        }
        let toks: Vec<&str> = line.split(|c: char| c.is_whitespace() || c == ',' || c == ';').filter(|t| !t.is_empty()).collect();
        for (i, t0) in toks.iter().enumerate() {
            // hosts file: "0.0.0.0 example.com" — the address column is not an entry
            if i == 0 && toks.len() > 1 && is_unspecified_host(t0) {
                continue;
            }
            seen += 1;
            if seen > MAX_BULK {
                out.rejected.push("слишком много записей — остальное пропущено".into());
                return out;
            }
            let mut t = t0.trim_matches(|c| c == '"' || c == '\'');
            for p in ["domain:", "full:", "domain-suffix:", "suffix:", "||", "+.", "."] {
                if let Some(r) = t.strip_prefix(p) {
                    t = r;
                    break;
                }
            }
            let t = t.trim_end_matches('^');
            if t.is_empty() {
                continue;
            }
            // a bare word is a whole-zone entry ("ru"): only when it is alone on its line
            // and short; in running text it is far more likely a stray word
            let bare = !t.contains('.') && !t.contains(':') && !t.contains('/');
            if bare && !looks_like_app(t) && !(toks.len() == 1 && t.chars().count() <= 4) {
                out.rejected.push(clip(t0));
            } else if looks_like_app(t) {
                match normalize_app(t) {
                    Ok(n) => push_unique(&mut out.apps, n),
                    Err(_) => out.rejected.push(clip(t0)),
                }
            } else {
                match normalize_site(t) {
                    Ok(n) => push_unique(&mut out.sites, n),
                    Err(_) => out.rejected.push(clip(t0)),
                }
            }
        }
    }
    out
}

fn clip(s: &str) -> String {
    crate::util::clip(s, 48)
}

// ---------------------------------------------------------------- matching

/// A site entry matches a host: domains cover themselves and subdomains; IP entries
/// are CIDR blocks.
pub fn entry_matches(entry: &str, host: &str) -> bool {
    if is_ip_entry(entry) {
        let Ok(ip) = host.trim_end_matches("/32").trim_end_matches("/128").parse::<IpAddr>() else { return false };
        return cidr_contains(entry, ip);
    }
    host == entry || host.strip_suffix(entry).is_some_and(|p| p.ends_with('.'))
}

fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let Some((base, pfx)) = cidr.split_once('/') else { return false };
    let (Ok(base), Ok(pfx)) = (base.parse::<IpAddr>(), pfx.parse::<u32>()) else { return false };
    match (base, ip) {
        (IpAddr::V4(b), IpAddr::V4(i)) if pfx <= 32 => {
            let m = if pfx == 0 { 0 } else { u32::MAX << (32 - pfx) };
            u32::from(b) & m == u32::from(i) & m
        }
        (IpAddr::V6(b), IpAddr::V6(i)) if pfx <= 128 => {
            let m = if pfx == 0 { 0 } else { u128::MAX << (128 - pfx) };
            u128::from(b) & m == u128::from(i) & m
        }
        _ => false,
    }
}

/// `inner` is covered by `outer` (same entry, a subdomain of it, or a smaller block).
pub fn entry_covers(outer: &str, inner: &str) -> bool {
    if is_ip_entry(outer) || is_ip_entry(inner) {
        if !(is_ip_entry(outer) && is_ip_entry(inner)) {
            return false;
        }
        let (Some((ib, ip)), Some((_, op))) = (inner.split_once('/'), outer.split_once('/')) else { return false };
        let (Ok(ib), Ok(ip), Ok(op)) = (ib.parse::<IpAddr>(), ip.parse::<u32>(), op.parse::<u32>()) else { return false };
        return op <= ip && cidr_contains(outer, ib);
    }
    entry_matches(outer, inner)
}

// ------------------------------------------------------------------ explain

#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub unit_id: String,
    pub name: String,
    pub target: Target,
    pub entry: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Subject {
    Site(String),
    App(String),
    Invalid,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Explain {
    pub subject: Subject,
    /// All routing units that match, in precedence order; the first one decides.
    pub hits: Vec<Hit>,
    pub default: Target,
}

impl Explain {
    pub fn winner(&self) -> Option<&Hit> {
        self.hits.first()
    }
    pub fn target(&self) -> &Target {
        self.winner().map(|h| &h.target).unwrap_or(&self.default)
    }
}

/// Where would a site (URL, domain, IP) or a program go, and which rule decides?
pub fn explain(routes: &Routes, input: &str) -> Explain {
    let t = input.trim();
    let subject = if t.is_empty() {
        Subject::Invalid
    } else if looks_like_app(t) {
        normalize_app(t).map(Subject::App).unwrap_or(Subject::Invalid)
    } else {
        normalize_site(t).map(|s| Subject::Site(s.trim_end_matches("/32").trim_end_matches("/128").to_string())).unwrap_or(Subject::Invalid)
    };
    let mut hits = Vec::new();
    for u in routes.units() {
        match &subject {
            Subject::Site(h) => {
                // the most specific entry of the unit is the one worth showing
                let best = routes
                    .eff_list(&u, false)
                    .into_iter()
                    .filter(|e| entry_matches(e, h))
                    .max_by_key(|e| e.len());
                if let Some(e) = best {
                    hits.push(Hit { unit_id: u.id.clone(), name: u.name.clone(), target: u.target.clone(), entry: e });
                }
            }
            Subject::App(a) => {
                if let Some(e) = routes.eff_list(&u, true).into_iter().find(|e| e.eq_ignore_ascii_case(a)) {
                    hits.push(Hit { unit_id: u.id.clone(), name: u.name.clone(), target: u.target.clone(), entry: e });
                }
            }
            Subject::Invalid => {}
        }
    }
    Explain { subject, hits, default: routes.default.clone() }
}

// --------------------------------------------------------------------- lint

#[derive(Debug, Clone, PartialEq)]
pub struct Issue {
    /// Route (unit) the issue is about, or empty.
    pub route: String,
    pub text: String,
}

/// Problems worth telling the user about, most important first.
pub fn lint(routes: &Routes) -> Vec<Issue> {
    let mut out = Vec::new();
    let units = routes.units();
    // empty / dangling
    for r in routes.list.iter().filter(|r| r.enabled) {
        if routes.eff_entries(r) == 0 {
            out.push(Issue { route: r.id.clone(), text: format!("Маршрут «{}» пуст — добавьте сайты, программы или подключите список", r.name) });
        }
        for l in &r.lists {
            if routes.entry_list(l).is_none() {
                out.push(Issue { route: r.id.clone(), text: format!("В маршруте «{}» подключён удалённый список", r.name) });
            }
        }
    }
    for u in &units {
        if let Target::Chain(c) = &u.target {
            if routes.chain(c).is_none() {
                out.push(Issue { route: u.id.clone(), text: format!("«{}» ведёт в удалённую цепочку — трафик пойдёт через VPN", u.name) });
            }
        }
    }
    if let Target::Chain(c) = &routes.default {
        if routes.chain(c).is_none() {
            out.push(Issue { route: String::new(), text: "Остальной трафик ведёт в удалённую цепочку".into() });
        }
    }
    // duplicates and shadowing between units
    for (j, b) in units.iter().enumerate() {
        for apps in [false, true] {
            for e in routes.eff_list(b, apps) {
                for a in units.iter().take(j) {
                    let hit = routes.eff_list(a, apps).into_iter().find(|x| if apps { x.eq_ignore_ascii_case(&e) } else { entry_covers(x, &e) });
                    if let Some(x) = hit {
                        if a.target == b.target {
                            break;
                        }
                        let text = if x == e {
                            format!("«{e}» есть и в «{}», и в «{}» — сработает «{}»", a.name, b.name, a.name)
                        } else {
                            format!("«{e}» в «{}» никогда не сработает: его перекрывает «{x}» в «{}» (поднимите «{}» выше)", b.name, a.name, b.name)
                        };
                        out.push(Issue { route: b.id.clone(), text });
                        break;
                    }
                }
            }
        }
    }
    if routes.default == Target::Direct && units.is_empty() {
        out.push(Issue { route: String::new(), text: "Остальной трафик идёт напрямую, а маршрутов нет — VPN ничего не защищает".into() });
    }
    out.truncate(20);
    out
}

/// True when `r` would not change anything (kept for UI code that wants a quick check).
pub fn is_blank(routes: &Routes, r: &Route) -> bool {
    routes.eff_entries(r) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::{EntryList, Route};

    #[test]
    fn catalog_is_valid() {
        let mut ids = std::collections::HashSet::new();
        for p in PRESETS {
            assert!(ids.insert(p.id), "dup id {}", p.id);
            Target::parse(p.hint).unwrap();
            let (s, a) = p.entries();
            assert_eq!(s.len(), p.sites.iter().map(|x| normalize_site(x).unwrap()).collect::<std::collections::HashSet<_>>().len(), "{}", p.id);
            assert_eq!(a.len(), p.apps.len(), "{}", p.id);
            assert!(!s.is_empty() || !a.is_empty());
        }
    }

    #[test]
    fn bulk_formats() {
        let b = parse_bulk(
            "# comment\n0.0.0.0 ads.example.com\nhttps://www.Gemini.google.com/app, aistudio.google.com ; *.openai.com\n\
             DOMAIN-SUFFIX,claude.ai,Proxy\nIP-CIDR,10.1.2.3/8\nPROCESS-NAME,chrome.exe\ndomain:github.com\n||tracker.net^\n\
             C:\\Program Files\\Steam\\steam.exe\nDOMAIN-KEYWORD,google\nbad host!!\n+.t.me\n",
        );
        assert_eq!(
            b.sites,
            ["ads.example.com", "gemini.google.com", "aistudio.google.com", "openai.com", "claude.ai", "10.0.0.0/8", "github.com", "tracker.net", "t.me"]
        );
        assert_eq!(b.apps, ["chrome.exe", "steam.exe"]);
        assert_eq!(b.rejected.len(), 3, "{:?}", b.rejected);
        // dedup
        assert_eq!(parse_bulk("a.com a.com\nA.COM").sites, ["a.com"]);
    }

    #[test]
    fn matching() {
        assert!(entry_matches("google.com", "gemini.google.com"));
        assert!(entry_matches("google.com", "google.com"));
        assert!(!entry_matches("google.com", "notgoogle.com"));
        assert!(entry_matches("192.168.0.0/16", "192.168.4.7"));
        assert!(!entry_matches("192.168.0.0/16", "192.169.4.7"));
        assert!(!entry_matches("192.168.0.0/16", "example.com"));
        assert!(entry_matches("fc00::/7", "fd12::1"));
        assert!(entry_covers("google.com", "gemini.google.com"));
        assert!(!entry_covers("gemini.google.com", "google.com"));
        assert!(entry_covers("10.0.0.0/8", "10.1.0.0/16"));
        assert!(!entry_covers("10.1.0.0/16", "10.0.0.0/8"));
    }

    fn sample() -> (Routes, String, String) {
        let mut r = Routes::default();
        let mut gem = Route::new("Gemini", Target::Country("US".into()));
        gem.sites = vec!["gemini.google.com".into()];
        let mut goo = Route::new("Google", Target::Vpn);
        goo.sites = vec!["google.com".into()];
        goo.apps = vec!["chrome.exe".into()];
        let (a, b) = (gem.id.clone(), goo.id.clone());
        r.list = vec![gem, goo];
        (r, a, b)
    }

    #[test]
    fn explain_picks_first_and_lists_all() {
        let (r, a, _) = sample();
        let e = explain(&r, "https://gemini.google.com/app");
        assert_eq!(e.winner().unwrap().unit_id, a);
        assert_eq!(e.target(), &Target::Country("US".into()));
        assert_eq!(e.hits.len(), 2);
        let e = explain(&r, "mail.google.com");
        assert_eq!(e.target(), &Target::Vpn);
        assert_eq!(e.hits.len(), 1);
        let e = explain(&r, "example.org");
        assert!(e.winner().is_none());
        assert_eq!(e.target(), &Target::Vpn);
        let e = explain(&r, r"C:\x\Chrome.EXE");
        assert_eq!(e.hits.len(), 1);
        assert_eq!(explain(&r, "bad host").subject, Subject::Invalid);
        assert_eq!(explain(&r, "").subject, Subject::Invalid);
    }

    #[test]
    fn lint_finds_shadowing_and_dupes() {
        let (mut r, _, _) = sample();
        assert!(lint(&r).is_empty());
        // reversed order: google.com first hides gemini.google.com in the later route
        r.list.reverse();
        let l = lint(&r);
        assert_eq!(l.len(), 1, "{l:?}");
        assert!(l[0].text.contains("никогда не сработает"));
        // exact duplicate with a different target
        r.list.reverse();
        r.list[1].sites.push("gemini.google.com".into());
        let l = lint(&r);
        assert!(l.iter().any(|i| i.text.contains("есть и в")), "{l:?}");
        // empty route and dangling list
        let mut e = Route::new("Пусто", Target::Direct);
        e.lists.push("gone".into());
        r.list.push(e);
        assert!(lint(&r).iter().any(|i| i.text.contains("пуст")));
        assert!(lint(&r).iter().any(|i| i.text.contains("удалённый список")));
        // same target is not a conflict
        let (mut r2, _, _) = sample();
        r2.list[1].target = Target::Country("US".into());
        assert!(lint(&r2).is_empty());
        // direct default without routes
        let mut r3 = Routes::default();
        r3.default = Target::Direct;
        assert_eq!(lint(&r3).len(), 1);
        let mut l = EntryList::new("x");
        l.sites.push("a.com".into());
        let _ = l;
    }
}
