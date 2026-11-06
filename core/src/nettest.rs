//! «Что блокирует ваша сеть»: a short test of the direct path through the scanner's
//! DIRECT listener (bound to the physical interface, so it works while the tunnel is up).
//! The scanner reads the result: UDP protocols are not tried where UDP does not get out,
//! WARP and servers behind Cloudflare are not tried where Cloudflare is unreachable,
//! servers must pass a download test where the provider cuts connections to foreign
//! hosting after ~16 KB, and white-list networks get white-list servers first.

use crate::mihomo::Listener;
use crate::probe::{self, Dl};
use crate::util;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

/// How long a result describes the network.
pub const MAX_AGE: u64 = 12 * 3600;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct NetProfile {
    pub at: u64,
    /// The network the result belongs to (public /16 and country): another network,
    /// another test.
    #[serde(default)]
    pub key: String,
    /// Foreign sites that are blocked nowhere (Google, Wikipedia, Apple, GitHub): opened, tried.
    #[serde(default)]
    pub foreign: [u8; 2],
    /// Domestic control sites (Yandex, VK): opened, tried.
    #[serde(default)]
    pub domestic: [u8; 2],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cloudflare: Option<bool>,
    /// UDP to foreign hosts gets through (STUN, DNS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,
    /// Plain DNS answers for blocked sites are replaced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns_spoof: Option<bool>,
    /// Downloads from foreign hosting stop after the first kilobytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cut: Option<bool>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cut_hosts: Vec<String>,
    /// Only domestic (white-listed) resources open.
    #[serde(default)]
    pub whitelist: bool,
}

impl NetProfile {
    /// Anything at all answered: otherwise the test says nothing about the network.
    pub fn valid(&self) -> bool {
        self.foreign[0] > 0 || self.domestic[0] > 0
    }
    pub fn fresh(&self, key: &str, now: u64, max_age: u64) -> bool {
        self.valid() && self.key == key && now.saturating_sub(self.at) < max_age
    }
    /// UDP-based protocols from public lists are pointless here.
    pub fn skip_udp(&self) -> bool {
        self.valid() && self.udp == Some(false)
    }
    /// Cloudflare (WARP, servers behind its addresses) is unreachable directly.
    pub fn cf_blocked(&self) -> bool {
        self.valid() && self.cloudflare == Some(false)
    }
    /// Servers must pass the download test (unknown counts as yes).
    pub fn volume(&self) -> bool {
        !self.valid() || self.cut != Some(false)
    }
}

/// Network key from the direct public IP and the country.
pub fn key_of(ip: Option<IpAddr>, cc: Option<&str>) -> String {
    let net = match ip {
        Some(IpAddr::V4(a)) => {
            let o = a.octets();
            format!("{}.{}.0.0/16", o[0], o[1])
        }
        Some(IpAddr::V6(a)) => {
            let s = a.segments();
            format!("{:x}:{:x}:{:x}::/48", s[0], s[1], s[2])
        }
        None => String::new(),
    };
    format!("{net}|{}", cc.unwrap_or(""))
}

/// Cloudflare's published IPv4 ranges (anycast: CDN, WARP, 1.1.1.1).
const CF_V4: &[(u32, u8)] = &[
    (0xADF5_3000, 20), // 173.245.48.0/20
    (0x6715_F400, 22), // 103.21.244.0/22
    (0x6716_C800, 22), // 103.22.200.0/22
    (0x671F_0400, 22), // 103.31.4.0/22
    (0x8D65_4000, 18), // 141.101.64.0/18
    (0x6CA2_C000, 18), // 108.162.192.0/18
    (0xBE5D_F000, 20), // 190.93.240.0/20
    (0xBC72_6000, 20), // 188.114.96.0/20
    (0xC5EA_F000, 22), // 197.234.240.0/22
    (0xC629_8000, 17), // 198.41.128.0/17
    (0xA29E_0000, 15), // 162.158.0.0/15
    (0x6810_0000, 13), // 104.16.0.0/13
    (0x6818_0000, 14), // 104.24.0.0/14
    (0xAC40_0000, 13), // 172.64.0.0/13
    (0x8300_4800, 22), // 131.0.72.0/22
    (0x0101_0100, 24), // 1.1.1.0/24
    (0x0100_0000, 24), // 1.0.0.0/24
];

pub fn in_cloudflare(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let v = u32::from(a);
            CF_V4.iter().any(|(net, len)| (v ^ net) >> (32 - *len as u32) == 0)
        }
        IpAddr::V6(a) => {
            let s = a.segments();
            // 2606:4700::/32, 2803:f800::/32, 2405:b500::/32, 2405:8100::/32, 2a06:98c0::/29, 2c0f:f248::/32
            matches!((s[0], s[1]), (0x2606, 0x4700) | (0x2803, 0xf800) | (0x2405, 0xb500) | (0x2405, 0x8100) | (0x2c0f, 0xf248)) || (s[0] == 0x2a06 && s[1] & 0xfff8 == 0x98c0)
        }
    }
}

const FOREIGN: &[&str] = &["https://www.gstatic.com/generate_204", "https://www.wikipedia.org/", "https://www.apple.com/library/test/success.html", "https://github.com/"];
const DOMESTIC: &[&str] = &["https://ya.ru/", "https://vk.com/", "https://mirror.yandex.ru/"];
const CLOUDFLARE: &[&str] = &["https://www.cloudflare.com/cdn-cgi/trace", "https://1.1.1.1/cdn-cgi/trace", "https://cp.cloudflare.com/generate_204"];
/// Foreign hosting providers most free servers live at, and a domestic control.
const HOSTING: &[(&str, &str)] = &[
    ("Hetzner", "https://fsn1-speed.hetzner.com/100MB.bin"),
    ("OVH", "https://proof.ovh.net/files/10Mb.dat"),
    ("Vultr", "https://fra-de-ping.vultr.com/vultr.com.100MB.bin"),
];
const CF_DOWNLOAD: &str = "https://speed.cloudflare.com/__down?bytes={n}";
const DOMESTIC_DOWNLOAD: &[&str] = &["https://mirror.yandex.ru/debian/ls-lR.gz", "https://speedtest.selectel.ru/10MB"];
/// Sites blocked in Russia with stable addresses: a replaced plain DNS answer shows here.
const SPOOF_PROBES: &[&str] = &["rutracker.org", "www.linkedin.com"];

async fn reach(c: &reqwest::Client, url: &str) -> bool {
    matches!(tokio::time::timeout(Duration::from_secs(8), c.get(url).send()).await, Ok(Ok(r)) if r.status().as_u16() < 500)
}

async fn reach_all(c: &reqwest::Client, urls: &[&str]) -> [u8; 2] {
    let mut js = tokio::task::JoinSet::new();
    for u in urls {
        let (c, u) = (c.clone(), u.to_string());
        js.spawn(async move { reach(&c, &u).await });
    }
    let mut ok = 0u8;
    while let Some(r) = js.join_next().await {
        if r.unwrap_or(false) {
            ok += 1;
        }
    }
    [ok, urls.len() as u8]
}

/// A DNS query for the A records of `name`.
pub fn dns_query(name: &str, id: u16) -> Vec<u8> {
    let mut q = Vec::with_capacity(32 + name.len());
    q.extend_from_slice(&id.to_be_bytes());
    q.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    for label in name.trim_end_matches('.').split('.') {
        let l = &label.as_bytes()[..label.len().min(63)];
        q.push(l.len() as u8);
        q.extend_from_slice(l);
    }
    q.push(0);
    q.extend_from_slice(&[0, 1, 0, 1]);
    q
}

fn skip_name(m: &[u8], mut i: usize) -> Option<usize> {
    for _ in 0..128 {
        let l = *m.get(i)? as usize;
        if l == 0 {
            return Some(i + 1);
        }
        if l & 0xC0 == 0xC0 {
            return Some(i + 2);
        }
        i += 1 + l;
    }
    None
}

/// A records of a DNS response to the query with `id` (None: not a response to it).
pub fn dns_answers(m: &[u8], id: u16) -> Option<Vec<Ipv4Addr>> {
    if m.len() < 12 || u16::from_be_bytes([m[0], m[1]]) != id || m[2] & 0x80 == 0 {
        return None;
    }
    let qd = u16::from_be_bytes([m[4], m[5]]) as usize;
    let an = u16::from_be_bytes([m[6], m[7]]) as usize;
    let mut i = 12;
    for _ in 0..qd {
        i = skip_name(m, i)? + 4;
    }
    let mut out = Vec::new();
    for _ in 0..an.min(64) {
        i = skip_name(m, i)?;
        let t = u16::from_be_bytes([*m.get(i)?, *m.get(i + 1)?]);
        let len = u16::from_be_bytes([*m.get(i + 8)?, *m.get(i + 9)?]) as usize;
        i += 10;
        if t == 1 && len == 4 {
            let b = m.get(i..i + 4)?;
            out.push(Ipv4Addr::new(b[0], b[1], b[2], b[3]));
        }
        i += len;
    }
    Some(out)
}

/// Plain DNS over UDP through the listener (the way the network sees ordinary lookups).
async fn dns_udp(l: &Listener, server: &str, name: &str) -> Option<Vec<Ipv4Addr>> {
    let id: u16 = rand::random();
    let q = dns_query(name, id);
    let body = probe::udp_exchange(l.port, &l.user, &l.pass, server, 53, &q, Duration::from_secs(5), |b| dns_answers(b, id).is_some()).await.ok()?;
    dns_answers(&body, id)
}

/// The same lookup over HTTPS (Google JSON API, then Yandex DoH): what the answer should be.
async fn dns_https(c: &reqwest::Client, name: &str) -> Option<Vec<Ipv4Addr>> {
    let url = format!("https://dns.google/resolve?name={name}&type=A");
    if let Ok(Ok(r)) = tokio::time::timeout(Duration::from_secs(7), c.get(&url).send()).await {
        if let Ok(v) = r.text().await.map(|t| serde_json::from_str::<Value>(&t).unwrap_or(Value::Null)) {
            if let Some(a) = v.get("Answer").and_then(Value::as_array) {
                let ips: Vec<Ipv4Addr> = a.iter().filter(|x| x.get("type").and_then(Value::as_u64) == Some(1)).filter_map(|x| x.get("data")?.as_str()?.parse().ok()).collect();
                return Some(ips);
            }
            if v.get("Status").is_some() {
                return Some(Vec::new());
            }
        }
    }
    let q = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(dns_query(name, 0));
    let url = format!("https://common.dot.dns.yandex.net/dns-query?dns={q}");
    let r = tokio::time::timeout(Duration::from_secs(7), c.get(&url).header("accept", "application/dns-message").send()).await.ok()?.ok()?;
    let b = r.bytes().await.ok()?;
    dns_answers(&b, 0)
}

fn bogon(ip: &Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_unspecified() || ip.is_link_local() || ip.is_broadcast() || ip.octets()[0] == 0
}

/// Plain answers vs. encrypted ones for the probe names: replaced when, for every name
/// both ways answered, the plain answer shares no address with the real one and either
/// points nowhere (private addresses) or is the same stub for different sites.
pub fn spoof_verdict(pairs: &[(Option<Vec<Ipv4Addr>>, Option<Vec<Ipv4Addr>>)]) -> Option<bool> {
    let both: Vec<(&Vec<Ipv4Addr>, &Vec<Ipv4Addr>)> = pairs.iter().filter_map(|(p, d)| Some((p.as_ref()?, d.as_ref()?))).filter(|(_, d)| !d.is_empty()).collect();
    if both.is_empty() {
        return None;
    }
    let disjoint = |p: &Vec<Ipv4Addr>, d: &Vec<Ipv4Addr>| !p.iter().any(|x| d.contains(x));
    if !both.iter().all(|(p, d)| disjoint(p, d)) {
        return Some(false);
    }
    let nowhere = both.iter().any(|(p, _)| p.is_empty() || p.iter().all(bogon));
    let stub = both.len() >= 2 && {
        let a: HashSet<&Ipv4Addr> = both[0].0.iter().collect();
        both[1..].iter().all(|(p, _)| !p.is_empty() && p.iter().all(|x| a.contains(x)))
    };
    // disjoint for every name: real resolvers agree with themselves
    Some(nowhere || stub || both.len() >= 2)
}

/// Runs the whole test (about 15 seconds) through the DIRECT listener `l`.
pub async fn run(l: &Listener, key: String) -> NetProfile {
    let mut p = NetProfile { at: util::now(), key, ..Default::default() };
    let Ok(c) = probe::client(Some((l.port, &l.user, &l.pass)), Duration::from_secs(10)) else { return p };
    let sites = async {
        let (f, d, cf) = tokio::join!(reach_all(&c, FOREIGN), reach_all(&c, DOMESTIC), reach_all(&c, CLOUDFLARE));
        (f, d, cf)
    };
    let udp = async {
        let stun_g = probe::stun_via(l.port, &l.user, &l.pass, "stun.l.google.com", 19302, Duration::from_secs(6));
        let dns_g = dns_udp(l, "8.8.8.8", "www.google.com");
        let dns_y = dns_udp(l, "77.88.8.8", "ya.ru");
        let (a, b, y) = tokio::join!(stun_g, dns_g, dns_y);
        (a.is_ok() || b.is_some(), y.is_some())
    };
    let spoof = async {
        let mut pairs = Vec::new();
        for name in SPOOF_PROBES {
            let (plain, real) = tokio::join!(dns_udp(l, "8.8.8.8", name), dns_https(&c, name));
            pairs.push((plain, real));
        }
        spoof_verdict(&pairs)
    };
    let cut = async {
        let want = 160 * 1024;
        let mut js = tokio::task::JoinSet::new();
        for (name, url) in HOSTING {
            let (c, name, url) = (c.clone(), name.to_string(), url.to_string());
            js.spawn(async move { (name, probe::download(&c, &url, want).await) });
        }
        let cfu = CF_DOWNLOAD.replace("{n}", &want.to_string());
        let c2 = c.clone();
        js.spawn(async move { ("Cloudflare".to_string(), probe::download(&c2, &cfu, want).await) });
        let mut res: Vec<(String, Dl)> = Vec::new();
        while let Some(Ok(r)) = js.join_next().await {
            res.push(r);
        }
        let mut home = Dl::Fail;
        for u in DOMESTIC_DOWNLOAD {
            home = probe::download(&c, u, want).await;
            if home != Dl::Fail {
                break;
            }
        }
        (res, home)
    };
    let ((f, d, cf), (udp_foreign, udp_home), spoofed, (dl, home)) = tokio::join!(sites, udp, spoof, cut);
    p.foreign = f;
    p.domestic = d;
    if p.valid() {
        p.cloudflare = Some(cf[0] > 0);
        p.udp = if udp_foreign { Some(true) } else if udp_home { Some(false) } else { None };
        p.dns_spoof = spoofed;
        // stalled after a few kilobytes while the domestic control (if it answered) went through
        let control_ok = home != Dl::Cut(0) && !matches!(home, Dl::Cut(n) if n < 64 * 1024);
        let mut cut_hosts: Vec<String> = dl.iter().filter(|(_, r)| matches!(r, Dl::Cut(n) if *n < 64 * 1024)).map(|(n, _)| n.clone()).collect();
        cut_hosts.sort();
        let full = dl.iter().any(|(_, r)| *r == Dl::Full);
        p.cut = if !cut_hosts.is_empty() && control_ok { Some(true) } else if full { Some(false) } else { None };
        if p.cut == Some(true) {
            p.cut_hosts = cut_hosts;
        }
        p.whitelist = d[0] > 0 && f[0] == 0 && cf[0] == 0;
    }
    p
}

/// One line for the log and the settings row.
pub fn summary(p: &NetProfile) -> String {
    if !p.valid() {
        return "не удалось проверить — нет связи".into();
    }
    let mut v: Vec<String> = Vec::new();
    if p.whitelist {
        v.push("белые списки".into());
    } else if p.foreign[0] < p.foreign[1] {
        v.push(format!("зарубежные сайты {} из {}", p.foreign[0], p.foreign[1]));
    }
    match p.udp {
        Some(true) => v.push("UDP есть".into()),
        Some(false) => v.push("UDP за рубеж не проходит".into()),
        None => {}
    }
    if p.cloudflare == Some(false) {
        v.push("Cloudflare недоступен".into());
    }
    if p.dns_spoof == Some(true) {
        v.push("DNS подменяется".into());
    }
    match p.cut {
        Some(true) => v.push(format!("обрыв 16 КБ: {}", p.cut_hosts.join(", "))),
        Some(false) => v.push("без обрывов".into()),
        None => {}
    }
    if v.is_empty() { "ограничений не найдено".into() } else { v.join(" · ") }
}

/// Rows for the details dialog: (title, value, state: 1 fine / 0 unknown / -1 problem, what it means).
pub fn lines(p: &NetProfile) -> Vec<(String, String, i8, String)> {
    let mut out = Vec::new();
    if !p.valid() {
        out.push(("Связь".into(), "нет ответа".into(), -1, "Ни один сайт не ответил — проверьте подключение к интернету.".into()));
        return out;
    }
    let tri = |o: Option<bool>| match o {
        Some(true) => 1,
        Some(false) => -1,
        None => 0,
    };
    out.push((
        "Зарубежные сайты".into(),
        format!("открылось {} из {}", p.foreign[0], p.foreign[1]),
        if p.foreign[0] == 0 { -1 } else { 1 },
        if p.whitelist {
            "Похоже на режим белых списков: открываются только разрешённые сайты. Серверы из «белых» списков проверяются первыми.".into()
        } else {
            String::new()
        },
    ));
    out.push((
        "Cloudflare".into(),
        match p.cloudflare {
            Some(true) => "доступен".into(),
            Some(false) => "недоступен".into(),
            None => "не проверен".into(),
        },
        tri(p.cloudflare),
        if p.cloudflare == Some(false) {
            "WARP напрямую не заработает — Лазейка его не проверяет и не тратит на это время. Серверы с адресами Cloudflare пропускаются. Через VPN WARP работает: цепочка «VPN → WARP».".into()
        } else {
            String::new()
        },
    ));
    out.push((
        "UDP".into(),
        match p.udp {
            Some(true) => "проходит".into(),
            Some(false) => "за рубеж не проходит".into(),
            None => "не проверен".into(),
        },
        tri(p.udp),
        if p.udp == Some(false) { "Hysteria2, TUIC и WireGuard из бесплатных списков не проверяются: в этой сети они не заработают.".into() } else { String::new() },
    ));
    out.push((
        "DNS".into(),
        match p.dns_spoof {
            Some(true) => "подменяется".into(),
            Some(false) => "честный".into(),
            None => "не проверен".into(),
        },
        tri(p.dns_spoof.map(|s| !s)),
        if p.dns_spoof == Some(true) { "Провайдер подменяет адреса заблокированных сайтов. Лазейка узнаёт адреса через зашифрованный DNS — на её работу это не влияет.".into() } else { String::new() },
    ));
    out.push((
        "Обрыв после 16 КБ".into(),
        match p.cut {
            Some(true) => format!("есть: {}", p.cut_hosts.join(", ")),
            Some(false) => "нет".into(),
            None => "не проверен".into(),
        },
        tri(p.cut.map(|c| !c)),
        if p.cut == Some(true) {
            "Провайдер обрывает соединения с зарубежными хостингами после первых килобайт: сервер отвечает на проверку, но сайты через него не грузятся. Каждый найденный сервер теперь проверяется скачиванием 160 КБ — такие отсеиваются.".into()
        } else {
            String::new()
        },
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_roundtrip() {
        let q = dns_query("ya.ru", 0x1234);
        assert_eq!(&q[..2], &[0x12, 0x34]);
        // response: header (QR set, 1 question, 1 answer), question copied, answer via pointer
        let mut r = q.clone();
        r[2] = 0x81;
        r[3] = 0x80;
        r[7] = 1;
        r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 77, 88, 55, 242]);
        assert_eq!(dns_answers(&r, 0x1234), Some(vec![Ipv4Addr::new(77, 88, 55, 242)]));
        assert_eq!(dns_answers(&r, 0x9999), None);
        assert_eq!(dns_answers(&q, 0x1234), None, "a query is not an answer");
    }

    #[test]
    fn cloudflare_ranges() {
        assert!(in_cloudflare("104.21.33.146".parse().unwrap()));
        assert!(in_cloudflare("172.67.146.105".parse().unwrap()));
        assert!(in_cloudflare("188.114.97.1".parse().unwrap()));
        assert!(in_cloudflare("162.159.192.1".parse().unwrap()));
        assert!(in_cloudflare("1.1.1.1".parse().unwrap()));
        assert!(!in_cloudflare("8.8.8.8".parse().unwrap()));
        assert!(!in_cloudflare("95.217.1.1".parse().unwrap()));
        assert!(in_cloudflare("2606:4700::6810:84e5".parse().unwrap()));
        assert!(!in_cloudflare("2a01:4f8::1".parse().unwrap()));
    }

    #[test]
    fn spoof_rules() {
        let ip = |s: &str| s.parse::<Ipv4Addr>().unwrap();
        // honest: plain and encrypted agree
        assert_eq!(spoof_verdict(&[(Some(vec![ip("195.82.146.214")]), Some(vec![ip("195.82.146.214")]))]), Some(false));
        // one stub for two different sites
        let stub = vec![ip("62.33.207.196")];
        assert_eq!(spoof_verdict(&[(Some(stub.clone()), Some(vec![ip("195.82.146.214")])), (Some(stub), Some(vec![ip("13.107.42.14")]))]), Some(true));
        // a private answer
        assert_eq!(spoof_verdict(&[(Some(vec![ip("10.10.34.35")]), Some(vec![ip("195.82.146.214")])), (None, None)]), Some(true));
        // nothing to compare
        assert_eq!(spoof_verdict(&[(None, Some(vec![ip("1.2.3.4")]))]), None);
    }

    #[test]
    fn profile_gates() {
        let mut p = NetProfile { foreign: [3, 4], domestic: [3, 3], udp: Some(false), cloudflare: Some(false), cut: Some(false), key: "k".into(), at: 100, ..Default::default() };
        assert!(p.skip_udp() && p.cf_blocked() && !p.volume());
        assert!(p.fresh("k", 200, MAX_AGE) && !p.fresh("other", 200, MAX_AGE) && !p.fresh("k", 100 + MAX_AGE, MAX_AGE));
        p.cut = None;
        assert!(p.volume(), "unknown cut: test the volume");
        let dead = NetProfile::default();
        assert!(!dead.skip_udp() && !dead.cf_blocked() && dead.volume());
        assert_eq!(key_of(Some("95.24.1.2".parse().unwrap()), Some("RU")), "95.24.0.0/16|RU");
    }
}
