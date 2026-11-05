//! Catalog of public server lists (regularly updated GitHub/Codeberg/GitLab repos)
//! with mirrors, tiers and caps; fetching with cache fallback.

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Duration;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SourceDef {
    pub id: String,
    pub name: String,
    /// 1 = made for Russia, small and fresh; 2 = Russia, large; 3 = global aggregators.
    pub tier: u8,
    /// Max candidates taken from this source per scan.
    pub cap: usize,
    /// Primary URL first, then mirrors.
    pub urls: Vec<String>,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn yes() -> bool {
    true
}

fn igareck(file: &str) -> Vec<String> {
    let f = file.replace('+', "%2B");
    vec![
        format!("https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/{f}"),
        format!("https://codeberg.org/igareck/vpn-configs-for-russia/raw/branch/main/{f}"),
        format!("https://gitlab.com/igareck/vpn-configs-for-russia/-/raw/main/{f}"),
        format!("https://bitbucket.org/igareck/vpn-configs-for-russia/raw/main/{f}"),
        format!("https://raw.githack.com/igareck/vpn-configs-for-russia/main/{f}"),
    ]
}

fn gh(repo: &str, path: &str) -> Vec<String> {
    vec![
        format!("https://raw.githubusercontent.com/{repo}/{path}"),
        format!("https://raw.githack.com/{repo}/{}", path.trim_start_matches("refs/heads/")),
    ]
}

fn def(id: &str, name: &str, tier: u8, cap: usize, urls: Vec<String>, enabled: bool) -> SourceDef {
    SourceDef { id: id.into(), name: name.into(), tier, cap, urls, enabled }
}

/// Built-in catalog. Order inside a tier = default priority.
pub fn catalog() -> Vec<SourceDef> {
    vec![
        def("igareck-vless", "igareck · VLESS (РФ)", 1, 400, igareck("BLACK_VLESS_RUS.txt"), true),
        def("igareck-vless-mobile", "igareck · VLESS мобильный (РФ)", 1, 400, igareck("BLACK_VLESS_RUS_mobile.txt"), true),
        def("igareck-mixed", "igareck · SS/Trojan/Hysteria2 (РФ)", 1, 400, igareck("BLACK_SS+All_RUS.txt"), true),
        def("igareck-weak-dpi", "igareck · SS слабый DPI (РФ)", 1, 200, igareck("BLACK_SS_WEAK_DPI_RUS.txt"), true),
        def("zieng2-wl", "zieng2 · VLESS universal", 1, 300, gh("zieng2/wl", "main/vless_universal.txt"), true),
        def("rkp-black", "RKP · обход блокировок", 1, 100, gh("RKPchannel/RKP_bypass_configs", "refs/heads/main/blacklist.txt"), true),
        def("igareck-white-mobile", "igareck · белые списки (мобильный)", 1, 300, igareck("Vless-Reality-White-Lists-Rus-Mobile.txt"), true),
        def("rkp-white", "RKP · белые списки", 1, 100, gh("RKPchannel/RKP_bypass_configs", "refs/heads/main/whitelist.txt"), true),
        def("kort0881-vless", "kort0881 · VLESS RU-SNI", 2, 400, gh("kort0881/vpn-vless-configs-russia", "main/data/githubmirror/ru-sni/vless.txt"), true),
        def("kort0881-hy2", "kort0881 · Hysteria2", 2, 200, gh("kort0881/vpn-vless-configs-russia", "main/data/githubmirror/clean/hysteria2.txt"), true),
        def("matin-vless", "MatinGhanbari · VLESS", 3, 250, gh("MatinGhanbari/v2ray-configs", "main/subscriptions/filtered/subs/vless.txt"), true),
        def("matin-hy2", "MatinGhanbari · Hysteria2", 3, 150, gh("MatinGhanbari/v2ray-configs", "main/subscriptions/filtered/subs/hysteria2.txt"), true),
        def("matin-trojan", "MatinGhanbari · Trojan", 3, 150, gh("MatinGhanbari/v2ray-configs", "main/subscriptions/filtered/subs/trojan.txt"), true),
        def("matin-ss", "MatinGhanbari · Shadowsocks", 3, 150, gh("MatinGhanbari/v2ray-configs", "main/subscriptions/filtered/subs/ss.txt"), true),
        def("mahan-vless", "MahanKenway · VLESS", 3, 200, gh("MahanKenway/Freedom-V2Ray", "main/configs/vless.txt"), true),
        def("danial-vless", "Danialsamadi · VLESS", 3, 200, gh("Danialsamadi/v2go", "main/Splitted-By-Protocol/vless.txt"), true),
        def("barry-vless", "barry-far · VLESS (большой)", 3, 300, gh("barry-far/V2ray-Config", "main/Splitted-By-Protocol/vless.txt"), true),
        def("soli-vless", "SoliSpirit · VLESS (большой)", 3, 300, gh("SoliSpirit/v2ray-configs", "refs/heads/main/Protocols/vless.txt"), false),
        def("radikal-all", "0xRadikal · все (очень большой)", 3, 300, gh("0xRadikal/Free-v2ray-Configs", "main/all/configs.txt"), false),
    ]
}

pub const MAX_SIZE: usize = 6 * 1024 * 1024;

pub fn fetch_client() -> reqwest::Client {
    reqwest::Client::builder()
        .tls_backend_preconfigured(crate::probe::tls_config())
        .user_agent("Lazeyka/0.1")
        .connect_timeout(Duration::from_secs(8))
        .timeout(Duration::from_secs(25))
        .no_proxy()
        .build()
        .expect("client")
}

pub async fn get_capped(c: &reqwest::Client, url: &str, cap: usize) -> Result<String, String> {
    let mut r = c.get(url).send().await.map_err(|e| crate::probe::short_err(&e))?;
    if !r.status().is_success() {
        return Err(format!("HTTP {}", r.status().as_u16()));
    }
    let mut buf: Vec<u8> = Vec::new();
    while let Some(ch) = r.chunk().await.map_err(|e| crate::probe::short_err(&e))? {
        buf.extend_from_slice(&ch);
        if buf.len() > cap {
            // keep what we have up to the last full line
            if let Some(p) = buf.iter().rposition(|b| *b == b'\n') {
                buf.truncate(p + 1);
            }
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Fetches a source trying mirrors in order; uses a fresh cache entry if younger than
/// `max_age` seconds and falls back to any cached copy when all mirrors fail.
pub async fn fetch(c: &reqwest::Client, d: &SourceDef, cache: &Path, max_age: u64) -> Result<String, String> {
    let file = cache.join(format!("{}.txt", d.id));
    let age = std::fs::metadata(&file)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.elapsed().ok())
        .map(|e| e.as_secs());
    if let Some(a) = age {
        if a < max_age {
            if let Ok(t) = std::fs::read_to_string(&file) {
                return Ok(t);
            }
        }
    }
    let mut err = String::from("нет адресов");
    for u in &d.urls {
        match get_capped(c, u, MAX_SIZE).await {
            Ok(t) if t.contains("://") || crate::util::looks_base64(&t) => {
                let _ = std::fs::create_dir_all(cache);
                let _ = crate::mihomo::write_atomic(&file, t.as_bytes());
                return Ok(t);
            }
            Ok(_) => err = "пустой список".into(),
            Err(e) => err = e,
        }
    }
    std::fs::read_to_string(&file).map_err(|_| err)
}
