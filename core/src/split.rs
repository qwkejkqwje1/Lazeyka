//! Site and program entries of routes: normalization, rule-provider payloads, import.
//! `Split` is the 0.1–0.2 settings format (one exclude / include switch), kept to migrate
//! old settings into routes.

use crate::util::ascii_host;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "lowercase")]
pub enum SplitMode {
    /// «Всё через VPN, кроме исключений»
    #[default]
    Exclude,
    /// «Через VPN только выбранное»
    Include,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct SplitList {
    #[serde(default)]
    pub sites: Vec<String>,
    #[serde(default)]
    pub apps: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Split {
    #[serde(default)]
    pub mode: SplitMode,
    #[serde(default)]
    pub exclude: SplitList,
    #[serde(default)]
    pub include: SplitList,
}

impl Split {
    pub fn active(&self) -> &SplitList {
        match self.mode {
            SplitMode::Exclude => &self.exclude,
            SplitMode::Include => &self.include,
        }
    }
    pub fn list_mut(&mut self, mode: SplitMode) -> &mut SplitList {
        match mode {
            SplitMode::Exclude => &mut self.exclude,
            SplitMode::Include => &mut self.include,
        }
    }
}

/// Normalizes user input to a site entry: "example.com" (covers subdomains),
/// "1.2.3.4/32", "10.0.0.0/8", "2001:db8::/32".
pub fn normalize_site(input: &str) -> Result<String, String> {
    let mut s = input.trim().trim_matches(|c| c == '"' || c == '\'').trim();
    if s.is_empty() {
        return Err("пустая строка".into());
    }
    if let Some((_, rest)) = s.split_once("://") {
        s = rest;
    }
    // CIDR first (contains '/', must not be cut as a path)
    if let Some((ip, pfx)) = s.split_once('/') {
        if let (Ok(ip), Ok(pfx)) = (ip.trim().parse::<IpAddr>(), pfx.trim().parse::<u8>()) {
            return cidr(ip, pfx);
        }
    }
    let s = s.split(['/', '?', '#']).next().unwrap_or("");
    let s = s.rsplit_once('@').map(|(_, h)| h).unwrap_or(s);
    // bracketed IPv6 with optional port
    if let Some(rest) = s.strip_prefix('[') {
        let v6 = rest.split(']').next().unwrap_or("");
        let ip: IpAddr = v6.parse().map_err(|_| "некорректный IPv6-адрес")?;
        return cidr(ip, 128);
    }
    if let Ok(ip) = s.parse::<IpAddr>() {
        let p = if ip.is_ipv4() { 32 } else { 128 };
        return cidr(ip, p);
    }
    let host = match s.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => s,
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        return cidr(ip, 32);
    }
    let host = host.trim_start_matches("*.").trim_start_matches('.').trim_end_matches('.');
    let host = host.strip_prefix("www.").unwrap_or(host);
    let d = ascii_host(host).ok_or("некорректный адрес сайта")?;
    if d.is_empty() || d.len() > 253 {
        return Err("некорректный адрес сайта".into());
    }
    let labels: Vec<&str> = d.split('.').collect();
    for l in &labels {
        if l.is_empty() || l.len() > 63 || !l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') || l.starts_with('-') {
            return Err("некорректный адрес сайта".into());
        }
    }
    if labels.len() == 1 && !labels[0].bytes().all(|b| b.is_ascii_alphabetic() || b == b'-') && !labels[0].starts_with("xn--") {
        return Err("некорректный адрес сайта".into());
    }
    Ok(d)
}

fn cidr(ip: IpAddr, pfx: u8) -> Result<String, String> {
    match ip {
        IpAddr::V4(v4) => {
            if pfx > 32 {
                return Err("некорректная маска".into());
            }
            let n = u32::from(v4);
            let mask = if pfx == 0 { 0 } else { u32::MAX << (32 - pfx) };
            Ok(format!("{}/{pfx}", std::net::Ipv4Addr::from(n & mask)))
        }
        IpAddr::V6(v6) => {
            if pfx > 128 {
                return Err("некорректная маска".into());
            }
            let n = u128::from(v6);
            let mask = if pfx == 0 { 0 } else { u128::MAX << (128 - pfx) };
            Ok(format!("{}/{pfx}", std::net::Ipv6Addr::from(n & mask)))
        }
    }
}

/// Program entry: executable file name ("chrome.exe") from a name or full path.
pub fn normalize_app(input: &str) -> Result<String, String> {
    let s = input.trim().trim_matches('"').trim();
    let name = s.rsplit(['\\', '/']).next().unwrap_or("").trim();
    if name.is_empty() || name.len() > 255 {
        return Err("пустое имя программы".into());
    }
    if name.chars().any(|c| matches!(c, ',' | '\n' | '\r' | '"' | '<' | '>' | '|' | '*' | '?' | ':')) {
        return Err("недопустимые символы в имени программы".into());
    }
    if cfg!(windows) && !name.to_ascii_lowercase().ends_with(".exe") {
        return Ok(format!("{name}.exe"));
    }
    Ok(name.to_string())
}

pub fn is_ip_entry(s: &str) -> bool {
    s.contains('/') && s.split('/').next().is_some_and(|ip| ip.parse::<IpAddr>().is_ok())
}

/// Classical rule-provider payloads: (domains, ips, apps). Never empty (placeholder
/// rules match nothing) so providers can always be hot-reloaded.
pub fn provider_texts(sites: &[String], apps: &[String]) -> (String, String, String) {
    let mut d = String::new();
    let mut i = String::new();
    for s in sites {
        if is_ip_entry(s) {
            let kind = if s.contains(':') { "IP-CIDR6" } else { "IP-CIDR" };
            i.push_str(&format!("{kind},{s}\n"));
        } else {
            d.push_str(&format!("DOMAIN-SUFFIX,{s}\n"));
        }
    }
    let mut a = String::new();
    for p in apps {
        a.push_str(&format!("PROCESS-NAME,{p}\n"));
    }
    if d.is_empty() {
        d.push_str("DOMAIN,lazeyka-placeholder.invalid\n");
    }
    if i.is_empty() {
        i.push_str("IP-CIDR,255.255.255.254/32\n");
    }
    if a.is_empty() {
        a.push_str("PROCESS-NAME,lazeyka-placeholder.none\n");
    }
    (d, i, a)
}

/// Adds entries from text (one per line); returns (added, rejected).
pub fn import_lines(target: &mut Vec<String>, text: &str, apps: bool) -> (usize, usize) {
    let (mut added, mut bad) = (0, 0);
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let r = if apps { normalize_app(l) } else { normalize_site(l) };
        match r {
            Ok(v) => {
                if !target.contains(&v) {
                    target.push(v);
                    added += 1;
                }
            }
            Err(_) => bad += 1,
        }
    }
    (added, bad)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sites() {
        assert_eq!(normalize_site("https://www.YouTube.com/watch?v=1").unwrap(), "youtube.com");
        assert_eq!(normalize_site("*.example.org").unwrap(), "example.org");
        assert_eq!(normalize_site("example.org:8443").unwrap(), "example.org");
        assert_eq!(normalize_site("1.2.3.4").unwrap(), "1.2.3.4/32");
        assert_eq!(normalize_site("10.1.2.3/8").unwrap(), "10.0.0.0/8");
        assert_eq!(normalize_site("2001:db8::1/32").unwrap(), "2001:db8::/32");
        assert_eq!(normalize_site("[2001:db8::1]:443").unwrap(), "2001:db8::1/128");
        assert_eq!(normalize_site("президент.рф").unwrap(), "xn--d1abbgf6aiiy.xn--p1ai");
        assert_eq!(normalize_site("ru").unwrap(), "ru");
        assert_eq!(normalize_site("рф").unwrap(), "xn--p1ai");
        assert!(normalize_site("bad host").is_err());
        assert!(normalize_site("a,b.com").is_err());
    }
    #[test]
    fn apps() {
        assert_eq!(normalize_app(r#""C:\Program Files\Google\Chrome\Application\chrome.exe""#).unwrap(), "chrome.exe");
        assert!(normalize_app("a,b.exe").is_err());
    }
    #[test]
    fn providers() {
        let sites = vec!["a.com".into(), "1.2.3.0/24".into(), "2001:db8::/32".into()];
        let (d, i, a) = provider_texts(&sites, &[]);
        assert_eq!(d, "DOMAIN-SUFFIX,a.com\n");
        assert_eq!(i, "IP-CIDR,1.2.3.0/24\nIP-CIDR6,2001:db8::/32\n");
        assert!(a.contains("placeholder"));
    }
}
