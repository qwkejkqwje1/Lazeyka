//! Small helpers shared by parsers: lenient base64, percent decoding,
//! query strings, host:port splitting, time.

use base64::Engine;
use base64::alphabet;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};

const LENIENT: GeneralPurposeConfig = GeneralPurposeConfig::new()
    .with_decode_padding_mode(DecodePaddingMode::Indifferent)
    .with_decode_allow_trailing_bits(true);
const B64: GeneralPurpose = GeneralPurpose::new(&alphabet::STANDARD, LENIENT);
const B64URL: GeneralPurpose = GeneralPurpose::new(&alphabet::URL_SAFE, LENIENT);

/// Decodes standard or URL-safe base64, with or without padding/whitespace.
pub fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let t: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let t = t.trim_end_matches('=');
    if t.is_empty() {
        return None;
    }
    if t.contains('-') || t.contains('_') {
        B64URL.decode(t).ok()
    } else {
        B64.decode(t).ok()
    }
}

pub fn b64_decode_str(s: &str) -> Option<String> {
    String::from_utf8(b64_decode(s)?).ok()
}

pub fn b64_encode(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

/// Looks like base64 text (used to detect base64 subscriptions).
pub fn looks_base64(s: &str) -> bool {
    let t = s.trim();
    !t.is_empty()
        && t.len() >= 8
        && t.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_' | b'\r' | b'\n' | b' '))
}

pub fn pct(s: &str) -> String {
    percent_encoding::percent_decode_str(s).decode_utf8_lossy().into_owned()
}

/// Decodes repeatedly (some generators percent-encode values 2-3 times).
pub fn pct_deep(s: &str) -> String {
    let mut cur = s.to_string();
    for _ in 0..4 {
        let next = pct(&cur);
        if next == cur {
            break;
        }
        cur = next;
    }
    cur
}

/// Parsed query string with case-insensitive lookup. Values are percent-decoded once,
/// '+' is kept literally (share links use it inside base64 values).
#[derive(Debug, Default, Clone)]
pub struct Query(pub Vec<(String, String)>);

impl Query {
    pub fn parse(q: &str) -> Query {
        let mut v = Vec::new();
        for part in q.split('&') {
            if part.is_empty() {
                continue;
            }
            let (k, val) = match part.split_once('=') {
                Some((k, val)) => (k, val),
                None => (part, ""),
            };
            v.push((pct(k).trim().to_ascii_lowercase(), pct(val).trim().to_string()));
        }
        Query(v)
    }
    /// Non-empty value for a key (case-insensitive).
    pub fn get(&self, k: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, val)| key.eq_ignore_ascii_case(k) && !val.is_empty())
            .map(|(_, v)| v.as_str())
    }
    pub fn any(&self, keys: &[&str]) -> Option<&str> {
        keys.iter().find_map(|k| self.get(k))
    }
    pub fn flag(&self, keys: &[&str]) -> bool {
        keys.iter().any(|k| matches!(self.get(k).map(|v| v.to_ascii_lowercase()).as_deref(), Some("1" | "true" | "yes")))
    }
    /// Value decoded repeatedly, lowercased (for enum-like params: alpn, fp, type...).
    pub fn enum_val(&self, k: &str) -> Option<String> {
        self.get(k).map(|v| pct_deep(v).to_ascii_lowercase())
    }
}

/// Splits "host:port", "[v6]:port". Returns host without brackets.
pub fn split_host_port(s: &str) -> Option<(String, String)> {
    let s = s.trim();
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port = after.strip_prefix(':')?;
        return Some((host.to_string(), port.to_string()));
    }
    let idx = s.rfind(':')?;
    let (h, p) = (&s[..idx], &s[idx + 1..]);
    if h.contains(':') {
        // bare IPv6 without brackets: ambiguous, reject
        return None;
    }
    Some((h.to_string(), p.to_string()))
}

pub fn parse_port(p: &str) -> Option<u16> {
    let n: u32 = p.trim().parse().ok()?;
    if (1..=65535).contains(&n) { Some(n as u16) } else { None }
}

/// Converts an internationalized domain to ASCII (punycode); keeps IPs and ASCII as is.
pub fn ascii_host(h: &str) -> Option<String> {
    let h = h.trim().trim_end_matches('.');
    if h.is_ascii() {
        return Some(h.to_ascii_lowercase());
    }
    match url::Host::parse(h).ok()? {
        url::Host::Domain(d) => Some(d),
        _ => None,
    }
}

/// Valid server host: domain name or IP literal.
pub fn valid_host(h: &str) -> bool {
    if h.is_empty() || h.len() > 253 {
        return false;
    }
    if h.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    h.split('.').all(|l| {
        !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    })
}

pub fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn random_token(n: usize) -> String {
    use rand::Rng;
    const CH: &[u8] = b"abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut r = rand::rng();
    (0..n).map(|_| CH[r.random_range(0..CH.len())] as char).collect()
}

/// Truncates a display name to a sane length (chars, not bytes).
pub fn clip(s: &str, n: usize) -> String {
    let t = s.trim();
    if t.chars().count() <= n { t.to_string() } else { t.chars().take(n).collect::<String>() + "…" }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn b64_variants() {
        assert_eq!(b64_decode_str("aGVsbG8=").unwrap(), "hello");
        assert_eq!(b64_decode_str("aGVsbG8").unwrap(), "hello");
        assert_eq!(b64_decode_str("aGVs\nbG8=").unwrap(), "hello");
        assert_eq!(b64_decode(&"-_8").unwrap(), vec![0xfb, 0xff]);
    }
    #[test]
    fn hostport() {
        assert_eq!(split_host_port("[::1]:443"), Some(("::1".into(), "443".into())));
        assert_eq!(split_host_port("a.b:80"), Some(("a.b".into(), "80".into())));
        assert_eq!(split_host_port("::1"), None);
        assert_eq!(pct_deep("http%25252F1.1"), "http/1.1");
    }
}

/// Server name for display: strips emoji (flags are shown as country badges) and
/// decorative separators that subscription authors like to add.
pub fn display_name(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        let u = c as u32;
        let emoji = matches!(u,
            0x1F000..=0x1FAFF | 0x2600..=0x27BF | 0x2B00..=0x2BFF | 0xFE00..=0xFE0F | 0x200D | 0x20E3 | 0xE0000..=0xE007F | 0x2190..=0x21FF | 0x2300..=0x23FF | 0x25A0..=0x25FF);
        if emoji || c.is_control() {
            out.push(' ');
        } else {
            out.push(c);
        }
    }
    let t: Vec<&str> = out.split_whitespace().collect();
    let mut r = t.join(" ");
    // collapse separators left behind by removed emoji: "A | | B" -> "A | B"
    while r.contains("| |") {
        r = r.replace("| |", "|");
    }
    let r = r.trim_start_matches(|c: char| c.is_whitespace() || "|-—–_:·•,;/".contains(c));
    let r = r.trim_end_matches(|c: char| c.is_whitespace() || "|-—–_:·•,;/".contains(c));
    clip(r, 64)
}

#[cfg(test)]
mod name_tests {
    #[test]
    fn display_name() {
        assert_eq!(super::display_name("🇩🇪 Germany, Frankfurt am Main | [BL]"), "Germany, Frankfurt am Main | [BL]");
        assert_eq!(super::display_name("🇳🇱 The Netherlands | 🌐 | "), "The Netherlands");
        assert_eq!(super::display_name("Мой сервер"), "Мой сервер");
        assert_eq!(super::display_name("🚀"), "");
    }
}
