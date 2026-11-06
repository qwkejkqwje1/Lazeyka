//! Real end-to-end checks through a node's SOCKS listener: exit IP (TLS-validated),
//! latency, HTTP tampering, popular services, UDP (SOCKS5 UDP ASSOCIATE + STUN), speed.

use crate::model::*;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

static TLS: OnceLock<rustls::ClientConfig> = OnceLock::new();

/// Shared rustls config: ring provider + Mozilla roots (no OS store: a MITM-ing node can't pass).
pub fn tls_config() -> rustls::ClientConfig {
    TLS.get_or_init(|| {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let mut c = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("tls versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
        c.alpn_protocols = vec![b"http/1.1".to_vec()];
        c
    })
    .clone()
}

pub const UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36";

/// HTTP client going through a SOCKS5 listener (remote DNS), or direct when `socks` is None.
pub fn client(socks: Option<(u16, &str, &str)>, timeout: Duration) -> Result<reqwest::Client, String> {
    let mut b = reqwest::Client::builder()
        .tls_backend_preconfigured(tls_config())
        .user_agent(UA)
        .connect_timeout(Duration::from_secs(6))
        .timeout(timeout)
        .pool_max_idle_per_host(1)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy();
    if let Some((port, u, p)) = socks {
        let proxy = reqwest::Proxy::all(format!("socks5h://{u}:{p}@127.0.0.1:{port}")).map_err(|e| e.to_string())?;
        b = b.proxy(proxy);
    }
    b.build().map_err(|e| e.to_string())
}

#[derive(Debug, Clone, Default)]
pub struct Trace {
    pub ip: Option<IpAddr>,
    pub loc: Option<String>,
    pub warp: bool,
}

pub fn parse_trace(body: &str) -> Trace {
    let mut t = Trace::default();
    for l in body.lines() {
        if let Some(v) = l.strip_prefix("ip=") {
            t.ip = v.trim().parse().ok();
        } else if let Some(v) = l.strip_prefix("loc=") {
            let v = v.trim().to_ascii_uppercase();
            if v.len() == 2 && v != "XX" {
                t.loc = Some(v);
            }
        } else if let Some(v) = l.strip_prefix("warp=") {
            t.warp = v.trim() == "on" || v.trim() == "plus";
        }
    }
    t
}

/// Exit IP via Cloudflare trace (fallback: Amazon checkip). Returns (trace, rtt_ms of 2nd request).
pub async fn exit_ip(c: &reqwest::Client) -> Result<(Trace, Option<u32>), String> {
    let urls = ["https://www.cloudflare.com/cdn-cgi/trace", "https://1.1.1.1/cdn-cgi/trace"];
    let mut last_err = String::new();
    for u in urls {
        match c.get(u).send().await {
            Ok(r) if r.status().is_success() => {
                let body = r.text().await.unwrap_or_default();
                let t = parse_trace(&body);
                if t.ip.is_none() {
                    last_err = "нет IP в ответе".into();
                    continue;
                }
                // second request on the warm connection = clean round trip through the tunnel
                let t0 = Instant::now();
                let rtt = match c.get(u).send().await {
                    Ok(r) if r.status().is_success() => {
                        let _ = r.bytes().await;
                        Some(t0.elapsed().as_millis().max(1) as u32)
                    }
                    _ => None,
                };
                return Ok((t, rtt));
            }
            Ok(r) => last_err = format!("HTTP {}", r.status().as_u16()),
            Err(e) => last_err = short_err(&e),
        }
    }
    // fallback
    match c.get("https://checkip.amazonaws.com/").send().await {
        Ok(r) if r.status().is_success() => {
            let body = r.text().await.unwrap_or_default();
            let ip: Option<IpAddr> = body.trim().parse().ok();
            if ip.is_some() {
                return Ok((Trace { ip, loc: None, warp: false }, None));
            }
            Err("нет IP в ответе".into())
        }
        Ok(r) => Err(format!("HTTP {}", r.status().as_u16())),
        Err(e) => Err(if last_err.is_empty() { short_err(&e) } else { last_err }),
    }
}

pub fn short_err(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        return "таймаут".into();
    }
    if e.is_connect() {
        return "нет соединения".into();
    }
    let mut s = e.to_string();
    let mut src = std::error::Error::source(e);
    while let Some(x) = src {
        s = x.to_string();
        src = x.source();
    }
    let s = s.to_lowercase();
    if s.contains("certificate") || s.contains("invalidcert") || s.contains("unknownissuer") {
        "подмена TLS-сертификата".into()
    } else if s.contains("reset") {
        "соединение сброшено".into()
    } else if s.contains("eof") || s.contains("closed") {
        "соединение закрыто".into()
    } else {
        crate::util::clip(&s, 60)
    }
}

/// true = clean, false = content injected/modified, None = couldn't check.
pub async fn tamper_check(c: &reqwest::Client) -> Option<bool> {
    let checks = [
        ("http://www.msftconnecttest.com/connecttest.txt", "Microsoft Connect Test"),
        ("http://detectportal.firefox.com/success.txt", "success\n"),
    ];
    let mut any = false;
    for (url, want) in checks {
        if let Ok(r) = c.get(url).send().await {
            let st = r.status().as_u16();
            let body = r.text().await.unwrap_or_default();
            if st != 200 || body != want {
                return Some(false);
            }
            any = true;
        }
    }
    if any { Some(true) } else { None }
}

pub async fn services(c: &reqwest::Client) -> u8 {
    let yt = async {
        matches!(c.get("https://www.youtube.com/generate_204").send().await, Ok(r) if r.status().as_u16() == 204)
    };
    let dc = async {
        match c.get("https://discord.com/api/v9/gateway").send().await {
            Ok(r) if r.status().is_success() => r.text().await.unwrap_or_default().contains("wss://"),
            _ => false,
        }
    };
    let tg = async {
        matches!(c.get("https://api.telegram.org/").send().await, Ok(r) if r.status().as_u16() < 500)
    };
    let (a, b, d) = tokio::join!(yt, dc, tg);
    (if a { SVC_YOUTUBE } else { 0 }) | (if b { SVC_DISCORD } else { 0 }) | (if d { SVC_TELEGRAM } else { 0 })
}

/// Bytes downloaded per speed test (at most; the time limit usually ends it first).
pub const SPEED_BYTES: u64 = 6_000_000;

/// Download test files, tried in order: free servers often block one of them
/// (speed-test domains are a popular block on public VPN servers).
const SPEED_URLS: &[&str] = &[
    "https://speed.cloudflare.com/__down?bytes={n}",
    "https://cachefly.cachefly.net/10mb.test",
    "https://fsn1-speed.hetzner.com/100MB.bin",
    "https://proof.ovh.net/files/10Mb.dat",
];

/// Download speed (kbit/s), capped by bytes and time; tries several test files.
pub async fn speed(c: &reqwest::Client, max_bytes: u64, max_time: Duration) -> Option<u32> {
    for u in SPEED_URLS {
        let url = u.replace("{n}", &max_bytes.to_string());
        if let Some(v) = speed_from(c, &url, max_bytes, max_time).await {
            return Some(v);
        }
    }
    None
}

/// One measurement. The first 256 KB (TCP slow start, TLS) are not counted.
async fn speed_from(c: &reqwest::Client, url: &str, max_bytes: u64, max_time: Duration) -> Option<u32> {
    const WARMUP: u64 = 256 * 1024;
    let rq = c.get(url).header("range", format!("bytes=0-{}", max_bytes.saturating_sub(1))).timeout(max_time + Duration::from_secs(8));
    let mut r = tokio::time::timeout(Duration::from_secs(7), rq.send()).await.ok()?.ok()?;
    if !r.status().is_success() {
        return None;
    }
    let t0 = Instant::now();
    let mut got: u64 = 0;
    let mut warm: Option<(Instant, u64)> = None;
    loop {
        let Some(left) = max_time.checked_sub(t0.elapsed()) else { break };
        match tokio::time::timeout(left, r.chunk()).await {
            Ok(Ok(Some(ch))) => {
                got += ch.len() as u64;
                if warm.is_none() && got >= WARMUP {
                    warm = Some((Instant::now(), got));
                }
                if got >= max_bytes {
                    break;
                }
            }
            _ => break,
        }
    }
    if got < 64 * 1024 {
        return None;
    }
    let (bytes, secs) = match warm {
        Some((t, b)) if got - b >= WARMUP => (got - b, t.elapsed().as_secs_f64()),
        _ => (got, t0.elapsed().as_secs_f64()),
    };
    Some(((bytes as f64 * 8.0 / 1000.0) / secs.max(0.05)) as u32)
}

/// Bytes a server must deliver in one go. Where the provider cuts connections to foreign
/// hosting after ~16 KB, a server answers the small test requests and then hangs on
/// anything real; a download of this size tells the two apart.
pub const VOLUME_BYTES: u64 = 160 * 1024;

/// Error text of a server that stalls after the first kilobytes.
pub const CUT_ERR: &str = "обрыв после ~16 КБ";

const VOLUME_URLS: &[&str] = &[
    "https://speed.cloudflare.com/__down?bytes={n}",
    "https://cachefly.cachefly.net/1mb.test",
    "https://proof.ovh.net/files/10Mb.dat",
];

/// Result of one download: done, stalled after `n` bytes, or could not start.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Dl {
    Full,
    Cut(u64),
    Fail,
}

/// Downloads up to `want` bytes; a pause of 5 seconds without data ends it.
pub async fn download(c: &reqwest::Client, url: &str, want: u64) -> Dl {
    let rq = c.get(url).header("range", format!("bytes=0-{}", want.saturating_sub(1))).timeout(Duration::from_secs(20));
    let mut r = match tokio::time::timeout(Duration::from_secs(8), rq.send()).await {
        Ok(Ok(r)) if r.status().is_success() => r,
        _ => return Dl::Fail,
    };
    let t0 = Instant::now();
    let mut got: u64 = 0;
    while got < want && t0.elapsed() < Duration::from_secs(14) {
        match tokio::time::timeout(Duration::from_secs(5), r.chunk()).await {
            Ok(Ok(Some(ch))) => got += ch.len() as u64,
            Ok(Ok(None)) => break,
            _ => return if got >= want * 3 / 4 { Dl::Full } else { Dl::Cut(got) },
        }
    }
    if got >= want * 3 / 4 { Dl::Full } else { Dl::Cut(got) }
}

/// The "16 KB" test through a node: `Some(n)` = the download stalled after n bytes,
/// None = fine (or nothing to judge by: every test file unreachable).
pub async fn volume_cut(c: &reqwest::Client) -> Option<u64> {
    for u in VOLUME_URLS {
        let url = u.replace("{n}", &VOLUME_BYTES.to_string());
        match download(c, &url, VOLUME_BYTES).await {
            Dl::Full => return None,
            Dl::Cut(n) => return Some(n),
            Dl::Fail => continue,
        }
    }
    None
}

// ---------------- SOCKS5 UDP + STUN ----------------

async fn socks5_handshake(s: &mut TcpStream, user: &str, pass: &str) -> std::io::Result<()> {
    s.write_all(&[5, 1, 2]).await?;
    let mut b = [0u8; 2];
    s.read_exact(&mut b).await?;
    if b != [5, 2] {
        return Err(std::io::Error::other("socks: auth method rejected"));
    }
    let mut a = vec![1, user.len() as u8];
    a.extend_from_slice(user.as_bytes());
    a.push(pass.len() as u8);
    a.extend_from_slice(pass.as_bytes());
    s.write_all(&a).await?;
    s.read_exact(&mut b).await?;
    if b[1] != 0 {
        return Err(std::io::Error::other("socks: auth failed"));
    }
    Ok(())
}

async fn read_socks_addr(s: &mut TcpStream) -> std::io::Result<SocketAddr> {
    let mut h = [0u8; 4];
    s.read_exact(&mut h).await?;
    if h[1] != 0 {
        return Err(std::io::Error::other(format!("socks: reply {}", h[1])));
    }
    let ip: IpAddr = match h[3] {
        1 => {
            let mut a = [0u8; 4];
            s.read_exact(&mut a).await?;
            IpAddr::from(a)
        }
        4 => {
            let mut a = [0u8; 16];
            s.read_exact(&mut a).await?;
            IpAddr::from(a)
        }
        3 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            let mut d = vec![0u8; l[0] as usize];
            s.read_exact(&mut d).await?;
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        }
        _ => return Err(std::io::Error::other("socks: bad atyp")),
    };
    let mut p = [0u8; 2];
    s.read_exact(&mut p).await?;
    Ok(SocketAddr::new(ip, u16::from_be_bytes(p)))
}

/// One UDP request/response through a SOCKS5 listener (UDP ASSOCIATE): sends `payload`
/// to `host:port` (resolved by the listener) up to three times and returns the first
/// reply that `accept` takes (the SOCKS header already stripped).
pub async fn udp_exchange(
    port: u16,
    user: &str,
    pass: &str,
    host: &str,
    dport: u16,
    payload: &[u8],
    timeout: Duration,
    accept: impl Fn(&[u8]) -> bool,
) -> Result<Vec<u8>, String> {
    let fut = async {
        let mut ctl = TcpStream::connect(("127.0.0.1", port)).await.map_err(|e| e.to_string())?;
        socks5_handshake(&mut ctl, user, pass).await.map_err(|e| e.to_string())?;
        ctl.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await.map_err(|e| e.to_string())?;
        let mut relay = read_socks_addr(&mut ctl).await.map_err(|e| e.to_string())?;
        if relay.ip().is_unspecified() {
            relay.set_ip(IpAddr::V4(Ipv4Addr::LOCALHOST));
        }
        let sock = UdpSocket::bind("127.0.0.1:0").await.map_err(|e| e.to_string())?;
        let mut pkt = match host.parse::<IpAddr>() {
            Ok(IpAddr::V4(a)) => {
                let mut v = vec![0, 0, 0, 1];
                v.extend_from_slice(&a.octets());
                v
            }
            Ok(IpAddr::V6(a)) => {
                let mut v = vec![0, 0, 0, 4];
                v.extend_from_slice(&a.octets());
                v
            }
            Err(_) => {
                let h = host.as_bytes();
                let mut v = vec![0, 0, 0, 3, h.len().min(255) as u8];
                v.extend_from_slice(&h[..h.len().min(255)]);
                v
            }
        };
        pkt.extend_from_slice(&dport.to_be_bytes());
        pkt.extend_from_slice(payload);
        let mut buf = vec![0u8; 2048];
        for attempt in 0..3 {
            sock.send_to(&pkt, relay).await.map_err(|e| e.to_string())?;
            let wait = Duration::from_millis(1200 + attempt * 600);
            match tokio::time::timeout(wait, sock.recv_from(&mut buf)).await {
                Ok(Ok((n, _))) => {
                    if let Some(body) = strip_socks_udp(&buf[..n]) {
                        if accept(body) {
                            let out = body.to_vec();
                            drop(ctl);
                            return Ok(out);
                        }
                    }
                }
                Ok(Err(e)) => return Err(e.to_string()),
                Err(_) => continue,
            }
        }
        Err("UDP не проходит".to_string())
    };
    match tokio::time::timeout(timeout, fut).await {
        Ok(r) => r,
        Err(_) => Err("UDP: таймаут".into()),
    }
}

/// The datagram inside a SOCKS5 UDP reply.
fn strip_socks_udp(p: &[u8]) -> Option<&[u8]> {
    if p.len() < 4 || p[2] != 0 {
        return None;
    }
    let off = match p[3] {
        1 => 4 + 4 + 2,
        4 => 4 + 16 + 2,
        3 => 4 + 1 + *p.get(4)? as usize + 2,
        _ => return None,
    };
    p.get(off..)
}

/// A STUN binding request with a fresh transaction id.
pub fn stun_request() -> (Vec<u8>, [u8; 12]) {
    let mut tid = [0u8; 12];
    use rand::RngCore;
    rand::rng().fill_bytes(&mut tid);
    let mut pkt = vec![0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xA4, 0x42];
    pkt.extend_from_slice(&tid);
    (pkt, tid)
}

/// STUN binding through the node's UDP relay. Returns the public mapped address.
pub async fn udp_stun(port: u16, user: &str, pass: &str, timeout: Duration) -> Result<SocketAddr, String> {
    stun_via(port, user, pass, "stun.cloudflare.com", 3478, timeout).await
}

/// STUN binding to `host:dport` through a SOCKS5 listener.
pub async fn stun_via(port: u16, user: &str, pass: &str, host: &str, dport: u16, timeout: Duration) -> Result<SocketAddr, String> {
    let (pkt, tid) = stun_request();
    let body = udp_exchange(port, user, pass, host, dport, &pkt, timeout, |b| parse_stun(b, &tid).is_some()).await?;
    parse_stun(&body, &tid).ok_or_else(|| "UDP: непонятный ответ".to_string())
}

pub fn parse_stun(m: &[u8], tid: &[u8; 12]) -> Option<SocketAddr> {
    if m.len() < 20 || m[0] != 0x01 || m[1] != 0x01 || m[4..8] != [0x21, 0x12, 0xA4, 0x42] || &m[8..20] != tid {
        return None;
    }
    let len = u16::from_be_bytes([m[2], m[3]]) as usize;
    let attrs = m.get(20..20 + len)?;
    let mut i = 0;
    let mut mapped = None;
    while i + 4 <= attrs.len() {
        let ty = u16::from_be_bytes([attrs[i], attrs[i + 1]]);
        let l = u16::from_be_bytes([attrs[i + 2], attrs[i + 3]]) as usize;
        let v = attrs.get(i + 4..i + 4 + l)?;
        if (ty == 0x0020 || ty == 0x0001) && v.len() >= 8 {
            let xor = ty == 0x0020;
            let mut port = u16::from_be_bytes([v[2], v[3]]);
            if xor {
                port ^= 0x2112;
            }
            let addr = match v[1] {
                1 => {
                    let mut a = [v[4], v[5], v[6], v[7]];
                    if xor {
                        for (k, b) in a.iter_mut().enumerate() {
                            *b ^= [0x21, 0x12, 0xA4, 0x42][k];
                        }
                    }
                    IpAddr::from(a)
                }
                2 if v.len() >= 20 => {
                    let mut a = [0u8; 16];
                    a.copy_from_slice(&v[4..20]);
                    if xor {
                        let key: Vec<u8> = [0x21, 0x12, 0xA4, 0x42].iter().chain(tid.iter()).copied().collect();
                        for (k, b) in a.iter_mut().enumerate() {
                            *b ^= key[k];
                        }
                    }
                    IpAddr::from(a)
                }
                _ => return None,
            };
            let sa = SocketAddr::new(addr, port);
            if xor {
                return Some(sa);
            }
            mapped = Some(sa);
        }
        i += 4 + l.div_ceil(4) * 4;
    }
    mapped
}

#[derive(Clone)]
pub struct NodeCheck {
    pub port: u16,
    pub user: String,
    pub pass: String,
    pub udp: bool,
    pub services: bool,
    /// Download test against the "16 KB" cut (see [`VOLUME_BYTES`]).
    pub volume: bool,
}

/// Full check of one node. Geo/exclusion decisions are made by the caller.
pub async fn check_node(nc: &NodeCheck) -> (Probe, Option<Trace>) {
    let mut p = Probe { at: crate::util::now(), ..Default::default() };
    let c = match client(Some((nc.port, &nc.user, &nc.pass)), Duration::from_secs(8)) {
        Ok(c) => c,
        Err(e) => {
            p.error = Some(e);
            return (p, None);
        }
    };
    let (trace, rtt) = match exit_ip(&c).await {
        Ok(x) => x,
        Err(e) => {
            p.error = Some(e);
            return (p, None);
        }
    };
    p.exit_ip = trace.ip.map(|i| i.to_string());
    p.latency = rtt;
    let tamper = async { tamper_check(&c).await };
    let svc = async {
        if nc.services { services(&c).await } else { 0 }
    };
    let udp = async {
        if nc.udp {
            Some(udp_stun(nc.port, &nc.user, &nc.pass, Duration::from_secs(5)).await.is_ok())
        } else {
            None
        }
    };
    let volume = async {
        if nc.volume { volume_cut(&c).await } else { None }
    };
    let (t, s, u, v) = tokio::join!(tamper, svc, udp, volume);
    p.services = s | if u == Some(true) { SVC_UDP } else { 0 };
    p.udp = u;
    if t == Some(false) {
        p.error = Some("подмена содержимого".into());
        return (p, Some(trace));
    }
    if v.is_some() {
        p.error = Some(CUT_ERR.into());
        return (p, Some(trace));
    }
    p.ok = true;
    (p, Some(trace))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn trace_parse() {
        let t = parse_trace("fl=1\nh=www.cloudflare.com\nip=203.0.113.5\nts=1\nloc=NL\nwarp=off\n");
        assert_eq!(t.ip, Some("203.0.113.5".parse().unwrap()));
        assert_eq!(t.loc.as_deref(), Some("NL"));
        assert!(!t.warp);
    }
    #[test]
    fn stun_parse() {
        let tid = [9u8; 12];
        // XOR-MAPPED-ADDRESS for 1.2.3.4:5000
        let port = 5000u16 ^ 0x2112;
        let ip = [1 ^ 0x21, 2 ^ 0x12, 3 ^ 0xA4, 4 ^ 0x42];
        let mut m = vec![0x01, 0x01, 0x00, 0x0c, 0x21, 0x12, 0xA4, 0x42];
        m.extend_from_slice(&tid);
        m.extend_from_slice(&[0x00, 0x20, 0x00, 0x08, 0x00, 0x01]);
        m.extend_from_slice(&port.to_be_bytes());
        m.extend_from_slice(&ip);
        assert_eq!(parse_stun(&m, &tid), Some("1.2.3.4:5000".parse().unwrap()));
    }
}
