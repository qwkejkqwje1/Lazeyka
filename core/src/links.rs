//! Share-link parsers → mihomo proxy definitions.
//!
//! Supported: vless://, vmess:// (base64 JSON and URI form), trojan://, ss:// (SIP002 and
//! legacy, obfs/v2ray-plugin), hysteria2:// | hy2:// (port hopping, salamander),
//! tuic://, anytls://, wireguard:// | wg:// (incl. AmneziaWG params).

use crate::util::*;
use serde_json::{Map, Value, json};

#[derive(Debug, Clone)]
pub struct Parsed {
    pub name: String,
    pub proxy: Map<String, Value>,
}

type R = Result<Parsed, String>;

pub fn parse_link(line: &str) -> R {
    let line = line.trim().trim_matches(|c| c == '"' || c == '\'' || c == '`');
    let (scheme, rest) = line.split_once("://").ok_or("не похоже на ссылку")?;
    match scheme.to_ascii_lowercase().as_str() {
        "vless" => vless(rest),
        "vmess" => vmess(rest),
        "trojan" => trojan(rest),
        "ss" => ss(rest),
        "hysteria2" | "hy2" => hy2(rest),
        "tuic" => tuic(rest),
        "anytls" => anytls(rest),
        "wireguard" | "wg" => wireguard(rest),
        "ssr" => Err("ShadowsocksR не поддерживается".into()),
        "hysteria" => Err("Hysteria v1 не поддерживается".into()),
        other => Err(format!("схема {other}:// не поддерживается")),
    }
}

struct Url {
    user: String,
    host: String,
    port: String,
    query: Query,
    name: String,
}

fn split_url(rest: &str) -> Result<Url, String> {
    let (main, frag) = match rest.split_once('#') {
        Some((m, f)) => (m, pct(f)),
        None => (rest, String::new()),
    };
    let (main, query) = match main.split_once('?') {
        Some((m, q)) => (m, Query::parse(q)),
        None => (main, Query::default()),
    };
    let (user_raw, hostpart) = match main.rfind('@') {
        Some(i) => (&main[..i], &main[i + 1..]),
        None => ("", main),
    };
    let hp = match hostpart.find('/') {
        Some(i) => &hostpart[..i],
        None => hostpart,
    };
    let (host, port) = split_host_port(hp).ok_or("нет адреса host:port")?;
    let host = ascii_host(&host).unwrap_or_default();
    if !valid_host(&host) {
        return Err(format!("некорректный адрес {host}"));
    }
    Ok(Url { user: pct(user_raw), host, port: port.trim().to_string(), query, name: frag.trim().to_string() })
}

fn base(ty: &str, u: &Url) -> Result<Map<String, Value>, String> {
    let port = parse_port(&u.port).ok_or_else(|| format!("некорректный порт {}", u.port))?;
    let mut m = Map::new();
    m.insert("type".into(), ty.into());
    m.insert("server".into(), u.host.clone().into());
    m.insert("port".into(), port.into());
    m.insert("udp".into(), true.into());
    Ok(m)
}

const FINGERPRINTS: &[&str] = &["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized"];

fn fingerprint(q: &Query) -> Option<String> {
    let fp = q.enum_val("fp").or_else(|| q.enum_val("fingerprint"))?;
    if fp == "none" {
        return None;
    }
    if FINGERPRINTS.contains(&fp.as_str()) {
        Some(fp)
    } else if fp.starts_with("random") {
        Some("random".into())
    } else {
        Some("chrome".into())
    }
}

fn alpn(q: &Query) -> Option<Value> {
    let a = q.get("alpn").map(pct_deep)?;
    let v: Vec<Value> = a
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| matches!(s.as_str(), "h2" | "http/1.1" | "h3"))
        .map(Value::from)
        .collect();
    if v.is_empty() { None } else { Some(Value::Array(v)) }
}

fn first_host(h: &str) -> Option<String> {
    let f = h.split(',').next()?.trim();
    if f.is_empty() { None } else { Some(f.to_string()) }
}

fn is_domain(h: &str) -> bool {
    h.parse::<std::net::IpAddr>().is_err() && valid_host(h) && h.contains('.')
}

/// Applies `security` (tls / reality / none). `sni_key` is "servername" (vless/vmess) or "sni" (trojan).
fn apply_security(m: &mut Map<String, Value>, q: &Query, security: &str, net: &str, sni_key: &str, tls_flag: bool) -> Result<(), String> {
    let sni = q
        .any(&["sni", "peer", "servername"])
        .map(|s| s.to_string())
        .or_else(|| {
            if matches!(net, "ws" | "httpupgrade" | "h2" | "http" | "xhttp" | "splithttp") {
                q.get("host").and_then(first_host).filter(|h| is_domain(h))
            } else {
                None
            }
        });
    match security {
        "reality" => {
            let pbk = q.any(&["pbk", "publickey", "public-key"]).ok_or("Reality без public key")?;
            let raw = b64_decode(pbk).ok_or("Reality: некорректный public key")?;
            if raw.len() != 32 {
                return Err("Reality: некорректный public key".into());
            }
            if tls_flag {
                m.insert("tls".into(), true.into());
            }
            let mut ro = Map::new();
            ro.insert("public-key".into(), pbk.trim().into());
            if let Some(sid) = q.any(&["sid", "shortid", "short-id"]) {
                if !sid.bytes().all(|b| b.is_ascii_hexdigit()) || sid.len() > 16 {
                    return Err("Reality: некорректный short id".into());
                }
                ro.insert("short-id".into(), sid.into());
            }
            m.insert("reality-opts".into(), Value::Object(ro));
            m.insert("client-fingerprint".into(), fingerprint(q).unwrap_or_else(|| "chrome".into()).into());
            if let Some(s) = sni {
                m.insert(sni_key.into(), s.into());
            }
        }
        "tls" | "xtls" => {
            if tls_flag {
                m.insert("tls".into(), true.into());
            }
            if let Some(s) = sni {
                m.insert(sni_key.into(), s.into());
            }
            if let Some(fp) = fingerprint(q) {
                m.insert("client-fingerprint".into(), fp.into());
            }
            if let Some(a) = alpn(q) {
                m.insert("alpn".into(), a);
            }
            if q.flag(&["allowinsecure", "insecure", "skip-cert-verify"]) {
                m.insert("skip-cert-verify".into(), true.into());
            }
        }
        // some generators write "false", "0" or vmess-style "auto" for "no TLS"
        "" | "none" | "false" | "0" | "auto" => {}
        other => return Err(format!("security={other} не поддерживается")),
    }
    Ok(())
}

/// ws path may carry `?ed=2048` (early data) → mihomo ws-opts.
fn ws_path(path: &str) -> (String, Option<u64>) {
    if let Some((p, qs)) = path.split_once('?') {
        let mut ed = None;
        let mut keep = Vec::new();
        for kv in qs.split('&') {
            match kv.split_once('=') {
                Some(("ed", v)) => ed = v.parse::<u64>().ok(),
                _ if !kv.is_empty() => keep.push(kv),
                _ => {}
            }
        }
        let p = if keep.is_empty() { p.to_string() } else { format!("{p}?{}", keep.join("&")) };
        (p, ed)
    } else {
        (path.to_string(), None)
    }
}

fn apply_transport(m: &mut Map<String, Value>, q: &Query, net: &str, allowed: &[&str]) -> Result<(), String> {
    // an encoded '#' sometimes glues the server name onto the last parameter
    let net = net.split('#').next().unwrap_or("").trim();
    let net = match net {
        "" | "raw" | "none" => "tcp",
        "splithttp" => "xhttp",
        "kcp" => "mkcp",
        "http" => {
            // vmess/vless "http" transport is HTTP/2 in V2Ray terms
            "h2"
        }
        n => n,
    };
    if !allowed.contains(&net) {
        return Err(format!("транспорт {net} не поддерживается"));
    }
    let path = q.get("path").map(|s| s.to_string());
    let host = q.get("host").and_then(first_host);
    match net {
        "tcp" => {
            if q.enum_val("headertype").as_deref() == Some("http") {
                m.insert("network".into(), "http".into());
                let mut ho = Map::new();
                ho.insert("method".into(), "GET".into());
                let paths: Vec<Value> = path.unwrap_or_else(|| "/".into()).split(',').map(|s| Value::from(s.trim())).collect();
                ho.insert("path".into(), Value::Array(paths));
                if let Some(h) = q.get("host") {
                    let hosts: Vec<Value> = h.split(',').map(|s| Value::from(s.trim())).collect();
                    ho.insert("headers".into(), json!({ "Host": hosts }));
                }
                m.insert("http-opts".into(), Value::Object(ho));
            } else {
                m.insert("network".into(), "tcp".into());
            }
        }
        "ws" | "httpupgrade" => {
            m.insert("network".into(), "ws".into());
            let (p, ed) = ws_path(path.as_deref().unwrap_or("/"));
            let mut wo = Map::new();
            wo.insert("path".into(), if p.is_empty() { "/".into() } else { p.into() });
            if let Some(h) = host {
                wo.insert("headers".into(), json!({ "Host": h }));
            }
            if net == "httpupgrade" {
                wo.insert("v2ray-http-upgrade".into(), true.into());
                if ed.is_some() {
                    wo.insert("v2ray-http-upgrade-fast-open".into(), true.into());
                }
            } else if let Some(ed) = ed {
                wo.insert("max-early-data".into(), ed.into());
                wo.insert("early-data-header-name".into(), "Sec-WebSocket-Protocol".into());
            }
            m.insert("ws-opts".into(), Value::Object(wo));
        }
        "grpc" => {
            m.insert("network".into(), "grpc".into());
            let sn = q.any(&["servicename", "serviceName", "path"]).unwrap_or("");
            m.insert("grpc-opts".into(), json!({ "grpc-service-name": sn }));
        }
        "h2" => {
            m.insert("network".into(), "h2".into());
            let mut ho = Map::new();
            if let Some(h) = q.get("host") {
                let hosts: Vec<Value> = h.split(',').map(|s| Value::from(s.trim())).collect();
                ho.insert("host".into(), Value::Array(hosts));
            }
            ho.insert("path".into(), path.unwrap_or_else(|| "/".into()).into());
            m.insert("h2-opts".into(), Value::Object(ho));
        }
        "xhttp" => {
            m.insert("network".into(), "xhttp".into());
            let mut xo = Map::new();
            xo.insert("path".into(), path.unwrap_or_else(|| "/".into()).into());
            if let Some(h) = host {
                xo.insert("host".into(), h.into());
            }
            if let Some(mode) = q.enum_val("mode") {
                if matches!(mode.as_str(), "stream-one" | "stream-up" | "packet-up") {
                    xo.insert("mode".into(), mode.into());
                }
            }
            if let Some(extra) = q.get("extra") {
                if let Ok(Value::Object(e)) = serde_json::from_str::<Value>(&pct_deep(extra)) {
                    xhttp_extra(&e, &mut xo);
                }
            }
            m.insert("xhttp-opts".into(), Value::Object(xo));
        }
        "mkcp" => {
            m.insert("network".into(), "mkcp".into());
            let mut ko = Map::new();
            if let Some(h) = q.enum_val("headertype").filter(|h| h != "none") {
                ko.insert("header".into(), h.into());
            }
            if let Some(seed) = q.get("seed") {
                ko.insert("seed".into(), seed.into());
            }
            m.insert("mkcp-opts".into(), Value::Object(ko));
        }
        _ => return Err(format!("транспорт {net} не поддерживается")),
    }
    Ok(())
}

fn as_str_val(v: &Value) -> Option<Value> {
    match v {
        Value::String(s) if !s.is_empty() => Some(Value::String(s.clone())),
        Value::Number(n) => Some(Value::String(n.to_string())),
        Value::Object(o) => {
            // {"from": 100, "to": 1000}
            let f = o.get("from")?.as_u64()?;
            let t = o.get("to")?.as_u64()?;
            Some(Value::String(format!("{f}-{t}")))
        }
        _ => None,
    }
}

/// Xray `extra` JSON of XHTTP → mihomo xhttp-opts fields.
fn xhttp_extra(e: &Map<String, Value>, xo: &mut Map<String, Value>) {
    if let Some(Value::Object(h)) = e.get("headers") {
        let hm: Map<String, Value> = h.iter().filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), Value::from(s)))).collect();
        if !hm.is_empty() {
            xo.insert("headers".into(), Value::Object(hm));
        }
    }
    for (src, dst) in [
        ("xPaddingBytes", "x-padding-bytes"),
        ("scMaxEachPostBytes", "sc-max-each-post-bytes"),
        ("scMinPostsIntervalMs", "sc-min-posts-interval-ms"),
    ] {
        if let Some(v) = e.get(src).and_then(as_str_val) {
            xo.insert(dst.into(), v);
        }
    }
    if let Some(Value::Bool(b)) = e.get("noGRPCHeader") {
        xo.insert("no-grpc-header".into(), (*b).into());
    }
    if let Some(Value::Object(x)) = e.get("xmux") {
        let mut r = Map::new();
        for (src, dst) in [
            ("maxConcurrency", "max-concurrency"),
            ("maxConnections", "max-connections"),
            ("cMaxReuseTimes", "c-max-reuse-times"),
            ("hMaxRequestTimes", "h-max-request-times"),
            ("hMaxReusableSecs", "h-max-reusable-secs"),
            ("hKeepAlivePeriod", "h-keep-alive-period"),
        ] {
            if let Some(v) = x.get(src).and_then(as_str_val) {
                if dst == "h-keep-alive-period" {
                    if let Some(n) = v.as_str().and_then(|s| s.parse::<i64>().ok()) {
                        r.insert(dst.into(), n.into());
                    }
                } else {
                    r.insert(dst.into(), v);
                }
            }
        }
        if !r.is_empty() {
            xo.insert("reuse-settings".into(), Value::Object(r));
        }
    }
    if let Some(Value::Object(d)) = e.get("downloadSettings") {
        let mut ds = Map::new();
        if let Some(a) = d.get("address").and_then(|v| v.as_str()) {
            ds.insert("server".into(), a.into());
        }
        if let Some(p) = d.get("port").and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok()))) {
            ds.insert("port".into(), p.into());
        }
        let sec = d.get("security").and_then(|v| v.as_str()).unwrap_or("");
        if sec == "tls" || sec == "reality" {
            ds.insert("tls".into(), true.into());
        }
        if let Some(Value::Object(t)) = d.get("tlsSettings") {
            if let Some(s) = t.get("serverName").and_then(|v| v.as_str()) {
                ds.insert("servername".into(), s.into());
            }
            if let Some(s) = t.get("fingerprint").and_then(|v| v.as_str()) {
                ds.insert("client-fingerprint".into(), s.into());
            }
            if t.get("allowInsecure").and_then(|v| v.as_bool()) == Some(true) {
                ds.insert("skip-cert-verify".into(), true.into());
            }
        }
        if let Some(Value::Object(t)) = d.get("realitySettings") {
            if let Some(s) = t.get("serverName").and_then(|v| v.as_str()) {
                ds.insert("servername".into(), s.into());
            }
            ds.insert(
                "client-fingerprint".into(),
                t.get("fingerprint").and_then(|v| v.as_str()).unwrap_or("chrome").into(),
            );
            let mut ro = Map::new();
            if let Some(s) = t.get("publicKey").and_then(|v| v.as_str()) {
                ro.insert("public-key".into(), s.into());
            }
            if let Some(s) = t.get("shortId").and_then(|v| v.as_str()) {
                if !s.is_empty() {
                    ro.insert("short-id".into(), s.into());
                }
            }
            ds.insert("reality-opts".into(), Value::Object(ro));
        }
        if let Some(Value::Object(x)) = d.get("xhttpSettings") {
            if let Some(s) = x.get("path").and_then(|v| v.as_str()) {
                ds.insert("path".into(), s.into());
            }
            if let Some(s) = x.get("host").and_then(|v| v.as_str()) {
                ds.insert("host".into(), s.into());
            }
        }
        if ds.contains_key("server") {
            xo.insert("download-settings".into(), Value::Object(ds));
        }
    }
}

fn vless(rest: &str) -> R {
    let u = split_url(rest)?;
    let uuid = u.user.trim().to_string();
    if uuid.is_empty() || uuid.contains(':') {
        return Err("VLESS без UUID".into());
    }
    let mut m = base("vless", &u)?;
    m.insert("uuid".into(), uuid.into());
    let q = &u.query;
    let net = q.enum_val("type").unwrap_or_default();
    let security = q.enum_val("security").unwrap_or_default();
    apply_security(&mut m, q, &security, &net, "servername", true)?;
    apply_transport(&mut m, q, &net, &["tcp", "ws", "httpupgrade", "grpc", "h2", "xhttp", "mkcp"])?;
    if let Some(flow) = q.enum_val("flow") {
        if flow.starts_with("xtls-rprx-vision") {
            m.insert("flow".into(), "xtls-rprx-vision".into());
        } else if flow != "none" {
            return Err(format!("flow {flow} не поддерживается"));
        }
    }
    if let Some(enc) = q.get("encryption").map(pct_deep) {
        if enc != "none" {
            m.insert("encryption".into(), enc.into());
        }
    }
    if let Some(pe) = q.enum_val("packetencoding") {
        if pe == "xudp" || pe == "packetaddr" {
            m.insert("packet-encoding".into(), pe.into());
        }
    }
    Ok(Parsed { name: u.name, proxy: m })
}

fn trojan(rest: &str) -> R {
    let u = split_url(rest)?;
    if u.user.is_empty() {
        return Err("Trojan без пароля".into());
    }
    let mut m = base("trojan", &u)?;
    m.insert("password".into(), u.user.clone().into());
    let q = &u.query;
    let net = q.enum_val("type").unwrap_or_default();
    let security = q.enum_val("security").unwrap_or_else(|| "tls".into());
    let security = if security.is_empty() { "tls".to_string() } else { security };
    if security == "none" {
        return Err("Trojan без TLS не поддерживается".into());
    }
    apply_security(&mut m, q, &security, &net, "sni", false)?;
    apply_transport(&mut m, q, &net, &["tcp", "ws", "httpupgrade", "grpc"])?;
    Ok(Parsed { name: u.name, proxy: m })
}

const VMESS_CIPHERS: &[&str] = &["auto", "aes-128-gcm", "chacha20-poly1305", "none", "zero"];

fn jstr(v: &Value, k: &str) -> Option<String> {
    match v.get(k)? {
        Value::String(s) => {
            let s = s.trim();
            if s.is_empty() { None } else { Some(s.to_string()) }
        }
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(if *b { "1".into() } else { "0".into() }),
        _ => None,
    }
}

fn vmess(rest: &str) -> R {
    let (body, frag) = match rest.split_once('#') {
        Some((b, f)) => (b, Some(pct(f))),
        None => (rest, None),
    };
    let decoded = b64_decode_str(body.trim()).and_then(|s| serde_json::from_str::<Value>(&s).ok());
    let Some(j) = decoded else {
        // URI form: vmess://uuid@host:port?type=ws&security=tls...
        let u = split_url(rest)?;
        let mut m = base("vmess", &u)?;
        if u.user.is_empty() {
            return Err("VMess без UUID".into());
        }
        m.insert("uuid".into(), u.user.clone().into());
        m.insert("alterId".into(), 0.into());
        let q = &u.query;
        let c = q.enum_val("encryption").filter(|c| VMESS_CIPHERS.contains(&c.as_str())).unwrap_or_else(|| "auto".into());
        m.insert("cipher".into(), c.into());
        let net = q.enum_val("type").unwrap_or_default();
        let security = q.enum_val("security").unwrap_or_default();
        apply_security(&mut m, q, &security, &net, "servername", true)?;
        apply_transport(&mut m, q, &net, &["tcp", "ws", "httpupgrade", "grpc", "h2", "mkcp"])?;
        return Ok(Parsed { name: u.name, proxy: m });
    };
    let host = jstr(&j, "add").ok_or("VMess без адреса")?;
    let port = jstr(&j, "port").ok_or("VMess без порта")?;
    let uuid = jstr(&j, "id").ok_or("VMess без UUID")?;
    if !valid_host(&host) {
        return Err(format!("некорректный адрес {host}"));
    }
    let port = parse_port(&port).ok_or("некорректный порт")?;
    let mut m = Map::new();
    m.insert("type".into(), "vmess".into());
    m.insert("server".into(), host.into());
    m.insert("port".into(), port.into());
    m.insert("udp".into(), true.into());
    m.insert("uuid".into(), uuid.into());
    let aid: u64 = jstr(&j, "aid").and_then(|s| s.parse().ok()).unwrap_or(0);
    m.insert("alterId".into(), aid.into());
    let c = jstr(&j, "scy").map(|s| s.to_ascii_lowercase()).filter(|c| VMESS_CIPHERS.contains(&c.as_str())).unwrap_or_else(|| "auto".into());
    m.insert("cipher".into(), c.into());
    let net = jstr(&j, "net").unwrap_or_default().to_ascii_lowercase();
    let mut qv: Vec<(String, String)> = Vec::new();
    let mut put = |k: &str, v: Option<String>| {
        if let Some(v) = v {
            qv.push((k.to_string(), v));
        }
    };
    put("path", jstr(&j, "path"));
    put("host", jstr(&j, "host"));
    put("sni", jstr(&j, "sni"));
    put("alpn", jstr(&j, "alpn"));
    put("fp", jstr(&j, "fp"));
    put("allowinsecure", jstr(&j, "allowInsecure").or_else(|| jstr(&j, "skip-cert-verify")).or_else(|| jstr(&j, "insecure")));
    let ty = jstr(&j, "type");
    match net.as_str() {
        "grpc" => put("servicename", jstr(&j, "path")),
        "kcp" | "mkcp" => {
            put("headertype", ty);
            put("seed", jstr(&j, "path"));
        }
        _ => put("headertype", ty),
    }
    if let Some(pbk) = jstr(&j, "pbk") {
        put("pbk", Some(pbk));
        put("sid", jstr(&j, "sid"));
    }
    let q = Query(qv);
    let security = jstr(&j, "tls").unwrap_or_default().to_ascii_lowercase();
    apply_security(&mut m, &q, &security, &net, "servername", true)?;
    apply_transport(&mut m, &q, &net, &["tcp", "ws", "httpupgrade", "grpc", "h2", "mkcp"])?;
    let name = frag.or_else(|| jstr(&j, "ps")).unwrap_or_default();
    Ok(Parsed { name, proxy: m })
}

pub const SS_CIPHERS: &[&str] = &[
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-ccm",
    "aes-256-ccm",
    "none",
];

fn ss_cipher(c: &str) -> Option<String> {
    let c = c.trim().to_ascii_lowercase();
    let c = match c.as_str() {
        "chacha20-poly1305" => "chacha20-ietf-poly1305".to_string(),
        "xchacha20-poly1305" => "xchacha20-ietf-poly1305".to_string(),
        "plain" => "none".to_string(),
        _ => c,
    };
    SS_CIPHERS.contains(&c.as_str()).then_some(c)
}

fn ss(rest: &str) -> R {
    let (main, name) = match rest.split_once('#') {
        Some((m, f)) => (m, pct(f).trim().to_string()),
        None => (rest, String::new()),
    };
    let (main, query) = match main.split_once('?') {
        Some((m, q)) => (m, Query::parse(q)),
        None => (main, Query::default()),
    };
    let main = main.trim().trim_end_matches('/');
    let (method, password, hostport) = if let Some(at) = main.rfind('@') {
        let ui = &main[..at];
        let hostport = main[at + 1..].to_string();
        let plain = pct(ui);
        match plain.split_once(':') {
            Some((a, b)) if ss_cipher(a).is_some() => (a.to_string(), b.to_string(), hostport),
            _ => {
                let dec = b64_decode_str(&plain).ok_or("SS: не удалось декодировать метод и пароль")?;
                let (a, b) = dec.split_once(':').ok_or("SS: нет пароля")?;
                (a.to_string(), b.to_string(), hostport)
            }
        }
    } else {
        let dec = b64_decode_str(main).ok_or("SS: не удалось декодировать ссылку")?;
        let at = dec.rfind('@').ok_or("SS: нет адреса")?;
        let (cred, hp) = (&dec[..at], &dec[at + 1..]);
        let (a, b) = cred.split_once(':').ok_or("SS: нет пароля")?;
        (a.to_string(), b.to_string(), hp.to_string())
    };
    let cipher = ss_cipher(&method).ok_or_else(|| format!("SS: шифр {method} не поддерживается"))?;
    let (host, port) = split_host_port(&hostport).ok_or("SS: нет host:port")?;
    if !valid_host(&host) {
        return Err(format!("некорректный адрес {host}"));
    }
    let port = parse_port(&port).ok_or("некорректный порт")?;
    let mut m = Map::new();
    m.insert("type".into(), "ss".into());
    m.insert("server".into(), host.into());
    m.insert("port".into(), port.into());
    m.insert("cipher".into(), cipher.into());
    m.insert("password".into(), password.into());
    m.insert("udp".into(), true.into());
    if let Some(plugin) = query.get("plugin") {
        let mut parts = plugin.split(';');
        let pname = parts.next().unwrap_or("").trim().to_ascii_lowercase();
        let mut opts: Vec<(String, String)> = Vec::new();
        for p in parts {
            let (k, v) = p.split_once('=').unwrap_or((p, ""));
            opts.push((k.trim().to_ascii_lowercase(), v.trim().to_string()));
        }
        let get = |k: &str| opts.iter().find(|(kk, _)| kk == k).map(|(_, v)| v.clone());
        let has = |k: &str| opts.iter().any(|(kk, _)| kk == k);
        match pname.as_str() {
            "obfs-local" | "simple-obfs" | "obfs" => {
                let mode = get("obfs").unwrap_or_else(|| "http".into());
                if mode != "http" && mode != "tls" {
                    return Err(format!("obfs={mode} не поддерживается"));
                }
                let mut po = Map::new();
                po.insert("mode".into(), mode.into());
                if let Some(h) = get("obfs-host") {
                    po.insert("host".into(), h.into());
                }
                m.insert("plugin".into(), "obfs".into());
                m.insert("plugin-opts".into(), Value::Object(po));
            }
            "v2ray-plugin" => {
                let mode = get("mode").unwrap_or_else(|| "websocket".into());
                if mode != "websocket" {
                    return Err(format!("v2ray-plugin mode={mode} не поддерживается"));
                }
                let mut po = Map::new();
                po.insert("mode".into(), "websocket".into());
                if has("tls") {
                    po.insert("tls".into(), true.into());
                }
                if let Some(h) = get("host") {
                    po.insert("host".into(), h.into());
                }
                if let Some(p) = get("path") {
                    po.insert("path".into(), p.into());
                }
                let mux = get("mux").map(|v| v != "0" && v != "false").unwrap_or(false);
                if mux {
                    po.insert("mux".into(), true.into());
                }
                m.insert("plugin".into(), "v2ray-plugin".into());
                m.insert("plugin-opts".into(), Value::Object(po));
            }
            "" | "none" => {}
            other => return Err(format!("плагин SS {other} не поддерживается")),
        }
    }
    Ok(Parsed { name, proxy: m })
}

fn hy2(rest: &str) -> R {
    let u = split_url(rest).or_else(|_| {
        // authority with port list "host:443,20000-30000" fails validation in split_url only on port; retry manually
        Err::<Url, String>("Hysteria2: нет адреса".into())
    })?;
    let q = &u.query;
    let mut ports: Option<String> = q.get("mport").map(|s| s.replace(' ', ""));
    let port = if let Some(p) = parse_port(&u.port) {
        p
    } else {
        let list = u.port.replace(' ', "");
        let first = list.split([',', '-']).next().unwrap_or("");
        let p = parse_port(first).ok_or_else(|| format!("некорректный порт {}", u.port))?;
        if !list.bytes().all(|b| b.is_ascii_digit() || b == b',' || b == b'-') {
            return Err("некорректный список портов".into());
        }
        ports = Some(list);
        p
    };
    let mut m = Map::new();
    m.insert("type".into(), "hysteria2".into());
    m.insert("server".into(), u.host.clone().into());
    m.insert("port".into(), port.into());
    if let Some(ps) = ports {
        m.insert("ports".into(), ps.into());
    }
    m.insert("password".into(), u.user.clone().into());
    m.insert("udp".into(), true.into());
    if let Some(s) = q.any(&["sni", "peer"]) {
        m.insert("sni".into(), s.into());
    }
    if q.flag(&["insecure", "allowinsecure", "skip-cert-verify"]) {
        m.insert("skip-cert-verify".into(), true.into());
    }
    if let Some(o) = q.enum_val("obfs").filter(|o| o != "none") {
        if o != "salamander" && o != "gecko" {
            return Err(format!("obfs {o} не поддерживается"));
        }
        m.insert("obfs".into(), o.into());
        if let Some(op) = q.any(&["obfs-password", "obfs_password", "obfspassword"]) {
            m.insert("obfs-password".into(), op.into());
        }
    }
    if let Some(a) = alpn(q) {
        m.insert("alpn".into(), a);
    }
    if let Some(pin) = q.any(&["pinsha256", "pin-sha256"]) {
        let hex: String = pin.chars().filter(|c| c.is_ascii_hexdigit()).collect();
        if hex.len() == 64 {
            m.insert("fingerprint".into(), hex.to_ascii_lowercase().into());
        }
    }
    Ok(Parsed { name: u.name, proxy: m })
}

fn tuic(rest: &str) -> R {
    let u = split_url(rest)?;
    let mut m = base("tuic", &u)?;
    let q = &u.query;
    match u.user.split_once(':') {
        Some((id, pw)) => {
            m.insert("uuid".into(), id.into());
            m.insert("password".into(), pw.into());
        }
        None if !u.user.is_empty() => {
            m.insert("token".into(), u.user.clone().into());
        }
        None => return Err("TUIC без учётных данных".into()),
    }
    if let Some(s) = q.get("sni") {
        m.insert("sni".into(), s.into());
    }
    let a = alpn(q).unwrap_or_else(|| json!(["h3"]));
    m.insert("alpn".into(), a);
    if let Some(cc) = q.enum_val("congestion_control").or_else(|| q.enum_val("congestion-controller")) {
        if matches!(cc.as_str(), "bbr" | "cubic" | "new_reno") {
            m.insert("congestion-controller".into(), cc.into());
        }
    }
    if let Some(mode) = q.enum_val("udp_relay_mode").or_else(|| q.enum_val("udp-relay-mode")) {
        if mode == "native" || mode == "quic" {
            m.insert("udp-relay-mode".into(), mode.into());
        }
    }
    if q.flag(&["allow_insecure", "insecure", "allowinsecure", "skip-cert-verify"]) {
        m.insert("skip-cert-verify".into(), true.into());
    }
    if q.flag(&["disable_sni", "disable-sni"]) {
        m.insert("disable-sni".into(), true.into());
    }
    if q.flag(&["reduce_rtt", "zero_rtt_handshake", "reduce-rtt"]) {
        m.insert("reduce-rtt".into(), true.into());
    }
    Ok(Parsed { name: u.name, proxy: m })
}

fn anytls(rest: &str) -> R {
    let u = split_url(rest)?;
    if u.user.is_empty() {
        return Err("AnyTLS без пароля".into());
    }
    let mut m = base("anytls", &u)?;
    m.insert("password".into(), u.user.clone().into());
    let q = &u.query;
    if let Some(s) = q.any(&["sni", "peer"]) {
        m.insert("sni".into(), s.into());
    }
    if let Some(fp) = fingerprint(q) {
        m.insert("client-fingerprint".into(), fp.into());
    }
    if let Some(a) = alpn(q) {
        m.insert("alpn".into(), a);
    }
    if q.flag(&["insecure", "allowinsecure", "skip-cert-verify"]) {
        m.insert("skip-cert-verify".into(), true.into());
    }
    Ok(Parsed { name: u.name, proxy: m })
}

/// Fields of a WireGuard/AmneziaWG peer, shared by links, .conf files, Amnezia and WARP.
#[derive(Debug, Default, Clone)]
pub struct WgFields {
    pub server: String,
    pub port: u16,
    pub private_key: String,
    pub public_key: String,
    pub psk: Option<String>,
    pub addrs: Vec<String>,
    pub mtu: Option<u64>,
    pub reserved: Option<Value>,
    pub keepalive: Option<u64>,
    /// AmneziaWG options in mihomo naming (jc, jmin, s1, h1, i1, …).
    pub awg: Map<String, Value>,
}

fn valid_wg_key(k: &str) -> bool {
    b64_decode(k).is_some_and(|b| b.len() == 32)
}

/// AmneziaWG parameter name (any case) → mihomo key and whether it's numeric.
pub fn awg_key(k: &str) -> Option<(&'static str, bool)> {
    let k = k.to_ascii_lowercase().replace(['_', '-'], "");
    Some(match k.as_str() {
        "jc" => ("jc", true),
        "jmin" => ("jmin", true),
        "jmax" => ("jmax", true),
        "s1" => ("s1", true),
        "s2" => ("s2", true),
        "s3" => ("s3", true),
        "s4" => ("s4", true),
        "h1" => ("h1", false),
        "h2" => ("h2", false),
        "h3" => ("h3", false),
        "h4" => ("h4", false),
        "i1" => ("i1", false),
        "i2" => ("i2", false),
        "i3" => ("i3", false),
        "i4" => ("i4", false),
        "i5" => ("i5", false),
        "j1" => ("j1", false),
        "j2" => ("j2", false),
        "j3" => ("j3", false),
        "itime" => ("itime", true),
        "version" => ("version", true),
        "headerprotectionkey" => ("header-protection-key", false),
        "contentpaddingaddition" => ("content-padding-addition", false),
        "rekeyaftertime" => ("rekey-after-time", true),
        "rekeytimeout" => ("rekey-timeout", true),
        "rejectaftertime" => ("reject-after-time", true),
        "keepalivetimeout" => ("keepalive-timeout", true),
        "maxhandshakeattempts" => ("max-handshake-attempts", true),
        "randomtrailers" => ("random-trailers", false),
        "disablecookies" => ("disable-cookies", false),
        _ => return None,
    })
}

/// Puts one AmneziaWG parameter into `awg`, normalizing types. Returns false if unknown.
pub fn awg_put(awg: &mut Map<String, Value>, k: &str, v: &str) -> bool {
    let Some((key, numeric)) = awg_key(k) else { return false };
    let v = v.trim();
    if v.is_empty() {
        return true;
    }
    let val: Value = if numeric {
        match v.parse::<u64>() {
            Ok(n) => n.into(),
            Err(_) => return true,
        }
    } else if key.starts_with('h') && key.len() == 2 {
        // single value → number; range "a-b" → string
        match v.parse::<u64>() {
            Ok(n) => n.into(),
            Err(_) => v.into(),
        }
    } else if key == "random-trailers" || key == "disable-cookies" {
        matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes").into()
    } else {
        v.into()
    };
    awg.insert(key.into(), val);
    true
}

pub fn wg_proxy(f: &WgFields) -> Result<Map<String, Value>, String> {
    if !valid_wg_key(&f.private_key) {
        return Err("WireGuard: некорректный приватный ключ".into());
    }
    if !valid_wg_key(&f.public_key) {
        return Err("WireGuard: некорректный публичный ключ сервера".into());
    }
    if !valid_host(&f.server) || f.port == 0 {
        return Err("WireGuard: нет адреса сервера".into());
    }
    let mut m = Map::new();
    m.insert("type".into(), "wireguard".into());
    m.insert("server".into(), f.server.clone().into());
    m.insert("port".into(), f.port.into());
    let mut v4 = None;
    let mut v6 = None;
    for a in &f.addrs {
        let ip = a.split('/').next().unwrap_or("").trim();
        match ip.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(x)) if v4.is_none() => v4 = Some(x.to_string()),
            Ok(std::net::IpAddr::V6(x)) if v6.is_none() => v6 = Some(x.to_string()),
            _ => {}
        }
    }
    let Some(v4) = v4.or_else(|| v6.is_some().then(String::new)) else {
        return Err("WireGuard: нет адреса интерфейса (Address)".into());
    };
    if !v4.is_empty() {
        m.insert("ip".into(), v4.into());
    }
    if let Some(v6) = v6 {
        m.insert("ipv6".into(), v6.into());
    }
    m.insert("private-key".into(), f.private_key.trim().into());
    m.insert("public-key".into(), f.public_key.trim().into());
    if let Some(psk) = f.psk.as_ref().filter(|p| valid_wg_key(p)) {
        m.insert("pre-shared-key".into(), psk.trim().into());
    }
    if let Some(r) = &f.reserved {
        m.insert("reserved".into(), r.clone());
    }
    if let Some(mtu) = f.mtu.filter(|m| (576..=9000).contains(m)) {
        m.insert("mtu".into(), mtu.into());
    }
    if let Some(k) = f.keepalive.filter(|k| *k > 0) {
        m.insert("persistent-keepalive".into(), k.into());
    }
    m.insert("udp".into(), true.into());
    m.insert("remote-dns-resolve".into(), true.into());
    m.insert("dns".into(), json!(["1.1.1.1", "8.8.8.8"]));
    if !f.awg.is_empty() {
        let mut o = f.awg.clone();
        if o.contains_key("header-protection-key") && !o.contains_key("version") {
            o.insert("version".into(), 3.into());
        }
        m.insert("amnezia-wg-option".into(), Value::Object(o));
    }
    Ok(m)
}

fn parse_reserved(s: &str) -> Option<Value> {
    let s = s.trim().trim_matches(|c| c == '[' || c == ']');
    let nums: Vec<u64> = s.split(',').filter_map(|x| x.trim().parse::<u64>().ok()).filter(|n| *n < 256).collect();
    if nums.len() == 3 {
        Some(json!(nums))
    } else if b64_decode(s).is_some_and(|b| b.len() == 3) {
        Some(Value::String(s.to_string()))
    } else {
        None
    }
}

fn wireguard(rest: &str) -> R {
    let u = split_url(rest)?;
    let q = &u.query;
    let port = parse_port(&u.port).ok_or("некорректный порт")?;
    let mut f = WgFields {
        server: u.host.clone(),
        port,
        private_key: if u.user.is_empty() { q.any(&["privatekey", "secretkey", "private-key"]).unwrap_or("").to_string() } else { u.user.clone() },
        public_key: q.any(&["publickey", "public-key", "peer_public_key", "peerpublickey"]).unwrap_or("").to_string(),
        psk: q.any(&["presharedkey", "pre-shared-key", "psk"]).map(|s| s.to_string()),
        addrs: q.any(&["address", "ip", "addresses", "local_address"]).unwrap_or("").split(',').map(|s| s.trim().to_string()).collect(),
        mtu: q.get("mtu").and_then(|s| s.parse().ok()),
        reserved: q.get("reserved").and_then(parse_reserved),
        keepalive: q.any(&["keepalive", "persistentkeepalive"]).and_then(|s| s.parse().ok()),
        awg: Map::new(),
    };
    for (k, v) in &q.0 {
        awg_put(&mut f.awg, k, v);
    }
    let m = wg_proxy(&f)?;
    Ok(Parsed { name: u.name, proxy: m })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Map<String, Value> {
        match parse_link(s) {
            Ok(x) => x.proxy,
            Err(e) => panic!("{s}: {e}"),
        }
    }

    #[test]
    fn vless_reality_vision() {
        let m = p("vless://3c8f1e2a-1111-2222-3333-444455556666@1.2.3.4:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&sid=6ba85179e30d4fc2&type=tcp&headerType=none#%F0%9F%87%B3%F0%9F%87%B1%20NL");
        assert_eq!(m["type"], "vless");
        assert_eq!(m["tls"], true);
        assert_eq!(m["servername"], "www.microsoft.com");
        assert_eq!(m["flow"], "xtls-rprx-vision");
        assert_eq!(m["reality-opts"]["short-id"], "6ba85179e30d4fc2");
        assert_eq!(m["network"], "tcp");
        assert_eq!(parse_link("vless://u@1.2.3.4:443?security=reality&pbk=bad").is_err(), true);
    }

    #[test]
    fn vless_xhttp_ws() {
        let m = p("vless://u@ex.com:443?security=tls&type=xhttp&path=%2Fx&host=cdn.ex.com&mode=packet-up&alpn=h2%2Chttp%252F1.1#a");
        assert_eq!(m["network"], "xhttp");
        assert_eq!(m["xhttp-opts"]["mode"], "packet-up");
        assert_eq!(m["xhttp-opts"]["host"], "cdn.ex.com");
        assert_eq!(m["servername"], "cdn.ex.com");
        assert_eq!(m["alpn"], json!(["h2", "http/1.1"]));
        let m = p("vless://u@ex.com:80?type=ws&path=%2Fws%3Fed%3D2048&host=a.com");
        assert_eq!(m["ws-opts"]["path"], "/ws");
        assert_eq!(m["ws-opts"]["max-early-data"], 2048);
        assert!(m.get("tls").is_none());
        let m = p("vless://u@ex.com:80?type=httpupgrade&path=%2Fu&host=a.com");
        assert_eq!(m["ws-opts"]["v2ray-http-upgrade"], true);
        let m = p("vless://u@ex.com:443?type=grpc&serviceName=gs&security=tls&sni=s.com");
        assert_eq!(m["grpc-opts"]["grpc-service-name"], "gs");
        let extra = "%7B%22xmux%22%3A%7B%22maxConcurrency%22%3A%2216-32%22%2C%22cMaxReuseTimes%22%3A0%7D%2C%22xPaddingBytes%22%3A%22100-1000%22%7D";
        let m = p(&format!("vless://u@ex.com:443?type=xhttp&security=tls&extra={extra}"));
        assert_eq!(m["xhttp-opts"]["reuse-settings"]["max-concurrency"], "16-32");
        assert_eq!(m["xhttp-opts"]["x-padding-bytes"], "100-1000");
    }

    #[test]
    fn vmess_json() {
        let j = r#"{"v":"2","ps":"test","add":"1.2.3.4","port":"8080","id":"b831381d-6324-4d53-ad4f-8cda48b30811","aid":"0","scy":"auto","net":"ws","type":"none","host":"h.com","path":"/p","tls":"tls","sni":"s.com"}"#;
        let l = format!("vmess://{}", b64_encode(j.as_bytes()));
        let x = parse_link(&l).unwrap();
        assert_eq!(x.name, "test");
        assert_eq!(x.proxy["ws-opts"]["headers"]["Host"], "h.com");
        assert_eq!(x.proxy["servername"], "s.com");
        assert_eq!(x.proxy["port"], 8080);
    }

    #[test]
    fn trojan_ss() {
        let m = p("trojan://pa%40ss@t.com:443?sni=x.com&type=ws&path=%2F&allowInsecure=1#t");
        assert_eq!(m["password"], "pa@ss");
        assert_eq!(m["sni"], "x.com");
        assert_eq!(m["skip-cert-verify"], true);
        let m = p("ss://YWVzLTEyOC1nY206dGVzdA@192.168.100.1:8888#Example1");
        assert_eq!(m["cipher"], "aes-128-gcm");
        assert_eq!(m["password"], "test");
        let m = p("ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2BrZQ%3D%3D@1.2.3.4:443/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.com#x");
        assert_eq!(m["password"], "YctPZ6U7xPPcU+gp3u+rZQ==");
        assert_eq!(m["plugin"], "obfs");
        assert_eq!(m["plugin-opts"]["host"], "example.com");
        let legacy = format!("ss://{}#L", b64_encode(b"chacha20-ietf-poly1305:pw@5.6.7.8:1234"));
        let m = p(&legacy);
        assert_eq!(m["server"], "5.6.7.8");
        assert_eq!(m["port"], 1234);
    }

    #[test]
    fn hy2_tuic_anytls() {
        let m = p("hysteria2://letmein@example.com:443,20000-30000/?insecure=1&obfs=salamander&obfs-password=gawrgura&sni=real.example.com#hy");
        assert_eq!(m["ports"], "443,20000-30000");
        assert_eq!(m["port"], 443);
        assert_eq!(m["obfs"], "salamander");
        let m = p("hy2://pw@[2001:db8::1]:8443?sni=a.com");
        assert_eq!(m["server"], "2001:db8::1");
        let m = p("tuic://uuid-1:pw@t.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=t.com");
        assert_eq!(m["uuid"], "uuid-1");
        assert_eq!(m["congestion-controller"], "bbr");
        let m = p("anytls://pw@a.com:443?sni=a.com&fp=chrome&insecure=1");
        assert_eq!(m["client-fingerprint"], "chrome");
    }

    #[test]
    fn wg_link() {
        let k = b64_encode(&[7u8; 32]);
        let l = format!(
            "wireguard://{}@162.159.192.1:2408?publickey={}&address=172.16.0.2/32,2606:4700::2/128&reserved=1,2,3&mtu=1280&jc=4&jmin=40&jmax=70#warp",
            percent_encoding::utf8_percent_encode(&k, percent_encoding::NON_ALPHANUMERIC),
            percent_encoding::utf8_percent_encode(&k, percent_encoding::NON_ALPHANUMERIC)
        );
        let m = p(&l);
        assert_eq!(m["ip"], "172.16.0.2");
        assert_eq!(m["ipv6"], "2606:4700::2");
        assert_eq!(m["reserved"], json!([1, 2, 3]));
        assert_eq!(m["amnezia-wg-option"]["jc"], 4);
    }

    #[test]
    fn real_samples() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../research/src");
        let Ok(rd) = std::fs::read_dir(&dir) else { return };
        let (mut ok, mut bad) = (0, 0);
        let mut errs = std::collections::BTreeMap::<String, usize>::new();
        for e in rd.flatten() {
            let t = std::fs::read_to_string(e.path()).unwrap_or_default();
            for line in t.lines() {
                let l = line.trim();
                if l.is_empty() || l.starts_with('#') || !l.contains("://") {
                    continue;
                }
                match parse_link(l) {
                    Ok(_) => ok += 1,
                    Err(er) => {
                        bad += 1;
                        *errs.entry(er).or_default() += 1;
                    }
                }
            }
        }
        eprintln!("samples ok={ok} bad={bad} {errs:?}");
        assert!(ok > 300, "too few parsed: {ok}");
        assert!(bad * 10 < ok, "too many errors: {bad}");
    }
}
