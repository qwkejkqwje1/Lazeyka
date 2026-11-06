//! Import of user/server lists: share links (one per line), base64 subscriptions,
//! Clash/mihomo YAML, WireGuard/AmneziaWG .conf, OpenVPN .ovpn, Amnezia `vpn://`.

use crate::links::{self, Parsed, WgFields, awg_put, parse_link, wg_proxy};
use crate::util::*;
use serde_json::{Map, Value, json};

/// Maximum uncompressed JSON payload accepted from an Amnezia `vpn://` container (4 MiB).
pub const MAX_AMNEZIA_JSON: usize = 4 * 1024 * 1024;

#[derive(Debug, Default)]
pub struct Report {
    pub items: Vec<Parsed>,
    pub errors: Vec<String>,
}

impl Report {
    fn push(&mut self, r: Result<Parsed, String>) {
        match r {
            Ok(p) => self.items.push(p),
            Err(e) => self.errors.push(e),
        }
    }
}

/// Parses any supported text. `depth` guards against nested base64.
pub fn parse_text(text: &str) -> Report {
    parse_inner(text, 0)
}

fn parse_inner(text: &str, depth: u8) -> Report {
    let mut rep = Report::default();
    let t = text.trim_start_matches('\u{feff}').trim();
    if t.is_empty() {
        return rep;
    }
    if t.contains("[Interface]") || t.contains("[interface]") {
        rep.push(parse_wg_conf(t, ""));
        return rep;
    }
    if looks_ovpn(t) {
        rep.push(parse_ovpn(t, ""));
        return rep;
    }
    if t.starts_with("proxies:") || t.contains("\nproxies:") || (t.starts_with('{') && t.contains("\"proxies\"")) {
        if let Some(r) = parse_clash(t) {
            return r;
        }
    }
    if !t.contains("://") && depth < 2 && looks_base64(t) {
        if let Some(dec) = b64_decode_str(t) {
            return parse_inner(&dec, depth + 1);
        }
    }
    for line in t.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with("//") {
            continue;
        }
        // lines may hold several links separated by spaces
        for tok in l.split_whitespace() {
            if !tok.contains("://") {
                continue;
            }
            if tok.get(..6).is_some_and(|prefix| prefix.eq_ignore_ascii_case("vpn://")) && tok.len() > 6 {
                match parse_amnezia(tok) {
                    Ok(v) => rep.items.extend(v),
                    Err(e) => rep.errors.push(e),
                }
            } else {
                rep.push(parse_link(tok));
            }
        }
    }
    if rep.items.is_empty() && rep.errors.is_empty() && depth < 2 && looks_base64(t) {
        if let Some(dec) = b64_decode_str(t) {
            return parse_inner(&dec, depth + 1);
        }
    }
    rep
}

// ---------- Clash / mihomo YAML ----------

const CLASH_TYPES: &[&str] = &["vless", "vmess", "trojan", "ss", "hysteria2", "tuic", "anytls", "wireguard", "openvpn", "masque"];
/// Keys that could reference local files or alter routing; never imported.
const DROP_KEYS: &[&str] = &[
    "name",
    "dialer-proxy",
    "interface-name",
    "routing-mark",
    "ca",
    "certificate",
    "ca-str",
    "provider",
    "smux",
    "ip-stack",
];

pub fn parse_clash(t: &str) -> Option<Report> {
    let v: serde_yaml_ng::Value = serde_yaml_ng::from_str(t).ok()?;
    let j: Value = serde_json::to_value(&v).ok()?;
    let list = j.get("proxies")?.as_array()?;
    let mut rep = Report::default();
    for p in list {
        rep.push(clash_proxy(p));
    }
    Some(rep)
}

pub fn clash_proxy(p: &Value) -> Result<Parsed, String> {
    let o = p.as_object().ok_or("некорректная запись proxies")?;
    let ty = o.get("type").and_then(|v| v.as_str()).unwrap_or("");
    if !CLASH_TYPES.contains(&ty) {
        return Err(format!("тип {ty} не поддерживается"));
    }
    let name = o.get("name").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let mut m = Map::new();
    for (k, v) in o {
        if DROP_KEYS.contains(&k.as_str()) {
            continue;
        }
        if k == "private-key" && ty != "wireguard" && ty != "masque" {
            continue; // TLS client key path
        }
        m.insert(k.clone(), v.clone());
    }
    // port may be a string
    if let Some(Value::String(s)) = m.get("port") {
        let n = parse_port(s).ok_or("некорректный порт")?;
        m.insert("port".into(), n.into());
    }
    let host = m.get("server").and_then(|v| v.as_str()).unwrap_or("");
    if !valid_host(host) || m.get("port").and_then(|v| v.as_u64()).unwrap_or(0) == 0 {
        return Err("нет адреса сервера".into());
    }
    if ty == "wireguard" {
        m.insert("remote-dns-resolve".into(), true.into());
        m.entry("dns").or_insert(json!(["1.1.1.1", "8.8.8.8"]));
        if let Some(Value::Object(peers)) = m.get("peers").and_then(|p| p.get(0)).cloned().map(|v| {
            if let Value::Object(o) = v { Value::Object(o) } else { Value::Null }
        }) {
            // flatten single-peer form for simplicity
            for k in ["server", "port", "public-key", "pre-shared-key", "reserved"] {
                if let Some(v) = peers.get(k) {
                    m.insert(k.into(), v.clone());
                }
            }
            m.remove("peers");
        }
    }
    m.entry("udp").or_insert(true.into());
    Ok(Parsed { name, proxy: m })
}

// ---------- WireGuard / AmneziaWG .conf ----------

pub fn parse_wg_conf(t: &str, name: &str) -> Result<Parsed, String> {
    let mut f = WgFields::default();
    let mut section = String::new();
    let mut endpoint = String::new();
    for raw in t.lines() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            section = line.trim_matches(|c| c == '[' || c == ']').to_ascii_lowercase();
            continue;
        }
        let Some((k, v)) = line.split_once('=') else { continue };
        let (k, v) = (k.trim(), v.trim());
        let kl = k.to_ascii_lowercase();
        match (section.as_str(), kl.as_str()) {
            ("interface", "privatekey") => f.private_key = v.to_string(),
            ("interface", "address") => f.addrs.extend(v.split(',').map(|s| s.trim().to_string())),
            ("interface", "mtu") => f.mtu = v.parse().ok(),
            ("interface", "dns") | ("interface", "listenport") | ("interface", "table") => {}
            ("interface", _) => {
                awg_put(&mut f.awg, k, v);
            }
            ("peer", "publickey") if f.public_key.is_empty() => f.public_key = v.to_string(),
            ("peer", "presharedkey") if f.psk.is_none() => f.psk = Some(v.to_string()),
            ("peer", "endpoint") if endpoint.is_empty() => endpoint = v.to_string(),
            ("peer", "persistentkeepalive") => f.keepalive = v.parse().ok(),
            _ => {}
        }
    }
    let (host, port) = split_host_port(&endpoint).ok_or("в конфигурации нет Endpoint")?;
    f.server = host;
    f.port = parse_port(&port).ok_or("некорректный порт в Endpoint")?;
    // Amnezia leaves placeholders like $PRIMARY_DNS — harmless; but unresolved keys are fatal
    if f.private_key.starts_with('$') || f.public_key.starts_with('$') {
        return Err("конфигурация не заполнена (шаблон)".into());
    }
    let m = wg_proxy(&f)?;
    Ok(Parsed { name: name.to_string(), proxy: m })
}

// ---------- OpenVPN ----------

fn looks_ovpn(t: &str) -> bool {
    t.lines().any(|l| {
        let l = l.trim_start();
        l.starts_with("remote ") || l == "client"
    }) && (t.contains("<ca>") || t.contains("\nca ") || t.contains("dev tun"))
}

pub fn parse_ovpn(t: &str, name: &str) -> Result<Parsed, String> {
    let mut m = Map::new();
    m.insert("type".into(), "openvpn".into());
    let mut proto = "udp".to_string();
    let mut port: Option<u16> = None;
    let mut remote: Option<(String, Option<u16>, Option<String>)> = None;
    let mut needs_auth = false;
    let mut lines = t.lines().peekable();
    while let Some(raw) = lines.next() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(tag) = line.strip_prefix('<').and_then(|s| s.strip_suffix('>')) {
            if tag.starts_with('/') {
                continue;
            }
            let end = format!("</{tag}>");
            let mut body = String::new();
            for l in lines.by_ref() {
                if l.trim() == end {
                    break;
                }
                body.push_str(l.trim_end());
                body.push('\n');
            }
            match tag {
                "ca" | "cert" | "key" | "tls-auth" | "tls-crypt" | "tls-crypt-v2" => {
                    m.insert(tag.into(), body.into());
                }
                "auth-user-pass" => {
                    let mut it = body.lines();
                    if let (Some(u), Some(p)) = (it.next(), it.next()) {
                        m.insert("username".into(), u.trim().into());
                        m.insert("password".into(), p.trim().into());
                    }
                }
                _ => {}
            }
            continue;
        }
        let mut parts = line.split_whitespace();
        let key = parts.next().unwrap_or("");
        let args: Vec<&str> = parts.collect();
        match key {
            "remote" if remote.is_none() => {
                if let Some(h) = args.first() {
                    remote = Some((h.to_string(), args.get(1).and_then(|p| parse_port(p)), args.get(2).map(|s| s.to_string())));
                }
            }
            "proto" => {
                if let Some(p) = args.first() {
                    proto = p.to_string();
                }
            }
            "port" => port = args.first().and_then(|p| parse_port(p)),
            "cipher" => {
                if let Some(c) = args.first() {
                    m.insert("cipher".into(), c.to_ascii_uppercase().into());
                }
            }
            "data-ciphers" | "ncp-ciphers" => {
                if let Some(c) = args.first() {
                    let l: Vec<Value> = c.split(':').map(|s| Value::from(s.to_ascii_uppercase())).collect();
                    m.insert("data-ciphers".into(), Value::Array(l));
                }
            }
            "data-ciphers-fallback" => {
                if let Some(c) = args.first() {
                    m.insert("data-ciphers-fallback".into(), c.to_ascii_uppercase().into());
                }
            }
            "auth" => {
                if let Some(c) = args.first() {
                    m.insert("auth".into(), c.to_ascii_uppercase().into());
                }
            }
            "comp-lzo" => {
                m.insert("comp-lzo".into(), args.first().copied().unwrap_or("yes").into());
            }
            "key-direction" => {
                if let Some(c) = args.first() {
                    m.insert("key-direction".into(), (*c).into());
                }
            }
            "auth-user-pass" => needs_auth = true,
            "tun-mtu" => {
                if let Some(n) = args.first().and_then(|s| s.parse::<u64>().ok()) {
                    m.insert("mtu".into(), n.into());
                }
            }
            _ => {}
        }
    }
    let (host, rport, rproto) = remote.ok_or("в .ovpn нет строки remote")?;
    if !valid_host(&host) {
        return Err(format!("некорректный адрес {host}"));
    }
    let proto = rproto.unwrap_or(proto);
    let proto = if proto.starts_with("tcp") { "tcp" } else { "udp" };
    m.insert("server".into(), host.into());
    m.insert("port".into(), rport.or(port).unwrap_or(1194).into());
    m.insert("proto".into(), proto.into());
    m.insert("udp".into(), true.into());
    m.insert("remote-dns-resolve".into(), true.into());
    m.insert("dns".into(), json!(["1.1.1.1", "8.8.8.8"]));
    if !m.contains_key("ca") {
        return Err("в .ovpn нет сертификата <ca>".into());
    }
    if needs_auth && !m.contains_key("username") {
        return Err("для этого OpenVPN-профиля нужны логин и пароль: добавьте блок <auth-user-pass>логин\nпароль</auth-user-pass>".into());
    }
    if !needs_auth && !m.contains_key("cert") {
        return Err("в .ovpn нет клиентского сертификата".into());
    }
    Ok(Parsed { name: name.to_string(), proxy: m })
}

// ---------- Amnezia vpn:// ----------

pub fn parse_amnezia(s: &str) -> Result<Vec<Parsed>, String> {
    let trimmed = s.trim();
    if !trimmed.get(..6).is_some_and(|p| p.eq_ignore_ascii_case("vpn://")) {
        return Err("vpn://: некорректный префикс".into());
    }
    let body = trimmed.get(6..).ok_or("vpn://: пустая ссылка")?.trim();
    if body.len() > MAX_AMNEZIA_JSON * 2 {
        return Err("vpn://: превышен допустимый размер конфигурации".into());
    }
    let raw = b64_decode(body).ok_or("vpn://: не удалось декодировать")?;
    if raw.len() > MAX_AMNEZIA_JSON {
        return Err("vpn://: превышен допустимый размер конфигурации".into());
    }
    let json_bytes = if raw.len() > 4 && raw[4] == 0x78 {
        // qCompress: 4-byte big-endian uncompressed length + zlib stream
        let declared = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        if declared > MAX_AMNEZIA_JSON {
            return Err("vpn://: превышен лимит распакованных данных".into());
        }
        use std::io::Read;
        let d = flate2::read::ZlibDecoder::new(&raw[4..]);
        let mut out = Vec::with_capacity(declared.min(64 * 1024));
        d.take((MAX_AMNEZIA_JSON + 1) as u64)
            .read_to_end(&mut out)
            .map_err(|_| "vpn://: повреждённые данные")?;
        if out.len() > MAX_AMNEZIA_JSON {
            return Err("vpn://: превышен лимит распакованных данных".into());
        }
        out
    } else {
        raw
    };
    let j: Value = serde_json::from_slice(&json_bytes).map_err(|_| "vpn://: некорректный JSON")?;
    let desc = j.get("description").and_then(|v| v.as_str()).unwrap_or("Amnezia").to_string();
    let host_name = j.get("hostName").and_then(|v| v.as_str()).unwrap_or("").to_string();
    let mut out = Vec::new();
    let mut errs = Vec::new();
    for c in j.get("containers").and_then(|v| v.as_array()).cloned().unwrap_or_default() {
        let kind = c.get("container").and_then(|v| v.as_str()).unwrap_or("");
        let key = match kind {
            "amnezia-awg" | "amnezia-awg2" => "awg",
            "amnezia-wireguard" => "wireguard",
            "amnezia-xray" => "xray",
            "amnezia-openvpn" => "openvpn",
            _ => continue,
        };
        let Some(inner) = c.get(key) else { continue };
        let last = inner.get("last_config").and_then(|v| v.as_str()).unwrap_or("");
        let lc: Value = serde_json::from_str(last).unwrap_or(Value::Null);
        let r = match key {
            "awg" | "wireguard" => amnezia_wg(&lc, inner, &host_name, &desc),
            "xray" => xray_outbound(&lc).map(|proxy| Parsed { name: desc.clone(), proxy }),
            "openvpn" => match lc.get("config").and_then(|v| v.as_str()) {
                Some(cfg) => parse_ovpn(cfg, &desc),
                None => Err("vpn://: нет конфигурации OpenVPN".into()),
            },
            _ => continue,
        };
        match r {
            Ok(p) => out.push(p),
            Err(e) => errs.push(e),
        }
    }
    if out.is_empty() {
        return Err(errs.into_iter().next().unwrap_or_else(|| "vpn://: нет поддерживаемых протоколов".into()));
    }
    Ok(out)
}

fn amnezia_wg(lc: &Value, inner: &Value, host: &str, desc: &str) -> Result<Parsed, String> {
    if let Some(cfg) = lc.get("config").and_then(|v| v.as_str()) {
        let cfg = cfg.replace("$SERVER_IP_ADDRESS", host);
        if let Ok(p) = parse_wg_conf(&cfg, desc) {
            return Ok(p);
        }
    }
    let g = |k: &str| {
        lc.get(k)
            .or_else(|| inner.get(k))
            .and_then(|v| match v {
                Value::String(s) => Some(s.clone()),
                Value::Number(n) => Some(n.to_string()),
                _ => None,
            })
            .filter(|s| !s.is_empty())
    };
    let mut f = WgFields {
        server: g("hostName").unwrap_or_else(|| host.to_string()),
        port: g("port").and_then(|p| parse_port(&p)).ok_or("vpn://: нет порта")?,
        private_key: g("client_priv_key").ok_or("vpn://: нет ключа клиента")?,
        public_key: g("server_pub_key").ok_or("vpn://: нет ключа сервера")?,
        psk: g("psk_key"),
        addrs: vec![g("client_ip").ok_or("vpn://: нет адреса клиента")?],
        mtu: g("mtu").and_then(|s| s.parse().ok()),
        reserved: None,
        keepalive: g("persistent_keep_alive").and_then(|s| s.parse().ok()),
        awg: Map::new(),
    };
    for k in ["Jc", "Jmin", "Jmax", "S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4", "I1", "I2", "I3", "I4", "I5"] {
        if let Some(v) = g(k) {
            awg_put(&mut f.awg, k, &v);
        }
    }
    Ok(Parsed { name: desc.to_string(), proxy: wg_proxy(&f)? })
}

/// Xray JSON config (first vless/vmess/trojan outbound) → mihomo proxy.
pub fn xray_outbound(cfg: &Value) -> Result<Map<String, Value>, String> {
    let obs = cfg.get("outbounds").and_then(|v| v.as_array()).ok_or("Xray: нет outbounds")?;
    let ob = obs
        .iter()
        .find(|o| matches!(o.get("protocol").and_then(|v| v.as_str()), Some("vless" | "vmess" | "trojan")))
        .ok_or("Xray: нет поддерживаемого outbound")?;
    let proto = ob["protocol"].as_str().unwrap_or("");
    let s = &ob["settings"];
    let (addr, port, user) = if proto == "trojan" {
        let sv = &s["servers"][0];
        (sv["address"].as_str().unwrap_or(""), sv["port"].as_u64().unwrap_or(0), sv.clone())
    } else {
        let v = &s["vnext"][0];
        (v["address"].as_str().unwrap_or(""), v["port"].as_u64().unwrap_or(0), v["users"][0].clone())
    };
    let ss = &ob["streamSettings"];
    let mut q: Vec<(String, String)> = Vec::new();
    let mut put = |k: &str, v: Option<&str>| {
        if let Some(v) = v.filter(|v| !v.is_empty()) {
            q.push((k.into(), v.into()));
        }
    };
    let net = ss["network"].as_str().unwrap_or("tcp");
    put("type", Some(net));
    let sec = ss["security"].as_str().unwrap_or("none");
    put("security", Some(sec));
    let tls = if sec == "reality" { &ss["realitySettings"] } else { &ss["tlsSettings"] };
    put("sni", tls["serverName"].as_str());
    put("fp", tls["fingerprint"].as_str());
    put("pbk", tls["publicKey"].as_str());
    put("sid", tls["shortId"].as_str());
    if tls["allowInsecure"].as_bool() == Some(true) {
        put("allowinsecure", Some("1"));
    }
    let alpn_s = tls["alpn"].as_array().map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(","));
    put("alpn", alpn_s.as_deref());
    let ts = match net {
        "ws" => &ss["wsSettings"],
        "grpc" => &ss["grpcSettings"],
        "xhttp" | "splithttp" => &ss["xhttpSettings"],
        "httpupgrade" => &ss["httpupgradeSettings"],
        _ => &ss["tcpSettings"],
    };
    put("path", ts["path"].as_str());
    put("host", ts["host"].as_str().or_else(|| ts["headers"]["Host"].as_str()));
    put("servicename", ts["serviceName"].as_str());
    put("mode", ts["mode"].as_str());
    put("flow", user["flow"].as_str());
    put("encryption", user["encryption"].as_str());
    let id = if proto == "trojan" { user["password"].as_str().unwrap_or("") } else { user["id"].as_str().unwrap_or("") };
    let qs: String = q
        .iter()
        .map(|(k, v)| format!("{k}={}", percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC)))
        .collect::<Vec<_>>()
        .join("&");
    let host = if addr.contains(':') { format!("[{addr}]") } else { addr.to_string() };
    let link = format!(
        "{proto}://{}@{host}:{port}?{qs}",
        percent_encoding::utf8_percent_encode(id, percent_encoding::NON_ALPHANUMERIC)
    );
    let p = links::parse_link(&link)?;
    Ok(p.proxy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_sub_and_lines() {
        let plain = "# profile-title: x\nvless://u@a.com:443?security=tls#a\n\ntrojan://p@b.com:443#b\nbad line\n";
        let r = parse_text(plain);
        assert_eq!(r.items.len(), 2);
        let enc = b64_encode(plain.as_bytes());
        let r = parse_text(&enc);
        assert_eq!(r.items.len(), 2);
    }

    #[test]
    fn unicode_tokens_never_panic() {
        for sample in [
            "a://😀x",
            "Я://😀",
            "😀://test",
            "v://😀",
            "vp://😀",
            "vpn://😀",
            "a://😀x vless://u@a.com:443?security=tls#ok",
            "тест://сервер.рф:443",
        ] {
            let r = parse_text(sample);
            if sample.contains("vless://") {
                assert_eq!(r.items.len(), 1);
            }
        }
        assert!(parse_amnezia("a://😀x").is_err());
    }

    #[test]
    fn amnezia_decompression_bomb_is_rejected() {
        use base64::Engine;
        use std::io::Write;
        // 1. Declared header size exceeds MAX_AMNEZIA_JSON
        let mut fake_header = ((MAX_AMNEZIA_JSON as u32) + 1024).to_be_bytes().to_vec();
        fake_header.extend_from_slice(&[0x78, 0x9c, 0x03, 0x00, 0x00, 0x00, 0x00, 0x01]);
        let link = format!("vpn://{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&fake_header));
        let err = parse_amnezia(&link).unwrap_err();
        assert!(err.contains("превышен лимит"), "{err}");

        // 2. Small declared header, but actual zlib stream expands past MAX_AMNEZIA_JSON
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        let chunk = vec![b'A'; 64 * 1024];
        for _ in 0..((MAX_AMNEZIA_JSON / chunk.len()) + 2) {
            z.write_all(&chunk).unwrap();
        }
        let comp = z.finish().unwrap();
        let mut bomb = 100u32.to_be_bytes().to_vec();
        bomb.extend(comp);
        let bomb_link = format!("vpn://{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bomb));
        let err2 = parse_amnezia(&bomb_link).unwrap_err();
        assert!(err2.contains("превышен лимит"), "{err2}");
    }

    #[test]
    fn clash_yaml() {
        let y = "proxies:\n  - name: a\n    type: ss\n    server: 1.2.3.4\n    port: '8388'\n    cipher: aes-128-gcm\n    password: x\n    dialer-proxy: evil\n  - name: b\n    type: socks5\n    server: 1.1.1.1\n    port: 1\n";
        let r = parse_text(y);
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.items[0].proxy["port"], 8388);
        assert!(r.items[0].proxy.get("dialer-proxy").is_none());
        assert_eq!(r.errors.len(), 1);
    }

    fn key(b: u8) -> String {
        b64_encode(&[b; 32])
    }

    #[test]
    fn awg_conf() {
        let c = format!(
            "[Interface]\nPrivateKey = {}\nAddress = 10.8.1.2/32\nDNS = 1.1.1.1\nJc = 4\nJmin = 10\nJmax = 50\nS1 = 77\nS2 = 25\nH1 = 1355447220\nH2 = 1-1000\nH3 = 3\nH4 = 4\nI1 = <b 0xc000>\n\n[Peer]\nPublicKey = {}\nPresharedKey = {}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 5.6.7.8:51820\nPersistentKeepalive = 25\n",
            key(1),
            key(2),
            key(3)
        );
        let r = parse_text(&c);
        assert_eq!(r.items.len(), 1, "{:?}", r.errors);
        let m = &r.items[0].proxy;
        let o = &m["amnezia-wg-option"];
        assert_eq!(o["jc"], 4);
        assert_eq!(o["h1"], 1355447220u64);
        assert_eq!(o["h2"], "1-1000");
        assert_eq!(o["i1"], "<b 0xc000>");
        assert_eq!(m["persistent-keepalive"], 25);
    }

    #[test]
    fn amnezia_vpn_link() {
        use std::io::Write;
        let conf = format!(
            "[Interface]\nAddress = 10.8.1.5/32\nDNS = $PRIMARY_DNS, $SECONDARY_DNS\nPrivateKey = {}\nJc = 3\nJmin = 10\nJmax = 30\n[Peer]\nPublicKey = {}\nEndpoint = 9.9.9.9:443\nAllowedIPs = 0.0.0.0/0\n",
            key(4),
            key(5)
        );
        let lc = json!({ "config": conf, "hostName": "9.9.9.9", "port": 443 }).to_string();
        let xray = json!({"outbounds":[{"protocol":"vless","settings":{"vnext":[{"address":"8.8.4.4","port":443,"users":[{"id":"abc","flow":"xtls-rprx-vision","encryption":"none"}]}]},"streamSettings":{"network":"tcp","security":"reality","realitySettings":{"serverName":"www.google.com","fingerprint":"chrome","publicKey":"SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc","shortId":"ab"}}}]}).to_string();
        let doc = json!({
            "containers": [
                {"container": "amnezia-awg", "awg": {"last_config": lc, "port": "443"}},
                {"container": "amnezia-xray", "xray": {"last_config": xray}}
            ],
            "defaultContainer": "amnezia-awg",
            "description": "Мой сервер",
            "hostName": "9.9.9.9"
        })
        .to_string();
        let mut z = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::new(8));
        z.write_all(doc.as_bytes()).unwrap();
        let comp = z.finish().unwrap();
        let mut blob = (doc.len() as u32).to_be_bytes().to_vec();
        blob.extend(comp);
        use base64::Engine;
        let link = format!("vpn://{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&blob));
        let r = parse_text(&link);
        assert_eq!(r.items.len(), 2, "{:?}", r.errors);
        assert_eq!(r.items[0].name, "Мой сервер");
        assert_eq!(r.items[0].proxy["amnezia-wg-option"]["jc"], 3);
        assert_eq!(r.items[1].proxy["reality-opts"]["short-id"], "ab");
        assert_eq!(r.items[1].proxy["flow"], "xtls-rprx-vision");
    }

    #[test]
    fn ovpn() {
        let o = "client\ndev tun\nproto udp\nremote vpn.example.com 1194\ncipher AES-256-GCM\nauth SHA256\n<ca>\n-----BEGIN CERTIFICATE-----\nAAA\n-----END CERTIFICATE-----\n</ca>\n<cert>\nC\n</cert>\n<key>\nK\n</key>\n";
        let r = parse_text(o);
        assert_eq!(r.items.len(), 1, "{:?}", r.errors);
        assert_eq!(r.items[0].proxy["proto"], "udp");
        assert_eq!(r.items[0].proxy["cipher"], "AES-256-GCM");
    }
}
