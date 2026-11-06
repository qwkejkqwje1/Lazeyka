//! Core data model: servers, probe results, verification states, trust levels, and free-tier limits.

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    Vless,
    Vmess,
    Trojan,
    Ss,
    Hysteria2,
    Tuic,
    Anytls,
    Wireguard,
    Awg,
    Openvpn,
    Masque,
}

impl Proto {
    pub fn label(self) -> &'static str {
        match self {
            Proto::Vless => "VLESS",
            Proto::Vmess => "VMess",
            Proto::Trojan => "Trojan",
            Proto::Ss => "Shadowsocks",
            Proto::Hysteria2 => "Hysteria2",
            Proto::Tuic => "TUIC",
            Proto::Anytls => "AnyTLS",
            Proto::Wireguard => "WireGuard",
            Proto::Awg => "AmneziaWG",
            Proto::Openvpn => "OpenVPN",
            Proto::Masque => "MASQUE",
        }
    }
    pub fn all() -> &'static [Proto] {
        &[
            Proto::Vless,
            Proto::Vmess,
            Proto::Trojan,
            Proto::Ss,
            Proto::Hysteria2,
            Proto::Tuic,
            Proto::Anytls,
            Proto::Wireguard,
            Proto::Awg,
            Proto::Openvpn,
            Proto::Masque,
        ]
    }
    /// Classifies a mihomo proxy definition.
    pub fn of(proxy: &Map<String, Value>) -> Option<Proto> {
        Some(match proxy.get("type")?.as_str()? {
            "vless" => Proto::Vless,
            "vmess" => Proto::Vmess,
            "trojan" => Proto::Trojan,
            "ss" => Proto::Ss,
            "hysteria2" => Proto::Hysteria2,
            "tuic" => Proto::Tuic,
            "anytls" => Proto::Anytls,
            "wireguard" => {
                if proxy.contains_key("amnezia-wg-option") {
                    Proto::Awg
                } else {
                    Proto::Wireguard
                }
            }
            "openvpn" => Proto::Openvpn,
            "masque" => Proto::Masque,
            _ => return None,
        })
    }
    /// Transport runs over UDP (TCP pre-checks are meaningless).
    pub fn udp_based(self) -> bool {
        matches!(self, Proto::Hysteria2 | Proto::Tuic | Proto::Wireguard | Proto::Awg | Proto::Masque)
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default, Hash)]
#[serde(rename_all = "lowercase")]
pub enum Origin {
    /// Added by the user (link, file, subscription): always preferred.
    Mine,
    /// Found by the scanner in public sources.
    #[default]
    Free,
    /// Built-in Cloudflare WARP profile.
    Warp,
}

/// Trust category of a server source: official free providers and user-owned servers
/// are never mixed with untrusted public community nodes.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TrustLevel {
    UserOwned,
    OfficialFree,
    PublicCommunity,
}

impl TrustLevel {
    pub fn label(self) -> &'static str {
        match self {
            TrustLevel::UserOwned => "Свой сервер",
            TrustLevel::OfficialFree => "Официальный бесплатный",
            TrustLevel::PublicCommunity => "Публичный узел",
        }
    }

    pub fn warning(self) -> Option<&'static str> {
        match self {
            TrustLevel::PublicCommunity => Some(
                "Публичный узел: оператор сервера может видеть метаданные соединений и незашифрованный HTTP-трафик. Для банков и личных кабинетов используйте только HTTPS.",
            ),
            _ => None,
        }
    }
}

/// Detailed lifecycle & verification state of a server (Section 6).
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug, Default)]
#[serde(rename_all = "snake_case")]
pub enum ServerState {
    #[default]
    Found,
    ConfigValid,
    ReachableDirect,
    ReachableRelay,
    HandshakeOk,
    InternetOk,
    CountryVerified,
    Unstable,
    TempUnavailable,
    AuthRequired,
    Disabled,
}

impl ServerState {
    pub fn label(self) -> &'static str {
        match self {
            ServerState::Found => "Найден",
            ServerState::ConfigValid => "Конфигурация корректна",
            ServerState::ReachableDirect => "Доступен напрямую",
            ServerState::ReachableRelay => "Доступен через входное звено",
            ServerState::HandshakeOk => "VPN установлен",
            ServerState::InternetOk => "Интернет работает",
            ServerState::CountryVerified => "Страна подтверждена",
            ServerState::Unstable => "Нестабилен",
            ServerState::TempUnavailable => "Временно недоступен",
            ServerState::AuthRequired => "Требует авторизации",
            ServerState::Disabled => "Отключён пользователем",
        }
    }
}

/// Optional limits of a free provider tier.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct FreeTierLimits {
    /// Monthly or session traffic cap in MiB (0 = unlimited).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub traffic_mb: u64,
    /// Optional explicit monthly traffic cap in MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_mb_month: Option<u64>,
    /// Speed cap in kbit/s (0 = unlimited).
    #[serde(default, skip_serializing_if = "is_zero32")]
    pub speed_kbps: u32,
    /// Simultaneous device limit (0 = unlimited).
    #[serde(default, skip_serializing_if = "is_zero8")]
    pub max_devices: u8,
    /// Human-readable note on free tier conditions.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

impl FreeTierLimits {
    pub fn summary(&self) -> Option<String> {
        if !self.note.is_empty() {
            return Some(self.note.clone());
        }
        let mut parts = Vec::new();
        if let Some(mb) = self.traffic_mb_month.or_else(|| (self.traffic_mb > 0).then_some(self.traffic_mb)) {
            if mb >= 1024 {
                parts.push(format!("Лимит: {} ГБ/мес", mb / 1024));
            } else {
                parts.push(format!("Лимит: {} МБ/мес", mb));
            }
        }
        if self.speed_kbps > 0 {
            parts.push(format!("до {} Мбит/с", (self.speed_kbps / 1000).max(1)));
        }
        if self.max_devices > 0 {
            parts.push(format!("устройств: {}", self.max_devices));
        }
        if parts.is_empty() { None } else { Some(parts.join(" · ")) }
    }
}

/// Services bitmask in [`Probe::services`].
pub const SVC_YOUTUBE: u8 = 1;
pub const SVC_DISCORD: u8 = 2;
pub const SVC_TELEGRAM: u8 = 4;
pub const SVC_UDP: u8 = 8;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Probe {
    /// Unix time of the check.
    pub at: u64,
    pub ok: bool,
    /// Round trip through the server, ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_ip: Option<String>,
    /// ISO country of the exit IP (DB-IP Lite / trace).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_cc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp: Option<bool>,
    /// Download speed, kbit/s (only measured for the best servers).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub speed: Option<u32>,
    /// Unix time of the speed measurement.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub speed_at: u64,
    #[serde(default)]
    pub services: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Server {
    /// Stable id: hash of the canonical proxy definition. Used as mihomo proxy name.
    pub id: String,
    pub name: String,
    pub proto: Proto,
    pub host: String,
    pub port: u16,
    /// Human label of the transport: "Reality", "XHTTP·TLS", "QUIC"...
    pub transport: String,
    /// mihomo proxy definition without `name`.
    pub proxy: Map<String, Value>,
    #[serde(default)]
    pub origin: Origin,
    /// Source id (catalog source, subscription id, provider id, "manual").
    #[serde(default)]
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub probe: Option<Probe>,
    #[serde(default)]
    pub added: u64,
    /// Successful checks in total.
    #[serde(default)]
    pub oks: u32,
    /// Consecutive failed checks.
    #[serde(default)]
    pub fails: u32,
    #[serde(default)]
    pub last_ok: u64,
    /// Marked with a star by the user: listed first, preferred by AUTO, never pruned.
    #[serde(default, skip_serializing_if = "is_false")]
    pub fav: bool,
    /// Results of the last checks, newest in bit 0 (1 = worked).
    #[serde(default, skip_serializing_if = "is_zero32")]
    pub hist: u32,
    /// Number of valid bits in `hist` (≤ 32).
    #[serde(default, skip_serializing_if = "is_zero8")]
    pub hist_n: u8,
    /// The server answers only through this working server (its id): the direct path from
    /// here is blocked, the entry hop gets the connection out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    /// Last attempt to test the server through an entry hop (unix seconds).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub relay_at: u64,
    /// Explicitly disabled by the user.
    #[serde(default, skip_serializing_if = "is_false")]
    pub disabled: bool,
    /// Last check failed due to authentication/token expiration rather than network/server death.
    #[serde(default, skip_serializing_if = "is_false")]
    pub auth_error: bool,
    /// Circuit breaker open until this unix timestamp (seconds).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub cb_until: u64,
    /// Optional free-tier limitations associated with this server/provider.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<FreeTierLimits>,
}

/// Name of the config-level copy of a working server that relay servers dial through.
pub fn hop_name(id: &str) -> String {
    format!("hop:{id}")
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}
fn is_zero32(v: &u32) -> bool {
    *v == 0
}
fn is_zero8(v: &u8) -> bool {
    *v == 0
}
fn is_false(v: &bool) -> bool {
    !*v
}

/// Detects whether an error string represents an authentication, password, or token failure.
pub fn is_auth_failure(err: &str) -> bool {
    let l = err.to_lowercase();
    l.contains("auth")
        || l.contains("авториз")
        || l.contains("пароль")
        || l.contains("токен")
        || l.contains("token")
        || l.contains("unauthorized")
        || l.contains("forbidden")
        || l.contains("http 401")
        || l.contains("http 403")
        || l.contains("логин")
}

impl Server {
    pub fn new(name: &str, mut proxy: Map<String, Value>, origin: Origin, source: &str) -> Result<Server, String> {
        proxy.remove("name");
        let proto = Proto::of(&proxy).ok_or("неподдерживаемый тип")?;
        let host = proxy.get("server").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let port = proxy.get("port").and_then(|v| v.as_u64()).unwrap_or(0) as u16;
        if host.is_empty() || port == 0 {
            return Err("нет адреса сервера".into());
        }
        let id = proxy_id(&proxy);
        let transport = transport_label(proto, &proxy);
        let name = if name.trim().is_empty() { format!("{host}:{port}") } else { crate::util::clip(name, 60) };
        Ok(Server {
            id,
            name,
            proto,
            host,
            port,
            transport,
            proxy,
            origin,
            source: source.to_string(),
            probe: None,
            added: crate::util::now(),
            oks: 0,
            fails: 0,
            last_ok: 0,
            fav: false,
            hist: 0,
            hist_n: 0,
            relay: None,
            relay_at: 0,
            disabled: false,
            auth_error: false,
            cb_until: 0,
            limits: None,
        })
    }

    /// mihomo proxy JSON with `name` = id.
    pub fn mihomo_proxy(&self) -> Value {
        let mut m = self.proxy.clone();
        m.insert("name".into(), Value::String(self.id.clone()));
        if let Some(h) = &self.relay {
            m.insert("dialer-proxy".into(), Value::String(hop_name(h)));
        }
        Value::Object(m)
    }

    /// True when the server has verified internet access and is not disabled or auth-blocked.
    pub fn good(&self) -> bool {
        !self.disabled && !self.auth_error && self.probe.as_ref().is_some_and(|p| p.ok && p.exit_ip.is_some())
    }

    /// True when the circuit breaker is currently open for this server at `now`.
    pub fn circuit_open(&self, now: u64) -> bool {
        self.cb_until > now
    }

    /// Trips the circuit breaker for an exponentially scaled pause (30 s .. 30 min).
    pub fn trip_circuit(&mut self, now: u64) {
        let shift = self.fails.saturating_sub(1).min(6);
        let pause = (30u64 << shift).min(1800);
        self.cb_until = now.saturating_add(pause);
    }

    /// Trust level of the server.
    pub fn trust_level(&self) -> TrustLevel {
        match self.origin {
            Origin::Mine => TrustLevel::UserOwned,
            Origin::Warp => TrustLevel::OfficialFree,
            Origin::Free => {
                if self.source.starts_with("official:") {
                    TrustLevel::OfficialFree
                } else {
                    TrustLevel::PublicCommunity
                }
            }
        }
    }

    /// Security warning for untrusted public community nodes.
    pub fn trust_warning(&self) -> Option<&'static str> {
        self.trust_level().warning()
    }

    /// Detailed state of the server according to the 11-state verification model.
    pub fn state(&self, now: u64) -> ServerState {
        if self.disabled {
            return ServerState::Disabled;
        }
        if self.auth_error {
            return ServerState::AuthRequired;
        }
        if self.circuit_open(now) {
            return ServerState::TempUnavailable;
        }
        let Some(p) = &self.probe else {
            return ServerState::ConfigValid;
        };
        if p.error.as_deref().is_some_and(is_auth_failure) {
            return ServerState::AuthRequired;
        }
        if !p.ok {
            return ServerState::TempUnavailable;
        }
        if p.exit_ip.is_none() {
            return ServerState::HandshakeOk;
        }
        if self.hist_n >= 4 && self.stability().is_some_and(|st| st < 50) {
            return ServerState::Unstable;
        }
        if self.relay.is_some() {
            return ServerState::ReachableRelay;
        }
        if p.exit_cc.is_some() {
            return ServerState::CountryVerified;
        }
        ServerState::InternetOk
    }

    pub fn latency(&self) -> Option<u32> {
        self.probe.as_ref().filter(|p| p.ok).and_then(|p| p.latency)
    }
    pub fn country(&self) -> Option<&str> {
        self.probe.as_ref().and_then(|p| p.exit_cc.as_deref())
    }

    /// Appends a check result to the stability history.
    pub fn record(&mut self, ok: bool) {
        self.hist = (self.hist << 1) | ok as u32;
        self.hist_n = (self.hist_n + 1).min(32);
    }

    /// Share of successful checks among the recorded ones, percent (needs ≥ 2 checks).
    pub fn stability(&self) -> Option<u8> {
        if self.hist_n < 2 {
            return None;
        }
        let mask = if self.hist_n >= 32 { u32::MAX } else { (1u32 << self.hist_n) - 1 };
        let ok = (self.hist & mask).count_ones();
        Some(((ok * 100 + self.hist_n as u32 / 2) / self.hist_n as u32) as u8)
    }

    /// Measured speed if it is recent enough to trust.
    pub fn fresh_speed(&self, now: u64, max_age: u64) -> Option<u32> {
        let p = self.probe.as_ref().filter(|p| p.ok)?;
        let sp = p.speed?;
        if p.speed_at == 0 || now.saturating_sub(p.speed_at) <= max_age { Some(sp) } else { None }
    }
}

/// Canonical JSON (sorted keys at every level) → sha256 → short id.
pub fn proxy_id(proxy: &Map<String, Value>) -> String {
    let mut s = String::new();
    canon(&Value::Object(proxy.clone()), &mut s);
    let h = Sha256::digest(s.as_bytes());
    let hex: String = h.iter().take(6).map(|b| format!("{b:02x}")).collect();
    format!("n{hex}")
}

fn canon(v: &Value, out: &mut String) {
    match v {
        Value::Object(m) => {
            let mut keys: Vec<&String> = m.keys().filter(|k| k.as_str() != "name").collect();
            keys.sort();
            out.push('{');
            for k in keys {
                out.push_str(&serde_json::to_string(k).unwrap_or_default());
                out.push(':');
                canon(&m[k], out);
                out.push(',');
            }
            out.push('}');
        }
        Value::Array(a) => {
            out.push('[');
            for x in a {
                canon(x, out);
                out.push(',');
            }
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

pub fn transport_label(proto: Proto, p: &Map<String, Value>) -> String {
    let s = |k: &str| p.get(k).and_then(|v| v.as_str()).unwrap_or("");
    let reality = p.contains_key("reality-opts");
    let tls = p.get("tls").and_then(|v| v.as_bool()).unwrap_or(false);
    let net = match s("network") {
        "ws" => {
            let up = p
                .get("ws-opts")
                .and_then(|o| o.get("v2ray-http-upgrade"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if up { "HTTPUpgrade" } else { "WS" }
        }
        "grpc" => "gRPC",
        "xhttp" => "XHTTP",
        "h2" => "H2",
        "h3" => "H3",
        "http" => "HTTP",
        "mkcp" => "mKCP",
        _ => "",
    };
    let mut parts: Vec<String> = Vec::new();
    match proto {
        Proto::Vless | Proto::Vmess | Proto::Trojan => {
            if reality {
                parts.push("Reality".into());
            } else if tls || proto == Proto::Trojan {
                parts.push("TLS".into());
            }
            if !net.is_empty() {
                parts.push(net.into());
            }
            if proto == Proto::Vless && s("flow").starts_with("xtls-rprx-vision") {
                parts.push("Vision".into());
            }
            if proto == Proto::Vless && !s("encryption").is_empty() && s("encryption") != "none" {
                parts.push("PQ".into());
            }
        }
        Proto::Ss => {
            if let Some(pl) = p.get("plugin").and_then(|v| v.as_str()) {
                parts.push(pl.to_string());
            }
            if s("cipher").starts_with("2022-") {
                parts.push("2022".into());
            }
        }
        Proto::Hysteria2 => {
            parts.push("QUIC".into());
            if p.contains_key("obfs") {
                parts.push("obfs".into());
            }
            if p.contains_key("ports") {
                parts.push("hopping".into());
            }
        }
        Proto::Tuic => parts.push("QUIC".into()),
        Proto::Anytls => parts.push("TLS".into()),
        Proto::Awg => {
            let o = p.get("amnezia-wg-option");
            let v3 = o.and_then(|o| o.get("version")).and_then(|v| v.as_u64()) == Some(3);
            let has_i = o.and_then(|o| o.get("i1")).is_some();
            let range = o
                .and_then(|o| o.get("h1"))
                .map(|v| v.as_str().is_some_and(|s| s.contains('-')))
                .unwrap_or(false);
            let s3 = o.and_then(|o| o.get("s3")).is_some();
            parts.push(
                if v3 {
                    "v3"
                } else if range || s3 {
                    "v2"
                } else if has_i {
                    "v1.5"
                } else {
                    "v1"
                }
                .into(),
            );
        }
        Proto::Wireguard => {}
        Proto::Openvpn => parts.push(s("proto").to_ascii_uppercase()),
        Proto::Masque => {
            if net == "h2" {
                parts.push("HTTP/2".into());
            } else {
                parts.push("QUIC·H3".into());
            }
        }
    }
    parts.join("·")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stability_history() {
        let p: Map<String, Value> = serde_json::from_str(r#"{"type":"ss","server":"a","port":1,"cipher":"aes-128-gcm","password":"x"}"#).unwrap();
        let mut s = Server::new("", p, Origin::Free, "t").unwrap();
        assert_eq!(s.stability(), None);
        s.record(true);
        assert_eq!(s.stability(), None);
        s.record(false);
        assert_eq!(s.stability(), Some(50));
        for _ in 0..40 {
            s.record(true);
        }
        assert_eq!(s.hist_n, 32);
        assert_eq!(s.stability(), Some(100));
        s.record(false);
        assert_eq!(s.stability(), Some(97));
        // old files without the new fields still load
        let j = serde_json::to_string(&s).unwrap();
        let back: Server = serde_json::from_str(&j).unwrap();
        assert_eq!(back.hist, s.hist);
        let mut v: Value = serde_json::from_str(&j).unwrap();
        v.as_object_mut().unwrap().remove("hist");
        v.as_object_mut().unwrap().remove("hist_n");
        let old: Server = serde_json::from_value(v).unwrap();
        assert_eq!(old.stability(), None);
        assert!(!old.fav);
    }

    #[test]
    fn server_states_and_trust() {
        let p: Map<String, Value> = serde_json::from_str(r#"{"type":"masque","server":"162.159.198.1","port":443,"network":"h2"}"#).unwrap();
        let mut s = Server::new("MASQUE test", p, Origin::Free, "public-list").unwrap();
        assert_eq!(s.proto, Proto::Masque);
        assert_eq!(s.transport, "HTTP/2");
        assert_eq!(s.trust_level(), TrustLevel::PublicCommunity);
        assert!(s.trust_warning().is_some());
        assert_eq!(s.state(100), ServerState::ConfigValid);

        // TCP/handshake without exit IP must NOT make server `good()`
        s.probe = Some(Probe { at: 100, ok: true, latency: Some(40), exit_ip: None, ..Default::default() });
        assert!(!s.good());
        assert_eq!(s.state(100), ServerState::HandshakeOk);

        // Verified exit IP and country
        s.probe = Some(Probe { at: 100, ok: true, latency: Some(40), exit_ip: Some("203.0.113.9".into()), exit_cc: Some("DE".into()), ..Default::default() });
        assert!(s.good());
        assert_eq!(s.state(100), ServerState::CountryVerified);

        // Relay server reports ReachableRelay even when exit_cc is present
        s.relay = Some("hop1".into());
        assert_eq!(s.state(100), ServerState::ReachableRelay);
        s.relay = None;

        // Circuit breaker open -> TempUnavailable
        s.fails = 3;
        s.trip_circuit(100);
        assert_eq!(s.state(110), ServerState::TempUnavailable);
        s.cb_until = 0;

        // Auth error state
        s.auth_error = true;
        assert!(!s.good());
        assert_eq!(s.state(100), ServerState::AuthRequired);
    }

    #[test]
    fn id_stable_and_order_independent() {
        let a: Map<String, Value> = serde_json::from_str(r#"{"type":"ss","server":"a","port":1,"cipher":"aes-128-gcm","password":"x"}"#).unwrap();
        let b: Map<String, Value> = serde_json::from_str(r#"{"password":"x","port":1,"cipher":"aes-128-gcm","server":"a","type":"ss","name":"zz"}"#).unwrap();
        assert_eq!(proxy_id(&a), proxy_id(&b));
        assert_eq!(proxy_id(&a).len(), 13);
    }
}
