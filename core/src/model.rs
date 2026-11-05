//! Core data model: servers, probe results.

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
            _ => return None,
        })
    }
    /// Transport runs over UDP (TCP pre-checks are meaningless).
    pub fn udp_based(self) -> bool {
        matches!(self, Proto::Hysteria2 | Proto::Tuic | Proto::Wireguard | Proto::Awg)
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
    /// ISO country of the exit IP (DB-IP Lite).
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
    /// Source id (catalog source, subscription id, "manual").
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
    /// here is blocked, the entry hop gets the connection out. TCP-based protocols only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    /// Last attempt to test the server through an entry hop (unix seconds).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub relay_at: u64,
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

    pub fn good(&self) -> bool {
        self.probe.as_ref().is_some_and(|p| p.ok)
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
    fn id_stable_and_order_independent() {
        let a: Map<String, Value> = serde_json::from_str(r#"{"type":"ss","server":"a","port":1,"cipher":"aes-128-gcm","password":"x"}"#).unwrap();
        let b: Map<String, Value> = serde_json::from_str(r#"{"password":"x","port":1,"cipher":"aes-128-gcm","server":"a","type":"ss","name":"zz"}"#).unwrap();
        assert_eq!(proxy_id(&a), proxy_id(&b));
        assert_eq!(proxy_id(&a).len(), 13);
    }
}
