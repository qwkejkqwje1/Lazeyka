//! Built-in Cloudflare WARP: device registration (wgcf-style) and server variants
//! (plain WireGuard and AmneziaWG with junk packets / QUIC-like I1), tested by the scanner.

use crate::links::{WgFields, wg_proxy};
use crate::model::{Origin, Server};
use crate::util::{b64_decode, b64_encode};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::time::Duration;

pub const PEER_KEY: &str = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Account {
    pub id: String,
    pub token: String,
    pub private_key: String,
    pub v4: String,
    pub v6: String,
    /// 3 bytes from client_id (WireGuard "reserved").
    pub reserved: Vec<u8>,
    pub peer_key: String,
    pub registered: u64,
}

pub fn keypair() -> (String, String) {
    use rand::RngCore;
    let mut sk = [0u8; 32];
    rand::rng().fill_bytes(&mut sk);
    let secret = x25519_dalek::StaticSecret::from(sk);
    let public = x25519_dalek::PublicKey::from(&secret);
    (b64_encode(secret.as_bytes()), b64_encode(public.as_bytes()))
}

fn tos() -> String {
    // RFC 3339 UTC without external crates
    let s = crate::util::now();
    let days = s / 86400;
    let rem = s % 86400;
    let (y, m, d) = civil(days as i64);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000Z", rem / 3600, (rem % 3600) / 60, rem % 60)
}

fn civil(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Registers a new WARP device. `client` decides the route (direct or through a proxy).
pub async fn register(client: &reqwest::Client) -> Result<Account, String> {
    let (sk, pk) = keypair();
    let body = json!({
        "key": pk,
        "install_id": "",
        "fcm_token": "",
        "tos": tos(),
        "model": "PC",
        "serial_number": "",
        "locale": "en_US",
        "type": "Android"
    });
    let mut last = String::new();
    for (ver, cv) in [("v0a2158", "a-6.10-2158"), ("v0a1922", "a-6.3-1922")] {
        let r = client
            .post(format!("https://api.cloudflareclient.com/{ver}/reg"))
            .header("User-Agent", "okhttp/3.12.1")
            .header("CF-Client-Version", cv)
            .header("Content-Type", "application/json; charset=UTF-8")
            .timeout(Duration::from_secs(20))
            .body(body.to_string())
            .send()
            .await;
        let r = match r {
            Ok(r) => r,
            Err(e) => {
                last = crate::probe::short_err(&e);
                continue;
            }
        };
        let st = r.status();
        let text = r.text().await.unwrap_or_default();
        if !st.is_success() {
            last = format!("HTTP {}", st.as_u16());
            continue;
        }
        let v: Value = serde_json::from_str(&text).map_err(|_| "WARP: некорректный ответ".to_string())?;
        let cfg = &v["config"];
        let reserved = cfg["client_id"].as_str().and_then(b64_decode).unwrap_or_default();
        let acc = Account {
            id: v["id"].as_str().unwrap_or("").to_string(),
            token: v["token"].as_str().unwrap_or("").to_string(),
            private_key: sk.clone(),
            v4: cfg["interface"]["addresses"]["v4"].as_str().unwrap_or("172.16.0.2").to_string(),
            v6: cfg["interface"]["addresses"]["v6"].as_str().unwrap_or("").to_string(),
            reserved: if reserved.len() == 3 { reserved } else { vec![0, 0, 0] },
            peer_key: cfg["peers"][0]["public_key"].as_str().unwrap_or(PEER_KEY).to_string(),
            registered: crate::util::now(),
        };
        if acc.id.is_empty() {
            return Err("WARP: регистрация не удалась".into());
        }
        return Ok(acc);
    }
    Err(format!("WARP: сервер регистрации недоступен ({last})"))
}

/// Endpoints (anycast IPs × ports known to be served by WARP).
pub const ENDPOINTS: &[(&str, u16)] = &[
    ("162.159.192.1", 2408),
    ("162.159.193.10", 4500),
    ("162.159.195.1", 1701),
    ("188.114.98.10", 500),
    ("188.114.99.10", 854),
];

/// QUIC-Initial-like first packet for AmneziaWG 1.5 (I1): long header, version 1,
/// random 8-byte DCID, then random "encrypted" payload.
pub const I1_QUIC: &str = "<b 0xc30000000108><r 8><b 0x000044d0><r 616><r 616>";

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Variant {
    Plain,
    Junk,
    Quic,
}

pub fn variant_name(v: Variant) -> &'static str {
    match v {
        Variant::Plain => "WireGuard",
        Variant::Junk => "AmneziaWG",
        Variant::Quic => "AmneziaWG·QUIC",
    }
}

pub fn server(acc: &Account, ep: (&str, u16), v: Variant) -> Result<Server, String> {
    let mut awg = Map::new();
    if v != Variant::Plain {
        awg.insert("jc".into(), 4.into());
        awg.insert("jmin".into(), 40.into());
        awg.insert("jmax".into(), 70.into());
        for (i, k) in ["h1", "h2", "h3", "h4"].iter().enumerate() {
            awg.insert((*k).into(), (i as u64 + 1).into());
        }
        if v == Variant::Quic {
            awg.insert("i1".into(), I1_QUIC.into());
        }
    }
    let mut addrs = vec![format!("{}/32", acc.v4)];
    if !acc.v6.is_empty() {
        addrs.push(format!("{}/128", acc.v6));
    }
    let f = WgFields {
        server: ep.0.to_string(),
        port: ep.1,
        private_key: acc.private_key.clone(),
        public_key: acc.peer_key.clone(),
        psk: None,
        addrs,
        mtu: Some(1280),
        reserved: Some(json!(acc.reserved)),
        keepalive: Some(25),
        awg,
    };
    let proxy = wg_proxy(&f)?;
    let name = format!("Cloudflare WARP · {} · {}:{}", variant_name(v), ep.0, ep.1);
    Server::new(&name, proxy, Origin::Warp, "warp")
}

/// All WARP variants for the scanner.
pub fn servers(acc: &Account) -> Vec<Server> {
    let mut out = Vec::new();
    for ep in ENDPOINTS {
        for v in [Variant::Junk, Variant::Quic, Variant::Plain] {
            if let Ok(s) = server(acc, *ep, v) {
                out.push(s);
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn time_and_keys() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(20_000), (2024, 10, 4));
        let (sk, pk) = keypair();
        assert_eq!(b64_decode(&sk).unwrap().len(), 32);
        assert_eq!(b64_decode(&pk).unwrap().len(), 32);
        let acc = Account {
            id: "x".into(),
            token: "t".into(),
            private_key: sk,
            v4: "172.16.0.2".into(),
            v6: "2606:4700:110:8a36::1".into(),
            reserved: vec![1, 2, 3],
            peer_key: PEER_KEY.into(),
            registered: 0,
        };
        let s = servers(&acc);
        assert_eq!(s.len(), ENDPOINTS.len() * 3);
        assert_eq!(s[0].proto, crate::model::Proto::Awg);
        assert_eq!(s[2].proto, crate::model::Proto::Wireguard);
    }
}
