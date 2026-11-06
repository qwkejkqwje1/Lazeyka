//! Free VPN provider registry, authentication error classification, portable encrypted
//! credential storage (machine-scoped + password-protected portable export), and log redaction.

use crate::model::FreeTierLimits;
use crate::util::{b64_decode, b64_encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Authentication mechanism supported by a free provider.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum AuthKind {
    /// Automatic anonymous/device registration via official API (e.g. Cloudflare WARP).
    DeviceRegistration,
    /// OAuth / Device Authorization Flow or official token import.
    OAuthDeviceFlow,
    /// Official account with free-tier WireGuard / OpenVPN configuration import.
    AccountConfigImport,
    /// Public community source requiring no account.
    None,
}

/// Distinct classification of provider/authentication errors (Section 4):
/// prevents auth errors or free-tier quota limits from marking a server as dead.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ProviderErrorKind {
    AuthFailed,
    TokenExpired,
    FreeTierLimit,
    ConnectionLimit,
    ServerUnavailable,
    NetworkBlocked,
    ConfigError,
}

impl ProviderErrorKind {
    pub fn label(self) -> &'static str {
        match self {
            ProviderErrorKind::AuthFailed => "Ошибка авторизации (проверьте учётные данные)",
            ProviderErrorKind::TokenExpired => "Сессия или токен истекли (требуется обновление токена)",
            ProviderErrorKind::FreeTierLimit => "Достигнуто ограничение бесплатного тарифа",
            ProviderErrorKind::ConnectionLimit => "Превышен лимит одновременных подключений",
            ProviderErrorKind::ServerUnavailable => "Сервер временно недоступен",
            ProviderErrorKind::NetworkBlocked => "Сетевая блокировка маршрута к провайдеру",
            ProviderErrorKind::ConfigError => "Ошибка в параметрах конфигурации",
        }
    }

    /// True when the error is related to user auth/quota rather than server health.
    pub fn is_account_issue(self) -> bool {
        matches!(
            self,
            ProviderErrorKind::AuthFailed | ProviderErrorKind::TokenExpired | ProviderErrorKind::FreeTierLimit | ProviderErrorKind::ConnectionLimit
        )
    }
}

/// Classifies an error string into a [`ProviderErrorKind`].
pub fn classify_error(err: &str) -> ProviderErrorKind {
    let l = err.to_lowercase();
    if l.contains("expired") || l.contains("истёк") || l.contains("истек") {
        ProviderErrorKind::TokenExpired
    } else if l.contains("auth")
        || l.contains("авториз")
        || l.contains("пароль")
        || l.contains("логин")
        || l.contains("http 401")
        || l.contains("http 403")
        || l.contains("unauthorized")
    {
        ProviderErrorKind::AuthFailed
    } else if l.contains("quota")
        || l.contains("трафик")
        || l.contains("тариф")
        || l.contains("bandwidth")
        || l.contains("http 429")
    {
        ProviderErrorKind::FreeTierLimit
    } else if l.contains("too many connections")
        || l.contains("device limit")
        || l.contains("устройств")
        || l.contains("подключений")
    {
        ProviderErrorKind::ConnectionLimit
    } else if l.contains("некорректн") || l.contains("конфигурац") || l.contains("шаблон") {
        ProviderErrorKind::ConfigError
    } else if l.contains("сброшено")
        || l.contains("16 кб")
        || l.contains("сертификат")
        || l.contains("блокир")
    {
        ProviderErrorKind::NetworkBlocked
    } else {
        ProviderErrorKind::ServerUnavailable
    }
}

/// Metadata of a supported official free VPN provider in [`FreeProviderRegistry`].
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ProviderSpec {
    pub id: String,
    pub name: String,
    pub auth: AuthKind,
    pub countries: Vec<String>,
    pub protocols: Vec<String>,
    pub limits: FreeTierLimits,
}

/// Built-in registry of legitimate free VPN providers and their free-tier parameters.
pub fn free_provider_registry() -> Vec<ProviderSpec> {
    vec![
        ProviderSpec {
            id: "cloudflare-warp".into(),
            name: "Cloudflare WARP (Free)".into(),
            auth: AuthKind::DeviceRegistration,
            countries: vec!["AUTO".into()],
            protocols: vec!["WireGuard".into(), "AmneziaWG".into(), "MASQUE".into()],
            limits: FreeTierLimits {
                traffic_mb: 0,
                traffic_mb_month: None,
                speed_kbps: 0,
                max_devices: 1,
                note: "Безлимитный трафик · 1 устройство на ключ · автоматический выбор ближайшего узла Cloudflare".into(),
            },
        },
        ProviderSpec {
            id: "proton-free".into(),
            name: "Proton VPN (Free Tier)".into(),
            auth: AuthKind::AccountConfigImport,
            countries: vec!["NL".into(), "US".into(), "JP".into(), "RO".into(), "PL".into()],
            protocols: vec!["WireGuard".into(), "OpenVPN".into()],
            limits: FreeTierLimits {
                traffic_mb: 0,
                traffic_mb_month: None,
                speed_kbps: 0,
                max_devices: 1,
                note: "Безлимитный трафик · 1 устройство · 5 бесплатных стран (импорт официального .conf / .ovpn)".into(),
            },
        },
        ProviderSpec {
            id: "windscribe-free".into(),
            name: "Windscribe (Free Tier)".into(),
            auth: AuthKind::AccountConfigImport,
            countries: vec!["US".into(), "CA".into(), "GB".into(), "DE".into(), "NL".into(), "FR".into(), "CH".into(), "NO".into(), "RO".into(), "HK".into()],
            protocols: vec!["WireGuard".into(), "OpenVPN".into()],
            limits: FreeTierLimits {
                traffic_mb: 10 * 1024,
                traffic_mb_month: Some(10 * 1024),
                speed_kbps: 0,
                max_devices: 0,
                note: "До 10 ГБ/мес при подтверждённой почте · 10 бесплатных стран".into(),
            },
        },
    ]
}

// ------------------------------------------------------------------ Credential protection & portable export

const ENC_PREFIX: &str = "enc1:";

/// Protects a secret string for local storage in `scope` (`warp.json`, etc.) using an
/// authenticated stream envelope bound to the local machine and installation directory.
pub fn protect_secret(plain: &str, scope: &Path) -> String {
    if plain.is_empty() || plain.starts_with(ENC_PREFIX) {
        return plain.to_string();
    }
    encrypt_with_password(plain, &local_machine_key(scope))
}

/// Unprotects a secret string previously protected with [`protect_secret`].
/// Plaintext values from older config versions are returned as-is for seamless migration.
pub fn unprotect_secret(stored: &str, scope: &Path) -> Option<String> {
    if stored.is_empty() {
        return Some(String::new());
    }
    if stored.starts_with(ENC_PREFIX) {
        return decrypt_with_password(stored, &local_machine_key(scope))
            .or_else(|_| decrypt_with_password(stored, &legacy_machine_key()))
            .ok();
    }
    Some(stored.to_string())
}

fn legacy_machine_key() -> String {
    let user = std::env::var("USERNAME").or_else(|_| std::env::var("USER")).unwrap_or_else(|_| "lazeyka".into());
    let host = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "local".into());
    format!("lazeyka-local-key:{user}@{host}")
}

fn local_machine_key(scope: &Path) -> String {
    let host = std::env::var("COMPUTERNAME").or_else(|_| std::env::var("HOSTNAME")).unwrap_or_else(|_| "local".into());
    let file_name = scope.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).unwrap_or_default();
    format!("lazeyka-local-key-v2:{host}:{file_name}")
}

/// Encrypts `plain` with a user password for portable backup/export (`enc1:<salt+mac+ciphertext>`).
pub fn encrypt_with_password(plain: &str, password: &str) -> String {
    let salt = crate::util::random_token(12);
    let data = plain.as_bytes();
    let stream = keystream(password.as_bytes(), salt.as_bytes(), data.len());
    let cipher: Vec<u8> = data.iter().zip(stream.iter()).map(|(a, b)| a ^ b).collect();
    let mac = compute_mac(password.as_bytes(), salt.as_bytes(), &cipher);
    let mut payload = Vec::with_capacity(12 + 16 + cipher.len());
    payload.extend_from_slice(salt.as_bytes());
    payload.extend_from_slice(&mac);
    payload.extend_from_slice(&cipher);
    format!("{ENC_PREFIX}{}", b64_encode(&payload))
}

/// Decrypts a portable backup string created by [`encrypt_with_password`].
pub fn decrypt_with_password(encoded: &str, password: &str) -> Result<String, String> {
    let body = encoded.strip_prefix(ENC_PREFIX).ok_or("неизвестный формат шифрования")?;
    let raw = b64_decode(body).ok_or("повреждённые зашифрованные данные")?;
    if raw.len() < 28 {
        return Err("некорректная длина зашифрованного блока".into());
    }
    let salt = &raw[..12];
    let mac = &raw[12..28];
    let cipher = &raw[28..];
    let expected = compute_mac(password.as_bytes(), salt, cipher);
    if mac != expected {
        return Err("неверный пароль или повреждённые данные".into());
    }
    let stream = keystream(password.as_bytes(), salt, cipher.len());
    let plain: Vec<u8> = cipher.iter().zip(stream.iter()).map(|(a, b)| a ^ b).collect();
    String::from_utf8(plain).map_err(|_| "ошибка декодирования UTF-8 после расшифровки".into())
}

fn keystream(password: &[u8], salt: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut counter = 0u64;
    while out.len() < len {
        let mut h = Sha256::new();
        h.update(b"lazeyka-kdf-v1:");
        h.update(salt);
        h.update(b":");
        h.update(password);
        h.update(counter.to_le_bytes());
        let block = h.finalize();
        let take = (len - out.len()).min(block.len());
        out.extend_from_slice(&block[..take]);
        counter += 1;
    }
    out
}

fn compute_mac(password: &[u8], salt: &[u8], cipher: &[u8]) -> [u8; 16] {
    let mut h = Sha256::new();
    h.update(b"lazeyka-mac-v1:");
    h.update(salt);
    h.update(b":");
    h.update(password);
    h.update(b":");
    h.update(cipher);
    let digest = h.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest[..16]);
    out
}

/// Redacts sensitive tokens, private keys, UUIDs, and passwords from log strings before writing to disk.
pub fn redact_secrets(msg: &str) -> String {
    let mut out = msg.to_string();
    for marker in [
        "private-key",
        "private_key",
        "preshared-key",
        "pre-shared-key",
        "obfs-password",
        "password",
        "auth-str",
        "auth_str",
        "token",
        "secret",
        "uuid",
    ] {
        if out.to_ascii_lowercase().contains(marker) {
            out = redact_key_value_all(&out, marker);
        }
    }
    out
}

fn redact_key_value_all(s: &str, key: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while !rest.is_empty() {
        let lower = rest.to_ascii_lowercase();
        let Some(pos) = lower.find(key) else {
            out.push_str(rest);
            break;
        };
        let after = pos + key.len();
        out.push_str(&rest[..after]);
        let after_key = &rest[after..];
        let trimmed_sep = after_key.trim_start_matches([' ', '\t', '"', '\'']);
        let sep_offset = after_key.len() - trimmed_sep.len();
        if let Some(stripped_sep) = trimmed_sep.strip_prefix([':', '=']) {
            out.push_str(&after_key[..sep_offset + 1]);
            let val_trimmed = stripped_sep.trim_start_matches([' ', '\t']);
            let ws_len = stripped_sep.len() - val_trimmed.len();
            out.push_str(&stripped_sep[..ws_len]);
            if let Some(in_quote) = val_trimmed.strip_prefix('"') {
                if let Some(end_q) = in_quote.find('"') {
                    out.push_str("\"[REDACTED]\"");
                    rest = &in_quote[end_q + 1..];
                    continue;
                }
            } else if let Some(in_sq) = val_trimmed.strip_prefix('\'') {
                if let Some(end_q) = in_sq.find('\'') {
                    out.push_str("'[REDACTED]'");
                    rest = &in_sq[end_q + 1..];
                    continue;
                }
            } else {
                let end = val_trimmed.find([',', ' ', '\n', '\r', '}', ')']).unwrap_or(val_trimmed.len());
                out.push_str("[REDACTED]");
                rest = &val_trimmed[end..];
                continue;
            }
        }
        rest = after_key;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_encryption_roundtrip_and_wrong_password() {
        let secret = "private-wg-key-1234567890";
        let enc = encrypt_with_password(secret, "my-portable-pass");
        assert!(enc.starts_with(ENC_PREFIX));
        assert!(!enc.contains(secret));
        let dec = decrypt_with_password(&enc, "my-portable-pass").unwrap();
        assert_eq!(dec, secret);
        assert!(decrypt_with_password(&enc, "wrong-pass").is_err());
    }

    #[test]
    fn local_secret_protection() {
        let scope = Path::new("/tmp/lazeyka/warp.json");
        let tok = "warp-secret-token-xyz";
        let p = protect_secret(tok, scope);
        assert_ne!(p, tok);
        assert_eq!(unprotect_secret(&p, scope).as_deref(), Some(tok));
        // Legacy plaintext transparently loads
        assert_eq!(unprotect_secret("legacy-plain", scope).as_deref(), Some("legacy-plain"));
    }

    #[test]
    fn error_classification_distinguishes_auth_from_dead() {
        assert_eq!(classify_error("HTTP 401 Unauthorized"), ProviderErrorKind::AuthFailed);
        assert_eq!(classify_error("token expired"), ProviderErrorKind::TokenExpired);
        assert_eq!(classify_error("HTTP 429 quota exceeded"), ProviderErrorKind::FreeTierLimit);
        assert!(classify_error("HTTP 401 Unauthorized").is_account_issue());
        assert!(!classify_error("порт закрыт (TCP)").is_account_issue());
    }

    #[test]
    fn log_redaction_hides_multiple_secrets_and_uuids() {
        let line = r#"config error: {"private-key": "superSecretKey123", "password": "pw2", "uuid": "11112222-3333-4444-5555-666677778888", "server": "1.2.3.4"}"#;
        let clean = redact_secrets(line);
        assert!(!clean.contains("superSecretKey123"));
        assert!(!clean.contains("pw2"));
        assert!(!clean.contains("11112222-3333-4444-5555-666677778888"));
        assert!(clean.contains("1.2.3.4"));
        assert!(clean.contains("[REDACTED]"));
    }
}
