//! Updates: the program itself (GitHub Releases of the project) and the mihomo sidecar
//! (MetaCubeX/mihomo). Assets are checked against a mandatory SHA-256 hash, the zip
//! is unpacked with strict archive limits/deduplication, PE x64 headers are validated
//! before running `-v`, and the files are swapped with a rename.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const PROGRAM_REPO: &str = "qwkejkqwje1/Lazeyka";
pub const MIHOMO_REPO: &str = "MetaCubeX/mihomo";
/// Biggest download we accept.
pub const MAX_DOWNLOAD: u64 = 120 * 1024 * 1024;
/// Maximum total unpacked bytes across all entries in an update archive.
pub const MAX_EXTRACT_TOTAL: u64 = 200 * 1024 * 1024;
/// Maximum number of entries allowed in an update archive.
pub const MAX_ARCHIVE_ENTRIES: usize = 64;
/// Maximum number of extracted files allowed from an update archive.
pub const MAX_EXTRACT_FILES: usize = 12;

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Release {
    /// "0.5.0" (no leading v).
    pub version: String,
    pub url: String,
    pub size: u64,
    pub sha256: Option<String>,
    pub notes: String,
}

/// "v1.19.33", "0.4.0+sdk-1.4" → (1, 19, 33).
pub fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let s = s.trim().trim_start_matches(['v', 'V']);
    let core = s.split(['+', '-', ' ']).next()?;
    let mut it = core.split('.');
    let a = it.next()?.parse().ok()?;
    let b = it.next().unwrap_or("0").parse().ok()?;
    let c = it.next().unwrap_or("0").parse().ok()?;
    Some((a, b, c))
}

/// `latest` is a strictly newer version than `current` (unparsable → false).
pub fn newer(current: &str, latest: &str) -> bool {
    match (parse_version(current), parse_version(latest)) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

/// The program archive: `lazeyka-0.5.0-windows-x64.zip`.
pub fn is_program_asset(name: &str) -> bool {
    let n = name.to_lowercase();
    n.starts_with("lazeyka") && n.contains("windows") && n.ends_with(".zip")
}

/// The mihomo build the program ships: Windows, amd64, GOAMD64=v1 ("compatible").
pub fn is_mihomo_asset(name: &str) -> bool {
    name.starts_with("mihomo-windows-amd64-compatible-v") && name.ends_with(".zip")
}

/// Valid 64-char hex SHA-256 digest.
pub fn valid_sha256(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Extracts SHA-256 for `asset_name` from release body text when GitHub's `digest` field is absent.
fn sha256_from_body(body: &str, asset_name: &str) -> Option<String> {
    for line in body.lines() {
        if line.contains(asset_name) {
            for tok in line.split(|c: char| c.is_whitespace() || c == ':' || c == '`' || c == '*') {
                if valid_sha256(tok) {
                    return Some(tok.to_ascii_lowercase());
                }
            }
        }
    }
    None
}

/// Picks the release asset and its details from the GitHub API answer.
pub fn parse_release(v: &Value, pick: fn(&str) -> bool) -> Result<Release, String> {
    let tag = v.get("tag_name").and_then(Value::as_str).ok_or("в ответе нет версии")?;
    let a = v
        .get("assets")
        .and_then(Value::as_array)
        .and_then(|a| a.iter().find(|x| x.get("name").and_then(Value::as_str).is_some_and(pick)))
        .ok_or("в релизе нет подходящего файла")?;
    let asset_name = a.get("name").and_then(Value::as_str).unwrap_or("");
    let url = a.get("browser_download_url").and_then(Value::as_str).ok_or("нет ссылки")?;
    if !url.starts_with("https://") {
        return Err("небезопасная ссылка".into());
    }
    let body = v.get("body").and_then(Value::as_str).unwrap_or("");
    let sha256 = a
        .get("digest")
        .and_then(Value::as_str)
        .and_then(|d| d.strip_prefix("sha256:"))
        .map(|d| d.to_lowercase())
        .filter(|d| valid_sha256(d))
        .or_else(|| sha256_from_body(body, asset_name));
    Ok(Release {
        version: tag.trim_start_matches(['v', 'V']).to_string(),
        url: url.to_string(),
        size: a.get("size").and_then(Value::as_u64).unwrap_or(0),
        sha256,
        notes: body.chars().take(1500).collect(),
    })
}

fn client(long: bool) -> reqwest::Client {
    reqwest::Client::builder()
        .tls_backend_preconfigured(crate::probe::tls_config())
        .user_agent(concat!("Lazeyka/", env!("CARGO_PKG_VERSION")))
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(if long { 900 } else { 20 }))
        .no_proxy()
        .build()
        .expect("client")
}

/// Latest release of `repo` with the asset chosen by `pick`.
pub async fn latest(repo: &str, pick: fn(&str) -> bool) -> Result<Release, String> {
    let url = format!("https://api.github.com/repos/{repo}/releases/latest");
    let r = client(false).get(&url).header("Accept", "application/vnd.github+json").send().await.map_err(|e| crate::probe::short_err(&e))?;
    if !r.status().is_success() {
        return Err(format!("GitHub ответил {}", r.status().as_u16()));
    }
    let body = r.bytes().await.map_err(|e| crate::probe::short_err(&e))?;
    let v: Value = serde_json::from_slice(&body).map_err(|_| "непонятный ответ GitHub".to_string())?;
    parse_release(&v, pick)
}

/// Downloads the release asset to `dest` (written to `.part` first) and strictly verifies its SHA-256 hash.
pub async fn download(rel: &Release, dest: &Path) -> Result<(), String> {
    let want = rel
        .sha256
        .as_deref()
        .filter(|h| valid_sha256(h))
        .ok_or("в релизе отсутствует контрольная сумма SHA-256 — обновление отклонено")?;
    if rel.size > MAX_DOWNLOAD {
        return Err("файл слишком большой".into());
    }
    if let Some(d) = dest.parent() {
        std::fs::create_dir_all(d).map_err(|e| e.to_string())?;
    }
    let part = dest.with_extension("part");
    let mut r = client(true).get(&rel.url).send().await.map_err(|e| crate::probe::short_err(&e))?;
    if !r.status().is_success() {
        return Err(format!("загрузка: HTTP {}", r.status().as_u16()));
    }
    let mut f = std::fs::File::create(&part).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut total = 0u64;
    {
        use std::io::Write;
        while let Some(ch) = r.chunk().await.map_err(|e| crate::probe::short_err(&e))? {
            total += ch.len() as u64;
            if total > MAX_DOWNLOAD {
                let _ = std::fs::remove_file(&part);
                return Err("файл слишком большой".into());
            }
            hash.update(&ch);
            f.write_all(&ch).map_err(|e| e.to_string())?;
        }
    }
    drop(f);
    let got = hex(&hash.finalize());
    if got != want {
        let _ = std::fs::remove_file(&part);
        return Err("контрольная сумма SHA-256 не совпала — файл отброшен".into());
    }
    if rel.size > 0 && total != rel.size {
        let _ = std::fs::remove_file(&part);
        return Err("файл загружен не полностью".into());
    }
    let _ = std::fs::remove_file(dest);
    std::fs::rename(&part, dest).map_err(|e| e.to_string())
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub fn sha256_file(p: &Path) -> std::io::Result<String> {
    let mut f = std::fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(hex(&h.finalize()))
}

/// Validates that `p` is a Windows PE executable targeting x86_64 (`IMAGE_FILE_MACHINE_AMD64 = 0x8664`)
/// before any process execution is attempted.
pub fn verify_pe_amd64(p: &Path) -> Result<(), String> {
    let mut f = std::fs::File::open(p).map_err(|e| e.to_string())?;
    let mut buf = [0u8; 4096];
    let n = f.read(&mut buf).map_err(|e| e.to_string())?;
    if n < 64 || &buf[0..2] != b"MZ" {
        return Err("файл не является исполняемым PE (нет заголовка MZ)".into());
    }
    let pe_off = u32::from_le_bytes([buf[0x3c], buf[0x3d], buf[0x3e], buf[0x3f]]) as usize;
    if pe_off + 6 > n || &buf[pe_off..pe_off + 4] != b"PE\0\0" {
        return Err("повреждён PE-заголовок исполняемого файла".into());
    }
    let machine = u16::from_le_bytes([buf[pe_off + 4], buf[pe_off + 5]]);
    if machine != 0x8664 {
        return Err(format!("неподходящая архитектура исполняемого файла (0x{machine:04x}, ожидалась x86_64)"));
    }
    Ok(())
}

/// Unpacks the files of `zip` whose base name satisfies `want` into `out` (flat, no
/// subfolders, no path tricks, no duplicate filenames, bounded total size and file count).
pub fn extract(zip: &Path, out: &Path, want: &dyn Fn(&str) -> bool) -> Result<Vec<PathBuf>, String> {
    let f = std::fs::File::open(zip).map_err(|e| e.to_string())?;
    let mut ar = zip::ZipArchive::new(f).map_err(|e| format!("архив повреждён: {e}"))?;
    if ar.len() > MAX_ARCHIVE_ENTRIES {
        return Err("в архиве слишком много записей".into());
    }
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let mut done = Vec::new();
    let mut seen_names: HashSet<String> = HashSet::new();
    let mut total_bytes: u64 = 0;
    for i in 0..ar.len() {
        let mut e = ar.by_index(i).map_err(|e| e.to_string())?;
        if e.is_dir() {
            continue;
        }
        let raw_name = e.name().to_string();
        if raw_name.contains("..") {
            return Err("небезопасный путь в архиве".into());
        }
        let base = raw_name.rsplit(['/', '\\']).next().unwrap_or("").to_string();
        if base.is_empty() || base.starts_with('.') || !want(&base) {
            continue;
        }
        if !seen_names.insert(base.to_ascii_lowercase()) {
            let _ = std::fs::remove_dir_all(out);
            return Err(format!("в архиве повторяется файл {base}"));
        }
        if done.len() >= MAX_EXTRACT_FILES {
            let _ = std::fs::remove_dir_all(out);
            return Err("превышено допустимое число распаковываемых файлов".into());
        }
        if e.size() > MAX_DOWNLOAD * 2 || total_bytes.saturating_add(e.size()) > MAX_EXTRACT_TOTAL {
            let _ = std::fs::remove_dir_all(out);
            return Err("в архиве превышен допустимый объём распаковки".into());
        }
        let to = out.join(&base);
        let mut w = std::fs::File::create(&to).map_err(|e| e.to_string())?;
        let remaining = (MAX_EXTRACT_TOTAL - total_bytes) + 1;
        let written = std::io::copy(&mut e.by_ref().take(remaining), &mut w).map_err(|e| e.to_string())?;
        drop(w);
        total_bytes = total_bytes.saturating_add(written);
        if total_bytes > MAX_EXTRACT_TOTAL {
            let _ = std::fs::remove_dir_all(out);
            return Err("в архиве превышен допустимый объём распаковки".into());
        }
        done.push(to);
    }
    Ok(done)
}

/// Version printed by `mihomo -v` ("Mihomo Meta v1.19.33 windows amd64 …" → "1.19.33").
pub fn parse_mihomo_version(out: &str) -> Option<String> {
    out.split_whitespace().find(|w| w.starts_with('v') && parse_version(w).is_some()).map(|w| w.trim_start_matches('v').to_string())
}

/// Runs `bin -v`; None when it does not start or does not look like mihomo.
pub async fn mihomo_version(bin: &Path) -> Option<String> {
    let mut c = tokio::process::Command::new(bin);
    c.arg("-v").stdin(std::process::Stdio::null()).kill_on_drop(true);
    #[cfg(windows)]
    c.creation_flags(0x0800_0000);
    let out = tokio::time::timeout(Duration::from_secs(10), c.output()).await.ok()?.ok()?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    if !text.to_lowercase().contains("mihomo") {
        return None;
    }
    parse_mihomo_version(&text)
}

/// Swaps `new` into `target`, keeping the old file as `<target>.old`. The old binary may
/// be running: a rename works where overwriting does not.
pub fn swap_in(new: &Path, target: &Path) -> std::io::Result<()> {
    let old = target.with_extension(match target.extension().and_then(|e| e.to_str()) {
        Some(e) => format!("{e}.old"),
        None => "old".into(),
    });
    let _ = std::fs::remove_file(&old);
    if target.exists() {
        std::fs::rename(target, &old)?;
    }
    if let Err(e) = std::fs::rename(new, target) {
        let _ = std::fs::rename(&old, target);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn versions() {
        assert_eq!(parse_version("v1.19.33"), Some((1, 19, 33)));
        assert_eq!(parse_version("0.4.0+sdk-1.4.341.0"), Some((0, 4, 0)));
        assert_eq!(parse_version("0.5"), Some((0, 5, 0)));
        assert_eq!(parse_version("nightly"), None);
        assert!(newer("0.4.0", "v0.5.0"));
        assert!(newer("1.19.9", "1.19.33"));
        assert!(!newer("0.5.0", "0.5.0"));
        assert!(!newer("0.5.0", "0.4.9"));
        assert!(!newer("0.5.0", "alpha"));
    }

    #[test]
    fn release_parsing() {
        let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let v = json!({
            "tag_name": "v1.19.34",
            "body": "notes",
            "assets": [
                { "name": "mihomo-linux-amd64-v1.19.34.gz", "browser_download_url": "https://x/linux.gz", "size": 1 },
                { "name": "mihomo-windows-amd64-compatible-v1.19.34.zip", "browser_download_url": "https://x/win.zip", "size": 22, "digest": format!("sha256:{digest}") }
            ]
        });
        let r = parse_release(&v, is_mihomo_asset).unwrap();
        assert_eq!(r.version, "1.19.34");
        assert_eq!(r.url, "https://x/win.zip");
        assert_eq!(r.sha256.as_deref(), Some(digest));
        assert!(parse_release(&v, is_program_asset).is_err());
        let http = json!({ "tag_name": "v1", "assets": [{ "name": "lazeyka-1-windows-x64.zip", "browser_download_url": "http://x/a.zip" }] });
        assert!(parse_release(&http, is_program_asset).is_err());
        assert!(is_program_asset("lazeyka-0.5.0-windows-x64.zip"));
        assert!(!is_program_asset("lazeyka-0.5.0-src.zip"));
    }

    #[test]
    fn mihomo_version_text() {
        assert_eq!(parse_mihomo_version("Mihomo Meta v1.19.33 windows amd64 with go1.26 Wed\nUse tags: with_gvisor").as_deref(), Some("1.19.33"));
        assert_eq!(parse_mihomo_version("hello"), None);
    }

    #[test]
    fn swap_keeps_backup() {
        let d = std::env::temp_dir().join(format!("lz-swap-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let (t, n) = (d.join("mihomo.exe"), d.join("mihomo.exe.new"));
        std::fs::write(&t, b"old").unwrap();
        std::fs::write(&n, b"new").unwrap();
        swap_in(&n, &t).unwrap();
        assert_eq!(std::fs::read(&t).unwrap(), b"new");
        assert_eq!(std::fs::read(d.join("mihomo.exe.old")).unwrap(), b"old");
        assert!(!n.exists());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn zip_extract_rejects_traversal_and_duplicates() {
        use std::io::Write;
        let d = std::env::temp_dir().join(format!("lz-zip-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let z = d.join("a.zip");
        {
            let mut w = zip::ZipWriter::new(std::fs::File::create(&z).unwrap());
            let o = zip::write::SimpleFileOptions::default();
            w.start_file("Lazeyka/lazeyka.exe", o).unwrap();
            w.write_all(b"exe").unwrap();
            w.start_file("other.txt", o).unwrap();
            w.write_all(b"x").unwrap();
            w.finish().unwrap();
        }
        let out = d.join("out");
        let got = extract(&z, &out, &|n| n == "lazeyka.exe").unwrap();
        assert_eq!(got, vec![out.join("lazeyka.exe")]);

        // Duplicate file in archive must fail
        let z_dup = d.join("dup.zip");
        {
            let mut w = zip::ZipWriter::new(std::fs::File::create(&z_dup).unwrap());
            let o = zip::write::SimpleFileOptions::default();
            w.start_file("a/lazeyka.exe", o).unwrap();
            w.write_all(b"one").unwrap();
            w.start_file("b/lazeyka.exe", o).unwrap();
            w.write_all(b"two").unwrap();
            w.finish().unwrap();
        }
        let out_dup = d.join("out_dup");
        assert!(extract(&z_dup, &out_dup, &|n| n == "lazeyka.exe").is_err());

        // Path traversal in archive must fail
        let z_trav = d.join("trav.zip");
        {
            let mut w = zip::ZipWriter::new(std::fs::File::create(&z_trav).unwrap());
            let o = zip::write::SimpleFileOptions::default();
            w.start_file("../evil.exe", o).unwrap();
            w.write_all(b"x").unwrap();
            w.finish().unwrap();
        }
        let out_trav = d.join("out_trav");
        assert!(extract(&z_trav, &out_trav, &|_| true).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn pe_header_validation() {
        let d = std::env::temp_dir().join(format!("lz-pe-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let p = d.join("test.exe");
        let mut fake_pe = vec![0u8; 128];
        fake_pe[0] = b'M';
        fake_pe[1] = b'Z';
        fake_pe[0x3c] = 0x40;
        fake_pe[0x40..0x44].copy_from_slice(b"PE\0\0");
        fake_pe[0x44..0x46].copy_from_slice(&0x8664u16.to_le_bytes());
        std::fs::write(&p, &fake_pe).unwrap();
        assert!(verify_pe_amd64(&p).is_ok());

        // Wrong architecture (x86 0x014c)
        fake_pe[0x44..0x46].copy_from_slice(&0x014cu16.to_le_bytes());
        std::fs::write(&p, &fake_pe).unwrap();
        assert!(verify_pe_amd64(&p).is_err());
        let _ = std::fs::remove_dir_all(&d);
    }
}
