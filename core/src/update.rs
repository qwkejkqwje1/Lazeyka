//! Updates: the program itself (GitHub Releases of the project) and the mihomo sidecar
//! (MetaCubeX/mihomo). Assets are checked against the SHA-256 GitHub publishes, the zip
//! is unpacked here and the files are swapped with a rename, which Windows allows for
//! a running executable.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const PROGRAM_REPO: &str = "qwkejkqwje1/Lazeyka";
pub const MIHOMO_REPO: &str = "MetaCubeX/mihomo";
/// Biggest download we accept.
const MAX_DOWNLOAD: u64 = 120 * 1024 * 1024;

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

/// Picks the release asset and its details from the GitHub API answer.
pub fn parse_release(v: &Value, pick: fn(&str) -> bool) -> Result<Release, String> {
    let tag = v.get("tag_name").and_then(Value::as_str).ok_or("в ответе нет версии")?;
    let a = v
        .get("assets")
        .and_then(Value::as_array)
        .and_then(|a| a.iter().find(|x| x.get("name").and_then(Value::as_str).is_some_and(pick)))
        .ok_or("в релизе нет подходящего файла")?;
    let url = a.get("browser_download_url").and_then(Value::as_str).ok_or("нет ссылки")?;
    if !url.starts_with("https://") {
        return Err("небезопасная ссылка".into());
    }
    Ok(Release {
        version: tag.trim_start_matches(['v', 'V']).to_string(),
        url: url.to_string(),
        size: a.get("size").and_then(Value::as_u64).unwrap_or(0),
        sha256: a.get("digest").and_then(Value::as_str).and_then(|d| d.strip_prefix("sha256:")).map(|d| d.to_lowercase()),
        notes: v.get("body").and_then(Value::as_str).unwrap_or("").chars().take(1500).collect(),
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

/// Downloads the release asset to `dest` (written to `.part` first) and checks its hash.
pub async fn download(rel: &Release, dest: &Path) -> Result<(), String> {
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
    if let Some(want) = &rel.sha256 {
        if &got != want {
            let _ = std::fs::remove_file(&part);
            return Err("контрольная сумма не совпала — файл отброшен".into());
        }
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

/// Unpacks the files of `zip` whose base name satisfies `want` into `out` (flat, no
/// subfolders, no path tricks). Returns the written paths.
pub fn extract(zip: &Path, out: &Path, want: &dyn Fn(&str) -> bool) -> Result<Vec<PathBuf>, String> {
    let f = std::fs::File::open(zip).map_err(|e| e.to_string())?;
    let mut ar = zip::ZipArchive::new(f).map_err(|e| format!("архив повреждён: {e}"))?;
    std::fs::create_dir_all(out).map_err(|e| e.to_string())?;
    let mut done = Vec::new();
    for i in 0..ar.len() {
        let mut e = ar.by_index(i).map_err(|e| e.to_string())?;
        if e.is_dir() {
            continue;
        }
        let base = e.name().rsplit(['/', '\\']).next().unwrap_or("").to_string();
        if base.is_empty() || base.starts_with('.') || !want(&base) {
            continue;
        }
        if e.size() > MAX_DOWNLOAD * 2 {
            return Err("в архиве слишком большой файл".into());
        }
        let to = out.join(&base);
        let mut w = std::fs::File::create(&to).map_err(|e| e.to_string())?;
        std::io::copy(&mut e.by_ref().take(MAX_DOWNLOAD * 2), &mut w).map_err(|e| e.to_string())?;
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
        let v = json!({
            "tag_name": "v1.19.34",
            "body": "notes",
            "assets": [
                { "name": "mihomo-linux-amd64-v1.19.34.gz", "browser_download_url": "https://x/linux.gz", "size": 1 },
                { "name": "mihomo-windows-amd64-compatible-v1.19.34.zip", "browser_download_url": "https://x/win.zip", "size": 22, "digest": "sha256:ABCDEF" }
            ]
        });
        let r = parse_release(&v, is_mihomo_asset).unwrap();
        assert_eq!(r.version, "1.19.34");
        assert_eq!(r.url, "https://x/win.zip");
        assert_eq!(r.sha256.as_deref(), Some("abcdef"));
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
    fn zip_extract_is_flat() {
        use std::io::Write;
        let d = std::env::temp_dir().join(format!("lz-zip-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let z = d.join("a.zip");
        {
            let mut w = zip::ZipWriter::new(std::fs::File::create(&z).unwrap());
            let o = zip::write::SimpleFileOptions::default();
            w.start_file("Lazeyka/lazeyka.exe", o).unwrap();
            w.write_all(b"exe").unwrap();
            w.start_file("../evil.txt", o).unwrap();
            w.write_all(b"x").unwrap();
            w.finish().unwrap();
        }
        let out = d.join("out");
        let got = extract(&z, &out, &|n| n == "lazeyka.exe").unwrap();
        assert_eq!(got, vec![out.join("lazeyka.exe")]);
        assert!(!d.join("evil.txt").exists());
        let _ = std::fs::remove_dir_all(&d);
    }
}
