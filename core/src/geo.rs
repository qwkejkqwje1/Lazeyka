//! Offline IP → country lookup using DB-IP "IP to Country Lite" (CC BY 4.0).
//! The database is memory-mapped, so it costs almost no RAM.

use std::net::IpAddr;
use std::path::Path;

pub struct Geo {
    reader: maxminddb::Reader<memmap2::Mmap>,
}

impl Geo {
    pub fn open(path: &Path) -> Result<Geo, String> {
        // SAFETY: the file is owned by the app and is replaced only via rename (never truncated in place).
        let reader = unsafe { maxminddb::Reader::open_mmap(path) }.map_err(|e| format!("база стран: {e}"))?;
        Ok(Geo { reader })
    }

    pub fn country(&self, ip: IpAddr) -> Option<String> {
        let r = self.reader.lookup(ip).ok()?;
        let cc: Option<String> = r.decode_path(&maxminddb::path!["country", "iso_code"]).ok()?;
        cc.filter(|c| c.len() == 2).map(|c| c.to_ascii_uppercase())
    }

    pub fn build_date(&self) -> u64 {
        self.reader.metadata().build_epoch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lookup() {
        let p = std::path::Path::new("/data/vpn/dl/dbip-country-lite-2026-11.mmdb");
        if !p.exists() {
            return;
        }
        let g = Geo::open(p).unwrap();
        assert_eq!(g.country("77.88.8.8".parse().unwrap()).as_deref(), Some("RU"));
        assert_eq!(g.country("8.8.8.8".parse().unwrap()).as_deref(), Some("US"));
        assert_eq!(g.country("127.0.0.1".parse().unwrap()), None);
    }
}
