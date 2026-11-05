//! Dev tool: how many links of a list survive parsing. `cargo run -p lazeyka-core --example parsecheck FILE...`
use lazeyka_core::{import, model::{Origin, Server}, scan};
use std::collections::BTreeMap;
fn main() {
    for f in std::env::args().skip(1) {
        let t = std::fs::read_to_string(&f).unwrap_or_default();
        let dec = if t.contains("://") { t.clone() } else { lazeyka_core::util::b64_decode_str(t.trim()).unwrap_or_default() };
        let mut links: BTreeMap<String, usize> = BTreeMap::new();
        for l in dec.split_whitespace() {
            if let Some(i) = l.find("://") { if i < 12 { *links.entry(l[..i].to_lowercase()).or_default() += 1; } }
        }
        let rep = import::parse_text(&t);
        let mut ok: BTreeMap<String, usize> = BTreeMap::new();
        let (mut bad, mut ins) = (0, 0);
        for it in rep.items {
            match Server::new(&it.name, it.proxy, Origin::Free, "x") {
                Ok(s) => { if scan::insecure(&s) { ins += 1 } *ok.entry(format!("{:?}", s.proto)).or_default() += 1 }
                Err(_) => bad += 1,
            }
        }
        println!("{f}\n  links {links:?}\n  parsed {ok:?} server-err {bad} insecure {ins} errors {}", rep.errors.len());
        let mut errs: BTreeMap<String, usize> = BTreeMap::new();
        for e in &rep.errors { *errs.entry(e.chars().take(70).collect()).or_default() += 1; }
        let mut v: Vec<_> = errs.into_iter().collect(); v.sort_by(|a, b| b.1.cmp(&a.1));
        for (e, n) in v.into_iter().take(5) { println!("    {n} × {e}"); }
    }
}
