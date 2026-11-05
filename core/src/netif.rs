//! Physical network interface detection (for binding the scanner while the TUN is up).

/// Name of the interface carrying the default route, ignoring our TUN.
pub fn physical(tun: &str) -> Option<String> {
    imp::physical(tun)
}

#[cfg(windows)]
mod imp {
    use windows::Win32::Foundation::WIN32_ERROR;
    use windows::Win32::NetworkManagement::IpHelper::{
        ConvertInterfaceLuidToAlias, FreeMibTable, GetIpForwardTable2, GetIpInterfaceEntry, MIB_IPFORWARD_TABLE2, MIB_IPINTERFACE_ROW,
    };
    use windows::Win32::Networking::WinSock::AF_INET;

    pub fn physical(tun: &str) -> Option<String> {
        unsafe {
            let mut table: *mut MIB_IPFORWARD_TABLE2 = std::ptr::null_mut();
            if GetIpForwardTable2(AF_INET, &mut table) != WIN32_ERROR(0) || table.is_null() {
                return None;
            }
            let t = &*table;
            let rows = std::slice::from_raw_parts(t.Table.as_ptr(), t.NumEntries as usize);
            let mut best: Option<(u32, String)> = None;
            for r in rows {
                if r.DestinationPrefix.PrefixLength != 0 {
                    continue;
                }
                let mut alias = [0u16; 257];
                if ConvertInterfaceLuidToAlias(&r.InterfaceLuid, &mut alias) != WIN32_ERROR(0) {
                    continue;
                }
                let len = alias.iter().position(|c| *c == 0).unwrap_or(alias.len());
                let name = String::from_utf16_lossy(&alias[..len]);
                if name.eq_ignore_ascii_case(tun) || name.is_empty() {
                    continue;
                }
                let mut row = MIB_IPINTERFACE_ROW { Family: AF_INET, InterfaceLuid: r.InterfaceLuid, ..Default::default() };
                let ifm = if GetIpInterfaceEntry(&mut row) == WIN32_ERROR(0) {
                    if row.Connected == false {
                        continue;
                    }
                    row.Metric
                } else {
                    0
                };
                let m = r.Metric.saturating_add(ifm);
                if best.as_ref().is_none_or(|(bm, _)| m < *bm) {
                    best = Some((m, name));
                }
            }
            FreeMibTable(table as *const _);
            best.map(|(_, n)| n)
        }
    }
}

#[cfg(not(windows))]
mod imp {
    pub fn physical(tun: &str) -> Option<String> {
        let t = std::fs::read_to_string("/proc/net/route").ok()?;
        let mut best: Option<(u32, String)> = None;
        for l in t.lines().skip(1) {
            let f: Vec<&str> = l.split_whitespace().collect();
            if f.len() < 8 || f[1] != "00000000" || f[7] != "00000000" || f[0] == tun {
                continue;
            }
            let m: u32 = f[6].parse().unwrap_or(0);
            if best.as_ref().is_none_or(|(bm, _)| m < *bm) {
                best = Some((m, f[0].to_string()));
            }
        }
        best.map(|(_, n)| n)
    }
}
