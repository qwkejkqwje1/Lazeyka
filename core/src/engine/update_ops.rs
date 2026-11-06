//! Updates inside the engine: the check, the automatic mihomo update and the download of
//! a new program package (the UI starts its installer; the engine never replaces itself).

use super::*;
use crate::update;
use std::path::PathBuf;

/// What the last check found.
#[derive(Default, Clone)]
pub(super) struct UpdateState {
    pub checked: u64,
    pub program: Option<update::Release>,
    pub mihomo: Option<update::Release>,
    pub mihomo_installed: String,
    pub error: Option<String>,
    pub busy: bool,
    /// Program version the user was already told about.
    pub announced: String,
}

/// Files of a program package.
fn is_package_file(n: &str) -> bool {
    matches!(n, "lazeyka.exe" | "mihomo.exe" | "dbip-country-lite.mmdb" | "LICENSE.txt" | "THIRD-PARTY.txt" | "README.txt")
}

impl Engine {
    fn update_json(&self) -> Value {
        let u = self.st.lock().unwrap().update.clone();
        let auto = self.st.lock().unwrap().settings.auto_update;
        json!({
            "current": self.version,
            "program": u.program.as_ref().map(|r| json!({ "version": r.version, "size": r.size, "notes": r.notes })),
            "mihomo_installed": u.mihomo_installed,
            "mihomo": u.mihomo.as_ref().map(|r| json!({ "version": r.version, "size": r.size })),
            "checked": u.checked,
            "error": u.error,
            "busy": u.busy,
            "auto": auto,
        })
    }

    fn mihomo_overridden(&self) -> bool {
        std::env::var_os("LAZEYKA_MIHOMO").is_some()
    }

    /// Asks GitHub for the newest program and mihomo.
    pub(super) async fn update_check(self: &Arc<Self>) -> Result<Value, String> {
        let installed = update::mihomo_version(&self.paths.mihomo()).await.unwrap_or_else(|| {
            let c = self.core_version.lock().unwrap().clone();
            update::parse_mihomo_version(&c).unwrap_or_default()
        });
        let prog = update::latest(update::PROGRAM_REPO, update::is_program_asset).await;
        let mih = if self.mihomo_overridden() { Err("mihomo задан вручную".to_string()) } else { update::latest(update::MIHOMO_REPO, update::is_mihomo_asset).await };
        let err = match (&prog, &mih) {
            (Err(a), Err(_)) => Some(a.clone()),
            _ => None,
        };
        let announce = {
            let mut st = self.st.lock().unwrap();
            st.update.checked = util::now();
            st.update.mihomo_installed = installed.clone();
            st.update.error = err.clone();
            if let Ok(r) = prog {
                st.update.program = update::newer(&self.version, &r.version).then_some(r);
            }
            if let Ok(r) = mih {
                st.update.mihomo = (!installed.is_empty() && update::newer(&installed, &r.version)).then_some(r);
            }
            let ver = st.update.program.as_ref().map(|r| r.version.clone());
            match ver {
                Some(v) if st.update.announced != v => {
                    st.update.announced = v.clone();
                    Some(v)
                }
                _ => None,
            }
        };
        if let Some(v) = announce {
            self.notice(&format!("Доступна новая версия Лазейки: {v}. Обновить можно на вкладке «Настройки»"));
        }
        match err {
            Some(e) => Err(format!("не удалось проверить обновления: {e}")),
            None => Ok(self.update_json()),
        }
    }

    /// Downloads and installs the newest mihomo next to the old one (kept as `.old`).
    /// Takes effect at the next connection.
    pub(super) async fn update_mihomo(self: &Arc<Self>) -> Result<Value, String> {
        if self.mihomo_overridden() {
            return Err("mihomo задан вручную (LAZEYKA_MIHOMO)".into());
        }
        if self.scanning.load(Ordering::Relaxed) {
            return Err("идёт поиск серверов — повторите позже".into());
        }
        let rel = self.st.lock().unwrap().update.mihomo.clone().ok_or("новой версии mihomo нет")?;
        if std::mem::replace(&mut self.st.lock().unwrap().update.busy, true) {
            return Err("обновление уже идёт".into());
        }
        let res = self.update_mihomo_inner(&rel).await;
        {
            let mut st = self.st.lock().unwrap();
            st.update.busy = false;
            if res.is_ok() {
                st.update.mihomo = None;
                st.update.mihomo_installed = rel.version.clone();
            }
        }
        match res {
            Ok(()) => {
                let tail = if self.connected() { " Применится при следующем подключении" } else { "" };
                self.notice(&format!("mihomo обновлён до {}.{tail}", rel.version));
                Ok(self.update_json())
            }
            Err(e) => {
                self.log(&format!("обновление mihomo не удалось: {e}"));
                Err(e)
            }
        }
    }

    async fn update_mihomo_inner(&self, rel: &update::Release) -> Result<(), String> {
        if rel.sha256.as_deref().is_none_or(|h| !update::valid_sha256(h)) {
            return Err("обновление mihomo отклонено: отсутствует контрольная сумма SHA-256".into());
        }
        let dir = self.paths.data.join("update");
        let _ = std::fs::remove_dir_all(&dir);
        let zip = dir.join("mihomo.zip");
        update::download(rel, &zip).await?;
        let files = update::extract(&zip, &dir, &|n| {
            let l = n.to_ascii_lowercase();
            (l == "mihomo.exe" || l.starts_with("mihomo-windows-amd64")) && l.ends_with(".exe")
        })?;
        let _ = std::fs::remove_file(&zip);
        if files.len() != 1 {
            let _ = std::fs::remove_dir_all(&dir);
            return Err("в архиве mihomo должен быть ровно один исполняемый файл".into());
        }
        let exe = files.into_iter().next().ok_or("в архиве нет mihomo")?;
        // Verify PE x86_64 header before staging or executing
        if let Err(e) = update::verify_pe_amd64(&exe) {
            let _ = std::fs::remove_dir_all(&dir);
            return Err(e);
        }
        let target = self.paths.mihomo();
        let staged = target.with_extension("exe.new");
        let _ = std::fs::remove_file(&staged);
        std::fs::rename(&exe, &staged).or_else(|_| std::fs::copy(&exe, &staged).map(|_| ())).map_err(|e| format!("не удалось положить файл: {e}"))?;
        // the new binary must run and be the version we asked for before it replaces the old one
        match update::mihomo_version(&staged).await {
            Some(v) if v == rel.version => {}
            Some(v) => {
                let _ = std::fs::remove_file(&staged);
                let _ = std::fs::remove_dir_all(&dir);
                return Err(format!("в архиве версия {v}, а не {}", rel.version));
            }
            None => {
                let _ = std::fs::remove_file(&staged);
                let _ = std::fs::remove_dir_all(&dir);
                return Err("новый mihomo не запускается — прежний оставлен".into());
            }
        }
        update::swap_in(&staged, &target).map_err(|e| format!("не удалось заменить mihomo: {e}"))?;
        let _ = std::fs::remove_dir_all(&dir);
        Ok(())
    }

    /// Where the program package is unpacked: `<home>\update` next to lazeyka.exe — readable
    /// by the user who starts the installer (the data folder is closed to everyone but the
    /// service) and inside the program's own folder, so nothing is left elsewhere.
    fn package_dir(&self) -> PathBuf {
        if cfg!(windows) {
            self.paths.bin.join("update")
        } else {
            self.paths.data.join("update-pkg")
        }
    }

    /// Removes the unpacked package of an earlier update (and the 0.6.0 location).
    fn clean_package(&self) {
        let _ = std::fs::remove_dir_all(self.package_dir());
        if cfg!(windows) {
            if let Some(pd) = std::env::var_os("ProgramData") {
                let _ = std::fs::remove_dir_all(PathBuf::from(pd).join("Lazeyka-update"));
            }
        }
    }

    /// Downloads the newest program package and unpacks it. Returns the path and the
    /// SHA-256 of its `lazeyka.exe`: the UI checks it right before starting the installer.
    pub(super) async fn update_program(self: &Arc<Self>) -> Result<Value, String> {
        let rel = self.st.lock().unwrap().update.program.clone().ok_or("новой версии нет")?;
        if rel.sha256.as_deref().is_none_or(|h| !update::valid_sha256(h)) {
            return Err("обновление отклонено: в релизе отсутствует контрольная сумма SHA-256".into());
        }
        if std::mem::replace(&mut self.st.lock().unwrap().update.busy, true) {
            return Err("обновление уже идёт".into());
        }
        let res: Result<(PathBuf, String), String> = async {
            let dir = self.package_dir();
            let _ = std::fs::remove_dir_all(&dir);
            let zip = dir.join("package.zip");
            update::download(&rel, &zip).await?;
            let files = update::extract(&zip, &dir, &is_package_file)?;
            let _ = std::fs::remove_file(&zip);
            let exe = files.into_iter().find(|p| p.file_name().is_some_and(|n| n == "lazeyka.exe")).ok_or("в архиве нет lazeyka.exe")?;
            update::verify_pe_amd64(&exe)?;
            let sum = update::sha256_file(&exe).map_err(|e| e.to_string())?;
            Ok((exe, sum))
        }
        .await;
        self.st.lock().unwrap().update.busy = false;
        match res {
            Ok((exe, sum)) => Ok(json!({ "version": rel.version, "exe": exe.to_string_lossy(), "sha256": sum })),
            Err(e) => {
                self.log(&format!("загрузка обновления не удалась: {e}"));
                Err(e)
            }
        }
    }

    /// Background loop: a check every 12 hours (2 after a failure); mihomo is installed
    /// by itself when nothing else is running. The program is only announced.
    pub(super) async fn update_loop(self: Arc<Self>) {
        tokio::time::sleep(Duration::from_secs(120)).await;
        if !self.st.lock().unwrap().update.busy {
            self.clean_package();
        }
        loop {
            let (auto, checked, failed) = {
                let st = self.st.lock().unwrap();
                (st.settings.auto_update, st.update.checked, st.update.error.is_some())
            };
            let wait = if failed { 2 * 3600 } else { 12 * 3600 };
            if auto && util::now().saturating_sub(checked) >= wait {
                if let Err(e) = self.update_check().await {
                    self.log(&e);
                }
            }
            let has_mihomo = self.st.lock().unwrap().update.mihomo.is_some();
            if auto && has_mihomo && !self.scanning.load(Ordering::Relaxed) {
                let _ = self.update_mihomo().await;
            }
            tokio::time::sleep(Duration::from_secs(900)).await;
        }
    }
}
