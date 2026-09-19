//! Where the server keeps its state: the SQLite database and the pepper key.
//! Both are created readable by the owner only; the directory likewise.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::accounts::{self, Auth};
use crate::store::Store;

pub fn resolve(arg: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = arg.or_else(|| std::env::var_os("QIUI_DATA_DIR").map(PathBuf::from)) {
        return Ok(p);
    }
    let home = std::env::var_os("HOME").context("HOME is not set; pass --data-dir")?;
    Ok(PathBuf::from(home).join(".local/share/qiui-server"))
}

fn private_dir(dir: &Path) -> Result<()> {
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub(crate) fn require_private(path: &Path) -> Result<()> {
    let mode = fs::metadata(path)?.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!("{} is accessible to other users (mode {mode:o}); run: chmod 600 {}", path.display(), path.display());
    }
    Ok(())
}

/// Read the pepper, creating it on first run. Losing it invalidates every stored password hash.
fn load_pepper(dir: &Path) -> Result<Vec<u8>> {
    let path = dir.join("pepper.key");
    match OpenOptions::new().write(true).create_new(true).mode(0o600).open(&path) {
        Ok(mut f) => {
            let pepper = accounts::random_bytes::<32>();
            f.write_all(&pepper)?;
            Ok(pepper.to_vec())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            require_private(&path)?;
            let pepper = fs::read(&path)?;
            if pepper.len() < 16 {
                bail!("{} is too short to be a valid pepper", path.display());
            }
            Ok(pepper)
        }
        Err(e) => Err(e).with_context(|| format!("creating {}", path.display())),
    }
}

/// QIUI credentials and the pod's address. Stored owner-only in the data directory, next to the
/// database. This is a plain 0600 file, not encryption: anyone who can read your files can read it.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Config {
    pub client_id: Option<String>,
    pub api_key: Option<String>,
    pub mac: Option<String>,
    /// `mailto:` or https address push services can reach if this server misbehaves.
    pub push_contact: Option<String>,
}

pub fn load_config(root: &Path) -> Result<Config> {
    let path = root.join("config.json");
    if !path.exists() {
        return Ok(Config::default());
    }
    require_private(&path)?;
    serde_json::from_slice(&fs::read(&path)?).with_context(|| format!("reading {}", path.display()))
}

pub fn save_config(root: &Path, cfg: &Config) -> Result<()> {
    private_dir(root)?;
    let tmp = root.join("config.json.tmp");
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    f.write_all(&serde_json::to_vec_pretty(cfg)?)?;
    f.sync_all()?;
    fs::rename(&tmp, root.join("config.json"))?;
    Ok(())
}

pub fn open(root: &Path) -> Result<(Store, Auth)> {
    private_dir(root)?;
    let pepper = load_pepper(root)?;
    let db = root.join("qiui.db");
    if !db.exists() {
        OpenOptions::new().write(true).create_new(true).mode(0o600).open(&db)?;
    }
    require_private(&db)?;
    Ok((Store::open(&db)?, Auth::new(pepper)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn creates_private_files_and_reuses_the_same_pepper() {
        let dir = std::env::temp_dir().join(format!("qiui-datadir-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let (_store, auth) = open(&dir).unwrap();
        let hash = auth.hash_secret("a long enough secret").unwrap();
        drop(_store);

        for f in ["pepper.key", "qiui.db"] {
            let mode = fs::metadata(dir.join(f)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{f}");
        }
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);

        // A second open must load the same pepper, so old hashes still verify.
        let (_s2, auth2) = open(&dir).unwrap();
        assert!(auth2.verify_secret("a long enough secret", &hash));

        // A pepper readable by others is refused.
        fs::set_permissions(dir.join("pepper.key"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(open(&dir).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn config_round_trips_privately_and_a_loose_file_is_refused() {
        let dir = std::env::temp_dir().join(format!("qiui-config-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        assert!(load_config(&dir).unwrap().client_id.is_none());

        save_config(&dir, &Config { client_id: Some("Client_x".into()), api_key: None, mac: Some("AA:BB".into()), push_contact: None }).unwrap();
        assert_eq!(fs::metadata(dir.join("config.json")).unwrap().permissions().mode() & 0o777, 0o600);
        let back = load_config(&dir).unwrap();
        assert_eq!((back.client_id.as_deref(), back.mac.as_deref()), (Some("Client_x"), Some("AA:BB")));

        fs::set_permissions(dir.join("config.json"), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_config(&dir).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
