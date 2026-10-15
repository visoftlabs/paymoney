//! The data directory, owner-only: `{records,leaves,roots}/<name>.json`.

use crate::Error;
use serde::{Serialize, de::DeserializeOwned};
use std::{
    io::Write,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};
use tempfile::NamedTempFile;
use uuid::Uuid;

/// The data directory's name under the platform's data home.
const DATA_DIR: &str = "finance.paymoney";

pub struct Store {
    root: PathBuf,
}
impl Store {
    /// `DATA_DIR` in the platform's data directory (Application Support, the XDG data home),
    /// created owner-only.
    pub fn platform() -> Result<Self, Error> {
        let root = dirs::data_dir().ok_or(Error::Home)?.join(DATA_DIR);
        std::fs::create_dir_all(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// `<kind>/<id>.json`: a UUID is never a path, so no name escapes the store.
    pub fn path(&self, kind: &str, id: &Uuid) -> Result<PathBuf, Error> {
        let dir = self.root.join(kind);
        std::fs::create_dir_all(&dir)?;
        Ok(dir.join(format!("{id}.json")))
    }
}

pub fn read<T: DeserializeOwned>(path: &Path) -> Result<T, Error> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

/// Atomically replaces `path` with an owner-only file (tempfile's default mode); readers see the
/// old or the new file, never a partial one.
pub fn replace<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
    let mut file = NamedTempFile::new_in(path.with_file_name(""))?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.persist(path)?;
    tracing::info!(event.name = "file.written", file.path = %path.display());
    Ok(())
}
