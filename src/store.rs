//! The data directory, owner-only: the notary key and `{records,leaves,roots}/<name>.json`.

use crate::{Error, patterns::NAME};
use serde::{Serialize, de::DeserializeOwned};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::{
    fmt,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    str::FromStr,
};

pub fn home() -> Result<PathBuf, Error> {
    std::env::home_dir().ok_or(Error::Home)
}

pub struct Store {
    root: PathBuf,
}
impl Store {
    /// Apple's Application Support on macOS; the XDG Base Directory data home on Linux.
    pub fn platform() -> Result<Self, Error> {
        #[cfg(target_os = "macos")]
        let root = home()?.join("Library/Application Support/finance.paymoney");
        #[cfg(target_os = "linux")]
        let root = match std::env::var_os("XDG_DATA_HOME").map(PathBuf::from) {
            // XDG: a relative path is invalid and ignored.
            Some(base) if base.is_absolute() => base,
            _ => home()?.join(".local/share"),
        }
        .join("paymoney");
        Self::at(root)
    }

    /// The store rooted at `root`, created owner-only.
    pub fn at(root: PathBuf) -> Result<Self, Error> {
        std::fs::create_dir_all(&root)?;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn path(&self, kind: &str, name: &str) -> Result<PathBuf, Error> {
        let dir = self.root.join(kind);
        std::fs::create_dir_all(&dir)?;
        Ok(dir.join(format!("{name}.json")))
    }
}

/// An artifact's name, matching `NAME`.
#[derive(SerializeDisplay, DeserializeFromStr)]
pub struct Name(String);
impl FromStr for Name {
    type Err = Error;
    fn from_str(name: &str) -> Result<Self, Error> {
        match NAME.is_match(name) {
            true => Ok(Self(name.to_owned())),
            false => Err(Error::Name(name.to_owned())),
        }
    }
}
impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

pub fn read<T: DeserializeOwned>(path: &Path) -> Result<T, Error> {
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

/// Atomically replaces `path`; readers see the old or the new file, never a partial one.
pub fn replace<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
    let mut partial = path.as_os_str().to_owned();
    partial.push(format!(".{}.partial", std::process::id()));
    std::fs::write(&partial, serde_json::to_vec(value)?)?;
    std::fs::rename(&partial, path)?;
    tracing::info!(event.name = "file.written", file.path = %path.display());
    Ok(())
}
