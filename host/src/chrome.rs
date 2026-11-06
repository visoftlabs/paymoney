//! Chrome's registration of this binary as the extension's native messaging host.

use crate::Error;
use native_messaging::Scope;
use std::path::PathBuf;

/// Chrome's native messaging host name, which the extension connects to.
const HOST: &str = "finance.paymoney.host";
/// PROOF: fixed by the public `key` in paymoney-finance's extension manifest: SHA-256 of the DER
/// key, first 32 hex digits mapped `0–f → a–p`.
const EXTENSION_ID: &str = "bcohgdaijipkkfnnifeibdbniagkeebc";

/// Registers this binary as Chrome's native messaging host for the extension, for this user, and
/// returns the manifest's path.
pub fn install() -> Result<PathBuf, Error> {
    let binary = std::env::current_exe()?;
    let origin = format!("chrome-extension://{EXTENSION_ID}/");
    native_messaging::install(
        HOST,
        "PayMoney native prover",
        &binary,
        &[origin],
        &[],
        &["chrome"],
        Scope::User,
    )?;
    let path = native_messaging::manifest_path("chrome", Scope::User, HOST)?;
    tracing::info!(event.name = "host.installed", file.path = %path.display(), process.executable.path = %binary.display());
    Ok(path)
}
