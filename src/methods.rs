//! The JSON-RPC methods. Artifacts are named files in the data directory; each is replaced
//! atomically, so a step can be rerun.

use crate::{
    Error,
    http::{self, Server},
    notary::{self, NOTARIZE_STEPS, Notary, Record},
    store::{self, Name, Store},
};
use paymoney_core::{Aggregate, Circuits, LegProof, Progress, Verdict};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json, to_value};
use std::path::PathBuf;
use uuid::Uuid;

/// Chrome's native messaging host name, which the extension connects to.
const HOST: &str = "finance.paymoney.host";
/// PROOF: fixed by the public `key` in paymoney-finance's extension manifest: SHA-256 of the DER
/// key, first 32 hex digits mapped `0–f → a–p`.
const EXTENSION_ID: &str = "bcohgdaijipkkfnnifeibdbniagkeebc";

#[derive(Deserialize, Serialize)]
#[serde(
    tag = "method",
    content = "params",
    rename_all = "lowercase",
    rename_all_fields = "camelCase"
)]
pub enum Method {
    #[serde(rename = "host.status")]
    HostStatus,
    Fetch {
        request: http::Request,
    },
    Notarize {
        request: http::Request,
        notary: Notary,
    },
    Prove {
        record: Name,
        leg_id: Uuid,
    },
    Aggregate {
        leg_ids: Vec<Uuid>,
    },
    Submit {
        root: Name,
        server: reqwest::Url,
    },
    Install,
    #[serde(other)]
    Unknown,
}

/// A server's RFC 9457 problem.
#[derive(Deserialize)]
struct Problem {
    detail: String,
}

impl Method {
    pub async fn handle(self, store: &Store) -> Result<Value, Error> {
        // The message as received, attached values redacted: rerunnable once they are filled in.
        tracing::info!(event.name = "message.received", rpc.message = %serde_json::to_string(&self)?);
        Ok(match self {
            Method::HostStatus => {
                json!({ "version": env!("CARGO_PKG_VERSION"), "dataDir": to_value(store.root())? })
            }
            Method::Fetch { request } => {
                json!({ "response": to_value(http::fetch(&request, &Server::of(&request)).await?)? })
            }
            Method::Notarize { request, notary } => {
                let mut progress = Progress::new(NOTARIZE_STEPS);
                let server = Server::of(&request);
                let (record, response) =
                    notary::notarize(&request, &notary, &server, &mut progress).await?;
                progress.advance("record.saving");
                let name = match record {
                    Some(record) => {
                        let name = notary::name(&request);
                        store::replace(&store.path("records", &name)?, &record)?;
                        Some(name)
                    }
                    None => None,
                };
                json!({ "response": to_value(response)?, "record": name })
            }
            Method::Prove { record, leg_id } => {
                let mut progress = Progress::new(3);
                let record: Record = store::read(&store.path("records", &record.to_string())?)?;
                progress.advance("circuits.preparing");
                let circuits = Circuits::prepare()?;
                progress.advance("leaf.proving");
                let leaf = record.prove(&circuits, leg_id)?;
                progress.advance("leaf.saving");
                store::replace(&store.path("leaves", &leg_id.to_string())?, &leaf)?;
                json!({ "key": leaf.leg.key.to_string(), "amount": leaf.leg.amount.minor().to_string() })
            }
            Method::Aggregate { leg_ids } => {
                let leaves = leg_ids
                    .iter()
                    .map(|leg| store::read::<LegProof>(&store.path("leaves", &leg.to_string())?))
                    .collect::<Result<Vec<_>, _>>()?;
                let mut progress = Progress::new(3);
                progress.advance("circuits.preparing");
                let circuits = Circuits::prepare()?;
                progress.advance("root.proving");
                let root = circuits.aggregate(leaves)?;
                progress.advance("root.saving");
                let statement = root.statement;
                let name = format!(
                    "{}-{}-{}",
                    statement.lo,
                    statement.hi,
                    statement.count.get()
                );
                store::replace(&store.path("roots", &name)?, &root)?;
                json!({ "root": name, "summary": to_value(Verdict::from(statement))? })
            }
            Method::Submit { root, server } => {
                let root: Aggregate = store::read(&store.path("roots", &root.to_string())?)?;
                submit(&root, &server).await?
            }
            Method::Install => json!({ "manifest": to_value(install()?)? }),
            Method::Unknown => return Err(Error::UnknownMethod),
        })
    }
}

/// The server's verdict; a problem response is an error carrying the problem.
async fn submit(root: &Aggregate, server: &reqwest::Url) -> Result<Value, Error> {
    let url = server.join("api/proofs")?;
    let response = reqwest::Client::new()
        .post(url.clone())
        .json(root)
        .send()
        .await?;
    let status = response.status();
    let body: Value = response.json().await?;
    tracing::info!(event.name = "root.submitted", url.full = %url, http.response.status_code = status.as_u16());
    match status.is_success() {
        true => Ok(body),
        false => Err(Error::Problem {
            detail: serde_json::from_value::<Problem>(body.clone())?.detail,
            problem: body,
        }),
    }
}

/// Registers this binary as Chrome's native messaging host for the extension.
fn install() -> Result<PathBuf, Error> {
    #[cfg(target_os = "macos")]
    let dir = store::home()?.join("Library/Application Support/Google/Chrome/NativeMessagingHosts");
    #[cfg(target_os = "linux")]
    let dir = store::home()?.join(".config/google-chrome/NativeMessagingHosts");
    std::fs::create_dir_all(&dir)?;
    let binary = std::env::current_exe()?;
    let manifest = json!({
        "name": HOST,
        "description": "PayMoney native prover",
        "path": binary,
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{EXTENSION_ID}/")],
    });
    let path = dir.join(format!("{HOST}.json"));
    store::replace(&path, &manifest)?;
    tracing::info!(event.name = "host.installed", file.path = %path.display(), process.executable.path = %binary.display());
    Ok(path)
}
