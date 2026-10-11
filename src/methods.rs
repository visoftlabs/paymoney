//! The JSON-RPC methods. Artifacts are files in the data directory named by UUID: a record by
//! its transaction, a leaf by its leg, a root by a fresh id; each is replaced atomically, so a step
//! can be rerun.

use crate::{
    Error, http,
    notary::{self, Record},
    server::{Client, Server},
    store::{self, Store},
};
use native_messaging::Scope;
use paymoney_core::{Aggregate, Amount, Circuits, Key, LegProof, Statement, attestation};
use serde::{Deserialize, Serialize};
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
        server: Server,
    },
    Prove {
        record: Uuid,
        leg_id: Uuid,
    },
    Aggregate {
        leg_ids: Vec<Uuid>,
    },
    Submit {
        root: Uuid,
        server: Server,
    },
    Install,
    #[serde(other)]
    Unknown,
}

/// A method's result.
#[derive(Clone, Serialize)]
#[serde(untagged, rename_all_fields = "camelCase")]
pub enum Reply {
    HostStatus {
        version: &'static str,
        data_dir: PathBuf,
    },
    Fetched {
        response: http::Response,
    },
    Notarized {
        response: http::Response,
        record: Option<Uuid>,
    },
    Proven {
        key: Key,
        amount: Amount,
    },
    Aggregated {
        root: Uuid,
        summary: Statement,
    },
    Statement(Statement),
    Installed {
        manifest: PathBuf,
    },
}

impl Method {
    pub async fn handle(self, store: &Store, client: &Client) -> Result<Reply, Error> {
        // The message as received, attached values redacted: rerunnable once they are filled in.
        tracing::info!(event.name = "message.received", rpc.message = %serde_json::to_string(&self)?);
        Ok(match self {
            Method::HostStatus => Reply::HostStatus {
                version: env!("CARGO_PKG_VERSION"),
                data_dir: store.root().to_owned(),
            },
            Method::Fetch { request } => Reply::Fetched {
                response: http::fetch(&request).await?,
            },
            Method::Notarize { request, server } => {
                let (record, response) = notary::notarize(&request, &server, client).await?;
                // PROOF: `transaction` captures a hyphenated UUID, which always parses.
                let id = |record: &Record| {
                    Uuid::try_parse_ascii(attestation::transaction(&record.request)?).ok()
                };
                let record = match record
                    .as_ref()
                    .and_then(|record| Some((id(record)?, record)))
                {
                    Some((id, record)) => {
                        store::replace(&store.path("records", &id)?, record)?;
                        Some(id)
                    }
                    None => None,
                };
                Reply::Notarized { response, record }
            }
            Method::Prove { record, leg_id } => {
                let record: Record = store::read(&store.path("records", &record)?)?;
                let circuits = Circuits::prepare()?;
                let leaf = record.prove(&circuits, leg_id)?;
                store::replace(&store.path("leaves", &leg_id)?, &leaf)?;
                Reply::Proven {
                    key: leaf.leg.key,
                    amount: leaf.leg.amount,
                }
            }
            Method::Aggregate { leg_ids } => {
                let leaves = leg_ids
                    .iter()
                    .map(|leg| store::read::<LegProof>(&store.path("leaves", leg)?))
                    .collect::<Result<Vec<_>, _>>()?;
                let circuits = Circuits::prepare()?;
                let root = circuits.aggregate(leaves)?;
                let id = Uuid::new_v4();
                store::replace(&store.path("roots", &id)?, &root)?;
                Reply::Aggregated {
                    root: id,
                    summary: root.statement,
                }
            }
            Method::Submit { root, server } => {
                let root: Aggregate = store::read(&store.path("roots", &root)?)?;
                Reply::Statement(submit(&root, &server, client).await?)
            }
            Method::Install => Reply::Installed {
                manifest: install()?,
            },
            Method::Unknown => return Err(Error::UnknownMethod),
        })
    }
}

/// The statement the server verified in `root`; its RFC 9457 problem is an error carrying the
/// problem.
async fn submit(root: &Aggregate, server: &Server, client: &Client) -> Result<Statement, Error> {
    let (response, connection) = client.post(server, "api/proofs").json(root).send().await?;
    let verdict = async {
        let response = response.await?;
        let status = response.status();
        tracing::info!(event.name = "root.submitted", url.full = %server.url, http.response.status_code = status.as_u16());
        match status.is_success() {
            true => response.json().await,
            false => Err(Error::Problem(response.json().await?)),
        }
    };
    let ((), statement) = tokio::try_join!(connection, verdict)?;
    Ok(statement)
}

/// Registers this binary as Chrome's native messaging host for the extension, for this user.
fn install() -> Result<PathBuf, Error> {
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
