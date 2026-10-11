//! `paymoney` serves JSON-RPC 2.0 over Chrome's native messaging on stdio; its log is
//! tracing-subscriber's JSON on stderr, since stdout carries the frames.

use paymoney::{Error, rpc, server::Client, store::Store};
use tracing_subscriber::{EnvFilter, filter::LevelFilter};

#[tokio::main]
async fn main() -> Result<(), Error> {
    // `RUST_LOG` overrides the INFO default.
    tracing_subscriber::fmt()
        .json()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .init();
    rpc::serve(
        std::io::stdin().lock(),
        std::io::stdout().lock(),
        &Store::platform()?,
        &Client::bind()?,
    )
    .await
}
