//! `paymoney` serves JSON-RPC 2.0 over Chrome's native messaging on stdio; its log is
//! tracing-subscriber's JSON on stderr and, as `log` notifications, on stdout for the page.

use paymoney::{Error, rpc, server::Client, store::Store};
use tracing_subscriber::{
    EnvFilter,
    filter::LevelFilter,
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};

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
        .finish()
        .with(
            fmt::layer()
                .json()
                .with_span_events(FmtSpan::NEW | FmtSpan::CLOSE)
                .with_writer(|| rpc::Log),
        )
        .init();
    rpc::serve(
        std::io::stdin().lock(),
        &Store::platform()?,
        &Client::bind()?,
    )
    .await
}
