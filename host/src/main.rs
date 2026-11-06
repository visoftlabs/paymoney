//! `paymoney` serves JSON-RPC 2.0 over Chrome's native messaging on stdio; its log is
//! tracing-subscriber's JSON on stderr and, as `log` notifications, on stdout for the page.
//! `paymoney install` registers it with Chrome instead.

use clap::{Parser, Subcommand};
use paymoney::{Error, chrome, rpc, server::Client, store::Store};
use tracing_subscriber::{
    EnvFilter,
    filter::LevelFilter,
    fmt::{self, format::FmtSpan},
    layer::SubscriberExt,
    util::SubscriberInitExt,
};
use url::Url;

#[derive(Parser)]
#[command(version, about)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
    /// The calling extension's origin, which Chrome passes when it starts the host: parsed, then
    /// unread, since the manifest's `allowed_origins` already admits only PayMoney's.
    #[arg(hide = true)]
    _origin: Option<Url>,
}

#[derive(Subcommand)]
enum Command {
    /// Registers this binary with Chrome, for this user, and prints the manifest's path.
    Install,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    // `RUST_LOG` overrides the INFO default.
    let stderr = tracing_subscriber::registry()
        .with(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with(fmt::layer().json().with_writer(std::io::stderr));
    match cli.command {
        Some(Command::Install) => {
            stderr.init();
            println!("{}", chrome::install()?.display());
            Ok(())
        }
        None => {
            stderr
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
    }
}
