//! `paymoney` serves JSON-RPC 2.0 on stdio: one message per line, or per native-messaging frame
//! when Chrome starts it with the extension's origin.

use paymoney::{
    Error,
    patterns::ORIGIN,
    rpc::{self, Framing, Sink},
    store::Store,
};
use std::sync::Arc;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let framing = match std::env::args().nth(1) {
        None => Framing::Lines,
        Some(origin) if ORIGIN.is_match(&origin) => Framing::Chrome,
        Some(other) => return Err(Error::Usage(other)),
    };
    let sink = Sink::new(framing, std::io::stdout());
    rpc::subscriber(Arc::clone(&sink)).try_init()?;
    rpc::serve(&sink, std::io::stdin().lock(), &Store::platform()?).await
}
