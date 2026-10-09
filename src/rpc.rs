//! JSON-RPC 2.0 over stdio: one message per line (as MCP's stdio transport) or per Chrome
//! native-messaging frame. Every log event is a `log` notification with OpenTelemetry attributes.

use crate::{Error, methods::Method, store::Store};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{
    fmt,
    io::{BufRead, ErrorKind, Write},
    sync::{Arc, Mutex, PoisonError},
};
use tracing::field::{Field, Visit};
use tracing_subscriber::{
    EnvFilter, Layer, filter::LevelFilter, layer::Context, layer::SubscriberExt,
};

/// Policy: frames from the extension carry ids, headers and small bodies only.
const MAX_FRAME: usize = 64 * 1024;

const PARSE_ERROR: i64 = -32700;
const INVALID_REQUEST: i64 = -32600;
const METHOD_NOT_FOUND: i64 = -32601;
const INVALID_PARAMS: i64 = -32602;
const SERVER_ERROR: i64 = -32000;

#[derive(Clone, Copy)]
pub enum Framing {
    /// One message per line.
    Lines,
    /// Chrome's native-endian 32-bit length prefix.
    Chrome,
}
impl Framing {
    fn read(self, stdin: &mut impl BufRead) -> Result<Option<Vec<u8>>, Error> {
        match self {
            Framing::Lines => {
                let mut line = Vec::new();
                Ok((stdin.read_until(b'\n', &mut line)? > 0).then_some(line))
            }
            Framing::Chrome => {
                let mut length = [0; 4];
                match stdin.read_exact(&mut length) {
                    Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(None),
                    read => read?,
                }
                let length = u32::from_ne_bytes(length) as usize;
                if length > MAX_FRAME {
                    return Err(Error::Frame(length));
                }
                let mut frame = vec![0; length];
                stdin.read_exact(&mut frame)?;
                Ok(Some(frame))
            }
        }
    }
}

/// Where messages go: the one owner of the output, shared by the responder and the log layer.
pub struct Sink<W> {
    framing: Framing,
    out: Mutex<W>,
}
impl<W: Write> Sink<W> {
    pub fn new(framing: Framing, out: W) -> Arc<Self> {
        Arc::new(Self {
            framing,
            out: Mutex::new(out),
        })
    }

    /// One whole message under the lock, so messages never interleave.
    fn send(&self, message: &Value) -> Result<(), Error> {
        let bytes = serde_json::to_vec(message)?;
        let mut out = self.out.lock().unwrap_or_else(PoisonError::into_inner);
        match self.framing {
            Framing::Lines => out.write_all(&[&bytes[..], b"\n"].concat())?,
            Framing::Chrome => {
                let length = u32::try_from(bytes.len()).or(Err(Error::Frame(bytes.len())))?;
                out.write_all(&[&length.to_ne_bytes()[..], &bytes].concat())?;
            }
        }
        Ok(out.flush()?)
    }
}

/// The log as `log` notifications on `sink`; `RUST_LOG` overrides the INFO default.
pub fn subscriber<W: Write + Send + 'static>(sink: Arc<Sink<W>>) -> impl tracing::Subscriber {
    let filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();
    tracing_subscriber::registry().with(Notify(sink).with_filter(filter))
}

/// Answers each message on `input` until it ends.
pub async fn serve<W: Write>(
    sink: &Sink<W>,
    mut input: impl BufRead,
    store: &Store,
) -> Result<(), Error> {
    tracing::info!(
        event.name = "host.started",
        service.version = env!("CARGO_PKG_VERSION")
    );
    while let Some(message) = sink.framing.read(&mut input)? {
        if let Some(response) = answer(&message, store).await {
            sink.send(&response)?;
        }
    }
    Ok(())
}

#[derive(Deserialize)]
enum Version {
    #[serde(rename = "2.0")]
    V2,
}

#[derive(Deserialize)]
struct Envelope {
    #[serde(rename = "jsonrpc")]
    _version: Version,
    method: String,
    params: Option<Value>,
}

#[derive(Serialize)]
struct Fault {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<Value>,
}
impl Fault {
    fn new(code: i64, message: impl fmt::Display) -> Self {
        Self {
            code,
            message: message.to_string(),
            data: None,
        }
    }
}
impl From<Error> for Fault {
    fn from(error: Error) -> Self {
        match error {
            Error::UnknownMethod => Fault::new(METHOD_NOT_FOUND, error),
            Error::Problem { detail, problem } => Fault {
                code: SERVER_ERROR,
                message: detail,
                data: Some(problem),
            },
            error => Fault::new(SERVER_ERROR, error),
        }
    }
}

/// The response to one message; `None` for a notification, which gets no reply.
async fn answer(message: &[u8], store: &Store) -> Option<Value> {
    let message: Value = match serde_json::from_slice(message) {
        Ok(message) => message,
        Err(error) => return Some(reply(Value::Null, Err(Fault::new(PARSE_ERROR, error)))),
    };
    let id = message.get("id").cloned();
    let envelope = match (&id, Envelope::deserialize(&message)) {
        (Some(Value::Array(_) | Value::Object(_) | Value::Bool(_)), _) => Err(Fault::new(
            INVALID_REQUEST,
            "id must be a string, a number or null",
        )),
        (_, Err(error)) => Err(Fault::new(INVALID_REQUEST, error)),
        (_, Ok(envelope)) => Ok(envelope),
    };
    let result = match envelope {
        Ok(Envelope { method, params, .. }) => call(method, params, store).await,
        Err(fault) => return Some(reply(id.unwrap_or(Value::Null), Err(fault))),
    };
    id.map(|id| reply(id, result))
}

async fn call(method: String, params: Option<Value>, store: &Store) -> Result<Value, Fault> {
    // The name alone classifies it first: an unknown method is -32601 whatever its params.
    if let Ok(Method::Unknown) = serde_json::from_value::<Method>(json!({ "method": method })) {
        return Err(Fault::from(Error::UnknownMethod));
    }
    let call = match params {
        Some(params) => json!({ "method": method, "params": params }),
        None => json!({ "method": method }),
    };
    let method = match serde_json::from_value::<Method>(call) {
        Ok(method) => method,
        Err(error) => return Err(Fault::new(INVALID_PARAMS, error)),
    };
    Ok(method.handle(store).await?)
}

fn reply(id: Value, result: Result<Value, Fault>) -> Value {
    match result {
        Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
        Err(fault) => json!({ "jsonrpc": "2.0", "id": id, "error": fault }),
    }
}

/// Sends each event as `{"jsonrpc":"2.0","method":"log","params":{severity_text, …fields}}`.
struct Notify<W>(Arc<Sink<W>>);
impl<S: tracing::Subscriber, W: Write + Send + 'static> Layer<S> for Notify<W> {
    fn on_event(&self, event: &tracing::Event<'_>, _: Context<'_, S>) {
        let mut params = Map::new();
        params.insert(
            "severity_text".into(),
            event.metadata().level().as_str().into(),
        );
        event.record(&mut Attributes(&mut params));
        let notification = json!({ "jsonrpc": "2.0", "method": "log", "params": params });
        if let Err(error) = self.0.send(&notification) {
            // The output is gone; the response that follows fails the same way and ends `serve`.
            eprintln!("log notification lost: {error}");
        }
    }
}

struct Attributes<'a>(&'a mut Map<String, Value>);
impl Visit for Attributes<'_> {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0
            .insert(field.name().into(), format!("{value:?}").into());
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().into(), value.into());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().into(), value.into());
    }
}
