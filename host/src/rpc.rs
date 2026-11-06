//! JSON-RPC 2.0 over Chrome's native messaging: one message per length-prefixed frame on stdio.

use crate::{
    Error,
    methods::{Method, Reply},
    server::Client,
    store::Store,
};
use jsonrpsee_types::{
    ErrorCode, ErrorObject, ErrorObjectOwned, Id, InvalidRequest, Notification, Request, Response,
    ResponsePayload, TwoPointZero, error::CALL_EXECUTION_FAILED_CODE,
};
use native_messaging::host::{self, NmError};
use serde::{Deserialize, Serialize};
use serde_json::value::RawValue;
use std::{
    borrow::Cow,
    io::{self, Read, Write},
};

/// Policy: frames from the extension carry ids, headers and small bodies only.
const MAX_FRAME: usize = 64 * 1024;

/// What the binary writes to the browser.
#[derive(Serialize)]
#[serde(untagged)]
enum Out<'a> {
    /// The answer to a request.
    Response(Response<'a, Reply>),
    /// A `log` notification: one tracing-subscriber JSON record.
    Log(Notification<'a, &'a RawValue>),
}

/// Writes one length-prefixed frame to stdout, from any thread.
fn send(out: &Out) -> Result<(), NmError> {
    // PROOF: `send_json` writes the whole frame with one `write_all`, which holds stdout's lock
    // for the call, so frames from concurrent threads never interleave.
    host::send_json(&mut io::stdout(), out)
}

/// tracing-subscriber's writer for the page's log: each record it formats becomes one
/// `Out::Log`.
pub struct Log;

impl Write for Log {
    fn write(&mut self, line: &[u8]) -> io::Result<usize> {
        // PROOF: the fmt layer formats a record into one buffer and passes it to `write_all`,
        // which this `write` consumes whole, so each call is exactly one record.
        let record = serde_json::from_slice::<&RawValue>(line)?;
        send(&Out::Log(Notification::new("log".into(), record))).map_err(io::Error::other)?;
        Ok(line.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Answers each frame on `input` until the browser disconnects.
pub async fn serve(mut input: impl Read, store: &Store, client: &Client) -> Result<(), Error> {
    tracing::info!(
        event.name = "host.started",
        service.version = env!("CARGO_PKG_VERSION")
    );
    while let Some(message) = host::decode_message_opt(&mut input, MAX_FRAME)? {
        if let Some(response) = answer(message.as_bytes(), store, client).await {
            send(&Out::Response(response))?;
        }
    }
    Ok(())
}

/// A notification (JSON-RPC 2.0 §4.1): it has no `id` member, so a frame with any `id` is a
/// request, answered even when that id is invalid (§5).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Note<'a> {
    #[serde(rename = "jsonrpc")]
    _jsonrpc: TwoPointZero,
    #[serde(borrow)]
    method: Cow<'a, str>,
    #[serde(borrow, default)]
    params: Option<&'a RawValue>,
}

/// One inbound frame.
enum Incoming<'a> {
    Request(Request<'a>),
    Note(Note<'a>),
    /// Not JSON, or no request: answered with this error.
    Invalid(Response<'static, Reply>),
}

impl<'a> Incoming<'a> {
    /// The first shape `bytes` fits, in this order. Rationale: not a `#[serde(untagged)]` enum,
    /// whose buffering cannot hand serde_json's `RawValue` params through.
    fn parse(bytes: &'a [u8]) -> Self {
        let error =
            |code: ErrorCode, id| Self::Invalid(Response::new(ResponsePayload::error(code), id));
        if let Ok(request) = serde_json::from_slice(bytes) {
            return Self::Request(request);
        }
        match serde_json::from_slice(bytes) {
            Ok(note) => Self::Note(note),
            Err(syntax) if syntax.is_syntax() || syntax.is_eof() => {
                error(ErrorCode::ParseError, Id::Null)
            }
            // The id when it is valid, null otherwise (§5).
            Err(_) => match serde_json::from_slice::<InvalidRequest>(bytes) {
                Ok(invalid) => error(ErrorCode::InvalidRequest, invalid.id.into_owned()),
                Err(_) => error(ErrorCode::InvalidRequest, Id::Null),
            },
        }
    }
}

/// The response to one message; `None` for a notification, which gets no reply.
async fn answer(bytes: &[u8], store: &Store, client: &Client) -> Option<Response<'static, Reply>> {
    match Incoming::parse(bytes) {
        Incoming::Request(request) => {
            let payload = call(&request.method, request.params.as_deref(), store, client).await;
            Some(Response::new(payload, request.id.into_owned()))
        }
        Incoming::Note(note) => {
            call(&note.method, note.params, store, client).await;
            None
        }
        Incoming::Invalid(response) => Some(response),
    }
}

/// The `{ method, params }` that `Method` deserializes from.
#[derive(Serialize)]
struct Call<'a> {
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<&'a RawValue>,
}

async fn call(
    method: &str,
    params: Option<&RawValue>,
    store: &Store,
    client: &Client,
) -> ResponsePayload<'static, Reply> {
    let parse = |call: Call| serde_json::to_value(call).and_then(serde_json::from_value::<Method>);
    // The name alone classifies it first: an unknown method is -32601 whatever its params.
    if let Ok(Method::Unknown) = parse(Call {
        method,
        params: None,
    }) {
        return ResponsePayload::error(ErrorCode::MethodNotFound);
    }
    let method = match parse(Call { method, params }) {
        Ok(method) => method,
        Err(error) => {
            let code = ErrorCode::InvalidParams.code();
            return ResponsePayload::error(ErrorObject::owned(code, error.to_string(), None::<()>));
        }
    };
    match method.handle(store, client).await {
        Ok(reply) => ResponsePayload::success(reply),
        Err(error) => ResponsePayload::error(error),
    }
}

impl From<Error> for ErrorObjectOwned {
    fn from(error: Error) -> Self {
        match error {
            Error::UnknownMethod => ErrorCode::MethodNotFound.into(),
            Error::Problem(problem) => ErrorObject::owned(
                CALL_EXECUTION_FAILED_CODE,
                problem.detail.clone(),
                Some(problem),
            ),
            error => ErrorObject::owned(CALL_EXECUTION_FAILED_CODE, error.to_string(), None::<()>),
        }
    }
}
