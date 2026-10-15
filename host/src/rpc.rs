//! JSON-RPC 2.0 over Chrome's native messaging: one message per length-prefixed frame on stdio.

use crate::{
    Error,
    methods::{Method, Reply},
    server::Client,
    store::Store,
};
use jsonrpsee_types::{
    ErrorCode, ErrorObject, ErrorObjectOwned, Id, InvalidRequest, Notification, Request, Response,
    ResponsePayload, error::CALL_EXECUTION_FAILED_CODE,
};
use native_messaging::host;
use serde::Serialize;
use serde_json::{Value, value::RawValue};
use std::io::{Read, Write};

/// Policy: frames from the extension carry ids, headers and small bodies only.
const MAX_FRAME: usize = 64 * 1024;

/// Answers each frame on `input` until the browser disconnects.
pub async fn serve(
    mut input: impl Read,
    mut output: impl Write,
    store: &Store,
    client: &Client,
) -> Result<(), Error> {
    tracing::info!(
        event.name = "host.started",
        service.version = env!("CARGO_PKG_VERSION")
    );
    while let Some(message) = host::decode_message_opt(&mut input, MAX_FRAME)? {
        if let Some(response) = answer(message.as_bytes(), store, client).await {
            host::send_json(&mut output, &response)?;
        }
    }
    Ok(())
}

/// The response to one message; `None` for a notification, which gets no reply.
async fn answer(bytes: &[u8], store: &Store, client: &Client) -> Option<Response<'static, Reply>> {
    let error = |code: ErrorCode, id| Some(Response::new(ResponsePayload::error(code), id));
    let Ok(message) = serde_json::from_slice::<Value>(bytes) else {
        return error(ErrorCode::ParseError, Id::Null);
    };
    // A message without an id is a notification (JSON-RPC 2.0 §4.1).
    if message.get("id").is_none() {
        let Ok(notification) = serde_json::from_slice::<Notification<Option<&RawValue>>>(bytes)
        else {
            return error(ErrorCode::InvalidRequest, Id::Null);
        };
        call(&notification.method, notification.params, store, client).await;
        return None;
    }
    match serde_json::from_slice::<Request>(bytes) {
        Ok(request) => {
            let payload = call(&request.method, request.params.as_deref(), store, client).await;
            Some(Response::new(payload, request.id.into_owned()))
        }
        // The id when it is valid, null otherwise (§5).
        Err(_) => match serde_json::from_slice::<InvalidRequest>(bytes) {
            Ok(invalid) => error(ErrorCode::InvalidRequest, invalid.id.into_owned()),
            Err(_) => error(ErrorCode::InvalidRequest, Id::Null),
        },
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
