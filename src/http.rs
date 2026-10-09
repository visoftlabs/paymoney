//! One HTTP/1.1 exchange, in and out as HAR 1.2: request line, then `host` and `content-type`
//! derived from the URL and `postData`, then the headers in the caller's order. `_attached` values
//! are session secrets: never committed, logged or stored.

use crate::Error;
use http_body_util::{BodyExt, Full};
use hyper::{
    Method,
    body::Bytes,
    header::{CONTENT_LENGTH, CONTENT_TYPE, HOST, HeaderName, HeaderValue, TRANSFER_ENCODING},
};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tlsn::webpki::RootCertStore;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use url::Url;

/// Derived from the URL and `postData`.
const DERIVED: [HeaderName; 4] = [HOST, CONTENT_TYPE, CONTENT_LENGTH, TRANSFER_ENCODING];

/// A HAR header; `_attached`, a HAR custom field, marks a session secret.
#[derive(Deserialize, Serialize)]
struct Header {
    name: String,
    value: String,
    #[serde(
        rename = "_attached",
        default,
        skip_serializing_if = "std::ops::Not::not"
    )]
    attached: bool,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PostData {
    mime_type: String,
    text: String,
}

/// The HAR request fields a request is built from; the rest (`httpVersion`, `cookies`, …) is
/// ignored, so a DevTools HAR entry parses.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Har {
    method: String,
    url: Url,
    headers: Vec<Header>,
    #[serde(skip_serializing_if = "Option::is_none")]
    post_data: Option<PostData>,
}

#[derive(Clone)]
enum Line {
    Value(HeaderName, HeaderValue),
    Attached(HeaderName, HeaderValue),
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// An `https` request with unique, non-derived header names. Serializes as HAR with attached
/// values redacted.
#[derive(Clone, Deserialize, Serialize)]
#[serde(try_from = "Har", into = "Har")]
pub struct Request {
    method: Method,
    url: Url,
    host: String,
    port: u16,
    headers: Vec<Line>,
    body: Option<(HeaderValue, Bytes)>,
}
impl TryFrom<Har> for Request {
    type Error = Error;
    fn try_from(har: Har) -> Result<Self, Error> {
        let url = har.url;
        let (Some(host), Some(port), "https") =
            (url.host_str(), url.port_or_known_default(), url.scheme())
        else {
            return Err(Error::Scheme(url));
        };
        let host = host.to_owned();
        let mut seen = Vec::new();
        let mut parse = |header: Header| {
            let Header {
                name,
                value,
                attached,
            } = header;
            let parsed = HeaderName::try_from(&name).or(Err(Error::Header(name.clone())))?;
            if DERIVED.contains(&parsed) {
                return Err(Error::Reserved(name));
            }
            if seen.contains(&parsed) {
                return Err(Error::Header(name));
            }
            seen.push(parsed.clone());
            let value = HeaderValue::try_from(value).or(Err(Error::Header(name)))?;
            Ok(match attached {
                true => Line::Attached(parsed, value),
                false => Line::Value(parsed, value),
            })
        };
        let headers = har
            .headers
            .into_iter()
            .map(&mut parse)
            .collect::<Result<_, Error>>()?;
        let body = match har.post_data {
            Some(PostData { mime_type, text }) => Some((
                HeaderValue::try_from(mime_type).or(Err(Error::Header("content-type".into())))?,
                Bytes::from(text),
            )),
            None => None,
        };
        Ok(Self {
            method: Method::from_bytes(har.method.as_bytes())?,
            url,
            host,
            port,
            headers,
            body,
        })
    }
}
impl From<Request> for Har {
    fn from(request: Request) -> Self {
        let headers = request
            .headers
            .iter()
            .map(|line| match line {
                Line::Value(name, value) => Header {
                    name: name.to_string(),
                    value: text(value.as_bytes()),
                    attached: false,
                },
                Line::Attached(name, _) => Header {
                    name: name.to_string(),
                    value: "<redacted>".into(),
                    attached: true,
                },
            })
            .collect();
        let post_data = request.body.as_ref().map(|(mime, body)| PostData {
            mime_type: text(mime.as_bytes()),
            text: text(body),
        });
        Har {
            method: request.method.to_string(),
            url: request.url,
            headers,
            post_data,
        }
    }
}
impl Request {
    pub fn host(&self) -> &str {
        &self.host
    }

    /// `host[:port]`, the port only when not the default.
    fn authority(&self) -> String {
        match self.url.port() {
            Some(port) => format!("{}:{port}", self.host),
            None => self.host.clone(),
        }
    }

    fn target(&self) -> &str {
        &self.url[url::Position::BeforePath..url::Position::AfterQuery]
    }

    /// The derived headers, then the caller's, in wire order; `true` marks an attached one.
    fn lines(&self) -> impl Iterator<Item = (&HeaderName, &HeaderValue, bool)> {
        let derived = self
            .body
            .iter()
            .map(|(mime, _)| (&CONTENT_TYPE, mime, false));
        derived.chain(self.headers.iter().map(|line| match line {
            Line::Value(name, value) => (name, value, false),
            Line::Attached(name, value) => (name, value, true),
        }))
    }

    /// What notarization commits: request line, `host`, and every header before the first
    /// attached one, the longest head without a secret.
    pub fn committed(&self) -> Vec<u8> {
        let line = format!(
            "{} {} HTTP/1.1\r\nhost: {}\r\n",
            self.method,
            self.target(),
            self.authority()
        );
        self.lines().take_while(|(_, _, attached)| !attached).fold(
            line.into_bytes(),
            |mut bytes, (name, value, _)| {
                bytes.extend([name.as_str().as_bytes(), b": ", value.as_bytes(), b"\r\n"].concat());
                bytes
            },
        )
    }

    fn http(&self) -> Result<hyper::Request<Full<Bytes>>, Error> {
        let builder = hyper::Request::builder()
            .method(self.method.clone())
            .uri(self.target())
            .header(HOST, self.authority());
        let builder = self.lines().fold(builder, |builder, (name, value, _)| {
            builder.header(name, value)
        });
        let body = self.body.as_ref().map(|(_, body)| body.clone());
        Ok(builder.body(Full::new(body.unwrap_or_default()))?)
    }
}

/// A HAR response. Headers are withheld: `set-cookie` can carry the session.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub status: u16,
    pub status_text: String,
    pub headers: [(); 0],
    pub content: Content,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Content {
    pub size: usize,
    pub mime_type: String,
    pub text: String,
}

/// Where a request's host is reached, and the roots that authenticate it.
#[derive(Clone)]
pub struct Server {
    pub address: String,
    pub roots: RootCertStore,
}
impl Server {
    /// The URL's host and port, under Mozilla's roots.
    pub fn of(request: &Request) -> Self {
        Self {
            address: format!("{}:{}", request.host, request.port),
            roots: RootCertStore::mozilla(),
        }
    }
}

/// One exchange over `io`; the connection ends with it.
pub async fn send<T>(io: T, request: &Request) -> Result<Response, Error>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(io)).await?;
    let connection = tokio::spawn(connection);
    let response = sender.send_request(request.http()?).await?;
    let status = response.status();
    // HAR's value for an unknown type.
    let mime_type = match response.headers().get(CONTENT_TYPE) {
        Some(value) => text(value.as_bytes()),
        None => "x-unknown".into(),
    };
    let body = response.into_body().collect().await?.to_bytes();
    drop(sender);
    connection.await??;
    tracing::info!(
        event.name = "response.received",
        http.request.method = %request.method,
        url.full = %request.url,
        http.response.status_code = status.as_u16(),
        http.response.body.size = body.len()
    );
    Ok(Response {
        status: status.as_u16(),
        status_text: status.canonical_reason().unwrap_or_default().into(),
        headers: [],
        content: Content {
            size: body.len(),
            mime_type,
            text: String::from_utf8(body.to_vec())?,
        },
    })
}

/// A plain HTTPS exchange.
pub async fn fetch(request: &Request, server: &Server) -> Result<Response, Error> {
    let mut roots = rustls::RootCertStore::empty();
    for root in &server.roots.roots {
        roots.add(rustls::pki_types::CertificateDer::from(root.0.clone()))?;
    }
    // rustls's own default provider, named: tlsn also compiles `ring`, so rustls cannot choose.
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let name = rustls::pki_types::ServerName::try_from(request.host.clone())?;
    let tcp = TcpStream::connect(&server.address).await?;
    let tls = tokio_rustls::TlsConnector::from(Arc::new(config))
        .connect(name, tcp)
        .await?;
    send(tls, request).await
}
