//! The PayMoney server over HTTP/3. A request is built as in reqwest; `send` returns, as hyper's
//! handshake does, the response future and the connection future, which the caller runs together.
//! The transport follows h3's `examples/client.rs`.

use crate::{Error, http};
use futures::{Future, StreamExt, TryStreamExt, stream::BoxStream};
use h3::client::RequestStream;
use hyper::{
    StatusCode,
    body::{Buf, Bytes},
    header::{CONTENT_TYPE, HeaderValue},
};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::{CertificateDer, pem::PemObject};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{io, net::Ipv6Addr, sync::Arc, time::Duration};
use tokio_util::sync::{CancellationToken, DropGuard};
use url::Url;

/// Policy: keeps a connection alive across its quiet stretches, well inside the 30 s idle timeout.
const KEEP_ALIVE: Duration = Duration::from_secs(5);
/// RFC 9114 §8.1: H3_NO_ERROR, a connection closed with nothing left to do.
const H3_NO_ERROR: u32 = 0x100;

/// A request or response body, as a stream of chunks.
pub type Body = BoxStream<'static, io::Result<Bytes>>;

/// The server's origin and, for a self-signed certificate, that certificate (PEM), then the only
/// root trusted; without one, Mozilla's roots verify it.
#[derive(Deserialize, Serialize)]
pub struct Server {
    pub url: Url,
    pub certificate: Option<String>,
}

/// An RFC 9457 problem: the server's answer to a root it does not accept.
#[derive(Debug, Deserialize, Serialize)]
pub struct Problem {
    pub r#type: String,
    pub title: String,
    pub status: u16,
    pub detail: String,
}

/// The process's QUIC endpoint, which every request connects from.
pub struct Client {
    endpoint: quinn::Endpoint,
}
impl Client {
    /// Binds the endpoint on IPv6, as quinn's and h3's client examples do.
    pub fn bind() -> Result<Self, Error> {
        let endpoint = quinn::Endpoint::client((Ipv6Addr::UNSPECIFIED, 0).into())?;
        Ok(Self { endpoint })
    }

    /// A `POST` to `path` on `server`.
    pub fn post<'a>(&'a self, server: &'a Server, path: &str) -> RequestBuilder<'a> {
        let request = (|| {
            let url = server.url.join(path)?;
            Ok(hyper::Request::post(url.as_str()).body(futures::stream::empty().boxed())?)
        })();
        RequestBuilder {
            client: self,
            server,
            request,
        }
    }

    /// A new connection to the host of `uri`, trusting `server`'s certificate.
    async fn connect(&self, server: &Server, uri: &hyper::Uri) -> Result<quinn::Connection, Error> {
        let url = Url::parse(&uri.to_string())?;
        let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) else {
            return Err(Error::Scheme(url));
        };
        // IPv6 only: `localhost` is `::1`.
        let Some(address) = tokio::net::lookup_host((host, port))
            .await?
            .find(std::net::SocketAddr::is_ipv6)
        else {
            return Err(Error::Scheme(url));
        };
        let roots = match &server.certificate {
            Some(pem) => {
                let mut roots = rustls::RootCertStore::empty();
                roots.add(CertificateDer::from_pem_slice(pem.as_bytes())?)?;
                roots
            }
            None => http::roots()?,
        };
        let mut tls = http::tls(roots)?;
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let mut config = quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(tls)?));
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(KEEP_ALIVE));
        config.transport_config(Arc::new(transport));
        Ok(self.endpoint.connect_with(config, address, host)?.await?)
    }
}

/// A request being built; its first error surfaces at `send` (reqwest's `RequestBuilder`).
pub struct RequestBuilder<'a> {
    client: &'a Client,
    server: &'a Server,
    request: Result<hyper::Request<Body>, Error>,
}
impl RequestBuilder<'_> {
    /// `value` as a JSON body.
    pub fn json(mut self, value: &impl Serialize) -> Self {
        let body = serde_json::to_vec(value);
        self.request = self.request.and_then(|mut request| {
            let headers = request.headers_mut();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            let chunk = Bytes::from(body?);
            *request.body_mut() = futures::stream::iter([Ok(chunk)]).boxed();
            Ok(request)
        });
        self
    }

    pub fn body(mut self, body: Body) -> Self {
        if let Ok(request) = &mut self.request {
            *request.body_mut() = body;
        }
        self
    }

    /// Connects and sends the head. Returns the response and the connection, which the caller
    /// runs together, as hyper's `Connection`: the connection sends the body, drives HTTP/3, and
    /// closes once the response is read or dropped.
    pub async fn send(
        self,
    ) -> Result<
        (
            impl Future<Output = Result<Response, Error>>,
            impl Future<Output = Result<(), Error>>,
        ),
        Error,
    > {
        let (head, mut body) = self.request?.into_parts();
        let quic = self.client.connect(self.server, &head.uri).await?;
        let (mut driver, mut requests) =
            h3::client::new(h3_quinn::Connection::new(quic.clone())).await?;
        let (mut sending, mut receiving) = requests
            .send_request(hyper::Request::from_parts(head, ()))
            .await?
            .split();
        let read = CancellationToken::new();
        let done = read.clone().drop_guard();
        let response = async move {
            let status = receiving.recv_response().await?.status();
            Ok(Response {
                status,
                receiving,
                done,
            })
        };
        let connection = async move {
            let exchange = async {
                while let Some(chunk) = body.next().await {
                    sending.send_data(chunk?).await?;
                }
                sending.finish().await?;
                read.cancelled().await;
                quic.close(H3_NO_ERROR.into(), b"");
                Ok(())
            };
            // `requests` lives as long as the exchange: dropping it would end the connection.
            let _requests = requests;
            tokio::select! {
                result = exchange => result,
                error = driver.wait_idle() => Err(error.into()),
            }
        };
        Ok((response, connection))
    }
}

/// A response; reading its body to the end, or dropping it, lets the connection close.
pub struct Response {
    status: StatusCode,
    receiving: RequestStream<h3_quinn::RecvStream, Bytes>,
    done: DropGuard,
}
impl Response {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    /// The response, unless its status is a client or server error.
    pub fn error_for_status(self) -> Result<Self, Error> {
        match self.status.is_client_error() || self.status.is_server_error() {
            true => Err(Error::Status(self.status)),
            false => Ok(self),
        }
    }

    /// The body as it arrives.
    pub fn bytes_stream(self) -> Body {
        let Self {
            receiving, done, ..
        } = self;
        futures::stream::unfold(Some((receiving, done)), |state| async move {
            let (mut receiving, done) = state?;
            match receiving.recv_data().await {
                Ok(Some(mut data)) => {
                    let bytes = data.copy_to_bytes(data.remaining());
                    Some((Ok(bytes), Some((receiving, done))))
                }
                Ok(None) => None,
                Err(error) => Some((Err(io::Error::other(error)), None)),
            }
        })
        .boxed()
    }

    /// The whole body, parsed as JSON.
    pub async fn json<T: DeserializeOwned>(self) -> Result<T, Error> {
        let body = self
            .bytes_stream()
            .try_fold(Vec::new(), |mut body, bytes| async move {
                body.extend_from_slice(&bytes);
                Ok(body)
            })
            .await?;
        Ok(serde_json::from_slice(&body)?)
    }
}
