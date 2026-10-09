//! PayMoney: notarize Revolut transactions with tlsn, prove each leg, aggregate the proofs. The
//! `paymoney` binary serves every step as a JSON-RPC 2.0 method on stdio.

pub mod crypto;
pub mod http;
pub mod methods;
pub mod notary;
pub mod patterns;
pub mod rpc;
pub mod store;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("HTTP: {0}")]
    Http(#[from] reqwest::Error),
    #[error("URL: {0}")]
    Url(#[from] url::ParseError),
    #[error("proof system: {0}")]
    Proof(#[from] paymoney_core::Error),
    #[error("TLSNotary: {0}")]
    Tlsn(#[from] tlsn::Error),
    #[error("TLSNotary prover config: {0}")]
    ProverConfig(#[from] tlsn::config::prover::ProverConfigError),
    #[error("TLS config: {0}")]
    TlsConfig(#[from] tlsn::config::tls::TlsConfigError),
    #[error("MPC-TLS config: {0}")]
    MpcConfig(#[from] tlsn::config::tls_commit::mpc::MpcTlsConfigError),
    #[error("disclosure config: {0}")]
    ProveConfig(#[from] tlsn::config::prove::ProveConfigError),
    #[error("server name: {0}")]
    ServerName(#[from] tlsn::connection::InvalidDnsNameError),
    #[error("transcript: {0}")]
    Transcript(#[from] tlsn::transcript::InvalidTranscriptLength),
    #[error("HTTP over MPC-TLS: {0}")]
    Hyper(#[from] hyper::Error),
    #[error("HTTP request: {0}")]
    Request(#[from] hyper::http::Error),
    #[error("task: {0}")]
    Join(#[from] tokio::task::JoinError),
    #[error("invalid or repeated header {0:?}")]
    Header(String),
    #[error("header {0:?} is derived from the URL or the body")]
    Reserved(String),
    #[error("only https URLs with a host: {0}")]
    Scheme(url::Url),
    #[error("HTTP method: {0}")]
    Method(#[from] hyper::http::method::InvalidMethod),
    #[error("TLS: {0}")]
    Tls(#[from] rustls::Error),
    #[error("DNS name: {0}")]
    DnsName(#[from] rustls::pki_types::InvalidDnsNameError),
    #[error("response body is not UTF-8")]
    Utf8(#[from] std::string::FromUtf8Error),
    #[error("notarization rejected")]
    Rejected,
    #[error("notary connection: {0}")]
    Connecting(#[from] wtransport::error::ConnectingError),
    #[error("notary session: {0}")]
    Connection(#[from] wtransport::error::ConnectionError),
    #[error("notary stream: {0}")]
    StreamOpening(#[from] wtransport::error::StreamOpeningError),
    #[error("certificate hash is not 64 lowercase hex digits: {0:?}")]
    CertificateHash(String),
    #[error("invalid name {0:?}")]
    Name(String),
    #[error("logging: {0}")]
    Logging(#[from] tracing_subscriber::util::TryInitError),
    #[error("Method not found")]
    UnknownMethod,
    #[error("{detail}")]
    Problem {
        detail: String,
        problem: serde_json::Value,
    },
    #[error("unexpected argument {0:?}: paymoney reads JSON-RPC 2.0 messages, one per stdin line")]
    Usage(String),
    #[error("frame of {0} bytes exceeds the native messaging limit")]
    Frame(usize),
    #[error("no home directory")]
    Home,
    #[error("attestation request: {0}")]
    RequestBuilder(#[from] tlsn::attestation::request::RequestBuilderError),
    #[error("attestation request config: {0}")]
    RequestConfig(#[from] tlsn::attestation::request::RequestConfigBuilderError),
    #[error("attestation does not match the request: {0}")]
    Validation(#[from] tlsn::attestation::request::AttestationValidationError),
    #[error("transcript commitments: {0}")]
    Commit(#[from] tlsn::transcript::TranscriptCommitConfigBuilderError),
    #[error("hash provider: {0}")]
    HashProvider(#[from] tlsn::hash::HashProviderError),
}
