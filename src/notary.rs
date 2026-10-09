//! The prover's side of MPC-TLS with tlsn attestations: it commits to the request head and the
//! whole response (hash 128) and reveals nothing; the notary, reached over WebTransport, adds the
//! verified server name and signs with XMSS.

use crate::{
    Error,
    crypto::{self, HASH, SIGNATURE},
    http::{self, Request, Response, Server},
    patterns::{CERTIFICATE_HASH, HEX_BYTE},
};
use futures::{AsyncReadExt, AsyncWriteExt};
use paymoney_core::{Attested, Circuits, LegProof, Progress, PublicKey, Signature, tlsn_hash};
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::{fmt, future::IntoFuture, str::FromStr};
use tlsn::{
    Session as MpcSession,
    attestation::{
        Attestation,
        request::{Request as AttestationRequest, RequestConfig},
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig,
    },
    connection::{HandshakeData, ServerName},
    transcript::{Direction, TranscriptCommitConfig, TranscriptCommitmentKind, TranscriptSecret},
};
use tokio::net::TcpStream;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use url::Url;
use uuid::Uuid;
use wtransport::{ClientConfig, Endpoint, VarInt, tls::Sha256Digest};

/// Policy: the request carries the browser's cookies (a few KiB).
pub const MAX_SENT: usize = 1 << 13;
/// The leaf circuit's response capacity.
pub const MAX_RECV: usize = paymoney_core::MAX_RESPONSE;

/// Where the notary is: its WebTransport URL and, for a self-signed certificate, that certificate's
/// SHA-256, pinned as WebTransport's `serverCertificateHashes` does; without one, the platform's
/// roots verify it.
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Notary {
    pub url: Url,
    pub certificate_hash: Option<CertificateHash>,
}

/// A certificate's SHA-256, as lowercase hex on the wire.
#[derive(Clone, Copy, SerializeDisplay, DeserializeFromStr)]
pub struct CertificateHash([u8; 32]);
impl FromStr for CertificateHash {
    type Err = Error;
    fn from_str(hex: &str) -> Result<Self, Error> {
        if !CERTIFICATE_HASH.is_match(hex) {
            return Err(Error::CertificateHash(hex.to_owned()));
        }
        let bytes = HEX_BYTE
            .find_iter(hex)
            .map(|byte| u8::from_str_radix(byte.as_str(), 16))
            .collect::<Result<Vec<_>, _>>()
            .or(Err(Error::CertificateHash(hex.to_owned())))?;
        Ok(Self(
            bytes
                .try_into()
                .or(Err(Error::CertificateHash(hex.to_owned())))?,
        ))
    }
}
impl fmt::Display for CertificateHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// The steps `notarize` logs; the caller logs the last, saving the record.
pub const NOTARIZE_STEPS: usize = 6;

/// A notarized transaction: the attestation, the committed bytes and their blinders. Local
/// evidence; the leaf proof keeps all of it private.
#[derive(Deserialize, Serialize)]
pub struct Record {
    pub attestation: Attestation,
    /// Bytes, not text: a chunk boundary may split a UTF-8 sequence.
    pub request: Vec<u8>,
    pub request_blinder: [u8; 16],
    pub response: Vec<u8>,
    pub response_blinder: [u8; 16],
}
impl Record {
    /// Proves the leg `leg` of this transaction from its attestation.
    pub fn prove(&self, circuits: &Circuits, leg: Uuid) -> Result<LegProof, Error> {
        let attestation = &self.attestation;
        let fields = attestation
            .body
            .hash_fields(crypto::provider().hash.get(&HASH)?);
        let opaque = |index: usize| -> Result<[u8; 32], Error> {
            let (_, hash) = fields.get(index).ok_or(Error::Rejected)?;
            hash.as_bytes().try_into().or(Err(Error::Rejected))
        };
        let attested = Attested {
            key: PublicKey::from_bytes(&attestation.body.verifying_key().data)?,
            signature: Signature::from_bytes(&attestation.signature.data)?,
            uid: attestation.header.id.0,
            opaque: [opaque(1)?, opaque(2)?, opaque(3)?],
            request: &self.request,
            request_blinder: self.request_blinder,
            response: &self.response,
            response_blinder: self.response_blinder,
        };
        let leg = leg.hyphenated().to_string();
        Ok(circuits.prove_leg(&attested, leg.as_bytes())?)
    }
}

/// Sends `request` through MPC-TLS and has its committed head and the response attested; a record
/// only for a 200, the one status the leaf opens. Logs the first five of `NOTARIZE_STEPS`.
pub async fn notarize(
    request: &Request,
    notary: &Notary,
    server: &Server,
    progress: &mut Progress,
) -> Result<(Option<Record>, Response), Error> {
    progress.advance("notary.connecting");
    let config = ClientConfig::builder().with_bind_default();
    let config = match notary.certificate_hash {
        Some(CertificateHash(hash)) => config
            .with_server_certificate_hashes([Sha256Digest::new(hash)])
            .build(),
        None => config.with_native_certs().build(),
    };
    // The WebTransport session lives as long as this call; its one bidirectional stream carries
    // the MPC-TLS session.
    let session = Endpoint::client(config)?
        .connect(notary.url.as_str())
        .await?;
    let (send, recv) = session.open_bi().await?.await?;
    let (driver, mut handle) = MpcSession::new(tokio::io::join(recv, send).compat()).split();
    let driver = tokio::spawn(driver);
    let mpc = MpcTlsConfig::builder()
        .max_sent_data(MAX_SENT)
        .max_recv_data(MAX_RECV)
        .build()?;
    progress.advance("mpc.preprocessing");
    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(mpc)
        .await?;
    progress.advance("revolut.exchanging");
    let tcp = TcpStream::connect(&server.address).await?;
    tcp.set_nodelay(true)?;
    let server_name =
        || -> Result<ServerName, Error> { Ok(ServerName::Dns(request.host().try_into()?)) };
    let tls = TlsClientConfig::builder()
        .server_name(server_name()?)
        .root_store(server.roots.clone())
        .build()?;
    let (connection, prover) = prover.connect(tls, tcp.compat())?;
    let prover = tokio::spawn(prover.into_future());
    // The protocol finishes whatever the status, so the notary sees a closed session.
    let response = http::send(connection.compat(), request).await?;
    let mut prover = prover.await??;
    let transcript = prover.transcript().clone();
    let received = transcript.received();
    let committed = request.committed();
    if !transcript.sent().starts_with(&committed) {
        return Err(Error::Rejected);
    }
    let mut commit = TranscriptCommitConfig::builder(&transcript);
    commit.default_kind(TranscriptCommitmentKind::Hash { alg: HASH });
    commit.commit_sent(&(0..committed.len()))?;
    commit.commit_recv(&(0..received.len()))?;
    let commit = commit.build()?;
    let mut config = RequestConfig::builder();
    config
        .signature_alg(SIGNATURE)
        .hash_alg(HASH)
        .transcript_commit(commit.clone());
    let config = config.build()?;
    let mut prove = ProveConfig::builder(&transcript);
    prove.server_identity().transcript_commit(commit);
    progress.advance("commitments.proving");
    let output = prover.prove(&prove.build()?).await?;
    let tls = prover.tls_transcript().clone();
    prover.close().await?;

    progress.advance("attestation.requesting");
    let provider = crypto::provider();
    let mut builder = AttestationRequest::builder(&config);
    builder
        .server_name(server_name()?)
        .handshake_data(HandshakeData {
            certs: tls.server_cert_chain().ok_or(Error::Rejected)?.to_vec(),
            sig: tls.server_signature().ok_or(Error::Rejected)?.clone(),
            binding: tls.certificate_binding().clone(),
        })
        .transcript(transcript.clone())
        .transcript_commitments(
            output.transcript_secrets.clone(),
            output.transcript_commitments,
        );
    let (attestation_request, _) = builder.build(&provider)?;
    handle.close();
    let mut socket = driver.await??;
    socket
        .write_all(&serde_json::to_vec(&attestation_request)?)
        .await?;
    socket.close().await?;
    let mut attestation = Vec::new();
    socket.read_to_end(&mut attestation).await?;
    let attestation: Attestation = serde_json::from_slice(&attestation)?;
    attestation_request.validate(&attestation, &provider)?;
    // Everything is read: closing now, with no error, ends the notary's wait for this session.
    session.close(VarInt::MIN, b"");
    tracing::info!(
        event.name = "session.notarized",
        server.address = request.host(),
        http.response.status_code = response.status
    );
    if response.status != 200 {
        return Ok((None, response));
    }

    let blinder = |direction| {
        output
            .transcript_secrets
            .iter()
            .find_map(|secret| match secret {
                TranscriptSecret::Hash(secret) if secret.direction == direction => {
                    secret.blinder.as_bytes().try_into().ok()
                }
                _ => None,
            })
    };
    let record = Record {
        attestation,
        request: committed,
        request_blinder: blinder(Direction::Sent).ok_or(Error::Rejected)?,
        response: received.to_vec(),
        response_blinder: blinder(Direction::Received).ok_or(Error::Rejected)?,
    };
    Ok((Some(record), response))
}

/// A record's name: the hash of the committed head, so notarizing a request again replaces it.
pub fn name(request: &Request) -> String {
    let digest = tlsn_hash(&request.committed());
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
