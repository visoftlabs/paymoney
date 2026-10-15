//! The prover's side of MPC-TLS: commitments (hash 128) to the request head and the whole
//! response, nothing revealed; the notary adds the verified server name and signs with XMSS.

use crate::{
    Error,
    crypto::{self, HASH, SIGNATURE},
    http::{self, Request, Response},
    server::{Client, Server},
};
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, StreamExt};
use hyper::StatusCode;
use paymoney_core::{
    Attested, Circuits, HASH_BYTES, LegProof, PublicKey, Signature,
    attestation::{BLINDER_BYTES, OPAQUE},
};
use serde::{Deserialize, Serialize};
use tlsn::{
    Mpc, Session as MpcSession, SessionHandle,
    attestation::{
        Attestation,
        request::{Request as AttestationRequest, RequestConfig},
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig,
    },
    connection::{HandshakeData, ServerName},
    prover::{
        Prover, ProverOutput,
        state::{CommitAccepted, Committed},
    },
    transcript::{
        Direction, TlsTranscript, Transcript, TranscriptCommitConfig, TranscriptCommitmentKind,
        TranscriptSecret,
    },
    webpki::RootCertStore,
};
use tokio::net::TcpStream;
use tokio_util::{
    compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt},
    io::{ReaderStream, StreamReader},
};
use tracing::{Instrument, info_span};
use uuid::Uuid;

/// Policy: the request carries the browser's cookies (a few KiB).
pub const MAX_SENT: usize = 8 * 1024;
/// The leaf circuit's response capacity.
pub const MAX_RECV: usize = paymoney_core::MAX_RESPONSE;
/// Policy: MPC bytes written ahead of the request stream before the session waits.
const BUFFER: usize = 64 * 1024;

/// A notarized transaction: the attestation, the committed bytes and their blinders. Local
/// evidence; the leaf proof keeps all of it private.
#[derive(Deserialize, Serialize)]
pub struct Record {
    pub attestation: Attestation,
    /// Bytes, not text: a chunk boundary may split a UTF-8 sequence.
    pub request: Vec<u8>,
    pub request_blinder: [u8; BLINDER_BYTES],
    pub response: Vec<u8>,
    pub response_blinder: [u8; BLINDER_BYTES],
}
impl Record {
    /// Proves the leg `leg` of this transaction from its attestation.
    pub fn prove(&self, circuits: &Circuits, leg: Uuid) -> Result<LegProof, Error> {
        let attestation = &self.attestation;
        let fields = attestation
            .body
            .hash_fields(crypto::provider().hash.get(&HASH)?);
        let opaque = |id: usize| -> Result<[u8; HASH_BYTES], Error> {
            let (_, hash) = fields.get(id).ok_or(Error::FieldHash(id))?;
            hash.as_bytes().try_into().or(Err(Error::FieldHash(id)))
        };
        let [connection, ephemeral_key, certificate] = OPAQUE.map(opaque);
        let attested = Attested {
            key: PublicKey::from_bytes(&attestation.body.verifying_key().data)?,
            signature: Signature::from_bytes(&attestation.signature.data)?,
            uid: attestation.header.id.0,
            opaque: [connection?, ephemeral_key?, certificate?],
            request: &self.request,
            request_blinder: self.request_blinder,
            response: &self.response,
            response_blinder: self.response_blinder,
        };
        let leg = leg.hyphenated().to_string();
        Ok(circuits.prove_leg(&attested, leg.as_bytes())?)
    }
}

/// Sends `request` through MPC-TLS and has its committed head and the response attested by
/// `server`'s notary; a record only for a 200, the one status the leaf opens. The notary
/// connection, the MPC session and the protocol run together and end together.
pub async fn notarize(
    request: &Request,
    server: &Server,
    client: &Client,
) -> Result<(Option<Record>, Response), Error> {
    let (unsent, writes) = tokio::io::simplex(BUFFER);
    let (notary, connection) = client
        .post(server, "api/notary")
        .body(ReaderStream::new(unsent).boxed())
        .send()
        .instrument(info_span!("connect"))
        .await?;
    let committed = request.committed();
    let notarization = async {
        let reads = StreamReader::new(notary.await?.error_for_status()?.bytes_stream());
        let (driver, mut handle) = MpcSession::new(tokio::io::join(reads, writes).compat()).split();
        let protocol = async {
            let prover = preprocess(&mut handle).await?;
            let (prover, response) = exchange(prover, request).await?;
            let proven = prove(prover, &committed).await?;
            handle.close();
            Ok::<_, Error>((proven, response))
        };
        let (mut socket, (proven, response)) =
            tokio::try_join!(async { Ok(driver.await?) }, protocol)?;
        let (transcript, tls, output, config) = proven;
        let attestation =
            request_attestation(&mut socket, request, &transcript, &tls, &output, &config).await?;
        Ok::<_, Error>((attestation, transcript, output, response))
    };
    let ((), (attestation, transcript, output, response)) =
        tokio::try_join!(connection, notarization)?;
    tracing::info!(
        event.name = "session.notarized",
        server.address = request.host(),
        http.response.status_code = response.status
    );
    if response.status != StatusCode::OK {
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
            .ok_or(Error::NoBlinder(direction))
    };
    let record = Record {
        attestation,
        request: committed,
        request_blinder: blinder(Direction::Sent)?,
        response: transcript.received().to_vec(),
        response_blinder: blinder(Direction::Received)?,
    };
    Ok((Some(record), response))
}

/// MPC preprocessing with the notary, within the transcript limits.
#[tracing::instrument(skip_all)]
async fn preprocess(handle: &mut SessionHandle) -> Result<Prover<CommitAccepted<Mpc>>, Error> {
    let mpc = MpcTlsConfig::builder()
        .max_sent_data(MAX_SENT)
        .max_recv_data(MAX_RECV)
        .build()?;
    Ok(handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(mpc)
        .await?)
}

/// The TLS connection to the request's host and the HTTP exchange, both under MPC; the prover
/// runs beside the exchange.
#[tracing::instrument(skip_all, fields(server.address = request.host()))]
async fn exchange(
    prover: Prover<CommitAccepted<Mpc>>,
    request: &Request,
) -> Result<(Prover<Committed>, Response), Error> {
    let tcp = TcpStream::connect(request.address()).await?;
    tcp.set_nodelay(true)?;
    let tls = TlsClientConfig::builder()
        .server_name(ServerName::Dns(request.host().try_into()?))
        .root_store(RootCertStore::mozilla())
        .build()?;
    let (connection, prover) = prover.connect(tls, tcp.compat())?;
    // The protocol finishes whatever the status, so the notary sees a closed session.
    Ok(tokio::try_join!(
        async { Ok(prover.await?) },
        http::send(connection.compat(), request)
    )?)
}

/// Commitments to the committed head and the whole response, proven to the notary: the
/// transcript, the TLS transcript, the prover's output and the attestation request config.
#[tracing::instrument(skip_all)]
async fn prove(
    mut prover: Prover<Committed>,
    committed: &[u8],
) -> Result<(Transcript, TlsTranscript, ProverOutput, RequestConfig), Error> {
    let transcript = prover.transcript().clone();
    if !transcript.sent().starts_with(committed) {
        return Err(Error::NotCommitted);
    }
    let mut commit = TranscriptCommitConfig::builder(&transcript);
    commit.default_kind(TranscriptCommitmentKind::Hash { alg: HASH });
    commit.commit_sent(&(0..committed.len()))?;
    commit.commit_recv(&(0..transcript.received().len()))?;
    let commit = commit.build()?;
    let mut config = RequestConfig::builder();
    config
        .signature_alg(SIGNATURE)
        .hash_alg(HASH)
        .transcript_commit(commit.clone());
    let config = config.build()?;
    let mut prove = ProveConfig::builder(&transcript);
    prove.server_identity().transcript_commit(commit);
    let output = prover.prove(&prove.build()?).await?;
    let tls = prover.tls_transcript().clone();
    prover.close().await?;
    Ok((transcript, tls, output, config))
}

/// The attestation request, sent on `socket` once MPC-TLS has ended, and the notary's
/// attestation, checked against it.
#[tracing::instrument(skip_all)]
async fn request_attestation(
    socket: &mut (impl AsyncRead + AsyncWrite + Unpin),
    request: &Request,
    transcript: &Transcript,
    tls: &TlsTranscript,
    output: &ProverOutput,
    config: &RequestConfig,
) -> Result<Attestation, Error> {
    let provider = crypto::provider();
    let mut builder = AttestationRequest::builder(config);
    builder
        .server_name(ServerName::Dns(request.host().try_into()?))
        .handshake_data(HandshakeData {
            certs: tls.server_cert_chain().ok_or(Error::NoHandshake)?.to_vec(),
            sig: tls.server_signature().ok_or(Error::NoHandshake)?.clone(),
            binding: tls.certificate_binding().clone(),
        })
        .transcript(transcript.clone())
        .transcript_commitments(
            output.transcript_secrets.clone(),
            output.transcript_commitments.clone(),
        );
    let (attestation_request, _) = builder.build(&provider)?;
    socket
        .write_all(&serde_json::to_vec(&attestation_request)?)
        .await?;
    socket.close().await?;
    let mut attestation = Vec::new();
    socket.read_to_end(&mut attestation).await?;
    let attestation: Attestation = serde_json::from_slice(&attestation)?;
    attestation_request.validate(&attestation, &provider)?;
    Ok(attestation)
}
