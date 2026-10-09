//! PayMoney proofs: one leaf proof per notarized transaction leg, aggregated by a verifier set
//! into a root stating the signed sum and count of distinct legs.

pub mod attestation;
mod circuits;
mod engine;
mod identity;
mod json;
mod leaf;
mod patterns;
mod progress;
mod shape;
mod statement;
mod xmss;

pub use circuits::{Aggregate, Circuits, LegProof, Member};
pub use engine::{TLSN_DOMAIN, tlsn_hash};
pub use leaf::{Attested, MAX_RESPONSE};
pub use progress::Progress;
pub use statement::{Amount, Count, Currency, Digest, Key, Leg, Statement, Verdict};
pub use xmss::{PublicKey, SecretKey, Signature};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid circuit or proof shape")]
    Shape,
    #[error("wrap and merge verifiers differ; recalibrate the layout")]
    Layout,
    #[error("statement belongs to another verifier set")]
    Set,
    #[error("legs differ in notary or currency")]
    Mismatch,
    #[error("non-canonical statement word")]
    Canonical,
    #[error("invalid currency code {0:?}")]
    Currency(String),
    #[error("keys are not strictly increasing: {0} then {1}")]
    Order(Key, Key),
    #[error("amount {0} is outside ±10^9 minor units")]
    Amount(i64),
    #[error("nothing to aggregate")]
    Empty,
    #[error("the committed request is not the transaction-details request the leaf opens")]
    Request,
    #[error("the response is not a notarized transaction-details response")]
    Response,
    #[error("the response holds no leg with that legId")]
    Leg,
    #[error("only COMPLETED legs count; this one is {0}")]
    State(String),
    #[error("notary key exhausted: every XMSS epoch is used")]
    Exhausted,
    #[error("invalid XMSS signature")]
    Signature,
    #[error("cannot construct the proof configuration: {0}")]
    Config(#[from] p3_recursion::builtin_config::BuiltinConfigError),
    #[error("circuit construction failed: {0}")]
    Build(#[from] p3_circuit::CircuitBuilderError),
    #[error("invalid statement schema: {0}")]
    Schema(#[from] p3_circuit::StatementError),
    #[error("circuit execution failed: {0}")]
    Circuit(#[from] p3_circuit::CircuitError),
    #[error("proving or verification failed: {0}")]
    Proof(#[from] p3_circuit_prover::BatchStarkProverError),
    #[error("recursive verifier failed: {0}")]
    Recursion(#[from] p3_recursion::verifier::VerificationError),
    #[error("descriptor encoding failed: {0}")]
    Json(#[from] serde_json::Error),
}
