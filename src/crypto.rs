//! tlsn plug-ins: hash algorithm 128 (Poseidon2-KoalaBear) and the XMSS signature verifier.

use paymoney_core::{PublicKey, Signature as Xmss, attestation, tlsn_hash};
use tlsn::{
    attestation::{
        CryptoProvider,
        signing::{KeyAlgId, SignatureAlgId, SignatureError, SignatureVerifier, VerifyingKey},
    },
    hash::{Hash, HashAlgId, HashAlgorithm},
};

pub const HASH: HashAlgId = HashAlgId::POSEIDON2_KOALABEAR;
pub const SIGNATURE: SignatureAlgId = SignatureAlgId::new(attestation::ALGORITHM);
pub const KEY: KeyAlgId = KeyAlgId::new(attestation::ALGORITHM);

struct Poseidon2;
impl HashAlgorithm for Poseidon2 {
    fn id(&self) -> HashAlgId {
        HASH
    }
    fn hash(&self, data: &[u8]) -> Hash {
        // PROOF: a 32-byte digest is within tlsn's 64-byte limit.
        Hash::try_from(tlsn_hash(data).to_vec()).unwrap_or_default()
    }
    fn hash_prefixed(&self, prefix: &[u8], data: &[u8]) -> Hash {
        self.hash(&[prefix, data].concat())
    }
}

struct Verifier;
impl SignatureVerifier for Verifier {
    fn alg_id(&self) -> SignatureAlgId {
        SIGNATURE
    }
    fn verify(&self, key: &VerifyingKey, msg: &[u8], sig: &[u8]) -> Result<(), SignatureError> {
        let rejected = |error: paymoney_core::Error| SignatureError::from_str(&error.to_string());
        if key.alg != KEY {
            return Err(SignatureError::from_str("not an XMSS key"));
        }
        let key = PublicKey::from_bytes(&key.data).map_err(rejected)?;
        key.verify_header(msg, &Xmss::from_bytes(sig).map_err(rejected)?)
            .map_err(rejected)
    }
}

/// tlsn's defaults plus hash 128 and the XMSS verifier; a notary adds its signer.
pub fn provider() -> CryptoProvider {
    let mut provider = CryptoProvider::default();
    provider.hash.set_algorithm(HASH, Box::new(Poseidon2));
    provider.signature.set_verifier(Box::new(Verifier));
    provider
}
