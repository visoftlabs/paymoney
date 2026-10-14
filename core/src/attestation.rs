//! The tlsn attestation fields the leaf recomputes, byte for byte: BCS encodings, 16-byte type
//! domains, the Merkle tree over field hashes and the signed header. All hashes are tlsn hash
//! algorithm 128 ([`tlsn_hash`]).

use crate::{
    engine::{HASH_BYTES, HEADER, hash, pack, tlsn_hash},
    patterns::REQUEST_HEAD,
    statement::Digest,
    xmss::{Block, KEY_BYTES, PublicKey},
};

/// tlsn algorithm IDs: hash 128, XMSS key and signature 128.
pub const ALGORITHM: u8 = 0x80;
/// The extension the notary adds with the server name it verified.
pub const SERVER_NAME: &[u8] = b"server_name";
pub const SERVER: &[u8] = b"app.revolut.com";
/// The committed head the leaf opens, around the transaction's UUID.
pub const REQUEST: [&[u8]; 2] = [
    b"GET /api/retail/transaction/",
    b" HTTP/1.1\r\nhost: app.revolut.com\r\nconnection: close\r\naccept-encoding: identity\r\n",
];
pub const UUID: usize = 36;
/// Bytes of an attestation uid and of a commitment blinder.
pub const UID_BYTES: usize = 16;
pub const BLINDER_BYTES: usize = 16;
/// Field ids the leaf takes as given: connection info, ephemeral key, certificate.
pub const OPAQUE: [usize; 3] = [1, 2, 3];
/// BCS of the `alg` and length that open a `VerifyingKey` and a `TypedHash`.
pub(crate) const KEY_PREFIX: [u8; 2] = [ALGORITHM, KEY_BYTES as u8];
pub(crate) const HASH_PREFIX: [u8; 2] = [ALGORITHM, HASH_BYTES as u8];
/// BCS of `Header::version`, a `u32` zero.
pub(crate) const VERSION: [u8; 4] = [0; 4];
pub const REQUEST_LEN: usize = REQUEST[0].len() + UUID + REQUEST[1].len();
/// Leaves in field-id order: key, connection, ephemeral key, certificate, extension, sent,
/// received.
pub const LEAVES: usize = 7;

// PROOF: tlsn's `impl_domain_separator!` domains, the first 16 bytes of BLAKE3 of each type's path
// as written; a wrong byte makes every real attestation fail to prove.
pub(crate) const VERIFYING_KEY: [u8; 16] = [
    0xae, 0xc3, 0x7d, 0x45, 0xb9, 0x9c, 0x4e, 0x4b, 0x63, 0x77, 0x06, 0xb1, 0xe9, 0x78, 0xa3, 0xeb,
];
const EXTENSION: [u8; 16] = [
    0x67, 0xed, 0x56, 0x7f, 0x31, 0x2c, 0xa4, 0x82, 0xb9, 0xf3, 0x65, 0xcc, 0x27, 0x1b, 0xaa, 0x42,
];
pub(crate) const TRANSCRIPT_COMMITMENT: [u8; 16] = [
    0xbd, 0x0a, 0xb9, 0xac, 0x6e, 0xa9, 0x3e, 0xbd, 0xa2, 0x50, 0x0e, 0x87, 0x69, 0xe6, 0x3a, 0x9e,
];

/// The transaction id in `head`, if it is the transaction-details head the leaf opens.
pub fn transaction(head: &[u8]) -> Option<&[u8]> {
    Some(REQUEST_HEAD.captures(head)?.get(1)?.as_bytes())
}

/// BCS of `VerifyingKey { alg, data }`: algorithm, length, key bytes.
pub(crate) fn key_bytes(key: &PublicKey) -> Vec<u8> {
    [&KEY_PREFIX[..], &key.to_bytes()].concat()
}
pub fn key_leaf(key: &PublicKey) -> [u8; HASH_BYTES] {
    tlsn_hash(&[&VERIFYING_KEY[..], &key_bytes(key)].concat())
}
/// The notary's identity in statements: its key's attestation field hash as words.
pub fn notary(key: &PublicKey) -> Digest {
    let mut words = [0; 8];
    for (word, bytes) in words.iter_mut().zip(key_leaf(key).as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    Digest(words)
}

pub(crate) fn extension_bytes() -> Vec<u8> {
    [
        &[SERVER_NAME.len() as u8],
        SERVER_NAME,
        &[SERVER.len() as u8],
        SERVER,
    ]
    .concat()
}
pub fn extension_leaf() -> [u8; HASH_BYTES] {
    tlsn_hash(&[&EXTENSION[..], &extension_bytes()].concat())
}

/// BCS of `TranscriptCommitment::Hash` over `[0, end)` of `direction` (0 sent, 1 received).
pub(crate) fn commitment_bytes(direction: u8, end: u64, digest: &[u8; HASH_BYTES]) -> Vec<u8> {
    let range = [0u64.to_le_bytes(), end.to_le_bytes()].concat();
    [&[0, direction, 1][..], &range, &HASH_PREFIX, digest].concat()
}
pub fn commitment_leaf(
    direction: u8,
    data: &[u8],
    blinder: &[u8; BLINDER_BYTES],
) -> [u8; HASH_BYTES] {
    let digest = tlsn_hash(&[data, blinder].concat());
    let bytes = commitment_bytes(direction, data.len() as u64, &digest);
    tlsn_hash(&[&TRANSCRIPT_COMMITMENT[..], &bytes].concat())
}

/// rs_merkle's root: pairs hashed as `H(left ‖ right)`, an odd last node promoted.
pub fn root(leaves: &[[u8; HASH_BYTES]]) -> [u8; HASH_BYTES] {
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        level = level
            .chunks(2)
            .map(|pair| match pair {
                [left, right] => tlsn_hash(&[*left, *right].concat()),
                [single] => *single,
                _ => [0; 32],
            })
            .collect();
    }
    level.first().copied().unwrap_or_default()
}

/// BCS of `Header { id, version: 0, root: TypedHash { alg, value } }`: the signed message.
pub fn header(uid: &[u8; UID_BYTES], root: &[u8; HASH_BYTES]) -> Vec<u8> {
    [&uid[..], &VERSION, &HASH_PREFIX, root].concat()
}

/// The XMSS message of a signed header.
pub(crate) fn message(header: &[u8]) -> Block {
    hash(HEADER, &pack(header))
}
