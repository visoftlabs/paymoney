//! The leaf: one leg of a Revolut transaction, proven from a tlsn attestation in zero knowledge.
//!
//! It recomputes the attestation's Merkle root from the notary key, the server-name extension and
//! both transcript commitments (re-hashed over private bytes), and verifies the notary's XMSS
//! signature on the header. The sent commitment opens to `GET /api/retail/transaction/{id}`; the
//! received one is the whole response: `HTTP/1.1 200`, a head ending at the first blank line,
//! then a JSON array closing on the last byte. A byte-serial JSON automaton (string, escape,
//! depth, top-level element) reads the leg's `id`, `legId`, `state`, `currency` and `amount`
//! right after their depth-2 keys, all in one element.

use crate::{
    Error,
    attestation::{self, LEAVES, REQUEST, REQUEST_LEN, UUID},
    circuits::{Built, base_words, equal, finish, vanish},
    engine::{self, E, F, HEADER, LEG, POSEIDON, TLSN_DOMAIN},
    json,
    patterns::{AMOUNT, HEAD_END, PLAIN_BODY, REQUEST_HEAD, STATUS_LINE},
    statement::{Amount, Currency, Key, LIMB_BITS, Leg},
    xmss::{self, BASE, CHAINS, DIGEST_WORDS, LOG_LIFETIME, PublicKey, Signature, TARGET_SUM},
};
use p3_circuit::{CircuitBuilder, ExprId, ops::Poseidon2PermCall};
use p3_field::{BasedVectorSpace, Field as _, PrimeCharacteristicRing, PrimeField32};

/// Calibrated: Revolut's head is 2.9 KB and each leg 1.2 KB; room for three legs.
pub const MAX_RESPONSE: usize = 8192;
/// Fields the leaf reads, in witness order: four strings, then the number.
const FIELDS: [&str; 5] = ["id", "legId", "state", "currency", "amount"];
pub(crate) const STATUS: &[u8] = b"HTTP/1.1 200 ";
const COMPLETED: &str = "COMPLETED";
/// Policy: |amount| < 10^9 minor units: nine digits, below 2^30 and the field modulus.
pub(crate) const MAX_DIGITS: u32 = 9;

/// What the leaf proves from; all of it stays private.
pub struct Attested<'a> {
    pub key: PublicKey,
    pub signature: Signature,
    pub uid: [u8; 16],
    /// Field hashes the leaf takes as given: connection info, ephemeral key, certificate.
    pub opaque: [[u8; 32]; 3],
    pub request: &'a [u8],
    pub request_blinder: [u8; 16],
    pub response: &'a [u8],
    pub response_blinder: [u8; 16],
}

/// The accumulator over E that names strings in-circuit: `acc·R + byte`.
fn accumulate(bytes: &[u8]) -> E {
    bytes
        .iter()
        .fold(E::ZERO, |acc, byte| acc * radix() + E::from_u8(*byte))
}
fn radix() -> E {
    E::from_basis_coefficients_fn(|i| F::from_u32(5 + 2 * i as u32))
}

/// A `legId` value's key: two words of H(LEG, its accumulator), low 24 bits each.
fn leg_key(value: &[u8]) -> Key {
    let words = engine::hash(LEG, accumulate(value).as_basis_coefficients_slice());
    let [low, high, ..] = words.map(|word| word.as_canonical_u32() & ((1 << LIMB_BITS) - 1));
    Key::from_limbs(low, high)
}

/// The response as the circuit frames it: each payload byte with its offset, and per byte the
/// zero-test hint (the inverse of the chunk bytes left after it, 0 when none). It mirrors the
/// circuit's grammar, not a general HTTP parser, so both accept the same bytes.
struct Framed {
    payload: Vec<(usize, u8)>,
    chunked: bool,
    inverses: Vec<u32>,
}

/// A plain body starts with `[`; otherwise it is chunked: hex size, CR LF, data, CR LF, and a
/// zero size ending it with CR LF. A byte-serial machine, not a pattern: a chunk's length equals
/// its declared size, which neither a regular nor a context-free grammar can state, and the
/// circuit needs its per-byte counter.
fn frame(response: &[u8]) -> Result<Framed, Error> {
    #[derive(Clone, Copy, PartialEq)]
    enum Phase {
        Size,
        SizeLf,
        Data,
        DataCr,
        DataLf,
        TrailerCr,
        TrailerLf,
        End,
    }
    let head = HEAD_END.find(response).ok_or(Error::Response)?.end();
    let body = response.get(head..).unwrap_or_default();
    let chunked = !PLAIN_BODY.is_match(body);
    let (mut phase, mut rest) = (Phase::Size, 0u32);
    let mut framed = Framed {
        payload: Vec::new(),
        chunked,
        inverses: vec![0; MAX_RESPONSE],
    };
    for (offset, byte) in (head..).zip(body.iter().copied()) {
        if !chunked {
            framed.payload.push((offset, byte));
            continue;
        }
        (phase, rest) = match (phase, byte) {
            (Phase::Size, b'\r') => (Phase::SizeLf, rest),
            (Phase::Size, _) => {
                let digit = char::from(byte).to_digit(16).ok_or(Error::Response)?;
                let size = rest
                    .checked_mul(16)
                    .and_then(|size| size.checked_add(digit));
                (Phase::Size, size.ok_or(Error::Response)?)
            }
            (Phase::SizeLf, b'\n') if rest == 0 => (Phase::TrailerCr, 0),
            (Phase::SizeLf, b'\n') => (Phase::Data, rest),
            (Phase::Data, _) => {
                framed.payload.push((offset, byte));
                // PROOF: `Data` is entered with `rest ≥ 1` and left when it reaches 0.
                match rest - 1 {
                    0 => (Phase::DataCr, 0),
                    left => (Phase::Data, left),
                }
            }
            (Phase::DataCr, b'\r') => (Phase::DataLf, 0),
            (Phase::DataLf, b'\n') => (Phase::Size, 0),
            (Phase::TrailerCr, b'\r') => (Phase::TrailerLf, 0),
            (Phase::TrailerLf, b'\n') => (Phase::End, 0),
            _ => return Err(Error::Response),
        };
        if let Some(slot) = framed.inverses.get_mut(offset)
            && rest != 0
        {
            *slot = F::from_u32(rest).inverse().as_canonical_u32();
        }
    }
    match chunked && phase != Phase::End {
        true => Err(Error::Response),
        false => Ok(framed),
    }
}

impl Attested<'_> {
    /// The leg the leaf proves and its private words, in allocation order.
    pub(crate) fn witness(&self, leg_id: &[u8]) -> Result<(Leg, Vec<u32>), Error> {
        let uuid = REQUEST_HEAD
            .captures(self.request)
            .and_then(|head| head.get(1))
            .ok_or(Error::Request)?
            .as_bytes();
        let response = self.response;
        if response.len() > MAX_RESPONSE || !STATUS_LINE.is_match(response) {
            return Err(Error::Response);
        }
        let Framed {
            payload,
            chunked,
            inverses,
        } = frame(response)?;
        let body = payload.iter().map(|(_, b)| *b).collect::<Vec<_>>();
        let leg_id = std::str::from_utf8(leg_id).or(Err(Error::Leg))?;
        let text = std::str::from_utf8(&body).or(Err(Error::Response))?;
        let fields = json::leg(text, FIELDS, leg_id)?;
        let [_, _, state, currency, amount] = fields;
        if state.text != COMPLETED {
            return Err(Error::State(state.text.to_owned()));
        }
        if !AMOUNT.is_match(amount.text) {
            return Err(Error::Response);
        }
        let minor = amount.text.parse::<i64>().or(Err(Error::Response))?;
        let leg = Leg {
            notary: attestation::notary(&self.key),
            currency: currency.text.parse::<Currency>()?,
            key: leg_key(leg_id.as_bytes()),
            amount: Amount::new(minor)?,
        };

        let mut words = Vec::new();
        let bytes =
            |words: &mut Vec<u32>, bytes: &[u8]| words.extend(bytes.iter().map(|b| u32::from(*b)));
        let key = self.key.to_bytes();
        words.extend(
            key.as_chunks::<4>()
                .0
                .iter()
                .map(|b| u32::from_le_bytes(*b)),
        );
        words.extend(self.signature.words());
        bytes(&mut words, &self.uid);
        self.opaque.iter().for_each(|leaf| bytes(&mut words, leaf));
        bytes(&mut words, uuid);
        bytes(&mut words, &self.request_blinder);
        let mut stream = [response, &self.response_blinder, &[1]].concat();
        stream.resize(MAX_RESPONSE + 17, 0);
        bytes(&mut words, &stream);
        words.extend((0..MAX_RESPONSE).map(|i| u32::from(i < response.len())));
        words.push(u32::from(chunked));
        words.extend(inverses);
        for field in fields {
            let (offset, _) = payload.get(field.at).copied().ok_or(Error::Response)?;
            words.extend((1..MAX_RESPONSE).map(|i| u32::from(i == offset)));
        }
        Ok((leg, words))
    }
}

// ---- circuit ------------------------------------------------------------------------------

/// The leaf's gadgets over the circuit builder.
trait Gadgets {
    fn constant(&mut self, value: u32) -> ExprId;
    fn constants(&mut self, bytes: &[u8]) -> Vec<ExprId>;
    fn private(&mut self, count: usize) -> Vec<ExprId>;
    fn bits(&mut self, value: ExprId, count: usize) -> Result<Vec<ExprId>, Error>;
    fn not(&mut self, value: ExprId) -> ExprId;
    fn product(&mut self, values: &[ExprId]) -> ExprId;
    fn sum(&mut self, values: &[ExprId]) -> ExprId;
    /// Σ weightᵢ·valueᵢ.
    fn weighted(&mut self, values: &[ExprId], weights: impl IntoIterator<Item = u32>) -> ExprId;
    /// Private bytes, each range-checked to 8 bits; returns the bytes and their bits.
    fn bytes(&mut self, count: usize) -> Result<(Vec<ExprId>, Vec<Vec<ExprId>>), Error>;
    fn flags(&mut self, count: usize) -> Vec<ExprId>;
    /// The canonical bits of a field word.
    fn canonical(&mut self, word: ExprId) -> Result<Vec<ExprId>, Error>;
    /// Field words as their canonical little-endian bytes.
    fn word_bytes(&mut self, words: &[ExprId]) -> Result<Vec<ExprId>, Error>;
    /// Little-endian 3-byte words.
    fn words(&mut self, bytes: &[ExprId]) -> Vec<ExprId>;
    /// Base coefficients of extension elements, each proven a base-field element.
    fn coefficients(&mut self, values: &[ExprId]) -> Result<Vec<ExprId>, Error>;
    /// tlsn hash 128 of fixed-length bytes; returns its digest bytes.
    fn tlsn_hash(&mut self, bytes: &[ExprId]) -> Result<Vec<ExprId>, Error>;
    /// The tagged sponge over base words, as [`engine::hash`].
    fn hash(&mut self, tag: u32, words: &[ExprId]) -> Result<Vec<ExprId>, Error>;
    fn accumulate(&mut self, bytes: &[ExprId]) -> ExprId;
}
impl Gadgets for CircuitBuilder<E> {
    fn constant(&mut self, value: u32) -> ExprId {
        self.define_const(E::from_u32(value))
    }
    fn constants(&mut self, bytes: &[u8]) -> Vec<ExprId> {
        bytes.iter().map(|b| self.constant(u32::from(*b))).collect()
    }
    fn private(&mut self, count: usize) -> Vec<ExprId> {
        self.alloc_private_inputs(count, "leaf witness")
    }
    fn bits(&mut self, value: ExprId, count: usize) -> Result<Vec<ExprId>, Error> {
        Ok(self.decompose_to_bits::<F>(value, count)?)
    }
    fn not(&mut self, value: ExprId) -> ExprId {
        let one = self.constant(1);
        self.sub(one, value)
    }
    fn product(&mut self, values: &[ExprId]) -> ExprId {
        let one = self.constant(1);
        values.iter().fold(one, |acc, value| self.mul(acc, *value))
    }
    fn sum(&mut self, values: &[ExprId]) -> ExprId {
        values
            .iter()
            .fold(ExprId::ZERO, |acc, value| self.add(acc, *value))
    }
    fn weighted(&mut self, values: &[ExprId], weights: impl IntoIterator<Item = u32>) -> ExprId {
        let mut acc = ExprId::ZERO;
        for (value, weight) in values.iter().zip(weights) {
            let weight = self.constant(weight);
            acc = self.mul_add(*value, weight, acc);
        }
        acc
    }
    fn bytes(&mut self, count: usize) -> Result<(Vec<ExprId>, Vec<Vec<ExprId>>), Error> {
        let bytes = self.private(count);
        let bits = bytes
            .iter()
            .map(|byte| self.bits(*byte, 8))
            .collect::<Result<_, _>>()?;
        Ok((bytes, bits))
    }
    fn flags(&mut self, count: usize) -> Vec<ExprId> {
        let flags = self.private(count);
        flags.iter().for_each(|flag| self.assert_bool(*flag));
        flags
    }
    fn canonical(&mut self, word: ExprId) -> Result<Vec<ExprId>, Error> {
        // PROOF: a full 31-bit decomposition is pinned below p by `decompose_to_bits` itself.
        self.bits(word, 31)
    }
    fn word_bytes(&mut self, words: &[ExprId]) -> Result<Vec<ExprId>, Error> {
        let mut bytes = Vec::with_capacity(4 * words.len());
        for word in words {
            let bits = self.canonical(*word)?;
            for byte in bits.chunks(8) {
                bytes.push(self.weighted(byte, (0..8).map(|i| 1 << i)));
            }
        }
        Ok(bytes)
    }
    fn words(&mut self, bytes: &[ExprId]) -> Vec<ExprId> {
        bytes
            .chunks(3)
            .map(|chunk| self.weighted(chunk, [1, 1 << 8, 1 << 16]))
            .collect()
    }
    fn coefficients(&mut self, values: &[ExprId]) -> Result<Vec<ExprId>, Error> {
        let mut words = Vec::with_capacity(4 * values.len());
        for value in values {
            let coefficients = self.decompose_ext_to_base_coeffs_via_alu::<F>(*value)?;
            base_words(self, &coefficients)?;
            words.extend(coefficients);
        }
        Ok(words)
    }
    fn tlsn_hash(&mut self, bytes: &[ExprId]) -> Result<Vec<ExprId>, Error> {
        let one = self.constant(1);
        let framed = [self.constants(TLSN_DOMAIN), bytes.to_vec(), vec![one]].concat();
        let mut words = self.words(&framed);
        words.resize(words.len().next_multiple_of(8), ExprId::ZERO);
        let packed = base_words(self, &words)?;
        let output = self.add_hash_slice(&POSEIDON, &packed, true)?;
        let words = self.coefficients(&output)?;
        self.word_bytes(&words)
    }
    fn hash(&mut self, tag: u32, words: &[ExprId]) -> Result<Vec<ExprId>, Error> {
        let packed = base_words(self, words)?;
        let output = engine::circuit_hash(self, tag, &packed)?;
        self.coefficients(&output)
    }
    fn accumulate(&mut self, bytes: &[ExprId]) -> ExprId {
        let radix = self.define_const(radix());
        bytes
            .iter()
            .fold(ExprId::ZERO, |acc, byte| self.mul_add(acc, radix, *byte))
    }
}

/// Builds the leaf; its statement is [`Leg::words`].
pub(crate) fn circuit() -> Result<Built, Error> {
    let mut builder = engine::builder()?;
    let statement = statement(&mut builder)?;
    finish(builder, &statement, Vec::new())
}

fn statement(g: &mut CircuitBuilder<E>) -> Result<Vec<ExprId>, Error> {
    // Witness, in `Attested::witness` order.
    let key = g.private(12);
    base_words(g, &key)?;
    let signature = g.private(xmss::SIGNATURE_WORDS);
    base_words(g, &signature)?;
    let (uid, _) = g.bytes(16)?;
    let (opaque, _) = g.bytes(96)?;
    let (uuid, _) = g.bytes(UUID)?;
    let (request_blinder, _) = g.bytes(16)?;
    let (stream, bits) = g.bytes(MAX_RESPONSE + 17)?;
    let mask = g.flags(MAX_RESPONSE);
    let chunked = g.flags(1);
    let chunked = chunked.first().copied().ok_or(Error::Shape)?;
    let inverses = g.private(MAX_RESPONSE);
    let selections = FIELDS
        .map(|_| [vec![ExprId::ZERO], g.flags(MAX_RESPONSE - 1)].concat())
        .to_vec();

    // The notary key's attestation field hash names the notary in the statement.
    let prefix = [
        &attestation::VERIFYING_KEY[..],
        &[attestation::ALGORITHM, 48],
    ]
    .concat();
    let key_bytes = [g.constants(&prefix), g.word_bytes(&key)?].concat();
    let notary_leaf = g.tlsn_hash(&key_bytes)?;

    let request = [
        g.constants(REQUEST[0]),
        uuid.clone(),
        g.constants(REQUEST[1]),
    ]
    .concat();
    let sent = g.tlsn_hash(&[request, request_blinder].concat())?;
    let response = response(g, &stream, &bits, &mask, chunked, &inverses, &selections)?;
    let id = g.accumulate(&uuid);
    equal(g, response.id, id);

    // Field hashes and the Merkle root, as `attestation::root`.
    let sent_end = g.constants(&(REQUEST_LEN as u64).to_le_bytes());
    let length = g.bits(response.length, 16)?;
    let mut received_end = length
        .chunks(8)
        .map(|byte| g.weighted(byte, (0..8).map(|i| 1 << i)))
        .collect::<Vec<_>>();
    received_end.extend(g.constants(&[0; 6]));
    let leaves = [
        notary_leaf.clone(),
        opaque.get(..32).ok_or(Error::Shape)?.to_vec(),
        opaque.get(32..64).ok_or(Error::Shape)?.to_vec(),
        opaque.get(64..).ok_or(Error::Shape)?.to_vec(),
        g.constants(&attestation::extension_leaf()),
        commitment(g, 0, sent_end, sent)?,
        commitment(g, 1, received_end, response.digest)?,
    ];
    let mut level = leaves.to_vec();
    debug_assert_eq!(level.len(), LEAVES);
    while level.len() > 1 {
        let mut next = Vec::new();
        for pair in level.chunks(2) {
            next.push(match pair {
                [left, right] => g.tlsn_hash(&[left.clone(), right.clone()].concat())?,
                [single] => single.clone(),
                _ => return Err(Error::Shape),
            });
        }
        level = next;
    }
    let root = level.into_iter().next().ok_or(Error::Shape)?;

    // The signed header, packed as `engine::pack`, and the notary's signature on its message.
    let separator = g.constants(&[0, 0, 0, 0, attestation::ALGORITHM, 32]);
    let marker = g.constant(1);
    let mut message = g.words(&[uid, separator, root, vec![marker]].concat());
    message.resize(message.len().next_multiple_of(4), ExprId::ZERO);
    let message = g.hash(HEADER, &message)?;
    xmss_verify(g, &key, &message, &signature)?;

    let mut statement = Vec::with_capacity(Leg::WORDS);
    for word in notary_leaf.chunks(4) {
        statement.push(g.weighted(word, [1, 1 << 8, 1 << 16, 1 << 24]));
    }
    statement.push(response.currency);
    statement.extend(response.key);
    statement.extend(response.amount);
    Ok(statement)
}

/// The field hash of a transcript commitment over `[0, end)`.
fn commitment(
    g: &mut CircuitBuilder<E>,
    direction: u8,
    end: Vec<ExprId>,
    digest: Vec<ExprId>,
) -> Result<Vec<ExprId>, Error> {
    let head = g.constants(
        &[
            &attestation::TRANSCRIPT_COMMITMENT[..],
            &[0, direction, 1],
            &[0; 8],
        ]
        .concat(),
    );
    let tail = g.constants(&[attestation::ALGORITHM, 32]);
    g.tlsn_hash(&[head, end, tail, digest].concat())
}

/// What the response yields: its length and digest, and the leg's fields.
struct Response {
    length: ExprId,
    digest: Vec<ExprId>,
    id: ExprId,
    currency: ExprId,
    key: [ExprId; 2],
    amount: [ExprId; 3],
}

/// One field's inner products with its one-hot selection, and its string capture.
#[derive(Clone, Copy)]
struct Field {
    picked: ExprId,
    ready: ExprId,
    named: ExprId,
    element: ExprId,
    opening: ExprId,
    capturing: ExprId,
    closes: ExprId,
    value: ExprId,
}
/// A field before its selection is folded in.
const UNSET: Field = Field {
    picked: ExprId::ZERO,
    ready: ExprId::ZERO,
    named: ExprId::ZERO,
    element: ExprId::ZERO,
    opening: ExprId::ZERO,
    capturing: ExprId::ZERO,
    closes: ExprId::ZERO,
    value: ExprId::ZERO,
};

/// Byte classes from the bits of one byte.
struct Classes {
    quote: ExprId,
    backslash: ExprId,
    open: ExprId,
    close: ExprId,
    comma: ExprId,
    colon: ExprId,
    cr: ExprId,
    lf: ExprId,
    minus: ExprId,
    /// High nibble 3: digits and `:;<=>?`.
    high3: ExprId,
    /// Low nibble above 9.
    above9: ExprId,
    nibble: ExprId,
    /// `0-9a-fA-F`, and its value.
    hex: ExprId,
    hex_value: ExprId,
}
impl Classes {
    fn of(g: &mut CircuitBuilder<E>, bits: &[ExprId]) -> Result<Self, Error> {
        let [b0, b1, b2, b3, b4, b5, b6, b7] =
            <[ExprId; 8]>::try_from(bits).or(Err(Error::Shape))?;
        let [n0, n1, n2, n3, n4, n5, n6, n7] = [b0, b1, b2, b3, b4, b5, b6, b7].map(|b| g.not(b));
        let (low67, high67) = (g.mul(n6, n7), g.mul(b6, n7));
        let (n4n5, n4b5, b4b5, b4n5) = (g.mul(n4, n5), g.mul(n4, b5), g.mul(b4, b5), g.mul(b4, n5));
        let (h0, h2, h3) = (g.mul(n4n5, low67), g.mul(n4b5, low67), g.mul(b4b5, low67));
        let (h5, h7) = (g.mul(b4n5, high67), g.mul(b4b5, high67));
        let (c1, c2, c3) = (g.mul(b3, n2), g.mul(b2, b3), g.mul(n2, n3));
        let (n0b1, b0b1, n0n1, b0n1) = (g.mul(n0, b1), g.mul(b0, b1), g.mul(n0, n1), g.mul(b0, n1));
        let (la, lb, lc, ld, l2) = (
            g.mul(n0b1, c1),
            g.mul(b0b1, c1),
            g.mul(n0n1, c2),
            g.mul(b0n1, c2),
            g.mul(n0b1, c3),
        );
        let brackets = g.add(h5, h7);
        let either = g.add(b1, b2);
        let both = g.mul(b1, b2);
        let either = g.sub(either, both);
        let above9 = g.mul(b3, either);
        let nibble = g.weighted(&[b0, b1, b2, b3], [1, 2, 4, 8]);
        // `a-f` and `A-F`: high nibble 6 or 4, low nibble 1..=6.
        let (none, all) = (g.mul(n0n1, n2), g.mul(b0b1, b2));
        let (some, not_all) = (g.not(none), g.not(all));
        let low16 = g.product(&[n3, some, not_all]);
        let (h4, h6) = (g.mul(n4n5, high67), g.mul(n4b5, high67));
        let letters = g.add(h4, h6);
        let letter = g.mul(letters, low16);
        let below10 = g.not(above9);
        let digit = g.mul(h3, below10);
        let hex = g.add(digit, letter);
        let nine = g.constant(9);
        let shifted = g.mul(nibble, hex);
        let hex_value = g.mul_add(letter, nine, shifted);
        Ok(Self {
            quote: g.mul(h2, l2),
            backslash: g.mul(h5, lc),
            open: g.mul(brackets, lb),
            close: g.mul(brackets, ld),
            comma: g.mul(h2, lc),
            colon: g.mul(h3, la),
            cr: g.mul(h0, ld),
            lf: g.mul(h0, la),
            minus: g.mul(h2, ld),
            high3: h3,
            above9,
            nibble,
            hex,
            hex_value,
        })
    }
}

/// The response: framing, digest, the chunk framing and the JSON automaton.
fn response(
    g: &mut CircuitBuilder<E>,
    stream: &[ExprId],
    bits: &[Vec<ExprId>],
    mask: &[ExprId],
    chunked: ExprId,
    inverses: &[ExprId],
    selections: &[Vec<ExprId>],
) -> Result<Response, Error> {
    let at = |values: &[ExprId], i: usize| values.get(i).copied().unwrap_or(ExprId::ZERO);
    let one = g.constant(1);
    let length = g.sum(mask);

    // `mask` is a prefix of ones; past `length + 16` (the blinder) come the marker, then zeros.
    equal(g, at(mask, 0), one);
    let blinded = |i: usize| if i < 16 { one } else { at(mask, i - 16) };
    let mut marker = Vec::with_capacity(stream.len());
    for i in 0..stream.len() {
        if i + 1 < MAX_RESPONSE {
            let gap = g.not(at(mask, i));
            let rise = g.mul(gap, at(mask, i + 1));
            vanish(g, rise);
        }
        let previous = if i == 0 { one } else { blinded(i - 1) };
        let end = g.sub(previous, blinded(i));
        let tail = g.not(blinded(i));
        let delta = g.sub(at(stream, i), end);
        let off = g.mul(tail, delta);
        vanish(g, off);
        marker.push(end);
    }

    // Digest: a chained sponge over every block; the block holding the marker is the last.
    let domain = g.constants(TLSN_DOMAIN);
    let mut words = g.words(&domain);
    words.extend(g.words(stream));
    words.resize(words.len().next_multiple_of(8), ExprId::ZERO);
    let positions = [vec![ExprId::ZERO; TLSN_DOMAIN.len()], marker].concat();
    let blocks = words
        .chunks(8)
        .map(|block| base_words(g, block))
        .collect::<Result<Vec<_>, _>>()?;
    let mut outputs = Vec::with_capacity(blocks.len());
    for (index, block) in blocks.iter().enumerate() {
        let (_, output) = g.add_poseidon2_perm(&Poseidon2PermCall {
            config: POSEIDON,
            new_start: index == 0,
            merkle_path: false,
            mmcs_bit: None,
            mmcs_bit2: None,
            inputs: block
                .iter()
                .copied()
                .map(Some)
                .chain([None, None])
                .collect(),
            out_ctl: vec![true; 2],
            return_all_outputs: false,
            mmcs_index_sum: None,
            absorb_len: 0,
        })?;
        outputs.push(output);
    }
    let mut digest = [ExprId::ZERO; 2];
    for (block, output) in outputs.iter().enumerate() {
        let window = positions.get(24 * block..).unwrap_or_default();
        let last = g.sum(window.get(..24.min(window.len())).unwrap_or_default());
        for (slot, word) in digest.iter_mut().zip(output) {
            *slot = g.mul_add(last, word.ok_or(Error::Shape)?, *slot);
        }
    }
    let digest = g.coefficients(&digest)?;
    let digest = g.word_bytes(&digest)?;

    for (i, byte) in STATUS.iter().enumerate() {
        let expected = g.constant(u32::from(*byte));
        equal(g, at(stream, i), expected);
    }

    let classes = bits
        .iter()
        .take(MAX_RESPONSE)
        .map(|bits| Classes::of(g, bits))
        .collect::<Result<Vec<_>, _>>()?;
    let radix_less_one = g.define_const(radix() - E::ONE);
    let [two, nine, fifteen, open_bracket, quote_byte, byte_radix] =
        [2, 9, 15, u32::from(b'['), u32::from(b'"'), 255].map(|value| g.constant(value));
    let plain = g.not(chunked);
    let zero = ExprId::ZERO;

    // State before byte i. `head` stays 1 through the first CR LF CR LF. The chunk framing is a
    // one-hot phase with the remaining size `rest`; the JSON automaton reads payload bytes only.
    let mut head = one;
    let [mut size, mut size_lf, mut data_phase] = [one, zero, zero];
    let [
        mut data_cr,
        mut data_lf,
        mut trailer_cr,
        mut trailer_lf,
        mut end,
    ] = [zero; 5];
    let (mut rest, mut rest_zero) = (zero, one);
    let [mut string, mut escape, mut depth, mut element] = [zero; 4];
    let [mut accumulator, mut seen, mut closed, mut after_colon] = [zero; 4];
    let [mut run, mut number, mut digits, mut negative] = [zero; 4];
    let mut previous_data = zero;
    let mut fields = [UNSET; 5];
    let [mut currency, mut currency_length] = [zero; 2];
    for i in 0..=MAX_RESPONSE {
        // Depth tests; the close of the JSON after the previous payload byte.
        let depth_bits = g.bits(depth, 4)?;
        let [d0, d1, d2, d3] = <[ExprId; 4]>::try_from(depth_bits).or(Err(Error::Shape))?;
        let [e0, e1, e2, e3] = [d0, d1, d2, d3].map(|bit| g.not(bit));
        let upper = g.mul(e2, e3);
        let (at_one, at_two, empty) = (
            g.product(&[d0, e1, upper]),
            g.product(&[e0, d1, upper]),
            g.product(&[e0, e1, upper]),
        );
        let open = g.not(closed);
        let closing = g.product(&[previous_data, empty, open]);
        closed = g.add(closed, closing);
        if i == MAX_RESPONSE {
            break;
        }
        let x = at(stream, i);
        let c = classes.get(i).ok_or(Error::Shape)?;
        let present = at(mask, i);
        let last = g.sub(present, at(mask, i + 1));

        // Head.
        let ended = match i {
            0..=2 => zero,
            _ => {
                let window = [
                    classes.get(i - 3).ok_or(Error::Shape)?.cr,
                    classes.get(i - 2).ok_or(Error::Shape)?.lf,
                    classes.get(i - 1).ok_or(Error::Shape)?.cr,
                    c.lf,
                ];
                g.product(&window)
            }
        };
        let headless = g.not(head);
        let body = g.mul(headless, present);
        let stays = g.not(ended);
        let next_head = g.mul(head, stays);
        let in_head = g.mul(last, head);
        vanish(g, in_head);

        // Chunk framing, on chunked body bytes.
        let framed = g.mul(body, chunked);
        // One check per byte: the phases are one-hot, so the allowed classes sum to 0 or 1.
        let allowed = [
            (size, g.add(c.hex, c.cr)),
            (size_lf, c.lf),
            (data_phase, one),
            (data_cr, c.cr),
            (data_lf, c.lf),
            (trailer_cr, c.cr),
            (trailer_lf, c.lf),
        ]
        .into_iter()
        .fold(zero, |sum, (phase, class)| g.mul_add(phase, class, sum));
        let refused = g.not(allowed);
        let refused = g.mul(framed, refused);
        vanish(g, refused);
        let size_hex = g.mul(size, c.hex);
        let grown = g.mul_add(rest, fifteen, c.hex_value);
        let grown = g.mul(size_hex, grown);
        let change = g.sub(grown, data_phase);
        let next_rest = g.mul_add(framed, change, rest);
        // `next_rest == 0`, from the prover's inverse: `z = 1 − r·r⁻¹` and `r·z = 0`.
        let inverse = at(inverses, i);
        let product = g.mul(next_rest, inverse);
        let next_zero = g.not(product);
        let check = g.mul(next_rest, next_zero);
        vanish(g, check);
        let (not_zero, not_next_zero) = (g.not(rest_zero), g.not(next_zero));
        let next = [
            g.add(size_hex, data_lf),
            g.mul(size, c.cr),
            {
                let opened = g.mul(size_lf, not_zero);
                let continued = g.mul(data_phase, not_next_zero);
                g.add(opened, continued)
            },
            g.mul(data_phase, next_zero),
            data_cr,
            g.mul(size_lf, rest_zero),
            trailer_cr,
            g.add(trailer_lf, end),
        ];
        let phases = [
            size, size_lf, data_phase, data_cr, data_lf, trailer_cr, trailer_lf, end,
        ];
        let stepped = phases
            .iter()
            .zip(next)
            .map(|(phase, next)| {
                let delta = g.sub(next, *phase);
                g.mul_add(framed, delta, *phase)
            })
            .collect::<Vec<_>>();
        let ending = g.not(stepped.get(7).copied().unwrap_or(zero));
        let unfinished = g.product(&[last, chunked, ending]);
        vanish(g, unfinished);

        // Payload bytes: the whole body when plain, data-phase bytes when chunked.
        let plain_body = g.mul(body, plain);
        let chunk_data = g.mul(framed, data_phase);
        let data = g.add(plain_body, chunk_data);
        let fresh = g.not(seen);
        let first = g.mul(data, fresh);
        let bracket = g.sub(x, open_bracket);
        let bracket = g.mul(first, bracket);
        vanish(g, bracket);
        let late = g.mul(data, closed);
        vanish(g, late);

        // Strings and escapes.
        let unescaped = g.not(escape);
        let quote = g.product(&[c.quote, unescaped, data]);
        let both = g.mul(string, quote);
        let toggled = g.add(string, quote);
        let doubled = g.mul(two, both);
        let next_string = g.sub(toggled, doubled);
        // Framing bytes keep the escape: a chunk boundary may split `\"` or `\\`.
        let escaping = g.product(&[string, unescaped, c.backslash]);
        let change = g.sub(escaping, escape);
        let next_escape = g.mul_add(data, change, escape);
        let not_string = g.not(string);
        let not_quote = g.not(c.quote);
        let outside = g.product(&[data, not_string, not_quote]);

        // Depth, top-level elements and depth-2 colons.
        let moves = g.sub(c.open, c.close);
        let next_depth = g.mul_add(outside, moves, depth);
        let comma = g.product(&[outside, c.comma, at_one]);
        let next_element = g.add(element, comma);
        let colon_here = g.product(&[outside, c.colon, at_two]);
        let change = g.sub(colon_here, after_colon);
        let next_after_colon = g.mul_add(data, change, after_colon);

        // String content, accumulated and reset on each opening quote.
        let inside = g.mul(string, next_string);
        let content = g.mul(data, inside);
        let opening_quote = g.mul(quote, not_string);
        let grown = g.mul_add(accumulator, radix_less_one, x);
        let grown = g.mul_add(content, grown, accumulator);
        let kept = g.not(opening_quote);
        let next_accumulator = g.mul(kept, grown);
        let closing_quote = g.mul(quote, string);

        // Fields: selections on payload bytes right after a depth-2 colon.
        let ready = g.mul(after_colon, data);
        for (f, (field, column)) in fields.iter_mut().zip(selections).enumerate() {
            let flag = at(column, i);
            field.picked = g.add(field.picked, flag);
            field.ready = g.mul_add(flag, ready, field.ready);
            field.named = g.mul_add(flag, accumulator, field.named);
            field.element = g.mul_add(flag, element, field.element);
            if f < 4 {
                // Strings: open on the selection; the value is the content at the closing quote.
                field.opening = g.mul_add(flag, x, field.opening);
                let close = g.mul(field.capturing, closing_quote);
                field.closes = g.add(field.closes, close);
                field.value = g.mul_add(close, accumulator, field.value);
                if f == 3 {
                    let counted = g.mul(field.capturing, content);
                    let shifted = g.mul_add(currency, byte_radix, x);
                    currency = g.mul_add(counted, shifted, currency);
                    currency_length = g.add(currency_length, counted);
                }
                let opened = g.add(field.capturing, flag);
                field.capturing = g.sub(opened, close);
            }
        }

        // The amount: payload characters from its selection to the next ',' or '}'.
        let selected = at(selections.get(4).ok_or(Error::Shape)?, i);
        let running = g.add(selected, run);
        let stops = g.add(c.comma, c.close);
        let go = g.not(stops);
        let character = g.product(&[running, go, data]);
        let minus = g.mul(character, c.minus);
        let not_selected = g.not(selected);
        let late_minus = g.mul(minus, not_selected);
        vanish(g, late_minus);
        let digit = g.sub(character, minus);
        let not_digit = g.not(c.high3);
        let wrong = g.mul(digit, not_digit);
        vanish(g, wrong);
        let wrong = g.mul(digit, c.above9);
        vanish(g, wrong);
        let shifted = g.mul_add(number, nine, c.nibble);
        number = g.mul_add(digit, shifted, number);
        digits = g.add(digits, digit);
        negative = g.add(negative, minus);
        let change = g.sub(character, run);
        run = g.mul_add(data, change, run);

        seen = g.add(seen, first);
        previous_data = data;
        head = next_head;
        [
            size, size_lf, data_phase, data_cr, data_lf, trailer_cr, trailer_lf, end,
        ] = <[ExprId; 8]>::try_from(stepped).or(Err(Error::Shape))?;
        rest = next_rest;
        rest_zero = next_zero;
        (string, escape, depth, element, accumulator, after_colon) = (
            next_string,
            next_escape,
            next_depth,
            next_element,
            next_accumulator,
            next_after_colon,
        );
    }
    equal(g, closed, one);

    // Each field: one selection, on a payload byte after a depth-2 colon whose key names it,
    // all in one element; strings open there and close once.
    for (f, (field, name)) in fields.iter().zip(FIELDS).enumerate() {
        equal(g, field.picked, one);
        equal(g, field.ready, one);
        let key = g.define_const(accumulate(name.as_bytes()));
        equal(g, field.named, key);
        equal(g, field.element, fields[0].element);
        if f < 4 {
            equal(g, field.opening, quote_byte);
            equal(g, field.closes, one);
        }
    }
    let [id, leg, state, _, _] = fields.map(|field| field.value);
    let completed = g.define_const(accumulate(COMPLETED.as_bytes()));
    equal(g, state, completed);
    let three = g.constant(3);
    equal(g, currency_length, three);

    // Key: as `Key::of_leg`, from canonical bits.
    let words = g.coefficients(&[leg])?;
    let hashed = g.hash(LEG, &words)?;
    let mut key = [zero; 2];
    for (limb, word) in key.iter_mut().zip(&hashed) {
        let bits = g.canonical(*word)?;
        *limb = g.weighted(bits.get(..24).ok_or(Error::Shape)?, (0..24).map(|i| 1 << i));
    }

    // Amount: 1..=9 digits, then 72-bit two's complement limbs.
    let below = g.sub(nine, digits);
    g.bits(below, 4)?;
    let above = g.sub(digits, one);
    g.bits(above, 4)?;
    let value = g.bits(number, 30)?;
    let low = g.weighted(
        value.get(..24).ok_or(Error::Shape)?,
        (0..24).map(|i| 1 << i),
    );
    let high = g.weighted(value.get(24..).ok_or(Error::Shape)?, (0..6).map(|i| 1 << i));
    let low_bits = value.get(..24).ok_or(Error::Shape)?.to_vec();
    let low_zero = {
        let negated = low_bits.iter().map(|bit| g.not(*bit)).collect::<Vec<_>>();
        g.product(&negated)
    };
    let radix24 = g.constant(1 << 24);
    let full = g.constant((1 << 24) - 1);
    let low_negative = {
        let complement = g.sub(radix24, low);
        let nonzero = g.not(low_zero);
        g.mul(nonzero, complement)
    };
    let high_negative = {
        let complement = g.sub(full, high);
        g.add(complement, low_zero)
    };
    let amount = [
        g.select(negative, low_negative, low),
        g.select(negative, high_negative, high),
        g.mul(negative, full),
    ];
    for limb in amount {
        g.bits(limb, 24)?;
    }

    Ok(Response {
        length,
        digest,
        id,
        currency,
        key,
        amount,
    })
}

/// In-circuit `PublicKey::verify_header`, step by step.
fn xmss_verify(
    g: &mut CircuitBuilder<E>,
    key: &[ExprId],
    message: &[ExprId],
    signature: &[ExprId],
) -> Result<(), Error> {
    let (parameter, root) = key.split_at_checked(4).ok_or(Error::Shape)?;
    let (epoch, rest) = signature.split_first().ok_or(Error::Shape)?;
    let blocks = rest.chunks(8).map(<[ExprId]>::to_vec).collect::<Vec<_>>();
    let (randomness, rest) = blocks.split_first().ok_or(Error::Shape)?;
    let (chains, path) = rest.split_at_checked(CHAINS).ok_or(Error::Shape)?;
    let tweak = |a: ExprId, b: ExprId, c: ExprId| [parameter, &[a, b, c, ExprId::ZERO]].concat();
    let zero = ExprId::ZERO;

    let digest = g.hash(
        engine::XMSS_MESSAGE,
        &[
            tweak(*epoch, zero, zero),
            randomness.clone(),
            message.to_vec(),
        ]
        .concat(),
    )?;
    let mut nibbles = Vec::new();
    for word in digest.iter().take(DIGEST_WORDS) {
        // `digits` rejects p − 1, the only value with bits 24..31 all set.
        let bits = g.bits(*word, 31)?;
        let top = g.product(bits.get(24..).ok_or(Error::Shape)?);
        vanish(g, top);
        nibbles.extend(bits.chunks(4).take(6).map(<[ExprId]>::to_vec));
    }
    let mut sum = zero;
    let mut ends = Vec::with_capacity(CHAINS);
    for (chain, (node, nibble)) in chains.iter().zip(&nibbles).enumerate() {
        let digit = g.weighted(nibble, [1, 2, 4, 8]);
        sum = g.add(sum, digit);
        // Step `position` runs once the digit is below it.
        let [b0, b1, b2, b3] = <[ExprId; 4]>::try_from(nibble.as_slice()).or(Err(Error::Shape))?;
        let [n0, n1, n2, n3] = [b0, b1, b2, b3].map(|bit| g.not(bit));
        let low = [g.mul(n0, n1), g.mul(b0, n1), g.mul(n0, b1), g.mul(b0, b1)];
        let high = [g.mul(n2, n3), g.mul(b2, n3), g.mul(n2, b3), g.mul(b2, b3)];
        let mut flags = Vec::with_capacity(16);
        for high in high {
            for low in low {
                flags.push(g.mul(low, high));
            }
        }
        let chain = g.constant(chain as u32);
        let mut active = zero;
        let mut current = node.clone();
        for (position, flag) in (1..BASE as u32).zip(&flags) {
            active = g.add(active, *flag);
            let position = g.constant(position);
            let next = g.hash(
                engine::XMSS_CHAIN,
                &[tweak(*epoch, chain, position), current.clone()].concat(),
            )?;
            current = current
                .iter()
                .zip(&next)
                .map(|(kept, stepped)| g.select(active, *stepped, *kept))
                .collect();
        }
        ends.push(current);
    }
    let target = g.constant(TARGET_SUM as u32);
    equal(g, sum, target);
    let leaf = [tweak(*epoch, zero, zero), ends.concat()].concat();
    let mut current = g.hash(engine::XMSS_LEAF, &leaf)?;
    let bits = g.bits(*epoch, LOG_LIFETIME)?;
    for (height, (sibling, bit)) in path.iter().zip(&bits).enumerate() {
        let left = current
            .iter()
            .zip(sibling)
            .map(|(this, other)| g.select(*bit, *other, *this))
            .collect::<Vec<_>>();
        let right = current
            .iter()
            .zip(sibling)
            .map(|(this, other)| g.select(*bit, *this, *other))
            .collect::<Vec<_>>();
        let parent = g.weighted(
            bits.get(height + 1..).unwrap_or_default(),
            (0..).map(|i| 1 << i),
        );
        let level = g.constant(height as u32 + 1);
        current = g.hash(
            engine::XMSS_TREE,
            &[tweak(level, parent, zero), left, right].concat(),
        )?;
    }
    for (computed, expected) in current.iter().zip(root) {
        equal(g, *computed, *expected);
    }
    Ok(())
}
