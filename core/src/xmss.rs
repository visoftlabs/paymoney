//! Generalized XMSS with target-sum Winternitz chains (Drake, Khovratovich, Kudinov, Wagner,
//! ePrint 2025/055) over the tagged Poseidon2 sponge; the leaf circuit verifies it in-circuit.

use crate::{
    Error,
    attestation::message,
    engine::{F, XMSS_CHAIN, XMSS_LEAF, XMSS_MESSAGE, XMSS_PRF, XMSS_TREE, hash},
};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use rayon::prelude::*;

// PROOF: leanSig `target_sum` encoding, chunk size 4: 39 base-16 chains, sum at expectation.
pub(crate) const CHAINS: usize = 39;
pub(crate) const BASE: usize = 16;
pub(crate) const TARGET_SUM: usize = 293;
/// Policy: 1024 signatures per key; key generation and signing rebuild the tree in ~1 s.
pub(crate) const LOG_LIFETIME: usize = 10;
/// Digest words carrying digits: six base-16 digits from the low 24 bits of each.
pub(crate) const DIGEST_WORDS: usize = CHAINS.div_ceil(6);
/// Signature words: epoch, randomness, chain nodes, authentication path.
pub(crate) const SIGNATURE_WORDS: usize = 1 + 8 * (1 + CHAINS + LOG_LIFETIME);

pub(crate) type Block = [F; 8];
pub(crate) type Parameter = [F; 4];

/// Public key: the tweak parameter and the Merkle root over all one-time keys.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PublicKey {
    pub(crate) parameter: Parameter,
    pub(crate) root: Block,
}

/// Secret key: a PRF seed and the public key it generates.
pub struct SecretKey {
    seed: Block,
    public: PublicKey,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature {
    pub(crate) epoch: u32,
    pub(crate) randomness: Block,
    pub(crate) chains: Vec<Block>,
    pub(crate) path: Vec<Block>,
}

/// Tweak block: the key's parameter followed by three position words.
pub(crate) fn tweak(parameter: &Parameter, a: u32, b: u32, c: u32) -> Block {
    let [p0, p1, p2, p3] = *parameter;
    [
        p0,
        p1,
        p2,
        p3,
        F::from_u32(a),
        F::from_u32(b),
        F::from_u32(c),
        F::ZERO,
    ]
}

fn walk(
    parameter: &Parameter,
    epoch: u32,
    chain: u32,
    from: u32,
    steps: u32,
    node: Block,
) -> Block {
    (from + 1..=from + steps).fold(node, |node, position| {
        hash(
            XMSS_CHAIN,
            &[tweak(parameter, epoch, chain, position), node].concat(),
        )
    })
}

fn start(seed: &Block, epoch: u32, chain: u32) -> Block {
    let position = [epoch, chain, 0, 0, 0, 0, 0, 0].map(F::from_u32);
    hash(XMSS_PRF, &[*seed, position].concat())
}

fn leaf(parameter: &Parameter, epoch: u32, ends: impl Iterator<Item = Block>) -> Block {
    let input = std::iter::once(tweak(parameter, epoch, 0, 0))
        .chain(ends)
        .flatten()
        .collect::<Vec<_>>();
    hash(XMSS_LEAF, &input)
}

fn node(parameter: &Parameter, level: u32, index: u32, left: Block, right: Block) -> Block {
    hash(
        XMSS_TREE,
        &[tweak(parameter, level, index, 0), left, right].concat(),
    )
}

fn digest(parameter: &Parameter, epoch: u32, randomness: &Block, message: &Block) -> Block {
    hash(
        XMSS_MESSAGE,
        &[tweak(parameter, epoch, 0, 0), *randomness, *message].concat(),
    )
}

/// Base-16 digits of a randomized digest, if its digit words decompose canonically and the
/// digits hit the target sum; equal sums make codewords incomparable.
fn digits(digest: &Block) -> Option<[u32; CHAINS]> {
    let words = digest
        .iter()
        .take(DIGEST_WORDS)
        .map(|word| word.as_canonical_u32());
    // The circuit decomposes each word into 31 bits; p - 1 is the only value with all of 24..31 set.
    if words.clone().any(|word| word >> 24 == 0x7f) {
        return None;
    }
    let mut digits = [0; CHAINS];
    let all = words.flat_map(|word| (0..6).map(move |index| (word >> (4 * index)) & 0xf));
    for (digit, value) in digits.iter_mut().zip(all) {
        *digit = value;
    }
    (digits.iter().sum::<u32>() == TARGET_SUM as u32).then_some(digits)
}

fn random_block() -> Block {
    rand::random::<[u32; 8]>().map(F::from_u32)
}

impl SecretKey {
    pub fn generate() -> Self {
        let seed = random_block();
        let parameter = rand::random::<[u32; 4]>().map(F::from_u32);
        let root = Self::tree(&seed, &parameter, 0).root;
        Self {
            seed,
            public: PublicKey { parameter, root },
        }
    }

    /// Leaves, then levels to the root; returns the root and `epoch`'s authentication path.
    fn tree(seed: &Block, parameter: &Parameter, epoch: u32) -> PublicKeyPath {
        let mut level = (0..1u32 << LOG_LIFETIME)
            .into_par_iter()
            .map(|epoch| {
                let ends = (0..CHAINS as u32).map(|chain| {
                    walk(
                        parameter,
                        epoch,
                        chain,
                        0,
                        BASE as u32 - 1,
                        start(seed, epoch, chain),
                    )
                });
                leaf(parameter, epoch, ends)
            })
            .collect::<Vec<_>>();
        let mut path = Vec::with_capacity(LOG_LIFETIME);
        for height in 0..LOG_LIFETIME as u32 {
            path.push(
                level
                    .get(((epoch >> height) ^ 1) as usize)
                    .copied()
                    .unwrap_or_default(),
            );
            level = level
                .as_chunks::<2>()
                .0
                .par_iter()
                .enumerate()
                .map(|(index, [left, right])| {
                    node(parameter, height + 1, index as u32, *left, *right)
                })
                .collect();
        }
        PublicKeyPath {
            root: level.first().copied().unwrap_or_default(),
            path,
        }
    }

    pub fn public(&self) -> PublicKey {
        self.public
    }

    /// Signs an attestation header with the one-time key of `epoch`; never reuse an epoch.
    pub fn sign_header(&self, epoch: u32, header: &[u8]) -> Result<Signature, Error> {
        self.sign(epoch, &message(header))
    }

    fn sign(&self, epoch: u32, message: &Block) -> Result<Signature, Error> {
        if epoch >> LOG_LIFETIME != 0 {
            return Err(Error::Exhausted);
        }
        let parameter = &self.public.parameter;
        let (randomness, digits) = loop {
            let randomness = random_block();
            if let Some(digits) = digits(&digest(parameter, epoch, &randomness, message)) {
                break (randomness, digits);
            }
        };
        let chains = (0..CHAINS as u32)
            .zip(digits)
            .map(|(chain, digit)| {
                walk(
                    parameter,
                    epoch,
                    chain,
                    0,
                    digit,
                    start(&self.seed, epoch, chain),
                )
            })
            .collect();
        Ok(Signature {
            epoch,
            randomness,
            chains,
            path: Self::tree(&self.seed, parameter, epoch).path,
        })
    }

    /// `seed ‖ parameter` as canonical words; the root is recomputed on load.
    pub fn to_words(&self) -> Vec<u32> {
        let parameter = self.public.parameter.iter();
        self.seed
            .iter()
            .chain(parameter)
            .map(PrimeField32::as_canonical_u32)
            .collect()
    }
    pub fn from_words(words: &[u32]) -> Result<Self, Error> {
        let words = canonical(words)?;
        let (seed, parameter) = words.split_first_chunk::<8>().ok_or(Error::Shape)?;
        let parameter: Parameter = parameter.try_into().or(Err(Error::Shape))?;
        let root = Self::tree(seed, &parameter, 0).root;
        Ok(Self {
            seed: *seed,
            public: PublicKey { parameter, root },
        })
    }
}

struct PublicKeyPath {
    root: Block,
    path: Vec<Block>,
}

fn canonical(words: &[u32]) -> Result<Vec<F>, Error> {
    words
        .iter()
        .map(|word| match *word < F::ORDER_U32 {
            true => Ok(F::from_u32(*word)),
            false => Err(Error::Canonical),
        })
        .collect()
}

impl PublicKey {
    /// `parameter ‖ root` as 48 little-endian bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let parameter = self.parameter.iter();
        parameter
            .chain(&self.root)
            .flat_map(|word| word.as_canonical_u32().to_le_bytes())
            .collect()
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let bytes = <&[u8; 48]>::try_from(bytes).or(Err(Error::Shape))?;
        let words = bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|chunk| u32::from_le_bytes(*chunk))
            .collect::<Vec<_>>();
        let words = canonical(&words)?;
        let (parameter, root) = words.split_first_chunk::<4>().ok_or(Error::Shape)?;
        Ok(Self {
            parameter: *parameter,
            root: root.try_into().or(Err(Error::Shape))?,
        })
    }

    pub fn verify_header(&self, header: &[u8], signature: &Signature) -> Result<(), Error> {
        self.verify(&message(header), signature)
    }

    fn verify(&self, message: &Block, signature: &Signature) -> Result<(), Error> {
        let Signature {
            epoch,
            randomness,
            chains,
            path,
        } = signature;
        let digits = digits(&digest(&self.parameter, *epoch, randomness, message))
            .ok_or(Error::Signature)?;
        let ends = chains
            .iter()
            .zip(digits)
            .enumerate()
            .map(|(chain, (node, digit))| {
                walk(
                    &self.parameter,
                    *epoch,
                    chain as u32,
                    digit,
                    BASE as u32 - 1 - digit,
                    *node,
                )
            });
        let mut current = leaf(&self.parameter, *epoch, ends);
        for (height, sibling) in path.iter().enumerate() {
            let index = epoch >> height;
            let (left, right) = match index & 1 {
                0 => (current, *sibling),
                _ => (*sibling, current),
            };
            current = node(&self.parameter, height as u32 + 1, index >> 1, left, right);
        }
        match epoch >> LOG_LIFETIME == 0 && current == self.root {
            true => Ok(()),
            false => Err(Error::Signature),
        }
    }
}

impl Signature {
    /// `epoch ‖ randomness ‖ chains ‖ path`, each word little-endian.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.words()
            .into_iter()
            .flat_map(u32::to_le_bytes)
            .collect()
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != 4 * SIGNATURE_WORDS {
            return Err(Error::Shape);
        }
        let words = bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|chunk| u32::from_le_bytes(*chunk))
            .collect::<Vec<_>>();
        let (epoch, rest) = words.split_first().ok_or(Error::Shape)?;
        let blocks = canonical(rest)?.as_chunks::<8>().0.to_vec();
        let (randomness, rest) = blocks.split_first().ok_or(Error::Shape)?;
        let (chains, path) = rest.split_at_checked(CHAINS).ok_or(Error::Shape)?;
        Ok(Self {
            epoch: *epoch,
            randomness: *randomness,
            chains: chains.to_vec(),
            path: path.to_vec(),
        })
    }
    /// Private words of the in-circuit verifier: epoch, randomness, chains, path.
    pub(crate) fn words(&self) -> Vec<u32> {
        let blocks = self.chains.iter().chain(&self.path);
        let words = self.randomness.iter().chain(blocks.flatten());
        std::iter::once(self.epoch)
            .chain(words.map(|word| word.as_canonical_u32()))
            .collect()
    }
}
