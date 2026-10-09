use crate::Error;
use p3_circuit::{Circuit, CircuitBuilder, ExprId, StatementSchema, ops::Poseidon2Config};
use p3_circuit_prover::{
    BatchStarkProver, ConstraintProfile, PreparedCircuitProver, StatementAirBuilder,
    StatementPreprocessor, StatementProver, TablePacking,
};
use p3_field::{
    BasedVectorSpace, PrimeCharacteristicRing, PrimeField32, extension::BinomialExtensionField,
};
use p3_koala_bear::KoalaBear;
use p3_recursion::{
    BatchOnly, BatchStarkVerifierInputsBuilder, FriRecursionBackend, FriRecursionConfig,
    PcsRecursionBackend,
    builtin_config::{
        FriConfigV1, KoalaBearD4Poseidon2SaltedConfig, SuiteIdV1, koala_bear_d4_poseidon2_salted,
    },
    verifier::VerifierLimits,
};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use rand::{Rng, SeedableRng, TryCryptoRng, TryRng, rngs::StdRng};
use std::{
    convert::Infallible,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

pub(crate) type F = KoalaBear;
pub(crate) type E = BinomialExtensionField<F, 4>;
pub(crate) type Config = KoalaBearD4Poseidon2SaltedConfig<Salt>;
pub(crate) type Backend =
    p3_recursion::backend::FriRecursionBackendForExt<4, 16, 8, Poseidon2Config>;
pub(crate) type Inputs = BatchStarkVerifierInputsBuilder<
    Config,
    <Config as FriRecursionConfig>::Commitment,
    <Config as FriRecursionConfig>::OpeningProof,
>;

// Domain-separation tags of the tagged sponge; changing one changes every key.
pub(crate) const CIRCUIT_KEY: u32 = 0x504d_0201;
pub(crate) const VERIFIER_SET: u32 = 0x504d_0202;
pub(crate) const DESCRIPTOR: u32 = 0x504d_0203;
pub(crate) const LEG: u32 = 0x504d_0301;
pub(crate) const XMSS_PRF: u32 = 0x504d_0401;
pub(crate) const XMSS_CHAIN: u32 = 0x504d_0402;
pub(crate) const XMSS_LEAF: u32 = 0x504d_0403;
pub(crate) const XMSS_TREE: u32 = 0x504d_0404;
pub(crate) const XMSS_MESSAGE: u32 = 0x504d_0405;
/// The signed attestation header, hashed to the XMSS message.
pub(crate) const HEADER: u32 = 0x504d_0501;

/// Domain of tlsn hash algorithm 128; 30 bytes, so the input starts on a word boundary.
pub const TLSN_DOMAIN: &[u8; 30] = b"tlsn/poseidon2/koalabear/16/v1";

pub(crate) const POSEIDON: Poseidon2Config = Poseidon2Config::KOALA_BEAR_D4_W16;
// Policy: proof-client's hiding FRI profile; not a composed-security claim.
pub(crate) const FRI: FriConfigV1 = FriConfigV1::new(
    SuiteIdV1::KoalaBearD4Poseidon2SaltedFri,
    /* log_blowup */ 2,
    /* log_final_poly_len */ 6,
    /* max_log_arity */ 2,
    /* num_queries */ 56,
    /* commit_pow_bits */ 0,
    /* query_pow_bits */ 15,
    /* input_cap_height */ 0,
    /* commit_cap_height */ 0,
    /* num_random_codewords */ <E as BasedVectorSpace<F>>::DIMENSION as u32,
    /* salt_elements */ 4,
);

pub(crate) fn backend() -> Backend {
    FriRecursionBackend::<16, 8, _>::new(POSEIDON).for_extension_degree::<4>()
}

/// Hiding randomness: seeded while preparing, so every verifier derives the same preprocessing
/// commitments; OS entropy once `fresh` is set, so proofs are zero-knowledge. Child generators
/// (`from_seed`) are seeded by their parent and inherit its mode.
pub struct Salt {
    seeded: StdRng,
    fresh: Option<Arc<AtomicBool>>,
}
impl TryRng for Salt {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        Ok(self.source().next_u32())
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        Ok(self.source().next_u64())
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), Infallible> {
        self.source().fill_bytes(bytes);
        Ok(())
    }
}
impl TryCryptoRng for Salt {}
impl SeedableRng for Salt {
    type Seed = <StdRng as SeedableRng>::Seed;
    fn from_seed(seed: Self::Seed) -> Self {
        Self {
            seeded: StdRng::from_seed(seed),
            fresh: None,
        }
    }
}
impl Salt {
    /// Reseeds from the OS once the switch is set; children seeded after that inherit it.
    fn source(&mut self) -> &mut StdRng {
        if let Some(fresh) = &self.fresh
            && fresh.load(Ordering::Acquire)
        {
            self.seeded = StdRng::from_rng(&mut rand::rng());
            self.fresh = None;
        }
        &mut self.seeded
    }
}

/// The proof configuration and the switch that turns its salts fresh.
pub(crate) fn config() -> Result<(Config, Arc<AtomicBool>), Error> {
    let fresh = Arc::new(AtomicBool::new(false));
    let salt = |seed| Salt {
        seeded: StdRng::seed_from_u64(seed),
        fresh: Some(Arc::clone(&fresh)),
    };
    let config = koala_bear_d4_poseidon2_salted(
        &FRI,
        &VerifierLimits::default(),
        salt(0),
        salt(1),
        salt(2),
    )?;
    Ok((config, fresh))
}

pub(crate) fn builder() -> Result<CircuitBuilder<E>, Error> {
    let mut builder = CircuitBuilder::new();
    config()?.0.prepare_circuit_for_verification(&mut builder)?;
    Ok(builder)
}

pub(crate) fn packing() -> TablePacking {
    // Policy: upstream's binomial-D4 packing.
    TablePacking::new(1, 3)
        .with_horner_pack_k(4)
        .with_fri_params(FRI.log_final_poly_len() as usize, FRI.log_blowup() as usize)
}

pub(crate) fn prepare(
    circuit: &Circuit<E>,
    schema: &StatementSchema,
    packing: TablePacking,
) -> Result<PreparedCircuitProver<Config>, Error> {
    let (config, fresh) = config()?;
    let mut prover = BatchStarkProver::new(config).with_table_packing(packing);
    for table in
        <Backend as PcsRecursionBackend<Config, BatchOnly, 4>>::non_primitive_provers(&backend(), 4)
    {
        prover.register_table_prover(table);
    }
    prover.register_table_prover(Box::new(StatementProver::<4>::new(schema.clone())));
    let mut preprocessors =
        <Backend as PcsRecursionBackend<Config, BatchOnly, 4>>::non_primitive_preprocessors(
            &backend(),
        );
    let mut airs =
        <Backend as PcsRecursionBackend<Config, BatchOnly, 4>>::non_primitive_air_builders(
            &backend(),
        );
    preprocessors.push(Box::new(StatementPreprocessor::new(schema.clone())));
    airs.push(Box::new(StatementAirBuilder::<4>::new(schema.clone())));
    let prepared = prover.prepare_circuit::<E, 4>(
        circuit,
        &preprocessors,
        &airs,
        ConstraintProfile::Standard,
    )?;
    fresh.store(true, Ordering::Release);
    Ok(prepared)
}

fn sponge(words: impl IntoIterator<Item = F>) -> [F; 8] {
    PaddingFreeSponge::<_, 16, 8, 8>::new(p3_koala_bear::default_koalabear_poseidon2_16())
        .hash_iter(words)
}

/// Native tagged sponge; [`circuit_hash`] computes the same digest in-circuit.
pub(crate) fn hash(tag: u32, words: &[F]) -> [F; 8] {
    let domain = [F::from_u32(tag), F::from_usize(words.len())];
    sponge(
        domain
            .into_iter()
            .chain([F::ZERO; 6])
            .chain(words.iter().copied()),
    )
}

/// tlsn hash algorithm 128 (`mpz_hash::poseidon2_koalabear`): `TLSN_DOMAIN ‖ bytes ‖ 0x01` as
/// little-endian 3-byte words, zero-filled to whole rate blocks, through the overwrite sponge;
/// the digest is the 8 rate words, little-endian.
pub fn tlsn_hash(bytes: &[u8]) -> [u8; 32] {
    let mut words = words(&[TLSN_DOMAIN, bytes, &[1]].concat());
    words.resize(words.len().next_multiple_of(8), F::ZERO);
    let mut bytes = [0; 32];
    for (out, word) in bytes.as_chunks_mut::<4>().0.iter_mut().zip(sponge(words)) {
        *out = word.as_canonical_u32().to_le_bytes();
    }
    bytes
}

fn words(bytes: &[u8]) -> Vec<F> {
    bytes
        .chunks(3)
        // PROOF: three bytes fit below the KoalaBear modulus.
        .map(|chunk| {
            F::from_u32(
                chunk
                    .iter()
                    .rev()
                    .fold(0, |word, byte| word << 8 | u32::from(*byte)),
            )
        })
        .collect()
}

/// `bytes ‖ 0x01` as little-endian 3-byte words, zero-padded to whole extension elements.
pub(crate) fn pack(bytes: &[u8]) -> Vec<F> {
    let mut words = words(&[bytes, &[1]].concat());
    words.resize(words.len().next_multiple_of(4), F::ZERO);
    words
}

pub(crate) fn circuit_hash(
    builder: &mut CircuitBuilder<E>,
    tag: u32,
    input: &[ExprId],
) -> Result<[ExprId; 2], Error> {
    let first = E::from_basis_coefficients_slice(&[
        F::from_u32(tag),
        F::from_usize(input.len() * 4),
        F::ZERO,
        F::ZERO,
    ])
    .ok_or(Error::Shape)?;
    let prefix = [builder.define_const(first), builder.define_const(E::ZERO)];
    let targets = prefix
        .into_iter()
        .chain(input.iter().copied())
        .collect::<Vec<_>>();
    builder
        .add_hash_slice(&POSEIDON, &targets, true)?
        .try_into()
        .or(Err(Error::Shape))
}
