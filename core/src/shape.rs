use crate::{
    Error,
    engine::{Config, E, F, FRI, Inputs, POSEIDON},
};
use p3_batch_stark::{
    BatchCommitments, BatchOpenedValues, BatchProof, proof::OpenedValuesWithLookups,
};
use p3_circuit::{CircuitBuilder, NonPrimitiveOpId};
use p3_circuit_prover::CircuitVerifier;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{BatchMultiOpening, CommitPhaseMultiStep, FriProof, fold_schedule};
use p3_lookup::{LookupTerminal, logup::LogUpGadget};
use p3_merkle_tree::PrunedMerklePaths;
use p3_recursion::{
    FriRecursionConfig, RecursiveAir,
    verifier::{trusted_batch_tables, verify_batch_circuit},
};
use p3_uni_stark::{OpenedValues, PreprocessedOpenedValues};

/// Verifier inputs of the trusted shape of `verifier`'s proofs, which `bind` ties to trusted
/// preprocessing; zero values are allocation placeholders.
pub(crate) fn allocate(
    builder: &mut CircuitBuilder<E>,
    verifier: &CircuitVerifier<Config>,
    public_count: usize,
    bind: impl FnOnce(&mut CircuitBuilder<E>, &Inputs) -> Result<(), Error>,
) -> Result<(Inputs, Vec<NonPrimitiveOpId>), Error> {
    let tables = trusted_batch_tables::<Config, 4>(verifier, &vec![F::ZERO; public_count])?;
    let common = verifier.common_data();
    let degrees = verifier.relation().trace_degree_bits();
    let mut instances = Vec::new();
    let mut random = Vec::new();
    let mut main = Vec::new();
    let mut quotient = Vec::new();
    let mut permutation = Vec::new();
    let mut terminals = Vec::new();
    let gadget = LogUpGadget::new();
    for (index, (air, &degree)) in tables.airs.iter().zip(degrees).enumerate() {
        let pre = common
            .preprocessed
            .as_ref()
            .and_then(|global| global.instances.get(index))
            .and_then(Option::as_ref);
        let pre_width = pre.map_or(0, |meta| meta.width);
        let lookups = common.lookups.get(index).ok_or(Error::Shape)?;
        let lookup_width = if lookups.is_empty() {
            0
        } else {
            (lookups.len() + 1) * 4
        };
        let chunks = 1usize
            << (air.get_log_num_quotient_chunks(pre_width, 1 << (degree - 1), lookups, 1, &gadget)
                + 1);
        let trace_next = <_ as RecursiveAir<F, E, LogUpGadget>>::opens_trace_next(air);
        let pre_next = <_ as RecursiveAir<F, E, LogUpGadget>>::opens_preprocessed_next(air);
        random.push((4, 1));
        main.push((
            <_ as RecursiveAir<F, E, LogUpGadget>>::width(air),
            1 + usize::from(trace_next),
        ));
        quotient.extend(std::iter::repeat_n((4, 1), chunks));
        if lookup_width != 0 {
            permutation.push((lookup_width, 2));
        }
        terminals.push((lookup_width != 0).then_some(LookupTerminal(E::ZERO)));
        instances.push(OpenedValuesWithLookups {
            base_opened_values: OpenedValues {
                trace_local: vec![E::ZERO; <_ as RecursiveAir<F, E, LogUpGadget>>::width(air)],
                trace_next: trace_next
                    .then(|| vec![E::ZERO; <_ as RecursiveAir<F, E, LogUpGadget>>::width(air)]),
                preprocessed: pre.map(|_| PreprocessedOpenedValues {
                    local: vec![E::ZERO; pre_width],
                    next: pre_next.then(|| vec![E::ZERO; pre_width]),
                }),
                quotient_chunks: vec![vec![E::ZERO; 4]; chunks],
                random: Some(vec![E::ZERO; 4]),
            },
            permutation_local: vec![E::ZERO; lookup_width],
            permutation_next: vec![E::ZERO; lookup_width],
        });
    }
    let has_permutation = !permutation.is_empty();
    let random_width = FRI.num_random_codewords() as usize;
    let mut rounds = vec![
        (random_width, random),
        (random_width, main),
        (random_width, quotient),
    ];
    // Use trusted preprocessing order.
    if let Some(global) = &common.preprocessed {
        let preprocessed = global
            .matrix_to_instance
            .iter()
            .map(|&index| {
                let air = tables.airs.get(index).ok_or(Error::Shape)?;
                let meta = global
                    .instances
                    .get(index)
                    .and_then(Option::as_ref)
                    .ok_or(Error::Shape)?;
                Ok((
                    meta.width,
                    1 + usize::from(
                        <_ as RecursiveAir<F, E, LogUpGadget>>::opens_preprocessed_next(air),
                    ),
                ))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        rounds.push((0, preprocessed));
    }
    if has_permutation {
        rounds.push((random_width, permutation));
    }
    let queries = FRI.num_queries() as usize;
    let salt_width = FRI.salt_elements() as usize;
    let hiding = rounds
        .iter()
        .map(|&(random_width, ref round)| {
            round
                .iter()
                .map(|&(_, points)| vec![vec![E::ZERO; random_width]; points])
                .collect()
        })
        .collect();
    let input_openings = rounds
        .iter()
        .map(|&(random_width, ref round)| BatchMultiOpening {
            opened_values: vec![
                round
                    .iter()
                    .map(|&(width, _)| vec![F::ZERO; width + random_width])
                    .collect();
                queries
            ],
            opening_proof: (
                vec![vec![vec![F::ZERO; salt_width]; round.len()]; queries],
                PrunedMerklePaths {
                    sibling_hashes: Vec::new(),
                },
            ),
        })
        .collect();
    let mut heights = degrees
        .iter()
        .map(|degree| degree + FRI.log_blowup() as usize)
        .collect::<Vec<_>>();
    heights.sort_unstable();
    heights.dedup();
    heights.reverse();
    let final_height = (FRI.log_final_poly_len() + FRI.log_blowup()) as usize;
    let mut commits = Vec::new();
    let mut openings = Vec::new();
    // PROOF: heights are sorted and distinct; the fixed profile has positive arity.
    for arity in fold_schedule(&heights, final_height, FRI.max_log_arity() as usize) {
        commits.push(vec![[F::ZERO; 8]].into());
        openings.push(CommitPhaseMultiStep {
            sibling_values: vec![vec![E::ZERO; (1 << arity) - 1]; queries],
            opening_proof: (
                vec![vec![vec![F::ZERO; salt_width]]; queries],
                PrunedMerklePaths {
                    sibling_hashes: Vec::new(),
                },
            ),
        });
    }
    let cap = || vec![[F::ZERO; 8]].into();
    let proof = BatchProof::<Config> {
        commitments: BatchCommitments {
            main: cap(),
            quotient_chunks: cap(),
            permutation: has_permutation.then(cap),
            random: Some(cap()),
        },
        opened_values: BatchOpenedValues { instances },
        opening_proof: (
            hiding,
            FriProof {
                commit_pow_witnesses: vec![F::ZERO; commits.len()],
                commit_phase_commits: commits,
                input_openings,
                commit_phase_openings: openings,
                final_poly: vec![E::ZERO; 1 << FRI.log_final_poly_len()],
                query_pow_witness: F::ZERO,
                batch_pow_witness: F::ZERO,
            },
        ),
        lookup_terminals: terminals,
        lookup_pow_witness: has_permutation.then_some(F::ZERO),
        ood_pow_witness: F::ZERO,
        degree_bits: degrees.to_vec(),
    };
    let counts = tables
        .public_values
        .iter()
        .map(Vec::len)
        .collect::<Vec<_>>();
    let inputs = Inputs::allocate(builder, &proof, common, &counts)?;
    bind(builder, &inputs)?;
    let ops = verify_batch_circuit::<_, Config, _, _, _, _, _, 16, 8>(
        verifier.config(),
        &tables.airs,
        builder,
        &inputs.proof_targets,
        &inputs.air_public_targets,
        verifier.config().pcs_verifier_params(),
        &inputs.common_data,
        &gadget,
        POSEIDON,
    )?;
    Ok((inputs, ops))
}
