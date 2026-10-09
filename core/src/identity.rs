//! Circuit key = H(descriptor digest ‖ preprocessing commitment). Equal descriptors let one
//! recursive verifier serve the whole set.

use crate::{
    Error,
    engine::{CIRCUIT_KEY, Config, DESCRIPTOR, E, F, FRI, hash, pack},
};
use p3_air::{Air, BaseAir, symbolic::AirLayout};
use p3_circuit_prover::CircuitVerifier;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::symbolic::InteractionSymbolicBuilder;

const PROFILE: &str = "paymoney/plonky3-recursion/1";

pub(crate) fn descriptor(verifier: &CircuitVerifier<Config>) -> Result<Vec<u8>, Error> {
    let common = verifier.common_data();
    let preprocessed = common.preprocessed.as_ref().ok_or(Error::Shape)?;
    let constraints = verifier
        .table_airs::<4>()?
        .iter()
        .map(|air| {
            let layout = AirLayout::from_air::<F>(air);
            let mut builder = InteractionSymbolicBuilder::<F, E>::new(layout);
            air.eval(&mut builder);
            (
                layout,
                (
                    builder.base_constraints(),
                    builder.extension_constraints(),
                    builder.constraint_layout(),
                ),
                air.main_next_row_columns(),
                air.preprocessed_next_row_columns(),
            )
        })
        .collect::<Vec<_>>();
    let relation = verifier.relation();
    let meta = preprocessed
        .instances
        .iter()
        .map(|instance| {
            instance
                .as_ref()
                .map(|instance| (instance.matrix_index, instance.width, instance.degree_bits))
        })
        .collect::<Vec<_>>();
    Ok(serde_json::to_vec(&(
        PROFILE,
        (
            FRI.suite().as_u16(),
            FRI.log_blowup(),
            FRI.log_final_poly_len(),
            FRI.max_log_arity(),
            FRI.num_queries(),
            FRI.commit_pow_bits(),
            FRI.query_pow_bits(),
            FRI.input_cap_height(),
            FRI.commit_cap_height(),
            FRI.num_random_codewords(),
            FRI.salt_elements(),
        ),
        relation.table_packing(),
        relation.trace_degree_bits(),
        verifier.statement_layout().schema(),
        verifier.statement_layout().table_instance(),
        verifier.table_public_values(&vec![
            F::ZERO;
            verifier.statement_layout().schema().base_len()
        ])?,
        meta,
        &preprocessed.matrix_to_instance,
        &common.lookups,
        constraints,
    ))?)
}

pub(crate) fn descriptor_digest(verifier: &CircuitVerifier<Config>) -> Result<[F; 8], Error> {
    Ok(hash(DESCRIPTOR, &pack(&descriptor(verifier)?)))
}

pub(crate) fn key(verifier: &CircuitVerifier<Config>) -> Result<[F; 8], Error> {
    let mut words = descriptor_digest(verifier)?.to_vec();
    let commitment = &verifier
        .common_data()
        .preprocessed
        .as_ref()
        .ok_or(Error::Shape)?
        .commitment;
    words.extend(commitment.roots().iter().flatten().copied());
    Ok(hash(CIRCUIT_KEY, &words))
}
