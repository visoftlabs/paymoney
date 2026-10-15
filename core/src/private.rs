//! Private inputs. Plonky3-recursion accepts a circuit only if every private input is created by
//! an ALU op or a coefficient lookup, and its builder folds identity ops away, so an input used
//! only through foldable arithmetic can end up created by nothing. Each constructor here
//! allocates its inputs together with the constraint that creates them, whatever the circuit
//! later does with them. They are the only callers of `alloc_private_input(s)`;
//! `core/tests/circuits.rs` fails on any input that ends up created by nothing.

use p3_circuit::{CircuitBuilder, ExprId};

use crate::{
    Error,
    circuits::base_words,
    engine::{E, F},
};

/// Private bytes and their little-endian bits.
pub(crate) struct Bytes {
    pub values: Vec<ExprId>,
    pub bits: Vec<Vec<ExprId>>,
}

/// Base-field words, created by the coefficient lookups that range-check them.
pub(crate) fn words(
    builder: &mut CircuitBuilder<E>,
    label: &'static str,
    count: usize,
) -> Result<Vec<ExprId>, Error> {
    let words = alloc(builder, label, count);
    base_words(builder, &words)?;
    Ok(words)
}

/// Bytes, created by their 8-bit decomposition.
pub(crate) fn bytes(
    builder: &mut CircuitBuilder<E>,
    label: &'static str,
    count: usize,
) -> Result<Bytes, Error> {
    let values = alloc(builder, label, count);
    let bits = values
        .iter()
        .map(|byte| builder.decompose_to_bits::<F>(*byte, 8))
        .collect::<Result<_, _>>()?;
    Ok(Bytes { values, bits })
}

/// Booleans, created by their bool checks.
pub(crate) fn flags(
    builder: &mut CircuitBuilder<E>,
    label: &'static str,
    count: usize,
) -> Vec<ExprId> {
    let flags = alloc(builder, label, count);
    flags.iter().for_each(|flag| builder.assert_bool(*flag));
    flags
}

/// One boolean, created by its bool check.
pub(crate) fn flag(builder: &mut CircuitBuilder<E>, label: &'static str) -> ExprId {
    let flag = builder.alloc_private_input(label);
    builder.assert_bool(flag);
    flag
}

fn alloc(builder: &mut CircuitBuilder<E>, label: &'static str, count: usize) -> Vec<ExprId> {
    builder.alloc_private_inputs(count, label)
}
