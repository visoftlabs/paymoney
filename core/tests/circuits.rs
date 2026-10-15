//! Plonky3-recursion rejects a circuit when preparing it, not when building it, so a dependency
//! bump that compiles can still break every proof; preparing all circuits catches that.

#[test]
fn every_circuit_prepares() {
    paymoney_core::Circuits::prepare().unwrap();
}
