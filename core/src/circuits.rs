//! PCD over legs: `leaf` proves one leg, `wrap` lifts it to a statement, `merge` joins two with
//! `left.hi < right.lo`. `{wrap, merge}` is one verifier set, so any tree verifies against one ID.

use crate::{
    Error,
    engine::{self, Backend, CIRCUIT_KEY, Config, E, F, Inputs, VERIFIER_SET},
    identity::{descriptor, descriptor_digest, key},
    leaf::Attested,
    progress::Progress,
    shape,
    statement::{COUNT_BITS, Digest, LIMB_BITS, Leg, Statement},
};
use p3_circuit::{
    Circuit, CircuitBuilder, ExprId, NonPrimitiveOpId, StatementExport, StatementSchema,
    ops::NpoTypeId,
};
use p3_circuit_prover::{BatchStarkProof, CircuitVerifier, PreparedCircuitProver, TablePacking};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::{BatchOnly, TrustedPcsRecursionBackend, prepared::ConstrainConstantCommitment};
use serde::{Deserialize, Serialize};
use std::ops::Range;

/// Calibrated: the smallest log2 heights `prepare` accepts for both wrap and merge.
const LAYOUT: Layout = Layout {
    constants: 9,
    public: 9,
    alu: 17,
    poseidon: 9,
    challenger: 16,
    recompose: 15,
};

struct Layout {
    constants: u8,
    public: u8,
    alu: u8,
    poseidon: u8,
    challenger: u8,
    recompose: u8,
}
impl Layout {
    fn packing(&self) -> TablePacking {
        let mut packing = engine::packing()
            .with_const_min_height(1 << self.constants)
            .with_public_min_height(1 << self.public)
            .with_alu_min_height(1 << self.alu)
            .with_npo_min_height(
                NpoTypeId::recompose_with_coeff_lookups(),
                1 << self.recompose,
            )
            .with_strict_heights();
        for (config, height) in [
            (engine::POSEIDON, self.poseidon),
            (engine::POSEIDON.for_challenger(), self.challenger),
            (
                engine::POSEIDON.for_shared_challenger_table(),
                self.challenger,
            ),
        ] {
            packing = packing.with_npo_min_height(NpoTypeId::poseidon2_perm(config), 1 << height);
        }
        packing
    }
}

#[derive(Serialize, Deserialize)]
pub struct LegProof {
    pub leg: Leg,
    proof: BatchStarkProof<Config>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Member {
    Wrap,
    Merge,
}

#[derive(Serialize, Deserialize)]
pub struct Aggregate {
    pub member: Member,
    pub statement: Statement,
    proof: BatchStarkProof<Config>,
}

/// Where a child proof's verifier inputs live in its parent circuit.
pub(crate) struct Wiring {
    inputs: Inputs,
    ops: Vec<NonPrimitiveOpId>,
}
struct Prepared {
    circuit: Circuit<E>,
    prover: PreparedCircuitProver<Config>,
    children: Vec<Wiring>,
}
pub(crate) struct Built {
    circuit: Circuit<E>,
    schema: StatementSchema,
    children: Vec<Wiring>,
}
/// A child proof, its statement words and the parent's extra witness for it.
struct Child<'a> {
    prepared: &'a Prepared,
    proof: &'a BatchStarkProof<Config>,
    words: Vec<u32>,
    extra: Vec<E>,
}

/// The three prepared circuits and the verifier-set ID, derived from code alone.
pub struct Circuits {
    leaf: Prepared,
    wrap: Prepared,
    merge: Prepared,
    keys: [[F; 8]; 2],
    set: Digest,
}
impl Circuits {
    #[tracing::instrument(name = "circuits", skip_all)]
    pub fn prepare() -> Result<Self, Error> {
        let leaf = prepared(crate::leaf::circuit()?, engine::packing())?;
        let heights = leaf
            .prover
            .verifier()
            .relation()
            .trace_degree_bits()
            .to_vec();
        tracing::info!(event.name = "circuit.prepared", paymoney.circuit = "leaf", paymoney.log2_heights = ?heights);
        let wrap = prepared(wrap(&leaf.prover.verifier())?, LAYOUT.packing())?;
        let template = wrap.prover.verifier();
        let merge = prepared(merge(&template)?, LAYOUT.packing())?;
        if descriptor(&template)? != descriptor(&merge.prover.verifier())? {
            return Err(Error::Layout);
        }
        let keys = [key(&template)?, key(&merge.prover.verifier())?];
        let set = Digest::from(engine::hash(VERIFIER_SET, keys.as_flattened()));
        tracing::info!(event.name = "set.derived", paymoney.set = %set);
        Ok(Self {
            leaf,
            wrap,
            merge,
            keys,
            set,
        })
    }

    pub fn set(&self) -> Digest {
        self.set
    }

    /// Proves the leg `leg_id` of an attested response; checks the proof against the native
    /// reading of the same bytes.
    #[tracing::instrument(skip_all)]
    pub fn prove_leg(&self, attested: &Attested, leg_id: &[u8]) -> Result<LegProof, Error> {
        let (leg, witness) = attested.witness(leg_id)?;
        tracing::info!(event.name = "leg.read", paymoney.key = %leg.key, paymoney.amount = leg.amount.minor(), paymoney.currency = %leg.currency, paymoney.notary = %leg.notary);
        let proof = prove(&self.leaf, &witness, Vec::new())?;
        check(&self.leaf, &proof, &leg.words())?;
        tracing::info!(event.name = "leaf.proven", paymoney.key = %leg.key);
        Ok(LegProof { leg, proof })
    }

    #[tracing::instrument(skip_all, fields(key = %leg.leg.key))]
    fn wrap(&self, leg: &LegProof) -> Result<Aggregate, Error> {
        let statement = Statement::of_leg(self.set, leg.leg);
        let child = Child {
            prepared: &self.leaf,
            proof: &leg.proof,
            words: leg.leg.words(),
            extra: Vec::new(),
        };
        let proof = prove(&self.wrap, &statement.words(), vec![child])?;
        Ok(Aggregate {
            member: Member::Wrap,
            statement,
            proof,
        })
    }

    #[tracing::instrument(skip_all)]
    fn merge(&self, left: &Aggregate, right: &Aggregate) -> Result<Aggregate, Error> {
        let (statement, hints) = left.statement.merge(&right.statement)?;
        tracing::info!(
            event.name = "merge.checked",
            paymoney.left = %format_args!("[{}, {}]", left.statement.lo, left.statement.hi),
            paymoney.right = %format_args!("[{}, {}]", right.statement.lo, right.statement.hi),
            paymoney.sum = statement.sum.minor(),
            paymoney.count = statement.count.get(),
        );
        let children = [left, right]
            .into_iter()
            .map(|child| {
                let bit = child.member as usize;
                let sibling = self.keys.get(1 - bit).ok_or(Error::Shape)?;
                Ok(Child {
                    prepared: self.member(child.member),
                    proof: &child.proof,
                    words: child.statement.words(),
                    extra: std::iter::once(E::from_usize(bit))
                        .chain(sibling.iter().copied().map(E::from))
                        .collect(),
                })
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let own = [statement.words(), hints.to_vec()].concat();
        let proof = prove(&self.merge, &own, children)?;
        Ok(Aggregate {
            member: Member::Merge,
            statement,
            proof,
        })
    }

    /// Sorts legs by key and merges them in a balanced tree.
    pub fn aggregate(&self, mut legs: Vec<LegProof>) -> Result<Aggregate, Error> {
        legs.sort_by_key(|leg| leg.leg.key);
        // Fail before any proving: the native merges reject what the circuits would.
        let mut statements = legs.iter().map(|leg| Statement::of_leg(self.set, leg.leg));
        let first = statements.next().ok_or(Error::Empty)?;
        statements.try_fold(first, |left, right| Ok::<_, Error>(left.merge(&right)?.0))?;
        // n leaves are wrapped, then merged pairwise n − 1 times.
        let mut progress = Progress::new(2 * legs.len() - 1);
        let mut level = legs
            .iter()
            .map(|leg| {
                progress.advance("leaf.wrapping");
                self.wrap(leg)
            })
            .collect::<Result<Vec<_>, _>>()?;
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut nodes = level.into_iter();
            while let Some(left) = nodes.next() {
                next.push(match nodes.next() {
                    Some(right) => {
                        progress.advance("proofs.merging");
                        self.merge(&left, &right)?
                    }
                    None => left,
                });
            }
            level = next;
        }
        let root = level.into_iter().next().ok_or(Error::Empty)?;
        tracing::info!(
            event.name = "aggregate.proven",
            paymoney.lo = %root.statement.lo,
            paymoney.hi = %root.statement.hi,
            paymoney.sum = root.statement.sum.minor(),
            paymoney.count = root.statement.count.get(),
        );
        Ok(root)
    }

    /// Checks the proof and that it belongs to this verifier set; which notaries to trust is the
    /// verifier's policy.
    pub fn check(&self, aggregate: &Aggregate) -> Result<Statement, Error> {
        let statement = aggregate.statement;
        if statement.set != self.set {
            return Err(Error::Set);
        }
        check(
            self.member(aggregate.member),
            &aggregate.proof,
            &statement.words(),
        )?;
        Ok(statement)
    }

    fn member(&self, member: Member) -> &Prepared {
        match member {
            Member::Wrap => &self.wrap,
            Member::Merge => &self.merge,
        }
    }
}

fn get(wires: &[ExprId], range: Range<usize>) -> Result<&[ExprId], Error> {
    wires.get(range).ok_or(Error::Shape)
}
fn at(wires: &[ExprId], index: usize) -> Result<ExprId, Error> {
    wires.get(index).copied().ok_or(Error::Shape)
}
/// Private base-field inputs, supplied in allocation order when proving.
fn inputs(builder: &mut CircuitBuilder<E>, count: usize) -> Result<Vec<ExprId>, Error> {
    let wires = builder.alloc_private_inputs(count, "witness");
    base_words(builder, &wires)?;
    Ok(wires)
}
fn bits(builder: &mut CircuitBuilder<E>, wire: ExprId, bits: u32) -> Result<(), Error> {
    builder.decompose_to_bits::<F>(wire, bits as usize)?;
    Ok(())
}
fn equal_all(builder: &mut CircuitBuilder<E>, left: &[ExprId], right: &[ExprId]) {
    for (left, right) in left.iter().zip(right) {
        equal(builder, *left, *right);
    }
}
pub(crate) fn finish(
    mut builder: CircuitBuilder<E>,
    statement: &[ExprId],
    children: Vec<Wiring>,
) -> Result<Built, Error> {
    let exports = statement
        .iter()
        .copied()
        .map(StatementExport::Base)
        .collect::<Vec<_>>();
    let schema = builder.set_statement_exports::<F>(&exports)?;
    Ok(Built {
        circuit: builder.build()?,
        schema,
        children,
    })
}

fn wrap(leaf: &CircuitVerifier<Config>) -> Result<Built, Error> {
    let mut builder = engine::builder()?;
    let own = inputs(&mut builder, Statement::WORDS)?;
    let (inputs, ops) = shape::allocate(&mut builder, leaf, Leg::WORDS, |builder, inputs| {
        let expected = &leaf
            .common_data()
            .preprocessed
            .as_ref()
            .ok_or(Error::Shape)?;
        let target = inputs.common_data.preprocessed_commitment();
        Ok(target
            .ok_or(Error::Shape)?
            .constrain_constant(builder, &expected.commitment)?)
    })?;
    let leg = statement_targets(leaf, &inputs)?;
    let shared = get(&own, Statement::SET.end..Statement::SHARED.end)?;
    equal_all(&mut builder, shared, get(&leg, Leg::SHARED)?);
    let key = get(&leg, Leg::KEY)?;
    equal_all(&mut builder, get(&own, Statement::LO)?, key);
    equal_all(&mut builder, get(&own, Statement::HI)?, key);
    equal_all(
        &mut builder,
        get(&own, Statement::SUM)?,
        get(&leg, Leg::AMOUNT)?,
    );
    let one = builder.define_const(E::ONE);
    equal(&mut builder, at(&own, Statement::COUNT)?, one);
    finish(builder, &own, vec![Wiring { inputs, ops }])
}

fn merge(template: &CircuitVerifier<Config>) -> Result<Built, Error> {
    let mut builder = engine::builder()?;
    let own = inputs(&mut builder, Statement::WORDS + 6)?;
    let shared = get(&own, Statement::SHARED)?.to_vec();
    let (left_wiring, left) = member(&mut builder, template, &shared)?;
    let (right_wiring, right) = member(&mut builder, template, &shared)?;
    let radix = builder.define_const(E::from_u32(1 << LIMB_BITS));
    let one = builder.define_const(E::ONE);
    let [gap0, gap1, borrow, c0, c1, c2] =
        <[ExprId; 6]>::try_from(get(&own, Statement::WORDS..Statement::WORDS + 6)?)
            .or(Err(Error::Shape))?;

    // left.hi + 1 + gap = right.lo over two limbs, so left.hi < right.lo.
    bits(&mut builder, gap0, LIMB_BITS)?;
    bits(&mut builder, gap1, LIMB_BITS)?;
    bits(&mut builder, borrow, 1)?;
    let [hi0, hi1] = [
        at(&left, Statement::HI.start)?,
        at(&left, Statement::HI.start + 1)?,
    ];
    let [lo0, lo1] = [
        at(&right, Statement::LO.start)?,
        at(&right, Statement::LO.start + 1)?,
    ];
    let low = builder.add(hi0, one);
    let low = builder.add(low, gap0);
    let expected = builder.mul_add(borrow, radix, lo0);
    equal(&mut builder, low, expected);
    let high = builder.add(hi1, borrow);
    let high = builder.add(high, gap1);
    equal(&mut builder, high, lo1);

    // sum = left.sum + right.sum mod 2^72, limb by limb with carries.
    let mut carry = builder.define_const(E::ZERO);
    for (sum, next) in Statement::SUM.zip([c0, c1, c2]) {
        bits(&mut builder, next, 1)?;
        let limb = at(&own, sum)?;
        bits(&mut builder, limb, LIMB_BITS)?;
        let total = builder.add(at(&left, sum)?, at(&right, sum)?);
        let total = builder.add(total, carry);
        let expected = builder.mul_add(next, radix, limb);
        equal(&mut builder, total, expected);
        carry = next;
    }

    let count = builder.add(at(&left, Statement::COUNT)?, at(&right, Statement::COUNT)?);
    equal(&mut builder, at(&own, Statement::COUNT)?, count);
    bits(&mut builder, count, COUNT_BITS)?;
    equal_all(
        &mut builder,
        get(&own, Statement::LO)?,
        get(&left, Statement::LO)?,
    );
    equal_all(
        &mut builder,
        get(&own, Statement::HI)?,
        get(&right, Statement::HI)?,
    );
    let statement = get(&own, 0..Statement::WORDS)?.to_vec();
    finish(builder, &statement, vec![left_wiring, right_wiring])
}

/// Verifies one child of the set: its key, recomputed from the preprocessing it consumes,
/// must hash with a sibling to the set ID, and its shared words must equal `shared`.
fn member(
    builder: &mut CircuitBuilder<E>,
    template: &CircuitVerifier<Config>,
    shared: &[ExprId],
) -> Result<(Wiring, Vec<ExprId>), Error> {
    let digest = descriptor_digest(template)?;
    let set = get(shared, Statement::SET)?;
    let (inputs, ops) = shape::allocate(builder, template, Statement::WORDS, |builder, inputs| {
        let cap = &inputs
            .common_data
            .preprocessed_commitment()
            .ok_or(Error::Shape)?
            .cap_targets;
        let mut key_words = digest
            .iter()
            .map(|word| builder.define_const(E::from(*word)))
            .collect::<Vec<_>>();
        key_words.extend(cap.iter().flatten().copied());
        let packed = base_words(builder, &key_words)?;
        let actual = engine::circuit_hash(builder, CIRCUIT_KEY, &packed)?;
        let bit = builder.alloc_private_input("set member");
        builder.assert_bool(bit);
        let siblings = builder.alloc_private_inputs(8, "set sibling");
        let packed = base_words(builder, &siblings)?;
        let mut words = Vec::new();
        for (node, sibling) in actual.iter().zip(&packed) {
            let delta = builder.sub(*sibling, *node);
            words.push(builder.mul_add(bit, delta, *node));
        }
        for (node, sibling) in actual.iter().zip(&packed) {
            let delta = builder.sub(*node, *sibling);
            words.push(builder.mul_add(bit, delta, *sibling));
        }
        let root = engine::circuit_hash(builder, VERIFIER_SET, &words)?;
        for (a, b) in root.into_iter().zip(base_words(builder, set)?) {
            equal(builder, a, b);
        }
        Ok(())
    })?;
    let words = statement_targets(template, &inputs)?;
    equal_all(builder, get(&words, Statement::SHARED)?, shared);
    Ok((Wiring { inputs, ops }, words))
}

fn prepared(built: Built, packing: TablePacking) -> Result<Prepared, Error> {
    Ok(Prepared {
        prover: engine::prepare(&built.circuit, &built.schema, packing)?,
        circuit: built.circuit,
        children: built.children,
    })
}

/// Checks each child, then proves `prepared` over `own` words and the children's witnesses.
fn prove(
    prepared: &Prepared,
    own: &[u32],
    children: Vec<Child<'_>>,
) -> Result<BatchStarkProof<Config>, Error> {
    let mut private = own.iter().copied().map(E::from_u32).collect::<Vec<_>>();
    let mut public = Vec::new();
    let mut statements = Vec::new();
    for (wiring, child) in prepared.children.iter().zip(&children) {
        check(child.prepared, child.proof, &child.words)?;
        let verifier = child.prepared.prover.verifier();
        let statement = child.words.iter().copied().map(F::new).collect::<Vec<_>>();
        let table = verifier.table_public_values(&statement)?;
        let (a, b) =
            wiring
                .inputs
                .try_pack_values(&table, &child.proof.proof, verifier.common_data())?;
        public.extend(a);
        private.extend(b);
        private.extend(child.extra.iter().copied());
        statements.push(statement);
    }
    let mut runner = prepared.circuit.runner();
    runner.set_public_inputs(&public)?;
    runner.set_private_inputs(&private)?;
    for ((wiring, child), statement) in prepared.children.iter().zip(&children).zip(&statements) {
        <Backend as TrustedPcsRecursionBackend<Config, BatchOnly, 4>>::set_private_data_for_trusted_batch(
            &engine::backend(),
            &child.prepared.prover.verifier(),
            child.proof,
            statement,
            &mut runner,
            &wiring.ops,
        )?;
    }
    tracing::info!(event.name = "witness.evaluating");
    let traces = runner.run()?;
    tracing::info!(event.name = "proof.generating");
    Ok(prepared.prover.prove(&traces)?)
}

/// `statement` words are canonical (parsed), so `F::new` is injective on them.
fn check(
    prepared: &Prepared,
    proof: &BatchStarkProof<Config>,
    statement: &[u32],
) -> Result<(), Error> {
    let verifier = prepared.prover.verifier();
    <Backend as TrustedPcsRecursionBackend<Config, BatchOnly, 4>>::preflight_trusted_batch(
        &engine::backend(),
        &verifier,
        proof,
    )?;
    let statement = statement.iter().copied().map(F::new).collect::<Vec<_>>();
    verifier.verify(proof, &statement)?;
    Ok(())
}

fn statement_targets(
    verifier: &CircuitVerifier<Config>,
    inputs: &Inputs,
) -> Result<Vec<ExprId>, Error> {
    let index = verifier
        .statement_layout()
        .table_instance()
        .ok_or(Error::Shape)?;
    inputs
        .air_public_targets
        .get(index)
        .cloned()
        .ok_or(Error::Shape)
}

/// `value = 0`: connected to `value + (0 − value)`, not to the zero constant, whose wire class a
/// `connect` would merge with bus creators.
pub(crate) fn vanish(builder: &mut CircuitBuilder<E>, value: ExprId) {
    if value != ExprId::ZERO {
        let negative = builder.sub(ExprId::ZERO, value);
        let zero = builder.add(value, negative);
        builder.connect(value, zero);
    }
}
pub(crate) fn equal(builder: &mut CircuitBuilder<E>, left: ExprId, right: ExprId) {
    let difference = builder.sub(left, right);
    vanish(builder, difference);
}

/// Packs base words four to an extension element, proving each is a base-field element.
pub(crate) fn base_words(
    builder: &mut CircuitBuilder<E>,
    words: &[ExprId],
) -> Result<Vec<ExprId>, Error> {
    let mut result = Vec::new();
    for chunk in words.chunks(4) {
        let mut padded = chunk.to_vec();
        padded.resize(4, ExprId::ZERO);
        let value = builder.recompose_base_coeffs_to_ext_via_alu::<F>(&padded)?;
        let bound = builder.recompose_base_coeffs_to_ext_with_coeff_lookups::<F>(&padded)?;
        builder.connect(value, bound);
        result.push(bound);
    }
    Ok(result)
}
