# Engineering Contract

Reusable engineering rules. `README.md` owns project architecture, setup, commands and operations;
`WEBAPP.md` applies these rules to web apps. On conflict, this file wins. Language-specific rules
apply only to source in that language.

For review, diagnosis or explanation, report without editing. For a requested change, preserve
existing work, make the smallest in-scope change, and run the relevant documented checks. Never
claim a check that was not run. The rules are normative; their basis explains intent and adds no
rule by inference.

---

## P — Stage-Minimality

> **Every runtime check is evidence of a missing type. Each check is discharged at the earliest
> binding time at which its inputs are bound; a residual check is admissible only at a
> binding-time boundary — the edge where dynamic input first arrives.**

### P1 · Construction

A type is inhabited only by valid values.

- A state that must not exist is unrepresentable, excluded by structure, not merely unreached.
- Required components are mandatory, not optional-and-checked.
- A finite set of cases, states or errors is one closed sum type; each variant carries exactly the
  data valid for it.
- **Native types wherever reasonable.** A constraint that travels (crosses a module or API
  boundary, is persisted or re-read) earns a distinct type; one checked and consumed in place earns
  a parse, not a type.
- Incomplete input exists only at the boundary that parses it.

Obligations:

- **Rust.** Structs with non-`Option` required fields, private fields and a smart constructor
  returning `Result<Self, E>`; case sets are data-carrying `enum`s; a primitive is a newtype only
  where its constraint travels.
- **JavaScript** (`.mjs` + JSDoc). Domain values come from a factory returning the value or
  throwing, frozen. Case sets are discriminated unions over a `const` tag set, one `@typedef` per
  variant.
- **Python.** Records are frozen, slotted, keyword-only dataclasses; case sets are `StrEnum`s or
  unions of such records.
- **CSS.** Geometry is constructed, never searched for: a box's size follows from the space its
  container passes in and its content's intrinsic size, never from measuring a rendered result.
  Space beyond intrinsic size is a declared proportion of free space (`fr`, `flex-grow`).
  Adaptation is declared where the space is (`@container`).
- **HTML.** Use the element whose semantics are the guarantee (`<button>`, `<a href>`, `<dialog>`,
  `<details>`, `<label for>`, `<fieldset>`, `<output>`); a generic element plus ARIA re-checks what
  the native one proves. Required relationships are structural.

_Limit:_ scope "illegal states unrepresentable" to stable domain cores and traveling constraints.
At an evolving boundary (serialized, persisted, or sent to an older peer) a permissive type parsed
into a precise one is correct, and a maximally strict wire schema is a defect. See **F**.

### P2 · Boundary

External input is untrusted until parsed exactly once, at the edge, and only there.

- Parsing returns a domain value or an error, never a truth-value beside the raw input, and
  consumes the raw value. A normalized native shape is fine: value-or-error is the requirement.
- Unknown failures convert into the boundary's single error model there, with operation context.
- A format is decoded by its parser, never by character manipulation.
- Past the boundary, code never re-validates.

Obligations:

- **Rust.** `serde` shape-checks the wire; one named parse at the handler's front consumes and
  normalizes. `deny_unknown_fields` for closed request shapes, not for evolving or durable data
  (**F**). Any regex is a `static LazyLock<Regex>` in `patterns.rs`.
- **JavaScript.** A schema parser at the edge (`JSON.parse` + validation, `URL`); any `RegExp` is
  a module-scope constant with a `// PROOF:` note. No `split`/`trim`/`slice` chains for structured
  formats.
- **HTML.** Controls declare their constraints (`type`, `required`, `min`, `max`, `step`,
  `pattern`, `maxlength`). A client-side constraint is an affordance, never a trust boundary; the
  server parses independently, and an island converts what the attribute already validated.

### P3 · Totality

Each valid case has one path and fails fast at the point of failure.

- **A fallback for an invalid internal state signals an imprecise type: fix the type.**
- Flow is linear composition over wrapped values, not nested branching with manual unwrapping.
- Transformation and validation are pure; effects are isolated (**A2**).
- An assertion the type system cannot verify carries a proof annotation; an unprovable forced
  success in request-handling or concurrent code is a defect.

**A fallback is not a progressive enhancement:** a fallback is an authored branch for an invalid
state or a capability missing inside the declared baseline; an enhancement is one path whose
platform degrades without one. Exhaustive matching over valid runtime data and explicit error
handling are neither. A requirement the baseline cannot support changes the topology or baseline.

Obligations:

- **Rust.** `?`, `map`, `and_then`; `unwrap`/`expect` only where infallibility is proven, with
  `// PROOF:`. No `panic!` in request or concurrent paths.
- **JavaScript.** Promise and array combinators with early `throw`; forced access carries
  `// PROOF:`. No throwing as control flow for expected cases.
- **Python.** `match` over closed sets ends in `assert_never`; ruff, ty and pytest diagnostics are
  errors.
- **CSS.** One cascade layer order, declared once. No `@supports` branch, vendor prefix, or rule
  that only undoes another. `!important` is a defect in the rule it overrides.

### P4 · Literals

Every literal resolves to exactly one binding time; one that fits none is a defect.

- **Structural**: bound by mathematics, calendar, protocol or format (a unit conversion, a port, a
  schema version), with a proof where not self-evident.
- **Policy**: bound once per deployment, not derivable from data (a retention window, a page size).
  One named, justified binding at the least scope shared by its consumers; documentation references
  it rather than restating it.
- **Calibrated**: a threshold over a measured quantity, derived from a measured reference of that
  quantity (a percentile, a ratio to a live baseline), never an absolute guessed offline. The
  reference is measured at a boundary, and readiness is gated on a self-check that a known value
  falls on its expected side. A dimensionless ratio beats an absolute magnitude.
- **CSS lengths**: structural (a ratio, `100%`, a `1px` hairline), policy (a `:root` token),
  calibrated (`min-content`, `fit-content`, `clamp()` over `cqi`/`vi`, `minmax()`). A hand-picked
  pixel breakpoint is an absolute threshold over a measured quantity, and a defect.

---

## A1 — Observation

> **A lifecycle is a coalgebra. State is observed, never accumulated.** `render : X → B` observes;
> `step : X × E → X` is pure and total over a closed event set; together `X → B × X^E`. **Events
> are observed, never manufactured.**

- Behavior is equal by bisimulation, so tests observe every source of truth and never reach inside.
- A timer may bound or delay a transition or meet a stated time-domain requirement; polling,
  intervals and periodic work are defects where an equivalent event exists.
- **Branch where the alternative is born:** a tagged union and its match are warranted only where
  runtime data decides the variant. Where each call site knows its case, write one function per
  case.
- **Derived views need no machine:** observe canonical inputs with a pure derivation; persist only
  irreducible data.

Obligations:

- **Rust.** State is an `enum`; `step` is a free function with no IO, clock or RNG; readers match
  exhaustively with no `_` arm absorbing new variants.
- **JavaScript.** State is a discriminated union; `step` is pure; readers `switch` with a
  `never`-typed guard in `default:`, so an unhandled variant fails `tsc`.

---

## A2 — Confinement

> **Effects are confined to a shell; the core is pure and total. Errors are effects: one typed
> error channel per boundary, handled or propagated with context, never dropped.**

A failed lifecycle state carries what recovery needs and exposes a named recovery transition,
never a hidden refresh or implicit retry.

Obligations:

- **Rust.** `Result<T, E>`; one `thiserror` enum per boundary with `#[from]`. No `anyhow`,
  `.map_err`, discarded `let _ = result`, or hand-picked `ExitCode`. Context `From` cannot carry is
  added by matching the source result and constructing the contextual variant. `main` returns
  `Result<(), E>`.
- **JavaScript.** Throw a tagged `Error` subclass at the point of failure, caught once at the
  shell and folded into an explicit error state. No empty `catch`, discarded promise, or `catch`
  returning a default.

---

## A3 — Ownership

> **Every resource has exactly one owner. Cleanup is structural and bound to scope.**

- Shared access is explicit; references beat copies. Long-lived resources belong to long-lived
  scopes; short-lived consumers borrow.
- State crossing a concurrency boundary has a documented owner; data races are defects.
- A retryable operation is idempotent at its boundary: a retry is a monotone update.

Obligations:

- **Rust.** Borrowing; `Drop`/RAII; shared mutable state is `Arc<Mutex<_>>` with a documented
  owner; `&T` over `clone()`.
- **JavaScript.** Lifetime tied to one scope (`using`, `[Symbol.dispose]`, `try`/`finally`); one
  owning module per shared mutable value.
- **CSS/DOM.** Geometry's one owner is the stylesheet. Script may write a custom property the sheet
  consumes, never a size or position, and never reads resolved geometry back.

---

## A4 — Least Scope

> **Every artifact carries a label in a lattice and sits at the least scope covering all its
> consumers.**

**Visibility.** An artifact used by two subtrees belongs at their lowest common ancestor. Never
import sideways or register globally; the root is the only global scope, a deliberate cost.

**Confidentiality.** build-truth (everyone) ⊏ server-truth (the server and its clients) ⊏
client-truth (one browser).

- Computation runs at the highest label where it is feasible, measured, so private inputs never
  flow down.
- Moving a value down is declassification and needs explicit authorization; where full offload is
  infeasible, minimize what crosses (a commitment, a blinded value, a partial computation).
- `README.md` documents authorized disclosures, recipients and exposed metadata.

---

## F — Forward-Only

P1 governs the in-memory value; F governs its persistence.

- **Derived data** (rebuildable from source): one canonical definition, dropped and recreated on
  mismatch. No migration, version branch, shim or deprecated-but-live API.
- **Durable data**: accretion-only. Fields are added, never repurposed; old fields are read, not
  required; removal is expand-then-contract. The persisted type is permissive at the edge and
  parsed into a precise one in memory (P2).

---

## S — Structure

> **Every module instantiates a named mathematical structure, and its laws are the module's audit
> checklist. Code that instantiates none, holds two copies of one mechanism, or breaks a law of
> its structure is a refactor candidate.** P and A1–A4 are instances: types as algebras,
> lifecycles as coalgebras, effects, affine ownership, a label lattice.

| Structure                             | In code                                      | Law to audit                                                       |
| ------------------------------------- | -------------------------------------------- | ------------------------------------------------------------------ |
| Isomorphism, section–retraction, lens | parse/print, encode/decode, forward/backward | `g ∘ f = id` on the stated domain; GetPut, PutGet                  |
| Idempotent                            | normalize, canonicalize, resend, retry       | `f ∘ f = f`                                                        |
| Monoid, fold                          | replay, accumulation, metering               | associative with identity; state = `fold step init events`         |
| Homomorphism                          | streamed vs whole, batched vs alone          | `h(a · b) = h(a) · h(b)`                                           |
| Mealy transducer                      | a streaming stage                            | `feed : S × I → S × O*`, `finish : S → O*`; stages compose         |
| Join-semilattice, monotone map        | merged records, admission, append-only logs  | join associative, commutative, idempotent; state only rises (CALM) |
| Group action                          | scheduling, batching, permuted inputs        | invariance `f(g·x) = f(x)` or equivariance `f(g·x) = g·f(x)`       |
| Well-founded and cyclic order         | loops, rotations, walks                      | each turn decreases a measure; a rotation visits each of ℤₙ once   |
| Bijection, enumeration                | index ↔ member, keyed draws                  | injective onto its set; its size is its count                      |
| Traversal                             | tree walks with a visitor                    | the identity visitor changes nothing; the walk ignores the visitor |
| Commutative diagram                   | two implementations or paths to one result   | both paths agree                                                   |

- **Symmetry is visible.** An operation and its inverse or dual sit together, with mirrored names
  (`forward`/`backward`, `mask`/`unmask`), the same signature shape and one shared mechanism.
- **Named, not explained.** A module's one-line doc names its structure ("a Mealy machine").
- **Shape, not hierarchy.** A structure shows in names, signatures and laws, never in an
  abstraction built to display it (Code Form: composition over abstraction).
- **Laws are witnessed.** A law the system relies on is a workflow assertion: by generator where
  the domain is unbounded, and an invariance as a metamorphic relation (Testing).

---

## Code Form

These shape expression and add no runtime semantics. Paths in documentation are relative to the
repository root; host-specific absolute paths are supplied at setup, never hard-coded.

- **Immutable and canonical.** Mutation is explicit and scoped; persist irreducible data, derive
  the rest on read.
- **Type inference.** Annotate inputs; infer outputs. _JS:_ `// @ts-check` on every file and a
  `@param` for every argument; `@returns` or `@type` only where inference would widen a literal; a
  `@type` cast only at a boundary, with `// PROOF:`.
- **Composition over abstraction.** Three similar lines beat a premature abstraction; flat
  composition of small functions over inheritance or trait towers.
- **Names over comments.** Names and types carry intent. A comment is **one line**, for a reader
  who knows the field, and is one of: a `// PROOF:` note (longer only where the proof needs it),
  a policy constant's justification, or why the obvious alternative was rejected. A comment that
  restates code is a defect.
- **Claims are measured.** Every factual claim records something checked; provisional values name
  the measurement that would settle them.
- **Choices on data are notebooks.** A choice made on measured data is a reproducible notebook:
  settings cells are its only inputs, every step shows its intermediate result and a check, its
  mechanics live in a library, and its export is the evidence the choice cites.
- **Drift is resolved, never carried.** When code and a document disagree, one is edited
  deliberately; a document mandating a gate the repo lacks is worse than none.
- **State, not flags.** No `if`/`else` or boolean flags: state is an enum read by exhaustive match;
  a predicate may filter, never persist.
- **Grammars are regexes.** Every bespoke string or byte grammar is a named regex in one patterns
  module per package (`patterns.rs`, `patterns.py`); standard formats use their parsers.
- **One workspace per language,** rooted at the repository root (Cargo `[workspace]`, npm
  `workspaces`, uv `[tool.uv.workspace]`), with one lockfile and one toolchain pin.
- **Centralized dependencies.** Each dependency is declared once at the workspace root; a member
  pins differently only when forced, justified on the line. Default features stay on unless one
  compiles native code or a correctness feature must be added, each with its reason.
- **Reproducible from clean state.** Generated, downloaded and compiled artifacts stay out of
  version control; a fresh clone plus documented setup works with no manual repair.

---

## Security

All external input is parsed at the boundary (P2).

- Untrusted data is never interpolated into a query or command; queries are parameterized.
- Untrusted content is never emitted unescaped; an autoescape bypass carries a `// PROOF:` naming
  its trust source, and every bypass site is enumerable.
- Every deployment sets `Content-Security-Policy` (with `frame-ancestors`),
  `Strict-Transport-Security` and `Cross-Origin-Opener-Policy`. A CSP is adopted whole, with
  inline-script hashes chosen deliberately, never weakened with `unsafe-eval`.

---

## Testing

Few tests, well designed.

- Generators for unbounded domains, exhaustive loops for enumerable sets; generators declare their
  shrinking.
- Real implementations first; a fake only where the dependency needs external I/O; a mock only at
  a system boundary that cannot run in tests.
- Tests exercise the public interface only and assert every source of truth a state-changing
  operation touches: response, projection, persisted row, log line.
- Only end-to-end workflows, each readable as usage documentation. Leave simple code untested;
  never assert a constant, a dependency's behavior or the platform's.
- Keep independent cryptographic conformance and adversarial checks: a round trip passes when both
  peers share a bug.
- Rejection cases belong in the workflows they protect. Test code is exempt from A2's error rules.

---

## Verification

`README.md` owns check commands, tool versions, test scopes and environment limits. Run the checks
relevant to the change and report only what ran. Constructors, input boundaries, ownership,
confidentiality, data evolution and structural laws still need review.

## Provenance

P: Curry–Howard and binding-time analysis; A1: Rutten's coalgebras; A2: algebraic effects; A3:
affine ownership; A4: Denning's lattice; S: Bird and de Moor's algebra of programming, lenses
(Foster et al.; Hofmann, Pierce, Wagner), CALM (Hellerstein, Alvaro), parametricity (Wadler),
metamorphic testing (Chen et al.).
