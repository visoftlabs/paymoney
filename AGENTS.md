# Engineering Contract

This file defines reusable engineering rules. `README.md` owns project-specific architecture,
setup, commands and operational policies.
On conflict, this file wins. Language-specific rules apply only to source in that language.

For review, diagnosis, or explanation, inspect and report without editing. For a requested change,
preserve existing work, make the smallest in-scope change, and run the relevant documented checks.
Never claim a check that was not run. The rules below are normative; their basis explains intent
but does not create additional rules by inference.

---

## P — Stage-Minimality

> **Every runtime check is evidence of a missing type. Each check is discharged at the earliest
> binding time at which its inputs are bound; a residual check is admissible only at a
> binding-time boundary — the edge where dynamic input first arrives.**

P has four faces: the same statement applied to types, to input, to control flow, and to constants.

### P1 · Construction

A type is inhabited only by valid values.

- Any state that must not exist is unrepresentable — excluded by structure, not merely unreached.
- Required components are mandatory, not optional-and-checked.
- A finite set of cases, states or errors is one closed sum type; variants are mutually exclusive
  and each carries exactly the data valid for that case.
- **Native types wherever reasonable.** A constraint that TRAVELS — crosses a module or API
  boundary, is persisted, or is re-read later — earns a distinct type. A constraint checked and
  immediately consumed in one place earns a parse, not a type: a wrapper is scope (**A4**), paid
  for by every reader.
- Incomplete input exists only at the boundary that parses it, never past it.

Obligations:

- **Rust.** `struct` with non-`Option` required fields, private fields, and a smart constructor
  returning `Result<Self, E>`; case sets are `enum`s with data-carrying variants; a primitive is
  refined by a newtype (`struct UserId(Uuid)`) only where its constraint travels.
- **JavaScript** (`.mjs` + JSDoc). Domain values are built only by a factory returning the value or
  throwing; the result is frozen. Case sets are discriminated unions over a `const` tag set, one
  `@typedef` per variant.
- **CSS.** Geometry is constructed, never searched for. A box's size follows from the space its
  container passes in and the intrinsic size of its content; it is never obtained by measuring a
  rendered result. A dependency that runs both ways cannot be expressed. Space beyond intrinsic
  size is a declared proportion of free space (`fr`, `flex-grow`), never an absolute magnitude
  computed elsewhere. Adaptation is declared where the space is (`@container`).
- **HTML.** Use the element whose semantics **are** the guarantee — `<button>`, `<a href>`,
  `<dialog>`, `<details>`, `<label for>`, `<fieldset>`, `<output>`. A generic element plus ARIA
  re-implements focus, keyboard activation, role and form participation, and therefore re-checks
  what the native element proves. Required relationships are structural.

_Limit:_ precision costs evolvability, so scope "illegal states unrepresentable" to **stable domain
cores and traveling constraints**. At an evolving boundary — anything serialized, persisted, or sent
to a peer older than you — a permissive type parsed into a precise one is correct, and a maximally
strict wire schema is a defect. See **F**.

### P2 · Boundary

External input is untyped and untrusted until it is parsed exactly once, at the edge, and ONLY
there.

- Parsing returns a domain value or an error — never a truth-value alongside the still-raw input.
- Parsing CONSUMES the raw value, so nothing downstream can hold what was never validated.
- The parse may return the same native-typed shape normalized: value-or-error is the requirement,
  a distinct type is not.
- Unknown failures convert into the boundary's single error model here, with operation context.
- Format decoding uses a parser for that format, never imperative character manipulation.
- Past the boundary, code consumes validated types and never re-validates.

Obligations:

- **Rust.** `serde` shape-checks the wire and one named parse at the handler's front consumes and
  normalizes the value; a `try_from` intermediate only where a wire shape needs one. Use
  `deny_unknown_fields` for closed request shapes, not evolving or durable wire data governed by
  **F**. Any regex is a `static LazyLock<Regex>` in one module with a `// PROOF:` note.
- **JavaScript.** A schema parser at the edge (`JSON.parse` + schema validation, the `URL`
  constructor); any `RegExp` is a module-scope constant with a `// PROOF:` note. No
  `split`/`trim`/`slice` chains for structured formats.
- **HTML.** The control declares its constraints (`type`, `required`, `min`, `max`, `step`,
  `pattern`, `maxlength`) so the platform validates once and the user is told immediately. **A
  client-side constraint is an affordance, never a trust boundary** — the server parses
  independently. An island parser _converts_ a validated string into a domain value; it does not
  re-assert a constraint the attribute already declares.

### P3 · Totality

Each valid case has one path and fails fast at the point of failure.

- **A fallback for an invalid internal state signals an imprecise type: fix the type, not the branch.**
- Flow is linear composition over wrapped values, not nested branching with manual unwrapping.
- Transformation and validation are pure; effects are isolated (**A2**).
- An assertion the type system cannot verify carries an explicit proof annotation. An unprovable
  forced success in request-handling or concurrent code is a defect.

**A fallback is not a progressive enhancement.** A fallback is an alternative path written for an
invalid state or an unsupported capability inside the declared baseline; a progressive enhancement
is a single path whose platform degrades without an authored compatibility branch. Exhaustive case
analysis over valid runtime data and explicit error handling are not fallbacks. If the baseline
cannot support a requirement, change the topology or baseline explicitly instead of hiding it in a
compatibility branch.

Obligations:

- **Rust.** `?`, `map`, `and_then`; `unwrap`/`expect` only where infallibility is compiler-proven,
  each with `// PROOF:`. No `panic!` in request or concurrent paths.
- **JavaScript.** Promise and array combinators with early `throw`; any forced access carries a
  `// PROOF:` note. No throwing as control flow for expected cases.
- **CSS.** One cascade layer order, declared once. No `@supports` branch, no vendor prefix, no rule
  whose only purpose is undoing another rule. `!important` is a defect in the rule it overrides.

### P4 · Literals

Every literal resolves to exactly one binding time; one that fits none is a defect.

- **Structural** — bound by mathematics, calendar, protocol or format, and could not be otherwise
  (a unit conversion, days in a month, a port, a schema version). Annotated with a proof where
  infallibility is not self-evident.
- **Policy** — bound once per deployment, not derivable from data (a retention window, a page size,
  a budget). Give it one named, justified, authoritative binding at the least scope shared by its
  consumers. If a host format admits no reusable binding, the justified use site is the binding.
  Documentation references that binding instead of becoming another executable source of truth.
- **Calibrated** — not statically bound at all: a threshold over a _measured_ quantity, derived from
  a measured reference of that same quantity (a percentile of its own distribution, a ratio to a
  live baseline, a proportional budget), never an absolute value guessed offline. The reference is
  measured at a boundary (startup, warm-up, a rolling window), and readiness is gated on a
  self-check: a known reference value must fall on its expected side of the cutoff or the component
  fails fast. A dimensionless ratio beats an absolute magnitude, because it scales with its target.
  This is adaptive/percentile thresholding as used in SLO monitoring; the self-check is what
  separates it from a guess.
- **CSS lengths** take the same three kinds: structural (a ratio, `100%`, a `1px` hairline), policy
  (a `:root` token), calibrated (`min-content`, `fit-content`, `clamp()` over `cqi`/`vi`,
  `minmax()`). A hand-picked pixel breakpoint is an absolute threshold over a measured quantity, and
  therefore a defect.

---

## A1 — Observation

> **A lifecycle is a coalgebra. State is observed, never accumulated.** `render : X → B` is the
> observation map; `step : X × E → X` is the transition structure, pure and total over a closed
> event set. Together they are one map `X → B × X^E`. **Events are observed, never manufactured.**

**Bisimulation** — identical observations forever — is the correct equality for behavior, which is
why tests observe every source of truth and never reach inside. With `step` returning `Result` this
is a `T`-coalgebra for an error monad rather than a clean Moore machine; the argument holds either
way.

**A timer is not a substitute for an observable event.** A timer may bound or delay a transition,
or represent an explicit time-domain requirement. Polling, intervals, cron and periodic background
work are defects when an equivalent event exists or the product has no time-based requirement.

**Branch where the alternative is born.** A tagged union and its exhaustive match are warranted only
where the variant is decided by _runtime data_ — parsed input, an I/O result, a connection fact.
Where every call site statically knows its case, write one function per case; never manufacture a
tag that a switch you also wrote immediately decodes.

**Derived views need no machine.** When the platform or store already owns the canonical inputs, do
not shadow them in a state object — observe them with a pure derivation. Persist only irreducible
data; derive on read.

Obligations:

- **Rust.** State is an `enum`; `step` is a free function with no IO, clock or RNG; readers `match`
  exhaustively with no `_` arm absorbing new variants.
- **JavaScript.** State is a discriminated union; `step` is pure; readers `switch` on the tag with a
  `never`-typed exhaustiveness guard in the `default:` arm, declared via JSDoc, so an unhandled
  variant fails `tsc`.

---

## A2 — Confinement

> **Effects are confined to a shell that interprets them; the core is pure and total. Errors are
> effects: one typed error channel per boundary, handled or propagated with context, never
> dropped.**

A failed lifecycle state carries the context needed to recover and exposes a **named recovery
transition** — recovery is a visible edge in the state graph, never a hidden refresh or an implicit
retry.

Obligations:

- **Rust.** `Result<T, E>`; one `thiserror` enum per boundary with `#[from]`. No `anyhow`,
  `.map_err`, discarded `let _ = result`, or manually selected process `ExitCode` in production
  paths. A boundary that must attach context which `From` cannot receive matches the source result
  explicitly and constructs its contextual variant there; reformatting or erasing an error remains
  a defect. Binary `main` functions return `Result<(), E>` and let `Termination` select failure.
- **JavaScript.** `throw` a descriptive tagged `Error` subclass at the point of failure, caught
  exactly once at the shell boundary and folded into an explicit error state. No empty `catch`, no
  discarded promise, no `catch` returning a default.

---

## A3 — Ownership

> **Every resource has exactly one owner. Cleanup is structural and bound to scope, never enforced
> by discipline.**

- Shared access is explicit; references beat copies.
- Long-lived resources are owned by long-lived scopes; short-lived consumers borrow.
- Any state crossing a concurrency boundary has a documented owner. Data races are defects, not
  trade-offs.
- **Any retryable operation is idempotent at its boundary** — a retry must be a monotone update, so
  re-delivery cannot change the outcome. (Monotonicity is CALM's condition for coordination-freeness,
  here in its single-node form.)

Obligations:

- **Rust.** Ownership and borrowing; `Drop`/RAII; shared mutable state is `Arc<Mutex<_>>` with a
  documented owner; prefer `&T` over `clone()`.
- **JavaScript.** Lifetime tied to one owning scope with explicit `close`/`[Symbol.dispose]` or
  `try`/`finally`; pass references, not deep copies; one owning module per shared mutable value.
- **CSS/DOM.** **Geometry has exactly one owner: the stylesheet.** Script may write a custom
  property — an input the sheet consumes — and may never write a size or a position. Reading
  resolved geometry back into script is the layout form of shared mutable state: it reintroduces the
  cycle P1 forbids and makes `render` depend on its own output.

---

## A4 — Least Scope

> **Every artifact carries a label in a lattice and is placed at the least scope that covers all its
> consumers — never higher.**

**Visibility.** Order scopes by inclusion. An artifact used by two subtrees belongs at their **lowest
common ancestor**. Never import sideways, never register globally. The root is the only global scope
and placing something there is a visible, deliberate cost.

**Confidentiality.** Order truth by how few principals may observe it: build-truth (everyone) ⊏
server-truth (the server and its clients) ⊏ client-truth (one browser).

- **Computation is pushed to the highest label at which it is feasible**, so private inputs never
  flow downward. Feasibility is _measured_, not assumed.
- Moving a value down — client-truth to the server — is declassification and requires explicit
  authorization.
- Where full offload is infeasible, minimize what crosses: a commitment, a blinded value, a partial
  computation.
- Document authorized disclosures, recipients and exposed metadata in `README.md`.

---

## F — Forward-Only (scoped policy)

Classify data before applying this policy. P1 governs the precise in-memory domain value; F governs
its persistence and evolution, so the rules never compete at the same boundary.

- **Derived data** — anything rebuildable from source: one canonical definition, dropped and
  recreated on mismatch. No migration code, no version branch, no compatibility shim, no
  deprecated-but-live API. Breaking changes are welcome when they increase correctness.
- **Durable data** — anything not rebuildable: **accretion-only**. New fields are added, never
  repurposed; old fields are read but not required; removal happens by expand-then-contract, not by
  destructive rewrite. The persisted type is permissive at the edge and parsed into a precise type
  in memory (P2), which is how the two rules reconcile.

---

## Code Form

These shape how the laws are expressed and add no runtime semantics.

Repository paths in documentation and commands are relative to the repository root. Name the
repository explicitly when switching context; do not assume a checkout location. Host-required
absolute paths are supplied by the user at setup time, never hard-coded to a developer machine.

- **Immutable and canonical.** Prefer immutable data; mutation is explicit and scoped. Persist only
  irreducible source data; derive computed values on read. _Rust:_ bindings default immutable, `mut`
  deliberate and local. _TS:_ `const`, frozen shared data, no in-place mutation of inputs.
- **Type inference.** Annotate inputs; infer outputs. Add a non-input annotation only where inference
  is insufficient or a boundary cast is required. Never restate a derivable type. _Rust:_ annotate
  parameters, not inferable `let` bindings. _JS:_ `// @ts-check` on every file and a `@param {Type}`
  for every argument, **never** a `@returns`; a `@type` cast only where inference degrades.
- **Composition over abstraction.** Three similar lines beat a premature abstraction; introduce one
  when the pattern is stable and repeated. Flat composition of small functions over inheritance or
  trait towers. (Governs code shape; P4 still centralizes policy constants.)
- **Names over comments.** Intent is carried by names, precise types and small functions. Three
  comment kinds qualify: a `// PROOF:` note (P2, P3, P4), the one-line justification on a policy
  constant, and a rationale note recording why the obvious alternative was rejected. What
  disqualifies a comment is restating the code, not its length.
- **Claims are measured.** Every factual comment and document claim records something checked.
  Hypotheses and provisional values are labelled with the measurement that would resolve them.
  Probe first; do not present memory as evidence.
- **Drift is resolved, never carried.** When the code and a document disagree, one of them is edited
  deliberately and the change says which. A document mandating a gate the repo does not have is
  worse than no document.
- **Centralized dependencies.** Every dependency's name and version is declared exactly once, at the
  workspace root; members reference the workspace declaration. A member pins differently only when
  forced, with a one-line justification beside the pin.
- **Reproducible from clean state.** Generated, downloaded and compiled artifacts are excluded from
  version control. A fresh clone plus documented setup produces a working system with no manual
  repair.

---

## Security

All external input is parsed at the boundary (P2 is the mechanism).

- Untrusted data is never interpolated into a query or command string; queries are parameterized.
- Untrusted content is never emitted through unescaped output. **Autoescaping is never bypassed
  without a `// PROOF:` naming the trust source**, and every bypass site is enumerable.
- Every deployment sets `Content-Security-Policy` (including `frame-ancestors`, the only clickjacking
  defense CSP uniquely provides), `Strict-Transport-Security` and `Cross-Origin-Opener-Policy`.
  These are not configuration restating a default: the insecure state _is_ the default, so setting
  them is a decision.
- A CSP is adopted whole, with inline-script hashes designed deliberately — never piecemeal, and
  never weakened with `unsafe-eval` to admit a framework.

---

## Testing

Few tests, well designed.

- **Generators for unbounded domains, exhaustive loops for enumerable sets.** Sampling a set you can
  enumerate trades coverage for nothing. Generators declare their shrinking.
- **Real implementations, in strict order:** (1) the real implementation with in-process
  dependencies — the default; (2) a fake (in-memory, real behavior) only when the real dependency
  requires external I/O; (3) a mock only at a system boundary that cannot run in tests. Do not mock
  what can be faked; do not fake what can be used directly.
- **Observation is the specification (A1).** Behavior is bisimulation, so tests exercise the public
  interface only and assert **every** source of truth a state-changing operation touches — response,
  projection, persisted row, log line. Reaching into private state asserts a distinction behavior
  cannot observe.
- Prefer end-to-end workflows through public interfaces that also document library usage.
  Leave simple code untested; remove duplicate helper tests and test-only abstractions.
- Retain independent cryptographic conformance and adversarial proof checks: a round trip can
  succeed when both peers share a bug.
- Mutation testing is not required. Rejection cases belong in the workflows they protect.
- Test code is exempt from A2's strict error handling; keep it direct.

---

## Verification

`README.md` owns check commands, tool versions, test scopes and environment limitations.
Run the checks relevant to the change and report only what ran.
Constructors, input boundaries, ownership, confidentiality and data evolution still require review.

## Provenance

P draws on Curry–Howard, parametricity, and binding-time analysis; P3 on total functional
programming. A1 uses Rutten's coalgebraic account of behavior, A2 algebraic effects and the
functional-core/imperative-shell split, A3 affine ownership and separation logic, and A4 Denning's
information-flow lattice. F is a repository policy that reconciles precise in-memory values with
evolving persisted data.
