# paymoney

Notarize Revolut transactions with TLSNotary (MPC-TLS), prove each leg in zero knowledge with
Plonky3, and aggregate leg proofs by proof-carrying data into one root stating their signed sum
(the balance diff) and count. `core/` (`paymoney-core`) is the proof system; the PayMoney server
verifies roots with it.

## The claim

A verified root states:

> Verifier set `set` checked `count` distinct legs, each read from a response `app.revolut.com`
> sent over TLS to `GET /api/retail/transaction/{id}`, attested by the notary whose key hashes to
> `notary`; each is `COMPLETED` in `currency`; their signed minor amounts sum to `sum`; their keys
> lie in `lo..=hi`.

It is a bearer claim: it binds no account, submitter or time (`ConnectionInfo.time` stays an
opaque field hash), and a root is transferable. One leg may appear in separately submitted roots;
a verifier that cares tracks accepted key ranges.

## Trust

| Party                      | Assumed                | Can                                                                                              |
| -------------------------- | ---------------------- | ------------------------------------------------------------------------------------------------ |
| Prover (extension, binary) | adversarial            | pick transactions, hidden headers, legs, positions; edit local files                             |
| Revolut                    | honest                 | is the only source of response bytes; chooses every key and the `id`, `state`, `currency` values |
| Notary                     | honest, one key holder | sees server name, lengths, timing; signs attestations                                            |
| Verifier                   | honest                 | trusts its notary's key; derives `set` from code                                                 |

Soundness: without forging XMSS, breaking Poseidon2 or the STARK, a prover cannot make a verifier
accept a statement other than the claim. The prover chooses which genuine bytes are read; the
circuit fixes how.

| Party           | Learns                                                                           | Never learns                     |
| --------------- | -------------------------------------------------------------------------------- | -------------------------------- |
| Notary          | server name and chain, TLS time/version, ciphertext lengths, blinded commitments | request, cookies, response, legs |
| Server          | the root statement                                                               | legs, amounts, ids, responses    |
| Page            | listed transactions, header names, logs, verdicts                                | header values, records, proofs   |
| data dir (0700) | records (full responses), leaves, roots, each 0600                               | session headers                  |

## Notarization (`src/notary.rs`, `src/http.rs`)

- Request: a HAR 1.2 request `{ method, url, headers: [{ name, value, _attached? }], postData? }`
  (other HAR fields ignored), `https` only; `host`, `content-type`, `content-length`,
  `transfer-encoding` and repeated names are refused. On the wire: request line, `host` from the
  URL, `content-type` from `postData.mimeType`, headers in order. `_attached` values are never
  committed, logged or stored.
- MPC-TLS with `max_sent = 8 KiB`, `max_recv = 8192`. The prover commits `sent[0..head)` (request
  line, `host`, the headers before the first attached one) and `recv[0..n)` with hash 128,
  revealing only the server identity. A 200 to the transaction-details head yields a `Record`,
  saved as `records/<transactionId>.json`.
- The session runs over one full-duplex HTTP/3 request, `POST /api/notary` to the server (request
  body up, response body down); the attestation request and the attestation cross it as JSON.
- The notary, run by the PayMoney server, adds `Extension { "server_name": <verified name> }` to
  what it verified and signs with XMSS.

The leaf opens exactly this 144-byte head:

```text
GET /api/retail/transaction/<36-char UUID> HTTP/1.1\r\nhost: app.revolut.com\r\nconnection: close\r\naccept-encoding: identity\r\n
```

**Hash 128.** `H(m)` = the 8 rate words of `PaddingFreeSponge<Poseidon2-KoalaBear-16, rate 8>` over
little-endian 3-byte words of `"tlsn/poseidon2/koalabear/16/v1" ‖ m ‖ 0x01 ‖ 0*`, each word as 4
LE bytes. Implemented natively (`tlsn_hash`), in tlsn's boolean VM (mpz2 fork) and in the leaf.
A commitment is `H(data ‖ blinder16)`.

**Attestation fields** (`H(domain ‖ BCS(field))`, rs_merkle root over 7 leaves; `domain` is
tlsn's `BLAKE3(type path)[..16]`, a constant per type in `core/src/attestation.rs`):

| Id  | Field                                       | In the leaf                      |
| --- | ------------------------------------------- | -------------------------------- |
| 0   | `VerifyingKey` `0x80 ‖ 0x30 ‖ key`          | recomputed; its hash is `notary` |
| 1–3 | connection info, ephemeral key, certificate | private, unchecked               |
| 4   | `server_name = app.revolut.com`             | constant                         |
| 5   | sent commitment over `[0, 144)`             | recomputed from the UUID         |
| 6   | received commitment over `[0, n)`           | recomputed from the response     |

The signed header is `uid16 ‖ 0⁴ ‖ 0x80 ‖ 0x20 ‖ root32`; the XMSS message is `H(HEADER, pack(header))`.

## Leaf (`core/src/leaf.rs`)

Commit-and-prove over the tlsn commitments (DECO's two-stage parsing). Private witness: key,
signature, uid, field hashes 1–3, UUID, both blinders, the response stream
`response ‖ blinder ‖ 0x01 ‖ 0*` (8209 bytes), a prefix mask, the framing bit, zero-test inverses,
and five one-hot positions. Constraints:

1. Field hashes 0, 5, 6, the Merkle root, the header, and XMSS verified in-circuit (Drake et al.,
   ePrint 2025/055: 39 chains, base 16, target sum 293, lifetime 2¹⁰).
2. `mask` is a prefix of ones of length `n`; the marker follows the blinder; the response digest
   is the chained sponge's output at the marker block. Bytes `0..13` are `HTTP/1.1 200 `.
3. Body framing: plain (first byte `[`) or chunked, by a one-hot phase machine whose `rest = 0`
   test is `z = 1 − rest·inv`, `rest·z = 0`. The payload is exactly the de-chunked body.
4. A byte-serial JSON pushdown automaton (string, escape across chunk boundaries, depth,
   top-level element, `acc·R + byte` accumulator over E with `R = (5, 7, 9, 11)`). The payload is
   one top-level array closing on its last byte.
5. Each field's position is a payload byte right after a structural `:` at depth 2, its key's
   accumulator matches, and all five share one element. Strings open at the position and close
   once; `currency` is 3 bytes; `amount` is an optional leading `-` and 1–9 digits.
6. `id = UUID`, `state = COMPLETED`; `key = 48 low bits of H(LEG, acc(legId))`; the amount as
   72-bit two's complement in three 24-bit limbs.

Statement (14 words): `notary[8] ‖ currency ‖ key[2] ‖ amount[3]`.

Strings never produce structural bytes, so payer text (descriptions, comments) cannot be read as
a field, even a description such as `Lunch \"amount\":999,\"state\":\"COMPLETED\" \\` split by a
chunk boundary inside the `\\`.
Natively, the witness reads the payload with a pest JSON grammar (`core/src/json.pest`), stricter
than the circuit (a liveness, never a soundness, difference); chunked framing stays a byte
machine, since a chunk's length equal to its declared size is beyond any grammar.
Accumulators are a fixed public polynomial, a fingerprint, not a collision-resistant hash: sound
because every compared string is Revolut's. Duplicate keys inside one leg object (not observed)
would let the prover pick either.

## Aggregation (`core/src/circuits.rs`)

Statement (25 words): `set[8] ‖ notary[8] ‖ currency ‖ lo[2] ‖ hi[2] ‖ sum[3] ‖ count`, each word
parsed canonically (digest words `< p`, limbs `< 2²⁴`, `count ∈ 1..2³⁰`).

- **wrap** verifies a leaf against its preprocessing commitment as a constant: `lo = hi = key`,
  `sum = amount`, `count = 1`.
- **merge** verifies two children as members of the set: each child's key,
  `H(CIRCUIT_KEY, descriptor digest ‖ preprocessing roots)`, hashes with a sibling key to `set`.
  It checks `left.hi + 1 + gap = right.lo` (integer equality over 24-bit limbs), the sum mod 2⁷²
  with carries, and the count in 30 bits.
- `set = H(VERIFIER_SET, key(wrap) ‖ key(merge))`. `prepare` requires equal wrap and merge
  descriptors, so one recursive verifier serves the set; the leaf is bound through wrap.
- Strictly increasing keys make the tree a Merkle-sum tree over a sorted range: no leg counts
  twice. A 48-bit key collision blocks aggregation (liveness), never double counts.
- Wrap and merge use fixed strict table heights (`LAYOUT`), calibrated as the smallest both accept.

`check`: canonical parse, `set` equals this code's, the proof checks; which notaries to trust is
the verifier's policy. A statement's JSON is readable as it stands: `set` and `notary` as 64 hex
digits, `currency` as its code, `lo`/`hi` as 12 hex digits, `sum` as signed decimal minor units,
`count` as a number; each parses back to its canonical words.

## Parameters

| Item        | Value                                                                                                                                                   |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Field       | KoalaBear `p = 2³¹ − 2²⁴ + 1`, challenges in its degree-4 extension                                                                                     |
| STARK       | batch STARK, hiding FRI: blowup 4, final poly 2⁶, arity 4, 56 queries, 15-bit PoW, 4 salt elements (proof-client's profile; no composed security claim) |
| ZK          | preprocessing seeded (0, 1, 2) so all verifiers derive one set; salts reseeded from the OS after `prepare`                                              |
| Domain tags | `0x504d_02xx` keys and set, `0x504d_0301` leg, `0x504d_04xx` XMSS, `0x504d_0501` header                                                                 |
| Limits      | response ≤ 8192 bytes, JSON depth ≤ 15, \|amount\| < 10⁹, < 2³⁰ legs, 2¹⁰ signatures per key                                                            |

## Interface

`paymoney` is a Chrome native-messaging host: JSON-RPC 2.0, one message per native-endian
length-prefixed frame (≤ 64 KiB in) on stdio. It logs tracing-subscriber's JSON to stderr, which
Chrome keeps in its own log, with OpenTelemetry attribute names (`event.name`, `url.full`, …); the
first event per request, `message.received`, carries the request with attached values redacted.
Protocol steps are spans: `notarize` runs `connect`, `preprocess`, `exchange`, `prove`,
`request_attestation`; `prove` and `aggregate` run `prepare`, then `prove_leg`, or `wrap` per leg
and `merge` per pair. `RUST_LOG` overrides the INFO default. Release builds only: debug builds run
Plonky3's serial self-checks.

| Method        | Params              | Result                                                                     |
| ------------- | ------------------- | -------------------------------------------------------------------------- |
| `host.status` | —                   | `{ version, dataDir }`                                                     |
| `fetch`       | `request` (HAR)     | `{ response }`: HAR, headers withheld (`set-cookie` can carry the session) |
| `notarize`    | `request`, `server` | `{ response, record }`; `record` is `null` unless 200                      |
| `prove`       | `record`, `legId`   | `{ key, amount }`                                                          |
| `aggregate`   | `legIds`            | `{ root, summary }`                                                        |
| `submit`      | `root`, `server`    | the statement the server verified; its RFC 9457 problem as error `data`    |
| `install`     | —                   | `{ manifest }`: Chrome's native messaging host `finance.paymoney.host`     |

`server` is the PayMoney server: `{ url, certificate? }`, its origin and, for a self-signed
certificate, that certificate (PEM), then the only root trusted (otherwise Mozilla's roots verify
it). Both methods speak HTTP/3 to it: `notarize` one full-duplex `POST /api/notary`, `submit` a
`POST /api/proofs` of the root, answered by its statement or an RFC 9457 problem.

Errors: -32700 parse, -32600 invalid request (batches included), -32601 unknown method, -32602
invalid params (a refused header, an id that is not a UUID), -32000 any failure inside a method.
Artifacts are named by UUID, never by path: `records/<transactionId>`, `leaves/<legId>`,
`roots/<fresh id>`, each replaced atomically, in the data dir: `~/Library/Application
Support/finance.paymoney` on macOS, `$XDG_DATA_HOME/finance.paymoney` (default `~/.local/share/finance.paymoney`)
on Linux.

```sh
cargo install --git https://github.com/visoftlabs/paymoney
printf '\053\000\000\000{"jsonrpc":"2.0","id":1,"method":"install"}' | paymoney | tail -c +5
```

From a terminal, a message is framed by hand: its JSON's byte length as a native-endian `u32`
(`\053\000\000\000` is 43), then the JSON; `tail -c +5` drops the reply's prefix.

A `request` lists the leaf's head first, then each session header as `{ name, _attached: true }`;
Revolut answered 400 to only `cookie`, `x-device-id`, `x-client-version` and
`x-browser-application`.

## Performance

2026-10-08, a local fixture, release, 16-core Apple Silicon: commitments for a 785-byte response 4.8 s;
preparing the circuits 2.3 s; one leaf 9.5 s (largest table 2²¹ rows); aggregating 3 legs 10 s.
A real 4.1 KB Revolut response is not yet measured. These figures predate Plonky3 `0.9.0-rc.1`
and upstream Plonky3-recursion's one-worker hiding pool; re-timing `prove` and `aggregate` on
this stack resolves them.

## Forks

Plonky3 is upstream's `0.9.0-rc.1` from crates.io. Each fork's `feat/paymoney` is rebased on an
unpatched mirror of upstream; consumers reference it by branch and `Cargo.lock` pins the commit.
A rebase may leave older lockfiles pinning commits no branch reaches.

- **Plonky3-recursion** (upstream `main`): `preprocessed_commitment()`.
- **mpz2**: the Poseidon2-KoalaBear boolean circuit (0.96 M AND gates per permutation) and the VM
  byte hash.
- **tlsn**: `HashAlgId::POSEIDON2_KOALABEAR` and its commitment arm; public `Body::hash_fields`.

## Open

- Measure a real `app.revolut.com` head, notarization time and peak RSS.
- The FRI profile's security level needs its own review.

## Checks

```sh
cargo fmt --check
cargo clippy --release --all-targets -- -D warnings
cargo test --release
```

The one test prepares every circuit (4 s in release): Plonky3-recursion rejects a circuit when
preparing it, not when building it, so a dependency bump must pass it. The rest of the pipeline
is checked by hand through paymoney-finance's guide.
