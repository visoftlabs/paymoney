//! Every pattern the binary matches text with, compiled once.

use regex::Regex;
use std::sync::LazyLock;

/// PROOF: Chrome passes the caller's origin, `chrome-extension://<32 letters a–p>/`, as the
/// native host's first argument.
pub static ORIGIN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("^chrome-extension://[a-p]{32}/$").expect("origin pattern"));
/// PROOF: artifact names are lowercase hex runs joined by single dashes: a record's digest, a
/// hyphenated UUID, or a root's `{lo}-{hi}-{count}`; never `/` or `.`, so never a path.
pub static NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("^[0-9a-f]+(?:-[0-9a-f]+)*$").expect("name pattern"));
/// PROOF: a certificate's SHA-256, as WebTransport's `serverCertificateHashes` pins it: 32 bytes in
/// lowercase hex.
pub static CERTIFICATE_HASH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("^[0-9a-f]{64}$").expect("certificate hash pattern"));
/// PROOF: one byte of a matched `CERTIFICATE_HASH`.
pub static HEX_BYTE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("[0-9a-f]{2}").expect("hex byte pattern"));
