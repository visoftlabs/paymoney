//! Every pattern the crate matches text with, compiled once.

use crate::{
    attestation::REQUEST,
    leaf::{MAX_DIGITS, STATUS},
    statement::CURRENCY_LETTERS,
};
use regex::{Regex, bytes};
use std::sync::LazyLock;

/// PROOF: ISO 4217 codes are three uppercase ASCII letters.
pub(crate) static CURRENCY: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!("^[A-Z]{{{CURRENCY_LETTERS}}}$")).expect("currency pattern")
});
/// PROOF: an HTTP/1.1 head ends at the first empty line (RFC 9112 §2.1).
pub(crate) static HEAD_END: LazyLock<bytes::Regex> =
    LazyLock::new(|| bytes::Regex::new(r"\r\n\r\n").expect("head end pattern"));
/// PROOF: a plain (not chunked) leaf body is the JSON array itself.
pub(crate) static PLAIN_BODY: LazyLock<bytes::Regex> =
    LazyLock::new(|| bytes::Regex::new(r"^\[").expect("plain body pattern"));
/// PROOF: the status line prefix the leaf opens, escaped from `STATUS`.
pub(crate) static STATUS_LINE: LazyLock<bytes::Regex> = LazyLock::new(|| {
    let status = regex::escape(&String::from_utf8_lossy(STATUS));
    bytes::Regex::new(&format!("^{status}")).expect("status line pattern")
});
/// PROOF: the committed head the leaf opens, escaped from `REQUEST`, its lowercase hyphenated
/// UUID (RFC 9562) captured.
pub(crate) static REQUEST_HEAD: LazyLock<bytes::Regex> = LazyLock::new(|| {
    let [before, after] = REQUEST.map(|part| regex::escape(&String::from_utf8_lossy(part)));
    let uuid = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";
    bytes::Regex::new(&format!("^{before}({uuid}){after}$")).expect("request head pattern")
});
/// PROOF: the amounts the leaf reads: an optional minus and up to `MAX_DIGITS` digits.
pub(crate) static AMOUNT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(&format!("^-?[0-9]{{1,{MAX_DIGITS}}}$")).expect("amount pattern"));
