//! Statement words, parsed canonically: each word is the unique representative its circuit
//! range-checks, so a statement has exactly one encoding.

use crate::{
    Error,
    engine::F,
    patterns::{CURRENCY, DIGEST, WORD},
};
use p3_field::PrimeField32;
use serde::{Deserialize, Serialize};
use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::{fmt, ops::Range, str::FromStr};

pub(crate) const LIMB_BITS: u32 = 24;
const LIMB_MASK: u32 = (1 << LIMB_BITS) - 1;
/// Policy: |amount| < 10^9 minor units (the leaf reads at most nine digits), so 2^30 legs never
/// wrap the 72-bit sum.
const MAX_AMOUNT: i64 = 1_000_000_000;
pub(crate) const COUNT_BITS: u32 = 30;

fn limbs<const N: usize>(words: [u32; N]) -> Result<[u32; N], Error> {
    match words.iter().all(|word| *word <= LIMB_MASK) {
        true => Ok(words),
        false => Err(Error::Canonical),
    }
}

/// Eight canonical KoalaBear words: a verifier set or a notary key; hex on display.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "[u32; 8]")]
pub struct Digest(pub(crate) [u32; 8]);
impl TryFrom<[u32; 8]> for Digest {
    type Error = Error;
    fn try_from(words: [u32; 8]) -> Result<Self, Error> {
        match words.iter().all(|word| *word < F::ORDER_U32) {
            true => Ok(Self(words)),
            false => Err(Error::Canonical),
        }
    }
}
impl From<[F; 8]> for Digest {
    fn from(words: [F; 8]) -> Self {
        Self(words.map(|word| word.as_canonical_u32()))
    }
}
impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|word| write!(f, "{word:08x}"))
    }
}
impl FromStr for Digest {
    type Err = Error;
    fn from_str(text: &str) -> Result<Self, Error> {
        if !DIGEST.is_match(text) {
            return Err(Error::Canonical);
        }
        let words = WORD
            .find_iter(text)
            .map(|word| u32::from_str_radix(word.as_str(), 16))
            .collect::<Result<Vec<_>, _>>()
            .or(Err(Error::Canonical))?;
        Self::try_from(<[u32; 8]>::try_from(words).or(Err(Error::Canonical))?)
    }
}

/// ISO 4217 code as one big-endian word of three uppercase ASCII letters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SerializeDisplay, DeserializeFromStr)]
pub struct Currency(pub(crate) u32);
impl FromStr for Currency {
    type Err = Error;
    fn from_str(code: &str) -> Result<Self, Error> {
        match CURRENCY.is_match(code) {
            true => Ok(Self(
                code.bytes()
                    .fold(0, |word, byte| word << 8 | u32::from(byte)),
            )),
            false => Err(Error::Currency(code.to_owned())),
        }
    }
}
impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [_, bytes @ ..] = self.0.to_be_bytes();
        f.write_str(&String::from_utf8_lossy(&bytes))
    }
}

/// Sort key of one leg: low 24 bits of two Poseidon2 words of its `legId`, a 48-bit integer;
/// in statements, the words `[low, high]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "[u32; 2]", into = "[u32; 2]")]
pub struct Key(u64);
impl TryFrom<[u32; 2]> for Key {
    type Error = Error;
    fn try_from(words: [u32; 2]) -> Result<Self, Error> {
        let [low, high] = limbs(words)?;
        Ok(Self::from_limbs(low, high))
    }
}
impl From<Key> for [u32; 2] {
    fn from(key: Key) -> Self {
        // PROOF: a key is below 2^48, so each 24-bit limb fits a word.
        [key.0 as u32 & LIMB_MASK, (key.0 >> LIMB_BITS) as u32]
    }
}
impl Key {
    /// From two limbs already below 2^24.
    pub(crate) fn from_limbs(low: u32, high: u32) -> Self {
        Self(u64::from(low) | u64::from(high) << LIMB_BITS)
    }
}
impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:012x}", self.0)
    }
}

/// Signed minor units as 72-bit two's complement in three 24-bit limbs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "[u32; 3]")]
pub struct Amount([u32; 3]);
impl TryFrom<[u32; 3]> for Amount {
    type Error = Error;
    fn try_from(words: [u32; 3]) -> Result<Self, Error> {
        Ok(Self(limbs(words)?))
    }
}
impl Amount {
    pub fn new(minor: i64) -> Result<Self, Error> {
        if !(-MAX_AMOUNT < minor && minor < MAX_AMOUNT) {
            return Err(Error::Amount(minor));
        }
        // PROOF: rem_euclid maps into [0, 2^72); each shifted limb is masked to 24 bits.
        let bits = i128::from(minor).rem_euclid(1 << 72) as u128;
        Ok(Self(
            [0, 1, 2].map(|i| (bits >> (LIMB_BITS * i)) as u32 & LIMB_MASK),
        ))
    }
    pub fn minor(self) -> i128 {
        let bits = self
            .0
            .iter()
            .rev()
            .fold(0u128, |total, limb| total << LIMB_BITS | u128::from(*limb));
        // PROOF: bits < 2^72 < i128::MAX; the top bit selects the negative half.
        let value = bits as i128;
        if bits >> 71 == 1 {
            value - (1 << 72)
        } else {
            value
        }
    }
    /// Sum mod 2^72 and the per-limb carries.
    fn add(self, other: Self) -> (Self, [u32; 3]) {
        let (mut limbs, mut carries, mut carry) = (self.0, [0; 3], 0);
        for ((limb, b), out) in limbs.iter_mut().zip(other.0).zip(&mut carries) {
            let total = *limb + b + carry;
            (*limb, carry) = (total & LIMB_MASK, total >> LIMB_BITS);
            *out = carry;
        }
        (Self(limbs), carries)
    }
}

/// Number of distinct legs, in `1..2^30`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "u32")]
pub struct Count(u32);
impl TryFrom<u32> for Count {
    type Error = Error;
    fn try_from(count: u32) -> Result<Self, Error> {
        match (1..1 << COUNT_BITS).contains(&count) {
            true => Ok(Self(count)),
            false => Err(Error::Canonical),
        }
    }
}
impl Count {
    pub fn get(self) -> u32 {
        self.0
    }
}

/// One proven leg: who attested it, in which currency, its key and signed amount.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Leg {
    pub notary: Digest,
    pub currency: Currency,
    pub key: Key,
    pub amount: Amount,
}
impl Leg {
    pub(crate) const WORDS: usize = 14;
    /// Notary and currency, copied into the statement's shared words.
    pub(crate) const SHARED: Range<usize> = 0..9;
    pub(crate) const KEY: Range<usize> = 9..11;
    pub(crate) const AMOUNT: Range<usize> = 11..14;
    pub(crate) fn words(&self) -> Vec<u32> {
        let notary = self.notary.0.into_iter();
        notary
            .chain([self.currency.0])
            .chain(<[u32; 2]>::from(self.key))
            .chain(self.amount.0)
            .collect()
    }
}

/// What an aggregate proves: `count` distinct legs attested by `notary` in `currency`, keys in
/// `lo..=hi`, summing to `sum`; `set` names the verifier set that checked them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub set: Digest,
    pub notary: Digest,
    pub currency: Currency,
    pub lo: Key,
    pub hi: Key,
    pub sum: Amount,
    pub count: Count,
}
impl Statement {
    pub(crate) const WORDS: usize = 25;
    pub(crate) const SET: Range<usize> = 0..8;
    /// Set, notary and currency: equal across a whole tree.
    pub(crate) const SHARED: Range<usize> = 0..17;
    pub(crate) const LO: Range<usize> = 17..19;
    pub(crate) const HI: Range<usize> = 19..21;
    pub(crate) const SUM: Range<usize> = 21..24;
    pub(crate) const COUNT: usize = 24;
    pub(crate) fn words(&self) -> Vec<u32> {
        let set = self.set.0.into_iter();
        set.chain(self.notary.0)
            .chain([self.currency.0])
            .chain(<[u32; 2]>::from(self.lo))
            .chain(<[u32; 2]>::from(self.hi))
            .chain(self.sum.0)
            .chain([self.count.0])
            .collect()
    }
    pub(crate) fn of_leg(set: Digest, leg: Leg) -> Self {
        Self {
            set,
            notary: leg.notary,
            currency: leg.currency,
            lo: leg.key,
            hi: leg.key,
            sum: leg.amount,
            count: Count(1),
        }
    }
    /// Native mirror of the merge relation: the merged statement and its witness hints
    /// `[gap0, gap1, borrow, carry0, carry1, carry2]`.
    pub(crate) fn merge(&self, right: &Self) -> Result<(Self, [u32; 6]), Error> {
        if (self.set, self.notary, self.currency) != (right.set, right.notary, right.currency) {
            return Err(Error::Mismatch);
        }
        let gap = right
            .lo
            .0
            .checked_sub(self.hi.0 + 1)
            .ok_or(Error::Order(self.hi, right.lo))?;
        let count = Count::try_from(self.count.0 + right.count.0)?;
        let (sum, [c0, c1, c2]) = self.sum.add(right.sum);
        // PROOF: gap < 2^48, so both shifted limbs fit 24 bits.
        let [gap0, gap1] = [gap as u32 & LIMB_MASK, (gap >> LIMB_BITS) as u32];
        let [hi_low, _] = <[u32; 2]>::from(self.hi);
        let borrow = (hi_low + 1 + gap0) >> LIMB_BITS;
        let merged = Self {
            hi: right.hi,
            sum,
            count,
            ..*self
        };
        Ok((merged, [gap0, gap1, borrow, c0, c1, c2]))
    }
}

/// A verified statement, for people: hex IDs, a signed diff in minor units.
#[derive(Debug, Deserialize, Serialize)]
pub struct Verdict {
    pub set: String,
    pub notary: String,
    pub currency: String,
    pub diff: String,
    pub count: u32,
    pub lo: String,
    pub hi: String,
}
impl From<Statement> for Verdict {
    fn from(statement: Statement) -> Self {
        Self {
            set: statement.set.to_string(),
            notary: statement.notary.to_string(),
            currency: statement.currency.to_string(),
            diff: statement.sum.minor().to_string(),
            count: statement.count.get(),
            lo: statement.lo.to_string(),
            hi: statement.hi.to_string(),
        }
    }
}
