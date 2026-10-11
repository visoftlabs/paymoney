//! Statement words, parsed canonically: each word is the unique representative its circuit
//! range-checks, so a statement has exactly one encoding.

use crate::{
    Error,
    engine::{DIGEST, F},
    patterns::CURRENCY,
};
use hex::FromHex;
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
/// Bits of |amount|: 10⁹ < 2³⁰.
pub(crate) const AMOUNT_BITS: u32 = 30;
/// ISO 4217 codes are three letters.
pub(crate) const CURRENCY_LETTERS: u32 = 3;

/// Eight canonical KoalaBear words: a verifier set or a notary key; 64 hex digits in JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SerializeDisplay, DeserializeFromStr)]
pub struct Digest(pub(crate) [u32; DIGEST]);
impl From<[F; DIGEST]> for Digest {
    fn from(words: [F; DIGEST]) -> Self {
        Self(words.map(|word| word.as_canonical_u32()))
    }
}
impl FromStr for Digest {
    type Err = Error;
    fn from_str(text: &str) -> Result<Self, Error> {
        let bytes = <[u8; 4 * DIGEST]>::from_hex(text).or(Err(Error::Canonical))?;
        let words = <[[u8; 4]; DIGEST]>::try_from(bytes.as_chunks::<4>().0)
            .or(Err(Error::Canonical))?
            .map(u32::from_be_bytes);
        match words.iter().all(|word| *word < F::ORDER_U32) {
            true => Ok(Self(words)),
            false => Err(Error::Canonical),
        }
    }
}
impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0.map(u32::to_be_bytes).as_flattened()))
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
/// 12 hex digits in JSON, the words `[low, high]` in statements.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, SerializeDisplay, DeserializeFromStr,
)]
pub struct Key(u64);
impl Key {
    /// From two limbs already below 2^24.
    pub(crate) fn from_limbs(low: u32, high: u32) -> Self {
        Self(u64::from(low) | u64::from(high) << LIMB_BITS)
    }
    fn limbs(self) -> [u32; 2] {
        // PROOF: a key is below 2^48, so each 24-bit limb fits a word.
        [self.0 as u32 & LIMB_MASK, (self.0 >> LIMB_BITS) as u32]
    }
}
impl FromStr for Key {
    type Err = Error;
    fn from_str(text: &str) -> Result<Self, Error> {
        match u64::from_str_radix(text, 16) {
            Ok(key) if key >> (2 * LIMB_BITS) == 0 => Ok(Self(key)),
            _ => Err(Error::Canonical),
        }
    }
}
impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:012x}", self.0)
    }
}

/// Signed minor units as 72-bit two's complement in three 24-bit limbs; a decimal string in JSON.
#[derive(Clone, Copy, Debug, PartialEq, Eq, SerializeDisplay, DeserializeFromStr)]
pub struct Amount([u32; 3]);
impl Amount {
    pub fn new(minor: i64) -> Result<Self, Error> {
        match -MAX_AMOUNT < minor && minor < MAX_AMOUNT {
            true => Ok(Self::of(i128::from(minor))),
            false => Err(Error::Amount(minor)),
        }
    }
    /// From any value in `[-2^71, 2^71)`.
    fn of(minor: i128) -> Self {
        // PROOF: rem_euclid maps into [0, 2^72); each shifted limb is masked to 24 bits.
        let bits = minor.rem_euclid(1 << 72) as u128;
        Self([0, 1, 2].map(|i| (bits >> (LIMB_BITS * i)) as u32 & LIMB_MASK))
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
impl FromStr for Amount {
    type Err = Error;
    fn from_str(text: &str) -> Result<Self, Error> {
        match text.parse::<i128>() {
            Ok(minor) if (-(1 << 71)..1 << 71).contains(&minor) => Ok(Self::of(minor)),
            _ => Err(Error::Canonical),
        }
    }
}
impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.minor())
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
            .chain(self.key.limbs())
            .chain(self.amount.0)
            .collect()
    }
}

/// What an aggregate proves: `count` distinct legs attested by `notary` in `currency`, keys in
/// `lo..=hi`, summing to `sum`; `set` names the verifier set that checked them. Its JSON is also
/// the verdict people read.
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
    /// Merge witness hints, `[gap0, gap1, borrow, carry0, carry1, carry2]`.
    pub(crate) const HINTS: usize = 6;
    pub(crate) fn words(&self) -> Vec<u32> {
        let set = self.set.0.into_iter();
        set.chain(self.notary.0)
            .chain([self.currency.0])
            .chain(self.lo.limbs())
            .chain(self.hi.limbs())
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
    pub(crate) fn merge(&self, right: &Self) -> Result<(Self, [u32; Self::HINTS]), Error> {
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
        let [hi_low, _] = self.hi.limbs();
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
