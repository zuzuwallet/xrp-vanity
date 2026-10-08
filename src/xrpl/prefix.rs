//! Classic-address prefix checks and a search-cost estimate.
//!
//! A classic address is Base58Check(`0x00 || account_id || checksum`).
//! The version byte is zero, so every address has at least one leading `r`
//! (`r` is alphabet index 0). Let `z` be the number of leading zero payload
//! bytes and `n` the integer value of the remaining bytes. The address is
//! `r` repeated `z` times, followed by the base58 digits of `n`.
//!
//! For exactly `z` leading zeros, `n` is in
//! `[2^(8*(24-z)), 2^(8*(25-z)))`. `2^192` does not fit in `u128`, so the
//! estimate uses `BigUint`. The displayed number is an estimate, not a
//! promise of how long a search will take.
//!
//! Checksum feasibility is exact. A payload is 21 data bytes plus a 4-byte
//! checksum. For an interval `[L, R)`, only data values from `L >> 32`
//! through `(R - 1) >> 32` can fall inside it. If that range covers a whole
//! 2^32-aligned block, some checksum is inside the block and the prefix is
//! possible. Otherwise at most two data values are hashed. A possible prefix
//! whose expected attempt count does not fit in the search counter is rejected.
//!
//! `rZuZu` fixes `z = 1` and a 4-digit body. Only the 32-digit slot intersects
//! the `z = 1` window, and that slot has width `58^28`. Expected attempts are
//! `round(2^192 / 58^28) = 264104224`.

use num_bigint::BigUint;

use crate::error::Error;
use crate::xrpl::base58::XRPL_ALPHABET;
use crate::xrpl::hash::sha256d;

/// Shared with `search::COUNTER_HEADROOM`.
///
/// `prefix` does not import `search`: that module already calls
/// `validate_prefix`. The search counter stops at `u64::MAX` minus this
/// headroom, so a prefix whose estimate is already past that line is rejected
/// before any worker starts.
pub(crate) const SEARCH_COUNTER_HEADROOM: u64 = 1_048_576;

/// Longest string that can be a prefix of a classic address.
///
/// The spec table allows up to 35 characters across Base58 types. A classic
/// address payload is 25 bytes beginning with `0x00`, so the integer is below
/// `2^192` and the body has at most 33 digits. With the leading `r`, the
/// maximum classic address length is 34.
pub const MAX_PREFIX_LEN: usize = 34;

const CONFIRMATION_THRESHOLD: u64 = 1_000_000_000_000;

const IMPOSSIBLE: &str = "prefix cannot occur in any classic address";
const UNCOUNTABLE: &str = "prefix search exceeds this implementation's supported attempt range";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrefixEstimate {
    expected: BigUint,
}

impl PrefixEstimate {
    pub fn expected_attempts(&self) -> &BigUint {
        &self.expected
    }

    pub fn display_attempts(&self) -> String {
        format_attempts(&self.expected)
    }

    /// True when the estimate is above 10^12. The CLI then asks for `SEARCH`.
    pub fn needs_large_search_confirmation(&self) -> bool {
        self.expected > BigUint::from(CONFIRMATION_THRESHOLD)
    }
}

pub fn validate_prefix(prefix: &str) -> Result<PrefixEstimate, Error> {
    if prefix.is_empty() {
        return Err(Error::Prefix("prefix must not be empty"));
    }
    let chars = prefix.chars().count();
    if chars > MAX_PREFIX_LEN {
        return Err(Error::Prefix("prefix is longer than 34 characters"));
    }
    if !prefix.starts_with('r') {
        return Err(Error::Prefix("prefix must start with r"));
    }
    if prefix.chars().any(|ch| alphabet_index(ch).is_none()) {
        return Err(Error::Prefix(
            "prefix contains a character outside the XRPL classic-address alphabet",
        ));
    }
    let expected = expected_attempts(prefix)?;
    Ok(PrefixEstimate { expected })
}

fn expected_attempts(prefix: &str) -> Result<BigUint, Error> {
    let k = prefix.chars().take_while(|ch| *ch == 'r').count();
    let rest: String = prefix.chars().skip(k).collect();
    let space = BigUint::from(1u8) << 192usize;

    if rest.is_empty() {
        if k == 0 || k > 25 {
            return Err(Error::Prefix(IMPOSSIBLE));
        }
        let count = BigUint::from(1u8) << (8 * (25 - k));
        let zero = BigUint::from(0u8);
        if !interval_has_valid_checksum(&zero, &count) {
            return Err(Error::Prefix(IMPOSSIBLE));
        }
        return finish_estimate(&space, &count);
    }

    // A non-empty body means z is exactly k. z = 25 consumes the whole payload.
    if k == 0 || k > 24 {
        return Err(Error::Prefix(IMPOSSIBLE));
    }

    let lo = BigUint::from(1u8) << (8 * (24 - k));
    let hi = BigUint::from(1u8) << (8 * (25 - k));
    let value = base58_value(&rest);
    let digits = rest.len();
    let fifty_eight = BigUint::from(58u32);
    let mut total = BigUint::from(0u8);
    let mut spans: Vec<(BigUint, BigUint)> = Vec::new();

    for length in digits..=33 {
        let pow = fifty_eight.pow((length - digits) as u32);
        let start = &value * &pow;
        let end = (&value + 1u32) * &pow;
        let left = if start > lo { start } else { lo.clone() };
        let right = if end < hi { end } else { hi.clone() };
        if left < right {
            total += &right - &left;
            spans.push((left, right));
        }
    }

    if total == BigUint::from(0u8)
        || !spans
            .iter()
            .any(|(start, end)| interval_has_valid_checksum(start, end))
    {
        return Err(Error::Prefix(IMPOSSIBLE));
    }
    finish_estimate(&space, &total)
}

fn finish_estimate(space: &BigUint, count: &BigUint) -> Result<BigUint, Error> {
    let expected = rounded_div(space, count);
    let limit = BigUint::from(u64::MAX.saturating_sub(SEARCH_COUNTER_HEADROOM));
    if expected >= limit {
        Err(Error::Prefix(UNCOUNTABLE))
    } else {
        Ok(expected)
    }
}

/// True when some 25-byte Base58Check payload lies in `[start, end)`.
///
/// `last >= first + 2` means a complete 2^32 checksum block sits inside the
/// interval, so a valid payload exists and no hash is required.
fn interval_has_valid_checksum(start: &BigUint, end: &BigUint) -> bool {
    if start >= end {
        return false;
    }
    let first = start >> 32usize;
    let one = BigUint::from(1u8);
    let last = (end - &one) >> 32usize;
    if last >= &first + 2u8 {
        return true;
    }
    checksum_lands_in_interval(&first, start, end)
        || (last != first && checksum_lands_in_interval(&last, start, end))
}

fn checksum_lands_in_interval(data: &BigUint, start: &BigUint, end: &BigUint) -> bool {
    let Some(data_bytes) = fit_be(data, 21) else {
        return false;
    };
    let sum = sha256d(&data_bytes);
    let mut payload = [0u8; 25];
    payload[..21].copy_from_slice(&data_bytes);
    payload[21..25].copy_from_slice(&sum[..4]);
    let value = BigUint::from_bytes_be(&payload);
    &value >= start && &value < end
}

/// Big-endian `width` bytes. `None` when `value` does not fit, which means it
/// is past the exclusive end of a `width`-byte integer.
fn fit_be(value: &BigUint, width: usize) -> Option<Vec<u8>> {
    let be = value.to_bytes_be();
    if be.len() > width {
        return None;
    }
    let mut out = vec![0u8; width];
    out[width - be.len()..].copy_from_slice(&be);
    Some(out)
}

fn rounded_div(numerator: &BigUint, denominator: &BigUint) -> BigUint {
    (numerator + (denominator >> 1usize)) / denominator
}

fn base58_value(text: &str) -> BigUint {
    let mut value = BigUint::from(0u8);
    let base = BigUint::from(58u32);
    for ch in text.chars() {
        let index = alphabet_index(ch).expect("caller checked the alphabet");
        value = value * &base + u32::from(index);
    }
    value
}

pub fn alphabet_index(ch: char) -> Option<u8> {
    XRPL_ALPHABET
        .chars()
        .position(|item| item == ch)
        .map(|index| index as u8)
}

pub fn format_attempts(value: &BigUint) -> String {
    let digits = value.to_str_radix(10);
    if digits.len() <= 15 {
        group_digits(&digits)
    } else {
        let exponent = digits.len() - 1;
        let mut mantissa = String::new();
        mantissa.push(digits.as_bytes()[0] as char);
        let fraction: String = digits.chars().skip(1).take(3).collect();
        if !fraction.is_empty() {
            mantissa.push('.');
            mantissa.push_str(&fraction);
        }
        format!("{mantissa}e{exponent}")
    }
}

pub fn group_digits(digits: &str) -> String {
    let mut grouped = String::new();
    for (index, ch) in digits.chars().rev().enumerate() {
        if index > 0 && index % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(ch);
    }
    grouped.chars().rev().collect()
}

#[cfg(test)]
mod tests {
    use super::{finish_estimate, SEARCH_COUNTER_HEADROOM};
    use crate::error::Error;
    use num_bigint::BigUint;

    #[test]
    fn counter_limit_rejects_the_headroom_boundary() {
        let space = BigUint::from(u64::MAX.saturating_sub(SEARCH_COUNTER_HEADROOM));
        let one = BigUint::from(1u8);
        assert_eq!(finish_estimate(&(&space - &one), &one), Ok(&space - &one));
        assert_eq!(
            finish_estimate(&space, &one),
            Err(Error::Prefix(
                "prefix search exceeds this implementation's supported attempt range"
            ))
        );
    }
}
