//! XRPL Base58 and Base58Check.
//!
//! Alphabet source: <https://xrpl.org/docs/references/protocol/data-types/base58-encodings>
//! and `XRPLF/xrpl.js` `packages/ripple-address-codec`.
//!
//! This is not the Bitcoin alphabet. Bitcoin uses
//! `123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz`.

use zeroize::{Zeroize, Zeroizing};

use crate::error::Error;
use crate::xrpl::hash::sha256d;

/// XRPL Base58 alphabet. The character at index 0 is `r`.
pub const XRPL_ALPHABET: &str = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

const ALPHABET: &[u8; 58] = b"rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

const DECODE: [u8; 128] = decode_table();

/// Reject Base58 strings longer than this. Seeds and classic addresses are shorter.
const MAX_INPUT_CHARS: usize = 128;

const fn decode_table() -> [u8; 128] {
    let mut table = [0xffu8; 128];
    let mut index = 0;
    while index < ALPHABET.len() {
        table[ALPHABET[index] as usize] = index as u8;
        index += 1;
    }
    table
}

pub fn base58_encode(data: &[u8]) -> String {
    let zeros = data.iter().take_while(|byte| **byte == 0).count();
    let mut digits = Vec::<u8>::new();
    for byte in data {
        let mut carry = u32::from(*byte);
        for digit in digits.iter_mut() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push(ALPHABET[0] as char);
    }
    for digit in digits.iter().rev() {
        out.push(ALPHABET[*digit as usize] as char);
    }
    out
}

pub fn base58_encode_into(data: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    encode_with_alphabet(data, ALPHABET, out)
}

pub fn base58_decode(input: &str) -> Result<Vec<u8>, Error> {
    if input.len() > MAX_INPUT_CHARS {
        return Err(Error::Base58);
    }
    let bytes = input.as_bytes();
    let mut zeros = 0usize;
    for byte in bytes {
        if *byte == ALPHABET[0] {
            zeros += 1;
        } else {
            break;
        }
    }

    let mut acc: Vec<u8> = Vec::new();
    for byte in bytes {
        if *byte >= 128 {
            return Err(Error::Base58);
        }
        let value = DECODE[*byte as usize];
        if value == 0xff {
            return Err(Error::Base58);
        }
        let mut carry = u32::from(value);
        for slot in acc.iter_mut().rev() {
            carry += u32::from(*slot) * 58;
            *slot = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            acc.insert(0, (carry & 0xff) as u8);
            carry >>= 8;
        }
    }

    let mut out = vec![0u8; zeros];
    out.extend_from_slice(&acc);
    Ok(out)
}

/// Payload is version bytes concatenated with the body. The checksum is the
/// first 4 bytes of SHA-256(SHA-256(payload)).
pub fn base58check_encode(payload: &[u8]) -> String {
    let mut full = Vec::with_capacity(payload.len() + 4);
    full.extend_from_slice(payload);
    let sum = sha256d(payload);
    full.extend_from_slice(&sum[..4]);
    base58_encode(&full)
}

pub fn base58check_encode_into(payload: &[u8], out: &mut [u8]) -> Result<usize, Error> {
    // Classic addresses are 25 bytes. Seeds are 23 bytes. Keep a fixed ceiling.
    if payload.len() > 64 {
        return Err(Error::Base58);
    }
    let mut full = [0u8; 68];
    full[..payload.len()].copy_from_slice(payload);
    let sum = sha256d(payload);
    full[payload.len()..payload.len() + 4].copy_from_slice(&sum[..4]);
    base58_encode_into(&full[..payload.len() + 4], out)
}

pub fn base58check_decode(input: &str) -> Result<Vec<u8>, Error> {
    let full = base58_decode(input)?;
    if full.len() < 5 {
        return Err(Error::Checksum);
    }
    let (payload, checksum) = full.split_at(full.len() - 4);
    let expected = sha256d(payload);
    if !constant_time_eq(&expected[..4], checksum) {
        return Err(Error::Checksum);
    }
    Ok(payload.to_vec())
}

/// Base58Check for secret payloads. Digit and checksum buffers are wiped.
///
/// The returned `String` still holds the encoded text. Callers that encode a
/// seed wrap it in `SecretString`.
pub(crate) fn base58check_encode_secret(payload: &[u8]) -> Result<String, Error> {
    if payload.len() > 64 {
        return Err(Error::Base58);
    }
    let mut full = Zeroizing::new([0u8; 68]);
    full[..payload.len()].copy_from_slice(payload);
    let mut sum = sha256d(payload);
    full[payload.len()..payload.len() + 4].copy_from_slice(&sum[..4]);
    Zeroize::zeroize(&mut sum);
    encode_secret_digits(&full[..payload.len() + 4])
}

/// Decode Base58Check into `payload_out` and wipe the checksummed buffer.
///
/// `payload_out` receives only the payload. Bytes past the returned length are
/// set to zero.
pub(crate) fn base58check_decode_secret(
    input: &str,
    payload_out: &mut [u8],
) -> Result<usize, Error> {
    if input.len() > MAX_INPUT_CHARS {
        return Err(Error::Base58);
    }
    let mut full = Zeroizing::new([0u8; 48]);
    let n = base58_decode_secret(input, full.as_mut())?;
    if n < 5 {
        return Err(Error::Checksum);
    }
    let split = n - 4;
    let mut expected = sha256d(&full[..split]);
    let matches = constant_time_eq(&expected[..4], &full[split..n]);
    Zeroize::zeroize(&mut expected);
    if !matches {
        return Err(Error::Checksum);
    }
    if split > payload_out.len() {
        return Err(Error::Base58);
    }
    payload_out[..split].copy_from_slice(&full[..split]);
    for byte in payload_out.iter_mut().skip(split) {
        *byte = 0;
    }
    Ok(split)
}

fn encode_secret_digits(data: &[u8]) -> Result<String, Error> {
    let zeros = data.iter().take_while(|byte| **byte == 0).count();
    let mut digits = Zeroizing::new([0u8; 96]);
    let mut digit_len = 0usize;
    for byte in data {
        let mut carry = u32::from(*byte);
        for digit in digits[..digit_len].iter_mut() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            if digit_len >= digits.len() {
                return Err(Error::Base58);
            }
            digits[digit_len] = (carry % 58) as u8;
            digit_len += 1;
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digit_len);
    for _ in 0..zeros {
        out.push(ALPHABET[0] as char);
    }
    for digit in digits[..digit_len].iter().rev() {
        out.push(ALPHABET[*digit as usize] as char);
    }
    Ok(out)
}

fn base58_decode_secret(input: &str, out: &mut [u8]) -> Result<usize, Error> {
    let bytes = input.as_bytes();
    let mut zeros = 0usize;
    for byte in bytes {
        if *byte == ALPHABET[0] {
            zeros += 1;
        } else {
            break;
        }
    }

    let mut acc = Zeroizing::new([0u8; 48]);
    let mut acc_len = 0usize;
    for byte in bytes {
        if *byte >= 128 {
            return Err(Error::Base58);
        }
        let value = DECODE[*byte as usize];
        if value == 0xff {
            return Err(Error::Base58);
        }
        let mut carry = u32::from(value);
        for offset in 0..acc_len {
            let idx = acc.len() - 1 - offset;
            carry += u32::from(acc[idx]) * 58;
            acc[idx] = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            if acc_len >= acc.len() {
                return Err(Error::Base58);
            }
            acc_len += 1;
            let idx = acc.len() - acc_len;
            acc[idx] = (carry & 0xff) as u8;
            carry >>= 8;
        }
    }

    let total = zeros + acc_len;
    if total > out.len() {
        return Err(Error::Base58);
    }
    for slot in out.iter_mut().take(zeros) {
        *slot = 0;
    }
    if acc_len > 0 {
        out[zeros..total].copy_from_slice(&acc[acc.len() - acc_len..]);
    }
    for slot in out.iter_mut().skip(total) {
        *slot = 0;
    }
    Ok(total)
}

fn encode_with_alphabet(data: &[u8], alphabet: &[u8; 58], out: &mut [u8]) -> Result<usize, Error> {
    let zeros = data.iter().take_while(|byte| **byte == 0).count();
    let mut digits = [0u8; 96];
    let mut digit_len = 0usize;
    for byte in data {
        let mut carry = u32::from(*byte);
        for digit in digits[..digit_len].iter_mut() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            if digit_len >= digits.len() {
                return Err(Error::Base58);
            }
            digits[digit_len] = (carry % 58) as u8;
            digit_len += 1;
            carry /= 58;
        }
    }
    let total = zeros + digit_len;
    if out.len() < total {
        return Err(Error::Base58);
    }
    for slot in out.iter_mut().take(zeros) {
        *slot = alphabet[0];
    }
    for (offset, digit) in digits[..digit_len].iter().rev().enumerate() {
        out[zeros + offset] = alphabet[*digit as usize];
    }
    Ok(total)
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    const BITCOIN_ALPHABET: &[u8; 58] =
        b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    #[test]
    fn alphabets_differ() {
        assert_ne!(ALPHABET, BITCOIN_ALPHABET);
        assert_eq!(XRPL_ALPHABET.as_bytes(), ALPHABET);
        assert_eq!(ALPHABET.len(), 58);
        assert_eq!(ALPHABET[0], b'r');
    }

    #[test]
    fn same_bytes_encode_differently_from_bitcoin() {
        let data = [0x00, 0x01, 0x02, 0xff];
        let mut xrpl = [0u8; 16];
        let mut bitcoin = [0u8; 16];
        let n = encode_with_alphabet(&data, ALPHABET, &mut xrpl).unwrap();
        let m = encode_with_alphabet(&data, BITCOIN_ALPHABET, &mut bitcoin).unwrap();
        assert_ne!(&xrpl[..n], &bitcoin[..m]);
        assert_eq!(xrpl[0], b'r');
        assert_eq!(bitcoin[0], b'1');
    }

    #[test]
    fn empty_and_zeros() {
        assert_eq!(base58_encode(&[]), "");
        assert_eq!(base58_decode("").unwrap(), Vec::<u8>::new());
        assert_eq!(base58_encode(&[0, 0, 0]), "rrr");
        assert_eq!(base58_decode("rrr").unwrap(), vec![0, 0, 0]);
        assert_eq!(base58_decode("r").unwrap(), vec![0]);
    }

    #[test]
    fn roundtrip_preserves_leading_zeros() {
        let samples: &[&[u8]] = &[
            &[0x00],
            &[0x00, 0x00, 0x01],
            &[0x00, 0x11, 0x22, 0x33, 0x44],
            b"123456789",
            &[0xff; 25],
            &[0x00, 0xff, 0x00, 0x7f],
        ];
        for sample in samples {
            let encoded = base58_encode(sample);
            let decoded = base58_decode(&encoded).unwrap();
            assert_eq!(&decoded, sample);
        }
    }

    #[test]
    fn official_versioned_payload() {
        // ripple-address-codec: version 0x00 || ASCII "123456789".
        let mut payload = vec![0x00];
        payload.extend_from_slice(b"123456789");
        assert_eq!(base58check_encode(&payload), "rnaC7gW34M77Kneb78s");
        assert_eq!(base58check_decode("rnaC7gW34M77Kneb78s").unwrap(), payload);
    }

    #[test]
    fn checksum_rejects_a_flipped_byte() {
        let payload = b"\x00hello world";
        let encoded = base58check_encode(payload);
        let mut raw = base58_decode(&encoded).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 0x01;
        let flipped = base58_encode(&raw);
        assert_eq!(base58check_decode(&flipped), Err(Error::Checksum));
    }

    #[test]
    fn rejects_unknown_characters_and_huge_input() {
        assert_eq!(base58_decode("r0"), Err(Error::Base58));
        assert_eq!(base58_decode("rO"), Err(Error::Base58));
        assert_eq!(base58_decode("rI"), Err(Error::Base58));
        assert_eq!(base58_decode("rl"), Err(Error::Base58));
        let huge = "r".repeat(200);
        assert_eq!(base58_decode(&huge), Err(Error::Base58));
    }

    #[test]
    fn short_checksum_input_fails() {
        assert_eq!(base58check_decode("rr"), Err(Error::Checksum));
        assert!(base58check_decode("1234").is_err());
    }

    #[test]
    fn secret_codec_matches_the_allocating_codec() {
        let payload = [
            0x01, 0xe1, 0x4b, 0x4c, 0x3a, 0x1d, 0x21, 0x3f, 0xbd, 0xfb, 0x14, 0xc7, 0xc2, 0x8d,
            0x60, 0x94, 0x69, 0xb3, 0x41,
        ];
        let encoded = base58check_encode_secret(&payload).unwrap();
        assert_eq!(encoded, base58check_encode(&payload));
        let mut decoded = [0u8; 32];
        let len = base58check_decode_secret(&encoded, &mut decoded).unwrap();
        assert_eq!(&decoded[..len], &payload);
        assert!(decoded[len..].iter().all(|byte| *byte == 0));
    }
}
