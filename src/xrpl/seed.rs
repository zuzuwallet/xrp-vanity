//! Ed25519 seed codec (`sEd...`).
//!
//! Version bytes `[0x01, 0xE1, 0x4B]` come from XRPLF `ripple-address-codec`
//! (`ED25519_SEED` in `packages/ripple-address-codec/src/xrp-codec.ts`).
//! The xrpl.org Base58 table lists family seed `0x21` and does not list this
//! prefix. Family seed `0x21` is the secp256k1 encoding and is rejected here.
//!
//! Checksum is the first 4 bytes of SHA-256(SHA-256(version || entropy)),
//! matching `encodeChecked` in that codec.

use zeroize::Zeroizing;

use crate::error::Error;
use crate::secret::SecretString;
use crate::xrpl::base58::{base58check_decode_secret, base58check_encode_secret};

/// Three-byte version prefix for an XRPL Ed25519 seed.
pub const ED25519_SEED_VERSION: [u8; 3] = [0x01, 0xe1, 0x4b];

/// secp256k1 family-seed version. Present so a valid `s...` seed is rejected
/// as the wrong algorithm instead of being treated as Ed25519.
const FAMILY_SEED_VERSION: u8 = 0x21;

pub fn encode_ed25519_seed(entropy: &[u8; 16]) -> SecretString {
    let mut payload = Zeroizing::new([0u8; 19]);
    payload[..3].copy_from_slice(&ED25519_SEED_VERSION);
    payload[3..].copy_from_slice(entropy);
    let text = base58check_encode_secret(payload.as_slice())
        .expect("ed25519 seed encoding fits in the stack buffer");
    SecretString::new(text)
}

pub fn decode_ed25519_seed(seed: &str) -> Result<Zeroizing<[u8; 16]>, Error> {
    let mut payload = Zeroizing::new([0u8; 32]);
    let len = base58check_decode_secret(seed, payload.as_mut())?;
    if len == 17 && payload[0] == FAMILY_SEED_VERSION {
        return Err(Error::NotEd25519Seed);
    }
    if len != 19 || payload[..3] != ED25519_SEED_VERSION {
        return Err(Error::NotEd25519Seed);
    }
    let mut entropy = Zeroizing::new([0u8; 16]);
    entropy.copy_from_slice(&payload[3..19]);
    Ok(entropy)
}
