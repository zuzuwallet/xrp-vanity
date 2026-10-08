//! XRPL classic-address and Ed25519 seed codec.
//!
//! Base58Check here is separate from the `bs58` encoder inside `xrpl-rust`.

mod base58;
mod hash;
mod keys;
mod prefix;
mod seed;

pub use base58::{
    base58_decode, base58_encode, base58check_decode, base58check_encode, XRPL_ALPHABET,
};
pub use keys::{
    account_id_from_classic_address, account_id_from_public_key, address_starts_with,
    classic_address_from_account_id, classic_address_from_public_key, derive_from_entropy,
    xrpl_ed25519_private_key, Derived,
};
pub(crate) use prefix::SEARCH_COUNTER_HEADROOM;
pub use prefix::{format_attempts, group_digits, validate_prefix, PrefixEstimate, MAX_PREFIX_LEN};
pub use seed::{decode_ed25519_seed, encode_ed25519_seed};

pub(crate) use hash::sha512_half;
