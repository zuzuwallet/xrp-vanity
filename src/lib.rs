// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Offline XRPL Ed25519 vanity classic-address generator.
//!
//! This crate does not use `unsafe`. Cryptography comes from maintained
//! libraries. The hand-written pieces are XRPL Base58Check and the wiring
//! required by the XRPL Ed25519 derivation rules.

#![forbid(unsafe_code)]

pub mod error;
mod hexutil;
pub mod independent;
pub mod search;
pub mod secret;
pub mod self_test;
pub mod verify;
pub mod wallet;
pub mod xrpl;

pub use error::Error;
pub use num_bigint::BigUint;
pub use search::{counter_would_overflow, search, SearchHit, COUNTER_HEADROOM, MAX_THREADS};
pub use secret::{SecretBytes, SecretString};
pub use self_test::run_self_tests;
pub use verify::confirm_match;
pub use wallet::{open_and_verify, write_encrypted_wallet, KdfParams, OpenedWallet};
pub use xrpl::{
    account_id_from_classic_address, account_id_from_public_key, address_starts_with,
    base58_decode, base58_encode, base58check_decode, base58check_encode,
    classic_address_from_account_id, classic_address_from_public_key, decode_ed25519_seed,
    derive_from_entropy, encode_ed25519_seed, validate_prefix, xrpl_ed25519_private_key, Derived,
    PrefixEstimate, MAX_PREFIX_LEN, XRPL_ALPHABET,
};
