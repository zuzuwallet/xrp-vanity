// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Checks that agree before a wallet is treated as valid.
//!
//! `xrpl-rust` also uses `ed25519-dalek`, so a bug in that library can make
//! our address and `xrpl-rust`'s address agree. `ring` recomputes the Ed25519
//! public key from the same RFC 8032 seed. The AccountID and Base58 steps
//! after `ring` still use our codec. That limit is stated in the README.

use ring::signature::{Ed25519KeyPair, KeyPair};
use zeroize::Zeroize;

use crate::error::Error;
use crate::independent;
use crate::xrpl::{self, derive_from_entropy, encode_ed25519_seed};

/// Require our derivation, `xrpl-rust`, and `ring` to agree.
///
/// `address` and `public_key` are public. The entropy is not printed on failure.
pub fn confirm_match(
    entropy: &[u8; 16],
    address: &str,
    public_key: &[u8; 33],
) -> Result<(), Error> {
    let derived = derive_from_entropy(entropy)?;
    if derived.address != address || derived.public_key != *public_key {
        return Err(Error::VerificationFailed);
    }

    let seed = encode_ed25519_seed(entropy);
    let independent_address = independent::classic_address_from_seed(seed.as_str())?;
    if independent_address != address {
        return Err(Error::VerificationFailed);
    }

    let ring_key = ring_public_key(entropy)?;
    if ring_key != *public_key {
        return Err(Error::VerificationFailed);
    }
    let ring_address = xrpl::classic_address_from_public_key(&ring_key)?;
    if ring_address != address {
        return Err(Error::VerificationFailed);
    }
    Ok(())
}

fn ring_public_key(entropy: &[u8; 16]) -> Result<[u8; 33], Error> {
    let mut seed = xrpl::sha512_half(entropy);
    let keypair = Ed25519KeyPair::from_seed_unchecked(seed.as_slice())
        .map_err(|_| Error::VerificationFailed)?;
    // ring stores the derived private scalar and prefix inside `keypair` and
    // does not zeroize them. Wiping `seed` does not wipe those copies.
    seed.zeroize();
    let raw = keypair.public_key().as_ref();
    if raw.len() != 32 {
        return Err(Error::VerificationFailed);
    }
    let mut public_key = [0u8; 33];
    public_key[0] = 0xed;
    public_key[1..].copy_from_slice(raw);
    Ok(public_key)
}
