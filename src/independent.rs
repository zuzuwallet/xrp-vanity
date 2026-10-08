//! Address derivation through `xrpl-rust`.
//!
//! This module does not call the Base58 or key code in `crate::xrpl`.
//! `xrpl-rust` 1.3.0 `derive_keypair` returns `(public_key_hex, private_key_hex)`.
//! The private key is a `String` that crate does not zeroize (upstream issue
//! #285). The copy returned here is zeroized before this function returns.
//! Copies still held inside that crate are outside our control.

use std::panic::{catch_unwind, AssertUnwindSafe};

use xrpl::core::keypairs::{derive_classic_address, derive_keypair};
use zeroize::{Zeroize, Zeroizing};

use crate::error::Error;

/// Classic address for an `sEd...` seed, derived by `xrpl-rust`.
pub fn classic_address_from_seed(seed: &str) -> Result<String, Error> {
    let derived = catch_unwind(AssertUnwindSafe(|| derive_keypair(seed, false)));
    let (public_key, private_key) = match derived {
        Ok(Ok(pair)) => pair,
        Ok(Err(_)) | Err(_) => return Err(Error::VerificationFailed),
    };
    let mut private_key = Zeroizing::new(private_key);
    private_key.zeroize();

    let address = catch_unwind(AssertUnwindSafe(|| derive_classic_address(&public_key)));
    match address {
        Ok(Ok(address)) => Ok(address),
        Ok(Err(_)) | Err(_) => Err(Error::VerificationFailed),
    }
}
