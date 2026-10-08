// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Official XRPL vectors. A failure names the check and includes no secret.
//!
//! Vectors:
//! - `ripple-address-codec` `test/xrp-codec.test.ts` seed encodings.
//! - `ripple-keypairs` `test/fixtures/api.json` Ed25519 seed, keys, and address.
//! - xrpl.org Addresses code sample: the `ED94...` public key and `rDTXLQ...`.
//! - `ripple-address-codec` account id `BA8E7862...` → `rJrRMgiRgrU6hDF4pgu5DXQdWyPbY35ErN`.

use crate::error::Error;
use crate::hexutil;
use crate::independent;
use crate::verify::confirm_match;
use crate::xrpl::{
    account_id_from_classic_address, account_id_from_public_key, base58_decode, base58_encode,
    classic_address_from_account_id, classic_address_from_public_key, decode_ed25519_seed,
    derive_from_entropy, encode_ed25519_seed, xrpl_ed25519_private_key,
};

const SEED_VECTORS: &[(&str, &str)] = &[
    (
        "4C3A1D213FBDFB14C7C28D609469B341",
        "sEdTM1uX8pu2do5XvTnutH6HsouMaM2",
    ),
    (
        "00000000000000000000000000000000",
        "sEdSJHS4oiAdz7w2X2ni1gFiqtbJHqE",
    ),
    (
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "sEdV19BLfeQeKdEXyYA4NhjPJe6XBfG",
    ),
];

const FULL_SEED: &str = "sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r";
const FULL_PRIVATE: &str = "EDB4C4E046826BD26190D09715FC31F4E6A728204EADD112905B08B14B7F15C4F3";
const FULL_PUBLIC: &str = "ED01FA53FA5A7E77798F882ECE20B1ABC00BB358A9E55A202D0D0676BD0CE37A63";
const FULL_ADDRESS: &str = "rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD";

const SAMPLE_PUBLIC: &str = "ED9434799226374926EDA3B54B1B461B4ABF7237962EAE18528FEA67595397FA32";
const SAMPLE_ADDRESS: &str = "rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN";

const ACCOUNT_ID: &str = "BA8E78626EE42C41B46D46C3048DF3A1C3C87072";
const ACCOUNT_ADDRESS: &str = "rJrRMgiRgrU6hDF4pgu5DXQdWyPbY35ErN";

/// secp256k1 family seed from `ripple-keypairs` fixtures. Valid checksum, wrong type.
const SECP_SEED: &str = "sp5fghtJtpUorTwvof1NpDXAzNwf5";

pub fn run_self_tests() -> Result<(), Error> {
    for (entropy_hex, seed) in SEED_VECTORS {
        check_seed(entropy_hex, seed)?;
    }
    check_flipped_checksum()?;
    check_secp_rejected()?;
    check_account_vector()?;
    check_address_sample()?;
    check_full_vector()?;
    Ok(())
}

fn check_seed(entropy_hex: &str, expected_seed: &str) -> Result<(), Error> {
    let name = "ed25519 seed vector";
    let entropy: [u8; 16] =
        hexutil::decode_exact(entropy_hex).map_err(|_| Error::SelfTest(name))?;
    let encoded = encode_ed25519_seed(&entropy);
    if encoded.as_str() != expected_seed {
        return Err(Error::SelfTest(name));
    }
    let decoded = decode_ed25519_seed(expected_seed).map_err(|_| Error::SelfTest(name))?;
    if decoded.as_slice() != entropy.as_slice() {
        return Err(Error::SelfTest(name));
    }
    Ok(())
}

fn check_flipped_checksum() -> Result<(), Error> {
    let name = "seed checksum";
    let seed = SEED_VECTORS[0].1;
    let mut raw = base58_decode(seed).map_err(|_| Error::SelfTest(name))?;
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    let flipped = base58_encode(&raw);
    match decode_ed25519_seed(&flipped) {
        Err(Error::Checksum) => Ok(()),
        _ => Err(Error::SelfTest(name)),
    }
}

fn check_secp_rejected() -> Result<(), Error> {
    match decode_ed25519_seed(SECP_SEED) {
        Err(Error::NotEd25519Seed) => Ok(()),
        _ => Err(Error::SelfTest("secp256k1 seed rejected")),
    }
}

fn check_account_vector() -> Result<(), Error> {
    let name = "account id vector";
    let account: [u8; 20] = hexutil::decode_exact(ACCOUNT_ID).map_err(|_| Error::SelfTest(name))?;
    if classic_address_from_account_id(&account) != ACCOUNT_ADDRESS {
        return Err(Error::SelfTest(name));
    }
    let decoded =
        account_id_from_classic_address(ACCOUNT_ADDRESS).map_err(|_| Error::SelfTest(name))?;
    if decoded != account {
        return Err(Error::SelfTest(name));
    }
    Ok(())
}

fn check_address_sample() -> Result<(), Error> {
    let name = "ed25519 address sample";
    let public_key: [u8; 33] =
        hexutil::decode_exact(SAMPLE_PUBLIC).map_err(|_| Error::SelfTest(name))?;
    let address =
        classic_address_from_public_key(&public_key).map_err(|_| Error::SelfTest(name))?;
    if address != SAMPLE_ADDRESS {
        return Err(Error::SelfTest(name));
    }
    let account = account_id_from_public_key(&public_key);
    if account.len() != 20 {
        return Err(Error::SelfTest(name));
    }
    let round = account_id_from_classic_address(&address).map_err(|_| Error::SelfTest(name))?;
    if round != account {
        return Err(Error::SelfTest(name));
    }
    Ok(())
}

fn check_full_vector() -> Result<(), Error> {
    let entropy =
        decode_ed25519_seed(FULL_SEED).map_err(|_| Error::SelfTest("ed25519 full vector"))?;
    let entropy_bytes: [u8; 16] = *entropy;

    let private = xrpl_ed25519_private_key(&entropy_bytes);
    if hexutil::encode_upper(private.as_bytes()) != FULL_PRIVATE {
        return Err(Error::SelfTest("ed25519 full vector private"));
    }

    let derived =
        derive_from_entropy(&entropy_bytes).map_err(|_| Error::SelfTest("ed25519 full vector"))?;
    if hexutil::encode_upper(&derived.public_key) != FULL_PUBLIC {
        return Err(Error::SelfTest("ed25519 full vector public"));
    }
    if derived.address != FULL_ADDRESS {
        return Err(Error::SelfTest("ed25519 full vector address"));
    }
    if account_id_from_public_key(&derived.public_key).len() != 20 {
        return Err(Error::SelfTest("ed25519 full vector address"));
    }

    let reencoded = encode_ed25519_seed(&entropy_bytes);
    if reencoded.as_str() != FULL_SEED {
        return Err(Error::SelfTest("ed25519 full vector"));
    }

    let independent_address = independent::classic_address_from_seed(FULL_SEED)
        .map_err(|_| Error::SelfTest("xrpl-rust independent address"))?;
    if independent_address != FULL_ADDRESS {
        return Err(Error::SelfTest("xrpl-rust independent address"));
    }

    confirm_match(&entropy_bytes, FULL_ADDRESS, &derived.public_key)
        .map_err(|_| Error::SelfTest("ring public key"))?;
    Ok(())
}
