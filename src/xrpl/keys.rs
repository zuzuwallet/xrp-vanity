// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! XRPL Ed25519 account derivation.
//!
//! Procedure, from xrpl.org cryptographic keys and XRPLF `ripple-keypairs`:
//! 1. 16-byte entropy.
//! 2. Secret seed = SHA-512Half(entropy) = first 32 bytes of SHA-512.
//! 3. That 32-byte value is an RFC 8032 Ed25519 seed. `ed25519-dalek`
//!    `SigningKey::from_bytes` hashes and clamps it. It is not a clamped scalar.
//! 4. XRPL public key = `0xED || 32-byte Ed25519 public key`.
//! 5. AccountID = RIPEMD160(SHA256(33-byte public key)).
//! 6. Classic address = Base58Check(0x00 || AccountID).
//!
//! The checksum covers `version || AccountID`, which is what the address code
//! sample and `ripple-address-codec` hash. One sentence on the addresses page
//! says the checksum is of the AccountID alone. The executable sample includes
//! the version byte, and that is what this code does.

use ed25519_dalek::SigningKey;
use ripemd::Ripemd160;
use sha2::{Digest, Sha256};

use crate::error::Error;
use crate::hexutil;
use crate::secret::SecretBytes;
use crate::xrpl::base58::{base58check_decode, base58check_encode_into};
use crate::xrpl::hash::sha512_half;

pub const ED25519_PUBLIC_PREFIX: u8 = 0xed;
pub const CLASSIC_ADDRESS_VERSION: u8 = 0x00;

/// Public result of derivation. The seed is not stored here.
#[derive(Clone, PartialEq, Eq)]
pub struct Derived {
    pub address: String,
    pub public_key: [u8; 33],
}

impl std::fmt::Debug for Derived {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Derived")
            .field("address", &self.address)
            .field("public_key", &hexutil::encode_upper(&self.public_key))
            .finish()
    }
}

/// XRPL's published "private key" encoding: `0xED || SHA-512Half(entropy)`.
/// This is not the clamped Ed25519 scalar.
pub fn xrpl_ed25519_private_key(entropy: &[u8; 16]) -> SecretBytes<33> {
    let half = sha512_half(entropy);
    let mut out = [0u8; 33];
    out[0] = ED25519_PUBLIC_PREFIX;
    out[1..].copy_from_slice(half.as_slice());
    SecretBytes::new(out)
}

pub fn derive_from_entropy(entropy: &[u8; 16]) -> Result<Derived, Error> {
    let public_key = public_key_from_entropy(entropy);
    let address = classic_address_from_public_key(&public_key)?;
    Ok(Derived {
        address,
        public_key,
    })
}

/// Hot-path prefix test. Encodes the address into a stack buffer.
pub fn address_starts_with(entropy: &[u8; 16], prefix: &str) -> Result<bool, Error> {
    let public_key = public_key_from_entropy(entropy);
    let mut buffer = [0u8; 48];
    let length = classic_address_into(&public_key, &mut buffer)?;
    let address = &buffer[..length];
    let prefix_bytes = prefix.as_bytes();
    Ok(address.len() >= prefix_bytes.len() && &address[..prefix_bytes.len()] == prefix_bytes)
}

pub fn account_id_from_public_key(public_key: &[u8; 33]) -> [u8; 20] {
    let sha = Sha256::digest(public_key);
    let ripe = Ripemd160::digest(sha);
    let mut account = [0u8; 20];
    account.copy_from_slice(&ripe);
    account
}

pub fn classic_address_from_public_key(public_key: &[u8; 33]) -> Result<String, Error> {
    if public_key[0] != ED25519_PUBLIC_PREFIX {
        return Err(Error::PublicKey);
    }
    Ok(classic_address_from_account_id(
        &account_id_from_public_key(public_key),
    ))
}

pub fn classic_address_from_account_id(account_id: &[u8; 20]) -> String {
    let mut payload = [0u8; 21];
    payload[0] = CLASSIC_ADDRESS_VERSION;
    payload[1..].copy_from_slice(account_id);
    let mut out = [0u8; 48];
    let n = base58check_encode_into(&payload, &mut out).expect("address fits in 48 bytes");
    String::from_utf8(out[..n].to_vec()).expect("address alphabet is ASCII")
}

pub fn classic_address_into(public_key: &[u8; 33], out: &mut [u8]) -> Result<usize, Error> {
    if public_key[0] != ED25519_PUBLIC_PREFIX {
        return Err(Error::PublicKey);
    }
    let account = account_id_from_public_key(public_key);
    let mut payload = [0u8; 21];
    payload[0] = CLASSIC_ADDRESS_VERSION;
    payload[1..].copy_from_slice(&account);
    base58check_encode_into(&payload, out)
}

pub fn account_id_from_classic_address(address: &str) -> Result<[u8; 20], Error> {
    let payload = base58check_decode(address)?;
    if payload.len() != 21 || payload[0] != CLASSIC_ADDRESS_VERSION {
        return Err(Error::PublicKey);
    }
    let mut account = [0u8; 20];
    account.copy_from_slice(&payload[1..]);
    Ok(account)
}

fn public_key_from_entropy(entropy: &[u8; 16]) -> [u8; 33] {
    let seed = sha512_half(entropy);
    let signing = SigningKey::from_bytes(&seed);
    let verifying = signing.verifying_key().to_bytes();
    drop(signing);
    let mut public_key = [0u8; 33];
    public_key[0] = ED25519_PUBLIC_PREFIX;
    public_key[1..].copy_from_slice(&verifying);
    public_key
}
