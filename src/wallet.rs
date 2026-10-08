// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Encrypted wallet file.
//!
//! The file holds the 16-byte entropy, not the `sEd` string. The key is
//! Argon2id (RFC 9106 section 4, second recommended option) and the cipher is
//! ChaCha20-Poly1305 (RFC 8439) from the RustCrypto crates. The associated
//! data binds the classic address, so editing the address fails authentication.
//!
//! The file is created with mode `0600` via `O_CREAT|O_EXCL`. It is not created
//! world-readable and then chmod'd. `hard_link` publishes it only when the
//! destination name is still absent.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Block, Params, Version};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::error::Error;
use crate::hexutil;
use crate::secret::SecretBytes;
use crate::verify::confirm_match;
use crate::xrpl::derive_from_entropy;

const FORMAT_NAME: &str = "xrpl-vanity-wallet";
const FORMAT_VERSION: u32 = 1;
const CURVE: &str = "ed25519";
const KDF_NAME: &str = "argon2id";
const KDF_VERSION: u32 = 19;
const AEAD_NAME: &str = "chacha20poly1305";
const AAD_PREFIX: &[u8] = b"xrpl-vanity-wallet-v1\0";
const AAD_SUFFIX: &[u8] = b"\0ed25519";
const MAX_WALLET_BYTES: u64 = 1_048_576;
const MAX_MEMORY_KIB: u32 = 1_048_576;
const MAX_ITERATIONS: u32 = 100;
const MAX_PARALLELISM: u32 = 16;
/// Linux `O_NOFOLLOW` (`0400000` in `asm-generic/fcntl.h`). Do not follow a symlink.
const O_NOFOLLOW: i32 = 0x20000;

/// Argon2id parameters stored in the wallet file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl KdfParams {
    /// RFC 9106 section 4, second recommended option: 64 MiB, t=3, p=4.
    /// Output length is 32 bytes and the salt is 16 bytes. Argon2 version is 0x13.
    pub const PRODUCTION: Self = Self {
        memory_kib: 65_536,
        iterations: 3,
        parallelism: 4,
    };

    pub fn is_production(self) -> bool {
        self == Self::PRODUCTION
    }

    pub(crate) fn within_caps(self) -> bool {
        self.iterations >= 1
            && self.iterations <= MAX_ITERATIONS
            && self.parallelism >= 1
            && self.parallelism <= MAX_PARALLELISM
            && self.memory_kib >= self.parallelism.saturating_mul(8)
            && self.memory_kib <= MAX_MEMORY_KIB
    }
}

pub struct OpenedWallet {
    pub address: String,
    pub public_key: [u8; 33],
    pub entropy: SecretBytes<16>,
}

impl std::fmt::Debug for OpenedWallet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedWallet")
            .field("address", &self.address)
            .field("public_key", &hexutil::encode_upper(&self.public_key))
            .field("entropy", &self.entropy)
            .finish()
    }
}

/// Minimum Unicode scalar values for a passphrase that creates a new wallet.
///
/// This is an accident check. It is not a measure of guessing resistance.
pub const MIN_NEW_PASSPHRASE_CHARS: usize = 12;

/// Accept a passphrase that may open an existing wallet.
///
/// Empty values and values longer than 1024 bytes are rejected. The value is
/// not trimmed. Short historical passphrases stay valid so an old wallet can
/// still be opened.
pub fn check_passphrase(passphrase: &str) -> Result<(), Error> {
    if passphrase.is_empty() || passphrase.len() > 1024 {
        Err(Error::Passphrase)
    } else {
        Ok(())
    }
}

/// Accept a passphrase for a wallet this program is about to create.
///
/// The open check still applies. A new passphrase must also contain at least
/// [`MIN_NEW_PASSPHRASE_CHARS`] Unicode scalar values.
pub fn check_new_passphrase(passphrase: &str) -> Result<(), Error> {
    check_passphrase(passphrase)?;
    if passphrase.chars().count() < MIN_NEW_PASSPHRASE_CHARS {
        Err(Error::Passphrase)
    } else {
        Ok(())
    }
}

pub fn write_encrypted_wallet(
    path: &Path,
    passphrase: &str,
    entropy: &[u8; 16],
) -> Result<(), Error> {
    check_new_passphrase(passphrase)?;
    // Refuse before Argon2. The hard-link check still covers a path created
    // while the ciphertext is being derived.
    if path.exists() {
        return Err(Error::OutputExists);
    }
    write_encrypted_wallet_with_kdf(path, passphrase, entropy, &KdfParams::PRODUCTION)
}

/// Write a wallet using caller-supplied KDF parameters inside the accepted caps.
///
/// Public callers use [`write_encrypted_wallet`], which always stores
/// [`KdfParams::PRODUCTION`]. This function exists so unit tests can avoid a
/// 64 MiB derivation. Parameters above the caps are rejected. `open_and_verify`
/// will not open a file written with anything other than the production parameters.
pub(crate) fn write_encrypted_wallet_with_kdf(
    path: &Path,
    passphrase: &str,
    entropy: &[u8; 16],
    kdf: &KdfParams,
) -> Result<(), Error> {
    check_passphrase(passphrase)?;
    if !kdf.within_caps() {
        return Err(Error::WalletFormat);
    }
    let derived = derive_from_entropy(entropy)?;
    confirm_match(entropy, &derived.address, &derived.public_key)?;

    let mut salt = Zeroizing::new([0u8; 16]);
    let mut nonce = Zeroizing::new([0u8; 12]);
    getrandom::getrandom(salt.as_mut()).map_err(|_| Error::Rng)?;
    getrandom::getrandom(nonce.as_mut()).map_err(|_| Error::Rng)?;
    let ciphertext = encrypt(passphrase, entropy, &derived.address, kdf, &salt, &nonce)?;

    let file = WalletFile {
        format: FORMAT_NAME.to_owned(),
        format_version: FORMAT_VERSION,
        curve: CURVE.to_owned(),
        classic_address: derived.address,
        public_key_hex: hexutil::encode_upper(&derived.public_key),
        kdf: KdfFile {
            name: KDF_NAME.to_owned(),
            version: KDF_VERSION,
            memory_kib: kdf.memory_kib,
            iterations: kdf.iterations,
            parallelism: kdf.parallelism,
            salt_b64: STANDARD.encode(salt.as_slice()),
        },
        aead: AeadFile {
            name: AEAD_NAME.to_owned(),
            nonce_b64: STANDARD.encode(nonce.as_slice()),
        },
        ciphertext_b64: STANDARD.encode(&ciphertext),
    };
    let mut json = serde_json::to_string_pretty(&file).map_err(|_| Error::WalletFormat)?;
    json.push('\n');
    write_private_file(path, json.as_bytes())
}

pub fn open_and_verify(path: &Path, passphrase: &str) -> Result<OpenedWallet, Error> {
    open_and_verify_inner(path, passphrase, true)
}

/// Open a wallet that may use the cheap in-crate test KDF.
///
/// Parameters outside the caps are rejected before Argon2 runs.
/// [`open_and_verify`] accepts only [`KdfParams::PRODUCTION`].
#[cfg(test)]
pub(crate) fn open_and_verify_with_kdf(
    path: &Path,
    passphrase: &str,
) -> Result<OpenedWallet, Error> {
    open_and_verify_inner(path, passphrase, false)
}

fn open_and_verify_inner(
    path: &Path,
    passphrase: &str,
    require_production: bool,
) -> Result<OpenedWallet, Error> {
    check_passphrase(passphrase)?;
    let file = read_wallet(path)?;
    if file.format != FORMAT_NAME || file.format_version != FORMAT_VERSION || file.curve != CURVE {
        return Err(Error::WalletFormat);
    }
    if file.kdf.name != KDF_NAME || file.kdf.version != KDF_VERSION || file.aead.name != AEAD_NAME {
        return Err(Error::WalletFormat);
    }
    let kdf = KdfParams {
        memory_kib: file.kdf.memory_kib,
        iterations: file.kdf.iterations,
        parallelism: file.kdf.parallelism,
    };
    let accepted = if require_production {
        kdf.is_production()
    } else {
        kdf.within_caps()
    };
    if !accepted {
        return Err(Error::WalletFormat);
    }
    let salt = decode_len::<16>(&file.kdf.salt_b64)?;
    let nonce = decode_len::<12>(&file.aead.nonce_b64)?;
    let ciphertext = STANDARD
        .decode(&file.ciphertext_b64)
        .map_err(|_| Error::WalletFormat)?;
    if ciphertext.len() != 32 {
        return Err(Error::WalletFormat);
    }

    let mut plaintext = decrypt(
        passphrase,
        &ciphertext,
        &file.classic_address,
        &kdf,
        &salt,
        &nonce,
    )?;
    let entropy = SecretBytes::new(std::mem::take(&mut *plaintext));
    let derived = derive_from_entropy(entropy.as_bytes()).map_err(|_| Error::VerificationFailed)?;
    if derived.address != file.classic_address
        || hexutil::encode_upper(&derived.public_key) != file.public_key_hex
    {
        return Err(Error::VerificationFailed);
    }
    confirm_match(entropy.as_bytes(), &derived.address, &derived.public_key)?;
    Ok(OpenedWallet {
        address: derived.address,
        public_key: derived.public_key,
        entropy,
    })
}

fn encrypt(
    passphrase: &str,
    entropy: &[u8; 16],
    address: &str,
    kdf: &KdfParams,
    salt: &[u8; 16],
    nonce: &[u8; 12],
) -> Result<Vec<u8>, Error> {
    let key = derive_key(passphrase.as_bytes(), salt, kdf)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| Error::WalletFormat)?;
    let nonce = Nonce::from_slice(nonce.as_slice());
    let aad = aad_bytes(address);
    cipher
        .encrypt(
            nonce,
            Payload {
                msg: entropy.as_slice(),
                aad: aad.as_slice(),
            },
        )
        .map_err(|_| Error::Decrypt)
}

fn decrypt(
    passphrase: &str,
    ciphertext: &[u8],
    address: &str,
    kdf: &KdfParams,
    salt: &[u8; 16],
    nonce: &[u8; 12],
) -> Result<Zeroizing<[u8; 16]>, Error> {
    let key = derive_key(passphrase.as_bytes(), salt, kdf)?;
    let cipher =
        ChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| Error::WalletFormat)?;
    let nonce = Nonce::from_slice(nonce.as_slice());
    let aad = aad_bytes(address);
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext,
                    aad: aad.as_slice(),
                },
            )
            .map_err(|_| Error::Decrypt)?,
    );
    if plain.len() != 16 {
        return Err(Error::Decrypt);
    }
    let mut entropy = Zeroizing::new([0u8; 16]);
    entropy.copy_from_slice(&plain);
    Ok(entropy)
}

fn derive_key(
    passphrase: &[u8],
    salt: &[u8],
    kdf: &KdfParams,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let params = Params::new(kdf.memory_kib, kdf.iterations, kdf.parallelism, Some(32))
        .map_err(|_| Error::WalletFormat)?;
    let block_count = params.block_count();
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    // Box, not Vec: zeroize can clear this allocation, and the slice cannot
    // grow and leave an older copy behind. Argon2 still keeps per-lane
    // address blocks on its own stack.
    let mut memory = Zeroizing::new(vec![Block::default(); block_count].into_boxed_slice());
    let mut key = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into_with_memory(passphrase, salt, key.as_mut(), &mut *memory)
        .map_err(|_| Error::WalletFormat)?;
    Ok(key)
}

fn aad_bytes(address: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_PREFIX.len() + address.len() + AAD_SUFFIX.len());
    out.extend_from_slice(AAD_PREFIX);
    out.extend_from_slice(address.as_bytes());
    out.extend_from_slice(AAD_SUFFIX);
    out
}

fn decode_len<const N: usize>(text: &str) -> Result<[u8; N], Error> {
    let bytes = STANDARD.decode(text).map_err(|_| Error::WalletFormat)?;
    if bytes.len() != N {
        return Err(Error::WalletFormat);
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn read_wallet(path: &Path) -> Result<WalletFile, Error> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(O_NOFOLLOW)
        .open(path)
        .map_err(|err| map_wallet_open_error(path, err))?;
    let meta = file.metadata().map_err(|err| Error::io(path, err))?;
    if meta.len() > MAX_WALLET_BYTES || !meta.is_file() {
        return Err(Error::WalletFormat);
    }
    let mut text = String::new();
    Read::by_ref(&mut file)
        .take(MAX_WALLET_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|err| Error::io(path, err))?;
    if text.len() as u64 > MAX_WALLET_BYTES {
        return Err(Error::WalletFormat);
    }
    serde_json::from_str(&text).map_err(|_| Error::WalletFormat)
}

fn map_wallet_open_error(path: &Path, err: std::io::Error) -> Error {
    // Linux ELOOP. `O_NOFOLLOW` returns this when the path is a symlink.
    if err.raw_os_error() == Some(40) {
        Error::Io(format!(
            "{}: wallet path must be a regular file",
            path.display()
        ))
    } else {
        Error::io(path, err)
    }
}

fn write_private_file(dest: &Path, contents: &[u8]) -> Result<(), Error> {
    if dest.exists() {
        return Err(Error::OutputExists);
    }
    let parent = parent_dir(dest);
    if !parent.is_dir() {
        return Err(Error::OutputDir);
    }
    let file_name = dest.file_name().ok_or(Error::OutputDir)?;
    let mut suffix = [0u8; 8];
    getrandom::getrandom(&mut suffix).map_err(|_| Error::Rng)?;
    let tmp_path = parent.join(format!(
        ".{}.tmp.{}",
        file_name.to_string_lossy(),
        hexutil::encode_upper(&suffix)
    ));

    let mut guard = RemoveOnDrop {
        path: tmp_path.clone(),
        armed: true,
    };
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp_path)
        .map_err(|err| Error::io(&tmp_path, err))?;
    let mode = file
        .metadata()
        .map_err(|err| Error::io(&tmp_path, err))?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        return Err(Error::Io(format!(
            "{}: created file was not private",
            tmp_path.display()
        )));
    }
    file.write_all(contents)
        .map_err(|err| Error::io(&tmp_path, err))?;
    file.sync_all().map_err(|err| Error::io(&tmp_path, err))?;
    drop(file);

    match fs::hard_link(&tmp_path, dest) {
        Ok(()) => {}
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(Error::OutputExists);
        }
        Err(err) => return Err(Error::io(dest, err)),
    }
    fs::remove_file(&tmp_path).map_err(|err| Error::io(&tmp_path, err))?;
    guard.armed = false;
    sync_directory(dest, parent)?;
    Ok(())
}

fn sync_directory(dest: &Path, parent: &Path) -> Result<(), Error> {
    let dir = File::open(parent).map_err(|err| {
        Error::Io(format!(
            "{}: wallet file was written, but opening its directory for sync failed: {err}. It may not survive a power loss.",
            dest.display()
        ))
    })?;
    dir.sync_all().map_err(|err| {
        Error::Io(format!(
            "{}: wallet file was written, but syncing its directory failed: {err}. It may not survive a power loss.",
            dest.display()
        ))
    })
}

fn parent_dir(path: &Path) -> &Path {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    }
}

struct RemoveOnDrop {
    path: PathBuf,
    armed: bool,
}

impl Drop for RemoveOnDrop {
    fn drop(&mut self) {
        if self.armed {
            let _ = fs::remove_file(&self.path);
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletFile {
    format: String,
    format_version: u32,
    curve: String,
    classic_address: String,
    public_key_hex: String,
    kdf: KdfFile,
    aead: AeadFile,
    ciphertext_b64: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfFile {
    name: String,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt_b64: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AeadFile {
    name: String,
    nonce_b64: String,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        check_new_passphrase, check_passphrase, open_and_verify, open_and_verify_with_kdf,
        write_encrypted_wallet, write_encrypted_wallet_with_kdf, KdfParams,
        MIN_NEW_PASSPHRASE_CHARS,
    };
    use crate::{decode_ed25519_seed, derive_from_entropy, encode_ed25519_seed, Error};

    fn scratch_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("xrpl-vanity-test-{nanos}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn test_kdf() -> KdfParams {
        KdfParams {
            memory_kib: 32,
            iterations: 1,
            parallelism: 1,
        }
    }

    struct DirGuard(PathBuf);
    impl Drop for DirGuard {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn new_passphrase_requires_twelve_unicode_scalars() {
        assert!(check_passphrase("x").is_ok());
        assert_eq!(check_new_passphrase("x"), Err(Error::Passphrase));
        assert_eq!(
            check_new_passphrase(&"a".repeat(MIN_NEW_PASSPHRASE_CHARS - 1)),
            Err(Error::Passphrase)
        );
        assert!(check_new_passphrase(&"a".repeat(MIN_NEW_PASSPHRASE_CHARS)).is_ok());
        assert!(check_new_passphrase(&"é".repeat(MIN_NEW_PASSPHRASE_CHARS)).is_ok());
        assert!(check_new_passphrase(&" ".repeat(MIN_NEW_PASSPHRASE_CHARS)).is_ok());
        assert_eq!(check_new_passphrase(""), Err(Error::Passphrase));
        assert_eq!(
            check_new_passphrase(&"a".repeat(1025)),
            Err(Error::Passphrase)
        );
        assert_eq!(check_passphrase(" x "), Ok(()));
    }

    #[test]
    fn public_writer_rejects_an_existing_path_before_argon2() {
        let dir = DirGuard(scratch_dir());
        let path = dir.0.join("wallet.json");
        let marker = b"not-the-vanity-wallet\n";
        fs::write(&path, marker).unwrap();
        let err = write_encrypted_wallet(&path, "correct horse battery", &[7u8; 16]).unwrap_err();
        assert_eq!(err, Error::OutputExists);
        assert_eq!(fs::read(&path).unwrap(), marker);
    }

    #[test]
    fn public_writer_rejects_a_short_passphrase_before_writing() {
        let dir = DirGuard(scratch_dir());
        let path = dir.0.join("wallet.json");
        let err = write_encrypted_wallet(&path, "x", &[7u8; 16]).unwrap_err();
        assert_eq!(err, Error::Passphrase);
        assert!(!path.exists());
    }

    #[test]
    fn production_constants_match_rfc9106_second_option() {
        let params = KdfParams::PRODUCTION;
        assert!(params.is_production());
        assert_eq!(params.memory_kib, 65_536);
        assert_eq!(params.iterations, 3);
        assert_eq!(params.parallelism, 4);
        assert!(params.within_caps());
        assert!(!test_kdf().is_production());
    }

    #[test]
    fn encrypted_round_trip_hides_the_seed() {
        let dir = DirGuard(scratch_dir());
        let path = dir.0.join("wallet.json");
        let entropy: [u8; 16] = *decode_ed25519_seed("sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r").unwrap();
        let derived = derive_from_entropy(&entropy).unwrap();
        write_encrypted_wallet_with_kdf(&path, "correct horse", &entropy, &test_kdf()).unwrap();

        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.ends_with('\n'));
        assert!(text.contains(&derived.address));
        assert!(!text.contains("sEd"));
        assert!(!text.contains(encode_ed25519_seed(&entropy).as_str()));
        assert!(text.contains("argon2id"));
        assert!(text.contains("chacha20poly1305"));

        let opened = open_and_verify_with_kdf(&path, "correct horse").unwrap();
        assert_eq!(opened.address, derived.address);
        assert_eq!(opened.public_key, derived.public_key);
        assert!(opened.entropy.as_bytes() == &entropy, "entropy mismatch");
        let debug = format!("{opened:?}");
        assert!(debug.contains("redacted"));
    }

    #[test]
    fn public_open_rejects_non_production_kdf_before_argon2() {
        let dir = DirGuard(scratch_dir());
        let path = dir.0.join("wallet.json");
        let entropy = [5u8; 16];
        write_encrypted_wallet_with_kdf(&path, "right-passphrase", &entropy, &test_kdf()).unwrap();
        assert!(matches!(
            open_and_verify(&path, "right-passphrase"),
            Err(Error::WalletFormat)
        ));
    }

    #[test]
    fn wrong_password_is_rejected() {
        let dir = DirGuard(scratch_dir());
        let path = dir.0.join("wallet.json");
        let entropy = [7u8; 16];
        write_encrypted_wallet_with_kdf(&path, "right-passphrase", &entropy, &test_kdf()).unwrap();
        assert!(matches!(
            open_and_verify_with_kdf(&path, "wrong-passphrase"),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn corrupted_ciphertext_is_rejected() {
        let dir = DirGuard(scratch_dir());
        let path = dir.0.join("wallet.json");
        let entropy = [9u8; 16];
        write_encrypted_wallet_with_kdf(&path, "right-passphrase", &entropy, &test_kdf()).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        let mut bytes = base64_decode(value["ciphertext_b64"].as_str().unwrap());
        bytes[0] ^= 0x01;
        value["ciphertext_b64"] = serde_json::Value::String(base64_encode(&bytes));
        fs::write(&path, serde_json::to_string_pretty(&value).unwrap() + "\n").unwrap();
        assert!(matches!(
            open_and_verify_with_kdf(&path, "right-passphrase"),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn tampered_address_is_rejected() {
        let dir = DirGuard(scratch_dir());
        let path = dir.0.join("wallet.json");
        let entropy = [3u8; 16];
        write_encrypted_wallet_with_kdf(&path, "right-passphrase", &entropy, &test_kdf()).unwrap();
        let mut text = fs::read_to_string(&path).unwrap();
        let address = derive_from_entropy(&entropy).unwrap().address;
        let mutated = flip_address_char(&address);
        assert_ne!(address, mutated);
        text = text.replace(&address, &mutated);
        fs::write(&path, text).unwrap();
        assert!(matches!(
            open_and_verify_with_kdf(&path, "right-passphrase"),
            Err(Error::Decrypt)
        ));
    }

    #[test]
    fn refuses_to_overwrite() {
        let dir = DirGuard(scratch_dir());
        let path = dir.0.join("wallet.json");
        write_encrypted_wallet_with_kdf(&path, "right-passphrase", &[1u8; 16], &test_kdf())
            .unwrap();
        let before = fs::read(&path).unwrap();
        let err =
            write_encrypted_wallet_with_kdf(&path, "right-passphrase", &[2u8; 16], &test_kdf());
        assert_eq!(err, Err(Error::OutputExists));
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn hostile_kdf_caps_are_rejected() {
        let dir = DirGuard(scratch_dir());
        let path = dir.0.join("wallet.json");
        let entropy = [4u8; 16];
        write_encrypted_wallet_with_kdf(&path, "right-passphrase", &entropy, &test_kdf()).unwrap();
        let mut value: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        value["kdf"]["memory_kib"] = serde_json::Value::from(2_000_000);
        fs::write(&path, serde_json::to_string_pretty(&value).unwrap() + "\n").unwrap();
        assert!(matches!(
            open_and_verify_with_kdf(&path, "right-passphrase"),
            Err(Error::WalletFormat)
        ));
    }

    #[test]
    fn symlink_wallet_is_rejected() {
        let dir = DirGuard(scratch_dir());
        let path = dir.0.join("wallet.json");
        let link = dir.0.join("link.json");
        write_encrypted_wallet_with_kdf(&path, "right-passphrase", &[4u8; 16], &test_kdf())
            .unwrap();
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let err = open_and_verify(&link, "right-passphrase").unwrap_err();
        assert!(
            err.to_string().contains("regular file"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn truncated_wallet_is_rejected() {
        let dir = DirGuard(scratch_dir());
        let path = dir.0.join("wallet.json");
        fs::write(&path, b"{").unwrap();
        assert!(matches!(
            open_and_verify(&path, "right-passphrase"),
            Err(Error::WalletFormat)
        ));
    }

    fn flip_address_char(address: &str) -> String {
        let mut chars: Vec<char> = address.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'r' { 'p' } else { 'r' };
        chars.into_iter().collect()
    }

    fn base64_decode(text: &str) -> Vec<u8> {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(text)
            .unwrap()
    }

    fn base64_encode(bytes: &[u8]) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }
}
