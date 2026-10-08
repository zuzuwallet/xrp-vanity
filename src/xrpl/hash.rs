use sha2::{Digest, Sha256, Sha512};
use zeroize::{Zeroize, Zeroizing};

/// SHA-256(SHA-256(data)).
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// First 32 bytes of SHA-512. XRPL calls this SHA-512Half.
pub fn sha512_half(data: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hash = Sha512::digest(data);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&hash[..32]);
    Zeroize::zeroize(&mut hash[..]);
    out
}
