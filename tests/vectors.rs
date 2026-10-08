#![forbid(unsafe_code)]

use xrpl_vanity::{
    account_id_from_classic_address, account_id_from_public_key, base58_decode, base58_encode,
    base58check_decode, classic_address_from_account_id, classic_address_from_public_key,
    confirm_match, decode_ed25519_seed, derive_from_entropy, encode_ed25519_seed, run_self_tests,
    xrpl_ed25519_private_key, Error, XRPL_ALPHABET,
};

const FULL_SEED: &str = "sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r";
const FULL_PRIVATE: &str = "EDB4C4E046826BD26190D09715FC31F4E6A728204EADD112905B08B14B7F15C4F3";
const FULL_PUBLIC: &str = "ED01FA53FA5A7E77798F882ECE20B1ABC00BB358A9E55A202D0D0676BD0CE37A63";
const FULL_ADDRESS: &str = "rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD";

fn hex_upper(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn decode_hex<const N: usize>(text: &str) -> [u8; N] {
    let mut out = [0u8; N];
    let bytes = text.as_bytes();
    for (index, slot) in out.iter_mut().enumerate() {
        let hi = match bytes[index * 2] {
            b @ b'0'..=b'9' => b - b'0',
            b @ b'A'..=b'F' => b - b'A' + 10,
            b @ b'a'..=b'f' => b - b'a' + 10,
            _ => panic!("hex"),
        };
        let lo = match bytes[index * 2 + 1] {
            b @ b'0'..=b'9' => b - b'0',
            b @ b'A'..=b'F' => b - b'A' + 10,
            b @ b'a'..=b'f' => b - b'a' + 10,
            _ => panic!("hex"),
        };
        *slot = (hi << 4) | lo;
    }
    out
}

#[test]
fn self_tests_pass() {
    run_self_tests().unwrap();
}

#[test]
fn alphabet_is_xrpl_not_bitcoin() {
    assert_eq!(
        XRPL_ALPHABET,
        "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"
    );
    assert_ne!(
        XRPL_ALPHABET,
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    );
    assert_eq!(XRPL_ALPHABET.len(), 58);
    assert!(!XRPL_ALPHABET.contains('0'));
    assert!(!XRPL_ALPHABET.contains('O'));
    assert!(!XRPL_ALPHABET.contains('I'));
    assert!(!XRPL_ALPHABET.contains('l'));
}

#[test]
fn account_id_vector_and_checksum() {
    let account: [u8; 20] = decode_hex("BA8E78626EE42C41B46D46C3048DF3A1C3C87072");
    let address = classic_address_from_account_id(&account);
    assert_eq!(address, "rJrRMgiRgrU6hDF4pgu5DXQdWyPbY35ErN");
    assert_eq!(account_id_from_classic_address(&address).unwrap(), account);

    let mut raw = base58_decode(&address).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 0xff;
    let broken = base58_encode(&raw);
    assert_eq!(base58check_decode(&broken), Err(Error::Checksum));
}

#[test]
fn official_public_key_sample() {
    let public_key: [u8; 33] =
        decode_hex("ED9434799226374926EDA3B54B1B461B4ABF7237962EAE18528FEA67595397FA32");
    assert_eq!(
        classic_address_from_public_key(&public_key).unwrap(),
        "rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN"
    );
    assert_eq!(account_id_from_public_key(&public_key).len(), 20);
}

#[test]
fn seed_round_trips() {
    let vectors = [
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
    for (entropy_hex, seed) in vectors {
        let entropy: [u8; 16] = decode_hex(entropy_hex);
        assert_eq!(encode_ed25519_seed(&entropy).as_str(), seed);
        assert_eq!(
            decode_ed25519_seed(seed).unwrap().as_slice(),
            entropy.as_slice()
        );
    }
}

#[test]
fn flipped_seed_checksum_is_rejected() {
    let seed = "sEdTM1uX8pu2do5XvTnutH6HsouMaM2";
    let mut raw = base58_decode(seed).unwrap();
    let last = raw.len() - 1;
    raw[last] ^= 0x01;
    let flipped = base58_encode(&raw);
    assert_eq!(decode_ed25519_seed(&flipped), Err(Error::Checksum));
}

#[test]
fn secp256k1_seed_is_rejected() {
    assert_eq!(
        decode_ed25519_seed("sp5fghtJtpUorTwvof1NpDXAzNwf5"),
        Err(Error::NotEd25519Seed)
    );
    assert_eq!(
        decode_ed25519_seed("sn259rEFXrQrWyx3Q7XneWcwV6dfL"),
        Err(Error::NotEd25519Seed)
    );
}

#[test]
fn short_payload_is_rejected() {
    let encoded = xrpl_vanity::base58check_encode(&[0x01]);
    assert!(decode_ed25519_seed(&encoded).is_err());
}

#[test]
fn full_ed25519_vector() {
    let entropy: [u8; 16] = *decode_ed25519_seed(FULL_SEED).unwrap();
    let private = xrpl_ed25519_private_key(&entropy);
    assert_eq!(hex_upper(private.as_bytes()), FULL_PRIVATE);
    let derived = derive_from_entropy(&entropy).unwrap();
    assert_eq!(hex_upper(&derived.public_key), FULL_PUBLIC);
    assert_eq!(derived.address, FULL_ADDRESS);
    assert_eq!(account_id_from_public_key(&derived.public_key).len(), 20);
    let account = account_id_from_classic_address(&derived.address).unwrap();
    assert_eq!(account_id_from_public_key(&derived.public_key), account);
    assert_eq!(encode_ed25519_seed(&entropy).as_str(), FULL_SEED);
    confirm_match(&entropy, FULL_ADDRESS, &derived.public_key).unwrap();
}

#[test]
fn independent_library_matches_full_vector() {
    let address = xrpl_vanity::independent::classic_address_from_seed(FULL_SEED).unwrap();
    assert_eq!(address, FULL_ADDRESS);
}

#[test]
fn confirm_match_rejects_a_different_address() {
    let entropy: [u8; 16] = *decode_ed25519_seed(FULL_SEED).unwrap();
    let derived = derive_from_entropy(&entropy).unwrap();
    let err = confirm_match(
        &entropy,
        "rJrRMgiRgrU6hDF4pgu5DXQdWyPbY35ErN",
        &derived.public_key,
    );
    assert_eq!(err, Err(Error::VerificationFailed));
}

#[test]
fn base58_roundtrip_random_payloads() {
    for n in 0..32u8 {
        let mut payload = [0u8; 25];
        payload[0] = n;
        payload[1] = n.wrapping_mul(3);
        payload[24] = 0xff;
        let encoded = base58_encode(&payload);
        assert_eq!(base58_decode(&encoded).unwrap(), payload);
    }
}
