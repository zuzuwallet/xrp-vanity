# xrpl-vanity

Offline generator for an XRPL Ed25519 classic address that starts with a chosen prefix. The first target this tree was built for is `rZuZu`.

Passing `cargo test` does not make a wallet safe for meaningful funds. This is key-generation software. Review the derivation, the wallet format, and the compiled binary yourself, or have someone else review them, before you send value to an address it produced. A green test run only shows that this program matched the vectors and checks named below.

Never paste an `sEd...` seed into a website, an AI or chat system, an issue tracker, a shell command, or an online verification service. The terminal scrollback, shell history, and process list are copies of a secret.

The compiled generator does not open network connections. It has no telemetry, update check, or HTTP client. `Cargo.lock` contains no `reqwest`, `hyper`, `tokio`, or `rustls` crate. Generation and verification work with networking disabled.

## What it does

For each candidate the program:

1. Reads 16 bytes from the operating-system CSPRNG (`getrandom`).
2. Derives an XRPL Ed25519 key pair from those bytes.
3. Builds the classic address.
4. Compares the address with the requested prefix.

The first match is checked again through `xrpl-rust` and through `ring` before it is treated as found. The 16-byte entropy is then encrypted and written to a new file created with mode `0600`. The seed is not printed. `export` is the only command that prints an `sEd...` seed, and it asks you to type `EXPORT` first.

secp256k1 key generation, X-addresses, passphrases used as seeds, RFC 1751, mnemonics, transaction signing, and ledger RPCs are out of scope.

## Fedora: build online, then disconnect

Install a C compiler and Rust while the machine can reach the network. `ring` and `secp256k1-sys` (pulled in by `xrpl-rust`) compile C code.

```bash
sudo dnf install gcc
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup component add rustfmt clippy
```

The checks recorded in this file used rustc 1.99.0 and cargo 1.99.0. On a machine where `sudo` is unavailable, a user-local GCC works if `CC`, `AR`, `C_INCLUDE_PATH`, and `LIBRARY_PATH` point at that toolchain. A GCC configured with `--prefix=/usr` and then unpacked somewhere else does not search its own `usr/include` unless `C_INCLUDE_PATH` is set. That is an environment workaround, not the normal Fedora install.

From this directory, while still online:

```bash
cargo build --release
```

Read `Cargo.lock` before you trust the binary. The versions below are the ones resolved for this tree. Optionally, still online:

```bash
cargo install cargo-audit cargo-deny --locked
cargo audit
cargo deny check advisories bans licenses sources
```

`cargo audit` and `cargo deny` download advisory data. The `xrpl-vanity` binary does not.

Then disconnect and use only the binary you just built:

```bash
nmcli networking off
./target/release/xrpl-vanity self-test
./target/release/xrpl-vanity generate rZuZu
./target/release/xrpl-vanity verify vanity-wallet.json
```

`nmcli networking off` may require privileges. Unplugging the network is the same step.

Copy `vanity-wallet.json` to offline storage. The file mode is `0600` from the moment it is created. Keep the passphrase with the same care as the file. Only after the encrypted secret is backed up, and after a separate review of how you will sign, consider funding the address. This program does not sign transactions and does not ask the ledger whether the address exists.

## Commands

```bash
xrpl-vanity self-test
xrpl-vanity generate rZuZu
xrpl-vanity generate rZuZu --threads 16 --output vanity-wallet.json
xrpl-vanity verify vanity-wallet.json
xrpl-vanity export vanity-wallet.json
```

`generate` defaults to `std::thread::available_parallelism`, clamped to 1..=256. `--threads 0` and values above 256 are rejected. The default output path is `vanity-wallet.json`. An existing output file is refused. There is no overwrite flag. Pick a different `--output` path. The parent directory must already exist. Both checks happen before the search starts.

A prefix whose estimated cost is above 10^12 attempts requires you to type `SEARCH`. `rZuZu` is under that line.

`generate`, `verify`, and `export` read the passphrase from the terminal with echo disabled (`rpassword`). The passphrase is not a command-line argument and it is not trimmed. `generate` asks twice, up to three attempts. A new passphrase must contain at least 12 Unicode scalar values and at most 1024 bytes. That minimum only stops accidents: `password12345` and a long diceware phrase both pass it, and they are not equally hard to guess. Use a generated passphrase for anything you might fund. `verify` and `export` still open an existing passphrase that is shorter than 12 characters, so an older wallet can be recovered. Empty passphrases are rejected on every command. The same new-passphrase rule is enforced by `write_encrypted_wallet`, not only by this binary.

During a search the program prints the prefix, the thread count, the estimate, self-test status, attempt totals, and a candidates/sec figure. On a match it prints the classic address, the attempt count, and the elapsed time, then the wallet path. It does not print the seed.

`verify` decrypts the file, derives the address again, and prints that address plus `Verification: PASS` when it matches the stored address.

`export` requires a terminal on both stdin and stdout. Redirecting stdout, including `export wallet.json > captured.txt`, is refused before any warning or seed is printed. It then prints warnings, waits for the line `EXPORT`, decrypts, and prints one `sEd...` line. Clear the terminal scrollback after you have copied the seed onto offline media.

Ctrl-C during the search sets a flag, the workers stop, and no wallet is written. After a match, Ctrl-C sets the same flag. The program returns normally, drops the seed buffers, and does not write a wallet. It does not call `process::exit`. The classic address is printed only after `write_encrypted_wallet` returns success: the ciphertext was hard-linked into place and the parent directory sync succeeded. Cancelling the passphrase, or any error from that write, discards the entropy and does not print the address. A file that appears at the output path during the search is not this wallet. The write is refused, including when that file shows up at the passphrase prompt. If the ciphertext was linked and only the directory sync failed, the address is not printed. Run `verify` on that file to read the public address.

Passphrase prompts for `generate`, `verify`, and `export` run on the main thread after that handler is installed. `rpassword` reads Ctrl-C itself, restores terminal echo before it returns, and the program then discards the passphrase. `verify` and `export` do not install the handler until after any earlier confirmation line, so Ctrl-C on `SEARCH` or `EXPORT` still stops the process while echo is on. Argon2 is not interrupted mid-calculation. If Ctrl-C arrives during that calculation, or after it returns but before the next line is printed, `verify` does not print a pass line and `export` does not print the seed. A Ctrl-C that arrives after the print has started cannot be taken back. Once an encrypted write has started, that write finishes. If the passphrase step fails, the program says the wallet was not saved.

Example search output:

```text
XRPL Vanity Generator
Algorithm: Ed25519
Target: rZuZu
Threads: 16
Estimated attempts: ~264,104,224 (estimate, not a guarantee)
Self-tests: PASS

Searching...
Attempts: 10,000,000
Rate: ... candidates/sec

Match found.
Attempts: ...
Elapsed: ...
The address is printed after the encrypted wallet is saved.

FOUND
Address: rZuZu...
Encrypted secret saved to vanity-wallet.json
```

## Derivation

Sources for this section, as fetched while this tree was built:

- [Cryptographic Keys](https://xrpl.org/docs/concepts/accounts/cryptographic-keys) (seed length, SHA-512Half, `0xED`, RFC 8032)
- [Addresses](https://xrpl.org/docs/concepts/accounts/addresses) (AccountID, Base58Check sample, alphabet)
- [Base58 encodings](https://xrpl.org/docs/references/protocol/data-types/base58-encodings)
- [ripple-address-codec `xrp-codec.ts`](https://github.com/XRPLF/xrpl.js/blob/main/packages/ripple-address-codec/src/xrp-codec.ts)
- [ripple-address-codec tests](https://github.com/XRPLF/xrpl.js/blob/main/packages/ripple-address-codec/test/xrp-codec.test.ts)
- [ripple-keypairs Ed25519](https://github.com/XRPLF/xrpl.js/blob/main/packages/ripple-keypairs/src/signing-schemes/ed25519/index.ts)
- [ripple-keypairs `Sha512.ts`](https://github.com/XRPLF/xrpl.js/blob/main/packages/ripple-keypairs/src/utils/Sha512.ts)
- [ripple-keypairs `fixtures/api.json`](https://github.com/XRPLF/xrpl.js/blob/main/packages/ripple-keypairs/test/fixtures/api.json)
- [rippled `SecretKey.cpp` on `develop`](https://github.com/XRPLF/rippled/blob/develop/src/libxrpl/protocol/SecretKey.cpp)
- [rippled `Seed.h` `toBase58`](https://github.com/XRPLF/rippled/blob/develop/include/xrpl/protocol/Seed.h)
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032) (Ed25519 seed)
- [RFC 9106](https://www.rfc-editor.org/rfc/rfc9106) section 4 (Argon2id parameters)
- [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439) (ChaCha20-Poly1305)

`ed25519-dalek` 2.2.0 (`SigningKey::from_bytes`) and `ring` 0.17.14 (`Ed25519KeyPair::from_seed_unchecked`) implement Ed25519. This crate does not.

Steps for one candidate:

1. Entropy is 16 bytes from the OS CSPRNG. Workers do not share a userspace RNG and do not reuse those bytes.
2. The secret scalar input is SHA-512Half(entropy): the first 32 bytes of SHA-512. xrpl.org calls this the 32-byte secret. `ripple-keypairs` names the same function `Sha512.half` and passes it to `@noble/curves` `getPublicKey`. rippled `generateSecretKey` for `KeyType::Ed25519` assigns `sha512Half(seed)` to the secret and calls `ed25519_publickey` on it.
3. That 32-byte value is an RFC 8032 seed. `SigningKey::from_bytes` hashes and clamps it. It is not a pre-clamped scalar. The XRPL "private key" string published by `ripple-keypairs` is `0xED` plus those 32 bytes, which is SHA-512Half again, not the clamped scalar.
4. The XRPL public key is `0xED` concatenated with the 32-byte Ed25519 public key. xrpl.org documents that prefix because an Ed25519 key is one byte shorter than a compressed secp256k1 key.
5. AccountID is RIPEMD160(SHA256(33-byte public key)).
6. The classic address is XRPL Base58Check of `0x00 || AccountID`. The 4-byte checksum is the first 4 bytes of SHA-256(SHA-256(`0x00 || AccountID`)). The alphabet is `rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz`.

The Addresses page says, in prose, that the checksum is SHA-256(SHA-256(Account ID)). The code sample on that same page hashes `0x00 || account_id`, and so does `encodeChecked` in `ripple-address-codec`. This program follows the code sample. The sample's published result is `ED9434799226374926EDA3B54B1B461B4ABF7237962EAE18528FEA67595397FA32` → `rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN`.

The `sEd...` encoding is not the family-seed prefix `0x21`. In current `xrp-codec.ts`:

```text
ED25519_SEED = [0x01, 0xe1, 0x4b]
FAMILY_SEED  = 0x21
ACCOUNT_ID   = 0x00
```

`encodeSeed` for Ed25519 Base58Checks `version || 16-byte entropy`. The xrpl.org Base58 table lists seed type `0x21` and does not list `01 E1 4B`. rippled `toBase58(Seed)` on `develop` encodes `TokenType::FamilySeed` (`0x21`). This program encodes and accepts only the three-byte Ed25519 version. A valid secp256k1 family seed such as `sp5fghtJtpUorTwvof1NpDXAzNwf5` is rejected.

Self-tests run before any search. A failure exits without writing a wallet. They cover:

| Check | Vector |
| --- | --- |
| Entropy → `sEd` and back | `4C3A1D213FBDFB14C7C28D609469B341` → `sEdTM1uX8pu2do5XvTnutH6HsouMaM2` |
| All-zero entropy | `sEdSJHS4oiAdz7w2X2ni1gFiqtbJHqE` |
| All-0xFF entropy | `sEdV19BLfeQeKdEXyYA4NhjPJe6XBfG` |
| Flipped seed checksum | rejected |
| secp256k1 family seed | rejected |
| AccountID → address | `BA8E78626EE42C41B46D46C3048DF3A1C3C87072` → `rJrRMgiRgrU6hDF4pgu5DXQdWyPbY35ErN` |
| Public key → address | `ED94347992...` → `rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN` |
| Full seed → keys → address | `sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r` → `rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD` |

The full vector's published public key is `ED01FA53FA5A7E77798F882ECE20B1ABC00BB358A9E55A202D0D0676BD0CE37A63` and its published private encoding is `EDB4C4E046826BD26190D09715FC31F4E6A728204EADD112905B08B14B7F15C4F3`. Those strings are test vectors from `ripple-keypairs`, not a wallet this program generated.

### Independent check

`confirm_match` requires three results to agree:

- This crate's dalek derivation and Base58Check.
- `xrpl-rust` 1.3.0 `derive_keypair(seed, false)` and `derive_classic_address`. That call does not use this crate's Base58. The private-key `String` returned by `xrpl-rust` is wrapped and zeroized here. Copies still held inside that crate are not. [xrpl-rust issue 285](https://github.com/XRPLF/xrpl-rust/issues/285) describes the `Wallet` secret fields and the intermediate derivation buffers.
- `ring` 0.17.14's Ed25519 public key from the same SHA-512Half seed. The AccountID and Base58 steps after `ring` still use this crate. `Ed25519KeyPair` stores the derived private scalar and prefix and does not implement zeroize. This crate wipes its own SHA-512Half seed before that keypair is dropped. It cannot wipe `ring`'s copies. That is the same class of limit as the `xrpl-rust` private-key `String`. `ring` 0.17.14 is newer than the 0.17.12 fix for RUSTSEC-2025-0009. The unmaintained notice on that advisory applies to versions before 0.17.

`xrpl-rust` also uses `ed25519-dalek`. A bug in that library can make our address and `xrpl-rust`'s address agree. `ring` covers the public-key step. It does not cover AccountID or Base58. A mistake shared with the XRPL address specification would pass all three.

`xrpl-rust` is built with default features off and feature `wallet`. The resolved features are `core`, `utils`, and `wallet`. `cargo tree -i reqwest` reports that `reqwest` is not in the graph. The same dependency still links `secp256k1`, which this program does not use to generate keys.

### Constants

| Rule | Value | Source |
| --- | --- | --- |
| Entropy | 16 bytes | xrpl.org Cryptographic Keys |
| Secret | SHA-512Half(entropy), first 32 bytes of SHA-512 | xrpl.org; `Sha512.first256` in ripple-keypairs |
| Use of that secret | RFC 8032 seed, then hash-and-clamp | ripple-keypairs `getPublicKey`; rippled `ed25519_publickey` |
| Public-key prefix | `0xED` | xrpl.org Cryptographic Keys |
| AccountID | RIPEMD160(SHA256(33-byte key)) | xrpl.org Addresses |
| Address version | `0x00` | xrpl.org Base58 table; `ACCOUNT_ID` in `xrp-codec.ts` |
| Checksum | SHA-256(SHA-256(`0x00 \|\| AccountID`)) first 4 bytes | Addresses code sample; `encodeChecked` |
| Alphabet | `rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz` | xrpl.org Base58 encodings |
| Ed25519 seed version | `01 E1 4B` | `ED25519_SEED` in `xrp-codec.ts` |
| Family seed | `0x21`, not produced | xrpl.org Base58 table; `FAMILY_SEED` in `xrp-codec.ts` |
| Argon2id | m=65536 KiB, t=3, p=4, 16-byte salt, 32-byte output, version `0x13` | RFC 9106 section 4, second option |
| AEAD | ChaCha20-Poly1305, 12-byte nonce | RFC 8439, crate `chacha20poly1305` 0.10.1 |

## Prefix estimate

A classic address is Base58Check of a 25-byte payload whose first byte is `0x00`, so every address starts with `r` (`r` is alphabet index 0). The integer value of the whole payload is below 2^192. For a body that starts at a given digit string, the estimate counts how many payloads in that range share the prefix and divides 2^192 by that count, rounding to nearest. Checksum correlation is ignored. The CLI prints the figure as an estimate.

`rZuZu` fixes one leading `r` and the four digits `ZuZu`. The matching window has width 58^28. The expected attempt count is 264,104,224. A unit test locks that number.

The prefix must be non-empty, start with `r`, use only the XRPL alphabet, and be at most 34 characters. 34 is the longest classic address this payload size can produce: one leading `r` plus at most 33 digits of a 192-bit integer. xrpl.org describes addresses as 25 to 35 characters and the Base58 table lists a maximum of 35. A 35-character string cannot be a prefix of an address this encoder emits, so it is rejected.

Some alphabet-legal strings are still impossible. More than 25 leading `r` characters cannot occur. `r` followed by 33 `Z` characters cannot occur, because `Z` is alphabet index 32 and the second character of a 34-character address only reaches index 23. Checksum feasibility is exact. A payload is 21 data bytes plus a 4-byte checksum. An interval that covers a whole 2^32-aligned block contains a valid checksum and is not hashed. Any narrower interval has at most two candidate data values, and the prefix is rejected when neither checksum lands inside it. `rw8cwDcNBuRTWWw7N5pzosPy7A3xCBEK7D`, `rDTXLQ7ZKZVKz33zJbHjgVShjsBnp`, and twenty-four or twenty-five leading `r`s are rejected because no classic address has that prefix. Twenty-one leading `r`s is the all-zero AccountID and is checksum-valid, but its estimate does not fit in the attempt counter, so it is rejected before a search starts. The attempt count stays an estimate. `SEARCH` is the warning for a huge estimate that still fits in the counter. It is not a promise that the search will finish.

## Secret storage

The wallet file holds ciphertext of the 16 raw entropy bytes. It does not hold an `sEd` string. Format version 1 accepts only the production KDF: 64 MiB, t=3, p=4. `open_and_verify` returns a format error before Argon2 runs when the file asks for any other parameters, including a 1 GiB work factor or the cheap parameters used by unit tests. The binary has no flag that selects a weaker KDF. In-crate tests use a private writer with a small Argon2 setup and still reject parameters outside fixed caps.

- KDF: Argon2id, version 19, memory 65536 KiB, 3 iterations, parallelism 4, 16-byte salt, 32-byte output.
- AEAD: ChaCha20-Poly1305. The nonce is 12 bytes from the OS CSPRNG. The ciphertext is 16 bytes of plaintext plus a 16-byte tag.
- Associated data is the exact byte string `xrpl-vanity-wallet-v1`, a NUL, the classic address, a NUL, and `ed25519`. Changing the stored address fails authentication.
- After decryption the program derives the address and public key again and runs `confirm_match`. A stored address that does not match the entropy is a fatal verification error.

The JSON object uses `deny_unknown_fields`. Fields are `format` (`xrpl-vanity-wallet`), `format_version` (1), `curve` (`ed25519`), `classic_address`, `public_key_hex`, `kdf` (name, version, memory_kib, iterations, parallelism, salt_b64), `aead` (name, nonce_b64), and `ciphertext_b64`. Files larger than 1 MiB are rejected. Salt, nonce, and ciphertext are standard Base64.

The file is created as a temporary name in the same directory with `O_CREAT|O_EXCL` and mode `0600`. If the created mode has any group or other permission bits, the write fails. The temp file is `fsync`ed and then hard-linked onto the destination. The link fails if the destination already exists. The temp name is removed afterward. The parent directory is `fsync`ed. If that sync fails, the wallet file is left in place, the command returns an error, and the address is not printed. Run `verify` on the file to read the public address. The error says the file may not survive a power loss. A crash before the link leaves no destination file.

A read opens the path once with the Linux `O_NOFOLLOW` flag and takes the size and the bytes from that file descriptor. A symbolic link is rejected. That flag and the `ELOOP` check are Linux-specific. This program targets Fedora.

Decrypting a production wallet costs about 64 MiB of RAM for a few iterations. Plan for that on the machine that runs `verify` or `export`. A file that asks for a different Argon2 setup is rejected before that cost is paid.

### Zeroization

`SecretBytes` and `SecretString` wrap the `zeroize` crate. `Debug` prints `[redacted]`. SHA-512Half zeroizes the digest buffer after copying the first 32 bytes. `ed25519-dalek` is built with its `zeroize` feature. The Argon2 output and the AEAD key are `Zeroizing`. The Argon2 working memory, about 64 MiB for a production wallet, is a `Zeroizing` boxed slice of blocks passed into `hash_password_into_with_memory`. `argon2` is built with its `zeroize` feature, which wipes that crate's initial hash and final block hash. It does not wipe the per-lane address blocks it keeps on its own stack. Decrypted entropy is held in `Zeroizing` from the moment ChaCha20-Poly1305 returns it. Seed Base58Check uses stack buffers that are wiped, including the checksummed bytes and the Base58 digits. The encoded `sEd` string is then wrapped in `SecretString`.

That is best-effort. It does not cover:

- copies the allocator, the compiler, or registers already made
- swap, hibernation, and crash dumps
- the `String` `xrpl-rust` keeps internally
- the private scalar and prefix stored inside `ring`'s `Ed25519KeyPair`
- the per-lane address blocks `argon2` keeps on its stack during key derivation
- terminal scrollback after `export`
- a panic hook that formats a value we failed to redact

The program does not install a process-wide panic hook. Library paths avoid `panic!` with secret contents. Disable crash dumps and swap on a machine that will hold a seed in memory. `export` is the operation that deliberately puts the seed on the screen.

## Threat model and limitations

Assumed: the OS CSPRNG, the CPU, and the machine you build and run on are not already hostile. A compromised compiler, a malicious `Cargo.lock` you did not read, or a rooted host defeats this program.

In scope: wrong XRPL encoding, a seed that does not match the printed address, a wallet file left world-readable, a passphrase on the command line, and a search that continues after the first hit.

Out of scope, and not solved here: malware on the host, a passphrase that passes the 12-character check and is still guessable, someone reading the terminal during `export`, physical access, side channels, and bugs in `ed25519-dalek`, `ring`, `argon2`, or `chacha20poly1305`. The duplicate-version warnings below are supply-chain noise, not a proof those crates are safe.

Further limits:

- The tool never asks the ledger if the address is already funded or already exists. A classic address is a hash. A collision with a funded account is not a realistic search outcome, and this program does not check.
- There is no signing path. Funding the address still needs a separate, reviewed way to sign.
- rippled's seed Base58 on `develop` is family seed `0x21`. An `sEd...` string may be rejected by `rippled` even though the 16-byte entropy is the seed `generateSecretKey(ed25519)` would hash. This program does not emit a `0x21` seed.
- The vendored C body of rippled's `ed25519_publickey` was not compiled or executed here. The call site passes SHA-512Half(seed) into that function. Agreement with `ripple-keypairs`, dalek, and `ring` is what this tree checks.
- `xrpl-rust` and this crate share `ed25519-dalek`. `ring` checks the public key only. `ring` keeps its own copy of the private scalar and prefix.
- The checksum prose on xrpl.org and the code sample disagree. This tree follows the sample.
- Twenty-five leading `r`s are rejected. The all-zero payload checksum is not four zero bytes. Twenty-one leading `r`s is checksum-valid and is rejected because the estimate does not fit in the attempt counter.
- The attempt count is an estimate, not a promise of wall time. A prefix is rejected when that estimate does not fit in the `u64` counter, minus a small headroom. That rejection includes prefixes a 128-bit seed is too short to reach in practice. The counter still stops an accepted search that runs far past its estimate.
- Workers stop on the first match. Another worker can have drawn entropy it then discards. That entropy is zeroized on drop of the `Zeroizing` buffer. A killed process does not run that drop.
- If any worker panics or the RNG fails, a match from another worker is discarded and no wallet is written.
- Attempt counters stop with an error before a `u64` would wrap. A prefix whose estimate is already past that line is rejected before the search starts.
- `generate` and `write_encrypted_wallet` reject a new passphrase shorter than 12 Unicode scalar values. Argon2id does not rescue a guessable passphrase. `verify` and `export` still open an existing short passphrase.
- Public wallet reads and writes accept only the production Argon2 parameters. A file with other parameters is rejected before Argon2 runs.

## Assumptions that were not executed

These were read from current sources or locked with published vectors. They were not confirmed by running `rippled`:

- `ed25519_publickey` in rippled's vendored C hashes the 32-byte secret the way RFC 8032 and `ed25519-dalek` do. The C function body was not reviewed line by line in this session.
- Importing an `sEd...` seed into current `rippled` was not tried. The `develop` parser that was read accepts family seed `0x21` only.
- No live `rZuZu` search was run, and no generated wallet was funded or broadcast.

## Benchmarks

Correctness is the constraint. The hot loop was measured before any change to it. A candidate is one `getrandom` of 16 bytes plus Ed25519 plus Base58Check. A separate Python loop of `os.urandom(16)`, 20,000 iterations, took 1.03 µs per call on this host (`os.urandom(1024)` took 9.53 µs). That is small next to derivation, so the search was left as one kernel read per candidate. Seeds are not expanded by a userspace DRBG.

`cargo bench --bench derive` uses criterion's default 100 samples. The entropy in `derive_from_entropy` and `hot_prefix_compare` is the published `4C3A1D21...` test vector, not a wallet. Two runs on this 16-thread machine disagreed by several times:

| Bench | Run while a compiler was busy | Later run |
| --- | --- | --- |
| `derive_from_entropy` | 17.45 µs (17.27–17.65) | 83.16 µs (79.67–86.48) |
| `hot_prefix_compare` | 26.62 µs (24.26–29.24) | 96.33 µs (95.44–97.25) |
| `getrandom_and_hot_prefix` | 124.5 µs (101.1–149.9) | 93.29 µs (91.10–95.87) |

Do not treat one of those rows as the machine's capacity. At the faster derive time, a single core is on the order of tens of thousands of candidates per second. `rZuZu` expects about 2.64×10^8 attempts. On a quiet 16-core machine that is minutes if the cores scale, and longer if they do not. The estimate on the CLI is the attempt count, not this wall-time guess.

Repeat the measurement with:

```bash
cargo bench --bench derive
```

## Dependency and security review

Direct dependencies, from the resolved `Cargo.lock`:

| Crate | Version | Role |
| --- | --- | --- |
| argon2 | 0.5.3 | Argon2id, `zeroize` feature on |
| generic-array | 0.14.7 | Enables `GenericArray::zeroize` for argon2 0.5.3 |
| base64 | 0.22.1 | Wallet encoding |
| chacha20poly1305 | 0.10.1 | AEAD |
| clap | 4.6.7 | CLI |
| ctrlc | 3.5.2 | Ctrl-C |
| ed25519-dalek | 2.2.0 | Ed25519 (with curve25519-dalek 4.1.3) |
| getrandom | 0.2.17 | OS CSPRNG |
| num-bigint | 0.4.8 | Prefix estimate only |
| ring | 0.17.14 | Second Ed25519 implementation |
| ripemd | 0.1.3 | RIPEMD160 |
| rpassword | 7.5.4 | Passphrase prompt |
| serde / serde_json | 1.0.229 / 1.0.151 | Wallet JSON |
| sha2 | 0.10.9 | SHA-256 and SHA-512 |
| thiserror | 2.0.21 | Errors |
| xrpl-rust | 1.3.0 | Independent address derivation |
| zeroize | 1.9.1 | Secret wipe |
| criterion | 0.5.1 | Benchmarks only |
| secp256k1 | 0.30.0 | Linked via xrpl-rust, not used to generate keys |

`sha2` 0.10 has no `zeroize` feature. The SHA-512 digest is zeroized explicitly.

`argon2` 0.5.3's `zeroize` feature calls `GenericArray::zeroize` but does not enable that impl. The direct `generic-array` dependency turns it on for the copy already required by `blake2`. It is not a second hash implementation.

`cargo audit` 0.22.2 loaded 1294 RustSec advisories and scanned 256 crate dependencies. Exit code 0. Re-running with `--deny warnings` also exited 0. No vulnerability text was printed.

`cargo deny` 0.20.2 with `deny.toml`: advisories ok, bans ok, licenses ok, sources ok (crates.io only). Exit code 0. It warned, and these warnings are real:

- `hashbrown` 0.15.5 (via `xrpl-rust`) and 0.17.1 (via `indexmap`)
- `syn` 1.0.109, 2.0.119, and 3.0.6
- `windows-sys` 0.52.0 (via `ring`) and 0.61.2

The license allow-list is MIT, Apache-2.0, Apache-2.0 WITH LLVM-exception, BSD-3-Clause, BSD-1-Clause, ISC, Unicode-3.0, CC0-1.0, Unlicense, and Zlib. `ring` is Apache-2.0 AND ISC. `xrpl-rust` is ISC. ICU crates pulled in through `url` are Unicode-3.0. `secp256k1` is CC0-1.0. Without `deny.toml`, the default cargo-deny config rejects every license, including MIT, because nothing is allow-listed. That run is not evidence of a non-free dependency.

`cargo-geiger` was not installed. This crate's library, binary, integration tests, and benchmark set `#![forbid(unsafe_code)]`. `ring`, `curve25519-dalek`, and `secp256k1-sys` contain unsafe code inside their own crates.

Recorded local gates, after the final source was in place:

- `cargo fmt --check`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo test --all` (54 tests)

## Layout

```text
Cargo.toml
Cargo.lock
deny.toml
.gitignore          /target and *-wallet.json
LICENSE-APACHE
LICENSE-MIT
NOTICE
README.md
src/lib.rs            crate root, no unsafe
src/main.rs           CLI
src/error.rs
src/secret.rs         zeroizing wrappers
src/hexutil.rs
src/self_test.rs      official vectors, run before a search
src/independent.rs    xrpl-rust address derivation
src/verify.rs         dalek + xrpl-rust + ring
src/search.rs         threads, cancellation, OS CSPRNG
src/wallet.rs         Argon2id, ChaCha20-Poly1305, and wallet tests
src/xrpl/base58.rs    XRPL alphabet and Base58Check
src/xrpl/hash.rs
src/xrpl/keys.rs      Ed25519 derivation and AccountID
src/xrpl/prefix.rs    prefix rules and the attempt estimate
src/xrpl/seed.rs      sEd codec
tests/vectors.rs
tests/prefix.rs
tests/search.rs
tests/cli.rs
tests/pty_ctrlc.rs
tests/pty_ctrlc.py
benches/derive.rs
```

## Tests

`cargo test --all` covers the XRPL alphabet against Bitcoin's alphabet, Base58Check checksum failures, Ed25519 seed encode/decode, the official vectors above, public-key and AccountID and classic-address derivation, prefix acceptance and impossible prefixes, the full-address checksum rejection, the `rZuZu` estimate, encrypted round-trip, mode `0600`, wrong passphrase, tampered ciphertext, tampered address, truncated JSON, hostile KDF parameters, non-production KDF rejection, symlink rejection, overwrite refusal, independent verification, and multithreaded cancellation. One test runs `python3` on a PTY: Ctrl-C at the `verify`, `export`, and `generate` passphrase prompts must restore echo, cancel, print no seed, and print no address before a wallet exists. The same test plants a file at the output path during the `generate` passphrase prompt and checks that the command fails with no `FOUND` line and no address. That test fails if `python3` is not installed.

Integration tests find the binary via `CARGO_BIN_EXE` when cargo provides it, and otherwise via `target/debug` or `target/release`. A custom `CARGO_TARGET_DIR` can break that fallback.

## License

Copyright (c) 2026 ZuZu Wallet.

https://ZuZuWallet.com

Support@ZuZuWallet.com

Licensed under either of

- Apache License, Version 2.0 (`LICENSE-APACHE`)
- MIT license (`LICENSE-MIT`)

at your option.

`publish = false` in `Cargo.toml`. This GitHub repository is the release. The crate is not published to crates.io.
