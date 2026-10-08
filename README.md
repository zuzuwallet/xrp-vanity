# xrpl-vanity

An offline, security-focused vanity address generator for **XRPL Ed25519 classic addresses**.

`xrpl-vanity` searches for an XRPL address beginning with a prefix you choose, such as:

```text
rZuZu...
```

Each candidate is generated from fresh operating-system randomness, independently verified before acceptance, and stored in an encrypted wallet file. The private `sEd...` seed is **never printed during generation**.

---

## Highlights

- Offline XRPL Ed25519 vanity address generation
- Fresh OS CSPRNG entropy for every candidate
- Multi-threaded search
- Built-in self-tests using published XRPL vectors
- Match verification through multiple implementations
- Argon2id + ChaCha20-Poly1305 encrypted wallet files
- Secret-memory zeroization where supported
- Atomic, no-overwrite wallet creation
- Wallet files created with mode `0600`
- Terminal-only private seed export
- No runtime telemetry, RPC client, HTTP client, or update checker
- `#![forbid(unsafe_code)]` in this crate

The compiled generator is designed to work with networking disabled.

---

# What it does

For each candidate, the program:

1. Reads **16 bytes** from the operating-system CSPRNG using `getrandom`.
2. Derives an XRPL Ed25519 keypair.
3. Builds the corresponding classic `r...` address.
4. Checks whether the address begins with the requested prefix.

When a match is found, the result is verified again through independent code paths before it is accepted.

The original 16-byte entropy is then encrypted and saved to a wallet file.

The private seed is **not displayed during generation**.

The only command that prints an `sEd...` seed is:

```bash
xrpl-vanity export vanity-wallet.json
```

and that command requires:

- an interactive terminal on both stdin and stdout;
- explicit confirmation by typing `EXPORT`;
- the wallet passphrase.

---

# Scope

This project intentionally has a narrow scope.

It supports:

- XRPL Ed25519 keys
- classic `r...` addresses
- vanity prefix searching
- encrypted local wallet storage
- wallet verification
- offline seed export

It does **not** provide:

- secp256k1 wallet generation
- X-address generation
- mnemonic phrases
- RFC 1751 seeds
- transaction signing
- ledger queries or RPC access
- online wallet functionality

---

# Building on Fedora

The recommended workflow is:

> **Build while online, then disconnect before generating a real wallet.**

The project has been tested with:

```text
rustc 1.99.0
cargo 1.99.0
```

Install a C compiler and Rust:

```bash
sudo dnf install gcc

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

rustup component add rustfmt clippy
```

`ring` and `secp256k1-sys` compile native code, so a working C toolchain is required.

Build using the committed dependency lockfile:

```bash
cargo build --release --locked
```

Run the test suite:

```bash
cargo test --locked --all
```

Run Clippy:

```bash
cargo clippy --locked \
  --all-targets \
  --all-features \
  -- -D warnings
```

Optional dependency/security checks:

```bash
cargo install cargo-audit cargo-deny --locked

cargo audit --deny warnings

cargo deny check advisories bans licenses sources
```

`cargo audit` and `cargo deny` require network access to retrieve advisory information.

The `xrpl-vanity` binary itself does not.

---

# Recommended offline workflow

Once the project is built and reviewed, disconnect networking before generating a real wallet.

For example:

```bash
sudo nmcli networking off
```

or physically disconnect the network.

Then run:

```bash
./target/release/xrpl-vanity self-test
```

Generate a wallet:

```bash
./target/release/xrpl-vanity generate rZuZu
```

Verify it:

```bash
./target/release/xrpl-vanity verify vanity-wallet.json
```

Back up the encrypted wallet before funding the address.

For an offline wallet-generation environment, also consider disabling:

- shared clipboard
- shared folders
- VM snapshots containing RAM
- swap
- crash dumps
- hibernation

The host OS and hypervisor remain part of your trust boundary.

---

# Commands

```bash
xrpl-vanity self-test
```

Runs the built-in XRPL known-answer and implementation checks.

```bash
xrpl-vanity generate rZuZu
```

Searches for a classic address beginning with `rZuZu`.

```bash
xrpl-vanity generate rZuZu \
  --threads 16 \
  --output vanity-wallet.json
```

Uses 16 worker threads and writes the encrypted wallet to the requested path.

```bash
xrpl-vanity verify vanity-wallet.json
```

Decrypts the wallet, derives the keys again, independently checks the result, and prints the public address.

```bash
xrpl-vanity export vanity-wallet.json
```

Displays the private `sEd...` seed after explicit confirmation.

---

# Generation behavior

By default, `generate` uses:

```text
std::thread::available_parallelism()
```

clamped to:

```text
1..=256
```

Values of `0` or greater than `256` are rejected.

The default output path is:

```text
vanity-wallet.json
```

Existing destination files are never overwritten.

There is no overwrite flag.

If a requested prefix has an estimated cost greater than:

```text
10^12 attempts
```

the program requires an additional confirmation by typing:

```text
SEARCH
```

The `rZuZu` target is below that threshold.

---

# Passphrases

`generate`, `verify`, and `export` read passphrases directly from the terminal using `rpassword`.

Passphrases are:

- never accepted as command-line arguments;
- entered with terminal echo disabled;
- not trimmed.

When creating a new wallet, the passphrase must contain:

- at least **12 Unicode scalar values**
- no more than **1024 bytes**

The minimum length is only intended to prevent obvious mistakes.

For example:

```text
password12345
```

technically passes the length requirement, but it is not a strong wallet passphrase.

Use a long, randomly generated passphrase for anything you intend to fund.

Older wallets using shorter non-empty passphrases can still be opened by `verify` and `export`.

The same new-passphrase policy is enforced by the library-level wallet writer, not only by the CLI.

---

# Example

```text
XRPL Vanity Generator
Algorithm: Ed25519
Target: rZuZu
Threads: 16
Estimated attempts: ~264,104,224
Self-tests: PASS

Searching...
Attempts: 10,000,000
Rate: ... candidates/sec

Match found.
Attempts: ...
Elapsed: ...

FOUND
Address: rZuZu...
Encrypted secret saved to vanity-wallet.json
```

The address is deliberately withheld until the encrypted wallet has been successfully published.

If wallet persistence fails, the generated entropy is discarded and the address is not shown.

---

# Verifying a wallet

Run:

```bash
xrpl-vanity verify vanity-wallet.json
```

The program:

1. reads the encrypted wallet;
2. validates the wallet format;
3. derives the Argon2id encryption key;
4. authenticates and decrypts the stored entropy;
5. derives the XRPL keys and address again;
6. runs the independent verification paths;
7. compares the result with the stored address.

A successful result looks like:

```text
Address: r...
Verification: PASS
```

---

# Exporting the private seed

Run:

```bash
xrpl-vanity export vanity-wallet.json
```

This command is intentionally restrictive.

Both **stdin and stdout must be attached to a terminal**.

For example, this is rejected:

```bash
xrpl-vanity export vanity-wallet.json > captured.txt
```

The program displays a warning and requires:

```text
EXPORT
```

before asking for the passphrase.

Only then does it print the `sEd...` seed.

> [!CAUTION]
> The displayed `sEd...` value is the wallet's private secret.
>
> Anyone who obtains it can control the account.

After recording it securely, clear the terminal scrollback or close the terminal session.

Do not:

```text
paste it into a browser
paste it into ChatGPT or another AI
paste it into an issue report
send it by email
put it in a shell command
store it in a public file
use an online seed checker
```

---

# Ctrl-C and cancellation

Cancellation is designed to fail safely.

During a search:

- Ctrl-C sets a cancellation flag.
- Worker threads stop.
- No wallet is written.

After a match:

- Ctrl-C causes normal unwinding.
- Secret buffers are dropped.
- No wallet is written unless persistence has already completed.
- `process::exit()` is not used.

The public address is displayed only after:

```text
encrypted wallet created
→ destination published
→ parent directory synced
→ wallet writer returned success
```

If another file appears at the destination during the search, wallet publication fails and the generated address is not shown.

Passphrase prompts run on the main thread.

`rpassword` restores terminal settings before control returns to the application.

If Ctrl-C arrives during Argon2 computation, the operation finishes internally, but the command checks the cancellation flag again before printing success information or private seed material.

Once terminal output has already begun, it cannot be taken back.

---

# XRPL derivation

Each candidate starts with:

```text
16 bytes of OS-random entropy
```

The derivation is:

```text
16-byte entropy
      ↓
SHA-512Half
      ↓
32-byte RFC 8032 Ed25519 seed
      ↓
Ed25519 public key
      ↓
0xED || public key
      ↓
SHA-256
      ↓
RIPEMD-160
      ↓
20-byte AccountID
      ↓
XRPL Base58Check
      ↓
classic r... address
```

More specifically:

### 1. Entropy

Each worker independently requests 16 bytes from the operating system CSPRNG.

Workers do not share a userspace RNG.

### 2. SHA-512Half

The first 32 bytes of SHA-512 over the entropy are used as the RFC 8032 Ed25519 seed.

### 3. Ed25519

`ed25519-dalek` performs the primary public-key derivation.

This project does not implement Ed25519 arithmetic itself.

### 4. XRPL public key

XRPL Ed25519 public keys are encoded as:

```text
0xED || 32-byte Ed25519 public key
```

### 5. AccountID

The AccountID is:

```text
RIPEMD160(
    SHA256(
        XRPL public key
    )
)
```

### 6. Classic address

The classic address is XRPL Base58Check encoding of:

```text
0x00 || AccountID
```

with the checksum:

```text
SHA256(
    SHA256(
        0x00 || AccountID
    )
)[0..4]
```

XRPL's Base58 alphabet is:

```text
rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz
```

---

# Ed25519 seed encoding

The exported `sEd...` seed uses the XRPL Ed25519 seed version:

```text
01 E1 4B
```

This is different from the older family-seed prefix:

```text
21
```

The program intentionally generates and accepts only the Ed25519 `sEd...` format.

A secp256k1 family seed such as:

```text
sp5fghtJtpUorTwvof1NpDXAzNwf5
```

is rejected.

---

# Independent verification

A winning candidate is accepted only when multiple derivation paths agree.

### Primary path

Uses:

- `ed25519-dalek`
- this crate's SHA / RIPEMD / XRPL Base58Check logic

### XRPL reference path

Uses:

- `xrpl-rust 1.3.0`
- `derive_keypair`
- `derive_classic_address`

### Independent Ed25519 path

Uses:

- `ring 0.17.14`

`ring` independently derives the Ed25519 public key from the same SHA-512Half seed.

The AccountID and Base58 stages after that still use this crate.

This is intentionally redundant.

A match is not trusted simply because the search loop found a string beginning with the requested prefix.

---

# Self-tests

Self-tests run before any vanity search begins.

If they fail, generation stops and no wallet is written.

Included checks cover:

| Check | Vector |
|---|---|
| Entropy → `sEd` and back | `4C3A1D213FBDFB14C7C28D609469B341` → `sEdTM1uX8pu2do5XvTnutH6HsouMaM2` |
| All-zero entropy | `sEdSJHS4oiAdz7w2X2ni1gFiqtbJHqE` |
| All-`FF` entropy | `sEdV19BLfeQeKdEXyYA4NhjPJe6XBfG` |
| Invalid seed checksum | rejected |
| secp256k1 family seed | rejected |
| AccountID → classic address | `BA8E...7072` → `rJrRMgiRgrU6hDF4pgu5DXQdWyPbY35ErN` |
| Public key → classic address | `ED9434...` → `rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN` |
| Full seed → keypair → address | `sEdSKaCy2JT7JaM7v95H9SxkhP9wS2r` → `rLUEXYuLiQptky37CqLcm9USQpPiz5rkpD` |

The published test-vector private keys and seeds included in the repository are test data only.

They are not wallets produced by this program.

---

# Prefix search

Every classic XRPL address starts with:

```text
r
```

because the classic address payload begins with version byte `0x00`.

A requested prefix must:

- be non-empty;
- begin with `r`;
- contain only characters from the XRPL Base58 alphabet;
- be feasible within the classic-address numeric range;
- fit within the implementation's attempt counter.

The program also performs exact checksum-feasibility checks for narrow prefix ranges.

This allows it to reject alphabetically valid but impossible prefixes before a search starts.

For example, certain long sequences of leading `r` characters and impossible high-value prefixes are rejected immediately.

---

# Search estimates

For:

```text
rZuZu
```

the expected search cost is approximately:

```text
264,104,224 attempts
```

This is an expectation, not a guarantee.

A random search can finish much earlier—or much later.

The estimate displayed by the program is an **attempt count**, not a promise of wall-clock time.

---

# Encrypted wallet format

The wallet contains encrypted **16-byte entropy**, not a plaintext `sEd...` seed.

Version 1 uses:

| Property | Value |
|---|---|
| KDF | Argon2id |
| Argon2 version | 19 / `0x13` |
| Memory | 65,536 KiB |
| Iterations | 3 |
| Parallelism | 4 |
| Salt | 16 random bytes |
| Output key | 32 bytes |
| AEAD | ChaCha20-Poly1305 |
| Nonce | 12 random bytes |
| File permissions | `0600` |

The authenticated associated data includes:

```text
xrpl-vanity-wallet-v1
classic address
ed25519
```

Changing authenticated public metadata causes decryption to fail.

Production wallet files must use exactly the production KDF parameters.

A wallet requesting weaker, stronger, or otherwise unexpected Argon2 parameters is rejected before Argon2 is executed.

---

# Wallet filesystem safety

Wallet creation uses a temporary file in the destination directory.

The process is:

```text
create temporary file with O_CREAT | O_EXCL
        ↓
verify mode 0600
        ↓
write ciphertext
        ↓
fsync file
        ↓
hard-link to final destination
        ↓
fail if destination already exists
        ↓
remove temporary name
        ↓
fsync parent directory
```

There is no overwrite mode.

Wallet reads:

- open the path once;
- use Linux `O_NOFOLLOW`;
- reject symbolic links;
- obtain file metadata and contents from the same file descriptor;
- reject files larger than 1 MiB.

This project currently targets Fedora/Linux for these filesystem protections.

---

# Zeroization

Secret data is wrapped using the `zeroize` crate where practical.

This includes:

- entropy
- decoded seed material
- SHA-512Half intermediate state
- Argon2 output
- Argon2 working memory
- AEAD key material
- decrypted wallet plaintext
- Base58Check secret buffers
- exported `sEd...` strings

`ed25519-dalek` is built with its zeroization feature enabled.

This is still **best-effort memory hygiene**, not a guarantee that no secret copy can ever exist.

It cannot fully control:

- compiler-generated copies
- CPU registers
- allocator behavior
- swap
- hibernation
- VM snapshots
- crash dumps
- internal copies made by dependencies
- terminal scrollback after export

`xrpl-rust` and `ring` may retain secret-derived internal material that this crate cannot wipe itself.

---

# Threat model

This project assumes:

- the operating system CSPRNG is trustworthy;
- the CPU is not malicious;
- the build machine is trustworthy;
- the Rust compiler/toolchain is trustworthy;
- the committed dependency lockfile has been reviewed.

The program tries to protect against mistakes such as:

- deriving the wrong XRPL address;
- storing a seed in a world-readable file;
- passing the passphrase on the command line;
- silently overwriting an existing wallet;
- printing a public address before its encrypted wallet exists;
- exporting a private seed through redirected stdout;
- continuing a search after a winning candidate is found.

It does **not** attempt to protect against:

- malware or root access;
- a compromised compiler;
- physical memory attacks;
- side-channel attacks;
- weak but sufficiently long passphrases;
- someone watching the terminal during export;
- vulnerabilities inside cryptographic dependencies.

---

# Benchmarks

The hot loop performs approximately:

```text
getrandom(16 bytes)
+
SHA-512Half
+
Ed25519 public-key derivation
+
HASH160
+
Base58Check
+
prefix comparison
```

Criterion benchmarks are available with:

```bash
cargo bench --bench derive
```

Benchmark results depend heavily on:

- CPU model
- CPU load
- power-management state
- thermal throttling
- thread count
- VM configuration

Do not treat a single benchmark run as a guaranteed search rate.

---

# Dependency and security review

The project pins dependencies through:

```text
Cargo.lock
```

Notable direct dependencies include:

| Crate | Role |
|---|---|
| `argon2` | wallet KDF |
| `chacha20poly1305` | wallet encryption |
| `ed25519-dalek` | primary Ed25519 derivation |
| `ring` | independent Ed25519 verification |
| `xrpl-rust` | independent XRPL derivation |
| `getrandom` | operating-system CSPRNG |
| `sha2` | SHA-256 / SHA-512 |
| `ripemd` | RIPEMD-160 |
| `zeroize` | secret-memory cleanup |
| `rpassword` | terminal passphrase input |
| `clap` | command-line interface |

The committed dependency graph contains no normal runtime HTTP stack such as:

```text
reqwest
hyper
tokio
rustls
```

Security checks used during development include:

```bash
cargo audit --deny warnings

cargo deny check advisories bans licenses sources
```

`cargo-deny` may report duplicate versions of transitive crates. Those warnings are dependency-tree information, not automatically vulnerabilities.

---

# Development checks

Before creating a release:

```bash
cargo fmt --check

cargo clippy \
  --all-targets \
  --all-features \
  -- -D warnings

cargo test --all

cargo audit --deny warnings

cargo deny check advisories bans licenses sources

cargo build --release --locked

./target/release/xrpl-vanity self-test
```

The integration suite includes PTY tests covering Ctrl-C behavior during:

- generation passphrase entry
- verification passphrase entry
- seed export
- output-file collision during generation

Those tests require `python3`.

---

# Repository layout

```text
Cargo.toml
Cargo.lock
deny.toml
.gitignore
LICENSE-APACHE
LICENSE-MIT
NOTICE
README.md

src/
├── lib.rs
├── main.rs
├── error.rs
├── secret.rs
├── hexutil.rs
├── self_test.rs
├── independent.rs
├── verify.rs
├── search.rs
├── wallet.rs
└── xrpl/
    ├── base58.rs
    ├── hash.rs
    ├── keys.rs
    ├── prefix.rs
    └── seed.rs

tests/
├── vectors.rs
├── prefix.rs
├── search.rs
├── cli.rs
├── pty_ctrlc.rs
└── pty_ctrlc.py

benches/
└── derive.rs
```

---

# Important limitations

A few things are worth keeping in mind:

- The generator does **not** query the XRPL ledger.
- It does not check whether an address has previously appeared on-chain.
- It does not sign transactions.
- You still need a separate, reviewed signing/recovery workflow.
- Search estimates are probabilistic.
- A sufficiently large search may run far longer than its estimate.
- The program uses Ed25519 only.
- The exported `sEd...` format may not be accepted by tooling that only supports older `0x21` family seeds.

---

# References

The implementation was built against published XRPL and cryptographic references including:

- XRPL Cryptographic Keys
- XRPL Addresses
- XRPL Base58 Encodings
- `ripple-address-codec`
- `ripple-keypairs`
- `rippled`
- RFC 8032 — Ed25519
- RFC 9106 — Argon2
- RFC 8439 — ChaCha20-Poly1305

---

# License

Copyright © 2026 ZuZu Wallet

https://ZuZuWallet.com

Support@ZuZuWallet.com

Licensed under either:

- Apache License, Version 2.0 — `LICENSE-APACHE`
- MIT License — `LICENSE-MIT`

at your option.

`publish = false` is set in `Cargo.toml`.

The GitHub repository is the distribution source; this crate is not published to crates.io.
