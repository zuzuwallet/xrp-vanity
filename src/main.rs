// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! CLI for the offline XRPL vanity generator.
//!
//! The seed is printed only by `export`, after an explicit confirmation.

#![forbid(unsafe_code)]

use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::{Parser, Subcommand};
use zeroize::Zeroizing;

use xrpl_vanity::wallet::{check_new_passphrase, check_passphrase, MIN_NEW_PASSPHRASE_CHARS};
use xrpl_vanity::xrpl::group_digits;
use xrpl_vanity::{
    encode_ed25519_seed, open_and_verify, run_self_tests, search, validate_prefix,
    write_encrypted_wallet, Error, MAX_THREADS,
};

#[derive(Parser)]
#[command(
    name = "xrpl-vanity",
    about = "Offline XRPL Ed25519 vanity classic-address generator",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run cryptographic self-tests and exit.
    SelfTest,
    /// Search for a classic address that starts with PREFIX.
    Generate {
        prefix: String,
        /// Worker threads. Defaults to the available parallelism.
        #[arg(long)]
        threads: Option<usize>,
        /// Encrypted wallet path. Refuses to overwrite an existing file.
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Decrypt a wallet and check that the seed matches the stored address.
    Verify { wallet: PathBuf },
    /// Decrypt a wallet and print the seed. Offline recovery only.
    Export { wallet: PathBuf },
}

fn main() -> ExitCode {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn run() -> Result<(), Error> {
    match Cli::parse().command {
        Command::SelfTest => cmd_self_test(),
        Command::Generate {
            prefix,
            threads,
            output,
        } => cmd_generate(&prefix, threads, output),
        Command::Verify { wallet } => cmd_verify(&wallet),
        Command::Export { wallet } => cmd_export(&wallet),
    }
}

fn cmd_self_test() -> Result<(), Error> {
    if let Err(err) = run_self_tests() {
        println!("Self-tests: FAIL");
        return Err(err);
    }
    println!("Self-tests: PASS");
    Ok(())
}

fn cmd_generate(
    prefix: &str,
    threads: Option<usize>,
    output: Option<PathBuf>,
) -> Result<(), Error> {
    let estimate = validate_prefix(prefix)?;
    let threads = match threads {
        Some(value) => {
            if value == 0 || value > MAX_THREADS {
                return Err(Error::Threads);
            }
            value
        }
        None => default_threads(),
    };
    let output = output.unwrap_or_else(|| PathBuf::from("vanity-wallet.json"));
    ensure_output_available(&output)?;

    println!("XRPL Vanity Generator");
    println!("Algorithm: Ed25519");
    println!("Target: {prefix}");
    println!("Threads: {threads}");
    println!(
        "Estimated attempts: ~{} (estimate, not a guarantee)",
        estimate.display_attempts()
    );
    if let Err(err) = run_self_tests() {
        println!("Self-tests: FAIL");
        return Err(err);
    }
    println!("Self-tests: PASS");
    require_tty()?;
    if estimate.needs_large_search_confirmation() {
        println!(
            "This prefix is expected to take more than {} attempts.",
            group_digits("1000000000000")
        );
        println!("Type SEARCH to continue:");
        confirm_line("SEARCH")?;
    }

    let cancel = Arc::new(AtomicBool::new(false));
    let interrupt = Arc::new(AtomicBool::new(false));
    install_interrupt(Arc::clone(&cancel), Arc::clone(&interrupt))?;

    println!();
    println!("Searching...");
    let _ = io::stdout().flush();
    let started = Instant::now();
    let hit = search(prefix, threads, Arc::clone(&cancel), |attempts, rate| {
        println!("Attempts: {}", group_u64(attempts));
        println!("Rate: {} candidates/sec", group_u64(rate));
        let _ = io::stdout().flush();
    });

    let hit = match hit {
        Ok(hit) if interrupt.load(Ordering::Acquire) => {
            return Err(Error::Cancelled {
                attempts: hit.attempts,
            });
        }
        other => other?,
    };

    if interrupt.load(Ordering::Acquire) {
        return Err(Error::Cancelled {
            attempts: hit.attempts,
        });
    }
    xrpl_vanity::confirm_match(hit.entropy.as_bytes(), &hit.address, &hit.public_key)?;
    if interrupt.load(Ordering::Acquire) {
        return Err(Error::Cancelled {
            attempts: hit.attempts,
        });
    }

    println!();
    println!("Match found.");
    println!("Attempts: {}", group_u64(hit.attempts));
    println!("Elapsed: {}", format_elapsed(started.elapsed()));
    println!("The address is printed after the encrypted wallet is saved.");
    println!();
    let _ = io::stdout().flush();

    let passphrase = match prompt_new_passphrase(&interrupt) {
        Ok(passphrase) => passphrase,
        Err(err) => {
            eprintln!("Wallet was not saved.");
            return match err {
                Error::Cancelled { .. } => Err(Error::Cancelled {
                    attempts: hit.attempts,
                }),
                other => Err(other),
            };
        }
    };
    if interrupt.load(Ordering::Acquire) {
        eprintln!("Wallet was not saved.");
        return Err(Error::Cancelled {
            attempts: hit.attempts,
        });
    }
    if let Err(err) = write_encrypted_wallet(&output, passphrase.as_str(), hit.entropy.as_bytes()) {
        // A file at the output path is not proof that it holds this match.
        // Another process can create it during the search or the passphrase prompt.
        eprintln!("Wallet was not saved successfully.");
        return Err(err);
    }
    print_found_address(&hit.address);
    println!("Encrypted secret saved to {}", output.display());
    Ok(())
}

fn print_found_address(address: &str) {
    println!("FOUND");
    println!("Address: {address}");
}

fn cmd_verify(path: &Path) -> Result<(), Error> {
    require_tty()?;
    let interrupt = install_command_interrupt()?;
    let passphrase = prompt_password_interruptible("Passphrase: ", interrupt.as_ref())?;
    check_passphrase(passphrase.as_str())?;
    let opened = open_and_verify(path, passphrase.as_str())?;
    secret_output_allowed(interrupt.load(Ordering::Acquire))?;
    let address = opened.address.clone();
    secret_output_allowed(interrupt.load(Ordering::Acquire))?;
    println!("Address: {address}");
    println!("Verification: PASS");
    Ok(())
}

fn cmd_export(path: &Path) -> Result<(), Error> {
    require_export_terminals()?;
    println!("WARNING: This operation prints the secret seed to this terminal.");
    println!(
        "Do not paste this into a website, chat, AI, issue tracker, shell history, or online verifier."
    );
    println!("Clear the terminal scrollback after the seed has been copied onto offline media.");
    println!("Type EXPORT to continue:");
    confirm_line("EXPORT")?;
    let interrupt = install_command_interrupt()?;
    let passphrase = prompt_password_interruptible("Passphrase: ", interrupt.as_ref())?;
    check_passphrase(passphrase.as_str())?;
    let opened = open_and_verify(path, passphrase.as_str())?;
    secret_output_allowed(interrupt.load(Ordering::Acquire))?;
    let seed = encode_ed25519_seed(opened.entropy.as_bytes());
    // Check again after encoding. A Ctrl-C in the gap still drops the seed
    // string instead of printing it. The handler cannot cancel a print that
    // has already started.
    secret_output_allowed(interrupt.load(Ordering::Acquire))?;
    println!("Seed: {}", seed.as_str());
    Ok(())
}

fn ensure_output_available(path: &Path) -> Result<(), Error> {
    if path.exists() {
        return Err(Error::OutputExists);
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() && !parent.is_dir() {
            return Err(Error::OutputDir);
        }
    }
    Ok(())
}

fn default_threads() -> usize {
    std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1)
        .clamp(1, MAX_THREADS)
}

fn require_tty() -> Result<(), Error> {
    if io::stdin().is_terminal() {
        Ok(())
    } else {
        Err(Error::NeedTerminal)
    }
}

fn require_export_terminals() -> Result<(), Error> {
    export_terminals_ok(io::stdin().is_terminal(), io::stdout().is_terminal())
}

fn export_terminals_ok(stdin_tty: bool, stdout_tty: bool) -> Result<(), Error> {
    if stdin_tty && stdout_tty {
        Ok(())
    } else {
        Err(Error::ExportNeedsTerminal)
    }
}

fn confirm_line(expected: &str) -> Result<(), Error> {
    require_tty()?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|err| Error::Io(format!("stdin: {err}")))?;
    if line.trim() == expected {
        Ok(())
    } else {
        Err(Error::NotConfirmed)
    }
}

fn install_command_interrupt() -> Result<Arc<AtomicBool>, Error> {
    let interrupt = Arc::new(AtomicBool::new(false));
    let cancel = Arc::new(AtomicBool::new(false));
    install_interrupt(cancel, Arc::clone(&interrupt))?;
    Ok(interrupt)
}

/// Refuse secret output after a slow step if Ctrl-C arrived while it ran.
fn secret_output_allowed(interrupted: bool) -> Result<(), Error> {
    if interrupted {
        Err(Error::Cancelled { attempts: 0 })
    } else {
        Ok(())
    }
}

fn prompt_new_passphrase(interrupt: &AtomicBool) -> Result<Zeroizing<String>, Error> {
    require_tty()?;
    for _ in 0..3 {
        if interrupt.load(Ordering::Acquire) {
            return Err(Error::Cancelled { attempts: 0 });
        }
        let first = prompt_password_interruptible("Passphrase: ", interrupt)?;
        let second = prompt_password_interruptible("Confirm passphrase: ", interrupt)?;
        if first.as_str() != second.as_str() {
            eprintln!("error: passphrase did not match");
            continue;
        }
        match check_new_passphrase(first.as_str()) {
            Ok(()) => return Ok(first),
            Err(_) => {
                if check_passphrase(first.as_str()).is_ok() {
                    eprintln!(
                        "error: a new passphrase must be at least {MIN_NEW_PASSPHRASE_CHARS} characters"
                    );
                    eprintln!(
                        "That minimum only stops accidents. It is not a measure of strength."
                    );
                } else {
                    eprintln!("error: passphrase rejected");
                }
            }
        }
    }
    Err(Error::Passphrase)
}

/// Read a passphrase on this thread.
///
/// `rpassword` turns terminal Ctrl-C into `ErrorKind::Interrupted` and restores
/// echo in `Drop` before that error returns. The caller then drops any
/// passphrase it already holds.
fn prompt_password_interruptible(
    label: &str,
    interrupt: &AtomicBool,
) -> Result<Zeroizing<String>, Error> {
    if interrupt.load(Ordering::Acquire) {
        return Err(Error::Cancelled { attempts: 0 });
    }
    password_prompt_result(
        rpassword::prompt_password(label),
        interrupt.load(Ordering::Acquire),
    )
}

fn password_prompt_result(
    read: Result<String, std::io::Error>,
    interrupted: bool,
) -> Result<Zeroizing<String>, Error> {
    if interrupted {
        if let Ok(password) = read {
            drop(Zeroizing::new(password));
        }
        return Err(Error::Cancelled { attempts: 0 });
    }
    match read {
        Ok(password) => Ok(Zeroizing::new(password)),
        Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {
            Err(Error::Cancelled { attempts: 0 })
        }
        Err(_) => Err(Error::NeedTerminal),
    }
}

fn install_interrupt(cancel: Arc<AtomicBool>, interrupt: Arc<AtomicBool>) -> Result<(), Error> {
    ctrlc::set_handler(move || {
        interrupt.store(true, Ordering::Release);
        cancel.store(true, Ordering::Release);
    })
    .map_err(|_| Error::Io("could not install the interrupt handler".to_owned()))
}

fn group_u64(value: u64) -> String {
    group_digits(&value.to_string())
}

fn format_elapsed(elapsed: Duration) -> String {
    if elapsed.as_secs() < 60 {
        format!("{:.3}s", elapsed.as_secs_f64())
    } else {
        let seconds = elapsed.as_secs();
        format!("{}m {}s", seconds / 60, seconds % 60)
    }
}

#[cfg(test)]
mod tests {
    use super::{export_terminals_ok, password_prompt_result, secret_output_allowed, Error};

    #[test]
    fn export_requires_both_terminals() {
        assert!(export_terminals_ok(true, true).is_ok());
        assert_eq!(
            export_terminals_ok(true, false),
            Err(Error::ExportNeedsTerminal)
        );
        assert_eq!(
            export_terminals_ok(false, true),
            Err(Error::ExportNeedsTerminal)
        );
        assert_eq!(
            export_terminals_ok(false, false),
            Err(Error::ExportNeedsTerminal)
        );
    }

    #[test]
    fn interrupted_passphrase_read_cancels_without_keeping_it() {
        let accepted =
            password_prompt_result(Ok("correct horse battery".to_owned()), false).unwrap();
        assert_eq!(accepted.as_str(), "correct horse battery");
        assert!(matches!(
            password_prompt_result(Ok("secret-passphrase".to_owned()), true),
            Err(Error::Cancelled { attempts: 0 })
        ));
        let interrupted = std::io::Error::new(std::io::ErrorKind::Interrupted, "interrupted");
        assert!(matches!(
            password_prompt_result(Err(interrupted), false),
            Err(Error::Cancelled { attempts: 0 })
        ));
        let other = std::io::Error::other("no tty");
        assert!(matches!(
            password_prompt_result(Err(other), false),
            Err(Error::NeedTerminal)
        ));
    }

    #[test]
    fn cancelled_decrypt_does_not_release_a_secret() {
        assert!(secret_output_allowed(false).is_ok());
        assert!(matches!(
            secret_output_allowed(true),
            Err(Error::Cancelled { attempts: 0 })
        ));
    }
}
