// Copyright (c) 2026 ZuZu Wallet
// https://ZuZuWallet.com
// Support@ZuZuWallet.com
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Parallel vanity search.
//!
//! Each attempt draws 16 bytes from the operating-system CSPRNG. Workers do
//! not share a userspace RNG and do not reuse entropy. The first match sets
//! an atomic flag. There is no lock in the candidate loop.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Sender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::error::Error;
use crate::secret::SecretBytes;
use crate::xrpl::{
    address_starts_with, derive_from_entropy, validate_prefix, SEARCH_COUNTER_HEADROOM,
};

pub const MAX_THREADS: usize = 256;
pub const COUNTER_HEADROOM: u64 = SEARCH_COUNTER_HEADROOM;
const ATTEMPT_CHUNK: u64 = 1024;

/// Stop before `fetch_add` could wrap a `u64` attempt counter.
pub fn counter_would_overflow(current: u64) -> bool {
    current >= u64::MAX.saturating_sub(COUNTER_HEADROOM)
}

pub struct SearchHit {
    pub entropy: SecretBytes<16>,
    pub address: String,
    pub public_key: [u8; 33],
    pub attempts: u64,
}

impl std::fmt::Debug for SearchHit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SearchHit")
            .field("entropy", &self.entropy)
            .field("address", &self.address)
            .field("public_key", &"[public]")
            .field("attempts", &self.attempts)
            .finish()
    }
}

pub fn validate_threads(threads: usize) -> Result<(), Error> {
    if threads == 0 || threads > MAX_THREADS {
        Err(Error::Threads)
    } else {
        Ok(())
    }
}

/// Search until `prefix` matches, `cancel` is set, or a worker fails.
///
/// `progress` receives `(attempts, candidates_per_second)` about once a second.
/// Both numbers are public. A panic or RNG failure in any worker discards a
/// match from another worker.
pub fn search<F>(
    prefix: &str,
    threads: usize,
    cancel: Arc<AtomicBool>,
    progress: F,
) -> Result<SearchHit, Error>
where
    F: Fn(u64, u64) + Send + Sync + 'static,
{
    validate_prefix(prefix)?;
    validate_threads(threads)?;

    let prefix = prefix.to_owned();
    let attempts = Arc::new(AtomicU64::new(0));
    let failed = Arc::new(AtomicBool::new(false));
    let overflow = Arc::new(AtomicBool::new(false));
    let (tx, rx) = mpsc::channel::<Zeroizing<[u8; 16]>>();

    let reporter = spawn_reporter(Arc::clone(&attempts), Arc::clone(&cancel), progress);

    let mut handles = Vec::with_capacity(threads);
    for _ in 0..threads {
        let tx = tx.clone();
        let cancel_worker = Arc::clone(&cancel);
        let attempts = Arc::clone(&attempts);
        let failed_worker = Arc::clone(&failed);
        let overflow = Arc::clone(&overflow);
        let prefix = prefix.clone();
        match thread::Builder::new()
            .name("xrpl-vanity".to_owned())
            .spawn(move || {
                let outcome = catch_unwind(AssertUnwindSafe(|| {
                    worker(&prefix, &cancel_worker, &attempts, &overflow, &tx)
                }));
                if !matches!(outcome, Ok(Ok(()))) {
                    failed_worker.store(true, Ordering::Release);
                    cancel_worker.store(true, Ordering::Release);
                }
            }) {
            Ok(handle) => handles.push(handle),
            Err(_) => {
                failed.store(true, Ordering::Release);
                cancel.store(true, Ordering::Release);
                break;
            }
        }
    }
    drop(tx);

    let first = rx.recv();
    cancel.store(true, Ordering::Release);
    join_workers(handles);
    let _ = reporter.join();

    let mut extra = Vec::new();
    while let Ok(more) = rx.try_recv() {
        extra.push(more);
    }

    let total = attempts.load(Ordering::Relaxed);
    if failed.load(Ordering::Acquire) {
        return Err(Error::SearchFailed);
    }
    if overflow.load(Ordering::Acquire) && first.is_err() {
        return Err(Error::SearchFailed);
    }

    let Some(entropy) = first.ok() else {
        return Err(Error::Cancelled { attempts: total });
    };
    drop(extra);

    let entropy = SecretBytes::new(*entropy);
    let derived = derive_from_entropy(entropy.as_bytes())?;
    if !derived.address.starts_with(&prefix) {
        return Err(Error::SearchFailed);
    }
    Ok(SearchHit {
        entropy,
        address: derived.address,
        public_key: derived.public_key,
        attempts: total,
    })
}

fn spawn_reporter<F>(
    attempts: Arc<AtomicU64>,
    cancel: Arc<AtomicBool>,
    progress: F,
) -> JoinHandle<()>
where
    F: Fn(u64, u64) + Send + Sync + 'static,
{
    thread::spawn(move || {
        let mut last_count = 0u64;
        let mut last_report = Instant::now();
        while !cancel.load(Ordering::Acquire) {
            thread::sleep(Duration::from_millis(50));
            if cancel.load(Ordering::Acquire) {
                break;
            }
            if last_report.elapsed() < Duration::from_secs(1) {
                continue;
            }
            let now = attempts.load(Ordering::Relaxed);
            let elapsed = last_report.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 {
                ((now.saturating_sub(last_count)) as f64 / elapsed) as u64
            } else {
                0
            };
            let _ = catch_unwind(AssertUnwindSafe(|| progress(now, rate)));
            last_count = now;
            last_report = Instant::now();
        }
    })
}

fn join_workers(handles: Vec<JoinHandle<()>>) {
    for handle in handles {
        let _ = handle.join();
    }
}

fn worker(
    prefix: &str,
    cancel: &AtomicBool,
    attempts: &AtomicU64,
    overflow: &AtomicBool,
    tx: &Sender<Zeroizing<[u8; 16]>>,
) -> Result<(), Error> {
    let mut local = 0u64;
    let result = (|| -> Result<(), Error> {
        loop {
            if cancel.load(Ordering::Acquire) {
                return Ok(());
            }
            let observed = attempts.load(Ordering::Relaxed).saturating_add(local);
            if counter_would_overflow(observed) {
                overflow.store(true, Ordering::Release);
                cancel.store(true, Ordering::Release);
                return Ok(());
            }

            let mut entropy = Zeroizing::new([0u8; 16]);
            if getrandom::getrandom(&mut entropy[..]).is_err() {
                return Err(Error::Rng);
            }
            let matched = address_starts_with(&entropy, prefix)?;
            local += 1;
            if local >= ATTEMPT_CHUNK {
                attempts.fetch_add(local, Ordering::Relaxed);
                local = 0;
            }
            if matched {
                let _ = tx.send(entropy);
                cancel.store(true, Ordering::Release);
                return Ok(());
            }
        }
    })();
    if local > 0 {
        attempts.fetch_add(local, Ordering::Relaxed);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::COUNTER_HEADROOM;
    use crate::xrpl::SEARCH_COUNTER_HEADROOM;

    #[test]
    fn counter_headroom_is_the_prefix_limit() {
        assert_eq!(COUNTER_HEADROOM, SEARCH_COUNTER_HEADROOM);
        assert_eq!(COUNTER_HEADROOM, 1_048_576);
    }
}
