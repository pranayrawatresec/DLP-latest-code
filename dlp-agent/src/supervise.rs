//! Cross-thread coordination primitives for the unified supervised run mode
//! (`run-endpoint`). PURE logic + atomics only — no OS calls, no I/O — so the
//! health-gate decision is unit-tested here without FFI.
//!
//! The one shared signal is [`SealerHealth`]: the in-process USB *sealer* marks
//! itself alive on every poll and records whether it holds a usable keyring; the
//! kernel *guard* reads it to decide whether a seal-eligible write may be allowed
//! (the sealer will armour it) or MUST be blocked (fail secure — never leave
//! plaintext on the stick when nobody can seal it).
//!
//! Fail-secure by construction: a freshly-constructed signal is UNHEALTHY until
//! the sealer proves both liveness (a first `mark_alive`) and a present keyring,
//! so the guard blocks seal-eligible writes during the sealer's startup window
//! rather than waving them through.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;

use crate::config::Config;

/// Read a consistent snapshot of the shared, live-resynced effective config.
///
/// `run-endpoint` shares ONE `Arc<RwLock<Config>>` between the guard and sealer
/// threads and lets the re-sync worker swap it; each worker reads a fresh
/// snapshot per iteration/scan so a live whitelist re-sync takes effect without
/// a restart. The standalone foreground commands wrap their (fixed) merged
/// config the same way so both call paths share one code path.
///
/// A poisoned lock (a panicked writer) is recovered rather than propagated —
/// the config is plain data and enforcement must never stop over a poisoned lock.
pub fn snapshot_config(shared: &Arc<RwLock<Config>>) -> Config {
    shared.read().unwrap_or_else(|p| p.into_inner()).clone()
}

/// Liveness + keyring signal shared (behind an `Arc`) between the sealer thread
/// (writer) and the guard thread (reader) in `run-endpoint`.
///
/// * `last_ok_ms` — monotonic milliseconds (since this signal was created) of the
///   sealer's last successful poll. `0` is the sentinel for "never marked alive".
/// * `keyring_present` — whether the sealer loaded a usable keyring at startup.
///   With no keyring the sealer can never seal, so the guard must block.
pub struct SealerHealth {
    start: Instant,
    last_ok_ms: AtomicU64,
    keyring_present: AtomicBool,
}

impl SealerHealth {
    /// Create a signal. `keyring_present` reflects whether a usable keyring was
    /// loaded; liveness starts at "never" so the signal is UNHEALTHY until the
    /// sealer's first `mark_alive` (fail secure during startup).
    pub fn new(keyring_present: bool) -> Self {
        SealerHealth {
            start: Instant::now(),
            last_ok_ms: AtomicU64::new(0),
            keyring_present: AtomicBool::new(keyring_present),
        }
    }

    /// Monotonic milliseconds since construction.
    fn now_ms(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// The sealer calls this on EVERY successful poll — including a poll that
    /// found nothing to seal (an idle-but-alive sealer is still healthy). Stores
    /// `max(now, 1)` so the "never" sentinel (`0`) can never be produced by a
    /// poll that happens at t=0.
    pub fn mark_alive(&self) {
        self.last_ok_ms.store(self.now_ms().max(1), Ordering::Relaxed);
    }

    /// Update whether a usable keyring is present (e.g. after a re-sync reloads
    /// keys). `false` makes the guard fail secure regardless of liveness.
    pub fn set_keyring_present(&self, present: bool) {
        self.keyring_present.store(present, Ordering::Relaxed);
    }

    /// Whether a keyring is currently present.
    pub fn keyring_present(&self) -> bool {
        self.keyring_present.load(Ordering::Relaxed)
    }

    /// Guard-side health check against wall time: healthy iff a keyring is present
    /// AND the sealer marked itself alive within `timeout_ms`.
    pub fn is_healthy(&self, timeout_ms: u64) -> bool {
        self.is_healthy_at(self.now_ms(), timeout_ms)
    }

    /// PURE health decision (unit-tested): healthy iff a keyring is present, the
    /// sealer has EVER marked itself alive (`last_ok_ms != 0`), and the last
    /// aliveness is within `timeout_ms` of `now_ms`.
    pub fn is_healthy_at(&self, now_ms: u64, timeout_ms: u64) -> bool {
        if !self.keyring_present.load(Ordering::Relaxed) {
            return false;
        }
        let last = self.last_ok_ms.load(Ordering::Relaxed);
        if last == 0 {
            return false; // never marked alive ⇒ unhealthy (fail secure)
        }
        now_ms.saturating_sub(last) <= timeout_ms
    }

    /// Test-only: set the last-alive timestamp explicitly (deterministic clock).
    #[cfg(test)]
    pub fn set_last_ok_ms(&self, ms: u64) {
        self.last_ok_ms.store(ms, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fresh_signal_is_unhealthy_until_first_mark() {
        let h = SealerHealth::new(true);
        // keyring present but never marked alive ⇒ unhealthy.
        assert!(!h.is_healthy_at(0, 10_000));
        assert!(!h.is_healthy_at(5_000, 10_000));
        h.set_last_ok_ms(5_000);
        assert!(h.is_healthy_at(5_000, 10_000));
    }

    #[test]
    fn stale_liveness_is_unhealthy() {
        let h = SealerHealth::new(true);
        h.set_last_ok_ms(1_000);
        // within window
        assert!(h.is_healthy_at(11_000, 10_000)); // exactly at the edge
        // beyond window
        assert!(!h.is_healthy_at(11_001, 10_000));
    }

    #[test]
    fn missing_keyring_is_always_unhealthy() {
        let h = SealerHealth::new(false);
        h.set_last_ok_ms(5_000);
        // fresh liveness but no keyring ⇒ unhealthy.
        assert!(!h.is_healthy_at(5_000, 10_000));
        // presence can be toggled on later (e.g. after a re-sync).
        h.set_keyring_present(true);
        assert!(h.is_healthy_at(5_000, 10_000));
    }

    #[test]
    fn mark_alive_never_writes_the_never_sentinel() {
        let h = SealerHealth::new(true);
        h.mark_alive();
        // Whatever the elapsed value, it is stored as >= 1, so the "never" (0)
        // sentinel is never produced by a real poll.
        assert!(h.keyring_present());
        // A generous window makes this deterministic regardless of timing.
        assert!(h.is_healthy(60_000));
    }
}
