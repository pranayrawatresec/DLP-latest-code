//! What the at-rest sweep's pending-directory queue costs on a REAL estate.
//!
//! The walker is breadth-first, so the queue grows to the width of the widest
//! level of the tree — a number no unit test can supply, because it is a
//! property of the customer's disk. This is the harness that measures it before
//! a rollout, and the evidence behind the memory cap in `ml::walk`:
//!
//! ```text
//! cargo run --release --example walk_frontier -- C:\Users
//! cargo run --release --example walk_frontier -- C:\Users --resume-after 5000
//! cargo run --release --example walk_frontier -- C:\Users --cap 64 --resume-after 800
//! ```
//!
//! `--cap N` shrinks the in-memory limit, which is how the spill and restart
//! paths get exercised on a machine whose own estate is too small to reach the
//! shipped cap — a test VM, say.
//!
//! It walks directories only — the extension filter is emptied, so not one file
//! is opened, hashed or classified. Nothing is enqueued and no verdict is
//! written; the only state it touches is a scratch state directory it makes and
//! removes itself.
//!
//! `--resume-after N` stops after N directories, checkpoints, drops the walker,
//! and starts a second one over the same state directory — the agent-restart
//! path. That is the one that used to be dead: a queue wider than the cap was
//! persisted EMPTY, so every restart re-walked the scope from the beginning.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dlp_agent::ml::cache::VerdictCache;
use dlp_agent::ml::walk::{load_checkpoint, StepStatus, WalkConfig, Walker};
use dlp_agent::ml::watch::{ClassifyJob, ClassifySink};
use dlp_agent::mlpolicy::{self, MlLabelRule, MlPolicy};

/// Counts what it was offered and keeps nothing.
struct CountingSink(AtomicU64);

impl ClassifySink for CountingSink {
    fn submit(&self, _job: ClassifyJob) -> bool {
        self.0.fetch_add(1, Ordering::Relaxed);
        true
    }
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let scope = PathBuf::from(
        args.first()
            .cloned()
            .unwrap_or_else(|| r"C:\Users".to_string()),
    );
    let flag = |name: &str| -> Option<usize> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .and_then(|n| n.parse().ok())
    };
    let resume_after = flag("--resume-after").unwrap_or(0);
    let cap = flag("--cap");

    // A policy that is live (an inert one makes the walker do nothing) but that
    // never matches anything we would act on.
    mlpolicy::set_active(MlPolicy {
        enabled: true,
        labels: vec![MlLabelRule {
            id: "FIN".to_string(),
            min_confidence: None,
        }],
        ..MlPolicy::default()
    });

    let state = std::env::temp_dir().join(format!("dlp-frontier-probe-{}", std::process::id()));
    std::fs::create_dir_all(&state)?;

    let mut cfg = WalkConfig::new(&state, vec![scope.clone()]);
    cfg.files_per_minute = 0; // unthrottled: we are measuring shape, not pace
    cfg.dir_listing_cost = 0.0;
    cfg.filter.extensions = &[]; // directories only — no file is ever opened
    if let Some(c) = cap {
        cfg.max_pending_dirs = c;
    }

    let cfg_cap = cfg.max_pending_dirs as u64;
    println!("scope            : {}", scope.display());
    println!("memory cap       : {} directories", cfg.max_pending_dirs);
    println!("checkpoint every : {} units of work", cfg.checkpoint_every);
    println!();

    let started = std::time::Instant::now();
    let cache = Arc::new(VerdictCache::open(&state, 4096)?);
    let sink = Arc::new(CountingSink(AtomicU64::new(0)));
    let walker = Walker::new(cfg.clone(), Arc::clone(&cache), sink.clone());
    walker.begin_full_sweep();

    let mut clock = 0u64;
    let mut steps = 0usize;
    let mut interrupted = false;
    loop {
        clock += 10;
        match walker.step(clock) {
            StepStatus::Completed => break,
            StepStatus::Idle | StepStatus::Inert => break,
            _ => {}
        }
        steps += 1;
        if resume_after > 0 && walker.counts().dirs as usize >= resume_after {
            interrupted = true;
            break;
        }
    }

    if interrupted {
        assert!(walker.checkpoint_now(), "a running sweep must checkpoint");
        let first = walker.counts();
        let q = walker.pending_dirs();
        println!("--- interrupted after {} directories ---", first.dirs);
        println!(
            "queue now        : {} waiting ({} in memory, {} in the sidecar)",
            q.total, q.in_memory, q.on_disk
        );
        println!("queue high-water : {} entries", q.high_water);
        println!("spilled to disk  : {} entries", q.spilled);

        let cp = load_checkpoint(&state).expect("a checkpoint must be on disk");
        if cp.pending_truncated {
            println!("checkpoint       : QUEUE NOT PERSISTED — a restart re-walks the scope");
        } else {
            println!(
                "checkpoint       : {} queued ({} in memory, {} in the sidecar)",
                cp.pending_dirs.len() as u64 + cp.spill.count,
                cp.pending_dirs.len(),
                cp.spill.count
            );
        }
        drop(walker);

        // The agent restart.
        println!("--- restarting over the same state directory ---");
        let walker = Walker::new(cfg, cache, sink.clone());
        walker.begin_full_sweep();
        let carried = walker.counts().dirs;
        println!(
            "resumed at       : {carried} directories already listed {}",
            if carried >= first.dirs {
                "(progress kept)"
            } else {
                "(PROGRESS LOST)"
            }
        );
        loop {
            clock += 10;
            match walker.step(clock) {
                StepStatus::Completed | StepStatus::Idle | StepStatus::Inert => break,
                _ => {}
            }
            steps += 1;
        }
        report(&walker, started, steps, first.dirs, cfg_cap);
    } else {
        report(&walker, started, steps, 0, cfg_cap);
    }

    let _ = std::fs::remove_dir_all(&state);
    Ok(())
}

fn report(
    walker: &Walker,
    started: std::time::Instant,
    steps: usize,
    before_restart: u64,
    cap: u64,
) {
    let c = walker.counts();
    let s = walker.stats().snapshot();
    println!();
    println!("--- sweep finished in {:.1?} ---", started.elapsed());
    println!("steps            : {steps}");
    println!(
        "directories      : {} this run{}",
        c.dirs,
        if before_restart > 0 {
            format!(" (of which {before_restart} were before the restart)")
        } else {
            String::new()
        }
    );
    println!("queue high-water : {} entries", s.dirs_pending_max);
    println!("spilled to disk  : {} entries", s.dirs_spilled);
    println!(
        "queue memory     : ~{:.2} MB held at peak (vs ~{:.2} MB with no cap)",
        (s.dirs_pending_max.min(cap) as f64 * 170.0) / (1024.0 * 1024.0),
        (s.dirs_pending_max as f64 * 170.0) / (1024.0 * 1024.0)
    );
    println!("checkpoints      : {}", s.checkpoints);
    println!("errors           : {} unreadable", c.errors);
}
