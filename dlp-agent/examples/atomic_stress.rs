//! Power-cut harness for `dlp_agent::atomicfile` — NOT shipped, test tooling.
//!
//! `atomic_stress write <dir> <mode>` loops forever replacing `<dir>\state.bin`
//! with a self-describing record: an 8-byte sequence number, 64 KiB of payload
//! derived from it, and a SHA-256 of both. Hard power the machine off while it
//! runs, boot, and run `atomic_stress check <dir>`: the record must exist and
//! verify. `mode` is `atomic` (the agent's helper) or `legacy` (the old
//! remove-then-rename with no flush), so the two can be compared on the same box.
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

const PAYLOAD: usize = 64 * 1024;

fn record(seq: u64) -> Vec<u8> {
    let mut v = seq.to_le_bytes().to_vec();
    v.extend((0..PAYLOAD).map(|i| (seq as usize).wrapping_add(i) as u8));
    let digest = Sha256::digest(&v);
    v.extend_from_slice(&digest);
    v
}

fn legacy_write(dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let tmp = dest.with_extension("bin.tmp");
    std::fs::write(&tmp, bytes)?;
    if dest.exists() {
        std::fs::remove_file(dest)?;
    }
    std::fs::rename(&tmp, dest)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = PathBuf::from(args.get(2).expect("usage: atomic_stress <write|check> <dir> [atomic|legacy]"));
    let dest = dir.join("state.bin");
    match args[1].as_str() {
        "write" => {
            std::fs::create_dir_all(&dir).unwrap();
            let legacy = args.get(3).map(|m| m == "legacy").unwrap_or(false);
            let mut seq = 0u64;
            loop {
                seq += 1;
                let r = record(seq);
                let res = if legacy { legacy_write(&dest, &r) } else { dlp_agent::atomicfile::write_atomic(&dest, &r) };
                if let Err(e) = res {
                    eprintln!("write {seq} failed: {e}");
                }
                if seq % 500 == 0 {
                    println!("seq {seq}");
                }
            }
        }
        "check" => match std::fs::read(&dest) {
            Err(e) => println!("RESULT MISSING ({e})"),
            Ok(b) if b.len() != 8 + PAYLOAD + 32 => println!("RESULT TORN (length {} of {})", b.len(), 8 + PAYLOAD + 32),
            Ok(b) => {
                let (body, digest) = b.split_at(8 + PAYLOAD);
                let seq = u64::from_le_bytes(body[..8].try_into().unwrap());
                if Sha256::digest(body).as_slice() == digest {
                    println!("RESULT VALID seq={seq}");
                } else {
                    println!("RESULT CORRUPT (checksum mismatch, claims seq={seq})");
                }
            }
        },
        other => panic!("unknown mode {other}"),
    }
}
