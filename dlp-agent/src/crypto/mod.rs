//! Trusted-destination encryption — the pure crypto core (milestone M1 of
//! ENCRYPT-ON-WRITE-IMPLEMENTATION.md).
//!
//! Two submodules, both pure computation (no file/network I/O on the hot path,
//! no `#[cfg(windows)]` — the whole module builds and tests cross-platform):
//!
//! * [`envelope`] — the `.dlpenc` wire format (spec §4): `DLPE` magic,
//!   version `0x01`, canonical-JSON header, AES-256-GCM body with the entire
//!   prefix as AAD. `seal` / `open` / `peek_header` over byte slices, one
//!   typed [`envelope::EnvelopeError`] — callers can distinguish
//!   wrong-key / tampered / malformed / key-destroyed (no `anyhow` here).
//! * [`keyring`] — [`keyring::Kek`] (32 bytes, zeroized on drop) and
//!   [`keyring::Keyring`] (`HashMap<key id, Kek>` + active key id + destroyed
//!   set). Key ids are FREE-FORM strings — never parsed anywhere, only used
//!   as opaque map keys (project decision overriding spec ambiguity).
//!
//! Security invariants enforced here:
//! * Fresh random 256-bit DEK per file, wrapped by the KEK (AES-256-GCM with
//!   its own nonce). DEKs and KEKs are zeroized on drop.
//! * RNG is injected behind [`envelope::EnvelopeRng`] (OS CSPRNG in
//!   production, scripted bytes in golden-vector tests); the clock is the
//!   `now_unix` parameter — house style, and it keeps golden vectors
//!   deterministic.
//! * Decrypt is offline-capable: `open` needs only the locally cached
//!   [`keyring::Keyring`], never a server round-trip (project decision).
//! * Key destruction is terminal (crypto-shredding): a destroyed id can never
//!   be re-inserted; opens against it fail `KeyDestroyed`, distinct from
//!   `UnknownKeyId` — a foreign/old stick is signal, not noise.
//! * No key material, plaintext, or file content ever appears in `Debug`
//!   output, errors, or logs (house rule 2).
//!
//! Persistence of the keyring at rest (DPAPI machine scope) is milestone M4,
//! NOT this module — only the dev keyfile loader lives in [`keyring`].

pub mod envelope;
pub mod keyring;

pub use envelope::{
    open, peek_header, seal, seal_with_rng, EnvelopeError, EnvelopeHeader, EnvelopeRng,
    OsEnvelopeRng,
};
pub use keyring::{Kek, Keyring, KeyringError};
