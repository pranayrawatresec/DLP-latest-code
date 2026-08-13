//! Trusted-destination encryption — PURE decision logic (encrypt-on-write
//! spec §3.1). No I/O, no OS calls, no state.
//!
//! A **trusted destination** (whitelisted USB stick, webmail origin, …) does
//! not get a policy hole — data flowing to it is *sealed* into a `.dlpenc`
//! envelope instead of blocked. This module owns the single pure decision:
//! given the destination's encrypt mode, the channel's verdict-band thresholds,
//! and (optionally) a detection verdict, should ONE settled file pass in
//! plaintext, be sealed, or be blocked?
//!
//! Thresholds live HERE in the channel layer — `detect/` is frozen and
//! audit-only by contract; it reports scores, channels apply bands.
//!
//! Fail-secure rows (spec §3.1, non-negotiable):
//! * `EncryptAll` ⇒ always `Seal`, verdict or no verdict (courier-stick mode).
//! * `EncryptSensitive` with NO verdict available (no bundle) ⇒ `Seal`.
//! * `EncryptSensitive` with `Extraction::Unreadable` ⇒ `Seal` (the
//!   "pre-encrypted file" blind spot is sealed, not waved through).
//! * The block band still blocks BY DEFAULT — whitelisting a destination must
//!   never silently weaken the block threshold (spec §10). A destination rule
//!   may OPT IN to sealing the block band instead (`on_block_band = "seal"`,
//!   [`BlockBandPolicy::Seal`]): the file still never leaves in plaintext, it
//!   leaves armoured. That trade (owner decision, 2026-08-12) is explicit
//!   per-rule config, never a default.

use serde::Deserialize;

use crate::detect::{Extraction, Verdict};

/// How much gets sealed on a trusted destination (spec §1).
///
/// Deserializes from the snake_case strings used in TOML rule fields
/// (`encrypt_sensitive` | `encrypt_all`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptMode {
    /// Files whose verdict scores in the sensitive band are sealed; clean
    /// files pass in plaintext. Unreadable/no-bundle ⇒ sealed (fail secure).
    EncryptSensitive,
    /// EVERY file written to this destination is sealed, no verdict needed
    /// (courier-stick mode; also covers files detection can't read).
    EncryptAll,
}

/// Verdict band thresholds for `EncryptSensitive` (channel-owned — detect
/// stays audit-only). `block_at` / `coverage_block_at` mirror `[kguard]` (one
/// source of truth: `Config::encrypt_bands()` copies them from there); the
/// encrypt band sits UNDER the block band:
///
/// ```text
/// containment >= block_at, or coverage >= coverage_block_at → Block (unchanged)
/// encrypt_at <= containment < block band, or any EDM hit,
///   or Unreadable                                           → Seal
/// else                                                      → Plain
/// ```
#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(default)]
pub struct EncryptBands {
    /// Lower edge of the seal band. Default 0.05.
    pub encrypt_at: f64,
    /// Containment at or above this blocks (mirrors `[kguard] block_at`). 0.30.
    pub block_at: f64,
    /// Coverage at or above this blocks (mirrors `[kguard] coverage_block_at`). 0.60.
    pub coverage_block_at: f64,
}

impl Default for EncryptBands {
    fn default() -> Self {
        EncryptBands { encrypt_at: 0.05, block_at: 0.30, coverage_block_at: 0.60 }
    }
}

/// What an `encrypt_sensitive` destination does with a file whose verdict
/// reaches the BLOCK band (containment ≥ `block_at` or coverage ≥
/// `coverage_block_at`). TOML rule field `on_block_band`.
///
/// `Block` is the spec §10 default: whitelisting never weakens the block
/// threshold. `Seal` is the explicit per-rule opt-in (owner decision,
/// 2026-08-12): "sensitive to a whitelisted drive ⇒ encrypted, not blocked" —
/// the data still never lands in plaintext, and the incident records the full
/// verdict either way. Irrelevant to `encrypt_all` (everything is sealed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BlockBandPolicy {
    /// Keep the existing block/quarantine path (spec default).
    #[default]
    Block,
    /// Seal block-band files like the rest of the sensitive band.
    Seal,
}

/// What to do with ONE settled file on an `Action::Encrypt` destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SealDecision {
    /// Clean file — pass in plaintext (audit as today).
    Plain,
    /// Seal into a `.dlpenc` envelope on the destination.
    Seal,
    /// Block band reached — keep the existing block/quarantine path.
    /// Whitelisting must never raise the leak ceiling.
    Block,
}

/// Pure decision for one settled file on an Encrypt destination (spec §3.1).
///
/// `verdict` is `None` when no verdict could be produced at all (no verified
/// bundle cached, scan I/O failure) — which on an `encrypt_sensitive`
/// destination fails secure to `Seal`. `EncryptAll` never even looks at the
/// verdict: everything is sealed.
pub fn decide_seal(
    mode: EncryptMode,
    bands: &EncryptBands,
    on_block_band: BlockBandPolicy,
    verdict: Option<&Verdict>,
) -> SealDecision {
    match mode {
        // Courier-stick mode: always seal — no verdict, no bundle required.
        EncryptMode::EncryptAll => SealDecision::Seal,
        EncryptMode::EncryptSensitive => {
            let v = match verdict {
                // No bundle / no verdict available ⇒ fail secure: seal.
                None => return SealDecision::Seal,
                Some(v) => v,
            };
            // Unreadable content (encrypted zip, unknown format) ⇒ treat as
            // sensitive: seal (fail secure; closes the pre-encrypted blind spot).
            if matches!(v.extraction, Extraction::Unreadable { .. }) {
                return SealDecision::Seal;
            }
            // Block band FIRST. Default: block — whitelisting never silently
            // weakens the block threshold (spec §10). `on_block_band = "seal"`
            // is the rule's explicit opt-in to armour instead of block; either
            // way the plaintext never stays on the destination. Thresholds
            // mirror the kguard channel: containment OR coverage.
            if v.idm
                .iter()
                .any(|m| m.containment >= bands.block_at || m.coverage >= bands.coverage_block_at)
            {
                return match on_block_band {
                    BlockBandPolicy::Block => SealDecision::Block,
                    BlockBandPolicy::Seal => SealDecision::Seal,
                };
            }
            // Any EDM hit, or containment in the encrypt band ⇒ seal.
            if !v.edm.is_empty() {
                return SealDecision::Seal;
            }
            if v.idm.iter().any(|m| m.containment >= bands.encrypt_at) {
                return SealDecision::Seal;
            }
            SealDecision::Plain
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::detect::edm::{EdmRowHit, EdmSourceHit};
    use crate::detect::{IdmMatch, Verdict};

    /// A verdict with one IDM match at the given containment/coverage.
    fn verdict_idm(containment: f64, coverage: f64) -> Verdict {
        Verdict {
            file_name: "f.txt".into(),
            file_sha256: "00".repeat(32),
            extraction: Extraction::Ok { format: "txt".into() },
            idm: vec![IdmMatch {
                version_id: "v1".into(),
                document_id: "d1".into(),
                collection_id: "c1".into(),
                title: "doc".into(),
                containment,
                coverage,
                matched_count: 1,
                total_count: 10,
                matched_hashes: vec![],
            }],
            edm: vec![],
        }
    }

    /// A clean verdict: readable, no IDM, no EDM.
    fn verdict_clean() -> Verdict {
        Verdict {
            file_name: "f.txt".into(),
            file_sha256: "00".repeat(32),
            extraction: Extraction::Ok { format: "txt".into() },
            idm: vec![],
            edm: vec![],
        }
    }

    fn verdict_unreadable() -> Verdict {
        Verdict {
            file_name: "f.zip".into(),
            file_sha256: "00".repeat(32),
            extraction: Extraction::Unreadable { reason: "encrypted-zip".into() },
            idm: vec![],
            edm: vec![],
        }
    }

    fn with_edm(mut v: Verdict) -> Verdict {
        v.edm = vec![EdmSourceHit {
            source_id: "s1".into(),
            name: "personnel".into(),
            rows_hit: vec![EdmRowHit { row_id: 1, fields: vec!["nid".into(), "name".into()] }],
        }];
        v
    }

    /// The FULL decision table from spec §3.1, one row per case — including
    /// every fail-secure row. Bands: encrypt_at 0.05, block_at 0.30,
    /// coverage_block_at 0.60 (the defaults).
    #[test]
    fn decision_table() {
        use EncryptMode::{EncryptAll, EncryptSensitive};
        use SealDecision::{Block, Plain, Seal};
        let bands = EncryptBands::default();

        // (name, mode, verdict, expected)
        let table: Vec<(&str, EncryptMode, Option<Verdict>, SealDecision)> = vec![
            // --- encrypt_all: ALWAYS seal, verdict irrelevant ---------------
            ("all/no-verdict (no bundle needed)", EncryptAll, None, Seal),
            ("all/clean", EncryptAll, Some(verdict_clean()), Seal),
            ("all/unreadable", EncryptAll, Some(verdict_unreadable()), Seal),
            ("all/block-band still sealed", EncryptAll, Some(verdict_idm(0.9, 0.9)), Seal),
            ("all/edm hit", EncryptAll, Some(with_edm(verdict_clean())), Seal),
            // --- encrypt_sensitive: fail-secure rows ------------------------
            ("sens/no-verdict (no bundle) => seal", EncryptSensitive, None, Seal),
            ("sens/unreadable => seal", EncryptSensitive, Some(verdict_unreadable()), Seal),
            // --- encrypt_sensitive: block band (never weakened) -------------
            ("sens/containment at block_at", EncryptSensitive, Some(verdict_idm(0.30, 0.0)), Block),
            ("sens/containment above block_at", EncryptSensitive, Some(verdict_idm(0.75, 0.0)), Block),
            ("sens/coverage at coverage_block_at", EncryptSensitive, Some(verdict_idm(0.0, 0.60)), Block),
            ("sens/coverage above coverage_block_at", EncryptSensitive, Some(verdict_idm(0.10, 0.95)), Block),
            ("sens/block band beats edm hit", EncryptSensitive, Some(with_edm(verdict_idm(0.5, 0.0))), Block),
            // --- encrypt_sensitive: seal band -------------------------------
            ("sens/containment at encrypt_at", EncryptSensitive, Some(verdict_idm(0.05, 0.0)), Seal),
            ("sens/containment inside seal band", EncryptSensitive, Some(verdict_idm(0.20, 0.0)), Seal),
            (
                "sens/containment just under block_at",
                EncryptSensitive,
                Some(verdict_idm(0.29999, 0.0)),
                Seal,
            ),
            ("sens/edm hit alone => seal", EncryptSensitive, Some(with_edm(verdict_clean())), Seal),
            (
                "sens/edm hit with sub-band idm => seal",
                EncryptSensitive,
                Some(with_edm(verdict_idm(0.01, 0.0))),
                Seal,
            ),
            // --- encrypt_sensitive: plain -----------------------------------
            ("sens/clean => plain", EncryptSensitive, Some(verdict_clean()), Plain),
            (
                "sens/containment just under encrypt_at => plain",
                EncryptSensitive,
                Some(verdict_idm(0.04999, 0.0)),
                Plain,
            ),
        ];

        for (name, mode, verdict, expected) in &table {
            let got = decide_seal(*mode, &bands, BlockBandPolicy::default(), verdict.as_ref());
            assert_eq!(got, *expected, "row failed: {name}");
        }
    }

    /// `on_block_band = "seal"` (owner opt-in): block-band files are sealed
    /// instead of blocked; every other row of the table is unchanged.
    #[test]
    fn seal_block_band_opt_in() {
        use BlockBandPolicy::Seal as SealBand;
        use EncryptMode::EncryptSensitive as Sens;
        use SealDecision::{Plain, Seal};
        let bands = EncryptBands::default();

        // The four block-band rows now seal.
        assert_eq!(decide_seal(Sens, &bands, SealBand, Some(&verdict_idm(0.30, 0.0))), Seal);
        assert_eq!(decide_seal(Sens, &bands, SealBand, Some(&verdict_idm(1.0, 1.0))), Seal);
        assert_eq!(decide_seal(Sens, &bands, SealBand, Some(&verdict_idm(0.0, 0.60))), Seal);
        assert_eq!(
            decide_seal(Sens, &bands, SealBand, Some(&with_edm(verdict_idm(0.5, 0.0)))),
            Seal
        );
        // Non-block rows are untouched by the policy.
        assert_eq!(decide_seal(Sens, &bands, SealBand, Some(&verdict_clean())), Plain);
        assert_eq!(decide_seal(Sens, &bands, SealBand, Some(&verdict_idm(0.20, 0.0))), Seal);
        assert_eq!(decide_seal(Sens, &bands, SealBand, None), Seal);
    }

    #[test]
    fn block_band_policy_deserializes_and_defaults_to_block() {
        #[derive(Deserialize)]
        struct T {
            #[serde(default)]
            on_block_band: BlockBandPolicy,
        }
        let t: T = toml::from_str("").unwrap();
        assert_eq!(t.on_block_band, BlockBandPolicy::Block, "default must stay the spec's Block");
        let t: T = toml::from_str(r#"on_block_band = "seal""#).unwrap();
        assert_eq!(t.on_block_band, BlockBandPolicy::Seal);
        assert!(toml::from_str::<T>(r#"on_block_band = "allow""#).is_err());
    }

    #[test]
    fn default_bands_match_the_spec() {
        let b = EncryptBands::default();
        assert_eq!(b.encrypt_at, 0.05);
        assert_eq!(b.block_at, 0.30);
        assert_eq!(b.coverage_block_at, 0.60);
    }

    #[test]
    fn custom_bands_are_honoured() {
        // A site raising encrypt_at narrows the seal band; the block band moves
        // with it independently.
        let bands = EncryptBands { encrypt_at: 0.10, block_at: 0.50, coverage_block_at: 0.80 };
        let sens = EncryptMode::EncryptSensitive;
        let d = BlockBandPolicy::default();
        assert_eq!(decide_seal(sens, &bands, d, Some(&verdict_idm(0.05, 0.0))), SealDecision::Plain);
        assert_eq!(decide_seal(sens, &bands, d, Some(&verdict_idm(0.10, 0.0))), SealDecision::Seal);
        assert_eq!(decide_seal(sens, &bands, d, Some(&verdict_idm(0.49, 0.0))), SealDecision::Seal);
        assert_eq!(decide_seal(sens, &bands, d, Some(&verdict_idm(0.50, 0.0))), SealDecision::Block);
        assert_eq!(decide_seal(sens, &bands, d, Some(&verdict_idm(0.0, 0.80))), SealDecision::Block);
    }

    #[test]
    fn encrypt_mode_deserializes_from_snake_case() {
        #[derive(Deserialize)]
        struct T {
            mode: EncryptMode,
        }
        let t: T = toml::from_str(r#"mode = "encrypt_all""#).unwrap();
        assert_eq!(t.mode, EncryptMode::EncryptAll);
        let t: T = toml::from_str(r#"mode = "encrypt_sensitive""#).unwrap();
        assert_eq!(t.mode, EncryptMode::EncryptSensitive);
        assert!(toml::from_str::<T>(r#"mode = "plaintext""#).is_err(), "unknown mode must be rejected");
    }
}
