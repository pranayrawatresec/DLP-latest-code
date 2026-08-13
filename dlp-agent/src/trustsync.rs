//! Trusted-destination + key sync (encrypt-on-write spec §6, milestone M6).
//!
//! The management server, over the agent's mTLS identity, delivers the
//! admin-authored trusted-destination whitelist AND the encryption KEKs the
//! agent needs to seal/open files on those destinations
//! (`GET /agent/trusted-config`). This module owns the **pure** half of that
//! contract:
//!
//! * the serde types mirroring the PINNED M6 wire contract
//!   ([`TrustedConfig`] / [`SyncedDestination`] / [`SyncedKey`]), and
//! * [`merge_into_usb`] — a PURE fold of the synced destinations into the
//!   effective `[usb]` config, so `usb-monitor` / `usb-guard` whitelist + seal
//!   exactly what the console set, with NO local `[usb]`/`[crypto]` config
//!   required.
//!
//! The NETWORK half — the mTLS GET, and persisting the keyring + destinations
//! at rest — lives in `checkin.rs` (it needs the binary-only `client` module
//! and `storage`). Keeping this module pure and cross-platform means the merge
//! and the wire parsing are unit-tested without a live server.
//!
//! House rule 2: this module handles key **ids** freely (they are opaque map
//! keys and audit values), but the raw KEK bytes carried in
//! [`SyncedKey::key_b64`] are NEVER logged and NEVER written to the destinations
//! file — they travel only into the DPAPI-sealed keyring at rest
//! ([`TrustedConfig::to_keyring_json`] → `storage::store_keyring`).

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::config::{UsbConfig, UsbRule};
use crate::trustdest::{BlockBandPolicy, EncryptMode};
use crate::usb::Action;

/// How a synced destination selects a device — mirrors the PINNED contract's
/// `matcher`: `{"serial":"<s>"}` OR `{"vid":"hhhh","pid":"hhhh"}`. Untagged so
/// the shape of the JSON object picks the variant.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SyncedMatcher {
    Serial { serial: String },
    VidPid { vid: String, pid: String },
}

/// One admin-authored trusted destination delivered by the server (M6 contract).
/// Metadata only — carries a key **id**, never key material.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct SyncedDestination {
    /// Channel this destination applies to (e.g. `"usb"`). Non-`usb` channels
    /// are ignored by [`merge_into_usb`] (they belong to other channels' merges).
    pub channel: String,
    pub matcher: SyncedMatcher,
    /// How much gets sealed (`encrypt_sensitive` | `encrypt_all`).
    pub mode: EncryptMode,
    /// FREE-FORM opaque KEK id — never parsed, only handed to the sealer/keyring.
    #[serde(rename = "keyId")]
    pub key_id: String,
    /// Block-band disposition for `encrypt_sensitive` (`block` | `seal`). Absent
    /// ⇒ the spec default `block` (whitelisting never weakens the block band).
    #[serde(rename = "onBlockBand", default)]
    pub on_block_band: BlockBandPolicy,
}

/// One delivered KEK: opaque id + base64 of the 32-byte UNWRAPPED key. The
/// base64 is raw key material — never logged, never persisted outside the
/// DPAPI-sealed keyring.
#[derive(Clone, Deserialize)]
pub struct SyncedKey {
    pub id: String,
    #[serde(rename = "keyB64")]
    pub key_b64: String,
}

impl std::fmt::Debug for SyncedKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // House rule 2: never print key material.
        f.debug_struct("SyncedKey")
            .field("id", &self.id)
            .field("key_b64", &"<redacted>")
            .finish()
    }
}

/// The full `GET /agent/trusted-config` payload (PINNED M6 contract).
#[derive(Debug, Deserialize)]
pub struct TrustedConfig {
    #[serde(default)]
    pub destinations: Vec<SyncedDestination>,
    #[serde(default)]
    pub keys: Vec<SyncedKey>,
}

impl TrustedConfig {
    /// The id new seals should use: prefer a key that some destination
    /// references (so new seals use the whitelist's key), else the first
    /// delivered key. `None` when the sync carried no keys.
    pub fn active_key_id(&self) -> Option<String> {
        for k in &self.keys {
            if self.destinations.iter().any(|d| d.key_id == k.id) {
                return Some(k.id.clone());
            }
        }
        self.keys.first().map(|k| k.id.clone())
    }

    /// Build the DPAPI-at-rest keyring JSON: the same dev-keyfile shape that
    /// `storage::store_keyring` seals and `crypto::Keyring::from_dev_json`
    /// parses — `{ "activeKeyId": <id>, "keys": { id: base64 } }`. Wrapped in
    /// [`Zeroizing`] because it carries raw KEK material. `None` when the sync
    /// delivered no keys (the caller keeps the last sealed keyring at rest).
    /// NEVER logged.
    pub fn to_keyring_json(&self) -> Option<Zeroizing<Vec<u8>>> {
        let active = self.active_key_id()?;
        let mut keys = serde_json::Map::with_capacity(self.keys.len());
        for k in &self.keys {
            keys.insert(k.id.clone(), serde_json::Value::String(k.key_b64.clone()));
        }
        let doc = serde_json::json!({
            "activeKeyId": active,
            "keys": serde_json::Value::Object(keys),
        });
        serde_json::to_vec(&doc).ok().map(Zeroizing::new)
    }
}

/// Merge the synced trusted destinations into the effective `[usb]` config
/// (encrypt-on-write M6). PURE — returns a clone of `cfg_usb` with the `usb`
/// destinations **prepended** as `Action::Encrypt` rules so first-match-wins
/// gives the console-authored whitelist precedence, and `enabled` flipped on
/// whenever any `usb` destination exists.
///
/// Precedence + safety: on the SAME device (matcher equality), the
/// more-restrictive of (synced `Encrypt`, local action) wins via
/// [`Action::max_restrictive`] — a device the admin both whitelisted-for-encrypt
/// AND locally restricted (read-only/block) is NOT weakened to `Encrypt`. An
/// empty destination list returns `cfg_usb` unchanged.
pub fn merge_into_usb(cfg_usb: &UsbConfig, dests: &[SyncedDestination]) -> UsbConfig {
    // Only `usb`-channel destinations concern this merge.
    let usb_dests: Vec<&SyncedDestination> =
        dests.iter().filter(|d| d.channel == "usb").collect();
    if usb_dests.is_empty() {
        return cfg_usb.clone();
    }

    let mut synced: Vec<UsbRule> = Vec::with_capacity(usb_dests.len());
    for d in &usb_dests {
        let action = match local_action_for(cfg_usb, &d.matcher) {
            Some(local) => Action::Encrypt.max_restrictive(local),
            None => Action::Encrypt,
        };
        synced.push(d.to_usb_rule(action));
    }

    let mut merged = cfg_usb.clone();
    // Synced rules FIRST (precedence), then the operator's local rules.
    synced.extend(merged.rules.iter().cloned());
    merged.rules = synced;
    merged.enabled = true;
    merged
}

impl SyncedDestination {
    /// Build the prepended `[[usb.rules]]` entry for this destination. `action`
    /// is the already-resolved effective action (Encrypt, or the more
    /// restrictive local action on the same device).
    fn to_usb_rule(&self, action: Action) -> UsbRule {
        let (match_serial, match_vid, match_pid) = match &self.matcher {
            SyncedMatcher::Serial { serial } => (Some(serial.clone()), None, None),
            SyncedMatcher::VidPid { vid, pid } => (None, Some(vid.clone()), Some(pid.clone())),
        };
        UsbRule {
            match_serial,
            match_vid,
            match_pid,
            match_bus_type: None,
            match_any: false,
            action,
            note: Some("synced trusted destination".into()),
            mode: Some(self.mode),
            // Empty id ⇒ None so the use-site substitutes [crypto] default_key_id.
            key_id: if self.key_id.is_empty() { None } else { Some(self.key_id.clone()) },
            on_block_band: self.on_block_band,
        }
    }
}

/// The action of the FIRST local rule that targets the same device as `matcher`
/// (case-insensitive, trimmed), or `None` when no local rule matches it.
fn local_action_for(cfg_usb: &UsbConfig, matcher: &SyncedMatcher) -> Option<Action> {
    cfg_usb
        .rules
        .iter()
        .find(|r| same_device(matcher, r))
        .map(|r| r.action)
}

/// Whether a synced matcher and a local `[[usb.rules]]` entry target the same
/// device (matcher equality; case-insensitive + trimmed, mirroring
/// `RuleMatch::matches`).
fn same_device(matcher: &SyncedMatcher, rule: &UsbRule) -> bool {
    match matcher {
        SyncedMatcher::Serial { serial } => rule
            .match_serial
            .as_deref()
            .map(|s| s.trim().eq_ignore_ascii_case(serial.trim()))
            .unwrap_or(false),
        SyncedMatcher::VidPid { vid, pid } => {
            let v = rule
                .match_vid
                .as_deref()
                .map(|s| s.trim().eq_ignore_ascii_case(vid.trim()))
                .unwrap_or(false);
            let p = rule
                .match_pid
                .as_deref()
                .map(|s| s.trim().eq_ignore_ascii_case(pid.trim()))
                .unwrap_or(false);
            v && p
        }
    }
}

// ---------------------------------------------------------------------------
// Persisted trusted-destinations file (metadata only — key IDS yes, key BYTES
// never). Small self-describing JSON: `{ "destinations": [ … ] }`.
// ---------------------------------------------------------------------------

/// Serialize the synced destinations for the at-rest `trusted-destinations.json`
/// (channel / matcher / mode / key IDS / block-band). Contains NO key material.
/// Round-trips with [`parse_destinations`].
pub fn serialize_destinations(dests: &[SyncedDestination]) -> Vec<u8> {
    let arr: Vec<serde_json::Value> = dests.iter().map(dest_to_value).collect();
    let doc = serde_json::json!({ "destinations": arr });
    serde_json::to_vec(&doc).unwrap_or_else(|_| br#"{"destinations":[]}"#.to_vec())
}

/// Parse the persisted `trusted-destinations.json` back into destinations.
pub fn parse_destinations(bytes: &[u8]) -> Result<Vec<SyncedDestination>, serde_json::Error> {
    #[derive(Deserialize)]
    struct PersistedFile {
        #[serde(default)]
        destinations: Vec<SyncedDestination>,
    }
    let pf: PersistedFile = serde_json::from_slice(bytes)?;
    Ok(pf.destinations)
}

fn dest_to_value(d: &SyncedDestination) -> serde_json::Value {
    let matcher = serde_json::to_value(&d.matcher).unwrap_or(serde_json::Value::Null);
    serde_json::json!({
        "channel": d.channel,
        "matcher": matcher,
        "mode": mode_str(d.mode),
        "keyId": d.key_id,
        "onBlockBand": band_str(d.on_block_band),
    })
}

fn mode_str(m: EncryptMode) -> &'static str {
    match m {
        EncryptMode::EncryptSensitive => "encrypt_sensitive",
        EncryptMode::EncryptAll => "encrypt_all",
    }
}

fn band_str(b: BlockBandPolicy) -> &'static str {
    match b {
        BlockBandPolicy::Block => "block",
        BlockBandPolicy::Seal => "seal",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::usb::device::DeviceIdentity;
    use crate::usb::policy::{decide, RuleMatch};

    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    fn dev(serial: &str, vid: &str, pid: &str) -> DeviceIdentity {
        DeviceIdentity {
            drive_letter: "E:".into(),
            vendor_id: vid.into(),
            product_id: pid.into(),
            serial: serial.into(),
            product_name: format!("{vid} {pid}"),
            bus_type: "usb".into(),
            removable: true,
        }
    }

    fn serial_dest(serial: &str, mode: EncryptMode, key: &str) -> SyncedDestination {
        SyncedDestination {
            channel: "usb".into(),
            matcher: SyncedMatcher::Serial { serial: serial.into() },
            mode,
            key_id: key.into(),
            on_block_band: BlockBandPolicy::Block,
        }
    }

    // --- merge: serial destination ----------------------------------------

    #[test]
    fn merge_prepends_serial_destination_and_enables() {
        let base = UsbConfig::default(); // enabled=false, no rules
        assert!(!base.enabled);
        let dests = vec![serial_dest("COURIER", EncryptMode::EncryptAll, "class-courier/v1")];
        let merged = merge_into_usb(&base, &dests);

        assert!(merged.enabled, "any destination flips the channel on");
        assert_eq!(merged.rules.len(), 1);
        let r = &merged.rules[0];
        assert_eq!(r.action, Action::Encrypt);
        assert_eq!(r.match_serial.as_deref(), Some("COURIER"));
        assert_eq!(r.mode, Some(EncryptMode::EncryptAll));
        assert_eq!(r.key_id.as_deref(), Some("class-courier/v1"));

        // The rule engine now whitelists the stick as an Encrypt destination.
        let policy = merged.to_policy();
        assert_eq!(decide(&policy, &dev("courier", "v", "p")).0, Action::Encrypt);
        // encrypt_params resolves the synced mode + key id.
        let (mode, key, _band) = merged.encrypt_params(&dev("courier", "v", "p"));
        assert_eq!(mode, EncryptMode::EncryptAll);
        assert_eq!(key.as_deref(), Some("class-courier/v1"));
    }

    // --- merge: vid/pid destination ---------------------------------------

    #[test]
    fn merge_prepends_vidpid_destination() {
        let base = UsbConfig::default();
        let dests = vec![SyncedDestination {
            channel: "usb".into(),
            matcher: SyncedMatcher::VidPid { vid: "0951".into(), pid: "1666".into() },
            mode: EncryptMode::EncryptSensitive,
            key_id: "class-internal/v1".into(),
            on_block_band: BlockBandPolicy::Seal,
        }];
        let merged = merge_into_usb(&base, &dests);
        let r = &merged.rules[0];
        assert_eq!(r.match_vid.as_deref(), Some("0951"));
        assert_eq!(r.match_pid.as_deref(), Some("1666"));
        assert!(r.match_serial.is_none());
        assert_eq!(r.on_block_band, BlockBandPolicy::Seal);
        assert_eq!(decide(&merged.to_policy(), &dev("s", "0951", "1666")).0, Action::Encrypt);
    }

    // --- merge: precedence (synced first) ---------------------------------

    #[test]
    fn synced_rules_take_precedence_via_first_match() {
        // Local Any→ReadOnly catch-all; a synced Encrypt for a specific serial
        // must win for that serial (prepended), while other devices still hit
        // the local catch-all.
        let mut base = UsbConfig::default();
        base.rules = vec![UsbRule {
            match_serial: None,
            match_vid: None,
            match_pid: None,
            match_bus_type: None,
            match_any: true,
            action: Action::ReadOnly,
            note: Some("local catch-all".into()),
            mode: None,
            key_id: None,
            on_block_band: BlockBandPolicy::Block,
        }];
        let dests = vec![serial_dest("COURIER", EncryptMode::EncryptAll, "k")];
        let merged = merge_into_usb(&base, &dests);
        assert_eq!(merged.rules.len(), 2);
        let policy = merged.to_policy();
        // Whitelisted stick → Encrypt (synced rule first).
        assert_eq!(decide(&policy, &dev("courier", "v", "p")).0, Action::Encrypt);
        // Any other device → local catch-all ReadOnly.
        let (action, matched) = decide(&policy, &dev("other", "v", "p"));
        assert_eq!(action, Action::ReadOnly);
        assert_eq!(matched.map(|r| &r.match_on), Some(&RuleMatch::Any));
    }

    // --- merge: more-restrictive-wins on the same device -------------------

    #[test]
    fn more_restrictive_local_wins_on_same_device() {
        // The admin locally BLOCKED this exact serial AND (mistakenly) added it
        // as an encrypt destination. Block (more restrictive) must win — the
        // prepended rule carries Block, not Encrypt.
        let mut base = UsbConfig::default();
        base.rules = vec![UsbRule {
            match_serial: Some("courier".into()),
            match_vid: None,
            match_pid: None,
            match_bus_type: None,
            match_any: false,
            action: Action::Block,
            note: Some("locally blocked".into()),
            mode: None,
            key_id: None,
            on_block_band: BlockBandPolicy::Block,
        }];
        let dests = vec![serial_dest("COURIER", EncryptMode::EncryptAll, "k")];
        let merged = merge_into_usb(&base, &dests);
        // The prepended synced rule was raised to Block (max_restrictive).
        assert_eq!(merged.rules[0].action, Action::Block);
        assert_eq!(decide(&merged.to_policy(), &dev("courier", "v", "p")).0, Action::Block);
    }

    #[test]
    fn less_restrictive_local_does_not_lower_encrypt() {
        // Local AllowAudited (LESS restrictive than Encrypt) must not weaken the
        // synced Encrypt: Encrypt wins.
        let mut base = UsbConfig::default();
        base.rules = vec![UsbRule {
            match_serial: Some("courier".into()),
            match_vid: None,
            match_pid: None,
            match_bus_type: None,
            match_any: false,
            action: Action::AllowAudited,
            note: None,
            mode: None,
            key_id: None,
            on_block_band: BlockBandPolicy::Block,
        }];
        let dests = vec![serial_dest("COURIER", EncryptMode::EncryptAll, "k")];
        let merged = merge_into_usb(&base, &dests);
        assert_eq!(merged.rules[0].action, Action::Encrypt);
    }

    // --- merge: empty = unchanged -----------------------------------------

    #[test]
    fn empty_destinations_leaves_config_unchanged() {
        let base = UsbConfig::default();
        let merged = merge_into_usb(&base, &[]);
        assert_eq!(merged.enabled, base.enabled, "no destination must not flip enabled");
        assert!(merged.rules.is_empty());
    }

    #[test]
    fn non_usb_destinations_are_ignored_by_the_usb_merge() {
        let base = UsbConfig::default();
        let dests = vec![SyncedDestination {
            channel: "web_upload".into(),
            matcher: SyncedMatcher::Serial { serial: "X".into() },
            mode: EncryptMode::EncryptAll,
            key_id: "k".into(),
            on_block_band: BlockBandPolicy::Block,
        }];
        let merged = merge_into_usb(&base, &dests);
        assert!(!merged.enabled, "a non-usb destination must not touch the usb config");
        assert!(merged.rules.is_empty());
    }

    // --- wire parse: fixture matching the PINNED contract ------------------

    #[test]
    fn parses_the_pinned_trusted_config_contract() {
        let key_b64 = B64.encode([0x11u8; 32]);
        let json = format!(
            r#"{{
              "destinations": [
                {{ "channel":"usb",
                   "matcher": {{ "serial":"0401396FBBF0C89E" }},
                   "mode":"encrypt_all",
                   "keyId":"class-internal/v1",
                   "onBlockBand":"block" }},
                {{ "channel":"usb",
                   "matcher": {{ "vid":"0951","pid":"1666" }},
                   "mode":"encrypt_sensitive",
                   "keyId":"class-secret/v2",
                   "onBlockBand":"seal" }}
              ],
              "keys": [
                {{ "id":"class-internal/v1", "keyB64":"{key_b64}" }},
                {{ "id":"class-secret/v2",   "keyB64":"{key_b64}" }}
              ]
            }}"#
        );
        let tc: TrustedConfig = serde_json::from_str(&json).expect("contract JSON parses");
        assert_eq!(tc.destinations.len(), 2);
        assert_eq!(tc.keys.len(), 2);

        let d0 = &tc.destinations[0];
        assert_eq!(d0.channel, "usb");
        assert_eq!(d0.matcher, SyncedMatcher::Serial { serial: "0401396FBBF0C89E".into() });
        assert_eq!(d0.mode, EncryptMode::EncryptAll);
        assert_eq!(d0.key_id, "class-internal/v1");
        assert_eq!(d0.on_block_band, BlockBandPolicy::Block);

        let d1 = &tc.destinations[1];
        assert_eq!(d1.matcher, SyncedMatcher::VidPid { vid: "0951".into(), pid: "1666".into() });
        assert_eq!(d1.mode, EncryptMode::EncryptSensitive);
        assert_eq!(d1.on_block_band, BlockBandPolicy::Seal);

        // active id prefers a destination-referenced key (the first here).
        assert_eq!(tc.active_key_id().as_deref(), Some("class-internal/v1"));
    }

    #[test]
    fn on_block_band_defaults_to_block_when_absent() {
        let json = r#"{ "destinations":[
            { "channel":"usb", "matcher":{"serial":"S"},
              "mode":"encrypt_sensitive", "keyId":"k" }
        ], "keys":[] }"#;
        let tc: TrustedConfig = serde_json::from_str(json).unwrap();
        assert_eq!(tc.destinations[0].on_block_band, BlockBandPolicy::Block);
    }

    // --- persisted destinations round-trip (metadata only) -----------------

    #[test]
    fn destinations_persist_round_trips_without_key_bytes() {
        let dests = vec![
            serial_dest("COURIER", EncryptMode::EncryptAll, "class-courier/v1"),
            SyncedDestination {
                channel: "usb".into(),
                matcher: SyncedMatcher::VidPid { vid: "0951".into(), pid: "1666".into() },
                mode: EncryptMode::EncryptSensitive,
                key_id: "class-internal/v1".into(),
                on_block_band: BlockBandPolicy::Seal,
            },
        ];
        let bytes = serialize_destinations(&dests);
        // Metadata only: the file must never contain base64 key material — but it
        // does carry key IDS (that is by design and audited).
        let text = String::from_utf8(bytes.clone()).unwrap();
        assert!(text.contains("class-courier/v1"));
        assert!(text.contains("encrypt_all"));
        let back = parse_destinations(&bytes).expect("round-trips");
        assert_eq!(back, dests);
    }

    #[test]
    fn parse_destinations_missing_file_shape_is_empty() {
        assert!(parse_destinations(b"{}").unwrap().is_empty());
    }

    // --- keyring-from-synced seal/open round-trip --------------------------

    #[test]
    fn keyring_from_synced_keys_seals_and_opens() {
        // Two synced keys; the destination references the second, so it becomes
        // the active seal key.
        let key_a = B64.encode([0xA1u8; 32]);
        let key_b = B64.encode([0xB2u8; 32]);
        let tc = TrustedConfig {
            destinations: vec![serial_dest("S", EncryptMode::EncryptAll, "class-secret/v2")],
            keys: vec![
                SyncedKey { id: "class-internal/v1".into(), key_b64: key_a },
                SyncedKey { id: "class-secret/v2".into(), key_b64: key_b },
            ],
        };
        assert_eq!(tc.active_key_id().as_deref(), Some("class-secret/v2"));

        // Build the keyring exactly as the agent persists it, then parse it back
        // (this is what storage.store_keyring seals and load_keyring restores).
        let json = tc.to_keyring_json().expect("keys present");
        let ring = crate::crypto::Keyring::from_dev_json(&json).expect("synced keyring parses");
        assert_eq!(ring.active_key_id(), "class-secret/v2");

        // Seal with the synced active KEK, open with a fresh ring parsed from the
        // same synced material — the M6 acceptance shape (seal + open from the
        // synced key, no dev keyfile).
        let plaintext = b"eyes only: the plan holds the line";
        let envelope = crate::crypto::seal(
            plaintext,
            "plan.docx",
            ring.active().expect("active kek"),
            "agent-xyz",
            1_700_000_000,
        )
        .expect("seal with synced key");

        let ring2 = crate::crypto::Keyring::from_dev_json(&json).expect("second ring parses");
        let (header, opened) = crate::crypto::open(&envelope, &ring2).expect("open with synced key");
        assert_eq!(opened, plaintext);
        assert_eq!(header.key_id, "class-secret/v2");
        assert_eq!(header.orig_name, "plan.docx");
    }

    #[test]
    fn no_keys_yields_no_keyring_json() {
        let tc = TrustedConfig { destinations: vec![], keys: vec![] };
        assert!(tc.to_keyring_json().is_none(), "no keys ⇒ keep the last keyring at rest");
    }

    #[test]
    fn active_key_falls_back_to_first_when_no_destination_reference() {
        let tc = TrustedConfig {
            destinations: vec![serial_dest("S", EncryptMode::EncryptAll, "unreferenced/v9")],
            keys: vec![SyncedKey { id: "class-internal/v1".into(), key_b64: B64.encode([7u8; 32]) }],
        };
        // No delivered key matches the destination's keyId ⇒ first key wins.
        assert_eq!(tc.active_key_id().as_deref(), Some("class-internal/v1"));
    }
}
