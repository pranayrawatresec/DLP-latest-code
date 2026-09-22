//! Endpoint ML DOCUMENT-CLASSIFICATION policy — the console-managed switch that
//! decides whether the ONNX business-function classifier counts as a SECOND,
//! independent sensitivity signal beside IDM/EDM fingerprinting. Delivered at
//! `GET /agent/ml-policy` (see the server route). Metadata only — label ids,
//! thresholds and counts; NEVER document text, snippets or scores of content.
//!
//! WHY a process-wide "active" copy (same reason as `ocrpolicy`): the classify
//! sites live behind the FROZEN `detect::verdict*` signatures — those cannot grow
//! a policy argument without breaking the golden vectors that gate the
//! fingerprint math byte-for-byte. So the sync worker publishes the policy once
//! and every channel (kguard write scan, USB, clipboard, browser upload) reads it
//! inline. Each site still decides its own behaviour: the write/copy/egress paths
//! run the model inline within their async budget; the SYNCHRONOUS kernel read
//! up-call never does (no time in the budget) — it CONSULTS `ml::cache` instead,
//! which off-path producers fill, and degrades to fingerprint-only on a miss
//! unless [`MlPolicy::deny_unclassified`] says otherwise.
//!
//! WHY the defaults are inert: disabled + an empty label set means the model
//! contributes nothing at all. A fresh endpoint, an older server that does not
//! serve this surface, or an unparseable cache therefore behaves exactly as it
//! did before the model existed — the classifier is opt-in, per label, from the
//! console. That is deliberate: ML can only ADD sensitivity (OR, never AND), so
//! an accidental "on" is a false-positive generator, not a protection gap.

use serde::{Deserialize, Serialize};
use std::sync::RwLock;

fn default_true() -> bool {
    true
}
/// Global floor when a selected label carries no override (contract default).
fn default_min_confidence() -> f64 {
    0.70
}
/// The frozen taxonomy/model version this agent expects. Carried so a result can
/// record WHICH model produced a label; the server is the authority.
fn default_model_version() -> String {
    "V6.2.01".to_string()
}

/// What a model-only hit does on an egress path: `audit` (incident only) or
/// `block`. Defaults to `Audit` so an absent/unknown value (older cache, older
/// server) can never turn a new signal into a new block.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MlAction {
    #[default]
    Audit,
    Block,
}

impl std::fmt::Display for MlAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            MlAction::Audit => "audit",
            MlAction::Block => "block",
        })
    }
}

/// One admin-selected label ("this business function is sensitive here"), with an
/// optional per-label confidence override. `min_confidence: None` = fall back to
/// the policy-wide [`MlPolicy::min_confidence`]; a site that needs NUC at 0.50 and
/// FIN at 0.90 sets them individually without moving the global floor.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MlLabelRule {
    /// Frozen 3-letter taxonomy id (`"FIN"`, `"NUC"`, …) — never the index, so a
    /// future taxonomy reorder cannot silently repoint a policy at another class.
    pub id: String,
    #[serde(default, rename = "minConfidence")]
    pub min_confidence: Option<f64>,
}

/// The wire + at-rest shape of the ML policy
/// (`{enabled, minConfidence, action, failBlock, modelVersion, labels}`).
/// EVERY field is `serde(default)` so an older server, an older cached file, or a
/// partial object still deserialises into the inert default rather than failing
/// the whole sync (which would leave the endpoint with no policy at all).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MlPolicy {
    #[serde(default)]
    pub enabled: bool,
    /// Global confidence floor, used for any selected label with no override.
    #[serde(default = "default_min_confidence", rename = "minConfidence")]
    pub min_confidence: f64,
    #[serde(default)]
    pub action: MlAction,
    /// Fail-secure default TRUE: when the model cannot be loaded or inference
    /// fails while the policy is enabled, EGRESS paths block. The kernel read
    /// path never honours this (see the module header).
    #[serde(default = "default_true", rename = "failBlock")]
    pub fail_block: bool,
    #[serde(default = "default_model_version", rename = "modelVersion")]
    pub model_version: String,
    /// The labels the admin marked sensitive. EMPTY = inert (no label can match).
    #[serde(default)]
    pub labels: Vec<MlLabelRule>,
    /// `denyUnclassified` — deny a kernel READ of content nothing has classified
    /// yet (contract P2). The one field on this policy that can create NEW
    /// denials, so it is the one field whose absence must mean OFF.
    ///
    /// FALSE IS THE FAIL-SAFE DIRECTION HERE, and this is the exception that
    /// proves the rule for the rest of the struct. Everywhere else on this policy
    /// the safe default is the RESTRICTIVE one (`fail_block` defaults true). Not
    /// here: with the flag on, the first read of every file that predates the
    /// agent — i.e. every file on a freshly-deployed endpoint — is denied until
    /// the at-rest walker has reached it. Enabling it before the estate is swept
    /// is a fleet outage, not a control. Hence `#[serde(default)]`: a server too
    /// old to serve the field, a truncated cache, a hand-edited JSON, all read as
    /// `false`.
    ///
    /// The supported rollout is: deploy → the walker's completion record says the
    /// estate is covered → verify coverage → enable. `detect::decide::
    /// deny_unclassified()` adds two more gates it cannot be enabled past — the
    /// policy must be LIVE and the on-demand classifier worker must be RUNNING,
    /// because a denial nothing can ever clear is an outage with no security
    /// gain.
    #[serde(default, rename = "denyUnclassified")]
    pub deny_unclassified: bool,
}

impl Default for MlPolicy {
    fn default() -> Self {
        MlPolicy {
            enabled: false,
            min_confidence: default_min_confidence(),
            action: MlAction::Audit,
            fail_block: true,
            model_version: default_model_version(),
            labels: Vec::new(),
            deny_unclassified: false,
        }
    }
}

impl MlPolicy {
    /// The model contributes nothing: switched off, or no label selected. Both
    /// are checked because "enabled with an empty set" is a real console state
    /// (an admin turning the feature on before choosing categories) and it must
    /// stay silent, not sensitive-everything.
    pub fn is_inert(&self) -> bool {
        !self.enabled || self.labels.is_empty()
    }

    /// Block (vs audit-only) a model-only hit on an egress path.
    pub fn blocks(&self) -> bool {
        matches!(self.action, MlAction::Block)
    }

    /// THE ml_sensitive rule (contract §D), pure so the fusion layer can call it
    /// without touching the policy store: a predicted label makes a document
    /// sensitive iff the policy is live, the label is one the admin selected, and
    /// the confidence reaches THAT label's threshold (its own override, else the
    /// policy-wide floor). Unknown label ⇒ false — an unselected business
    /// function is not a leak signal, however confident the model is.
    ///
    /// Ids are compared case-insensitively: the taxonomy is uppercase ASCII, and
    /// a console/cache that ever round-trips a lowercased id must not silently
    /// disarm a selected label.
    pub fn label_is_sensitive(&self, label_id: &str, confidence: f64) -> bool {
        if self.is_inert() {
            return false;
        }
        match self
            .labels
            .iter()
            .find(|r| r.id.eq_ignore_ascii_case(label_id))
        {
            Some(rule) => confidence >= rule.min_confidence.unwrap_or(self.min_confidence),
            None => false,
        }
    }
}

// Process-wide active policy. Inert until a process publishes the synced policy.
static ACTIVE: RwLock<Option<MlPolicy>> = RwLock::new(None);

/// Publish the active ML policy for this process (call at startup + on resync).
pub fn set_active(p: MlPolicy) {
    match ACTIVE.write() {
        Ok(mut w) => *w = Some(p),
        Err(e) => *e.into_inner() = Some(p),
    }
}

/// The active ML policy (default = inert when never published).
pub fn active() -> MlPolicy {
    match ACTIVE.read() {
        Ok(r) => r.clone().unwrap_or_default(),
        Err(e) => e.into_inner().clone().unwrap_or_default(),
    }
}

/// Convenience: is ML classification live for this process (on AND with at least
/// one selected label)? Sites use this to skip the whole inference path.
pub fn enabled() -> bool {
    !active().is_inert()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, min: Option<f64>) -> MlLabelRule {
        MlLabelRule { id: id.to_string(), min_confidence: min }
    }

    #[test]
    fn default_is_inert_failsecure() {
        let p = MlPolicy::default();
        assert!(!p.enabled);
        assert!(p.is_inert());
        assert!(!p.blocks());
        assert!(p.fail_block);
        assert_eq!(p.action, MlAction::Audit);
        assert_eq!(p.min_confidence, 0.70);
        assert_eq!(p.model_version, "V6.2.01");
        assert!(p.labels.is_empty());
        // The one field whose safe default is PERMISSIVE — see its doc comment.
        assert!(!p.deny_unclassified);
    }

    #[test]
    fn deny_unclassified_defaults_off_on_every_wire_shape() {
        // An older server that has never heard of the field.
        let old: MlPolicy = serde_json::from_str(
            r#"{"enabled":true,"labels":[{"id":"NUC"}],"minConfidence":0.6}"#,
        )
        .unwrap();
        assert!(!old.is_inert(), "the rest of the policy still parses");
        assert!(
            !old.deny_unclassified,
            "an absent denyUnclassified must never deny a first read"
        );
        // An explicit null is not a bool; serde(default) does NOT cover it, so a
        // console must send a bool or omit the key. Omission is the tested path.
        let empty: MlPolicy = serde_json::from_str("{}").unwrap();
        assert!(!empty.deny_unclassified);
        // ...and an explicit false is still false.
        let off: MlPolicy = serde_json::from_str(r#"{"denyUnclassified":false}"#).unwrap();
        assert!(!off.deny_unclassified);
    }

    #[test]
    fn deny_unclassified_round_trips_in_camel_case() {
        let p: MlPolicy = serde_json::from_str(
            r#"{"enabled":true,"denyUnclassified":true,"labels":[{"id":"NUC"}]}"#,
        )
        .unwrap();
        assert!(p.deny_unclassified);
        // The at-rest cache is this same shape, so the flag must survive a
        // save/reload — a policy that quietly lost it after a restart would flip
        // a deployed endpoint back to permissive without anyone touching the
        // console.
        let json = serde_json::to_string(&p).unwrap();
        assert!(
            json.contains("\"denyUnclassified\":true"),
            "serialised as camelCase: {json}"
        );
        let back: MlPolicy = serde_json::from_str(&json).unwrap();
        assert!(back.deny_unclassified);
    }

    #[test]
    fn deny_unclassified_does_not_touch_the_sensitivity_rule() {
        // It governs what happens on a cache MISS, never what a label MEANS.
        // Setting it must not change one answer of `label_is_sensitive`.
        let base = MlPolicy {
            enabled: true,
            min_confidence: 0.70,
            labels: vec![rule("FIN", None)],
            ..MlPolicy::default()
        };
        let strict = MlPolicy { deny_unclassified: true, ..base.clone() };
        for c in [0.0, 0.69, 0.70, 0.99] {
            assert_eq!(
                base.label_is_sensitive("FIN", c),
                strict.label_is_sensitive("FIN", c)
            );
            assert_eq!(
                base.label_is_sensitive("PUB", c),
                strict.label_is_sensitive("PUB", c)
            );
        }
        // And it cannot resurrect an inert policy (contract F3).
        let inert = MlPolicy { enabled: false, deny_unclassified: true, ..base };
        assert!(inert.is_inert());
        assert!(!inert.label_is_sensitive("FIN", 1.0));
    }

    #[test]
    fn wire_omitted_fields_default() {
        // Older server sends only `enabled` → every other field takes its
        // fail-secure default and the policy stays inert (no labels).
        let p: MlPolicy = serde_json::from_str(r#"{"enabled":true}"#).unwrap();
        assert!(p.enabled);
        assert!(p.is_inert());
        assert!(p.fail_block);
        assert_eq!(p.min_confidence, 0.70);
        assert_eq!(p.model_version, "V6.2.01");
        // Entirely empty object → the inert default.
        let e: MlPolicy = serde_json::from_str("{}").unwrap();
        assert!(e.is_inert());
    }

    #[test]
    fn wire_camel_case_round_trip() {
        let json = r#"{"enabled":true,"minConfidence":0.6,"action":"block",
                       "failBlock":false,"modelVersion":"V6.2.01",
                       "labels":[{"id":"FIN","minConfidence":0.8},{"id":"NUC"}]}"#;
        let p: MlPolicy = serde_json::from_str(json).unwrap();
        assert!(p.blocks());
        assert!(!p.fail_block);
        assert_eq!(p.min_confidence, 0.6);
        assert_eq!(p.labels.len(), 2);
        assert_eq!(p.labels[0].min_confidence, Some(0.8));
        assert!(p.labels[1].min_confidence.is_none());
        // Serialises back in the SAME camelCase wire shape (this is also the
        // at-rest cache format, so a round-trip must be lossless).
        let back: MlPolicy = serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(back.action, MlAction::Block);
        assert_eq!(back.labels[0].id, "FIN");
        assert_eq!(back.labels[1].min_confidence, None);
    }

    #[test]
    fn label_is_sensitive_disabled_policy_never_fires() {
        let p = MlPolicy {
            enabled: false,
            labels: vec![rule("FIN", None)],
            ..MlPolicy::default()
        };
        assert!(!p.label_is_sensitive("FIN", 1.0));
    }

    #[test]
    fn label_is_sensitive_empty_label_set_never_fires() {
        let p = MlPolicy { enabled: true, ..MlPolicy::default() };
        assert!(p.is_inert());
        assert!(!p.label_is_sensitive("FIN", 1.0));
    }

    #[test]
    fn label_is_sensitive_uses_global_threshold() {
        let p = MlPolicy {
            enabled: true,
            min_confidence: 0.70,
            labels: vec![rule("FIN", None)],
            ..MlPolicy::default()
        };
        assert!(!p.label_is_sensitive("FIN", 0.6999));
        assert!(p.label_is_sensitive("FIN", 0.70)); // >= is inclusive
        assert!(p.label_is_sensitive("FIN", 0.99));
    }

    #[test]
    fn label_is_sensitive_per_label_override_wins_both_ways() {
        let p = MlPolicy {
            enabled: true,
            min_confidence: 0.70,
            // FIN stricter than global, NUC looser than global.
            labels: vec![rule("FIN", Some(0.90)), rule("NUC", Some(0.50))],
            ..MlPolicy::default()
        };
        // Above the global floor but BELOW the label's own bar → not sensitive.
        assert!(!p.label_is_sensitive("FIN", 0.85));
        assert!(p.label_is_sensitive("FIN", 0.90));
        // Below the global floor but ABOVE the label's own bar → sensitive.
        assert!(p.label_is_sensitive("NUC", 0.55));
        assert!(!p.label_is_sensitive("NUC", 0.49));
    }

    #[test]
    fn label_is_sensitive_unknown_label_never_fires() {
        let p = MlPolicy {
            enabled: true,
            labels: vec![rule("FIN", None)],
            ..MlPolicy::default()
        };
        // A confident prediction on a label the admin did NOT mark is not a hit.
        assert!(!p.label_is_sensitive("PUB", 1.0));
        assert!(!p.label_is_sensitive("", 1.0));
        // Case-insensitive id match (taxonomy ids are uppercase ASCII).
        assert!(p.label_is_sensitive("fin", 0.99));
    }

    #[test]
    fn active_defaults_to_inert_then_follows_publish() {
        // NOTE: ACTIVE is process-wide; this test owns it (no other test writes it).
        assert!(!enabled());
        set_active(MlPolicy {
            enabled: true,
            labels: vec![rule("NUC", None)],
            ..MlPolicy::default()
        });
        assert!(enabled());
        assert!(active().label_is_sensitive("NUC", 0.8));
        set_active(MlPolicy::default());
        assert!(!enabled());
    }
}
