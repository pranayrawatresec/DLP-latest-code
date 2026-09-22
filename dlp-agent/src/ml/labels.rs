//! The frozen 29-label space of the V6.2.01 document classifier.
//!
//! The model emits a bare `logits[1, 29]`; the meaning of index *i* lives nowhere
//! in the graph. It lives here, and in exactly one other place — the taxonomy lock
//! `Document_classification/taxonomy/v6_2_01/registry.lock.json` and the sidecar
//! `model/model.onnx.json` it was exported into. Keeping our own copy is
//! deliberate: the agent must be able to name a label with no sidecar to hand and
//! with the server unreachable, and [`engine`](super::engine) cross-checks this
//! table against the sidecar on load so the two can never quietly disagree.
//!
//! **The order is FROZEN.** Indices 0..28 are what the classification head was
//! trained to emit. Re-ordering, inserting or removing an entry silently
//! re-labels every prediction the endpoint makes — a NUC document reported as
//! ADM. A new label space is a new model version, a new sidecar and a new set of
//! golden vectors, not an edit to this array.
//!
//! `domain` is presentation only: it is how the console groups the 29 checkboxes
//! (13 general / 3 education / 13 defence). Nothing in detection or fusion reads
//! it — an admin marks individual label ids sensitive, never a whole group.

/// One class of the model's output layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MlLabel {
    /// The three-letter id used on every wire surface and in the policy.
    pub id: &'static str,
    /// The display name shown in the console and carried in the verdict.
    pub name: &'static str,
    /// The console's grouping: `general`, `education` or `defence`. Display only.
    pub domain: &'static str,
}

/// How many classes the head emits. A model whose output width differs is a
/// different model and [`engine`](super::engine) refuses to load it.
pub const LABEL_COUNT: usize = 29;

/// The label space, in the model's own index order. Transcribed from
/// `model/model.onnx.json` (`labels` + `label_names`) for V6.2.01.
pub const LABELS: [MlLabel; LABEL_COUNT] = [
    // --- general (13) -------------------------------------------------------
    MlLabel { id: "ADM", name: "Administration", domain: "general" }, // 0
    MlLabel { id: "STU", name: "Student Records", domain: "education" }, // 1
    MlLabel { id: "TCH", name: "Teacher Records", domain: "education" }, // 2
    MlLabel { id: "GOV", name: "Government Reporting", domain: "general" }, // 3
    MlLabel { id: "INS", name: "Inspection", domain: "general" },    // 4
    MlLabel { id: "OPS", name: "Planning & Operations", domain: "general" }, // 5
    MlLabel { id: "FIN", name: "Finance", domain: "general" },       // 6
    MlLabel { id: "EXM", name: "Examination", domain: "education" }, // 7
    MlLabel { id: "COM", name: "Communication", domain: "general" }, // 8
    MlLabel { id: "POL", name: "Policies", domain: "general" },      // 9
    MlLabel { id: "ANA", name: "Analytics", domain: "general" },     // 10
    MlLabel { id: "PUB", name: "Public Information", domain: "general" }, // 11
    MlLabel { id: "OOD", name: "Other / Unknown", domain: "general" }, // 12
    MlLabel { id: "PER", name: "Personnel & Service Records", domain: "general" }, // 13
    // --- defence (13), interleaved exactly as the head emits them -----------
    MlLabel { id: "INT", name: "Intelligence & Threat Assessment", domain: "defence" }, // 14
    MlLabel { id: "WPN", name: "Weapons & Armament", domain: "defence" }, // 15
    MlLabel { id: "AVI", name: "Aviation & Air Systems", domain: "defence" }, // 16
    MlLabel { id: "NAV", name: "Naval & Maritime Systems", domain: "defence" }, // 17
    MlLabel { id: "SIG", name: "Signals & Communications", domain: "defence" }, // 18
    MlLabel { id: "CYB", name: "Cyber Defence", domain: "defence" }, // 19
    MlLabel { id: "SPC", name: "Space & Satellite Systems", domain: "defence" }, // 20
    MlLabel { id: "LOG", name: "Defence Logistics & Supply", domain: "defence" }, // 21
    MlLabel { id: "ACQ", name: "Defence Acquisition & Procurement", domain: "defence" }, // 22
    MlLabel { id: "DIP", name: "Defence Diplomacy & Border Affairs", domain: "defence" }, // 23
    MlLabel { id: "TRN", name: "Military Training & Doctrine", domain: "defence" }, // 24
    MlLabel { id: "MNT", name: "Maintenance & Engineering", domain: "defence" }, // 25
    MlLabel { id: "MED", name: "Medical", domain: "general" },       // 26
    MlLabel { id: "LEG", name: "Legal", domain: "general" },         // 27
    MlLabel { id: "NUC", name: "Nuclear & Strategic Systems", domain: "defence" }, // 28
];

// Compile-time guard. The array's length is what indexes the logits vector; a
// 28- or 30-entry table would mis-name predictions rather than fail, so this is
// checked by the compiler and not by a test somebody can forget to run.
const _: () = assert!(LABELS.len() == LABEL_COUNT);

/// The label at a model output index, or `None` when the index is out of range
/// (which can only mean the graph emitted a width this build does not know).
pub fn by_index(index: usize) -> Option<&'static MlLabel> {
    LABELS.get(index)
}

/// The label with this id, and its frozen model index. Case-sensitive: ids are
/// upper-case on every wire surface and a lower-case id is a caller bug, not a
/// spelling to be forgiven.
pub fn by_id(id: &str) -> Option<(usize, &'static MlLabel)> {
    LABELS.iter().position(|l| l.id == id).map(|i| (i, &LABELS[i]))
}

/// Every label id in model index order — the shape the console's
/// `GET /api/ml-policy/labels` and the sidecar's `labels` array both use.
pub fn ids() -> [&'static str; LABEL_COUNT] {
    let mut out = [""; LABEL_COUNT];
    let mut i = 0;
    while i < LABEL_COUNT {
        out[i] = LABELS[i].id;
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_exactly_twentynine() {
        assert_eq!(LABELS.len(), 29);
        assert_eq!(LABEL_COUNT, 29);
    }

    #[test]
    fn index_order_is_frozen() {
        // Spot-check the ends and the two boundaries that matter most: index 6
        // (FIN) and index 28 (NUC) are the ids the fusion tests and the console
        // examples use, so a shifted table shows up here first.
        assert_eq!(LABELS[0].id, "ADM");
        assert_eq!(LABELS[6].id, "FIN");
        assert_eq!(LABELS[12].id, "OOD");
        assert_eq!(LABELS[14].id, "INT");
        assert_eq!(LABELS[28].id, "NUC");
    }

    #[test]
    fn ids_are_unique() {
        for (i, a) in LABELS.iter().enumerate() {
            for b in LABELS.iter().skip(i + 1) {
                assert_ne!(a.id, b.id, "duplicate label id {}", a.id);
            }
        }
    }

    #[test]
    fn lookups_agree_with_the_table() {
        assert_eq!(by_index(6).unwrap().name, "Finance");
        assert_eq!(by_id("NUC").unwrap().0, 28);
        assert!(by_index(29).is_none());
        assert!(by_id("nuc").is_none());
        assert!(by_id("ZZZ").is_none());
    }

    #[test]
    fn domain_grouping_is_thirteen_three_thirteen() {
        let count = |d: &str| LABELS.iter().filter(|l| l.domain == d).count();
        assert_eq!(count("general"), 13);
        assert_eq!(count("education"), 3);
        assert_eq!(count("defence"), 13);
        assert_eq!(count("general") + count("education") + count("defence"), LABEL_COUNT);
    }
}
