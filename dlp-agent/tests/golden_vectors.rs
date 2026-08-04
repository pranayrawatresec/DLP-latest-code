//! Golden-vector gate for the IDM fingerprinting port (src/detect/).
//!
//! The contract is dlp-management-server/test/fixtures/fingerprint-vectors.json:
//! tokens, shingle hashes AND winnowed fingerprints must be IDENTICAL to the
//! Node reference (lib/fingerprint.js) for every vector. A failure here is a
//! breaking protocol change, not a flaky test — do NOT weaken these asserts.
//!
//! Also ports the primitive checks (F01/F05) and the detection-band checks
//! (F08–F13) from dlp-management-server/test/fingerprint.test.js, including
//! its mutation corpus, so containment behaviour matches the server too.

use dlp_agent::detect::{
    containment, fingerprint, fnv1a64, normalize, shingles_of, similarity, winnow, Fingerprint,
};
use serde::Deserialize;
use std::path::Path;

#[derive(Deserialize)]
struct Fixture {
    k: usize,
    w: usize,
    vectors: Vec<Vector>,
}

#[derive(Deserialize)]
struct Vector {
    name: String,
    input: String,
    canonical: String,
    tokens: Vec<String>,
    #[serde(rename = "tokenCount")]
    token_count: usize,
    #[serde(rename = "shingleCount")]
    shingle_count: usize,
    #[serde(rename = "shingleHashes")]
    shingle_hashes: Vec<String>,
    fingerprints: Vec<FixtureFingerprint>,
}

#[derive(Deserialize)]
struct FixtureFingerprint {
    hash: String, // signed 64-bit decimal string (BIGINT wire form)
    seq: u32,
}

fn load_fixture() -> Fixture {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../dlp-management-server/test/fixtures/fingerprint-vectors.json");
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read golden vectors at {}: {e}", path.display()));
    serde_json::from_str(&raw).expect("parsing fingerprint-vectors.json")
}

// =====================================================================
// B. Golden vectors — byte-for-byte identity with the Node reference.
// =====================================================================

#[test]
fn golden_vectors_reproduced_exactly() {
    let fixture = load_fixture();
    assert_eq!((fixture.k, fixture.w), (8, 8), "fixture must pin k=8 w=8");
    assert!(fixture.vectors.len() >= 10, "expected at least 10 vectors");

    for v in &fixture.vectors {
        let normalized = normalize(&v.input);
        assert_eq!(normalized.canonical, v.canonical, "{}: canonical drifted", v.name);
        assert_eq!(normalized.tokens, v.tokens, "{}: tokens drifted", v.name);

        let shingles = shingles_of(&normalized.tokens, fixture.k);
        let hashes: Vec<String> = shingles.iter().map(|s| fnv1a64(s).to_string()).collect();
        assert_eq!(hashes, v.shingle_hashes, "{}: shingle hashes drifted", v.name);

        let result = fingerprint(&v.input, fixture.k, fixture.w);
        assert_eq!(result.token_count, v.token_count, "{}: tokenCount drifted", v.name);
        assert_eq!(result.shingle_count, v.shingle_count, "{}: shingleCount drifted", v.name);

        let expected: Vec<Fingerprint> = v
            .fingerprints
            .iter()
            .map(|f| Fingerprint {
                hash: f.hash.parse::<i64>().expect("fixture hash must be a signed 64-bit decimal"),
                seq: f.seq,
            })
            .collect();
        assert_eq!(
            result.fingerprints, expected,
            "{}: winnowed fingerprints drifted",
            v.name
        );
    }
}

// =====================================================================
// A. Primitives — independently hard-coded, same as the Node suite.
// =====================================================================

#[test]
fn fnv1a64_matches_published_test_values_signed_form() {
    // Published FNV-1a test values — NOT derived from either implementation.
    let known: [(&str, u64); 3] = [
        ("", 0xcbf29ce484222325),
        ("a", 0xaf63dc4c8601ec8c),
        ("foobar", 0x85944171f73967e8),
    ];
    for (input, u64_value) in known {
        assert_eq!(fnv1a64(input), u64_value as i64, "fnv1a64({input:?})");
    }
    // Offset basis has the top bit set — signed form must be negative.
    assert!(fnv1a64("") < 0);
}

#[test]
fn winnow_unsigned_compare_rightmost_tie_record_on_min_change() {
    let fp = |hash: i64, seq: u32| Fingerprint { hash, seq };
    // Fewer than w hashes → single min; tie at value 3 → rightmost (index 2).
    assert_eq!(winnow(&[5, 3, 3, 9], 8), vec![fp(3, 2)]);
    // Unsigned compare: -1 is 0xffff...ffff unsigned — the LARGEST, never the min.
    assert_eq!(winnow(&[-1, 7], 8), vec![fp(7, 1)]);
    // w=2 walk over [9,5,5,8,2]: seq 1 (5), tie → rightmost seq 2 (5),
    // seq 2 again (no record), then seq 4 (2).
    assert_eq!(
        winnow(&[9, 5, 5, 8, 2], 2),
        vec![fp(5, 1), fp(5, 2), fp(2, 4)]
    );
    assert_eq!(winnow(&[], 8), vec![]);
}

// =====================================================================
// C. Detection bands — corpus ported verbatim from test/fingerprint.test.js.
// =====================================================================

const BASE_SENTENCES: [&str; 40] = [
    "The perimeter fence on the north side was inspected at first light by the duty officer.",
    "Every visitor badge must be surrendered at the gatehouse before the holder leaves the site.",
    "Deliveries arriving after eighteen hundred are held in the outer compound until morning.",
    "The generator room is tested under load on the first Tuesday of every month.",
    "Access to the server hall requires two named custodians to be present at all times.",
    "Contractors working above the false ceiling must lodge a permit with the facilities desk.",
    "The evacuation assembly point for buildings three and four is the west car park.",
    "Radio checks between the control room and each patrol are logged every thirty minutes.",
    "Keys to the archive store are issued against signature and counted at shift change.",
    "Any damaged seal on a document container is reported immediately to the registry team.",
    "The camera covering loading bay two was realigned after the survey noted a blind spot.",
    "Fire doors along the central corridor are checked for obstructions during each round.",
    "Personal devices are deposited in the lockers outside the secure working area.",
    "The visitor log for the previous quarter is reconciled against the badge system weekly.",
    "Escorts must remain within sight of their visitors for the whole duration of the stay.",
    "The standby lighting in stairwell six failed its discharge test and awaits new batteries.",
    "Waste destined for destruction is double bagged and weighed before collection.",
    "The duty roster for the holiday period was approved by the site manager on Friday.",
    "Alarm activations outside working hours trigger a callout to the response contractor.",
    "The fuel level in the standby tank is dipped manually and recorded each Monday.",
    "Grounds maintenance staff are briefed not to store equipment against the inner fence.",
    "The pass office closes at sixteen thirty and late arrivals are handled by the gatehouse.",
    "Lift number two remains out of service pending a replacement door interlock.",
    "A trial of the new turnstile software is scheduled for the last week of the month.",
    "The mail screening room reported no suspicious items during the reporting period.",
    "Roof access requests are countersigned by both the safety adviser and the duty engineer.",
    "The tamper alarm on the east gate cabinet was traced to a loose junction box lid.",
    "Cleaning crews assigned to restricted rooms hold the appropriate level of clearance.",
    "The quarterly lock audit found two cabinets keyed outside the approved suite.",
    "Vehicle searches at the main gate are conducted at random intervals through the day.",
    "The intruder detection system completed its annual certification without defects.",
    "Spare radios are kept on charge in the control room and rotated every week.",
    "The car park barrier arm was replaced after being struck by a delivery vehicle.",
    "Induction briefings for new starters now include the updated spill response procedure.",
    "The plant room door closer was adjusted so the door latches under its own weight.",
    "Records of the monthly fence line walk are retained for a minimum of three years.",
    "A faulty motion sensor in corridor nine produced repeated false alarms overnight.",
    "The gatehouse first aid kit was restocked and the eyewash bottles were replaced.",
    "External floodlighting switches to half output after midnight to reduce consumption.",
    "The annual review of patrol routes begins with a survey of the southern boundary.",
];

fn base_doc() -> String {
    BASE_SENTENCES.join(" ")
}

/// Cosmetic mutation: case, punctuation, extra whitespace — content identical.
fn reformatted_doc() -> String {
    BASE_SENTENCES
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let cased = if i % 2 == 0 { s.to_uppercase() } else { (*s).to_string() };
            let dotted = cased.replace('.', if i % 3 == 0 { "!!!" } else { " ..." });
            dotted.replace(' ', if i % 5 == 0 { "\t\t" } else { "  " })
        })
        .collect::<Vec<_>>()
        .join("\n\n --- \n\n")
}

/// One genuinely new paragraph appended.
fn appended_doc() -> String {
    let added = "A separate initiative examined the catering compound, where the review team \
        interviewed kitchen staff about out of hours deliveries, sampled the cold store \
        temperature logs, and recommended that the rear service door be fitted with the \
        same monitored contact used elsewhere on the site so that openings appear in the \
        central event record alongside every other controlled entrance.";
    format!("{} {added}", base_doc())
}

/// ~25% of sentences removed (two blocks of five: indexes 14-18 and 34-38).
fn deleted_doc() -> String {
    BASE_SENTENCES
        .iter()
        .enumerate()
        .filter(|(i, _)| !((14..=18).contains(i) || (34..=38).contains(i)))
        .map(|(_, s)| *s)
        .collect::<Vec<_>>()
        .join(" ")
}

/// Same topic (site security report), completely different wording.
fn rewritten_doc() -> String {
    [
        "Guards walked the boundary as usual and nothing unusual turned up along the wire.",
        "People coming in for meetings hand back their temporary cards when they go home.",
        "Trucks that show up late in the evening wait outside until somebody signs them in.",
        "We run the backup power plant once a month to make sure it still takes the strain.",
        "Nobody gets into the computer room alone; a second keyholder always tags along.",
        "Workmen poking around in the ceiling spaces need a chit from the office first.",
        "If the bells ring, everyone from the far blocks gathers on the tarmac by the gym.",
        "The wardens call in on the handsets twice an hour so the desk knows where they are.",
        "Whoever draws the strongroom key signs a book, and the bunch is tallied at handover.",
        "Broken wrappers on filing boxes get flagged straight away to the records people.",
        "One of the yard cameras was twisted round because it could not see a corner before.",
        "On every walkabout the wardens make sure nothing is piled up against the exits.",
        "Phones and smart watches stay in the cubbyholes by the entrance to the quiet zone.",
        "Someone cross checks the sign in sheets against the card reader printout regularly.",
        "Hosts stick with their guests from the front door until they are back out again.",
    ]
    .join(" ")
}

#[test]
fn containment_bands_across_realistic_mutations() {
    let base_fp = fingerprint(&base_doc(), 8, 8).fingerprints;
    assert!(!base_fp.is_empty(), "expected non-empty fingerprints");

    // F08: identical document → containment exactly 1.
    assert_eq!(containment(&base_fp, &base_fp), 1.0);

    // F09: reformatted variant (case/punctuation/whitespace) > 0.95.
    let c = containment(&base_fp, &fingerprint(&reformatted_doc(), 8, 8).fingerprints);
    assert!(c > 0.95, "reformatted: expected > 0.95, got {c}");

    // F10: one new paragraph appended keeps containment of base > 0.9.
    let c = containment(&base_fp, &fingerprint(&appended_doc(), 8, 8).fingerprints);
    assert!(c > 0.9, "appended: expected > 0.9, got {c}");

    // F11: deleting ~25% of sentences lands in (0.6, 0.9).
    let c = containment(&base_fp, &fingerprint(&deleted_doc(), 8, 8).fingerprints);
    assert!(c > 0.6 && c < 0.9, "deleted: expected 0.6 < c < 0.9, got {c}");

    // F12: fully rewritten text (same topic, new wording) < 0.2.
    let c = containment(&base_fp, &fingerprint(&rewritten_doc(), 8, 8).fingerprints);
    assert!(c < 0.2, "rewritten: expected < 0.2, got {c}");
}

#[test]
fn similarity_and_fail_secure_empty_sets() {
    let base_fp = fingerprint(&base_doc(), 8, 8).fingerprints;
    let part_fp = fingerprint(&deleted_doc(), 8, 8).fingerprints;

    let s = similarity(&base_fp, &part_fp);
    assert_eq!(s.containment, containment(&base_fp, &part_fp));
    assert!(s.coverage > 0.0 && s.coverage <= 1.0, "coverage out of range: {}", s.coverage);
    // The deleted doc is a pure subset of base → nearly all its material is protected.
    assert!(s.coverage > 0.9, "expected coverage > 0.9 for a subset doc, got {}", s.coverage);

    // Empty protected set must give 0, not match-everything — fail secure.
    assert_eq!(containment(&[], &base_fp), 0.0);
    let empty = similarity(&[], &[]);
    assert_eq!((empty.containment, empty.coverage), (0.0, 0.0));
}

#[test]
fn determinism_two_runs_identical() {
    let a = fingerprint(&base_doc(), 8, 8);
    let b = fingerprint(&base_doc(), 8, 8);
    assert_eq!(a, b);
    assert!(!a.fingerprints.is_empty());
}
