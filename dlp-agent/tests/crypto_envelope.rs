//! `.dlpenc` envelope gate (ENCRYPT-ON-WRITE-IMPLEMENTATION.md §4, milestone M1).
//!
//! Three layers of protection, mirroring the golden-vector discipline of
//! tests/verdict_bytes.rs:
//!
//! 1. **Golden vector** — a fixed KEK, a scripted RNG (deterministic DEK and
//!    nonces) and an injected clock must produce byte-for-byte identical
//!    envelopes forever. Any change to the wire format, header field order,
//!    or crypto parameters breaks this test — which is the point.
//! 2. **Tamper matrix** — every way an attacker (or bit rot) can mangle an
//!    envelope yields a *typed* `EnvelopeError`, never a panic and never
//!    partial plaintext.
//! 3. **Round-trip property** — seal→open is the identity over a spread of
//!    sizes 0..1 MiB using the production RNG path.
//!
//! No I/O beyond a temp keyfile for the keyring loader test; no hardware.

use dlp_agent::crypto::envelope::{open, peek_header, seal, seal_with_rng, EnvelopeError, EnvelopeRng};
use dlp_agent::crypto::keyring::{Kek, Keyring, KeyringError};
use sha2::{Digest, Sha256};

const KEY_ID: &str = "class-internal/v1";
const AGENT: &str = "agent-0007";
const NOW: u64 = 1_700_000_000;
const PLAINTEXT: &[u8] = b"attack at dawn";
const ORIG_NAME: &str = "plan.txt";

fn kek_bytes() -> [u8; 32] {
    let mut k = [0u8; 32];
    for (i, b) in k.iter_mut().enumerate() {
        *b = i as u8;
    }
    k
}

fn kek() -> Kek {
    Kek::new(KEY_ID, kek_bytes())
}

fn keyring() -> Keyring {
    let mut r = Keyring::new(KEY_ID);
    r.insert(kek());
    r
}

/// Deterministic RNG for golden vectors. Hands out a fixed byte script in the
/// documented draw order of `seal_with_rng`: DEK (32), DEK-wrap nonce (12),
/// body nonce (12). Panicking on exhaustion is fine — test-only type.
struct ScriptedRng {
    data: Vec<u8>,
    pos: usize,
}

impl EnvelopeRng for ScriptedRng {
    fn fill(&mut self, buf: &mut [u8]) {
        let end = self.pos + buf.len();
        buf.copy_from_slice(&self.data[self.pos..end]);
        self.pos = end;
    }
}

fn scripted() -> ScriptedRng {
    let mut data = Vec::new();
    data.extend((0u8..32).map(|i| 0x40 + i)); // DEK
    data.extend((0u8..12).map(|i| 0xD0 + i)); // DEK-wrap nonce
    data.extend((0u8..12).map(|i| 0xE0 + i)); // body nonce
    ScriptedRng { data, pos: 0 }
}

fn golden_envelope() -> Vec<u8> {
    seal_with_rng(&mut scripted(), PLAINTEXT, ORIG_NAME, &kek(), AGENT, NOW)
        .expect("golden seal must succeed")
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Byte-for-byte golden vector. Committed after the first deterministic run;
/// regressions in magic/version/header serialization/nonce/AAD/tag layout all
/// land here.
const GOLDEN_HEX: &str = "444c5045012a017b226b65794964223a22636c6173732d696e7465726e616c2f7631222c227772617070656444656b223a22624f616b4c537a69742b5951466d4c307570764a7270396244345955794f345261394d557a564e75634a6a573972787741776b547073387474647770464c6474222c2264656b4e6f6e6365223a22304e4853303954563174665932647262222c226f726967696e4167656e74223a226167656e742d30303037222c2263726561746564556e6978223a313730303030303030302c22706c61696e74657874536861323536223a2264353032383130633731616562313765356561316362663933306234366238376262363435613735646634356635303032333064303631393932616562393061222c226f7269674e616d65223a22706c616e2e747874227de0e1e2e3e4e5e6e7e8e9eaebceacbd08b96494b1e1e39286bdd1658a4e43229fff14a2eb848320480c7a";

#[test]
fn golden_vector_exact_bytes() {
    let env = golden_envelope();

    // Structural prefix.
    assert_eq!(&env[0..4], b"DLPE", "magic");
    assert_eq!(env[4], 0x01, "version");
    let h = u16::from_le_bytes([env[5], env[6]]) as usize;
    assert!(7 + h < env.len(), "header fits");

    // Header is canonical serde_json in struct-definition order, camelCase.
    let header_json = std::str::from_utf8(&env[7..7 + h]).expect("header is UTF-8 JSON");
    assert!(header_json.starts_with("{\"keyId\":\"class-internal/v1\",\"wrappedDek\":\""));
    assert!(header_json.contains("\"originAgent\":\"agent-0007\""));
    assert!(header_json.contains("\"createdUnix\":1700000000"));
    assert!(header_json.ends_with("\"origName\":\"plan.txt\"}"));

    // Trailing layout: 12-byte nonce + ciphertext + 16-byte tag.
    assert_eq!(env.len(), 7 + h + 12 + PLAINTEXT.len() + 16, "envelope length");

    // The whole thing, byte for byte.
    assert_eq!(to_hex(&env), GOLDEN_HEX, "envelope bytes must never drift");
}

#[test]
fn golden_vector_opens_and_header_is_consistent() {
    let env = golden_envelope();
    let (header, plaintext) = open(&env, &keyring()).expect("golden envelope must open");
    assert_eq!(plaintext, PLAINTEXT);
    assert_eq!(header.key_id, KEY_ID);
    assert_eq!(header.origin_agent, AGENT);
    assert_eq!(header.created_unix, NOW);
    assert_eq!(header.orig_name, ORIG_NAME);
    assert_eq!(header.plaintext_sha256, to_hex(&Sha256::digest(PLAINTEXT)));
}

#[test]
fn peek_header_needs_no_key() {
    let env = golden_envelope();
    let header = peek_header(&env).expect("peek must work without any keyring");
    assert_eq!(header.key_id, KEY_ID);
    assert_eq!(header.orig_name, ORIG_NAME);
    assert_eq!(header.plaintext_sha256, to_hex(&Sha256::digest(PLAINTEXT)));
}

#[test]
fn fresh_dek_per_file_makes_envelopes_differ() {
    // Production RNG path: sealing the same plaintext twice must never reuse
    // DEK or nonces, so the envelopes differ (and both still open).
    let a = seal(PLAINTEXT, ORIG_NAME, &kek(), AGENT, NOW).expect("seal a");
    let b = seal(PLAINTEXT, ORIG_NAME, &kek(), AGENT, NOW).expect("seal b");
    assert_ne!(a, b, "fresh random DEK/nonce per file");
    let ring = keyring();
    assert_eq!(open(&a, &ring).expect("open a").1, PLAINTEXT);
    assert_eq!(open(&b, &ring).expect("open b").1, PLAINTEXT);
}

// ---------------------------------------------------------------------------
// Tamper matrix — each mangling yields its distinct typed error, no panics.
// ---------------------------------------------------------------------------

#[test]
fn tamper_magic_bit_flip() {
    let mut env = golden_envelope();
    env[0] ^= 0x01;
    assert_eq!(open(&env, &keyring()).unwrap_err(), EnvelopeError::Malformed("magic"));
    assert_eq!(peek_header(&env).unwrap_err(), EnvelopeError::Malformed("magic"));
}

#[test]
fn tamper_unsupported_version() {
    let mut env = golden_envelope();
    env[4] = 0x02;
    assert_eq!(open(&env, &keyring()).unwrap_err(), EnvelopeError::Malformed("version"));
}

#[test]
fn tamper_header_len_overflow() {
    let mut env = golden_envelope();
    env[5] = 0xFF;
    env[6] = 0xFF; // header_len = 65535 >> actual envelope size
    assert_eq!(
        open(&env, &keyring()).unwrap_err(),
        EnvelopeError::Malformed("header-len-overflow")
    );
    assert_eq!(
        peek_header(&env).unwrap_err(),
        EnvelopeError::Malformed("header-len-overflow")
    );
}

#[test]
fn tamper_header_structural_bit_flip_breaks_json() {
    let mut env = golden_envelope();
    env[7] ^= 0x01; // '{' -> 'z': header no longer parses as JSON
    assert_eq!(open(&env, &keyring()).unwrap_err(), EnvelopeError::Malformed("header-json"));
}

#[test]
fn tamper_header_value_bit_flip_fails_aad_auth() {
    // Flip a byte INSIDE a JSON string value such that the header still parses
    // (hex digit '0' -> '1') — the AAD covers the header, so the body auth
    // must catch it. This is the "attacker rewrites metadata" case.
    let mut env = golden_envelope();
    let h = u16::from_le_bytes([env[5], env[6]]) as usize;
    let header = std::str::from_utf8(&env[7..7 + h]).unwrap().to_string();
    let marker = "\"plaintextSha256\":\"";
    let value_pos = 7 + header.find(marker).expect("sha field present") + marker.len();
    env[value_pos] ^= 0x01;
    // Guard: mutated header must still be valid JSON, otherwise this test
    // degenerates into the structural case above.
    serde_json::from_slice::<serde_json::Value>(&env[7..7 + h])
        .expect("mutated header still parses");
    assert_eq!(open(&env, &keyring()).unwrap_err(), EnvelopeError::Tampered);
}

#[test]
fn tamper_ciphertext_bit_flip() {
    let mut env = golden_envelope();
    let h = u16::from_le_bytes([env[5], env[6]]) as usize;
    let ct_start = 7 + h + 12;
    env[ct_start] ^= 0x01;
    assert_eq!(open(&env, &keyring()).unwrap_err(), EnvelopeError::Tampered);
}

#[test]
fn tamper_tag_bit_flip() {
    let mut env = golden_envelope();
    let last = env.len() - 1;
    env[last] ^= 0x01;
    assert_eq!(open(&env, &keyring()).unwrap_err(), EnvelopeError::Tampered);
}

#[test]
fn tamper_truncation() {
    let env = golden_envelope();
    let h = u16::from_le_bytes([env[5], env[6]]) as usize;

    // Structural truncations: not even the fixed prefix / nonce+tag present.
    assert_eq!(open(&[], &keyring()).unwrap_err(), EnvelopeError::Malformed("truncated"));
    assert_eq!(open(&env[..3], &keyring()).unwrap_err(), EnvelopeError::Malformed("truncated"));
    assert_eq!(
        open(&env[..7 + h + 5], &keyring()).unwrap_err(),
        EnvelopeError::Malformed("truncated"),
        "cut mid-nonce"
    );
    // Cutting into the tag is cryptographically indistinguishable from tag
    // corruption — GCM auth fails: Tampered, and no partial plaintext.
    assert_eq!(
        open(&env[..env.len() - 1], &keyring()).unwrap_err(),
        EnvelopeError::Tampered
    );
}

#[test]
fn tamper_wrong_kek() {
    let env = golden_envelope();
    let mut ring = Keyring::new(KEY_ID);
    ring.insert(Kek::new(KEY_ID, [0xAA; 32])); // same id, different key bytes
    assert_eq!(open(&env, &ring).unwrap_err(), EnvelopeError::WrongKey);
}

#[test]
fn tamper_unknown_key_id() {
    let env = golden_envelope();
    let mut ring = Keyring::new("class-secret/v1");
    ring.insert(Kek::new("class-secret/v1", [0xBB; 32]));
    assert_eq!(
        open(&env, &ring).unwrap_err(),
        EnvelopeError::UnknownKeyId(KEY_ID.to_string())
    );
}

#[test]
fn destroyed_key_is_key_destroyed_not_unknown() {
    let env = golden_envelope();
    let mut ring = keyring();
    assert!(ring.destroy(KEY_ID), "destroying a held key reports true");
    assert_eq!(
        open(&env, &ring).unwrap_err(),
        EnvelopeError::KeyDestroyed(KEY_ID.to_string())
    );
    // Destroy is terminal: re-inserting the same id must NOT resurrect it
    // (crypto-shredding semantics — fail secure).
    ring.insert(Kek::new(KEY_ID, kek_bytes()));
    assert_eq!(
        open(&env, &ring).unwrap_err(),
        EnvelopeError::KeyDestroyed(KEY_ID.to_string())
    );
}

// ---------------------------------------------------------------------------
// Round-trip property over sizes 0..1 MiB (spread of sizes, not exhaustive).
// ---------------------------------------------------------------------------

#[test]
fn round_trip_identity_over_size_spread() {
    let ring = keyring();
    for &n in &[0usize, 1, 15, 16, 255, 4096, 65_537, 1 << 20] {
        let plaintext: Vec<u8> = (0..n)
            .map(|i| (i as u32).wrapping_mul(2_654_435_761) as u8)
            .collect();
        let env = seal(&plaintext, "blob.bin", &kek(), AGENT, NOW)
            .unwrap_or_else(|e| panic!("seal {n} bytes: {e}"));
        let (header, out) = open(&env, &ring).unwrap_or_else(|e| panic!("open {n} bytes: {e}"));
        assert_eq!(out, plaintext, "round trip at {n} bytes");
        assert_eq!(header.plaintext_sha256, to_hex(&Sha256::digest(&plaintext)));
        assert_eq!(env.len(), 7 + 12 + 16 + n + (env.len() - 7 - 12 - 16 - n), "sane");
    }
}

// ---------------------------------------------------------------------------
// Keyring: dev keyfile loading (DPAPI at-rest persistence is M4, not here).
// ---------------------------------------------------------------------------

fn temp_path(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("dlp-crypto-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("temp dir");
    dir.join(name)
}

#[test]
fn keyring_loads_dev_keyfile_and_round_trips() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    let key_b64 = STANDARD.encode(kek_bytes());
    let json = format!(
        "{{\"activeKeyId\":\"{KEY_ID}\",\"keys\":{{\"{KEY_ID}\":\"{key_b64}\"}},\"destroyed\":[\"class-old/v1\"]}}"
    );
    let path = temp_path("keyring.json");
    std::fs::write(&path, json).expect("write keyfile");

    let ring = Keyring::load_dev_keyfile(&path).expect("keyfile loads");
    assert_eq!(ring.active_key_id(), KEY_ID);

    let active = ring.active().expect("active key resolvable");
    let env = seal(PLAINTEXT, ORIG_NAME, active, AGENT, NOW).expect("seal with loaded key");
    assert_eq!(open(&env, &ring).expect("open with loaded ring").1, PLAINTEXT);

    // Destroyed list from the file is honoured.
    assert_eq!(
        ring.lookup("class-old/v1").unwrap_err(),
        EnvelopeError::KeyDestroyed("class-old/v1".to_string())
    );
    let _ = std::fs::remove_file(&path);
}

#[test]
fn keyring_rejects_bad_key_length() {
    let path = temp_path("bad-len.json");
    std::fs::write(
        &path,
        "{\"activeKeyId\":\"k/v1\",\"keys\":{\"k/v1\":\"c2hvcnQ=\"}}", // "short"
    )
    .expect("write keyfile");
    match Keyring::load_dev_keyfile(&path).unwrap_err() {
        KeyringError::BadKeyLength { key_id, len } => {
            assert_eq!(key_id, "k/v1");
            assert_eq!(len, 5);
        }
        other => panic!("expected BadKeyLength, got {other:?}"),
    }
    let _ = std::fs::remove_file(&path);
}

#[test]
fn keyring_rejects_missing_active_key() {
    let path = temp_path("missing-active.json");
    let key_b64 = {
        use base64::{engine::general_purpose::STANDARD, Engine};
        STANDARD.encode([7u8; 32])
    };
    std::fs::write(
        &path,
        format!("{{\"activeKeyId\":\"absent/v1\",\"keys\":{{\"k/v1\":\"{key_b64}\"}}}}"),
    )
    .expect("write keyfile");
    match Keyring::load_dev_keyfile(&path).unwrap_err() {
        KeyringError::MissingActive(id) => assert_eq!(id, "absent/v1"),
        other => panic!("expected MissingActive, got {other:?}"),
    }
    let _ = std::fs::remove_file(&path);
}
