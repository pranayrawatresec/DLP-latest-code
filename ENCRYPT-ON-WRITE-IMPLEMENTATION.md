# Trusted-Destination Encryption (Encrypt-on-Write) — Implementation Spec

> **Audience: the coding agent that will implement this.** This document is
> self-contained: it describes the feature, the existing code you will extend
> (with exact file paths and the contracts you must not break), the new modules
> to create, wire formats, server changes, and milestone-by-milestone tasks with
> acceptance criteria. Read `CLAUDE.md` (repo root) first for the project rules;
> read `ENCRYPTION-FEATURES-README.md` for the market research and threat model
> behind this design. Status of this doc: **approved design, not yet built.**

---

## 1. The feature in one paragraph

Administrators **whitelist destinations** — a specific USB stick (by serial/VID:PID),
a webmail/upload origin, later an email recipient domain. Sensitive data flowing to a
whitelisted destination is **not blocked — it is always encrypted in transit onto that
destination**: the file lands as a `.dlpenc` envelope (AES-256-GCM, org-held keys)
that only enrolled endpoints of the same organisation can open. Non-whitelisted
destinations keep today's behaviour (audit / read-only / block). This turns the
whitelist from a hole in the policy ("trusted = uninspected") into a *stronger*
control ("trusted = usable, but the data is armoured"). Decryption on enrolled
endpoints is policy-checked and audited; revoking enrollment revokes access.

Two encryption modes per whitelisted destination:

| Mode | Behaviour |
|---|---|
| `encrypt_sensitive` | Files whose detection verdict scores in the sensitive band are sealed; clean files pass in plaintext |
| `encrypt_all` | **Every** file written to this destination is sealed, no verdict needed (courier-stick mode; also covers files detection can't read) |

Fail-secure composition: if the verdict is `Extraction::Unreadable` (encrypted zip,
unknown format) on an `encrypt_sensitive` destination, treat it as sensitive → seal it.

---

## 2. Repo map — what already exists that you will touch

Working tree layout (see `CLAUDE.md` for the product context):

```
dlp-agent/                  Rust agent (runs on every endpoint)
  src/detect/               ❄ FROZEN content-detection engine — DO NOT MODIFY.
    verdict.rs              verdict(path) / verdict_bytes(content, name, bundle) /
                            verdict_text(text) → Verdict { idm[], edm[], extraction }.
                            Audit-only by contract: thresholds are applied by CHANNELS.
  src/usb/                  USB removable-media channel (user mode)
    policy.rs               PURE decision engine. `Action { AllowAudited, ReadOnly,
                            Block }` + restrictiveness ordering; `RuleMatch
                            { Serial, VidPid, BusType, Any }`; `DeviceRule`;
                            `UsbPolicy { default_action, rules }`; `decide()` =
                            first-match-wins. THIS is where the whitelist lives.
    audit.rs                CopyAuditor: settle/dedup/scan pipeline over files
                            appearing on a mounted volume. Injectable root dir,
                            injectable clock (`poll(now_ms)`), injectable verdict
                            fn — everything unit-testable without hardware.
                            `ActionTaken { Audited, ReadOnly, Blocked }`,
                            `IncidentKind`, `UsbIncident` (the local incident record).
    enforce.rs              plan()/apply() dry-run discipline. Tests NEVER touch
                            the live system; they assert on `PlannedAction`.
    device.rs / watch.rs / queue.rs   identity, volume polling, offline queue.
  src/kguard/mod.rs         User-mode client of the minifilter port \DlpFltPort.
                            Wire protocol v2 (content-over-port): #[repr(C)]
                            size-locked mirrors of dlpflt.h; DLP_VERDICT_ALLOW=0,
                            DLP_VERDICT_BLOCK=1; bump DLP_MSG_VERSION on ANY change
                            and keep dlpflt.h byte-identical.
  src/browser_host.rs       Native-messaging host for the browser extension.
                            PINNED framing: 4-byte LE length + UTF-8 JSON.
                            Requests: scan_text | scan_file | scan_bytes (base64,
                            ≤4 MiB raw). Reply: {verdict: allow|block|warn, ...}.
                            NOTE: Chrome caps host→extension messages at 1 MB —
                            anything larger must be chunked (see §7.3).
  src/clipboard/            clipboard channel (thresholds mirror kguard's).
  src/netfilter/            WFP egress control + TCP reset; no content visibility
                            inside TLS (that's what the browser extension is for).
  src/config.rs             TOML config. Sections: [usb] UsbConfig (line ~131),
                            [kguard] KguardConfig with block_at=0.30 /
                            coverage_block_at=0.60 defaults, [clipboard], [netfilter],
                            [notify]. New sections go here with serde defaults.
  src/checkin.rs, enroll.rs, identity.rs, client.rs   mTLS enrollment + check-in.
  src/storage.rs            local agent state.
dlp-browser-ext/            MV3 extension: background.js, content.js, inject.js —
                            intercepts <input type=file> / drag-drop / fetch uploads,
                            calls the native host, blocks on `block`.
dlp-minifilter/             Kernel driver (C): dlpflt.c/.h, comms.c, wfpcallout.c.
                            Reads file content IN-KERNEL, ships ≤4 MiB over the port,
                            quarantines on BLOCK. Test-signing + reboot to load —
                            kernel changes are a LATER milestone (M8), not v1.
dlp-management-server/      Node/Express + PostgreSQL, hand-written SQL, RBAC,
                            append-only hash-chained audit log.
  agent/agentApp.js         the mTLS agent-facing API (check-in etc.).
  routes/, lib/rbac.js, migrations/   admin API, RBAC gates, schema migrations
                            (next free number: 006).
```

**House rules you must follow** (from `CLAUDE.md` + module docs — violations are
review-blockers):

1. `dlp-agent/src/detect/` is **frozen**. Channels apply thresholds; detect only reports.
2. **Never log or transmit file content**, extracted text, keys, or recovery secrets.
   Incidents carry hashes/scores/metadata only.
3. **Fail secure.** Missing bundle, unreachable server, unreadable file ⇒ the more
   restrictive outcome, never silent allow.
4. Pure logic in its own module with unit tests; OS calls `#[cfg(windows)]`-gated
   with non-Windows stubs (pattern: `usb/policy.rs` vs `usb/enforce.rs`).
5. Enforcement follows the **dry-run contract**: `plan()` returns an inspectable
   value; `apply()` touches the system only in `Mode::Live`; tests assert on plans.
6. Server: parameterised SQL only; two-gate (authn 401 → authz 403) on every route;
   every state-changing action and every secret access writes an audit entry.
7. Keep dependencies minimal. This feature's approved additions — **Rust:
   `aes-gcm`, `zeroize`** (RustCrypto; serde/serde_json already present).
   **Node: none** (use built-in `crypto`).
8. `#[repr(C)]` wire structs are size-locked with `const` asserts; any change to
   the kernel protocol bumps `DLP_MSG_VERSION` in BOTH `kguard/mod.rs` and `dlpflt.h`.

---

## 3. Policy model (the generalisation)

One concept serves every channel: a **trusted destination** = (channel, matcher,
encrypt mode, key id). Keep per-channel matcher types — don't force USB serials and
URL origins into one stringly-typed matcher.

### 3.1 New Rust types

`dlp-agent/src/usb/policy.rs` — extend the existing enum (keep serde snake_case;
TOML string `encrypt`):

```rust
pub enum Action {
    AllowAudited,
    Encrypt,      // NEW — writes proceed but land sealed (mode in the rule)
    ReadOnly,
    Block,
}
// restrictiveness: AllowAudited=0 < Encrypt=1 < ReadOnly=2 < Block=3.
// Encrypt is LESS restrictive than ReadOnly (writes still happen, transformed).
// max_restrictive() keeps working unchanged. Update every exhaustive match arm
// the compiler flags — do NOT add a catch-all `_ =>`.
```

New shared types in a new module `dlp-agent/src/trustdest.rs` (pure, no I/O):

```rust
/// How much gets sealed on a trusted destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EncryptMode { EncryptSensitive, EncryptAll }

/// Verdict band thresholds for `EncryptSensitive` (channel-owned, detect stays
/// audit-only). Defaults mirror [kguard]: block_at 0.30 / coverage 0.60; the
/// encrypt band sits UNDER the block band:
///   containment >= block_at            → Block   (unchanged)
///   encrypt_at <= containment < block_at, or any EDM hit, or Unreadable
///                                      → Seal
///   else                               → Plain
#[derive(Debug, Clone, Copy, Deserialize)]
pub struct EncryptBands { pub encrypt_at: f64 /* default 0.05 */,
                          pub block_at: f64, pub coverage_block_at: f64 }

/// Pure decision: what to do with ONE settled file on an Encrypt destination.
pub enum SealDecision { Plain, Seal, Block }
pub fn decide_seal(mode: EncryptMode, bands: &EncryptBands,
                   verdict: Option<&detect::Verdict>) -> SealDecision;
```

`decide_seal` rules (write these as table-driven unit tests first):
`EncryptAll` ⇒ always `Seal` (no verdict needed — do not even require a bundle).
`EncryptSensitive` + no bundle available ⇒ `Seal` (fail secure).
`EncryptSensitive` + `Extraction::Unreadable` ⇒ `Seal`.
Verdict in block band ⇒ `Block` (whitelisting a stick must never *weaken* the
block threshold). Verdict in encrypt band or any EDM hit ⇒ `Seal`. Else `Plain`.

### 3.2 Config (TOML first, server-synced later — M6)

`agent.example.toml` additions (implement in `config.rs` with serde defaults):

```toml
[usb]
# existing keys unchanged; rules gain optional encryption fields:
#   action = "encrypt" selects the new Action::Encrypt
#   mode   = "encrypt_all" | "encrypt_sensitive"   (default encrypt_sensitive)
#   key_id = "class-internal/v1"                    (default from [crypto])
rules = [
  { match = "serial", value = "0401396FBBF0C89E", action = "encrypt", mode = "encrypt_all", note = "site-A courier stick" },
  { match = "vid_pid", vid = "0951", pid = "1666", action = "encrypt" },
]

[crypto]
default_key_id = "class-internal/v1"
encrypt_at = 0.05           # lower edge of the seal band (EncryptSensitive)
# block_at / coverage_block_at are read from [kguard] to keep one source of truth.

[webupload]                  # consumed by browser_host (M7)
trusted_origins = [
  { origin = "https://mail.internal.example", mode = "encrypt_sensitive" },
]
```

---

## 4. The `.dlpenc` envelope — exact format

New module `dlp-agent/src/crypto/envelope.rs`. Pure functions over byte slices —
no I/O in this file; golden-vector tested cross-platform.

```
offset  size  field
0       4     magic = "DLPE"
4       1     version = 0x01
5       2     header_len (u16 LE) = H
7       H     header: canonical JSON (serde_json to_vec of the struct below —
              field order fixed by struct definition; no floats)
7+H     12    nonce (96-bit, OS CSPRNG, unique per file)
7+H+12  ..    ciphertext = AES-256-GCM(key=DEK, nonce, plaintext,
              aad = bytes[0 .. 7+H])          ← magic+version+len+header are ALL
7+H+12+C 16   GCM tag                            authenticated; tamper ⇒ open fails
```

Header struct (serde, camelCase to match the wire conventions in `verdict.rs`):

```rust
struct EnvelopeHeader {
    key_id: String,          // "class-internal/v1" — KEK id/version (crypto-shred unit)
    wrapped_dek: String,     // base64: AES-256-GCM(KEK, dek_nonce, DEK) — see below
    dek_nonce: String,       // base64 96-bit nonce used to wrap the DEK
    origin_agent: String,    // agent id (from identity.rs), NOT hostname
    created_unix: u64,
    plaintext_sha256: String,// hex — correlates with UsbIncident.file_sha256
    orig_name: String,       // original filename (name only, no path)
}
```

API (all errors are one typed enum `EnvelopeError` — never `anyhow` here, callers
must be able to distinguish `WrongKey` / `Tampered` / `Malformed` / `KeyDestroyed`):

```rust
pub fn seal(plaintext: &[u8], orig_name: &str, key: &Kek, agent_id: &str,
            now_unix: u64) -> Result<Vec<u8>, EnvelopeError>;
pub fn open(envelope: &[u8], keyring: &Keyring)
            -> Result<(EnvelopeHeader, Vec<u8>), EnvelopeError>;
pub fn peek_header(envelope: &[u8]) -> Result<EnvelopeHeader, EnvelopeError>; // no key needed
```

Rules: fresh random 256-bit DEK per file; DEK and plaintext buffers `zeroize`d on
drop; `seal` takes `now_unix` as a parameter (injected clock — house style, and it
keeps golden vectors deterministic); RNG injected behind a trait for tests, OS
CSPRNG (`aes_gcm::aead::OsRng`) in production. Extension on disk: original name +
`.dlpenc` (e.g. `plan.docx.dlpenc`), original name also inside the (authenticated)
header so renames don't lose it.

### 4.1 Keys — `dlp-agent/src/crypto/keyring.rs`

```
Org Root Key (ORK, 256-bit)      server-side only, .env DLP_ORG_ROOT_KEY (dev) → HSM later
  └── KEK "class-<name>/v<N>"    generated server-side; stored wrapped-by-ORK;
                                 delivered to agents over mTLS (M6); until M6, dev
                                 mode reads a local keyfile (see below)
        └── DEK (per file)       random; wrapped by KEK; lives only in the header
```

`Keyring` holds `HashMap<String, Kek>` (`Kek` = 32 bytes, `Zeroize + ZeroizeOnDrop`),
`active_key_id: String`. Persistence on the agent: encrypted at rest with **DPAPI
(user-independent machine scope, `CryptProtectData` with `CRYPTPROTECT_LOCAL_MACHINE`)**
under the agent data dir; `#[cfg(windows)]`-gated, non-Windows stub stores plaintext
ONLY under `#[cfg(test)]`/dev builds with a loud comment. Until M6 lands, `[crypto]
keyfile = "path"` (dev only, git-ignored) lets the feature run end-to-end.

**Offline behaviour (fail-secure, matches cached-policy semantics):** sealing and
opening use the locally cached keyring — no server round-trip on the hot path ever.
Key revocation/rotation propagates at check-in; bounded staleness is accepted and
documented in the incident (`keyId` says which version sealed it).

---

## 5. USB channel integration (user-mode v1)

### 5.1 Where the seal happens

`usb/audit.rs` — the `CopyAuditor` already: detects a settled file → runs the
injected verdict fn → raises `UsbIncident`. Extend the pipeline: when the volume's
policy action is `Encrypt`, after the verdict comes back, call `decide_seal(...)`:

- `SealDecision::Plain` → today's behaviour (audit incident if any match).
- `SealDecision::Seal` → **seal-in-place** on the volume:
  1. read plaintext fully (the settle machinery already guarantees the writer is done),
  2. write `<name>.dlpenc.tmp` beside it, fsync,
  3. atomically rename to `<name>.dlpenc`,
  4. delete the plaintext original,
  5. raise incident with new `ActionTaken::Encrypted` + `key_id` + both hashes.
  Any failure in 1–4 ⇒ do NOT delete the plaintext; raise
  `IncidentKind::EnforcementFailed` with the error note (fail secure = the copy is
  still flagged; nothing is silently lost or silently left unprotected without a record).
- `SealDecision::Block` → keep the existing block/quarantine path.

Add `ActionTaken::Encrypted` to `audit.rs` and thread it through the `From<Action>`
impl (Encrypt maps to `Encrypted` only after a successful seal — the *planned*
action and the *taken* action differ on failure; keep them distinct in the incident).

Extend `UsbIncident` with `pub key_id: Option<String>` and (for sealed files)
`pub sealed_sha256: Option<String>`. The server wire contract is additive-only.

**Known, documented limitation of v1:** plaintext exists on the stick between the
OS write and our seal (settle window, seconds). State this in the incident note
(`"sealed-post-write"`). Closing the window is the kernel milestone M8 — do not
attempt it in user mode with locks/oplocks tricks.

### 5.2 The whitelist is the existing rule engine

No new matching machinery: `RuleMatch::Serial` / `VidPid` already express the
whitelist; the new `action = "encrypt"` on those rules IS the trusted-destination
marker. `decide()` (first-match-wins) is untouched. Remember the module's own
security note: serials are spoofable — this is exactly why `Encrypt` (data is
armoured regardless) is a *better* whitelist action than `AllowAudited`.

### 5.3 Decrypt on enrolled endpoints

New subcommand: `dlp-agent decrypt <file.dlpenc> [-o out]` —
`peek_header` → load keyring → policy check → `open()` → **queue an audit incident
first** (channel `"decrypt"`, key id, plaintext hash, agent id, outcome), then write
the plaintext. If the key id is unknown/destroyed ⇒ typed error + incident
(`IncidentKind` gains `DecryptDenied` — someone holding old/foreign media is signal,
see UC-5 in the research doc). Explorer context-menu registration is a later polish
task (registry `HKCR\.dlpenc` — goes through `enforce.rs`-style plan/apply).

---

## 6. Management-server integration (M6)

### 6.1 Migration `migrations/006_encryption_keys.sql`

```sql
CREATE TABLE encryption_keys (
  id            TEXT PRIMARY KEY,          -- 'class-internal/v1'
  classification TEXT NOT NULL,            -- 'internal', 'secret', ...
  version       INTEGER NOT NULL,
  wrapped_kek   BYTEA NOT NULL,            -- AES-256-GCM under ORK (nonce||ct||tag)
  state         TEXT NOT NULL CHECK (state IN ('active','rotated','destroyed')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  destroyed_at  TIMESTAMPTZ,
  destroyed_by  TEXT,                      -- user id; two-person rule enforced in code
  UNIQUE (classification, version)
);

CREATE TABLE trusted_destinations (
  id          SERIAL PRIMARY KEY,
  channel     TEXT NOT NULL CHECK (channel IN ('usb','web_upload','email')),
  matcher     JSONB NOT NULL,   -- {"serial":"..."} | {"vid":"..","pid":".."} | {"origin":"https://.."}
  mode        TEXT NOT NULL CHECK (mode IN ('encrypt_sensitive','encrypt_all')),
  key_id      TEXT NOT NULL REFERENCES encryption_keys(id),
  note        TEXT,
  created_by  TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

(BitLocker escrow — `ENCRYPTION-FEATURES-README.md` §5.1 — shares this migration
number-space; if that lands first, this becomes 007. Check `migrations/` before writing.)

### 6.2 Endpoints

Agent-facing (`agent/agentApp.js`, inside the existing mTLS identity):
- `GET /agent/api/v1/keys` → active + rotated KEKs the agent's policy references,
  **plaintext KEK inside the mTLS body** (the channel is the protection — same
  trust level as the policy bundle it already receives). Response also carries
  `trusted_destinations` for this agent's policy. Agent merges over TOML: synced
  rules take precedence; on conflict the **more restrictive action wins**
  (`Action::max_restrictive`).

Admin-facing (new `routes/encryption.js`, two-gate like every route):
- `POST /api/encryption/keys` (create/rotate) — `sysadmin`.
- `POST /api/encryption/keys/:id/destroy` — two-person: first call records a
  pending request; a **different** privileged user confirms. Overwrite
  `wrapped_kek` with random bytes, set state/destroyed_at/destroyed_by. Audit both steps.
- `GET/POST/DELETE /api/encryption/trusted-destinations` — `policy_author`.
- Every plaintext-KEK egress (the agent endpoint) writes an audit entry:
  agent id, key ids, timestamp. Never log key material (rule 2).

RBAC additions in `lib/rbac.js`: `encryption_keys:manage` (sysadmin),
`trusted_destinations:write` (policy_author), `encryption_keys:destroy_confirm`
(the second-person permission — grant to incident_reviewer per the separation-of-
duties table; flag if one user holds both destroy permissions, per `CLAUDE.md`).

Server-side crypto: Node built-in `crypto` (`createCipheriv('aes-256-gcm')`) —
**no new npm dependency**. ORK from `process.env.DLP_ORG_ROOT_KEY` (32-byte hex);
refuse to boot the encryption routes without it (fail secure, no default key).

---

## 7. Web-upload / webmail channel (M7)

Email v1 = **webmail attachments through the existing browser extension**. There is
no SMTP/Outlook interception in this phase (a MAPI/COM add-in is future work; note
it in incidents as out-of-scope). "Whitelisted email" therefore means a **trusted
webmail origin** (e.g. the org's OWA/Gmail tenant): uploads there get sealed instead
of blocked.

### 7.1 Flow

`inject.js`/`content.js` already intercept `<input type=file>` / drag-drop / fetch
bodies and send `scan_bytes` (base64, ≤4 MiB raw) to the native host
(`browser_host.rs`). Extend the PINNED protocol **additively** (old extension +
new host and vice versa must not break — version-gate on request `version`):

```
Request  v2 (ext→host): unchanged fields + "version":2
Reply    v2 (host→ext): verdict gains "encrypt":
  {"version":2,"id":n,"verdict":"encrypt","sealId":"<uuid>","sealedSize":m,
   "chunkCount":k,"sealedName":"plan.docx.dlpenc"}
Chunk fetch (ext→host): {"version":2,"kind":"get_sealed_chunk","sealId":"..","index":i}
Chunk reply (host→ext): {"version":2,"sealId":"..","index":i,"data_b64":"..."}  ≤ 700 KiB raw
Done     (ext→host):    {"version":2,"kind":"seal_done","sealId":".."}   → host drops buffer
```

Chunking is REQUIRED: Chrome caps host→extension messages at **1 MB** (the module
doc in `browser_host.rs` already records this asymmetry). Host keeps sealed bytes
in an in-memory map keyed by `sealId` with a TTL (60 s) and a cap (8 entries /
64 MiB) — evict oldest, and a `get_sealed_chunk` for an evicted id returns a typed
error the extension maps to "block upload, tell user to retry".

Extension side: on `verdict:"encrypt"`, reassemble chunks into a `File` named
`sealedName` and swap it into the upload (`DataTransfer` for inputs; rebuild the
`FormData`/body for fetch interception — the harder path; if body rebuild is not
achievable for a given site pattern, **fall back to block** with reason
`encrypt-unavailable`, never fall back to plaintext-allow. Fail secure.).

### 7.2 Decision logic

`browser_host` matches request `origin` against `[webupload] trusted_origins`
(exact origin match, then registrable-domain suffix match). On match → run the
verdict as today → `decide_seal(...)` with the origin's mode → allow / encrypt /
block reply. Off-list origins: existing behaviour, no change. The >4 MiB upload
case (extension caps reads) on an `encrypt_all` origin ⇒ reply `block` with reason
`too-large-to-seal` (documented limitation; do not stream-seal in v1).

---

## 8. Kernel-assisted seal — M8, design-only for now

Goal: close the plaintext settle window of §5.1. Direction (do NOT start without
the driver owner): new verdict code `DLP_VERDICT_ENCRYPT = 2` in `dlpflt.h` +
`kguard/mod.rs` (bump `DLP_MSG_VERSION` to 3); on write-reason scans to removable
volumes the driver holds the file (existing quarantine machinery) while user mode
re-reads the FULL file (the port carries only ≤4 MiB), seals, writes the sibling,
then replies to release+delete the original. Everything in this doc works without
M8 — build M1–M7 first, in order.

---

## 9. Milestones — build in this order

Each milestone is independently shippable and PR-sized. Write the tests listed
BEFORE wiring the milestone into `main.rs`.

### M1 — `crypto/envelope.rs` + `crypto/keyring.rs` (pure core)
- [ ] Add `aes-gcm`, `zeroize` to `dlp-agent/Cargo.toml` (only these).
- [ ] Implement §4 exactly. `EnvelopeError` typed enum. Injected RNG + clock.
- [ ] Golden vectors: fixed key/nonce/plaintext → assert exact envelope bytes
      (commit vectors under `dlp-agent/tests/`, pattern: `verdict_bytes.rs`).
- [ ] Tamper matrix tests: bit-flip in ciphertext / header / magic / tag; truncated
      file; wrong KEK; unknown key_id; header_len overflow → each yields its
      distinct `EnvelopeError`, never a panic, never partial plaintext out.
- [ ] round-trip property test (any bytes 0..1 MiB seal→open == identity).
**Accept:** `cargo test` green on Windows AND non-Windows (pure module, no cfg).

### M2 — policy plumbing
- [ ] `Action::Encrypt` in `usb/policy.rs` (+restrictiveness table §3.1); fix every
      exhaustive match the compiler surfaces (`enforce.rs` plans `NoChange` for
      Encrypt — device-level nothing changes; the file-level seal is the auditor's job).
- [ ] `trustdest.rs` with `EncryptMode`, `EncryptBands`, `decide_seal` + the full
      decision-table unit tests from §3.1 (including fail-secure rows).
- [ ] `config.rs`: `[crypto]`, `[webupload]`, extended `[usb]` rule fields, serde
      defaults; update `agent.example.toml` (§3.2).
**Accept:** existing USB policy tests still pass unmodified (ordering change is
additive); new decision-table tests green.

### M3 — USB seal-in-place
- [ ] Extend `CopyAuditor` per §5.1 (injected verdict fn + injected SEALER fn —
      tests inject a fake sealer and assert call/no-call + incident shape).
- [ ] `ActionTaken::Encrypted`, `UsbIncident.key_id/sealed_sha256`,
      `IncidentKind::DecryptDenied`.
- [ ] Integration test against a temp dir masquerading as the volume (existing
      pattern in `audit.rs` docs): write file → poll(now) → settled → sealed
      sibling exists, plaintext gone, incident recorded. Failure-path test:
      sealer errors ⇒ plaintext kept + `EnforcementFailed`.
**Accept:** end-to-end temp-dir test green; no test touches real hardware.

### M4 — decrypt path
- [ ] `dlp-agent decrypt` subcommand (§5.3) + audit incident BEFORE plaintext write.
- [ ] DPAPI keyring-at-rest (`#[cfg(windows)]`; dev keyfile fallback).
**Accept:** seal on machine A dev-keyfile, open on machine B with same keyfile;
open with missing key ⇒ `DecryptDenied` incident, exit non-zero.

### M5 — operator demo runbook
- [ ] `ENCRYPT-DEMO-RUNBOOK.md` (pattern: `USB-DEMO-RUNBOOK.md`): whitelist a real
      stick's serial with `encrypt_all`, copy files, show `.dlpenc` on the stick,
      show decrypt + incidents on the console. This is the manual-verification
      gate for M1–M4 (module docs stay honest about what is machine-verified vs
      operator-verified — keep that discipline).

### M6 — server: keys + trusted destinations + sync
- [ ] Migration (§6.1 — renumber if 006 is taken), routes (§6.2), RBAC perms,
      audit entries, two-person destroy flow.
- [ ] Agent: fetch keys+destinations at check-in (`checkin.rs`), merge over TOML
      (more-restrictive-wins), persist via keyring.
- [ ] Server route tests: RBAC 401/403 matrix, audit-per-access, destroy needs two
      distinct users, param-SQL only.
**Accept:** fresh agent enrolls → receives KEK + destinations → seals with the
synced key with NO `[crypto] keyfile` configured.

### M7 — web-upload/webmail channel
- [ ] Protocol v2 + chunking in `browser_host.rs` (§7.1) — unit-test framing,
      chunk math, TTL eviction, version-gating (v1 requests still work).
- [ ] Extension: reassemble + swap for `<input type=file>` and drag-drop; fetch-body
      rebuild where feasible; block-fallback otherwise (§7.1). Update
      `dlp-browser-ext/README.md` manual test list.
**Accept:** manual (runbook): upload to whitelisted origin lands sealed; oversize
upload on `encrypt_all` origin is blocked with the right reason; off-list origins
unchanged.

### M8 — kernel-assisted (design doc only in this phase)
- [ ] Write `dlp-minifilter/docs/encrypt-verdict-LLD.md` per §8. No driver code.

---

## 10. Decisions already made — do not re-litigate

| Question | Decision | Why |
|---|---|---|
| Wrap DEK with AES-KW or GCM? | AES-256-GCM with its own nonce | one primitive in the whole feature; KW adds a dependency for no threat-model gain |
| Header encoding | canonical serde_json, camelCase | matches `verdict.rs` wire conventions; CBOR adds a dependency |
| KEK delivery | plaintext inside mTLS body | same trust as the policy bundle; re-wrapping to a cert-derived key adds complexity without changing the threat model (endpoint compromise defeats both) |
| Whitelist ⇒ weaker blocking? | **No.** Block band still blocks on `encrypt_sensitive` | whitelisting must never raise the leak ceiling |
| Unreadable content on encrypt destination | Seal it | fail secure; also the answer to the "pre-encrypted file" blind spot |
| Big uploads (>4 MiB) in browser channel | block with typed reason | streaming seal through 1 MB native-messaging chunks is v2 work |
| New npm deps | none | Node `crypto` suffices; air-gap supply-chain rule |
| Outlook/SMTP email | out of scope v1 | needs MAPI add-in; webmail origin covers the common defence deployment |

**Genuinely open** (ask the user, don't guess): (a) which role holds
`encryption_keys:destroy_confirm`; (b) KEK scoping per-site vs per-classification
for multi-site customers; (c) whether `decrypt` should require the device to be
online (current design: no — cached keyring, offline-capable, bounded staleness).

---

## 11. Definition of done for the whole feature

1. A whitelisted (`encrypt_all`) USB stick receives ONLY `.dlpenc` files; a lost
   stick yields ciphertext + authenticated headers, nothing else.
2. An `encrypt_sensitive` destination seals exactly the verdict band (golden
   thresholds), still blocks the block band, passes clean files untouched.
3. Enrolled endpoint decrypts with an audit trail; de-enrolled/foreign machine
   cannot, and the attempt is an incident.
4. Key destruction (two-person) makes previously sealed media unopenable
   (`KeyDestroyed` error surfaced as `DecryptDenied` incident).
5. Every key access, policy change, and decrypt is in the append-only audit log.
6. `cargo test` + server test suite green; no test requires hardware, a driver,
   or a live browser (those are runbook items).
7. No file content, plaintext, or key material in any log, incident, or DB row.
