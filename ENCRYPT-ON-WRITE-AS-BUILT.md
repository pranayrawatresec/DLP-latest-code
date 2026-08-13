# Trusted-Destination Encryption (Encrypt-on-Write) — As-Built Engineering Reference

> **Audience:** an engineer who will maintain or extend this feature.
> **Status:** M1–M6 built and machine-verified; M7 (web-upload/webmail) and M8
> (kernel-assisted seal) NOT started. This document describes **what actually
> exists in the working tree today**, the decisions behind it, the operational
> gotchas found during real-hardware/VM testing, and the open issues.
>
> Companion docs:
> - `ENCRYPT-ON-WRITE-IMPLEMENTATION.md` — the original approved design spec (the "why" and the intended contracts). Read it for rationale.
> - `ENCRYPTION-FEATURES-README.md` — market research + threat model.
> - `ENCRYPT-DEMO-RUNBOOK.md` — operator demo walkthrough (USB channel).
> - `CLAUDE.md` — project-wide rules (frozen detect engine, fail-secure, RBAC, no key material in logs, etc.).

---

## 1. What the feature does (one paragraph)

An admin **whitelists a destination** (today: a specific USB stick, by serial or
VID:PID) in the management console. Sensitive data written to a whitelisted stick
is **not blocked — it is sealed in transit** into a `.dlpenc` envelope
(AES-256-GCM, organisation-held keys) that only enrolled endpoints of the same
organisation can open. Non-whitelisted devices keep the existing behaviour
(audit / read-only / kernel block). Decryption on an enrolled endpoint is offline
(cached keyring), policy-checked, and audited; destroying the key
(crypto-shredding) makes all media sealed under it permanently unreadable.

Two per-destination encrypt modes and a per-destination block-band policy:

| Setting | Values | Meaning |
|---|---|---|
| `mode` | `encrypt_sensitive` \| `encrypt_all` | *sensitive*: only files whose verdict scores in the sensitive band are sealed, clean files pass plaintext. *all*: every file is sealed (courier-stick mode; no verdict/bundle needed). |
| `on_block_band` | `block` (default) \| `seal` | What happens to a file whose verdict reaches the **block band** on an `encrypt_sensitive` destination. `block` = keep the hard block (whitelisting never silently weakens it — spec §10). `seal` = armour it instead of blocking (owner opt-in). |

---

## 2. Owner decisions (override the spec where they differ)

These were decided by the project owner during the build; keep them unless told otherwise:

1. **Key destruction is single-person, sysadmin-only** (spec proposed two-person). The server route splits the destroy into an audited *request* step and an audited *effect* step so a two-person confirm can be inserted later without reshaping the audit trail. **Revisit before shipping to a real defence customer** — one admin bricking all encrypted media org-wide is what accreditors probe.
2. **KEK scope is per-classification** (e.g. `class-internal/v1`); key ids are **free-form opaque strings — never parsed anywhere**. Per-site keys can be introduced later purely as new ids, no format change.
3. **Decrypt is offline-capable** from the cached keyring (no server round-trip on the hot path). Revocation/rotation propagates at next sync; bounded staleness accepted.
4. **`on_block_band`** was added beyond the original spec so "a sensitive file to a whitelisted stick must be encrypted, not blocked" is selectable per destination. Default stays `block` (spec-faithful); the admin opts into `seal`.

---

## 3. Milestone status

| Milestone | Scope | Status |
|---|---|---|
| M1 | `crypto/envelope.rs` + `crypto/keyring.rs` (pure core) | **Done**, golden + tamper tested |
| M2 | Policy: `Action::Encrypt`, `trustdest.rs` (`decide_seal`), config | **Done** |
| M3 | USB seal-in-place in the copy auditor | **Done** |
| M4 | `dlp-agent decrypt` + DPAPI keyring at rest | **Done** |
| M5 | Operator demo runbook (`ENCRYPT-DEMO-RUNBOOK.md`) | **Done** |
| M6 | Server delivers keys+whitelist to agent over mTLS; agent syncs+merges | **Done** |
| — | Kernel guard / sealer **coexistence** (not a numbered milestone) | **Done** |
| — | Block-band `seal` opt-in + baseline + envelope passthrough (field-testing fixes) | **Done** |
| M7 | Web-upload / webmail sealing via browser extension | **Not started** (schema/types stubbed: `[webupload]` config, `web_upload`/`email` allowed in DB CHECK) |
| M8 | Kernel-assisted seal (close the settle-window plaintext gap) | **Not started** (design only, spec §8) |

---

## 4. Files touched / created (map)

### Rust agent (`dlp-agent/`)
- `src/crypto/mod.rs`, `src/crypto/envelope.rs`, `src/crypto/keyring.rs` — **NEW** (M1). The `.dlpenc` envelope + keyring. Pure, cross-platform.
- `src/trustdest.rs` — **NEW** (M2). Pure decision logic: `EncryptMode`, `EncryptBands`, `SealDecision`, `BlockBandPolicy`, `decide_seal()`.
- `src/trustsync.rs` — **NEW** (M6). Serde types for the server sync contract + `merge_into_usb()` (pure).
- `src/decrypt.rs` — **NEW** (M4). `decrypt_envelope()` library core (audit-before-write).
- `src/supervise.rs` — **NEW** (2026-08-13, §11a). `SealerHealth` liveness signal + `snapshot_config()` shared-config helper for the unified `run-endpoint`.
- `src/service.rs` — **NEW** (2026-08-13, §11a). Windows service (`DLPAgent`) install/uninstall + SCM dispatcher for `run-endpoint`.
- `src/usb/policy.rs` — `Action::Encrypt` variant + restrictiveness ordering.
- `src/usb/audit.rs` — `scan_and_seal_to_incident()`, `seal_file_in_place()`, `baseline_existing()`, `is_sealed_envelope_path()`, `ActionTaken::Encrypted`, `IncidentKind::{Sealed, DecryptDenied}`, `UsbIncident.{key_id, sealed_sha256}`.
- `src/usb/mod.rs` — `run_monitor` sealer wiring, `EncryptVolume`, baseline call, envelope-skip.
- `src/usb/enforce.rs` — `Action::Encrypt` arms (device-level `NoChange`; MTP fails to write-deny).
- `src/config.rs` — `CryptoConfig` (`[crypto]`), `WebuploadConfig` (`[webupload]`), `UsbRule.{mode, key_id, on_block_band}`, `UsbConfig::encrypt_params()`, `Config::encrypt_bands()`, `Config::with_synced_destinations()`, `Config::trusted_config_url()`.
- `src/kguard/mod.rs` — envelope passthrough + whitelist-aware `write_scan_override()` in `decide()` (coexistence).
- `src/checkin.rs` — `sync_trusted_config()`, `load_synced_destinations()` (M6 network half).
- `src/storage.rs` — `store_keyring`/`load_keyring` (DPAPI, M4), `store_trusted_destinations`/`load_trusted_destinations` (M6, metadata only).
- `src/main.rs` — `cmd_decrypt`, sync+merge wiring into `cmd_usb_monitor` and `cmd_usb_guard`, sealer keyring resolution.
- `src/lib.rs` — `pub mod crypto; pub mod trustdest; pub mod trustsync; pub mod decrypt;`
- `Cargo.toml` — added `aes-gcm = "0.10"`, `zeroize` (the ONLY new deps; approved).
- `agent.example.toml` — documented `[usb]` encrypt rules, `[crypto]`, `[webupload]`.
- `tests/crypto_envelope.rs`, `tests/decrypt_path.rs`, `tests/trusted_sync.rs`, plus additions to `tests/usb_audit.rs`.

### Management server (`dlp-management-server/`)
- `migrations/006_encryption_keys.sql` — **NEW**. `encryption_keys` + `trusted_destinations` tables.
- `migrations/007_agent_key_sync.sql` — **NEW**. Adds `trusted_destinations.on_block_band` (default `block`, CHECK block|seal) + nullable `detection_incidents.key_id` / `sealed_sha256`.
- `routes/encryption.js` — **NEW**. Admin API: keys (list/create/rotate/destroy) + trusted-destinations (list/create/delete). Two-gate + audited.
- `agent/agentApp.js` — added `GET /agent/trusted-config` (mTLS agent-facing delivery) + `unwrapKek()`; extended `POST /agent/incidents` to accept `encrypted` action and persist `keyId`/`sealedSha256`.
- `app.js` — mounts `/api/encryption`.
- `lib/rbac.js` — perms: `trusted_destinations:read` (policy_author, sysadmin, auditor), `trusted_destinations:write` (policy_author), `encryption_keys:manage` (sysadmin).
- `.env.example` — documented `DLP_ORG_ROOT_KEY`.
- `test/encryption.test.js`, `test/agentTrustedConfig.test.js` — **NEW**.

### Frontend (`dlp-management-frontend/`)
- `src/pages/TrustedDestinations.jsx` — **NEW**. "Trusted USB devices" page (table + add-device form incl. the `on_block_band` control).
- `src/store/apiSlice.js` — `TrustedDestination` tag + 4 endpoints.
- `src/App.jsx` — route `/trusted-destinations` (perm-gated).
- `src/components/layout/Sidebar.jsx` — nav entry.
- `src/components/ui/Icons.jsx` — `UsbIcon`.

---

## 5. The `.dlpenc` envelope format (as implemented)

Module: `dlp-agent/src/crypto/envelope.rs`. Pure functions over byte slices; golden-vector tested.

```
offset    size  field
0         4     magic  = "DLPE"            (crypto::envelope::MAGIC — reused everywhere, never a literal)
4         1     version = 0x01
5         2     header_len (u16 LE) = H
7         H     header: canonical serde_json (camelCase), field order fixed by struct
7+H       12    nonce (96-bit, OS CSPRNG, unique per file)
7+H+12    C     ciphertext = AES-256-GCM(key=DEK, nonce, plaintext, aad = bytes[0 .. 7+H])
7+H+12+C  16    GCM tag
```

`EnvelopeHeader` (serde, **camelCase** on the wire):

| Rust field | JSON | meaning |
|---|---|---|
| `key_id` | `keyId` | KEK id/version — the crypto-shred unit (free-form) |
| `wrapped_dek` | `wrappedDek` | base64: AES-256-GCM(KEK, dek_nonce, DEK) |
| `dek_nonce` | `dekNonce` | base64 96-bit nonce used to wrap the DEK |
| `origin_agent` | `originAgent` | agent id (from `identity`), NOT hostname |
| `created_unix` | `createdUnix` | u64 seconds (injected clock) |
| `plaintext_sha256` | `plaintextSha256` | hex — correlates with `UsbIncident.file_sha256` |
| `orig_name` | `origName` | original file name (no path) — survives rename |

**API:**
```rust
pub fn seal(plaintext: &[u8], orig_name: &str, key: &Kek, agent_id: &str, now_unix: u64) -> Result<Vec<u8>, EnvelopeError>;
pub fn seal_with_rng(rng: &mut dyn EnvelopeRng, ...) -> ...;   // injected RNG for golden vectors
pub fn open(envelope: &[u8], keyring: &Keyring) -> Result<(EnvelopeHeader, Vec<u8>), EnvelopeError>;
pub fn peek_header(envelope: &[u8]) -> Result<EnvelopeHeader, EnvelopeError>;  // unauthenticated claims until open() succeeds
```

**`EnvelopeError`** (typed — callers distinguish these; no `anyhow` in this module):
`Malformed(&'static str)`, `WrongKey`, `Tampered`, `UnknownKeyId(String)`, `KeyDestroyed(String)`, `HeaderTooLarge`, `SealFailed`.

**Rules:** fresh random 256-bit DEK per file; DEK + plaintext buffers `Zeroize`d on drop; `now_unix` injected (deterministic golden vectors); OS CSPRNG in prod (`aes_gcm::aead::OsRng`). On-disk name = `<orig>.dlpenc`.

### Key hierarchy
```
ORK  Org Root Key (32B)   server-only, env DLP_ORG_ROOT_KEY (dev) → HSM later
 └── KEK "class-<name>/vN"  generated server-side, stored wrapped-by-ORK, delivered to agents over mTLS (M6)
      └── DEK (per file)    random, wrapped by KEK, lives only in the envelope header
```
`Keyring` = `HashMap<String, Kek>` + `active_key_id` + a `destroyed` set (destruction is terminal; re-insert refused). `Kek` = 32 bytes, `Zeroize + ZeroizeOnDrop`, redacting `Debug`. At rest on the agent: **DPAPI machine-scope** (`CRYPTPROTECT_LOCAL_MACHINE`) via `storage.rs`; non-Windows/dev fallback reads a plaintext `[crypto].keyfile` (DEV ONLY, git-ignored).

---

## 6. Policy / decision logic (`trustdest.rs`)

```rust
pub enum EncryptMode { EncryptSensitive, EncryptAll }   // serde snake_case
pub enum BlockBandPolicy { Block, Seal }                // serde snake_case; default Block
pub enum SealDecision { Plain, Seal, Block }
pub struct EncryptBands { encrypt_at: f64 /*0.05*/, block_at: f64 /*0.30*/, coverage_block_at: f64 /*0.60*/ }

pub fn decide_seal(mode, bands, on_block_band, verdict: Option<&Verdict>) -> SealDecision
```

`decide_seal` truth table (block/coverage thresholds mirror `[kguard]` via `Config::encrypt_bands()` — one source of truth):

- `EncryptAll` ⇒ **Seal** always (no verdict/bundle required).
- `EncryptSensitive`:
  - no verdict (no bundle / scan error) ⇒ **Seal** (fail secure)
  - `Extraction::Unreadable` ⇒ **Seal** (closes the pre-encrypted blind spot)
  - block band (`containment ≥ block_at` OR `coverage ≥ coverage_block_at`) ⇒ `on_block_band == Seal ? Seal : Block`
  - any EDM hit, or `containment ≥ encrypt_at` ⇒ **Seal**
  - else ⇒ **Plain**

`Action` restrictiveness ordering: `AllowAudited(0) < Encrypt(1) < ReadOnly(2) < Block(3)`. `Encrypt` is less restrictive than `ReadOnly` (writes still happen, transformed). `max_restrictive()` is used when merging synced + local rules.

---

## 7. USB seal-in-place (`usb/audit.rs`, `usb/mod.rs`)

The `CopyAuditor` watches a mounted volume root, settles files (name+size+mtime stable for `settle_ms`, default 1500ms), dedups by `(path,size,mtime)`. For an `Action::Encrypt` volume, each settled file goes through `scan_and_seal_to_incident()`:

- **Plain** → today's behaviour (audit incident only on a match).
- **Seal** → injected sealer (`seal_file_in_place`): read plaintext → write `<name>.dlpenc.tmp` → fsync → atomic rename to `<name>.dlpenc` → delete plaintext. Success ⇒ incident `ActionTaken::Encrypted` + `key_id` + both hashes + note `sealed-post-write`. **Any failure ⇒ plaintext KEPT** + `IncidentKind::EnforcementFailed` (fail secure).
- **Block** → user-mode channel records a `Match` incident (note `block-band-on-encrypt-destination`); the kernel guard is the enforcing layer.

Two field-testing fixes that are easy to miss:

1. **Baseline (`baseline_existing`)** — on an encrypt volume, files already on the stick at mount are seeded into the dedup set so **only files copied *after* the monitor starts are sealed**. Without this, a full stick (thousands of files) would be scanned serially and re-sealed. Log line: `encrypt volume: pre-existing files baselined ... baselined=N`.
2. **Envelope passthrough (`is_sealed_envelope_path`)** — `scan_tree` skips `*.dlpenc` and `*.dlpenc.tmp` on every volume, so the sealer's own output is never re-detected and re-sealed (which otherwise recursed to `name.dlpenc.dlpenc.dlpenc`).

Oversized files (`> max_file_bytes`, default 100 MB) are **not** sealed (sealing needs a full in-memory read) — flagged `SkippedTooLarge` with note `not-sealed`.

**Known v1 limitation:** the OS writes plaintext first; the sealer seals seconds later. A stick yanked inside the settle window carries plaintext. M8 (kernel-assisted) closes this.

---

## 8. Decrypt path (`decrypt.rs`, `main.rs`)

```
dlp-agent decrypt <file.dlpenc> [-o <out>]
```
Flow (order enforced in code): `peek_header` → load keyring → `open()` → **build + write the audit incident FIRST** (channel `decrypt`: key id, plaintext hash, agent id, outcome) → only then write plaintext. If the incident can neither be posted (mTLS) nor queued locally, **nothing is written** (no un-audited decrypt). Unknown/destroyed key ⇒ `DecryptDenied` incident + non-zero exit, nothing written. Offline by design (cached keyring only). `-o` chooses the output path; default is the authenticated original name beside the input, refusing to overwrite without `-o`.

---

## 9. Server (M6) — key + whitelist delivery

### Admin API (`routes/encryption.js`, mounted at `/api/encryption`, session-auth, two-gate)
- `GET  /trusted-destinations` (`trusted_destinations:read`) → `{ destinations: [{ id, channel, matcher, mode, keyId, onBlockBand, note, createdBy, createdAt }] }`
- `POST /trusted-destinations` (`trusted_destinations:write`) — body `{ channel:'usb', matcher:{serial}|{vid,pid}, mode, keyId?, onBlockBand? }`. `keyId` defaults to the single active key (409 if none/ambiguous). `onBlockBand` defaults `block`.
- `DELETE /trusted-destinations/:id` (`trusted_destinations:write`)
- `GET  /keys` (`trusted_destinations:read`) → metadata only, **never `wrapped_kek`**
- `POST /keys` (`encryption_keys:manage`) — body `{ classification }`. 32 random bytes wrapped AES-256-GCM under ORK; previous active key of that classification → `rotated`. `503` if `DLP_ORG_ROOT_KEY` unset/malformed (fail secure, no default key).
- `POST /keys/:id/destroy` (`encryption_keys:manage`) — single-person; overwrites `wrapped_kek` with random bytes, state → `destroyed`. Request + effect audited separately.

### Agent-facing delivery (`agent/agentApp.js`, mTLS, `requireKnownAgent`)
```
GET /agent/trusted-config  →  200
{ "destinations": [ { "channel":"usb", "matcher":{"serial":"…"}|{"vid":"…","pid":"…"},
                      "mode":"encrypt_sensitive"|"encrypt_all",
                      "keyId":"class-internal/v1", "onBlockBand":"block"|"seal" } ],
  "keys":         [ { "id":"class-internal/v1", "keyB64":"<base64 of 32-byte UNWRAPPED KEK>" } ] }
```
- `keys[]` = every KEK referenced by a destination **plus** every `state='rotated'` key (so old files still open); `destroyed` keys excluded.
- Missing/malformed ORK ⇒ `503`. Plaintext KEK buffers zeroed after base64. One audit row per delivery: `agent.keys_delivered { keyIds, destinationCount }` — **ids only, never bytes**.

### DB (migrations 006 + 007)
`encryption_keys(id PK, classification, version, wrapped_kek BYTEA, state active|rotated|destroyed, created_at, destroyed_at, destroyed_by, UNIQUE(classification,version))`.
`trusted_destinations(id, channel usb|web_upload|email, matcher JSONB, mode, key_id → encryption_keys, on_block_band block|seal, note, created_by, created_at)`.
`detection_incidents` gained nullable `key_id`, `sealed_sha256`.
`wrapped_kek` layout = `nonce(12) || ciphertext(32) || tag(16)`.

---

## 10. Agent ↔ server sync (M6) — `trustsync.rs`, `checkin.rs`, `main.rs`

- `sync_trusted_config(cfg, storage)` — mTLS `GET {server}/agent/trusted-config` using the enrolled identity; parse; build a `Keyring` from the base64 KEK bytes and persist it (DPAPI); persist destinations to `state_dir/trusted-destinations.json` (**metadata only — key ids yes, key BYTES never written here**). **Fail-soft:** any network/parse error logs a warning and reuses the last-persisted keyring/destinations (offline fail-secure).
- `merge_into_usb(usb_config, dests)` (pure) — **prepends** synced destinations as `Action::Encrypt` `UsbRule`s (first-match-wins gives the console precedence) and sets `enabled=true` when any destination exists. On the same device, `Action::max_restrictive` keeps the stricter of (synced, local).
- Wired into **both** `cmd_usb_monitor` and `cmd_usb_guard` at startup: `sync_trusted_config` → `load_synced_destinations` → `with_synced_destinations` → the merged `cfg` is used downstream. The sealer keyring **prefers the synced DPAPI keyring** (`storage.load_keyring`) over `[crypto].keyfile`.

The guard becomes whitelist-aware **for free** because `kguard::decide` reads `cfg.usb` via `encrypt_params` — feeding it the merged config is enough.

**Net effect:** with M6, an endpoint needs **no local `[usb]`/`[crypto]` config**. The admin's console whitelist drives everything. (Local config still works and composes via more-restrictive-wins.)

**Startup log to confirm sync:** `synced trusted config from server destinations=N keys=M`.

---

## 11. Kernel guard / sealer coexistence

On a machine with the minifilter loaded, `usb-guard` (kernel port client, kernel decides at write-time) and `usb-monitor` (user-mode sealer) run **simultaneously**. Both fixes are user-mode only; the wire protocol is FROZEN (`DLP_MSG_VERSION` = 2). In `kguard::decide()`:

1. **Envelope passthrough** — content beginning with `DLPE` ⇒ ALLOW, no incident, both scan reasons, before the bundle check. Stops the guard quarantining the sealer's own `.dlpenc` output (different PID than the guard's skip-self identity).
2. **Whitelist-aware write scans** — for WRITE reason only, resolve the target volume's `DeviceIdentity` (NT path → drive letter via cached `QueryDosDeviceW` map → `usb::device::query_device_identity`), and if the device is an `Action::Encrypt` destination apply `decide_seal`: **Block** ⇒ block as before; **Seal** ⇒ ALLOW + `allowed-pending-seal` incident (guard stands aside, the sealer armours it); **Plain** ⇒ allow/no incident. Gated on `usb.enabled` (nobody to seal otherwise ⇒ keep prior behaviour). Read-taint scans and unresolvable devices keep today's behaviour exactly.

Combined behaviour on a write to an `encrypt` volume:

| File / verdict | Guard | Sealer |
|---|---|---|
| block band, `on_block_band=block` | BLOCK (quarantine) | never sees it |
| block band, `on_block_band=seal` | ALLOW + `allowed-pending-seal` | seals → `.dlpenc` |
| seal band / EDM / unreadable | ALLOW + `allowed-pending-seal` | seals |
| clean (`encrypt_sensitive`) | ALLOW, no incident | passes plaintext |
| `.dlpenc` envelope | ALLOW (passthrough) | n/a |

---

## 11a. Unified endpoint service + full matrix (2026-08-13)

The guard and sealer are no longer two things you run by hand. `dlp-agent run-endpoint` (Windows-only; the Windows service `DLPAgent` runs it under the SCM as LocalSystem) hosts **guard + sealer + check-in + periodic whitelist re-sync** as coordinated threads in ONE process, sharing one merged-config view (`Arc<RwLock<Config>>`, re-snapshotted each iteration) and one **sealer-liveness signal** (`supervise.rs::SealerHealth`). New files: `src/supervise.rs`, `src/service.rs`. Subcommands: `run-endpoint`, `install-service`, `uninstall-service` (SCM ImagePath = `<exe> service-run`). Logs go to `C:\ProgramData\DLPAgent\logs\dlp-agent.log` (rolling, 5 MB → `.1`) when run as the service; console when interactive. The old `usb-guard`/`usb-monitor` subcommands remain for debugging.

**What unification fixes:** the two-guard port contention (one process = one `\DlpFltPort` connection), guard/sealer whitelist divergence (one shared view), whitelist changes needing a restart (the resync thread swaps the shared config live), and — the important one — the **fail-open**.

**Fail-secure liveness gate.** `write_scan_override` takes a `sealer_healthy` bool. Healthy = keyring present AND the sealer marked itself alive within `sealer_health_timeout_secs` (default 10). On a `Seal` decision: healthy ⇒ ALLOW + `allowed-pending-seal`; **unhealthy ⇒ BLOCK + `seal-unavailable-blocked` (`ActionTaken::Blocked`)** — a seal-eligible file is never allowed to land as plaintext when nobody can seal it. Standalone `usb-guard` passes `healthy=true` (no in-process sealer) and keeps prior behaviour.

**Two thresholds, by design (owner decision):**
- `[kguard].removable_write_block_at` (default **0.15**) — blocks a sensitive file copied to a **non-whitelisted** removable device (WRITE path: `should_block_removable_write` = any EDM hit OR containment ≥ 0.15 OR coverage ≥ `coverage_block_at`).
- `[crypto].encrypt_at` (0.05) still defines the **seal** band on a whitelisted stick; `block_at` (0.30) still drives read-taint and the trusted-side `on_block_band` band. **Accepted residual:** a file with containment in **0.05–0.15** seals on a trusted stick but copies on an untrusted one (below the 0.15 block line). Owner chose 0.15 as the middle ground; this is deliberate, not a bug.

**`run-endpoint` runs the sealer with `enforce = false` (deliberate — `main.rs`).** The required behaviour is per-file and content-based; device-level enforcement (`enforce = true`) would apply `default_action` (default `ReadOnly`) to a whole non-whitelisted device and block even **clean** copies, violating the matrix. Sealing does not depend on `enforce`. **Tradeoff:** this also leaves the user-mode MTP/phone and USB-tethering device blocks OFF (they live behind `enforce`) — out of scope of the content matrix; revisit if phone/tethering device-control is wanted (would need enforcing those actions without imposing `default_action` read-only on storage).

**The full behavior matrix as it now stands** (service running: guard + healthy in-process sealer):

| Stick | File | Result |
|---|---|---|
| **whitelisted** | clean | copies plaintext |
| whitelisted | sensitive, seal decision (encrypt band, or block band with `on_block_band=seal`, or EDM/unreadable) | **sealed** → `.dlpenc` |
| whitelisted | block band with `on_block_band=block` | **blocked** (admin's UI choice) |
| whitelisted | sensitive but sealer unhealthy | **blocked** (`seal-unavailable-blocked`) |
| **not whitelisted** | clean | copies (allowed) |
| not whitelisted | containment ≥ 0.15, or any EDM, or coverage ≥ 0.60 | **blocked** |
| not whitelisted | containment 0.05–0.15 | copies (accepted residual) |

---

## 12. Operational gotchas (found during VM/real-hardware testing — READ THIS)

1. **`FailMode` must be reloaded to take effect.** The driver reads `FailMode` at `DriverEntry`. Setting `HKLM\SYSTEM\CurrentControlSet\Services\dlpflt\FailMode` does nothing until `fltmc unload dlpflt ; fltmc load dlpflt`. Product default should be `1` (fail-secure = deny removable writes when the guard isn't answering). The INF ships `0`.
2. **Exactly ONE `usb-guard` may connect to `\DlpFltPort`.** ~~Two guards steal the port from each other → `No waiter is present (0x801F0020)`.~~ **Resolved by the unified `DLPAgent` service** (one process, one connection). Still relevant if you run a foreground `usb-guard` for debugging **while the service is running** — stop the service first (`sc stop DLPAgent`).
3. **~~Sync happens at process startup only.~~** **Resolved:** `run-endpoint`'s resync thread re-fetches the whitelist every check-in interval and swaps the shared config live, so UI changes take effect without a restart. (Standalone `usb-monitor`/`usb-guard` are still startup-only.)
4. **`on_block_band` defaults to `block`.** A fully-fingerprinted file (e.g. an exact OPORD match) is in the **block band**, so on an `encrypt_sensitive` destination with the default it is BLOCKED, not sealed. To seal even highly-sensitive files, the admin must choose "Encrypt it onto this device" (`seal`) when whitelisting.
5. **Deploy via the service, not loose copies.** `provision-vm.ps1` now installs the `DLPAgent` service running `C:\ProgramData\DLPAgent\dlp-agent.exe service-run`. Update **that** exe (stop the service first) — a copy elsewhere (e.g. `C:\dlp\`) is not what the service runs. `setup-encrypt-vm.ps1` is **deprecated** (it re-adds the old task + local config that conflict with the service).
6. **Detect-and-quarantine is "flash then vanish."** A kernel-blocked file briefly appears on the stick and is deleted on handle close — seeing it appear is not proof it wasn't blocked; re-check a moment later.
7. **The dev keyfile holds plaintext key bytes.** DEV ONLY, git-ignored. On Windows the agent re-seals it at rest via DPAPI after first use, but the source keyfile is plaintext until server key sync (M6) removes the need for it. With M6 configured, prefer no keyfile at all.
8. **`DLP_ORG_ROOT_KEY`** (64 hex chars) must be in the server `.env` or key creation / agent key delivery returns `503`. Never commit it.

---

## 13. Testing

- **Agent:** `cd dlp-agent && cargo test`. Suites include `crypto_envelope` (golden vectors + full tamper matrix), `decrypt_path`, `trusted_sync`, `usb_audit` (seal-in-place, baseline, envelope-no-reseal, failure-path), plus `trustdest`/`trustsync`/`config` unit tests. All green as of last build.
- **Server:** `npm run test:encryption` (`test/encryption.test.js` 22 checks — RBAC matrix, ORK 503, matcher validation, key lifecycle, two-step destroy audit, hash-chain) and `test/agentTrustedConfig.test.js` (12 checks — unwrap round-trip, 32-byte keys, rotated-included/destroyed-excluded, 503, 401, `encrypted` incident persistence).
- **Frontend:** `cd dlp-management-frontend && npm run build`.
- **Operator:** `ENCRYPT-DEMO-RUNBOOK.md` (USB channel; single-VM and cross-machine decrypt).

No test requires hardware, a driver, or a live browser (those are runbook items).

---

## 14. Demo / end-to-end flow (as it works today)

1. Admin logs into the console, `POST /api/encryption/keys { classification:"internal" }` (no key-creation UI yet — see Open Issues) → `class-internal/v1`.
2. Admin opens **Trusted USB devices** → Add device: serial (the value the agent logs on arrival), mode `encrypt_sensitive`, block-band "Encrypt it onto this device" (`seal`), key `class-internal/v1`.
3. Endpoint agent, at `usb-monitor`/`usb-guard` startup, fetches the whitelist + key over mTLS (`destinations=1 keys=1`) — no local encrypt config needed.
4. Copy a sensitive file to the stick → guard stands aside (`allowed-pending-seal`), sealer writes `<name>.dlpenc`, plaintext removed. Clean files stay plaintext.
5. `dlp-agent decrypt <file>.dlpenc -o <out>` on any enrolled endpoint → original bytes, `Decrypted` audit incident. A machine without the key ⇒ `DecryptDenied`, nothing written.

---

## 15. Open issues / TODOs

**Closed 2026-08-13 by the unified service (§11a):** the fail-open (sealer absent → plaintext leak) is now fail-secure (guard blocks when the sealer is unhealthy); guard/sealer no longer diverge; live re-sync means no restart on whitelist change; two-guard port contention is gone; the non-whitelisted mid-band leak is narrowed from 0.05–0.30 down to the accepted 0.05–0.15 via `removable_write_block_at=0.15`.

Still open:
1. **No key-creation UI.** Keys are created via `POST /api/encryption/keys` only. For a fully self-service admin flow, add a "Create key" control to the console. (Whitelisting different sticks does NOT need new keys — keys are org-wide.)
2. **Accepted residual leak (0.05–0.15 containment).** A file sealable on a trusted stick (≥ `encrypt_at` 0.05) but below `removable_write_block_at` (0.15) still copies to a non-whitelisted stick. Deliberate owner choice (0.15 middle ground). To close entirely, set `removable_write_block_at = encrypt_at`.
3. **MTP/phone + USB-tethering device blocks are OFF under `run-endpoint`** (they live behind `enforce`, which is `false` to preserve "clean copies on non-whitelisted sticks"). If wanted, enforce those specific device actions without imposing `default_action` read-only on storage.
4. **VM block-not-taking investigation** — was traced to (a) the guard running the OLD exe / not restarted after a whitelist change, and (b) two-guard `No waiter` contention. Both are addressed by the unified service (one process, live re-sync, single port owner). Re-verify on the service before considering it fully closed; if it recurs, still check that `FailMode=1` is *loaded* (`fltmc unload/load dlpflt` after a registry change).
5. **Two-person key destruction** — deferred (owner decision #1); the request/effect split is in place to add it.
6. **Server incident display** — `detection_incidents.key_id`/`sealed_sha256` columns exist and the agent endpoint persists them; verify the incidents UI surfaces seal/decrypt incidents (the console row may still look thin for `encrypted`).
7. **Graceful guard-thread shutdown** — `FilterGetMessage` blocks uninterruptibly, so the guard thread is detached and torn down by process exit on service stop (checks the stop flag between messages). Fine for a service; noted in case a cleaner teardown is wanted.
8. **M7 (web-upload/webmail)** and **M8 (kernel-assisted seal, closes the settle-window plaintext gap)** — not started; see spec §7 and §8.
7. **KEK delivery is plaintext-inside-mTLS** (owner decision, spec §10) — acceptable at current threat model; HSM/FIPS is Phase 6.

---

## 16. House rules that gate any change here (from CLAUDE.md + module docs)

- `dlp-agent/src/detect/` is **frozen** — channels apply thresholds, detect only reports.
- **Never log/transmit/return** file content, extracted text, keys, DEKs, or the ORK. Incidents/audits carry hashes, ids, and metadata only. The one exception is the `keyB64` field of `GET /agent/trusted-config` (inside mTLS, same trust level as the policy bundle).
- **Fail secure** everywhere — missing bundle/key/ORK, unreachable server, unreadable file ⇒ the more restrictive outcome, never a silent allow.
- Pure logic in its own module with unit tests; OS calls `#[cfg(windows)]`-gated with non-Windows stubs.
- Server: parameterised SQL only; two-gate (401 then 403, denials audited); audit every state change and every key-material egress.
- `#[repr(C)]` kernel wire structs are size-locked; any change bumps `DLP_MSG_VERSION` in BOTH `kguard/mod.rs` and `dlpflt.h`. (M6 changed nothing on the wire.)
- Dependencies stay minimal (air-gapped supply-chain surface): Rust added only `aes-gcm` + `zeroize`; Node uses built-in `crypto` (no new deps).
