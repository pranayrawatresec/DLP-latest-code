# Encryption Features for the DLP Suite — Research, Use Cases & Implementation Approach

> Research date: 2026-08-11. Status: **proposal / design doc** — nothing here is built yet.
> The encrypt-on-write feature (F2/F3, generalised to all whitelisted destinations) now has
> a full implementation spec: see **`ENCRYPT-ON-WRITE-IMPLEMENTATION.md`** — that file is
> the handoff document for the implementing agent.
> Scope: what encryption capabilities (Trellix Data Encryption Suite–style) we should add
> to our defence DLP product, why, and how to build them on top of the existing
> agent / minifilter / management-server architecture.

---

## 1. Research summary — what the market does

### 1.1 Trellix Data Encryption Suite (the reference product)

Three components, all managed from their on-prem console (ePO):

| Component | What it does | Our takeaway |
|---|---|---|
| **Drive Encryption (TDE)** | Their own full-disk encryption: pre-boot auth, MFA, FIPS 140-2 validated module, NIST SP 800-111 compliant | **Do NOT build this.** Years of kernel/boot work; BitLocker already exists on every Windows endpoint |
| **Native Drive Encryption (TNE)** | Doesn't encrypt anything — centrally *manages* BitLocker/FileVault: status monitoring, recovery-key escrow, compliance reporting | **Build this.** Cheap (WMI calls), high accreditation value |
| **File & Removable Media Protection (FRP)** | Policy-driven, transparent file/folder encryption on USB, CD/DVD, email attachments, cloud folders | **Build a focused subset:** encrypt-on-write to removable media |

FRP's key model (from the Trellix product guide / KB72668) — three key types:

- **Regular keys** — created by admins in the console, usable in any policy. Data
  encrypted with a regular key is readable on *any* endpoint managed by the same
  console that has been granted that key. → This is the "readable inside the
  organisation, ciphertext outside it" property we want.
- **User personal keys** — per-user, follow the user across managed machines.
- **User local keys** — created on the client, never escrowed. (We will **not**
  offer this: un-escrowed keys violate our recoverability/audit posture.)

### 1.2 Microsoft Purview Endpoint DLP

- USB copy is an *activity* with configurable action: audit / block / block-with-override.
- Purview **automatically encrypts sensitivity-labeled files before they are
  transferred off the device** — encrypt is an outcome of classification, not a
  separate product. That is the modern pattern: **classification verdict → encrypt action**.
- Known weakness (documented): if a file is *already* encrypted before the copy,
  content inspection can't see inside it. Our `Extraction::Unreadable` verdict +
  fail-secure policy ("unreadable = treat as sensitive on removable media") already
  anticipates this.

### 1.3 BitLocker programmatic management

- WMI class **`Win32_EncryptableVolume`** (namespace `root\CIMV2\Security\MicrosoftVolumeEncryption`)
  exposes everything we need: protection status, encryption method, key protectors,
  `GetKeyProtectors`, and `BackupRecoveryInformationToActiveDirectory`.
- Enterprise tools (Intune, ConfigMgr, ManageEngine) all do the same thing: read
  status via WMI, escrow the **numerical recovery password** to a server, report
  compliance. There is no magic — we can do this from the Rust agent.

### Sources

- [Trellix Data Encryption product page](https://www.trellix.com/products/data-encryption/) · [data sheet (PDF)](https://www.trellix.com/assets/data-sheets/trellix-data-encryption-data-sheet.pdf)
- [Trellix FRP product guide (PDF)](https://docs-be.trellix.com/bundle/file-removable-media-v5-0-0-product/raw/resource/enus/PD26185.pdf) · [FRP key types (KB72668)](https://kcm.trellix.com/corporate/index?page=content&id=KB72668)
- [Trellix FRP on-prem privacy data sheet (PDF)](https://www.trellix.com/assets/trust/privacy/trellix-file-removable-media-protection-on-prem_privacy-data-sheets.pdf)
- [Purview Endpoint DLP overview](https://learn.microsoft.com/en-us/purview/endpoint-dlp-learn-about) · [endpoint settings](https://learn.microsoft.com/en-us/purview/dlp-configure-endpoint-settings)
- [Defender for Endpoint device control](https://learn.microsoft.com/en-us/defender-endpoint/device-control-overview)
- [`Win32_EncryptableVolume`](https://learn.microsoft.com/en-us/windows/win32/secprov/win32-encryptablevolume) · [`BackupRecoveryInformationToActiveDirectory`](https://learn.microsoft.com/en-us/windows/win32/secprov/backuprecoveryinformationtoactivedirectory-win32-encryptablevolume)
- [Trellix Drive Encryption FAQ (KB79784)](https://support.trellix.com/s/article/KB79784)

---

## 2. Where encryption fits our threat model

Encryption and content-inspection DLP cover **different attacker positions**:

| # | Threat scenario | Content DLP (built/building) | Encryption feature (this doc) |
|---|---|---|---|
| 1 | Authorised user uploads secret doc to webmail/cloud | ✅ netfilter + browser ext + detect engine | — |
| 2 | User copies secret doc to USB and walks out | ✅ detect + block (minifilter pre-write) | ✅ *encrypt instead of block* — file useless outside org |
| 3 | USB stick **lost/stolen in transit** (most common real defence incident) | ❌ copy was legitimate | ✅ encrypted media is ciphertext to the finder |
| 4 | **Laptop lost/stolen**, drive pulled or booted from live USB | ❌ agent not running | ✅ BitLocker (we verify + escrow, not implement) |
| 5 | Drive decommissioned / RMA'd with classified residue | ❌ | ✅ crypto-shredding: destroy key = sanitised |
| 6 | Classified **spillage** onto wrong media/machine | Partial (detect after the fact) | ✅ key revocation makes field copies unreadable |
| 7 | Screenshot / photo of screen / print | Clipboard + print channels | ❌ (encryption can't help) |
| 8 | Malware in the user's session | Partial | ❌ (session sees plaintext) |

Rule of thumb: **content DLP controls the live session; encryption controls the
bytes after they leave the session** (at rest, in transit on media, post-loss).
Defence customers are accredited against *both* — which is why Trellix bundles them.

---

## 3. Feature brainstorm (prioritised)

### F1 — BitLocker posture monitoring + recovery-key escrow ("TNE-lite") — **highest value/effort ratio**

The agent reads `Win32_EncryptableVolume` on check-in and reports per-volume:
protection status ON/OFF, encryption method (XTS-AES-256?), TPM protector present,
recovery password ID. Optionally escrows the numerical recovery password to the
management server (encrypted, RBAC-gated, access-audited — same handling as evidence).
Dashboard shows fleet encryption compliance; "disk not encrypted" becomes a finding.

- **Why first:** ~days of work, no kernel code, and it's the #1 checkbox a defence
  accreditor asks about (protects threat #4 without us writing any crypto).
- **Air-gap fit:** pure on-prem — we escrow to *our* server, no Azure AD/Intune needed.
  Many defence sites have no AD DS escrow configured at all; we become the escrow.

### F2 — Encrypt-on-write for removable media (FRP-style) — **the flagship feature**

A third policy verdict for the USB channel: today the policy engine decides
allow / read-only / block per device; with content verdicts we add **`Encrypt`** —
the file lands on the stick wrapped in an org-keyed envelope (`.dlpenc`), readable
only on enrolled endpoints of the same organisation.

- **Why:** defence sites *depend* on sanctioned media transfer between enclaves
  (air-gapped networks have no other path). Hard-block breaks the mission;
  allow leaks. Encrypt-on-write is the only verdict that serves both.
- Classification-aware, Purview-style: detection verdict (IDM containment / EDM hits)
  chooses the action — e.g. `containment ≥ 0.8 → Block`, `0.2–0.8 → Encrypt`,
  `< 0.2 → Allow (audited)`.

### F3 — Enrolled-endpoint decryption + audited access

The counterpart of F2: on an enrolled endpoint, the agent decrypts `.dlpenc` files
(explorer context-menu / double-click handler), **after** checking policy and writing
an audit incident ("who opened which protected file, where, when"). Un-enrolled or
de-enrolled machines simply lack the key material — revocation is enrollment revocation.

### F4 — Crypto-shredding & key lifecycle

Per-classification Key-Encryption-Keys (KEKs) with versions, stored server-side
(HSM in Phase 6). Destroying a KEK version renders every file wrapped under it —
on every USB stick in the field, every evidence blob — permanently unreadable.
This is the **spillage containment** and **media decommissioning** story (threats #5, #6),
and it aligns with the evidence-store design already planned in Phase 4.

### F5 — Provisioned "trusted media" (later)

Admin provisions specific USB serials as *organisation media*: the device rule
(`usb/policy.rs` already matches VID/PID/serial) says "writes to this device are
always encrypted; all other devices are read-only/blocked". Combines device control +
encryption into a courier workflow.

### F6 — Recovery / break-glass flows (later)

Challenge–response recovery for `.dlpenc` files when the server is unreachable and
the intended recipient machine lost enrollment (Trellix-style self-recovery). Must be
designed with the fail-secure rule: recovery requires an operator with a dedicated
permission, and every recovery is audited.

**Explicit non-goals** (per CLAUDE.md rules and sanity):
- ❌ Our own full-disk encryption / pre-boot auth (use BitLocker; we manage it).
- ❌ Un-escrowed "user local keys" (unauditable, unrecoverable).
- ❌ Rolling our own primitives — AES-256-GCM / HKDF from an established Rust
  crate (RustCrypto or `ring`), one new dependency, justified here.

---

## 4. Complete use cases (defence context)

### UC-1: Courier transfer between air-gapped enclaves
An analyst at Site A must move a working document set to Site B (no network path
exists — that's the point of the air gap). Policy: USB writes on analyst machines
→ `Encrypt` verdict. Files land on the stick as `.dlpenc` under the org KEK.
The courier's car is broken into; the stick is stolen. **Outcome:** attacker holds
AES-256-GCM ciphertext with no key material. At Site B (same org, same management
server / federated KEK), the enrolled endpoint decrypts transparently; the decrypt
is audited with the analyst's identity, device serial and file hash.

### UC-2: Insider walks out with a stick
An employee under notice copies project files to a personal USB stick. Detection
scores the files below the hard-block threshold (partial matches), so the copy is
allowed **encrypted**. At home, the files are unreadable. The incident feed shows
the copy with IDM matches; the reviewer revokes nothing — the data never actually
left in usable form. If the same user's matches had scored above threshold, the
minifilter would have blocked pre-write.

### UC-3: Fleet encryption compliance for accreditation
The security officer must evidence to the accreditor that 100% of endpoints holding
OFFICIAL-and-above material have XTS-AES-256 full-disk encryption with escrowed
recovery keys. Dashboard: encryption-posture tile per agent (from F1 check-in data),
export report. A newly imaged laptop shows red; sysadmin remediates before it gets
network access to classified shares.

### UC-4: Lost laptop
A field laptop is left on a train. BitLocker (verified ON by us, key escrowed with
us) makes the disk ciphertext. The incident reviewer confirms from the console that
the device's posture was compliant at last check-in — the mandatory-report to the
security authority is "no data compromise", not a breach notification.

### UC-5: Spillage containment
A SECRET document is discovered to have been written (encrypted) to several
transfer sticks under KEK `class-secret/v3`. Response: rotate to `v4` for new
writes, then **destroy `v3`** after confirming legitimate copies are re-secured.
Every stick in the field carrying `v3`-wrapped files is now sanitised without
physical recovery. The destruction itself is a two-person, audited action.

### UC-6: Media/drive decommissioning
Evidence-store blobs and encrypted media are keyed per classification/incident.
Retention expiry or disposal = key deletion (crypto-shredding), not multi-pass
wiping — instant, provable, and it works for media you no longer physically hold.

---

## 5. Implementation approach

### 5.0 Where it hooks into the existing architecture

```
                        ┌────────────────────────────────────────────┐
                        │  dlp-management-server (Node, on-prem)     │
                        │  + keys.js        KEK registry & wrapping  │
                        │  + escrow.js      BitLocker recovery pwds  │
                        │  + migrations/006_encryption_keys.sql      │
                        │  RBAC gates + audit on every key access    │
                        └──────────────▲─────────────────────────────┘
                                       │ mTLS (existing enroll/checkin)
┌──────────────────────────────────────┴───────────────────────────┐
│  dlp-agent (Rust)                                                │
│  usb/policy.rs      Action::Encrypt (new variant)                │
│  crypto/envelope.rs .dlpenc format: seal / open   (new)          │
│  crypto/keyring.rs  cached wrapped KEKs, zeroize  (new)          │
│  bitlocker/mod.rs   WMI posture + escrow          (new)          │
│  usb/audit.rs       verdict → encrypt pipeline    (extend)       │
│  kguard/mod.rs      pre-write hold for USB writes (extend)       │
└──────────────────────────▲───────────────────────────────────────┘
                           │ FltPort (existing content-over-port)
             ┌─────────────┴──────────────┐
             │  dlp-minifilter (C)        │
             │  post-write rename gate on │
             │  removable volumes (extend)│
             └────────────────────────────┘
```

### 5.1 Phase E1 — BitLocker posture + escrow (build first)

**Agent** (`src/bitlocker/mod.rs`, `#[cfg(windows)]` with stubs like `usb/`):

1. Query `Win32_EncryptableVolume` for every fixed volume. Prefer running
   `powershell Get-BitLockerVolume | ConvertTo-Json` via `std::process::Command`
   over adding a WMI/COM crate — zero new dependencies, and we already accept
   PowerShell for enforcement probes. Parse: `ProtectionStatus`, `EncryptionMethod`,
   `VolumeStatus`, protector types, `KeyProtectorId`.
2. Attach a `bitlockerPosture` object to the existing check-in payload.
3. Escrow (config opt-in, default on): send the numerical recovery password once
   per protector-ID over the existing mTLS channel; server stores it AES-256
   encrypted (same envelope machinery as evidence blobs, Phase 4). Agent **never
   logs or persists** the password locally (CLAUDE.md secrets rule).

**Server:**

- `migrations/006_encryption_keys.sql`: `bitlocker_escrow(agent_id, volume_guid,
  protector_id, ciphertext, created_at)` + `encryption_keys` (see E2).
- Route `GET /api/agents/:id/encryption-posture` — two-gate: authenticate, then
  `auditor` or `incident_reviewer` may read status; **reading an escrowed recovery
  password is its own permission** (recommend: `incident_reviewer` only, never
  `sysadmin` — mirrors the "sysadmin cannot read evidence" separation), and every
  read writes an audit entry with actor + protector id.
- Dashboard: fleet encryption-compliance tile + per-agent drill-down.

**Effort:** small. No kernel work, no new crates. Ship inside the current phase.

### 5.2 Phase E2 — `.dlpenc` envelope format + key hierarchy

**Key hierarchy** (all keys 256-bit, generated server-side with CSPRNG):

```
Org Root Key (ORK)            server .env → Phase 6: HSM        never leaves server
  └─ KEK per classification & version  e.g. class-internal/v1   wrapped by ORK at rest
       └─ DEK per file (random)        wrapped by KEK           lives only in file header
```

- Agents receive, at policy sync, the **wrapped KEKs their policy references**,
  re-wrapped to an agent key derived from the enrollment client certificate.
  Cached locally (encrypted-at-rest via DPAPI) so **encryption keeps working
  offline** — fail-secure means the *encrypt* direction must never depend on
  server reachability. Decrypt of cached KEKs also works offline; *revocation*
  propagates at next check-in (bounded staleness, same model as cached policy).
- Rust: `aes-gcm` + `hkdf` + `zeroize` (RustCrypto). Three small, widely-audited
  crates — the one dependency addition this design asks for. FIPS note: Phase 6
  can swap the module for a FIPS-validated provider behind the same trait.

**File format `*.dlpenc`** (version-tagged, deliberately boring):

```
magic "DLPE" | u8 version | u16 header_len
header (CBOR or fixed JSON, canonical):
  keyId: "class-internal/v1"        # KEK id + version → enables crypto-shredding
  wrappedDek: base64                 # DEK wrapped by that KEK (AES-KW or GCM)
  nonce: base64                      # per-file random 96-bit GCM nonce
  origin: { agentId, deviceSerial, timestamp }
  plaintextSha256: hex               # integrity + incident correlation
ciphertext: AES-256-GCM(DEK, nonce, plaintext, aad = header bytes)
```

Header is authenticated as GCM AAD → tamper with metadata and decryption fails.
`plan()`/`apply()` dry-run discipline from `usb/enforce.rs` applies: `seal()` and
`open()` are pure functions over bytes, golden-vector tested cross-platform.

### 5.3 Phase E3 — Encrypt verdict on the USB channel

Wiring order (each step shippable alone):

1. **Policy:** add `Action::Encrypt` to `usb/policy.rs` and a content-threshold
   map to the synced policy: `{ block: containment ≥ x, encrypt: ≥ y, else allow }`.
   The detect engine stays audit-only (its documented contract) — thresholds are
   applied by the *channel*, as designed.
2. **User-mode MVP (audit-encrypt):** extend the `CopyAuditor` pipeline in
   `usb/audit.rs` — after `scan_to_incident` returns a verdict scoring in the
   encrypt band, the worker **seals the file in place on the volume**
   (write `.dlpenc` sibling → fsync → delete plaintext → incident records
   `ActionTaken::Encrypted`). Honest limitation, stated in the incident: there is
   a window where plaintext was on the stick (settle time). Acceptable for the
   demo tier; closed by step 3.
3. **Kernel-assisted (closes the window):** reuse the existing kguard
   content-over-port flow — minifilter holds `IRP_MJ_WRITE`-completed files on
   removable volumes in a pending state (deny `IRP_MJ_CLEANUP` rename-visible
   completion, or simpler: block reads of the new file by other processes until
   verdict), ships bytes to user mode exactly as it does today, user mode returns
   `allow | block | encrypt`; on `encrypt` the agent writes the sealed copy and
   the filter releases/deletes the original. This is an extension of the existing
   pre-write blocking design (spec §9), not a new driver.
4. **Decrypt UX:** `dlp-agent decrypt <file>` + Explorer context-menu registration
   on enrolled endpoints; checks policy, unwraps DEK via cached KEK, writes
   plaintext only after an audit incident is queued. De-enrolled machine ⇒ no
   KEK ⇒ no decrypt — revocation for free.

### 5.4 Phase E4 — Server key lifecycle + crypto-shredding

- `encryption_keys(id, classification, version, wrapped_kek, state
  [active|rotated|destroyed], created_at, destroyed_at, destroyed_by)`.
- Rotation: new version becomes `active` (new writes); old stays `rotated`
  (decrypt-only). Destruction: **two-person rule** — one `sysadmin` requests,
  a second privileged actor confirms; row's key material is overwritten, state
  `destroyed`, audit-chained. Decrypt attempts against a destroyed KEK produce a
  distinct incident type (someone is holding old media — that's signal).
- Evidence store (Phase 4) uses the same table/hierarchy — one key-management
  implementation for both features.

### 5.5 Testing strategy (matches house style)

- `seal`/`open` golden vectors (fixed key/nonce → exact ciphertext bytes),
  cross-platform, like the fingerprint golden vectors.
- Tamper matrix: flipped ciphertext bit, altered header field, wrong KEK version,
  destroyed KEK — every case must fail *closed* with a typed error.
- USB pipeline: extend the existing dry-run `plan()` assertions — no test writes
  to a real volume; encrypt path tested against a temp dir masquerading as the volume.
- BitLocker parser: fixture JSON from `Get-BitLockerVolume` outputs (encrypted,
  decrypted, suspended, no-TPM cases).
- Server: RBAC matrix tests per route (401/403/200), audit-entry-per-access, and
  the two-person destruction flow.

### 5.6 Suggested build order & rough effort

| Order | Item | Effort | Depends on |
|---|---|---|---|
| 1 | E1 BitLocker posture + escrow | ~3–5 days | check-in (exists) |
| 2 | E2 envelope + keyring + server key registry | ~1 week | migrations, mTLS (exist) |
| 3 | E3 step 1–2: Encrypt verdict, user-mode seal | ~1 week | E2, usb/audit (exists) |
| 4 | E3 step 4: decrypt UX + audit | ~3 days | E2 |
| 5 | E4 rotation + crypto-shredding + two-person destroy | ~1 week | E2 |
| 6 | E3 step 3: kernel-assisted no-plaintext-window | ~2–3 weeks | minifilter pre-write work |
| 7 | F5 trusted-media provisioning, F6 recovery flows | later | all above |

---

## 6. Open questions (decide before E2)

1. **KEK scoping:** per-classification only, or per-classification × per-site?
   (Federation between two management servers — UC-1 across orgs — needs a
   key-exchange story we have not designed.)
2. **Who may destroy keys?** Proposal above says two privileged actors; confirm
   which of the four roles — this touches the separation-of-duties table.
3. **`.dlpenc` on non-Windows readers:** do we need a standalone (audited)
   reader utility for partners, or is "enrolled endpoints only" the product line?
4. **FIPS module choice for Phase 6:** validated OpenSSL provider vs. commercial
   Rust FIPS module — affects the crypto trait boundary we define now.
