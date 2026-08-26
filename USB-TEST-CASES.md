# USB Channel — Acceptance Test Cases

Complete edge-case suite for the removable-media (USB) channel. Each case:
**Purpose → Config → Setup → Action → Expected → Confirm**, with *why this edge
case matters*. Tick the ☐ as you go.

> **The USB channel has THREE enforcement layers — test them separately:**
> 1. **Kernel content block** (`dlpflt.sys` + the guard inside the `DLPAgent`
>    service): a *write* of sensitive content to a **non-trusted** stick is
>    quarantined. **On by default in the running service.**
> 2. **Encrypt-on-write** (sealer, same service): a write to a **trusted** stick
>    is sealed to `.dlpenc` instead of blocked.
> 3. **Device control** (`usb-monitor --enforce`): read-only / dismount / MTP /
>    tethering. **OFF under the service** — run it standalone for Group E.

## Honest behaviour to keep in mind while testing
- **Content block = detect-and-quarantine, not pre-commit.** The file briefly
  lands on the stick, is scanned when the copy settles, then deleted. You may see
  it "flash then vanish." That's the v1 design (true buffer-and-hold is v2).
- **Encrypt = seal-AFTER-write.** Plaintext lands first, sealed seconds later
  (`sealed-post-write`). A stick yanked *inside the settle window* keeps plaintext.
- **Two thresholds:** block a sensitive file at containment **≥ 0.15**
  (`removable_write_block_at`); start sealing at **≥ 0.05** (`encrypt_at`). Files
  scoring **0.05–0.15** copy to an untrusted stick **by design** (accepted residual).
- **Removable is always in scope** — no watch-path needed (unlike fixed C:).

---

## Prerequisites (you set these before starting)

**Server / console:**
1. Worker running; **OPORD** registered as a Protected Document + **index compiled**
   (a cached bundle on the endpoint). *Without this nothing is "sensitive."*
2. (For EDM case) an **EDM source** with a row like `Name: Priya Nair, Service No: SVC100002`.
3. (For Group C) an **encryption key** created (`POST /api/encryption/keys`,
   classification `internal`) — there's no key-creation UI, API only.

**Endpoint (VM):**
4. `DLPAgent` service RUNNING; driver loaded (`fltmc filters` shows `dlpflt`).
5. A **real USB stick** connected to the guest (VMware → *Removable Devices →
   Connect*). A fixed virtual disk won't be seen as removable.
6. `[usb] enabled = true` in `agent.toml` for the device-control group (E).
7. Test files staged: `OPORD.pdf` (sensitive, 8757 bytes), a truncated variant, an
   EDM text file, an **innocent** file, and a **>100 MB** dummy file.

**Note the stick's serial** from the log line `removable device arrived … serial=…`
— you'll need it for the trusted-destination whitelist (Group C).

---

## Group A — Device detection & classification

| ID | Purpose | Action | Expected | Why it matters |
|---|---|---|---|---|
| A1 | Detect a normal USB stick | Plug the stick | Log `removable device arrived` with drive letter, **serial**, `bus="usb"` | Baseline — everything keys off correct detection |
| A2 | USB SSD that reports as FIXED | Plug a USB-attached SSD | Still classified **removable** (bus-type, not drive-type) | Attackers use USB SSDs that lie as "fixed" to dodge drive-letter checks |
| A3 | Internal OS disk is ignored | (already present) | Internal C: disk must **NOT** appear as removable | A false positive here would try to police the boot disk |
| A4 | Phone / camera (MTP/WPD) | Plug a phone in MTP mode | Detected + logged; **informational only** under the service | MTP exposes files with no drive letter — a separate egress path |
| A5 | USB-tethering adapter | Plug a tethering phone | Detected as a tethering/RNDIS network device | USB tethering is an unmonitored network egress path |

☐ A1 ☐ A2 ☐ A3 ☐ A4 ☐ A5

---

## Group B — Kernel content block (write to a NON-trusted stick)

Service running, stick **not** whitelisted. Copy → the write is quarantined.

| ID | Purpose | Action | Expected | Why it matters |
|---|---|---|---|---|
| B1 | Block exact sensitive copy | Copy `OPORD.pdf` → stick | **Blocked/quarantined**; incident channel `usb-kguard`, containment ~1.0; toast | The headline USB capability |
| B2 | Allow an innocent file | Copy an innocent file → stick | **Allowed**, no incident | No over-blocking — the product must not break normal use |
| B3 | Evasion: truncated / reformatted | Copy a truncated OPORD variant | **Blocked** (containment still ≥0.15) | Fingerprint survives edits — a renamer/truncator can't slip data out |
| B4 | EDM row match | Copy the EDM text file | **Blocked** (row-2 exact-data hit) | Structured PII (names + service numbers) is caught even without the document |
| B5 | Oversized file skipped | Copy a >100 MB file | **Allowed** but noted `SkippedTooLarge` | Honest limit — huge files aren't scanned; you must know the ceiling |
| B6 | Unreadable content | Copy an **encrypted zip** of OPORD | Treated `unreadable` → **fail-secure** (blocked if fail-block on) | Attackers wrap data to defeat scanning; fail-secure denies the unknown |
| B7 | Borderline 0.05–0.15 | Copy a file with a *small* snippet of OPORD | **Allowed** to an untrusted stick (below block line) | Documents the accepted residual band, so it's not mistaken for a bug |

☐ B1 ☐ B2 ☐ B3 ☐ B4 ☐ B5 ☐ B6 ☐ B7

---

## Group C — Encrypt-on-write (write to a TRUSTED stick)

Whitelist the stick (Trusted USB devices → serial or VID:PID → **Encrypt
sensitive**, pick a key + block-band). Wait for `synced trusted config
destinations=1 keys=1` (or `sc stop/start DLPAgent`).

| ID | Purpose | Config | Action | Expected | Why it matters |
|---|---|---|---|---|---|
| C1 | Seal a sensitive file | mode=encrypt_sensitive | Copy `OPORD.pdf` → trusted stick | Lands as **`OPORD.pdf.dlpenc`**, plaintext removed; incident `action=Encrypted`, keyId | Courier use — data leaves *only* sealed |
| C2 | Pass a clean file in plaintext | mode=encrypt_sensitive | Copy innocent file → trusted stick | **Plaintext copy**, not sealed | Don't encrypt everything — only sensitive content |
| C3 | Courier mode seals everything | mode=encrypt_all | Copy any file → trusted stick | **Everything sealed** (even clean) | Whole-media courier posture, no cached bundle needed |
| C4 | Block-band = "block" on a full match | on_block_band=block | Copy full OPORD → trusted stick | **Blocked** (too sensitive even to seal out) | Highest classification may be forbidden from leaving at all |
| C5 | Block-band = "seal" on a full match | on_block_band=seal | Copy full OPORD → trusted stick | **Sealed armoured** instead of blocked | Lets the most-sensitive files leave, but only encrypted |
| C6 | No key / sealer unhealthy | destroy/omit the key | Copy sensitive → trusted stick | **Blocked** `seal-unavailable-blocked` — never plaintext | If we *can't* seal, we must not fall back to plaintext |

☐ C1 ☐ C2 ☐ C3 ☐ C4 ☐ C5 ☐ C6

---

## Group D — Decrypt sealed files

| ID | Purpose | Action | Expected | Why it matters |
|---|---|---|---|---|
| D1 | Authorised decrypt | `dlp-agent decrypt E:\OPORD.pdf.dlpenc -o out.pdf` on the **enrolled** endpoint | Plaintext written; **audit incident recorded first** (`Decrypted`) | The org can open its own sealed data — with an audit trail |
| D2 | Decrypt without the key | Same on a PC with **no agent/key** | **`DecryptDenied`**, nothing written, non-zero exit | Sealed media is useless outside the org |
| D3 | Crypto-shred | Destroy the key in the console, then D1 again | **Un-decryptable everywhere** | Instant remote "wipe" of all media sealed with that key |

☐ D1 ☐ D2 ☐ D3

---

## Group E — Device control (standalone `usb-monitor --enforce`)

**Stop the service first** (`sc stop DLPAgent`) so there's no port contention, then
run `dlp-agent usb-monitor --enforce` as **Admin**. ⚠️ These modify the machine —
VM only, snapshot first.

| ID | Purpose | Config | Action | Expected | Why it matters |
|---|---|---|---|---|---|
| E1 | Read-only enforcement | default_action=read_only | Plug stick | Stick becomes **write-protected** (`WriteProtect=1`); revert clears it | Softer control — read allowed, no data out |
| E2 | Block = dismount | default_action=block | Plug stick | Volume **dismounted** (disappears) | Hard control for unknown devices |
| E3 | Non-admin fails safe | run `--enforce` as standard user | — | `EnforcementFailed` incident, monitor keeps running | Must not crash or silently do nothing if it can't enforce |
| E4 | MTP / tethering block | mtp_action=block | Plug phone / tethering | Read/write **denied** (WPD registry) / adapter blocked | The non-drive-letter egress paths |

☐ E1 ☐ E2 ☐ E3 ☐ E4

---

## Group F — Fail-secure & residual edge cases

| ID | Purpose | Action | Expected | Why it matters |
|---|---|---|---|---|
| F1 | Guard down → deny all | Kill `usb-guard` / stop the service (FailMode=1) | **All** removable writes denied | Killing the agent must not *enable* exfil |
| F2 | No bundle → fail-secure | Remove the cached bundle, `fail_block=true` | Sensitive (and unknowable) writes **blocked** | Never fall open when we can't classify |
| F3 | Settle-window residue | Copy sensitive, **yank the stick immediately** | Plaintext may remain (block/seal hadn't fired) | The known v1 gap — must be documented, not hidden |
| F4 | Offline incident queue | Disconnect from server, trigger a block | Incident queued in `state_dir\usb-incident-queue\`, **flushed on next check-in** | No incident is lost when the server is unreachable |
| F5 | Partial-copy settle | Copy a large file slowly | Scanned only after it stops growing (`settled-by-timeout`) | Avoids scanning half-written files (false verdicts) |

☐ F1 ☐ F2 ☐ F3 ☐ F4 ☐ F5

---

## Confirmation cheat-sheet (how to read every result)
- **Endpoint log** `C:\ProgramData\DLPAgent\logs\dlp-agent.log`: `removable device arrived`,
  `kernel-blocked`, `allowed-pending-seal`, `sealed-post-write`,
  `seal-unavailable-blocked`, `kguard incident reported kind=Match`.
- **Toast**: "Blocked by DLP · File · USB · Ref INC-…" (unless `notify.mode=covert`).
- **Console → Incidents** (incident_reviewer): channels `usb`, `usb-kguard`,
  `usb-audit`; action `Blocked` / `Encrypted` / `Audited`; matched doc + containment.
- **Console → Audit** (auditor): key creation, whitelist changes, key deliveries,
  decrypts — all append-only.

## Traps (from the doc review — verify, don't assume)
- **FailMode**: the INF ships `0` (allow+audit); the product wants `1`. Check the
  loaded value: `reg query HKLM\SYSTEM\CurrentControlSet\Services\dlpflt /v FailMode`.
  Changing it needs `fltmc unload dlpflt; fltmc load dlpflt`.
- **MTP/tethering are OFF under the service** — only Group E (standalone `--enforce`) exercises them.
- **Only one guard may hold the port** — stop the service before a standalone guard, or you get `No waiter 0x801F0020`.
- **Seal incident rows** may render thin in the console (server mapping was fixed
  late) — verify C1/D1 actually show up.
