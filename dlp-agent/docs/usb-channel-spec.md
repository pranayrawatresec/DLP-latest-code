# USB Removable-Media Channel — Engineering Spec (Tier 1, Phase A1)

**Status:** build spec for the agent's first enforcement channel.
**Scope of THIS build:** user-mode USB removable-media **device control + copy auditing** in the
Rust agent. **Out of scope of this build (design-only, separate track):** the kernel filesystem
minifilter that does true pre-write *blocking*. See §9.

This document is the contract for the implementation. Build exactly what §3–§6 say, respect every
DO-NOT in §7, and meet every acceptance criterion in §8. When something is ambiguous, prefer the
**fail-secure** and **testable** option.

---

## 1. Why user-mode first (and what it does / doesn't buy)

The minifilter (kernel) is the only way to *block a write before it lands*. But it needs WDK, EV
signing + MS attestation, a test-signing VM, and cannot be exercised in `cargo test`. So we build the
**user-mode layer first**, which is real, shippable, and fully verifiable here:

- **Device control** — detect a removable device on arrival, identify it (VID/PID/serial/bus), and
  apply an allow / read-only / block policy using built-in Windows facilities (registry
  `WriteProtect`, `CM_Disable_DevNode`). No driver needed.
- **Copy auditing** — watch the removable volume; when a file is written to it, run the existing
  `detect::verdict()` and raise an **incident** (reuse the mTLS incident path). This is *detect +
  audit*, not pre-write block: the file may briefly exist on the stick, then we flag (and, in a later
  minifilter upgrade, block/quarantine).

This is honest about the gap: **audit-mode catches and attributes; it does not guarantee prevention.**
The minifilter (§9) closes that gap later and reuses everything here.

---

## 2. Architecture (where the new code sits)

```
                dlp-agent (existing binary)
  main.rs  ──►  new subcommand:  usb-monitor  [--enforce]
                     │
                     ▼
              src/usb/mod.rs   run_monitor(cfg, storage, bundle_opt)
                     │
     ┌───────────────┼───────────────┬──────────────────┐
     ▼               ▼               ▼                  ▼
 usb/watch.rs   usb/device.rs   usb/policy.rs      usb/audit.rs
 volume         identity        decide()           watch a volume,
 arrival/       (VID/PID/       allow/ro/block     on file settle →
 removal        serial/bus)     (pure logic)       detect::verdict()
 (polling)          │               │                  │
                    └──────► usb/enforce.rs ◄───────────┘
                    apply action (registry WriteProtect / CM_Disable_DevNode)
                    + emit incidents (reuse main.rs report path)
```

Reuse, do not reinvent:
- **Detection:** `detect::verdict(path, &bundle) -> Verdict` (already built + golden-tested).
- **Bundle:** `detect::Bundle::load(bytes, ca_pem)`; the cached bundle at `storage.load_index_bundle()`.
- **Incidents:** the `report_incident(cfg, storage, channel, verdict)` flow already in `main.rs`
  (POST `/agent/incidents` over mTLS). Refactor it into a callable helper if needed; channel label
  for this work is **`usb`** (audit) — keep it configurable.
- **Config:** extend `Config` with an optional `usb` section (§6).

---

## 3. Components — what to build

### 3.1 `usb/device.rs` — removable-volume enumeration + identity
- Enumerate current volumes: `GetLogicalDrives` → for each, `GetDriveTypeW`.
- **Removable classification — CRITICAL EDGE CASE:** `DRIVE_REMOVABLE` catches flash drives, but
  **external USB HDDs/SSDs frequently report `DRIVE_FIXED`**. Do NOT rely on drive type alone.
  Resolve the **bus type** via `IOCTL_STORAGE_QUERY_PROPERTY` (`StorageDeviceProperty` →
  `STORAGE_DEVICE_DESCRIPTOR.BusType`) on `\\.\X:`; treat `BusTypeUsb` (and `BusTypeSd`,
  `BusTypeMmc`) as removable regardless of drive-type. This prevents both misses (USB SSD seen as
  fixed) and false hits (the OS disk).
- `DeviceIdentity { drive_letter, vendor_id, product_id, serial, product_name, bus_type, removable }`
  from `STORAGE_DEVICE_DESCRIPTOR` (parse `VendorIdOffset`/`ProductIdOffset`/`SerialNumberOffset`
  into the returned buffer).
- **Testability requirement:** factor the descriptor-buffer → `DeviceIdentity` parsing into a pure
  function `parse_storage_descriptor(&[u8]) -> DeviceIdentity` that a unit test drives with a
  **synthetic buffer** (hand-built bytes with known offsets/strings). The IOCTL call itself is a thin
  wrapper the test does not need to hit.

### 3.2 `usb/watch.rs` — device arrival/removal detection
- **Primary mechanism: polling.** Every `poll_interval` (default 2s) snapshot the set of removable
  volumes (via §3.1) and diff against the last snapshot → emit `Arrived(DeviceIdentity)` /
  `Removed(drive_letter)`. Polling is chosen because it is robust, needs no message loop, and is
  **unit-testable** (feed it two successive volume sets, assert the diff events).
- `WM_DEVICECHANGE` (message-only window) is an **optional** low-latency enhancement, NOT required for
  v0, and MUST NOT be placed in any test path (a message loop hangs `cargo test`). If added, keep it
  behind the same event interface so tests use the polling path.

### 3.3 `usb/policy.rs` — the decision engine (PURE LOGIC — the most-tested file)
```
enum Action { AllowAudited, ReadOnly, Block }
struct DeviceRule { match: RuleMatch, action: Action, note: Option<String> }
enum RuleMatch { Serial(String), VidPid{vid,pid}, BusType(String), Any }
struct UsbPolicy { default_action: Action, rules: Vec<DeviceRule> }
fn decide(policy: &UsbPolicy, dev: &DeviceIdentity) -> (Action, Option<matched_rule>)
```
- **First match wins**, else `default_action`.
- **Unknown device → default, and the default is fail-secure** (recommend `Block` for defence, or
  `ReadOnly`; never silently `AllowAudited` by omission — the config must state it).
- Serial matching is a **convenience allowlist, not a security control** (serials are spoofable);
  document that. Read-only/audit still applies to allowed devices (defense in depth).
- No I/O, no Windows calls in this file — pure functions only.

### 3.4 `usb/enforce.rs` — apply the action  ⚠️ modifies the live system
- **ReadOnly:** set `HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies` `WriteProtect=1`
  (fleet-wide RO for removable) and/or the per-class `RemovableStorageDevices` GPO `Deny_Write`.
  Reverting on policy change must be supported.
- **Block:** `CM_Disable_DevNode` on the device instance (needs SYSTEM/admin), or dismount the volume.
- **HARD REQUIREMENT — do not brick the dev machine or the test runner:** `enforce` MUST support a
  **dry-run** mode that returns a `PlannedAction` (which registry value it *would* set / which devnode
  it *would* disable) **without executing it**. All automated tests use dry-run and assert the plan.
  Real enforcement is a **manual test only** (§8, MANUAL-TEST). Guard live enforcement behind the
  explicit `--enforce` CLI flag AND a config opt-in; default is audit-only.
- Handle failure (not admin, devnode busy) gracefully: log a structured warning, raise an incident of
  type "enforcement-failed", never crash the monitor.

### 3.5 `usb/audit.rs` — the copy auditor (the heart of v0 value)
- Given a volume root path, detect files written to it and scan them.
- **Detection of new/changed files:** `ReadDirectoryChangesW` (recursive) is the target mechanism, but
  for **testability the watched root MUST be injectable** — a plain directory path — so an integration
  test can point it at a temp dir. A simple recursive poll-scan of the tree (name+size+mtime diff) is
  an acceptable v0 implementation and is trivially testable; `ReadDirectoryChangesW` may be added as an
  enhancement behind the same interface.
- **Inspect-on-settle (EDGE CASE — partial writes):** a file mid-copy fires many events and is
  incomplete/locked. Do NOT scan on first sight. Wait until the file is **stable**: size unchanged for
  `settle_ms` (default 1500ms) AND openable with `FILE_SHARE_READ`. Cap the wait (`settle_timeout`,
  default 30s) → if still growing, scan once at timeout and note "settled-by-timeout".
- **Scan:** read the settled file (respect `max_file_bytes`, default 100MB — skip larger with an
  incident note), call `detect::verdict(path, &bundle)`. If `idm` or `edm` non-empty → build the
  incident. If `extraction == Unreadable` on a removable target → that is itself notable
  (**fail-secure hook**): raise a low-severity "unreadable-on-removable" incident (a later minifilter
  in enforce-mode would *block* this).
- **Dedup (EDGE CASE — bulk copy / re-scan):** maintain a bounded seen-set keyed by
  `(path, size, mtime)` (or content sha256) so the same file is not scanned repeatedly across poll
  cycles. Bound the set (e.g. LRU, cap 10k) so it can't grow without limit.
- **Concurrency (EDGE CASE — 500 files at once):** use a **bounded** worker pool (e.g. 2–4 workers),
  never spawn one thread per file. A bulk copy must not exhaust the machine.
- **Volume removed mid-scan:** reads fail → catch, stop watching that volume, do not crash.
- **Testability requirement:** the audit pipeline (settle → verdict → incident) must be exercised by
  an integration test using a temp directory as a simulated volume (§8). Allow the verdict source to
  be injectable (a `Fn(&Path) -> Verdict`) so the test can validate the settle/dedup/incident logic
  deterministically without depending on live fingerprint math (which is already golden-tested).

### 3.6 `usb/mod.rs` + `main.rs` wiring
- `run_monitor(cfg, storage, enforce: bool)`:
  1. Load the cached bundle (`storage.load_index_bundle()` → `Bundle::load` with the pinned CA). If
     none: audit still runs but every scan yields "no-policy" (log once); in `--enforce` mode with no
     bundle, **fail secure** per config (default: deny removable writes / read-only). Do not silently
     allow.
  2. Start the watcher (polling). On `Arrived`: resolve identity → `policy.decide()` → if `enforce`,
     apply via `enforce.rs`; always start the copy-auditor for that volume (unless the device is
     hard-Blocked and no longer mounted). On `Removed`: stop that volume's auditor.
  3. Incidents flow through the existing mTLS path when enrolled; when the server is unreachable or the
     agent is unenrolled, **queue incidents locally** (bounded, on disk under state_dir) and flush on
     the next successful check-in. Fail-secure: never drop silently beyond the bound; log the drop.
- `main.rs`: add `usb-monitor` mode. `--enforce` flag (default off = audit-only). `--help` documents
  it. The mode runs its own loop; it must NOT block or be blocked by the check-in loop (separate
  thread or separate process invocation is fine for v0 — separate invocation is simplest).

---

## 4. Data → incident shape
Reuse the existing incident contract. For a USB audit hit, POST to `/agent/incidents`:
```
{ channel: "usb",
  fileName: "<basename on the volume>",
  fileSha256: "<sha256 of the file>",
  verdict: <the detect::Verdict, verbatim> }
```
Add, in the local incident record (not necessarily the server contract), the **device identity**
(serial/vid-pid/drive letter) and the **action taken** (audited / read-only / blocked) so the
reviewer can see *which stick*. If extending the server contract is out of scope for this build, put
device context inside a `context` field the server already stores or in `verdict` — do not block on a
server change; note it as a follow-up.

---

## 5. Edge cases checklist (implement or explicitly handle)
1. External USB SSD/HDD reporting `DRIVE_FIXED` → use bus type, not drive type. (§3.1)
2. File still being copied (partial/locked) → inspect-on-settle with timeout. (§3.5)
3. Very large file → `max_file_bytes` cap, skip-with-note. (§3.5)
4. Locked/exclusive file → open `FILE_SHARE_READ`; on sharing violation retry a few times then
   skip-with-note. (§3.5)
5. Encrypted/unreadable content → `Unreadable` verdict → fail-secure "unreadable-on-removable"
   incident. (§3.5)
6. Bulk copy (hundreds of files) → bounded worker pool + dedup, no thread explosion, incident
   rate-limit/coalesce. (§3.5)
7. Same file re-appearing each poll → `(path,size,mtime)` dedup set, bounded. (§3.5)
8. Volume removed mid-scan → graceful stop, no crash. (§3.5)
9. Temp files created-then-deleted quickly → settle delay naturally skips vanished files.
10. MTP phone (no drive letter) → NOT covered by the volume watcher; detect device arrival and raise
    an "mtp-device-present" informational event; **full MTP content control is design-only** (needs
    WPD). Do not claim MTP files are scanned.
11. Server unreachable / agent unenrolled → queue incidents locally, bounded, flush later. (§3.6)
12. No bundle cached → audit logs "no-policy"; enforce mode fails secure. (§3.6)
13. Not running as admin/SYSTEM → enforcement calls fail; degrade to audit + "enforcement-failed"
    incident, never crash. (§3.4)
14. Reverting read-only when policy changes → enforce must be able to clear `WriteProtect`.

---

## 6. Config additions (`Config` + TOML)
Add an optional `[usb]` section (all fields defaulted; absent section = safe audit-only defaults):
```toml
[usb]
enabled = true
poll_interval_secs = 2
settle_ms = 1500
settle_timeout_secs = 30
max_file_bytes = 104857600      # 100 MB
default_action = "read_only"    # allow_audited | read_only | block  (fail-secure default)
channel_label = "usb"
[[usb.rules]]
match_serial = "0123456789ABCDEF"
action = "allow_audited"
note = "issued IronKey"
```
Parse with serde defaults; unknown/missing section must not break existing configs. Env overrides are
not required for the `[usb]` block.

---

## 7. DO NOT (hard constraints)
- **DO NOT** build or attempt to load a kernel driver / minifilter in this build. Design-only (§9).
- **DO NOT** actually set `WriteProtect`, call `CM_Disable_DevNode`, or dismount anything in automated
  tests. Dry-run only in tests; live enforcement is manual + flag-gated.
- **DO NOT** log file **contents**, or full sensitive text. Incidents carry hashes + metadata only,
  consistent with the existing incident path. Device serials are OK to log at debug.
- **DO NOT** change anything in `detect/` (the fingerprint math is a frozen cross-language contract).
- **DO NOT** block or slow the check-in loop; the monitor is independent.
- **DO NOT** add heavy new dependencies. Use the `windows` crate (extend its feature list) + std +
  what's already present. Justify any new crate in the result.
- **DO NOT** spawn unbounded threads; bounded worker pool only.
- **DO NOT** re-scan the same unchanged file every poll (dedup).
- **DO NOT** put a Windows message loop in any test path.
- **DO NOT** claim MTP/phone file contents are inspected (they are not in this build).

## 7b. Windows crate features likely needed (finalise as required)
`Win32_Storage_FileSystem` (GetLogicalDrives, GetDriveTypeW, CreateFileW, ReadDirectoryChangesW),
`Win32_System_Ioctl` + `Win32_System_IO` (DeviceIoControl, IOCTL_STORAGE_QUERY_PROPERTY),
`Win32_System_Registry` (RegSetValueExW/RegDeleteValueW for WriteProtect),
`Win32_Devices_DeviceAndDriverInstallation` (CM_* / SetupDi* for identity + disable),
`Win32_Foundation`. Keep the feature list minimal — only what compiles the code you actually write.

---

## 8. Acceptance criteria (the "production-grade" bar — all must hold)
1. `cargo build --release` succeeds with **no new warnings** beyond the pre-existing baseline.
2. `cargo test` — **all existing tests still pass** (golden_vectors, extract, bundle_loader), plus:
   - `usb::policy` unit tests: full decision matrix (≥10 cases: serial allow, vid/pid, bus-type, Any,
     default-block, default-read-only, precedence/first-match, unknown→default).
   - `usb::device::parse_storage_descriptor` unit test: a synthetic descriptor buffer → correct
     `DeviceIdentity` (vendor/product/serial extracted at the right offsets; a USB bus type classified
     removable; a fixed OS disk classified non-removable).
   - `tests/usb_audit.rs` integration: a temp dir as a simulated volume; drop a file → after settle it
     is scanned exactly once; a matching verdict produces an incident payload with the right
     channel/fileName/sha256; an innocent/no-match file produces **no** incident; the same file across
     two poll cycles is **not** re-scanned (dedup); a still-growing file is not scanned until settled.
   - `usb::enforce` dry-run test: for a given (policy, device) the `PlannedAction` is the correct
     registry/devnode operation, and **nothing is executed** (assert via the dry-run return, no live
     system change).
3. `dlp-agent usb-monitor --help` works; audit-only is the default; `--enforce` is documented and
   gated.
4. A `[usb]` config section parses; its absence keeps existing configs working.
5. No secrets or file contents logged (grep the new code for content-logging; none allowed).
6. A **MANUAL-TEST** section is added to the spec or a doc, listing the live steps that CANNOT be
   automated here (plug a real USB stick → arrival detected; copy the OPORD → incident raised; set
   read-only → write denied on the stick; unplug → auditor stops). These are labelled manual, not
   claimed as passing.
7. The result report is **honest**: it lists what was actually run (paste real `cargo test` summary),
   what is covered only by manual test, and any deviation from this spec.

---

## 9. Design-only (NOT built here): the kernel minifilter that adds true blocking
Documented so the picture is complete; **do not implement in this build**.
- A filesystem **minifilter** (`fltmgr.sys` client) registers pre-op callbacks on `IRP_MJ_CREATE` /
  `IRP_MJ_WRITE` for removable/network volumes. In the pre-op it **pends** the I/O, sends the target
  to the user-mode agent over a `FilterCommunicationPort`, the agent runs the **same `verdict()`**,
  and returns allow/deny; the filter completes the write or fails it with `STATUS_ACCESS_DENIED`.
- Timing: inspect-on-close-then-quarantine (simpler) vs buffer-and-hold-before-commit (true
  prevention). Start with the former.
- Ships as a small **C/C++** driver (Rust minifilter support is immature); all policy/detection stays
  in the Rust service. Requires WDK, **EV code-signing + Microsoft attestation**, an offline
  driver-update path for air-gapped sites, and a test-signing VM. None of this is verifiable in the
  current environment — hence design-only.
- Everything in this user-mode build (identity, policy, verdict, incidents) is **reused unchanged**;
  the minifilter only replaces the *detection trigger* (kernel write-intercept) and adds *pre-write
  denial*.

---

## 10. Build order for the implementer
1. `usb/policy.rs` + its unit tests (pure logic, no Windows — do this first, fully green).
2. `usb/device.rs` with `parse_storage_descriptor` + synthetic-buffer test; then the live IOCTL
   wrapper (compiled, not unit-hit).
3. `usb/audit.rs` with injectable root + injectable verdict source; `tests/usb_audit.rs`.
4. `usb/enforce.rs` with dry-run `PlannedAction` + test; live path behind flag.
5. `usb/watch.rs` polling + diff unit test.
6. `usb/mod.rs` `run_monitor` + `main.rs` `usb-monitor` subcommand + `Config [usb]`.
7. Full `cargo build --release` + `cargo test`; write the honest result + MANUAL-TEST steps.
