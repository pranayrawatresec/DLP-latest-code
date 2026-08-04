# Tier 1 Completion — Engineering Spec (Clipboard + Device-Control ext + Minifilter ext)

**Goal:** complete Tier 1 of `docs/egress-channels.html` **except print (⑥)** — three workstreams:
1. **Clipboard channel (⑤)** — new user-mode module (`dlp-agent/src/clipboard/`).
2. **Device-control extension (②)** — MTP/WPD block + USB-tethering block (extend `dlp-agent/src/usb/`).
3. **Minifilter extension (①)** — attach to fixed + network volumes with a watch-path set (extend
   `dlp-minifilter/src/dlpflt.c`).

**Verification boundary (honesty — read first):**
- Workstreams 1 & 2 are user-mode Rust: **`cargo build` + tests are verifiable here**; message-loop /
  live-device / live-registry behavior is operator MANUAL.
- Workstream 3 is a kernel driver: **compiles/links/`cl /analyze` here**; ALL runtime (loading,
  blocking, no-BSOD, fixed-volume performance) is operator MANUAL on a VM. Do NOT claim runtime.
- **Print (⑥) is explicitly OUT of scope.** **CD/DVD burn** is NOT given a dedicated IMAPI hook;
  document that its on-disk staging is partially covered by the fixed-volume minifilter, full
  burn-time block deferred.

Respect every DO-NOT. Prefer the fail-secure and testable option when ambiguous.

---

## Workstream 1 — Clipboard channel (⑤)  [user-mode, fully verifiable here]

### 1.1 Module `dlp-agent/src/clipboard/`
- `mod.rs` — `run_monitor(cfg, storage, bundle, enforce)` + public types.
- `watch.rs` — message-only window (`CreateWindowExW` HWND_MESSAGE) + `AddClipboardFormatListener`
  → `WM_CLIPBOARDUPDATE`. **Dedup by `GetClipboardSequenceNumber`.** NO message loop in any test path
  (a loop hangs `cargo test`) — factor the "on clipboard snapshot" logic into a pure function the
  tests drive directly.
- `formats.rs` — read + classify clipboard formats into an inspectable payload:
  - `CF_UNICODETEXT` → text.
  - `CF_HDROP` → list of file paths → each scanned via existing `detect::verdict(path)`.
  - `CF_HTML` / `CF_RTF` → strip to text (best-effort) → text.
  - `CF_DIB`/`CF_BITMAP` (image) → **not inspectable without OCR → out of scope**; record an
    "image-clipboard (uninspected)" note; policy may allow or block-images-wholesale (config).
  - Pure parsing (bytes → payload) must be unit-testable with synthetic buffers.
- `enforce.rs` — actions: `AllowAudited` (incident only), `Block` = `EmptyClipboard()` so the paste
  yields nothing (optionally set a short redaction-notice text). **Loop guard:** our own
  `EmptyClipboard`/`SetClipboardData` bumps the sequence number and re-fires `WM_CLIPBOARDUPDATE` —
  record the sequence number we just wrote and ignore the next update that matches it.

### 1.2 Detection on clipboard text — the one allowed `detect/` change
- Add `detect::verdict_text(text: &str, bundle: &Bundle) -> Verdict` by **refactoring** `verdict.rs`:
  extract the post-extraction matching (IDM containment/coverage + EDM proximity) into a core that
  BOTH `verdict(path)` (after `extract_text`) and `verdict_text` call. **The fingerprint MATH
  (normalize/shingle/winnow) and all scoring must be byte-identical — `tests/golden_vectors.rs` and
  every existing test MUST still pass unchanged.** This is the ONLY permitted edit under `detect/`;
  do not alter the math or the existing `verdict(path)` behavior/output.
- Clipboard text is usually a snippet → expect low `containment`, high `coverage`; EDM fires well on a
  copied row. Policy (§ shared) decides on either signal.

### 1.3 Wiring / config / CLI
- `clipboard-monitor [--enforce]` subcommand (audit-only default). Independent of the check-in loop.
- `[clipboard]` config: `enabled`, `default_action` (allow_audited|block), `max_bytes` (skip huge
  payloads), `block_images` (bool, default false), `channel_label` ("clipboard").
- Incidents reuse the existing usb/incident path + offline queue; `channel = "clipboard"`; carry
  content **hashes/verdict metadata only, never the copied text**.

### 1.4 Edge cases (implement/handle)
1. Clipboard locked by another process (`OpenClipboard` fails) → retry a few times w/ backoff, then
   skip with a note. Never spin.
2. Delayed rendering (`GetClipboardData` returns NULL / renders on demand) → handle NULL gracefully.
3. Rapid successive changes → sequence-number dedup + debounce.
4. Our own clear re-firing the listener → loop guard (§1.1).
5. Huge clipboard payload → `max_bytes` cap, skip-with-note.
6. Non-text/image formats → uninspected note; do not crash.
7. No bundle cached → audit logs "no-policy"; `--enforce` fails secure per config.

### 1.5 Tests (verifiable here)
- `formats` unit: synthetic `CF_HDROP`/`CF_UNICODETEXT` buffers → correct payload.
- `detect::verdict_text` unit: known text that matches a fixture bundle doc → non-empty idm; innocent
  text → empty. (Reuse the bundle-sample fixture or build a tiny bundle.)
- decision unit: allow/block per policy + signals; loop-guard logic (writing sets the ignore-seq).
- `tests/golden_vectors.rs` + all existing agent tests still green (proves the verdict refactor is
  behavior-preserving).

---

## Workstream 2 — Device-control extension (②)  [user-mode, logic verifiable here]

Extend `dlp-agent/src/usb/`.

### 2.1 MTP/WPD block (phones, cameras)
- New enforce action targeting the **WPD device setup class**: registry
  `HKLM\Software\Policies\Microsoft\Windows\RemovableStorageDevices\{6AC27878-A6FA-4155-BA85-F98F491D4F33}`
  DWORDs `Deny_Read` / `Deny_Write` (= 1 to deny). Reverting clears them.
- Today the watcher emits "mtp-device-present (informational)"; now `policy.decide()` can return an MTP
  action and `enforce.rs` applies the WPD policy. **Dry-run `PlannedAction::SetWpdDeny{read,write}`**
  returned + tested; live registry write behind `--enforce` + admin, MANUAL.

### 2.2 USB tethering block (RNDIS / USB-network)
- Detect a USB device presenting as a network interface (RNDIS/NCM). Block via Device Installation
  Restriction on the net class or disabling the devnode. `PlannedAction::BlockTethering` dry-run +
  tested; live MANUAL.

### 2.3 Config / policy / tests
- Extend `[usb]`: `mtp_action` (allow_audited|block, default block for defence), `tethering_action`
  (allow|block, default block). Absent = safe defaults.
- Unit tests: policy returns the right action for an MTP identity vs mass-storage vs tethering;
  enforce dry-run yields the correct `PlannedAction` (WPD reg values / tethering) **without executing**.

---

## Workstream 3 — Minifilter extension (①)  [kernel, compile-verifiable here]

Extend `dlp-minifilter/src/dlpflt.c` from removable-only to fixed + network volumes.

### 3.1 Attach policy (`InstanceSetupCallback`)
- **Removable** volumes → attach (as today).
- **Network (SMB) redirector** volumes → attach (copying to a share is a target). Detect via volume
  device type / `FLT_FSTYPE` / `FltGetVolumeProperties`.
- **Fixed** volumes → attach ONLY IF a non-empty **watch-path set** is configured (else
  `STATUS_FLT_DO_NOT_ATTACH`, preserving today's safety on machines with no watch set).
- Never attach to the boot/system paging structures beyond what's needed; skip unsupported FS types.

### 3.2 Inspection filter (performance-critical — §research)
- **Removable + network** instances: inspect all dirty files at CLEANUP (as today).
- **Fixed** instances: at CLEANUP, quick-reject unless the file path is **under a configured watch
  path** (sync folders e.g. `\Users\*\OneDrive`, `\Users\*\Dropbox`, `\Users\*\Google Drive`, or an
  explicit staging dir). Do the expensive `FltGetFileNameInformation` **lazily** — only for dirty
  files on attached instances — and compare against the watch-set prefix. This keeps the C: hot path
  cheap (most writes rejected by instance-type/volume before any name query).
- Watch-path set + volume-scope config delivered from user-mode **over the comms port at connect**
  (a new `DLP_CONFIG` message: array of watch prefixes + flags for fixed/network scanning). Kernel
  stores it in a filter-global struct; empty = removable-only behavior (backward compatible).

### 3.3 Correctness (unchanged rules still apply)
- Self-skip by service PID (else deadlock — the service reads watched files on C:/share now too).
- Skip paging I/O, directories, volume opens, reparse.
- IRQL/passive rules, contexts from NonPagedPool, clean unload.
- **No content over the port** — path + metadata only.

### 3.4 CD/DVD burn — honest note (no dedicated hook)
IMAPI stages files to a system-volume staging folder before committing to disc. With fixed-volume +
watch/staging coverage, those staging writes are **partially** caught. True burn-time interception
(IMAPI COM hook) is a separate mechanism, **deferred** — say so in the README/spec, do not claim full
CD coverage.

### 3.5 Build/verify (kernel)
- `build/build-driver.bat` compiles the extended `dlpflt.c` (+ any new `.c`) to `dlpflt.sys`,
  `/W4 /WX` clean (proven recipe in `dlp-minifilter/SPEC.md` §7).
- `build/analyze.bat` (`cl /analyze`) clean on our source.
- Runtime is MANUAL (VM). The extended attach touches fixed volumes → higher risk; the README must
  stress VM-only testing and that an empty watch-set = safe removable-only behavior.

---

## Shared: policy signals
All channels decide via the same rule shape (reuse/introduce a small policy helper):
`block` if `containment >= block_at` OR `coverage >= coverage_block_at` OR any EDM row hit OR
(`unreadable` AND channel is file-bearing AND fail-secure); else `warn` at the warn thresholds; else
`allow`. Thresholds come from config now (server-authored policy is a later build). Every decision →
incident + (enforce) action.

## DO NOT
- DO NOT implement print (⑥) or a dedicated CD/DVD IMAPI hook.
- DO NOT change the fingerprint MATH or `verdict(path)` behavior; the ONLY `detect/` edit is adding
  `verdict_text` via behavior-preserving refactor (golden vectors must pass).
- DO NOT put a Windows message loop (clipboard) in any test path.
- DO NOT log clipboard text, file contents, or send content over the minifilter port.
- DO NOT execute live registry/devnode/clipboard-clear actions in automated tests — dry-run/pure-logic
  only; live behind `--enforce`, MANUAL.
- DO NOT attach the minifilter to fixed volumes when the watch-set is empty (safety/back-compat).
- DO NOT add heavy new crates; use the `windows` crate (extend features: Win32_System_DataExchange,
  Win32_System_Memory, Win32_UI_WindowsAndMessaging for clipboard; Win32_System_Registry already used).

## Acceptance criteria
1. `cargo build --release` clean (no new warnings); ALL existing agent tests still pass incl.
   `golden_vectors` (proves the `verdict_text` refactor preserved behavior).
2. New clipboard tests (formats parse, `verdict_text` match/no-match, decision + loop-guard) pass.
3. New device-ext tests (MTP/tethering policy decisions + enforce dry-run PlannedActions) pass.
4. `clipboard-monitor --help` and updated `usb-monitor --help` document the new actions; audit-only
   defaults; `--enforce` gated.
5. Minifilter: `build-driver.bat` + `analyze.bat` clean; empty watch-set = removable-only
   (back-compat) confirmed by code review; `usb-guard`/config can supply the watch-set.
6. No content logging / no content over the port (grep-confirmed).
7. Manual-only items documented (live clipboard clear, live WPD/tethering registry, kernel runtime on
   fixed/network volumes).
8. Honest final report: real build/test outputs, MET/NOT per criterion, manual-only list, deviations.
