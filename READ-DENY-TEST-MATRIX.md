# Read-deny test matrix

A documented, repeatable acceptance matrix for the kernel read-deny / open-deny
feature — the replacement for ad-hoc "poke the VM by hand" testing. Two layers:

1. **Server (automated, host):** `cd dlp-management-server && npm test` — the
   Node suites cover policy/allowlist/group logic and mTLS delivery
   (`trustedReaders.test.js`, `groups.test.js`, `enrollment.test.js`, …). These
   run in CI with no VM.
2. **Kernel (VM):** the scenarios below, on the VMware test VM via the `vmrun`
   harness. The probe-based rows are automated by
   `dlp-minifilter/tools/verify-read-deny.ps1`; the policy-flip rows need a
   console/policy change and are listed as manual pre-conditions.

## Test assets

| Asset | What | Where |
|---|---|---|
| `openprobe.exe` | **UNSIGNED**, so untrusted regardless of path — the reliable untrusted tool. Modes: `open` (acquire a handle, no read — isolates open-deny), `read` (open **and** read bytes — the untrusted read), `overwrite`/`overwrite-rw` (truncating creates — the #4 empty-file cases). Built from `tools/openprobe.rs` (`rustc -O openprobe.rs -o openprobe.exe`). | `C:\Users\Public\` |
| A sensitive file | Any file the bundle classifies sensitive (e.g. `OPORD.pdf`). | `C:\Users\<user>\Desktop\` or `C:\Users\Public\` |
| A clean file | Any non-sensitive file (e.g. a plain `.txt`), in the watched scope. | `C:\Users\Public\` |

> **Do not use a `cmd.exe` copy (`reader2.exe`) as the untrusted reader.** Once
> the starter allowlist (migration 015) is seeded, `cmd.exe` is trusted by
> publisher **"Microsoft Windows"** — and Authenticode validates by hash, so a
> *copy* keeps that valid signature. It is therefore (correctly) a trusted reader
> and cannot test untrusted-read blocking. Use the unsigned `openprobe read`.

Untrusted probes sleep ~11s so the agent's ~2 s untrusted-PID push flags the PID
before the I/O.

## The matrix

| # | Scenario | Pre-condition | Action | Expected (enforce) |
|---|---|---|---|---|
| T1 | **Direct read** of sensitive by untrusted | read-deny=enforce, C: in scope, file sensitive | `openprobe read SENS` | **READ-DENIED** — in enforce the read-capable open is cancelled, so the bytes never leave; incident kind=Match |
| T2 | **Open-deny, fresh** (delegate close) | as T1, file not yet classified | `openprobe open SENS` | **OPEN-DENIED err=5**; Match incident |
| T3 | **Open-deny, cached** (repeat open) | run T2 first (verdict now cached) | `openprobe open SENS` again (2nd, 3rd) | **OPEN-DENIED err=5** every time (regression guard for the cached-positive fix) |
| T4 | **Memory-mapped read** of sensitive by untrusted | as T1 | untrusted process maps a section over SENS and faults pages in | **DENIED** at section acquire (paging reads never reach PreRead; DlpPreAcquireForSection blocks) |
| T5 | **Empty / new file** overwrite by untrusted | read-deny=enforce | `openprobe overwrite CLEAN_NEW` and `overwrite-rw CLEAN_NEW` | **OPEN-OK** (empty/new → not a positive match; #4 — no data loss, no hang) |
| T6 | **Clean file** read by untrusted | read-deny=enforce, file not sensitive | `openprobe read CLEAN` | **READ-OK** (open succeeds, bytes read) |
| T7 | **Trusted reader** reads sensitive | reader on the allowlist (publisher/path) | trusted app opens+reads SENS | **ALLOWED** (self/trusted); no incident |
| T8 | **Trusted flip** — remove from allowlist | move an app off the allowlist, resync | that app reads SENS | now **BLOCKED** after the agent pulls the updated list |
| T9 | **Monitor mode** | read-deny=monitor | T1/T2 actions | **ALLOWED** but a would-block incident is raised (classify runs, no deny) |
| T10 | **No-bundle / up-call fails** | agent has no fingerprint bundle, or port down | untrusted reads sensitive | fail-secure per `ExfilReadFailBlock` (default deny reads); OPEN not cancelled (fail-safe ≠ positive) |
| T11 | **Kill-switch off** | read-deny=disabled | T1/T2 actions | **ALLOWED** (feature fully off; PreRead/PostCreate no-op) |
| T12 | **Reboot persistence** | installed via installer (auto-start) | reboot, then T1 | **BLOCKED** — driver re-loads and boot-seed re-attaches C: without the agent running yet |
| T13 | **Per-group targeting** | machine assigned to a "monitor" group | T1 on that machine vs a Default (enforce) machine | assigned machine = monitor (allow+incident); Default = enforce (block) |

## Running the automated probe harness (T1–T3, T5, T6)

On the VM (agent running, read-deny=enforce, a sensitive file present):

```powershell
# stages nothing destructive; runs the probes and prints PASS/FAIL per row
powershell -ExecutionPolicy Bypass -File verify-read-deny.ps1 `
    -SensitiveFile "C:\Users\pranay\Desktop\OPORD.pdf"
```

Driven from the host through the `vmrun` harness (copy the script + probes into
the guest, run, copy the result back) — see `vm-verification-harness` notes.

## Notes

- T4 (memory-map) and T10 (no-bundle) are the delicate paths; verify them after
  any change to `DlpExfilClassifyAndCache`, `DlpPreAcquireForSection`, or the
  up-call timeout handling.
- Snapshot the VM before any driver reload (BSOD risk) — `vmrun snapshot`.
- The matrix rows map 1:1 to audit findings: T2/T3 ↔ open-deny (#4 + cached-
  positive fix), T4 ↔ mapped-read, T5 ↔ #4 empty-file scoping, T8 ↔ allowlist
  central-authority, T12 ↔ #8 boot-seed, T13 ↔ per-group targeting.
