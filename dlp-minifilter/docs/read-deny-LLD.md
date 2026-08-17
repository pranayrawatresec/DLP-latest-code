# Content-Aware Read-Deny for Exfil Channels — LLD

**Goal:** when an **exfil-capable process** (a remote-access tool, or any process holding a live
connection to a remote peer) reads a **sensitive** file, **deny the read** (`STATUS_ACCESS_DENIED`)
so the bytes never reach the tool — while ordinary apps read the same file normally and the tool
transfers non-sensitive files normally. This is the only content-aware way to stop AnyDesk / RustDesk
/ VNC / C2 file exfil, because the wire is encrypted/pinned/P2P; the file *read* is the one plaintext
chokepoint on the endpoint.

Read-deny = *don't let the exfil tool obtain the bytes at all* — no multi-process problem, no
async race, no encryption problem. (An earlier read-taint layer — let the read happen, then cut
the reader's network — was removed 2026-08-13; read-deny is the sole read-side enforcement.)

Everything is gated by a registry switch (`ExfilReadBlockEnabled`, default 0 = off).

---

## 1. The decision (evaluated in `DlpPreRead`, IRP_MJ_READ pre-op)

```
deny a read  iff  (requestor PID is an EXFIL channel)
             AND  (the target file is SENSITIVE)
             AND  (the file is in scope — removable, or a fixed watch prefix)
```
Anything else → allow (`FLT_PREOP_SUCCESS_NO_CALLBACK`). The two gates are independent signals:
"who is reading" (exfil-capability) and "what is being read" (content).

## 2. "Who" — the exfil-PID set (user-mode owned, kernel-consulted)

The **agent** owns the definition and pushes a bounded PID set to the driver; the driver just consults
it (fast, spinlock, at ≤DISPATCH). A PID is an exfil channel if EITHER:
- **Signature** — its image matches the remote-tool set (rustdesk/anydesk/*vnc*/tv_*/etc.), OR
- **Behavioral** — it currently holds an **ESTABLISHED TCP connection to a non-local peer**
  (RFC1918/loopback/link-local excluded). This catches unknown C2 / custom VNC with no signature.

The agent recomputes the set on a short interval (process enum + `GetExtendedTcpTable`) and pushes the
full set to the driver via a new `DLP_EXFIL_UPDATE` message (full-replace, bounded to
`DLP_EXFIL_MAX`). Kernel storage mirrors the BadHash ring exactly (KSPIN_LOCK, epoch stamp, PID+CreateTime
reuse guard). Process-exit `DlpCreateProcessNotify` also removes exited PIDs (defence in depth).

Rationale for user-mode ownership: signature matching + TCP-table correlation are trivial in user mode
and awful in kernel; the kernel only needs the resulting PID set for the hot-path lookup.

## 3. "What" — content classification (reuse everything)

At `DlpPreRead`, once (exfil PID + in-scope) is established, classify the file:
1. **SensFile cache hit (sensitive)** → deny now. (Cheapest; no read, no up-call.)
2. **SensFile/clean cache** → allow (`SUCCESS_NO_CALLBACK`) — add a small "clean file-id" cache so a
   tool re-reading an innocent file is cheap.
3. **Unknown** → SYNCHRONOUS classify at PASSIVE: `DlpReadStreamContent` (in-kernel, offset 0) →
   known-bad-hash ring → else `DlpQueryVerdict(Reason=READ)` up-call (bounded timeout, circuit
   breaker). Seed the sensfile/clean caches on `NT_SUCCESS`. Deny if BLOCK, else allow.
   - Fail-secure: on a verdict failure with `ExfilReadFailBlock`, deny (an exfil tool must not read an
     unverifiable file); default is deny (an exfil channel + unverifiable = block).

The synchronous up-call only happens on the FIRST unknown read by an exfil process of an in-scope file
— rare. The driver's own `FltReadFile` is attributed to System/top-level-IRP and skipped by
`DlpShouldSkip` (no re-entrancy).

## 4. `DlpPreRead` gate order (hot path — cheapest first)

```
1. ExfilReadBlockEnabled == 0            -> SUCCESS_NO_CALLBACK
2. DlpShouldSkip (paging IO / !PASSIVE / IoGetTopLevelIrp!=NULL / agent-PID / System)  -> SUCCESS_NO_CALLBACK
3. requestor PID not in exfil set        -> SUCCESS_NO_CALLBACK   (spinlock lookup; the common case)
4. zero-length read                      -> SUCCESS_NO_CALLBACK
5. resolve name; not in scope (fixed & !watched) -> SUCCESS_NO_CALLBACK
6. classify (sensfile/clean cache, else sync read + verdict)
7. SENSITIVE  -> FLT_PREOP_COMPLETE, IoStatus.Status = STATUS_ACCESS_DENIED, Information = 0
   CLEAN      -> SUCCESS_NO_CALLBACK
```
Non-exfil processes exit at step 3 with a single spinlocked array scan — negligible overhead; ordinary
file I/O is unaffected.

## 5. Deny mechanics
`Data->IoStatus.Status = STATUS_ACCESS_DENIED; Data->IoStatus.Information = 0; return FLT_PREOP_COMPLETE;`
The tool's `ReadFile` fails → its file transfer aborts. We raise an incident (channel `exfil-read`,
action Blocked) via the existing up-call incident path.

## 6. Safety / correctness
- **IRQL:** all fingerprint/read/up-call work is gated behind `DlpShouldSkip` (PASSIVE + top-level-IRP
  NULL). The exfil-set lookup is a bounded spinlocked scan, safe at ≤DISPATCH.
- **Re-entrancy:** the driver's own `FltReadFile` is skipped (System PID / top-level IRP), exactly like
  the write path.
- **No deadlock:** the up-call uses the existing bounded timeout + circuit breaker; a wedged agent
  fails-safe (deny per `ExfilReadFailBlock`, default deny for exfil channels) and never hangs a read
  beyond the ceiling.
- **Fail-safe scoping:** a failed name query, an oversized file (truncated flag), or an unknown scope
  fails toward the conservative side but NEVER crashes.
- **Default off:** `ExfilReadBlockEnabled=0` → `DlpPreRead` returns at step 1; behaviour identical to
  today. Opt-in, fail-safe.
- **Tamper:** the exfil set + read-deny live in the kernel; killing the user-mode agent stops PID-set
  updates but the last-known set + fail-secure still apply, and the agent process itself is
  ObCallbacks-protected.

## 7. What it does NOT do (honest limits)
- **Analog hole** (screen view + photo / retype) — unstoppable by any software.
- **Kernel-privileged C2** reading raw disk beneath the filter — needs EDR + Secure Boot.
- **First-read-before-classified for a brand-new file an exfil tool creates+reads instantly** — covered
  by the synchronous classify, but if content is unreadable/unsupported it falls to `ExfilReadFailBlock`.
- **Encrypted-at-rest** content the agent can't fingerprint.
- **mmap / section reads** — v1 targets buffered/cached `ReadFile` (the file-transfer path); section
  reads are a noted follow-on.

## 8. Config / registry
- `ExfilReadBlockEnabled` (DWORD, default 0) — master switch.
- `ExfilReadFailBlock` (DWORD, default 1) — deny on unverifiable content for an exfil process.
- Reuses `[kguard] scan_fixed` + `watch_paths` for scope.

## 9. Message contract (user -> kernel)
`DLP_EXFIL_UPDATE` — its own version, full-replace, bounded array. Independent of `DLP_MSG_VERSION`
(scan request/reply) and `DLP_CONFIG` (scan scope). Mirrored `#[repr(C)]` on the Rust side + size-locked.

## 10. Test matrix (VM)
- **RD-01** RustDesk copies OPORD (sensitive) from victim → **read denied**, transfer fails.
- **RD-02** RustDesk copies an innocent file → **allowed** (transfers fine).
- **RD-03** Word/Notepad opens OPORD locally → **allowed** (not an exfil process).
- **RD-04** Unknown tool with a live remote connection reads OPORD → **denied** (behavioral signal).
- **RD-05** Default off (`ExfilReadBlockEnabled=0`) → nothing denied.
- **RD-06** Agent killed mid-session → last set + fail-secure still deny; no crash.
- **RD-07** Driver Verifier (Pool/IRQL/Deadlock/DDI) clean under a copy flood.
