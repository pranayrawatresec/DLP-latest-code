# Read-Taint — Authoritative Implementation Checklist (AUDIT)

Audit date: 2026-08-07. Auditor: read-taint audit agent (no implementation code
written). Sources of truth, in order: `read-taint-LLD.md`, `read-taint-HLD.md`,
the frozen `src/dlpflt.h`, and the shipped `src/dlpflt.c` / `src/comms.c` +
the two DONE Rust files (`netfilter/tcpreset.rs`, `kguard/mod.rs`).

This checklist is function-by-function. Each item maps to its LLD section and to
the exact kernel-safety constraints (IRQL, lock, pool tag, rundown, teardown
order, WFP classifyFn contract). It is a work order, not code.

---

## 0. Current-state findings (verified)

| Fact | State | Evidence |
|---|---|---|
| Frozen header `dlpflt.h` | COMPLETE — every struct/field/prototype/tag present | §1 structs, `DLP_FLT_DATA` fields (Taint/SensFile/Scan/Wfp/ProcNotify), `ReadScanState`, `DLP_REASON_*`, tags all present |
| `comms.c` `DlpQueryVerdict(... Reason ...)` | DONE — stamps `request->Reserved = Reason` (line 448) | not to be modified |
| `comms.c` `DlpReadTaintPolicy` / `DlpReadDword` | DONE — reads `ReadTaintEnabled` + `TaintedEgressPolicy` REG_DWORDs, defaults disabled/block-all | not to be modified |
| `dlpflt.c` `IRP_MJ_READ` post-op registered | DONE — `{ IRP_MJ_READ, ...SKIP_PAGING_IO, NULL, DlpPostRead }` in `Callbacks[]` (line 156) | callback array already wired |
| `dlpflt.c` `DlpPostRead` body | **MISSING** — forward-declared (l.89) only | referenced by `Callbacks[]`; no definition |
| `dlpflt.c` `DlpReadStreamContent` | **MISSING** — `static` fwd-decl (l.98), CALLED at l.847 by `DlpInspectStream`, never defined | **this breaks the build today** (C2129) |
| `dlpflt.c` `DlpScanWorker` / `DlpProcessScanJob` / `DlpFreeScanJob` | **MISSING** — `static` fwd-decls (l.105-107), no bodies | — |
| `dlpflt.c` taint table (`DlpTaintLookup/Add/Remove/ResetAll`) | **MISSING** — prototypes in header only | — |
| `dlpflt.c` sensfile cache (`DlpSensFileLookup/Insert`) | **MISSING** — prototypes in header only | — |
| `dlpflt.c` `DlpStartScanWorker` / `DlpStopScanWorker` / `DlpScanEnqueue` | **MISSING** | — |
| `dlpflt.c` `DlpCreateProcessNotify` | **MISSING** | — |
| `dlpflt.c` DriverEntry read-taint wiring | **MISSING** — no new-field init, no `DlpReadTaintPolicy`, no worker/notify/WFP register | DriverEntry ends at FltStartFiltering with no gated block |
| `dlpflt.c` Unload teardown reorder | **MISSING** — current Unload is the pre-read-taint 4-step (Ob → port → sendrundown → unregister) | must become the LLD §5.5 order |
| `src/wfpcallout.c` | **DOES NOT EXIST** — only `comms.c` + `dlpflt.c` in `src/` | glob |
| `build/build-driver.bat` | **NOT UPDATED** — no `wfpcallout.c` step, no `wfpcallout.obj`, no `fwpkclnt.lib` | link line = `dlpflt.obj comms.obj` + fltMgr/ntoskrnl/hal/wdmsec/BufferOverflowFastFailK |
| Rust `tcpreset.rs` + `kguard/mod.rs` | DONE + unit-tested — DO NOT TOUCH | `tainted_egress_action`, `select_pid_rows` are the pure mirrors |

**Current build outcome:** `build-driver.bat` FAILS at `cl /c src\dlpflt.c` with
`error C2129: static function 'DlpReadStreamContent' declared but not defined`.
The tree does not compile the driver today; the read-taint core is entirely
absent below the declarations.

---

## 1. `dlpflt.c` — taint table (LLD §4; mirror the BadHash ring exactly)

Pattern to mirror byte-for-byte: `DlpBadHashLookup` / `DlpBadHashInsert`
(dlpflt.c l.1095-1148) — `KeAcquireSpinLock`/`KeReleaseSpinLock` on a dedicated
`KSPIN_LOCK`, epoch snapshot via `InterlockedCompareExchange(&epoch,0,0)`, linear
scan, ring cursor, dedup, saturating count.

- [ ] **`DlpTaintLookup(ULONG Pid)`** → BOOLEAN. LLD §4 / §5.3.
  - IRQL: **≤ DISPATCH_LEVEL** (the ONLY taint fn called from the WFP
    classifyFn). `KeAcquireSpinLock(&gDlpData.TaintLock,&old)` is correct here
    (raises to DISPATCH); never an ERESOURCE on this path.
  - Match `Valid && Pid==pid && TaintEpoch==gDlpData.TaintEpoch`. Snapshot
    `TaintEpoch` with an interlocked read before/under the lock.
  - `Pid==0` must never match (empty-slot sentinel). Release lock on every path.
  - No allocation, no I/O, no wait — it is called at DISPATCH from WFP.
- [ ] **`DlpTaintAdd(ULONG Pid)`** → VOID. LLD §4 (item 1 of §12 units).
  - IRQL: **PASSIVE** (worker / process-notify are the only callers).
  - Snapshot `TaintEpoch`; dedup within the current epoch (do not double-count).
  - PID-reuse guard: capture `CreateTime` via `PsGetProcessCreateTimeQuadPart`
    (callable at PASSIVE) for the current process — store in the slot. (Header
    field `CreateTime` exists for this; used to disambiguate a recycled PID.)
  - Fill next free slot; at capacity evict oldest via `TaintNext` ring cursor
    (`(slot+1)%DLP_TAINT_MAX`), set `Valid=TRUE`, saturating `TaintCount++`.
  - Lock: `TaintLock` spinlock, held minimally, **never across** the
    `PsGetProcessCreateTimeQuadPart` call if that call could page — capture the
    create-time BEFORE acquiring the spinlock (it takes no lock but keep the
    spinlock region pure stores). Pool tag: none (static array).
- [ ] **`DlpTaintRemove(ULONG Pid)`** → VOID. LLD §4. Process-exit path.
  - IRQL: **≤ DISPATCH** (process-notify runs ≤ APC, but treat as PASSIVE-safe).
  - Scan, clear matching slot: `Valid=FALSE`, `Pid=0`, saturating `TaintCount--`.
- [ ] **`DlpTaintResetAll(VOID)`** → VOID. LLD §4 / HLD §6.
  - `InterlockedIncrement(&gDlpData.TaintEpoch)` ONLY (implicit clear). Admin
    "reset taint" control. **Must NOT** be called on agent reconnect (HLD §6 —
    taint deliberately persists across agent restart; that is the fail-secure
    divergence from the badhash epoch, which IS bumped on reconnect in comms.c).
  - No wiring to `DlpPortConnect`. (Leave an unwired admin hook / note only.)

Kernel-safety summary: one `KSPIN_LOCK gDlpData.TaintLock`, spinlock band only,
epoch-stamped so no walk-to-clear, PID 0 sentinel, saturating count, no pool.

---

## 2. `dlpflt.c` — sensfile cache (LLD §4; same ring, CONTENT epoch)

- [ ] **`DlpSensFileLookup(ULONGLONG FileId, ULONGLONG VolumeId)`** → BOOLEAN.
  - IRQL: PASSIVE (worker + `DlpPostRead` cheap path).
  - Lock: `KSPIN_LOCK gDlpData.SensFileLock`. Match `Valid && FileId==f &&
    VolumeId==v && Epoch==gDlpData.Epoch` — stamp with the **content-policy
    `gDlpData.Epoch`** (NOT `TaintEpoch`), so an agent reconnect's epoch bump
    invalidates cached sensitivity (correct for a content verdict; LLD §4).
- [ ] **`DlpSensFileInsert(ULONGLONG FileId, ULONGLONG VolumeId)`** → VOID.
  - IRQL: PASSIVE. Dedup within current `Epoch`; ring-evict via `SensFileNext`
    (`%DLP_SENSFILE_MAX`); `Valid=TRUE`. Pool tag: none (static array).
  - `VolumeId==0` is the documented "unknown volume" fallback (accept rare
    cross-volume file-id collision → at worst an extra up-call, fail-safe).

---

## 3. `dlpflt.c` — shared read helper (LLD §3 step 2; factor, don't fork)

- [ ] **`DlpReadStreamContent(PFLT_INSTANCE, PFILE_OBJECT, PVOID *Buffer,
  PULONG Length, PBOOLEAN Truncated)`** → NTSTATUS. `static`.
  - **This is the item that breaks the build today** — it is declared (l.98) and
    called by `DlpInspectStream` (l.847) but never defined. Its body is the read
    block currently *inlined conceptually* by the write path; extract the exact
    `FltReadFile` offset-0..min(EOF,`DLP_MAX_CONTENT`) read into a fresh
    `ExAllocatePoolWithTag(NonPagedPoolNx, ..., DLP_GENERAL_TAG)` buffer.
  - IRQL: **PASSIVE** (`FltReadFile` waits). Caller frees `*Buffer` with
    `DLP_GENERAL_TAG` (both call sites: `DlpInspectStream` l.883-885 already
    does; the worker must too).
  - Set `*Truncated=TRUE` when EOF > `DLP_MAX_CONTENT`. On any query/alloc/read
    failure: free partials, `*Buffer=NULL`, `*Length=0`, return the failure —
    callers fail-safe (write path ships no content; **worker adds NO taint**).
  - Constraint: write behaviour must stay **identical** — this is a pure
    extraction, verified by the write path still compiling + behaving.
  - Pool tag: `DLP_GENERAL_TAG`. No leak on any error path (every early return
    frees). Never across a spinlock (it is a blocking read).

---

## 4. `dlpflt.c` — async scan worker + queue (LLD §2 enqueue, §3 worker)

Rundown discipline (critical): `ScanRundown` is **acquired at enqueue**
(`DlpScanEnqueue`) and **released by the worker per job**, so Unload's single
`ExWaitForRundownProtectionRelease(&ScanRundown)` drains all in-flight + queued
jobs. Never release it at enqueue.

- [ ] **`DlpScanEnqueue(PDLP_SCAN_JOB Job)`** → VOID (`__drv_aliasesMem`). LLD §2.
  - `if (!ExAcquireRundownProtection(&gDlpData.ScanRundown)) { DlpFreeScanJob;
    return; }` — unloading ⇒ drop (deref FILE_OBJECT + free), fail-safe.
  - Spinlock `ScanQueueLock`: `InsertTailList(&ScanQueue,&Job->Link)`;
    `InterlockedIncrement(&ScanQueueDepth)`; release.
  - `KeReleaseSemaphore(&ScanSem, 0, 1, FALSE)` — signal AFTER releasing the
    spinlock (never signal a semaphore while holding a spinlock at raised IRQL:
    `KeReleaseSemaphore` is legal ≤ DISPATCH but keep the lock region pure).
  - The rundown acquired here is the one the worker releases. IRQL: PASSIVE
    (called from `DlpPostRead`, which is PASSIVE-gated).
- [ ] **`DlpScanWorker(PVOID StartContext)`** → VOID. `static`. System thread. LLD §3.
  - IRQL: PASSIVE (dedicated `PsCreateSystemThread`).
  - Loop: `KeWaitForSingleObject(&ScanSem, Executive, KernelMode, FALSE, NULL)`;
    `if (InterlockedCompareExchange(&ScanStop,0,0)) drain-and-exit;`
    dequeue under `ScanQueueLock` (`RemoveHeadList`, `InterlockedDecrement`
    depth); `if(!job) continue;` `DlpProcessScanJob(job)`;
    `ObDereferenceObject(job->FileObject)`; `DlpFreeScanJob(job)` (frees with
    `DLP_JOB_TAG`); `ExReleaseRundownProtection(&ScanRundown)` (pairs w/ enqueue).
  - **Ordering trap:** every path that consumes a job MUST release the rundown
    exactly once (normal completion AND drain-and-exit) — a missed release hangs
    Unload forever; a double release corrupts the rundown.
  - Drain-and-exit: pop every remaining job, per job deref+free+release rundown,
    then `PsTerminateSystemThread(STATUS_SUCCESS)`.
- [ ] **`DlpProcessScanJob(PDLP_SCAN_JOB Job)`** → VOID. `static`. LLD §3 steps 1-6.
  - IRQL: PASSIVE. Cheapest-first:
    1. File-id: `FltQueryInformationFile(FILE_INTERNAL_INFORMATION)` (+ volume
       discriminator, §4 — v1 may use `VolumeId=0`). `if
       (DlpSensFileLookup(fileId,volId)) { DlpTaintAdd(Job->Pid); return; }` —
       no read, no up-call.
    2. `DlpReadStreamContent(Job->Instance, Job->FileObject, &buf,&len,&trunc)`.
       On failure → free, return, **no taint** (never taint on an unreadable read).
    3. `DlpComputeSha256(buf,len,sha)`; `if (DlpBadHashLookup(sha)) {
       DlpTaintAdd(pid); DlpSensFileInsert(fileId,volId); free; return; }`
       (reuses the item-10 ring — shared meaning "sensitive content").
    4. Up-call: `DlpQueryVerdict(&emptyName, fileId, Job->Pid, buf, len, trunc,
       **DLP_REASON_READ**, &block)`. Pass an empty `UNICODE_STRING` (agent only
       uses path for the incident label; cheapest = empty).
    5. `if (block) { DlpBadHashInsert(sha); DlpSensFileInsert(fileId,volId);
       DlpTaintAdd(Job->Pid); }`.
    6. Free `buf` with `DLP_GENERAL_TAG`.
  - **Instance lifetime:** no explicit instance ref (LLD §3) — a detached
    instance makes `FltReadFile` fail cleanly → "no content" → no taint. The
    scan rundown is what keeps the filter alive while the job runs.
  - No spinlock held across `FltQueryInformationFile` / `FltReadFile` /
    `DlpQueryVerdict` (all block). Every buffer freed on every path.
- [ ] **`DlpFreeScanJob(PDLP_SCAN_JOB Job)`** → VOID. `static`.
  - `ExFreePoolWithTag(Job, DLP_JOB_TAG)`. (Caller derefs `FileObject` first, or
    centralise the deref here — pick one and keep the worker's deref/free/release
    accounting exact; do not double-deref.)
- [ ] **`DlpStartScanWorker(VOID)`** → NTSTATUS. LLD §3.
  - IRQL: PASSIVE (DriverEntry). Init MUST precede thread create:
    `KeInitializeSpinLock(&ScanQueueLock)`, `InitializeListHead(&ScanQueue)`,
    `KeInitializeSemaphore(&ScanSem,0,MAXLONG)`, `ScanQueueDepth=0`,
    `ScanDropped=0`, `ScanStop=0`, `ExInitializeRundownProtection(&ScanRundown)`
    + `ScanRundownInit=TRUE`.
  - `PsCreateSystemThread(&ScanThreadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL,
    DlpScanWorker, NULL)`; on success `ObReferenceObjectByHandle(...,
    PsThreadType, ..., &ScanThread, NULL)` so Unload can `KeWaitForSingleObject`.
    `ZwClose(ScanThreadHandle)` after referencing (keep the PETHREAD, drop the
    HANDLE). On failure: undo rundown-init flag, return status.
- [ ] **`DlpStopScanWorker(VOID)`** → VOID. LLD §3 / §5.5.
  - IRQL: PASSIVE (Unload). `InterlockedExchange(&ScanStop,1);
    KeReleaseSemaphore(&ScanSem,0,1,FALSE);` then
    `KeWaitForSingleObject(ScanThread, Executive, KernelMode, FALSE, NULL);`
    `ObDereferenceObject(ScanThread); ScanThread=NULL;`. Then (per §5.5 step 4)
    `if (ScanRundownInit) ExWaitForRundownProtectionRelease(&ScanRundown);`.

Bounds: `DlpPostRead` enforces `DLP_SCAN_QUEUE_MAX` (drop = a miss, increments
`ScanDropped`, fail-safe toward not deadlocking) — see §5 below.

---

## 5. `dlpflt.c` — `DlpPostRead` body (LLD §2; runs ≤ DISPATCH, must not read)

- [ ] **`DlpPostRead(Data, FltObjects, CompletionContext, Flags)`** →
  `FLT_POSTOP_CALLBACK_STATUS`. LLD §2 steps 1-10.
  - **Contract:** runs at ≤ DISPATCH / possibly nested. It must **NOT** read the
    file, must NOT up-call, must NOT touch stream context at raised IRQL. It only
    claims-once + enqueues.
  - Order of gates:
    1. `Flags & FLTFL_POST_OPERATION_DRAINING` → `FINISHED`.
    2. `gDlpData.ReadTaintEnabled != DLP_READTAINT_ENABLED` → `FINISHED`
       (**kill-switch — this is the default-off gate that keeps today's
       behaviour**).
    3. `DlpShouldSkip(Data,FltObjects)` → `FINISHED` (reuses the exact
       paging/self/System/IRQL/re-entrancy gate; it already enforces
       `KeGetCurrentIrql()==PASSIVE_LEVEL` and `IoGetTopLevelIrp()==NULL`, so an
       async read at DISPATCH is skipped here — the trigger is strictly PASSIVE).
    4. `!NT_SUCCESS(Data->IoStatus.Status) || Information==0` → `FINISHED`.
    5. Substantiality gate: `Parameters.Read.Length >= DLP_READ_MIN` (512) else
       `FINISHED`.
    6. Get/attach stream context (reuse `DlpPostCreate` allocate-or-get pattern).
    7. **Claim-once:** `if (InterlockedCompareExchange(&ctx->ReadScanState,1,0)
       != 0) { release ctx; FINISHED; }`.
    8. Cheap repeat path: consult `DlpSensFileLookup` first (LLD §2.6 note / task
       brief) — if already known-sensitive, `DlpTaintAdd` may be taken directly;
       otherwise proceed to scope + enqueue. (Keep C: reads cheap.)
    9. Scope filter: `FltGetFileNameInformation(NORMALIZED)` + unless scope=all
       require `DlpConfigPathIsWatched(&name)` else release + `FINISHED` (no
       enqueue).
    10. Enqueue: `ExAllocatePoolWithTag(NonPagedPoolNx, sizeof(DLP_SCAN_JOB),
        DLP_JOB_TAG)`; if `ScanQueueDepth >= DLP_SCAN_QUEUE_MAX` → drop (free job,
        `InterlockedIncrement(&ScanDropped)`), release ctx, `FINISHED`;
        else `ObReferenceObject(FltObjects->FileObject)`, set `Instance`,
        `Pid=FltGetRequestorProcessId(Data)`, `Epoch=gDlpData.Epoch`,
        `DlpScanEnqueue(job)`. Release ctx. `FLT_POSTOP_FINISHED_PROCESSING`.
  - Kernel-safety: `ObReferenceObject` every enqueued FILE_OBJECT (worker
    derefs); free the job + skip the ref if the queue is full; release the stream
    context on **every** return; pool tag `DLP_JOB_TAG` for the job,
    `DLP_STREAM_CONTEXT_TAG` handled by FltMgr.

---

## 6. `dlpflt.c` — process-notify (LLD §4; PsSetCreateProcessNotifyRoutineEx)

- [ ] **`DlpCreateProcessNotify(PEPROCESS, HANDLE ProcessId,
  PPS_CREATE_NOTIFY_INFO CreateInfo)`** → VOID. LLD §4.
  - IRQL: PASSIVE (process create/exit path). On **exit** (`CreateInfo==NULL`):
    `DlpTaintRemove((ULONG)(ULONG_PTR)ProcessId)`. On create: nothing.
  - Registered in DriverEntry (gated) with `PsSetCreateProcessNotifyRoutineEx(
    DlpCreateProcessNotify, FALSE)`; set `ProcNotifyRegistered=TRUE` on success.
    Requires `/INTEGRITYCHECK` (already on the link line).
  - Unregister in Unload with `PsSetCreateProcessNotifyRoutineEx(...,TRUE)` guarded
    by `ProcNotifyRegistered`.

---

## 7. `dlpflt.c` — DriverEntry wiring (LLD §5.2 policy, §11) — GATED

Insert AFTER `FltStartFiltering` succeeds (l.263), all gated on
`gDlpData.ReadTaintEnabled == DLP_READTAINT_ENABLED`:

- [ ] Init new gDlpData state BEFORE any consumer (ideally before
  FltStartFiltering, alongside the existing item-2/4/10 init at l.211-218):
  `KeInitializeSpinLock(&TaintLock)`, `RtlZeroMemory(Taint,...)`, `TaintEpoch=1`
  (0 reserved), `TaintCount=0`, `TaintNext=0`; `KeInitializeSpinLock(
  &SensFileLock)`, `RtlZeroMemory(SensFile,...)`, `SensFileNext=0`. (Scan-queue
  state is initialised inside `DlpStartScanWorker`, §4.)
- [ ] `DlpReadTaintPolicy(RegistryPath)` — read the registry knobs (call the
  DONE comms.c fn). Do this BEFORE the gate test so the gate sees the real value.
- [ ] If enabled: `DlpStartScanWorker()` — on failure, log + continue FS-only
  (non-fatal), or unwind per site policy; LLD default = read-taint best-effort.
- [ ] If enabled: `PsSetCreateProcessNotifyRoutineEx(DlpCreateProcessNotify,
  FALSE)` → `ProcNotifyRegistered=TRUE`.
- [ ] If enabled: `DlpWfpRegister()` (in wfpcallout.c) — **failure is NON-FATAL**
  to the driver (FS/USB/content protection must survive; LLD §5.2). Log + continue.
  - Constraint: WFP register AFTER FltStartFiltering (the LLD requires the FS
    filter be live first). Do NOT make a WFP failure unwind the filter.
- [ ] Because the read-taint block is opt-in, DriverEntry with
  `ReadTaintEnabled=0` (shipped default) must behave **exactly as today** — no
  worker, no notify, no WFP, no new IRQL/lifetime surface.

---

## 8. `dlpflt.c` — `DlpUnload` teardown reorder (LLD §5.5) — STRICT REVERSE

Current Unload (l.281-316): Ob → port → send-rundown → FltUnregister → ConfigLock.
Rewrite to (each step guarded by its `*Registered`/`*Init` flag for idempotency;
skip the read-taint steps cleanly when disabled):

- [ ] 1. `DlpUnregisterObCallbacks()` (unchanged, first).
- [ ] 2. `DlpWfpUnregister()` — stop blocking egress (removes filters + callouts)
  BEFORE the worker stops, so no new blocks while draining. No-op if not registered.
- [ ] 3. `DlpStopScanWorker()` — signal `ScanStop`, release `ScanSem`,
  `KeWaitForSingleObject(ScanThread)`, `ObDereferenceObject(ScanThread)`.
- [ ] 4. `if (ScanRundownInit) ExWaitForRundownProtectionRelease(&ScanRundown)` —
  drains any job that slipped past between signal and stop.
- [ ] 5. `DlpCloseCommunicationPort()` (was step 2).
- [ ] 6. `if (SendRundownInit) ExWaitForRundownProtectionRelease(&SendRundown)`
  (existing item-2 drain).
- [ ] 7. `if (ProcNotifyRegistered) PsSetCreateProcessNotifyRoutineEx(
  DlpCreateProcessNotify, TRUE)`.
- [ ] 8. `FltUnregisterFilter`; delete `ConfigLock`.
  - Note: the LLD lists process-notify unregister at step 7 (after ports). It is
    safe there because taint-remove touches only the static table; but nothing
    reads the taint table after step 2 (WFP gone) + step 3 (worker gone), so this
    ordering is race-free. Keep the LLD order.
  - Kernel-safety: PASSIVE (`PAGED_CODE()`), every wait guarded by its init flag
    so a partial DriverEntry unwinds without waiting on an uninitialised object.

---

## 9. `src/wfpcallout.c` — NEW FILE (LLD §5) — the highest-risk component

INITGUID translation unit. Header order (LLD §8): `#include <initguid.h>` FIRST,
then `#include "dlpflt.h"`, then `#include <fwpsk.h>`, `#include <fwpmk.h>`.

- [ ] **Four fresh `DEFINE_GUID`** (LLD §5.1): `DLP_WFP_PROVIDER_GUID`,
  `DLP_WFP_SUBLAYER_GUID`, `DLP_WFP_CALLOUT_V4_GUID`, `DLP_WFP_CALLOUT_V6_GUID`.
  **Do NOT reuse** the user-mode build's `DLP_*_GUID` / `0x7b2e6f10…` values —
  separate subsystem, separate sublayer (HLD §5). Pick fresh random GUIDs.
- [ ] **`DlpWfpRemoteIsLocal(const FWPS_INCOMING_VALUES0* inFixed)`** → BOOLEAN.
  Pure helper (LLD §5.3, §12 unit 3). Read
  `inFixed->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS]`
  (and the V6 field for the v6 callout); classify RFC1918 / loopback /
  link-local → TRUE, public → FALSE. **Must match the Rust
  `tainted_egress_action` + locality assumptions exactly** (the pure mirror in
  `tcpreset.rs`). v4 and v6 vectors.
- [ ] **`DlpWfpClassify(inFixed, inMeta, layerData, classifyContext, filter,
  flowContext, out)`** → VOID NTAPI. classifyFn. LLD §5.3.
  - **Contract: runs at ≤ DISPATCH_LEVEL and MUST NEVER BLOCK** — no allocation,
    no I/O, no waits, no ERESOURCE. Only `DlpTaintLookup` (a bounded spinlock scan
    ≤ DISPATCH, acceptable) + field reads.
  - Body (must equal `tcpreset.rs::tainted_egress_action`'s matrix):
    - `if (!(out->rights & FWPS_RIGHT_ACTION_WRITE)) return;` (already hard-decided).
    - `out->actionType = FWP_ACTION_CONTINUE;` (default — **CONTINUE not PERMIT**,
      so read-taint composes with the user-mode default-deny allow-list; a PERMIT
      would override it — this is the crucial composition choice, HLD §5).
    - `if (!FWPS_IS_METADATA_FIELD_PRESENT(inMeta,
      FWPS_METADATA_FIELD_PROCESS_ID)) return;` (no PID ⇒ cannot attribute ⇒
      fail-safe CONTINUE; documented).
    - `pid=(ULONG)inMeta->processId;`
    - `servicePid = InterlockedCompareExchange(&gDlpData.ServicePid,0,0);
      if (pid==servicePid || pid==DLP_SYSTEM_PID) return;` (never block the
      agent/System — HLD §5 "agent PID never tainted, callout CONTINUEs it").
    - `if (DlpTaintLookup(pid)) { if (TaintedEgressPolicy==DLP_TEP_BLOCK_NONLOCAL
      && DlpWfpRemoteIsLocal(inFixed)) return; out->actionType=FWP_ACTION_BLOCK;
      out->rights &= ~FWPS_RIGHT_ACTION_WRITE; }`.
  - Provide separate v4/v6 registration but a shared classifyFn is fine (branch
    on layer via `inFixed->layerId` or register two `FWPS_CALLOUT2` with the same
    fn). Read the correct remote-address field per family.
- [ ] **`DlpWfpNotify(FWPS_CALLOUT_NOTIFY_TYPE, const GUID*, FWPS_FILTER2*)`** →
  NTSTATUS. Return `STATUS_SUCCESS` (no per-filter state). LLD §5.4. Required by
  `FwpsCalloutRegister2`.
- [ ] **`DlpWfpRegister(VOID)`** → NTSTATUS. LLD §5.2. IRQL: PASSIVE.
  Order, each step storing its rollback flag (fields already in the header):
  1. `IoCreateDevice(gDlpData.DriverObject, 0, NULL, FILE_DEVICE_NETWORK, ...,
     FALSE, &gDlpData.WfpDevice)`.
  2. `FwpsCalloutRegister2(WfpDevice, &callout_v4, &WfpCalloutIdV4)` →
     `WfpCalloutV4Reg=TRUE`; same v6 → `WfpCalloutV6Reg`. (`FWPS_CALLOUT2`:
     calloutKey, `classifyFn=DlpWfpClassify`, `notifyFn=DlpWfpNotify`,
     `flowDeleteFn=NULL`.)
  3. `FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &WfpEngine)` —
     **non-dynamic** session (we delete our objects explicitly in Unload).
  4. `FwpmTransactionBegin0`; inside: `FwpmProviderAdd0`→`WfpProviderAdded`;
     `FwpmSubLayerAdd0` (own provider + own weight)→`WfpSubLayerAdded`;
     `FwpmCalloutAdd0` v4 @ `FWPM_LAYER_ALE_AUTH_CONNECT_V4`→`WfpCalloutV4Added`,
     v6→`WfpCalloutV6Added`; `FwpmFilterAdd0` v4 (`layerKey=..._V4`,
     `subLayerKey=DLP_WFP_SUBLAYER_GUID`,
     `action.type=FWP_ACTION_CALLOUT_UNKNOWN`,
     `action.calloutKey=DLP_WFP_CALLOUT_V4_GUID`, `numFilterConditions=0`, mid
     weight, `&WfpFilterIdV4`)→`WfpFilterV4Added`, v6→`WfpFilterV6Added`;
     `FwpmTransactionCommit0`.
  5. Any failure → `FwpmTransactionAbort0` then `DlpWfpUnregister()`, return error.
  - Kernel-safety: no partial state left on failure (rollback flags drive
    idempotent unregister); `action.type = FWP_ACTION_CALLOUT_UNKNOWN` (a
    *filtering* callout, not terminating-permit) so the classify's CONTINUE/BLOCK
    governs; `numFilterConditions=0` (match all outbound; PID filtering is in the
    callout).
- [ ] **`DlpWfpUnregister(VOID)`** → VOID. LLD §5.5. IRQL: PASSIVE.
  Teardown order the LLD specifies (top BSOD/leak source — follow exactly),
  each guarded by its `*Added`/`*Reg` flag:
  1. If `WfpEngine`: transaction — `FwpmFilterDeleteById0(WfpEngine,
     WfpFilterIdV4/V6)` (guard `WfpFilterV4/6Added`) → callouts
     (`FwpmCalloutDeleteById0`/`…ByKey0`, guard `WfpCalloutV4/6Added`) →
     `FwpmSubLayerDeleteByKey0` (guard `WfpSubLayerAdded`) → `FwpmProviderDeleteByKey0`
     (guard `WfpProviderAdded`) → `FwpmEngineClose0(WfpEngine)`; clear WfpEngine.
  2. `FwpsCalloutUnregisterById0(WfpCalloutIdV4/V6)` per registered callout
     (guard `WfpCalloutV4/6Reg`). **May return `STATUS_DEVICE_BUSY`** if a classify
     is in flight — deleting the filters first (step 1) stops new classifies; if
     BUSY, bounded retry with a short `KeDelayExecutionThread` (this is the
     unregister-race that BSODs WFP drivers).
  3. `if (WfpDevice) IoDeleteDevice(WfpDevice); WfpDevice=NULL;`.
  - Fully idempotent (safe to call from a failed `DlpWfpRegister` and again from
    Unload) — every action guarded by its flag, every flag cleared after undo.

Ordering rule (LLD §5.5): **filters → callouts (FwpmCalloutDeleteById0) →
FwpsCalloutUnregisterById0 → sublayer/provider → engine close → IoDeleteDevice**,
driven by the *Added/*Reg flags.

---

## 10. `build/build-driver.bat` (LLD §8)

- [ ] Add a `wfpcallout.c` compile step mirroring the comms.c step, EXACT same
  flags (`/c /W4 /WX /wd4324 /wd4201 /wd4214 /sdl /guard:cf /GS /Od /GF /Gy /GR-
  /kernel` + the same `/D` set) → `/Fobuild\out\wfpcallout.obj src\wfpcallout.c`;
  `if errorlevel 1 goto :fail`.
- [ ] Add `build\out\wfpcallout.obj` to the `link.exe` line (after comms.obj).
- [ ] Add `fwpkclnt.lib` to the link libraries (WFP kernel client:
  `FwpsCalloutRegister2`, `FwpsCalloutUnregisterById0`, `FwpmEngineOpen0`,
  `FwpmFilterAdd0`, …). It lives in `%SDKROOT%\Lib\%SDKVER%\km\x64` (already on LIB).
- [ ] Keep the existing link flags verbatim (`/DRIVER /SUBSYSTEM:NATIVE,10.00
  /ENTRY:GsDriverEntry /NODEFAULTLIB /RELEASE /INTEGRITYCHECK /GUARD:CF`) and the
  km\crt-first INCLUDE.
- [ ] **Discrepancy to resolve before coding:** the task brief says add
  "`fwpkclnt.lib` + `ndis.lib`". **LLD §8 explicitly says "No `ndis.lib` is
  needed (we do not touch NDIS / packet injection)."** Follow the LLD (fwpkclnt
  only) unless a link error proves otherwise; adding `ndis.lib` is harmless but
  unnecessary. Do NOT add `uuid.lib` — the FWPM/FWPS GUIDs are instantiated by
  the single `#include <initguid.h>` TU; an unresolved `FWPM_LAYER_*` is an
  INITGUID-ordering bug, not a missing lib (LLD §8).
- [ ] No `taint.c` step needed — the taint/scan code is folded into `dlpflt.c`
  (the fwd-decls at l.104-107 confirm the "folded taint.c" choice). If a separate
  `taint.c` is chosen instead, add its own compile step + obj.

---

## 11. Cross-checks the implementer must preserve (do NOT regress)

- [ ] The Rust mirror `tcpreset.rs::tainted_egress_action` (BlockAll ⇒ Block;
  BlockNonlocal ⇒ local Continue / remote Block; clean ⇒ Continue) is the
  **byte-for-byte contract** for `DlpWfpClassify`. Keep them identical.
- [ ] `DlpQueryVerdict` is frozen (comms.c) — the worker calls it with
  `Reason=DLP_REASON_READ`; write path stays `DLP_REASON_WRITE`. No wire change.
- [ ] Taint persists across agent reconnect (HLD §6): `DlpTaintResetAll` is
  admin-only; the connect path in comms.c bumps `Epoch` (content) but must NOT
  bump `TaintEpoch`.
- [ ] Everything new is gated on `ReadTaintEnabled` so the shipped default build
  is behaviourally identical to today (fail-safe).
- [ ] Honest testing: `build-driver.bat` + `cargo test` are verifiable here;
  loading the `.sys`, WFP block, and unload-stress are operator-manual on a VM
  (Driver Verifier: Pool Tracking + Force IRQL + Deadlock + DDI + Low-Resource +
  WFP/NDIS checks). Never claim runtime verification.

---

## 12. Definition of done (build-verifiable here)

1. `dlpflt.c` defines every fwd-declared read-taint fn (§§1-8) → `cl /c
   src\dlpflt.c` compiles clean under `/W4 /WX /sdl /analyze`.
2. `src\wfpcallout.c` exists and compiles clean with the same flags (§9).
3. `build-driver.bat` compiles both new-relevant TUs and links `dlpflt.obj
   comms.obj wfpcallout.obj` + `fwpkclnt.lib` → `=== SUCCESS === dlpflt.sys`.
4. `cargo test` in `dlp-agent` still green (Rust untouched).
5. No runtime claims. VM load + Driver Verifier is the operator's manual step.
