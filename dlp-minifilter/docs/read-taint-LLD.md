# Read-Taint Network Egress Blocking — Low-Level Design (LLD)

Implementer-facing. Function- and struct-level. Pair with `read-taint-HLD.md`.
Every symbol prefix is `Dlp*`/`DLP_*` to match the existing driver. All new state
hangs off the existing `gDlpData` (`DLP_FLT_DATA`) so lifetime tracks the driver.

Ground truth already in the tree (do not re-derive):
- `DlpShouldSkip` (dlpflt.c) — the paging/self/System/IRQL/re-entrancy gate.
- `DlpQueryVerdict` (comms.c) — the content-over-port v2 up-call; **reused as-is**
  except for one added `Reason` argument (no wire size change).
- `DlpComputeSha256` / `DlpBadHashLookup` / `DlpBadHashInsert` (dlpflt.c) — the
  bounded, spinlock-guarded, epoch-stamped ring. **The taint table mirrors this
  exact pattern**, and the read fast-path **reuses** this ring.
- `DlpReadFailMode` (comms.c) — the registry-read pattern the new registry knobs copy.

---

## 1. New global state (add to `DLP_FLT_DATA` in `dlpflt.h`)

```c
/* ---- Read-taint: registry-driven master switch + tainted-egress policy ---- */
#define DLP_READTAINT_DISABLED   0
#define DLP_READTAINT_ENABLED    1
/* TaintedEgressPolicy values (what a tainted PID's egress does): */
#define DLP_TEP_BLOCK_ALL        0   /* block ALL outbound (default, fail-secure) */
#define DLP_TEP_BLOCK_NONLOCAL   1   /* permit RFC1918/loopback, block the rest   */

/* ---- Taint table (mirrors the BadHash ring: bounded, spinlock, epoch) ------ */
#define DLP_TAINT_MAX            1024        /* bounded PID set                    */

typedef struct _DLP_TAINT_ENTRY {
    volatile LONG Pid;          /* tainted requestor PID (0 = empty slot)         */
    LONG          TaintEpoch;   /* gDlpData.TaintEpoch snapshot at insert         */
    ULONGLONG     CreateTime;   /* PsGetProcessCreateTimeQuadPart (PID-reuse guard)*/
    BOOLEAN       Valid;
} DLP_TAINT_ENTRY, *PDLP_TAINT_ENTRY;

/* ---- Known-sensitive file-id cache (cheapest repeat-read path) ------------- */
#define DLP_SENSFILE_MAX        512
typedef struct _DLP_SENSFILE_ENTRY {
    ULONGLONG FileId;           /* FILE_INTERNAL_INFORMATION.IndexNumber          */
    ULONGLONG VolumeId;         /* per-instance discriminator (see §4)            */
    LONG      Epoch;            /* gDlpData.Epoch snapshot (content policy epoch)  */
    BOOLEAN   Valid;
} DLP_SENSFILE_ENTRY, *PDLP_SENSFILE_ENTRY;

/* ---- Async taint-scan work queue + worker thread -------------------------- */
typedef struct _DLP_SCAN_JOB {
    LIST_ENTRY     Link;
    PFLT_INSTANCE  Instance;    /* referenced (FltObjectReference not needed; see §3) */
    PFILE_OBJECT   FileObject;  /* ObReferenceObject'd                            */
    ULONG          Pid;
    LONG           Epoch;       /* content-policy epoch snapshot                  */
} DLP_SCAN_JOB, *PDLP_SCAN_JOB;
```

Fields to add to `DLP_FLT_DATA`:

```c
    /* Read-taint master switch + policy (registry, read in DriverEntry). */
    ULONG          ReadTaintEnabled;      /* DLP_READTAINT_* */
    ULONG          TaintedEgressPolicy;   /* DLP_TEP_*       */

    /* Taint table. */
    KSPIN_LOCK        TaintLock;
    DLP_TAINT_ENTRY   Taint[DLP_TAINT_MAX];
    volatile LONG     TaintEpoch;         /* starts 1; bumped ONLY by admin reset */
    volatile LONG     TaintCount;         /* live entries (diagnostics/bounding)  */

    /* Known-sensitive file-id cache. */
    KSPIN_LOCK          SensFileLock;
    DLP_SENSFILE_ENTRY  SensFile[DLP_SENSFILE_MAX];
    LONG                SensFileNext;

    /* Async scan queue + worker. */
    KSPIN_LOCK      ScanQueueLock;
    LIST_ENTRY      ScanQueue;
    KSEMAPHORE      ScanSem;              /* signalled per enqueue                */
    volatile LONG   ScanQueueDepth;       /* bounded at DLP_SCAN_QUEUE_MAX        */
    PETHREAD        ScanThread;           /* PsCreateSystemThread                 */
    HANDLE          ScanThreadHandle;
    volatile LONG   ScanStop;             /* 1 => worker drains and exits         */
    EX_RUNDOWN_REF  ScanRundown;          /* jobs hold it; Unload waits it once   */
    BOOLEAN         ScanRundownInit;

    /* WFP callout state. */
    PDEVICE_OBJECT  WfpDevice;            /* IoCreateDevice, for FwpsCalloutRegister */
    HANDLE          WfpEngine;            /* FwpmEngineOpen0                       */
    UINT32          WfpCalloutIdV4;       /* FwpsCalloutRegister runtime id        */
    UINT32          WfpCalloutIdV6;
    UINT64          WfpFilterIdV4;        /* FwpmFilterAdd0 id (for delete)        */
    UINT64          WfpFilterIdV6;
    BOOLEAN         WfpProviderAdded;
    BOOLEAN         WfpSubLayerAdded;
    BOOLEAN         WfpCalloutV4Added;    /* FwpmCalloutAdd0 done                  */
    BOOLEAN         WfpCalloutV6Added;
    BOOLEAN         WfpRegistered;        /* callouts registered with FwpsCalloutRegister */

    /* Process-notify registration. */
    BOOLEAN         ProcNotifyRegistered;
```

`#define DLP_SCAN_QUEUE_MAX 256` and pool tags `DLP_TAINT_TAG 'TplD'`,
`DLP_JOB_TAG 'JplD'` in `dlpflt.h`.

---

## 2. The read trigger — `IRP_MJ_READ` post-op, async, first-read only

**Why post-op READ (not post-create, not pre-read):** post-create is too early
(no data read yet, and scanning every opened file is far more traffic than every
*read* file). Pre-read cannot see whether a substantial read actually happens and
runs on the hot latency path. Post-read sees a completed read, can be filtered to
the first substantial one, and lets us defer all work.

**Why async (default) not sync — JUSTIFIED:** a synchronous scan would block the
completing read on a user-mode round-trip (`FltReadFile` + `FltSendMessage`), i.e.
add IPC latency to *every first read of every watched file* — unacceptable, and
post-op read can be at DISPATCH / nested where the up-call is illegal anyway. The
brief's default recommendation is async; we take it. The cost is the
existing-connection race (HLD §7), bounded by the immediate new-connect block and
the user-mode reset.

Register the op (in `Callbacks[]`, with `SKIP_PAGING_IO` like WRITE/CLEANUP):

```c
{ IRP_MJ_READ, FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, NULL, DlpPostRead },
```

`DlpPostRead(Data, FltObjects, CompletionContext, Flags)`:

1. If `Flags & FLTFL_POST_OPERATION_DRAINING` → `FINISHED`.
2. If `gDlpData.ReadTaintEnabled != DLP_READTAINT_ENABLED` → `FINISHED` (kill-switch).
3. `if (DlpShouldSkip(Data, FltObjects)) return FINISHED;` — reuses the exact
   paging/self/System/IRQL/re-entrancy gate. Note: `DlpShouldSkip` requires
   PASSIVE + no top-level IRP; post-read that fails this (async read at DISPATCH)
   is simply skipped for the *enqueue decision path that reads context* — but we
   must not touch stream context at DISPATCH. So: **guard `KeGetCurrentIrql()==
   PASSIVE_LEVEL` first** (already inside `DlpShouldSkip`); at raised IRQL, return
   `FINISHED` (we catch the file on another read or at open). This keeps the
   trigger strictly PASSIVE.
4. `IoStatus` failed or `Data->IoStatus.Information == 0` (no bytes) → `FINISHED`.
5. Optional substantiality gate: only proceed when the read offset is 0 or the
   cumulative bytes suggest a real content read (cheap: require
   `Parameters.Read.Length >= DLP_READ_MIN` e.g. 512). Tunable; documented.
6. Get/attach the stream context (reuse the `DlpPostCreate` allocate-or-get
   pattern). Add a field to `DLP_STREAM_CONTEXT`:
   `volatile LONG ReadScanState;  /* 0 unseen, 1 claimed */`.
7. **Claim once:** `if (InterlockedCompareExchange(&ctx->ReadScanState,1,0)!=0) →
   release ctx, FINISHED;` (another thread already enqueued this stream).
8. **Scope filter:** resolve the name (`FltGetFileNameInformation` NORMALIZED) and,
   unless `scope=all`, require `DlpConfigPathIsWatched(&name)` — else release and
   `FINISHED` (do NOT enqueue; keeps C: reads cheap). Reuses the existing config.
9. **Enqueue:** build a `DLP_SCAN_JOB`, `ObReferenceObject(FltObjects->FileObject)`,
   store `Instance` (kept valid by the scan rundown, §3), `Pid =
   FltGetRequestorProcessId(Data)`, `Epoch = gDlpData.Epoch`. `DlpScanEnqueue(job)`.
   If the queue is at `DLP_SCAN_QUEUE_MAX`, **drop** the job (deref FileObject,
   free) and increment a dropped counter — fail-safe toward *not* deadlocking;
   documented as a miss under flood.
10. Release ctx. Return `FLT_POSTOP_FINISHED_PROCESSING`.

`DlpScanEnqueue`:
- `if (!ExAcquireRundownProtection(&gDlpData.ScanRundown)) { drop; return; }`
- spinlock `ScanQueueLock`; `InsertTailList(&ScanQueue, &job->Link)`;
  `InterlockedIncrement(&ScanQueueDepth)`; release.
- `KeReleaseSemaphore(&ScanSem, 0, 1, FALSE)`.
- Note: the rundown is **released by the worker** when the job completes, not here
  — the acquire/enqueue pairs with the worker's per-job release so Unload's single
  `ExWaitForRundownProtectionRelease` drains all in-flight + queued jobs.

---

## 3. The worker thread — `DlpScanWorker` (PASSIVE_LEVEL)

Created in `DlpStartScanWorker` (called from DriverEntry after FltStartFiltering,
only if ReadTaintEnabled): `PsCreateSystemThread` → `ObReferenceObjectByHandle`
into `ScanThread` (PETHREAD) so Unload can `KeWaitForSingleObject` on it.

Loop:

```
for (;;) {
    KeWaitForSingleObject(&ScanSem, Executive, KernelMode, FALSE, NULL);
    if (InterlockedCompareExchange(&ScanStop,0,0)) { drain-and-exit; }
    job = dequeue();                 // spinlock ScanQueueLock; RemoveHeadList
    if (!job) continue;
    DlpProcessScanJob(job);          // does the work below
    ObDereferenceObject(job->FileObject);
    ExFreePoolWithTag(job, DLP_JOB_TAG);
    ExReleaseRundownProtection(&gDlpData.ScanRundown);   // pairs with enqueue
    InterlockedDecrement(&ScanQueueDepth);
}
```

Drain-and-exit: pop every remaining job, deref + free + release rundown for each,
then `PsTerminateSystemThread(STATUS_SUCCESS)`.

**Instance lifetime:** we do not hold an explicit instance reference; instead
`DlpInstanceTeardownStart` for an instance sets a per-instance "tearing down" flag
and the worker checks the FILE_OBJECT is still usable via `FltReadFile`'s own
status (a detached instance makes `FltReadFile` fail cleanly, which we treat as
"no content" → fail-safe, no taint). The **scan rundown** guarantees Unload cannot
free the filter while a job runs. This is the low-risk choice; the higher-assurance
alternative (reference the instance) is noted for the implementer if Verifier flags
a teardown race.

`DlpProcessScanJob(job)`:

1. **File-id cache:** query `FILE_INTERNAL_INFORMATION` (+ a volume discriminator,
   §4) via `FltQueryInformationFile`. `if (DlpSensFileLookup(fileId,volId)) {
   DlpTaintAdd(job->Pid); return; }` — no read, no up-call (cheapest path).
2. **Read content:** `FltReadFile` offset 0, up to `DLP_MAX_CONTENT`, into a
   `NonPagedPoolNx` buffer — identical to `DlpInspectStream`'s read block; factor
   that read into a shared helper `DlpReadStreamContent(Instance, FileObject,
   &buf, &len, &truncated)` and call it from both sites. On failure → free, return
   (no taint; fail-safe — we never taint on an unreadable read).
3. **Content-hash fast path:** `DlpComputeSha256(buf,len,sha)`. `if
   (DlpBadHashLookup(sha)) { DlpTaintAdd(pid); DlpSensFileInsert(fileId,volId);
   free; return; }` — reuses the item-10 ring (shared meaning: "sensitive content").
4. **Up-call:** `DlpQueryVerdict(&name?, fileId64, job->Pid, buf, len, truncated,
   DLP_REASON_READ, &block)`. (Name: pass an empty `UNICODE_STRING` or re-resolve;
   the agent only uses the path for the incident label. Cheapest: pass empty.)
5. **Tag on block:** `if (block) { DlpBadHashInsert(sha);
   DlpSensFileInsert(fileId,volId); DlpTaintAdd(job->Pid); }`.
6. Free the buffer.

`DlpQueryVerdict` gets one new parameter `ULONG Reason` and sets
`request->Reserved = Reason;` (see §6 — **no wire size change**). Existing write
callers pass `DLP_REASON_WRITE (0)`.

---

## 4. Taint table + sensfile cache (pure ring logic — mirror the BadHash ring)

All four functions mirror `DlpBadHashLookup/Insert` byte-for-byte in structure
(KSPIN_LOCK, epoch stamp, ring cursor, dedup). They are the **unit-testable pure
core** (see §9).

```c
BOOLEAN DlpTaintLookup(ULONG Pid);          // WFP path: spinlock, scan, epoch-match
VOID    DlpTaintAdd(ULONG Pid);             // dedup within TaintEpoch; evict oldest
VOID    DlpTaintRemove(ULONG Pid);          // process-exit path
VOID    DlpTaintResetAll(VOID);             // admin "reset taint": InterlockedIncrement(&TaintEpoch)
```

- `DlpTaintLookup`: acquire `TaintLock`, linear scan for `Valid && Pid==pid &&
  TaintEpoch==gDlpData.TaintEpoch`; release; return found. Runs at ≤ DISPATCH
  (WFP) — spinlock is correct (never an ERESOURCE here).
- `DlpTaintAdd`: snapshot `TaintEpoch`; capture `CreateTime` via
  `PsGetProcessCreateTimeQuadPart` only if callable (PASSIVE worker → yes); dedup;
  else fill the next ring slot (`(slot+1)%DLP_TAINT_MAX`), `Valid=TRUE`,
  `TaintCount++` (saturating). At capacity we evict the oldest ring slot —
  acceptable (a real deployment won't have 1024 concurrently-tainted PIDs; if it
  does, the evicted PID falls back to the user-mode default-deny).
- `DlpTaintRemove`: scan, clear the matching slot (`Valid=FALSE`, `Pid=0`,
  `TaintCount--`).
- `DlpTaintResetAll`: bump `TaintEpoch` only (implicit clear, like the badhash
  epoch). **Not** called on agent reconnect (HLD §6).

`SensFile` cache: `DlpSensFileLookup(fileId,volId)` / `DlpSensFileInsert(...)` —
same ring pattern, stamped with the content-policy `Epoch` (so a policy reload via
reconnect *does* invalidate cached sensitivity, which is correct for content
verdicts). `VolumeId`: cheapest stable discriminator is the instance context
pointer value hashed, or `FltGetVolumeGuidName`; for v1 use the
`FLT_INSTANCE`-derived volume serial from `FltGetVolumeProperties` cached in the
instance context. If a robust volume id is unavailable, store `VolumeId=0` and
accept a rare cross-volume file-id collision (fail-safe: at worst an extra up-call).

**Process-exit untaint:** `DlpCreateProcessNotify(ParentId, ProcessId, CreateInfo)`
registered with `PsSetCreateProcessNotifyRoutineEx` in DriverEntry (needs
`/INTEGRITYCHECK`, already present). On `CreateInfo == NULL` (exit):
`DlpTaintRemove((ULONG)(ULONG_PTR)ProcessId)`. Unregister in Unload with
`PsSetCreateProcessNotifyRoutineEx(..., TRUE)`.

---

## 5. The WFP callout (`wfpcallout.c`) — the highest-risk new component

### 5.1 GUIDs (new, distinct from the user-mode build's `DLP_*_GUID`)

Define with `DEFINE_GUID` in `wfpcallout.c` (which is the INITGUID TU, §8):
`DLP_WFP_PROVIDER_GUID`, `DLP_WFP_SUBLAYER_GUID`, `DLP_WFP_CALLOUT_V4_GUID`,
`DLP_WFP_CALLOUT_V6_GUID`. Pick fresh random GUIDs (do not reuse the user-mode
`0x7b2e6f10…` values — separate subsystem, separate sublayer).

### 5.2 Registration — `DlpWfpRegister(VOID)`, called from DriverEntry AFTER `FltStartFiltering`

Order (each step stores a rollback flag so `DlpWfpUnregister` is idempotent):

1. `IoCreateDevice(gDlpData.DriverObject, 0, NULL, FILE_DEVICE_NETWORK, ...,
   FALSE, &gDlpData.WfpDevice)` — `FwpsCalloutRegister` requires a device object.
2. For v4 and v6, fill `FWPS_CALLOUT2` { `calloutKey = DLP_WFP_CALLOUT_Vx_GUID`,
   `classifyFn = DlpWfpClassify`, `notifyFn = DlpWfpNotify`, `flowDeleteFn = NULL` }
   and `FwpsCalloutRegister2(WfpDevice, &callout, &WfpCalloutIdVx)`. Set
   `WfpRegistered = TRUE` after the first success.
3. `FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL, &WfpEngine)` — a
   **non-dynamic** session (we delete our objects explicitly in Unload; a dynamic
   session would vanish on handle close, which for a driver is the process/system
   context, not what we want).
4. `FwpmTransactionBegin0`. Inside the transaction:
   - `FwpmProviderAdd0` (our provider) → `WfpProviderAdded`.
   - `FwpmSubLayerAdd0` (our sublayer, owned by our provider, its own weight) →
     `WfpSubLayerAdded`.
   - `FwpmCalloutAdd0` for v4 (applicableLayer = `FWPM_LAYER_ALE_AUTH_CONNECT_V4`,
     calloutKey = `DLP_WFP_CALLOUT_V4_GUID`) → `WfpCalloutV4Added`; same for v6.
   - `FwpmFilterAdd0` v4: `layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4`,
     `subLayerKey = DLP_WFP_SUBLAYER_GUID`, `action.type =
     FWP_ACTION_CALLOUT_UNKNOWN` (a filtering callout, not terminating-permit),
     `action.calloutKey = DLP_WFP_CALLOUT_V4_GUID`, `numFilterConditions = 0`
     (match all outbound connects; PID filtering is in the callout), weight mid.
     Store `&WfpFilterIdV4`. Same for v6.
   - `FwpmTransactionCommit0`.
5. Any failure → `FwpmTransactionAbort0`, then `DlpWfpUnregister`, return the error.

**DriverEntry policy:** call `DlpWfpRegister` only if `ReadTaintEnabled`. A
registration failure is **non-fatal to the driver** (log + continue with FS-only
protection) — unlike the ObCallbacks failure which is fatal — because losing
network-taint should not disable USB/content protection. (Alternatively make it
fatal per site policy; default: non-fatal, documented.)

### 5.3 `DlpWfpClassify` (classifyFn) — runs at ≤ DISPATCH_LEVEL

Signature: `VOID NTAPI DlpWfpClassify(const FWPS_INCOMING_VALUES0* inFixed,
const FWPS_INCOMING_METADATA_VALUES0* inMeta, void* layerData, const void*
classifyContext, const FWPS_FILTER2* filter, UINT64 flowContext,
FWPS_CLASSIFY_OUT0* out)`.

```
if (!(out->rights & FWPS_RIGHT_ACTION_WRITE)) return;      // someone hard-decided already
out->actionType = FWP_ACTION_CONTINUE;                     // default: let others decide

if (!FWPS_IS_METADATA_FIELD_PRESENT(inMeta, FWPS_METADATA_FIELD_PROCESS_ID)) {
    // No PID → cannot attribute. Fail-safe choice = CONTINUE (do not block blind;
    // the user-mode allow-list still governs). Documented.
    return;
}
pid = (ULONG) inMeta->processId;

servicePid = InterlockedCompareExchange(&gDlpData.ServicePid,0,0);
if (pid == servicePid || pid == DLP_SYSTEM_PID) return;    // never block the agent/System

if (DlpTaintLookup(pid)) {
    if (gDlpData.TaintedEgressPolicy == DLP_TEP_BLOCK_NONLOCAL &&
        DlpWfpRemoteIsLocal(inFixed)) {
        return;                                            // permit RFC1918/loopback
    }
    out->actionType = FWP_ACTION_BLOCK;
    out->rights &= ~FWPS_RIGHT_ACTION_WRITE;               // hard block (veto)
    // no flowContext, no data touched — minimal work at DISPATCH
}
```

- **`CONTINUE` not `PERMIT`** on the clean path is the crucial composition choice:
  it lets the existing user-mode default-deny sublayer still block unapproved
  destinations. A `PERMIT` here would override it.
- `DlpWfpRemoteIsLocal` reads `inFixed->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_
  V4_IP_REMOTE_ADDRESS]` and tests RFC1918/loopback — a pure helper, unit-testable
  in isolation (feed it a u32/octets).
- No allocation, no I/O, no waits — safe at DISPATCH. `DlpTaintLookup` is a
  spinlock scan (bounded 1024) — acceptable at DISPATCH.

### 5.4 `DlpWfpNotify`

`NTSTATUS DlpWfpNotify(FWPS_CALLOUT_NOTIFY_TYPE type, const GUID* filterKey,
FWPS_FILTER2* filter) { return STATUS_SUCCESS; }` — no per-filter state needed.

### 5.5 Unregister — `DlpWfpUnregister(VOID)` (in Unload, with drain discipline)

Order is the reverse and must respect the callout rundown:
1. If `WfpEngine`: `FwpmEngineOpen0`-session cleanup — delete filters
   (`FwpmFilterDeleteById0(WfpEngine, WfpFilterIdV4/V6)`), then callouts
   (`FwpmCalloutDeleteByKey0` or `…ById0`), then sublayer
   (`FwpmSubLayerDeleteByKey0`), then provider, then `FwpmEngineClose0`.
   Wrap in a transaction; guard each by its `*Added` flag.
2. `FwpsCalloutUnregisterById0(WfpCalloutIdV4/V6)` for each registered callout.
   **This can return `STATUS_DEVICE_BUSY`** if a classify is still in flight —
   retry in a small bounded loop with a short `KeDelayExecutionThread`, OR rely on
   the fact that deleting the filters first (step 1) stops new classifies and the
   `flowDeleteFn`/notify drains. Standard WFP teardown ordering; implementer must
   follow it exactly (this is a top BSOD/leak source).
3. `IoDeleteDevice(WfpDevice)`.

**Unload sequencing (edit `DlpUnload`):** the correct global order becomes:
1. `DlpUnregisterObCallbacks()` (unchanged, first).
2. `DlpWfpUnregister()` — stop blocking egress (removes filters + callouts).
3. Signal the worker: `InterlockedExchange(&ScanStop,1); KeReleaseSemaphore(&ScanSem
   ,0,1,FALSE);` then `KeWaitForSingleObject(ScanThread)`; `ObDereferenceObject
   (ScanThread)`.
4. `if (ScanRundownInit) ExWaitForRundownProtectionRelease(&ScanRundown);` — drains
   any job that slipped past between signal and stop.
5. `DlpCloseCommunicationPort()`.
6. `ExWaitForRundownProtectionRelease(&SendRundown)` (existing).
7. `PsSetCreateProcessNotifyRoutineEx(DlpCreateProcessNotify, TRUE)`.
8. `FltUnregisterFilter`; delete `ConfigLock`.

---

## 6. Wire protocol decision — NO layout change

**Decision: the frozen v2 scan request/reply layout does NOT change; `DLP_CONFIG`
does NOT change.** The one previously-unused `ULONG Reserved` at offset 4 of
`DLP_SCAN_REQUEST` is repurposed as `Reason`:

```c
#define DLP_REASON_WRITE  0   /* legacy write/quarantine scan (old value of Reserved) */
#define DLP_REASON_READ   1   /* read-taint scan                                       */
```

- `sizeof(DLP_SCAN_REQUEST)` is unchanged (1056). The Rust mirror already declares
  `pub reserved: u32` — **rename it `reason: u32`** (same bytes, same offset); the
  `size_of == 1056` / `align == 8` compile-time asserts are untouched. This is the
  "keep the `#[repr(C)]` mirror byte-locked" requirement, satisfied with zero
  layout risk.
- Backward compatibility: old `usb-guard` ignored `Reserved`; a new driver's
  `Reason=1` is harmless to it (it still scores + replies). A new `usb-guard` seeing
  `Reason=0` from an old driver treats it as a write-scan (correct legacy path).
- Read scope knobs (`ReadTaintEnabled`, `TaintedEgressPolicy`) travel via the
  **registry** (kernel, read in DriverEntry like `FailMode`) — **not** the wire —
  so neither `DLP_MSG_VERSION` nor `DLP_CONFIG_VERSION` is bumped. Read *scope*
  (which paths) reuses the existing `DLP_CONFIG` watch-set already plumbed.

This is the minimal, safest possible protocol touch.

---

## 7. Existing-connection teardown — chosen mechanism

**Chosen (v1, shipped): user-mode TCP reset by owning PID, triggered by the
read-scan BLOCK reply.** When `usb-guard` computes `Reason==DLP_REASON_READ` +
BLOCK, it already holds `req.process_id`. It calls (new)
`netfilter::reset_pid_connections(pid)`:

- `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL, AF_INET)` and `AF_INET6` →
  enumerate `MIB_TCPROW_OWNER_PID`. **Pure selection logic** (unit-testable):
  pick rows where `owningPid == pid` and state is an active/established-ish state.
- For each selected v4 row, set `dwState = MIB_TCP_STATE_DELETE_TCB` and call
  `SetTcpEntry` (admin; `SetPerTcpConnectionEStats`/`SetTcp6Entry` path for v6 as
  available). Live `SetTcpEntry` is **operator-manual / admin**, mirroring the
  existing `WfpMode::Live` gating — tests only exercise the pure row-selection.

**Rationale for user-mode v1:** far lower kernel BSOD risk; reuses the agent's
existing process/network Win32 code; the kernel callout already guarantees the
*steady-state* block, so the reset only needs to close the one in-flight socket
once. Also independent of the kernel path (two safety nets).

**Higher-assurance follow-on (v2, documented, not v1): kernel `FwpsFlowAbort0` at
`ALE_FLOW_ESTABLISHED_V4/V6`.** Add a third/fourth callout at
`FWPM_LAYER_ALE_FLOW_ESTABLISHED_*` that records `(flowHandle, calloutId, layerId,
pid)` per established flow in a small table; when `DlpTaintAdd(pid)` fires, walk
that table and `FwpsFlowAbort0(WfpEngine?/flowId, calloutId, layerId)` every flow
owned by the PID, closing the race entirely in-kernel. This needs flow contexts
and `flowDeleteFn` lifetime handling — the single largest BSOD surface — so it is
deferred behind v1 and gated by its own Verifier pass. The LLD specifies v1 as the
build target; v2 is a labeled extension.

---

## 8. Build changes — `build/build-driver.bat`

Add one source file and one library; add nothing to the include path (the WFP
kernel headers already resolve under the existing `km` + `shared` INCLUDE entries).

1. **New TU compile step** (mirrors the comms.c step; this is the INITGUID TU):
   ```bat
   echo === compile wfpcallout.c ===
   cl.exe /nologo /c /W4 /WX /wd4324 /wd4201 /wd4214 /sdl /guard:cf /GS /Od /GF /Gy /GR- /kernel ^
     /D_WIN64 /D_AMD64_ /DAMD64 /DNTDDI_VERSION=0x0A000000 /D_WIN32_WINNT=0x0A00 ^
     /Fobuild\out\wfpcallout.obj src\wfpcallout.c
   if errorlevel 1 goto :fail
   ```
   `wfpcallout.c` begins:
   ```c
   #include <initguid.h>     /* instantiate the DEFINE_GUID WFP + our own GUIDs here ONLY */
   #include "dlpflt.h"       /* pulls fltKernel.h under _KERNEL_MODE */
   #include <fwpsk.h>        /* FwpsCalloutRegister2, FWPS_* classify types */
   #include <fwpmk.h>        /* FwpmEngineOpen0, FwpmFilterAdd0, FWPM_LAYER_* keys */
   ```
   (Also add a `taint.c` compile step the same way, or keep taint.c compiled into
   the existing dlpflt.c — implementer's choice; if separate, add its own step.)

2. **Link line** — add `fwpkclnt.lib` and the new obj(s):
   ```bat
   link.exe /NOLOGO /OUT:build\out\dlpflt.sys /DRIVER /SUBSYSTEM:NATIVE,10.00 /ENTRY:GsDriverEntry ^
     /NODEFAULTLIB /RELEASE /INTEGRITYCHECK /GUARD:CF ^
     build\out\dlpflt.obj build\out\comms.obj build\out\wfpcallout.obj build\out\taint.obj ^
     fltMgr.lib ntoskrnl.lib hal.lib wdmsec.lib fwpkclnt.lib BufferOverflowFastFailK.lib
   ```
   - `fwpkclnt.lib` is the WFP **kernel** client lib (in `%SDKROOT%\Lib\%SDKVER%\
     km\x64`, already on `LIB`). It provides `FwpsCalloutRegister2`,
     `FwpsCalloutUnregisterById0`, `FwpmEngineOpen0`, `FwpmFilterAdd0`, etc.
   - **No `ndis.lib`** is needed (we do not touch NDIS / packet injection).
   - **No extra `uuid.lib`**: the well-known `FWPM_LAYER_*` / `FWPS_*` GUIDs are
     instantiated locally by the single `#include <initguid.h>` TU. If the linker
     reports unresolved `FWPM_LAYER_*` externals, the fix is INITGUID ordering in
     `wfpcallout.c`, **not** adding a lib.

The proven flags (`/kernel`, `/INTEGRITYCHECK`, `/GUARD:CF`, `/W4 /WX`, the `/wd`
codes, km\crt-first INCLUDE) are unchanged.

---

## 9. User-mode changes (agent)

### 9.1 `kguard/mod.rs`
- Rename the mirror field `reserved: u32` → `reason: u32` (byte-identical). Keep
  the `size_of==1056` asserts.
- Add `pub const DLP_REASON_WRITE: u32 = 0; pub const DLP_REASON_READ: u32 = 1;`.
- In `message_loop`, after computing `block`, branch on `req.reason`:
  - `DLP_REASON_READ` + `block` → call `netfilter::reset_pid_connections(req.process_id)`
    (best-effort; log on failure) and raise a **read-taint** incident
    (`note: "read-taint"`, channel `kg.channel_label`) instead of the write "kernel-blocked"
    note. Still reply BLOCK (the driver taints from the reply).
  - `DLP_REASON_WRITE` → today's behavior, unchanged.
- The reply verdict semantics are unchanged (BLOCK/ALLOW); only the side-effects differ.

### 9.2 `netfilter` (new pure fn + gated live path — mirror the `wfp.rs` dry-run pattern)
- `rules.rs` or a new `tcpreset.rs`: **pure** `select_pid_rows(rows: &[TcpRow], pid:
  u32) -> Vec<TcpRow>` selecting active rows owned by `pid`. Fully unit-tested.
- `reset_pid_connections(pid)` `#[cfg(windows)]`: enumerate via `GetExtendedTcpTable`,
  `select_pid_rows`, and (admin) `SetTcpEntry(DELETE_TCB)`; non-Windows `bail!` stub.
  Live reset is operator-manual, never in tests (same contract as `execute_live`).

### 9.3 config
- `KguardConfig`: no new *wire* fields needed (scope reuses `watch_paths`). Optionally
  add doc-only knobs. The kernel master switch lives in the **registry**, set by the
  installer/INF (`ReadTaintEnabled`, `TaintedEgressPolicy`) — document these next to
  `FailMode`.
- `[netfilter]` allow-list guidance (docs + shipped example config): the allow-list
  **must** include the management server host:port and DNS resolver(s); the agent's
  own PIDs are never tainted. A `[readtaint]` doc section explains the registry knobs
  and that `scope=watch` (default) reuses `[kguard].watch_paths`.

---

## 10. Runtime verification plan (operator, VM only — NOT done here)

1. Test-sign `dlpflt.sys`; install the INF with `ReadTaintEnabled=1`.
2. **Driver Verifier** on `dlpflt.sys`: Pool Tracking, Force IRQL Checking,
   Deadlock Detection, DDI compliance checking, Low-Resource Simulation, **and the
   NDIS/WFP-specific verification**. This is mandatory — WFP callouts BSOD on IRQL
   and flow-lifetime mistakes.
3. Functional: read a known-sensitive file, then attempt HTTPS upload → expect
   BLOCK; attempt from a clean process → expect PERMIT. Verify agent mTLS check-in
   and DNS still work (allow-list correctness).
4. **Unload stress:** `fltmc unload` while (a) an HTTPS connection is mid-connect,
   (b) a scan job is in flight, (c) the agent is connected — expect clean unload,
   no leak (Pool Tracking), no BSOD. Repeat under Low-Resource Simulation.
5. PID-reuse soak: churn short-lived tainted processes; confirm the exit-notify
   drains the taint table (`TaintCount` returns to baseline) and no clean process
   is mis-blocked.

---

## 11. File-by-file change list (for the coding agents)

| File | Change |
|---|---|
| `src/dlpflt.h` | Add all §1 structs + `DLP_FLT_DATA` fields + tags + `DLP_REASON_*`; add `ReadScanState` to `DLP_STREAM_CONTEXT`; declare `DlpTaint*`, `DlpSensFile*`, scan-worker, WFP, process-notify prototypes; add `Reason` param to the `DlpQueryVerdict` prototype. |
| `src/dlpflt.c` | Add `IRP_MJ_READ` post-op to `Callbacks[]`; add `DlpPostRead`; add the shared `DlpReadStreamContent` helper (factor out of `DlpInspectStream`, keep write behavior identical); init all new `gDlpData` state in `DriverEntry`; call `DlpStartScanWorker` + `DlpWfpRegister` + `PsSetCreateProcessNotifyRoutineEx` (gated on `ReadTaintEnabled`) after `FltStartFiltering`; extend `DlpReadFailMode`-style registry read for `ReadTaintEnabled`/`TaintedEgressPolicy`; rewrite `DlpUnload` teardown order per §5.5. |
| `src/taint.c` (new) | `DlpTaintLookup/Add/Remove/ResetAll`, `DlpSensFileLookup/Insert`, the scan queue (`DlpScanEnqueue`, `DlpScanWorker`, `DlpProcessScanJob`, `DlpStartScanWorker`, `DlpStopScanWorker`), `DlpCreateProcessNotify`. (May instead live in dlpflt.c.) |
| `src/wfpcallout.c` (new) | INITGUID TU; the 4 GUIDs; `DlpWfpRegister`, `DlpWfpUnregister`, `DlpWfpClassify`, `DlpWfpNotify`, `DlpWfpRemoteIsLocal`. |
| `src/comms.c` | `DlpQueryVerdict` gains `ULONG Reason` param → `request->Reserved = Reason`. Existing call sites pass `DLP_REASON_WRITE`. No other change. |
| `build/build-driver.bat` | Add `wfpcallout.c` (+ `taint.c`) compile steps; add `fwpkclnt.lib` + the new objs to the link line (§8). |
| `dlp-agent/src/kguard/mod.rs` | `reserved`→`reason`; `DLP_REASON_*` consts; branch read-scan block → `reset_pid_connections` + read-taint incident. |
| `dlp-agent/src/netfilter/{mod.rs,rules.rs or tcpreset.rs}` | Pure `select_pid_rows`; `reset_pid_connections` (windows live + non-windows stub). |
| `dlp-agent/src/config.rs` | Doc-only `[readtaint]`/`[netfilter]` guidance; no wire-affecting struct change. |
| INF / installer | `ReadTaintEnabled`, `TaintedEgressPolicy` DWORDs under the service key; example `[netfilter]` allow-list with mgmt server + DNS. |

---

## 12. Pure-logic units to hand the testing agent

Kernel (write the four ring functions so they can be compiled against a plain
array in a host harness — no locks in the pure core, lock in a thin wrapper):

1. **Taint table** — `add` then `lookup` returns true; `remove` then `lookup`
   false; inserting > `DLP_TAINT_MAX` evicts oldest (ring wrap); dedup does not
   grow count; an entry stamped with a stale `TaintEpoch` reads as absent
   (`ResetAll`/epoch-bump implicitly clears); PID 0 never matches.
2. **Sensfile cache** — insert/lookup by `(FileId,VolumeId)`; stale `Epoch` reads
   absent; ring eviction bound; distinct volumes with same file id don't collide
   when `VolumeId` differs.
3. **`DlpWfpRemoteIsLocal`** — RFC1918 / loopback / link-local classify true;
   public addresses false; v4 and v6 vectors.

Rust (already the project's test style):

4. **`select_pid_rows`** — selects only rows whose `owningPid==pid` and active
   state; empty when none; ignores other PIDs; v4 + v6.
5. **Reason plumbing** — a `DlpScanRequest` with `reason==DLP_REASON_READ` and a
   block verdict drives the read-taint branch (reset + read-taint incident); with
   `reason==DLP_REASON_WRITE` drives the legacy path; `size_of==1056` asserts still
   hold after the `reserved`→`reason` rename.
6. **Tainted-egress policy decision** — a small pure `fn tainted_egress_action(
   tainted: bool, remote_is_local: bool, policy: Tep) -> Block|Continue` mirroring
   the kernel classify logic, so the block/permit matrix (block-all vs
   block-nonlocal × local/remote × tainted/clean) is table-tested in Rust even
   though the kernel path can't be run here.
