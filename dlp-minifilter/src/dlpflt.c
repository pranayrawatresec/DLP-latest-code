/*++

dlpflt.c  --  DLP filesystem minifilter driver core.

Modeled on Microsoft's canonical `scanner`/`avscan` minifilter sample
(scan-on-access, hand the file to a user-mode scanner over a communication
port, block on a bad verdict), adapted for DLP on removable media.

Responsibilities (SPEC section 2):
  * Register the filter and attach ONLY to removable volumes (InstanceSetup).
  * Track write-candidate streams via a stream context.
  * IRP_MJ_CREATE (post): flag a write-capable open as a candidate.
  * IRP_MJ_WRITE  (pre) : mark the stream dirty (do NOT scan; file incomplete).
  * IRP_MJ_CLEANUP(pre) : the inspection point -- last handle close, file fully
                          present. Send path+metadata to user-mode, await the
                          verdict, delete-if-sensitive (detect-and-quarantine).
  * IRP_MJ_SET_INFORMATION (pre): catch rename INTO the volume (a move is not a
                          write) and mark the destination stream a candidate.
  * Self-skip the service's own I/O by PID (SPEC 2.4) -- omission = deadlock.
  * Unload: close the port, unregister; instance teardown detaches cleanly.

Verification boundary: this file is BUILT and statically analyzed here. It is
NOT loaded or run in this environment (kernel; would need test-signing + reboot;
a bug = BSOD). Runtime correctness is the operator's manual test (SPEC section 8).

--*/

#include "dlpflt.h"
#include <ntddstor.h>   /* IOCTL_STORAGE_QUERY_PROPERTY, STORAGE_* for bus type */

/* ------------------------------------------------------------------------- *
 *  Global state                                                             *
 * ------------------------------------------------------------------------- */
DLP_FLT_DATA gDlpData = { 0 };

/* Monotonic correlation id for scan requests. */
static volatile LONG64 gDlpFileId = 0;

/* ------------------------------------------------------------------------- *
 *  Forward declarations                                                     *
 * ------------------------------------------------------------------------- */
DRIVER_INITIALIZE DriverEntry;

NTSTATUS FLTAPI DlpUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);

NTSTATUS FLTAPI DlpInstanceSetup(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
    _In_ DEVICE_TYPE VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType);

NTSTATUS FLTAPI DlpInstanceQueryTeardown(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

VOID FLTAPI DlpInstanceTeardownStart(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

VOID FLTAPI DlpInstanceTeardownComplete(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags);

VOID FLTAPI DlpContextCleanup(
    _In_ PFLT_CONTEXT Context,
    _In_ FLT_CONTEXT_TYPE ContextType);

FLT_POSTOP_CALLBACK_STATUS FLTAPI DlpPostCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS FLTAPI DlpPreWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_PREOP_CALLBACK_STATUS FLTAPI DlpPreCleanup(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_PREOP_CALLBACK_STATUS FLTAPI DlpPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

FLT_POSTOP_CALLBACK_STATUS FLTAPI DlpPostRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_opt_ PVOID CompletionContext,
    _In_ FLT_POST_OPERATION_FLAGS Flags);

/* Read-deny pre-op (content-aware exfil-tool read blocking, read-deny-LLD). */
FLT_PREOP_CALLBACK_STATUS FLTAPI DlpPreRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

/* Section-sync pre-op: denies an exfil PID from memory-MAPPING a sensitive file.
 * Mapped/paging reads never reach DlpPreRead (SKIP_PAGING_IO on IRP_MJ_READ), so
 * this is the chokepoint that blocks mmap-based exfil -- the path real RustDesk /
 * AnyDesk / VNC file transfer actually uses. The verdict is seeded synchronously
 * at DlpPostCreate (safe cached read), so this callback never reads a file. */
FLT_PREOP_CALLBACK_STATUS FLTAPI DlpPreAcquireForSection(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID *CompletionContext);

/* Shared read-deny classifier (DlpPreRead buffered path + DlpPostCreate seeding).
 * Reads content + up-calls ONCE, caches the verdict in the stream context and the
 * cross-open SensFile/CleanFile rings. Returns DLP_EXFIL_DENY or DLP_EXFIL_ALLOW
 * (fail-safe resolves any unreadable/timeout). PASSIVE; caller has confirmed
 * read-deny enabled, !DlpShouldSkip, and an exfil-channel requestor PID. */
static LONG DlpExfilClassifyAndCache(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ ULONG Pid);

/* Per-thread re-entrancy guard. Our own cached FltReadFile (in the classifier)
 * lazily creates the file's data section, re-entering DlpPreAcquireForSection on
 * the SAME thread; the guard lets that internal section through so we never deny
 * our own classification read. */
static VOID    DlpClassifyGuardInit(VOID);
static BOOLEAN DlpClassifyEnter(VOID);
static VOID    DlpClassifyExit(VOID);
static BOOLEAN DlpClassifyActive(VOID);

/* TEMP-DIAGNOSTIC forward decls (OPORD access trace). */
static BOOLEAN DlpNameHas(_In_ PCUNICODE_STRING Name, _In_ PCWSTR Sub);
static BOOLEAN DlpIsOpord(_Inout_ PFLT_CALLBACK_DATA Data);

/* Read-deny (mapped-read defence): enqueue an ASYNC content scan for an exfil
 * PID's OPEN of an in-scope file. The scan worker reads + up-calls at PASSIVE
 * OFF the create path, then taints the opener (WFP network cut -- the reliable
 * backstop that catches mmap exfil the read hooks cannot see) and seeds SensFile
 * (so the section-sync pre-op can block the mapping too). Never blocks the create
 * path and never up-calls synchronously, so it cannot deadlock the create
 * completion nor storm the guard. Claim-once via the stream context. */
static VOID DlpEnqueueOpenScan(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                               _Inout_ PFLT_CALLBACK_DATA Data);

/* Shared stream-read helper (factored out of DlpInspectStream; write behavior
 * is unchanged). Reads offset 0..min(EOF,DLP_MAX_CONTENT) into a fresh
 * NonPagedPoolNx buffer the caller frees with DLP_GENERAL_TAG. */
static NTSTATUS DlpReadStreamContent(_In_ PFLT_INSTANCE Instance,
                                     _In_ PFILE_OBJECT FileObject,
                                     _Outptr_result_maybenull_ PVOID *Buffer,
                                     _Out_ PULONG Length,
                                     _Out_ PBOOLEAN Truncated);

/* Async read-taint scan worker (folded taint.c). Static internals. */
static VOID     DlpScanWorker(_In_ PVOID StartContext);
static VOID     DlpProcessScanJob(_In_ PDLP_SCAN_JOB Job);
static VOID     DlpFreeScanJob(_In_ PDLP_SCAN_JOB Job);

static BOOLEAN DlpVolumeIsRemovable(_In_ PFLT_VOLUME Volume);
static BOOLEAN DlpShouldSkip(_In_ PFLT_CALLBACK_DATA Data,
                             _In_ PCFLT_RELATED_OBJECTS FltObjects);
static NTSTATUS DlpQuarantineFile(_In_ PCFLT_RELATED_OBJECTS FltObjects);
static VOID DlpInspectStream(_Inout_ PFLT_CALLBACK_DATA Data,
                             _In_ PCFLT_RELATED_OBJECTS FltObjects,
                             _In_ PDLP_STREAM_CONTEXT Ctx,
                             _In_ ULONG VolumeClass);

/* Known-bad content-hash fast path (item 10). */
static VOID    DlpComputeSha256(_In_reads_bytes_(Len) const UCHAR *Data,
                                _In_ ULONG Len, _Out_writes_(DLP_SHA256_LEN) UCHAR *Out);
static BOOLEAN DlpBadHashLookup(_In_reads_(DLP_SHA256_LEN) const UCHAR *Sha);
static VOID    DlpBadHashInsert(_In_reads_(DLP_SHA256_LEN) const UCHAR *Sha);

/* Kernel tamper protection via ObRegisterCallbacks (item 11). */
static NTSTATUS DlpRegisterObCallbacks(VOID);
static VOID     DlpUnregisterObCallbacks(VOID);

/* Bind the pageable routines to the PAGE section; DriverEntry to INIT. */
#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DlpUnload)
#pragma alloc_text(PAGE, DlpInstanceSetup)
#pragma alloc_text(PAGE, DlpInstanceQueryTeardown)
#pragma alloc_text(PAGE, DlpInstanceTeardownStart)
#pragma alloc_text(PAGE, DlpInstanceTeardownComplete)
#pragma alloc_text(PAGE, DlpVolumeIsRemovable)
#endif

/* ------------------------------------------------------------------------- *
 *  Filter registration                                                      *
 * ------------------------------------------------------------------------- */
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,          0, NULL,                    DlpPostCreate },
    /* SKIP_PAGING_IO on the write/cleanup ops that up-call (item 7): keeps us
     * off the modified/lazy-writer path, where an up-call must never wait. */
    { IRP_MJ_WRITE,           FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
                                 DlpPreWrite,             NULL          },
    { IRP_MJ_CLEANUP,         FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
                                 DlpPreCleanup,           NULL          },
    { IRP_MJ_SET_INFORMATION, 0, DlpPreSetInformation,    NULL          },
    /* READ. Pre-op = read-deny (content-aware exfil-tool block, no-op unless
     * ExfilReadBlockEnabled); post-op = read-taint trigger (no-op unless
     * ReadTaintEnabled). SKIP_PAGING_IO like WRITE/CLEANUP so we never sit on the
     * modified/lazy-writer path. Both default-off, so the shipped default adds
     * nothing to the read path. */
    { IRP_MJ_READ,            FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO,
                                 DlpPreRead,              DlpPostRead   },
    /* ACQUIRE_FOR_SECTION_SYNCHRONIZATION (pre). The MAPPED-read half of read-
     * deny: an exfil PID creating a data section over a sensitive file is denied
     * HERE, because the subsequent page-fault (paging) reads bypass IRP_MJ_READ
     * entirely. No-op unless ExfilReadBlockEnabled; the verdict is pre-seeded at
     * create so this callback is cache-only (never reads, never up-calls). */
    { IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION,
                              0, DlpPreAcquireForSection, NULL          },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_CONTEXT_REGISTRATION Contexts[] = {
    { FLT_STREAM_CONTEXT,
      0,
      DlpContextCleanup,
      sizeof(DLP_STREAM_CONTEXT),
      DLP_STREAM_CONTEXT_TAG,
      NULL, NULL, NULL },
    { FLT_INSTANCE_CONTEXT,
      0,
      DlpContextCleanup,
      sizeof(DLP_INSTANCE_CONTEXT),
      DLP_INSTANCE_CONTEXT_TAG,
      NULL, NULL, NULL },
    { FLT_CONTEXT_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),           /* Size                        */
    FLT_REGISTRATION_VERSION,           /* Version                     */
    0,                                  /* Flags                       */
    Contexts,                           /* ContextRegistration         */
    Callbacks,                          /* OperationRegistration       */
    DlpUnload,                          /* FilterUnloadCallback        */
    DlpInstanceSetup,                   /* InstanceSetupCallback       */
    DlpInstanceQueryTeardown,           /* InstanceQueryTeardownCallback */
    DlpInstanceTeardownStart,           /* InstanceTeardownStartCallback */
    DlpInstanceTeardownComplete,        /* InstanceTeardownCompleteCallback */
    NULL,                               /* GenerateFileNameCallback    */
    NULL,                               /* NormalizeNameComponentCallback */
    NULL,                               /* NormalizeContextCleanupCallback */
    NULL,                               /* TransactionNotificationCallback */
    NULL,                               /* NormalizeNameComponentExCallback */
    NULL                                /* SectionNotificationCallback */
};


/* ------------------------------------------------------------------------- *
 *  DriverEntry                                                              *
 * ------------------------------------------------------------------------- */
NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    gDlpData.DriverObject = DriverObject;
    gDlpData.FailMode = DLP_FAILMODE_ALLOW;   /* safe default; overridden below */

    /* Hardening state (items 2/3/4/10). Initialize BEFORE any callback can run
     * (before FltStartFiltering). Epoch starts at 1 (0 reserved for "never
     * decided"); the breaker starts closed; the known-bad ring starts empty. */
    ExInitializeRundownProtection(&gDlpData.SendRundown);   /* item 2, A4 */
    gDlpData.SendRundownInit = TRUE;
    gDlpData.Epoch = 1;                                     /* item 4, H2 */
    gDlpData.ConsecutiveTimeouts = 0;                       /* item 3, H5 */
    KeInitializeSpinLock(&gDlpData.BadHashLock);            /* item 10     */
    RtlZeroMemory(gDlpData.BadHash, sizeof(gDlpData.BadHash));
    gDlpData.BadHashNext = 0;
    gDlpData.ObCallbackHandle = NULL;

    /* Read-taint state (all gated by ReadTaintEnabled). Initialize the taint
     * table + sensfile cache BEFORE FltStartFiltering so any early DlpPostRead
     * finds valid spinlocks. Both mirror the BadHash ring (epoch-stamped). The
     * scan queue / rundown / worker thread are brought up later, gated on the
     * registry switch (DlpStartScanWorker); DlpPostRead does nothing until the
     * worker publishes readiness via ScanRundownInit. Defaults are the shipped
     * OFF/block-all (DlpReadTaintPolicy only overrides them from the registry). */
    gDlpData.ReadTaintEnabled = DLP_READTAINT_DISABLED;
    gDlpData.TaintedEgressPolicy = DLP_TEP_BLOCK_ALL;
    KeInitializeSpinLock(&gDlpData.TaintLock);
    RtlZeroMemory(gDlpData.Taint, sizeof(gDlpData.Taint));
    gDlpData.TaintEpoch = 1;                                /* 0 reserved       */
    gDlpData.TaintCount = 0;
    gDlpData.TaintNext = 0;
    KeInitializeSpinLock(&gDlpData.SensFileLock);
    RtlZeroMemory(gDlpData.SensFile, sizeof(gDlpData.SensFile));
    gDlpData.SensFileNext = 0;
    KeInitializeSpinLock(&gDlpData.CleanFileLock);
    RtlZeroMemory(gDlpData.CleanFile, sizeof(gDlpData.CleanFile));
    gDlpData.CleanFileNext = 0;
    DlpClassifyGuardInit();     /* per-thread re-entrancy guard (section re-entry) */
    /* Read-deny (content-aware exfil-tool read blocking). Defaults OFF + fail-block;
     * DlpReadExfilPolicy overrides from the registry. The exfil-PID set starts empty
     * and is filled by DLP_EXFIL_UPDATE messages once the agent connects. */
    gDlpData.ExfilReadBlockEnabled = DLP_EXFILREAD_DISABLED;
    gDlpData.ExfilReadFailBlock = 1;
    KeInitializeSpinLock(&gDlpData.ExfilLock);
    RtlZeroMemory(gDlpData.Exfil, sizeof(gDlpData.Exfil));
    gDlpData.ExfilEpoch = 1;                                /* 0 reserved       */
    gDlpData.ExfilCount = 0;
    gDlpData.ScanRundownInit = FALSE;
    gDlpData.ScanThread = NULL;
    gDlpData.ProcNotifyRegistered = FALSE;

    /* Scan-scope config lock. Initialize BEFORE FltStartFiltering so any early
     * InstanceSetup/CLEANUP that reads the config finds a valid lock. Until a
     * DLP_CONFIG message arrives, ConfigValid is 0 => removable-only. */
    status = ExInitializeResourceLite(&gDlpData.ConfigLock);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    gDlpData.ConfigLockInit = TRUE;

    /* TEMP-DIAGNOSTIC: save the service registry path for the OPORD trace. */
    gDlpData.SvcRegPathValid = FALSE;
    if (RegistryPath != NULL && RegistryPath->Buffer != NULL &&
        RegistryPath->Length > 0 &&
        RegistryPath->Length < sizeof(gDlpData.SvcRegPath)) {
        RtlCopyMemory(gDlpData.SvcRegPath, RegistryPath->Buffer, RegistryPath->Length);
        gDlpData.SvcRegPathBytes = RegistryPath->Length;
        gDlpData.SvcRegPathValid = TRUE;
    }

    /* Read the deployment's FailMode from the service registry key. */
    DlpReadFailMode(RegistryPath);

    /* Read the read-taint knobs (ReadTaintEnabled, TaintedEgressPolicy) from the
     * same key BEFORE FltStartFiltering, so the DlpPostRead kill-switch sees the
     * real value from the first read callback. Absent key => stays OFF (today's
     * FS-only behavior). */
    DlpReadTaintPolicy(RegistryPath);

    /* Read the read-deny knobs (ExfilReadBlockEnabled, ExfilReadFailBlock) from the
     * same key BEFORE FltStartFiltering, so DlpPreRead's kill-switch is correct from
     * the first read. Absent key => stays OFF (today's behavior). */
    DlpReadExfilPolicy(RegistryPath);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gDlpData.Filter);
    if (!NT_SUCCESS(status)) {
        ExDeleteResourceLite(&gDlpData.ConfigLock);
        gDlpData.ConfigLockInit = FALSE;
        return status;
    }

    status = DlpCreateCommunicationPort(gDlpData.Filter);
    if (!NT_SUCCESS(status)) {
        FltUnregisterFilter(gDlpData.Filter);
        gDlpData.Filter = NULL;
        ExDeleteResourceLite(&gDlpData.ConfigLock);
        gDlpData.ConfigLockInit = FALSE;
        return status;
    }

    /* Kernel tamper protection (item 11). Register the process-handle
     * ObCallback BEFORE filtering starts so the agent is protected the moment
     * it connects. Requires the image be linked /INTEGRITYCHECK and signed; a
     * registration failure is fatal (fail-secure toward the tamper guarantee)
     * and unwinds the port + filter. */
    status = DlpRegisterObCallbacks();
    if (!NT_SUCCESS(status)) {
        DlpCloseCommunicationPort();
        FltUnregisterFilter(gDlpData.Filter);
        gDlpData.Filter = NULL;
        ExDeleteResourceLite(&gDlpData.ConfigLock);
        gDlpData.ConfigLockInit = FALSE;
        return status;
    }

    status = FltStartFiltering(gDlpData.Filter);
    if (!NT_SUCCESS(status)) {
        DlpUnregisterObCallbacks();
        DlpCloseCommunicationPort();
        FltUnregisterFilter(gDlpData.Filter);
        gDlpData.Filter = NULL;
        ExDeleteResourceLite(&gDlpData.ConfigLock);
        gDlpData.ConfigLockInit = FALSE;
        return status;
    }

    /* --- Read-taint bring-up (opt-in; default OFF behaves EXACTLY as today) ---
     * Done AFTER FltStartFiltering (the FS filter must be live first, LLD §5.2).
     * All best-effort: read-taint must never fail DriverEntry -- losing the
     * network-egress block must not take down USB/content/FS protection.
     *   - Worker-start failure  => disable read-taint entirely (no half-up
     *                              subsystem; DlpPostRead then no-ops).
     *   - Process-notify failure => continue without exit-untaint (taint slots
     *                              are still bounded by ring eviction).
     *   - WFP register failure   => continue FS-only (NON-FATAL, LLD §5.2). */
    if (gDlpData.ReadTaintEnabled == DLP_READTAINT_ENABLED ||
        gDlpData.ExfilReadBlockEnabled == DLP_EXFILREAD_ENABLED) {
        NTSTATUS rtStatus = DlpStartScanWorker();
        if (!NT_SUCCESS(rtStatus)) {
            /* No worker => read-taint cannot function AND read-deny loses its
             * async open-scan (the mmap backstop: taint-the-opener + SensFile
             * seed). Disable read-taint; read-deny keeps its synchronous buffered-
             * read block (DlpPreRead) -- just without the mapped-read backstop. */
            gDlpData.ReadTaintEnabled = DLP_READTAINT_DISABLED;
        } else {
            /* WFP egress callout (wfpcallout.c): the taint -> network-cut enforcer.
             * Needed by BOTH read-taint and read-deny's open-scan backstop (a
             * tainted exfil tool cannot ship a mapped read it already made off the
             * box). NON-FATAL: on failure roll back partial WFP state (idempotent)
             * and keep FS protection + the read/section blocks. */
            rtStatus = DlpWfpRegister();
            if (!NT_SUCCESS(rtStatus)) {
                DlpWfpUnregister();
            }
        }
    }

    /* Process-exit notify serves BOTH read-taint (untaint the PID) and read-deny
     * (drop the exfil PID -> closes the PID-reuse window between agent pushes).
     * Register once if EITHER feature is live. Non-fatal: ring eviction / the
     * agent's next full-replace still bound both tables without it. */
    if (gDlpData.ReadTaintEnabled == DLP_READTAINT_ENABLED ||
        gDlpData.ExfilReadBlockEnabled == DLP_EXFILREAD_ENABLED) {
        if (NT_SUCCESS(PsSetCreateProcessNotifyRoutineEx(DlpCreateProcessNotify,
                                                         FALSE))) {
            gDlpData.ProcNotifyRegistered = TRUE;
        }
    }

    return STATUS_SUCCESS;
}


/* ------------------------------------------------------------------------- *
 *  Unload + instance teardown                                              *
 * ------------------------------------------------------------------------- */
NTSTATUS FLTAPI
DlpUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();

    /* Teardown order per LLD §5.5 -- STRICT REVERSE of bring-up. Every read-taint
     * step is idempotent / guarded by its own flag, so a driver that never
     * enabled read-taint (or only partially brought it up) tears down cleanly. */

    /* 1) Drop tamper protection FIRST (item 11): stop intercepting process-handle
     *    opens before anything else tears down. */
    DlpUnregisterObCallbacks();

    /* 2) Stop blocking egress: remove the WFP filters + callouts BEFORE the
     *    worker stops, so no new connect is blocked while we drain. No-op (fully
     *    idempotent, flag-guarded) when read-taint was never/only-partly up. */
    DlpWfpUnregister();

    /* 3+4) Stop the async scan worker. DlpStopScanWorker folds LLD §5.5 steps 3
     *    and 4 in the race-free order: it FIRST runs down ScanRundown (so every
     *    subsequent DlpScanEnqueue drops its job instead of orphaning a rundown
     *    ref) and drains all in-flight jobs the still-running worker holds, THEN
     *    signals + joins the worker thread. No-op if the worker never started. */
    DlpStopScanWorker();

    /* 5) Close the server port (and defensively NULL the client port) so no new
     *    agent can connect and no new up-call can begin. Done AFTER the worker
     *    drains so an in-flight read-scan up-call still reaches the agent. */
    DlpCloseCommunicationPort();

    /* 6) Drain in-flight FltSendMessage up-calls (item 2, A4). Waited EXACTLY
     *    ONCE, only here, and only AFTER the ports are closed so any send past
     *    the rundown-acquire runs to completion and none can newly start. This
     *    is what guarantees FltUnregisterFilter cannot hang on an outstanding
     *    send. Step 5 already NULLed &gDlpData.ClientPort, unblocking any send
     *    currently waiting inside FltSendMessage. */
    if (gDlpData.SendRundownInit) {
        ExWaitForRundownProtectionRelease(&gDlpData.SendRundown);
        gDlpData.SendRundownInit = FALSE;
    }

    /* 7) Unregister the process-exit untaint notify. Safe here: nothing reads the
     *    taint table any more (WFP gone in step 2, worker gone in step 3). */
    if (gDlpData.ProcNotifyRegistered) {
        (VOID)PsSetCreateProcessNotifyRoutineEx(DlpCreateProcessNotify, TRUE);
        gDlpData.ProcNotifyRegistered = FALSE;
    }

    /* 8) Unregister the filter; delete the config lock. */
    if (gDlpData.Filter != NULL) {
        FltUnregisterFilter(gDlpData.Filter);
        gDlpData.Filter = NULL;
    }

    if (gDlpData.ConfigLockInit) {
        ExDeleteResourceLite(&gDlpData.ConfigLock);
        gDlpData.ConfigLockInit = FALSE;
    }
    return STATUS_SUCCESS;
}

NTSTATUS FLTAPI
DlpInstanceQueryTeardown(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                         _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
    return STATUS_SUCCESS;   /* always allow detach */
}

VOID FLTAPI
DlpInstanceTeardownStart(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                         _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
}

VOID FLTAPI
DlpInstanceTeardownComplete(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                            _In_ FLT_INSTANCE_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();
}


/* ------------------------------------------------------------------------- *
 *  InstanceSetup -- attach to REMOVABLE volumes only (SPEC 2.1 / 6)         *
 * ------------------------------------------------------------------------- */
NTSTATUS FLTAPI
DlpInstanceSetup(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                 _In_ FLT_INSTANCE_SETUP_FLAGS Flags,
                 _In_ DEVICE_TYPE VolumeDeviceType,
                 _In_ FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    NTSTATUS status;
    ULONG volumeClass;
    PDLP_INSTANCE_CONTEXT instCtx = NULL;

    UNREFERENCED_PARAMETER(Flags);
    PAGED_CODE();

    /* Do not attach to raw/unrecognized/unknown filesystem volumes (applies to
     * every class). */
    if (VolumeFilesystemType == FLT_FSTYPE_RAW ||
        VolumeFilesystemType == FLT_FSTYPE_UNKNOWN) {
        return STATUS_FLT_DO_NOT_ATTACH;
    }

    /* Classify the volume and apply the attach policy (Tier-1 extension).
     * Empty/absent config keeps today's behavior: network attaches only if
     * ScanNetwork is set, fixed never attaches (removable-only back-compat). */
    if (VolumeDeviceType == FILE_DEVICE_NETWORK_FILE_SYSTEM) {
        /* Network (SMB) redirector: a copy to a share is an egress target, but
         * only inspect it when the deployment opted in. */
        if (!DlpConfigScanNetwork()) {
            return STATUS_FLT_DO_NOT_ATTACH;
        }
        volumeClass = DLP_VOL_NETWORK;
    } else if (DlpVolumeIsRemovable(FltObjects->Volume)) {
        /* Removable media -- attach as always. */
        volumeClass = DLP_VOL_REMOVABLE;
    } else {
        /* Fixed / OS volume: attach ONLY when a non-empty watch-set is
         * configured (DlpConfigScanFixed enforces ScanFixed AND WatchCount>0).
         * With no config we return DO_NOT_ATTACH -- never sit on the system
         * disk by default. This is the back-compat safety invariant. */
        if (!DlpConfigScanFixed()) {
            return STATUS_FLT_DO_NOT_ATTACH;
        }
        volumeClass = DLP_VOL_FIXED;
    }

    /* Stash the class in an instance context so the hot CLEANUP path can branch
     * (inspect-all vs watch-prefix-only) without re-querying the volume. If the
     * context cannot be set (rare OOM), CLEANUP falls back to inspect-all
     * (fail-secure toward inspection). */
    status = FltAllocateContext(gDlpData.Filter, FLT_INSTANCE_CONTEXT,
                                sizeof(DLP_INSTANCE_CONTEXT), NonPagedPoolNx,
                                (PFLT_CONTEXT *)&instCtx);
    if (NT_SUCCESS(status)) {
        instCtx->VolumeClass = volumeClass;
        (VOID)FltSetInstanceContext(FltObjects->Instance,
                                    FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                    (PFLT_CONTEXT)instCtx, NULL);
        FltReleaseContext((PFLT_CONTEXT)instCtx);
    }

    return STATUS_SUCCESS;
}


/*++
DlpVolumeIsRemovable -- classify a volume as removable.

Two signals, mirroring the user-mode agent's device classifier:
  1. FLT_VOLUME_PROPERTIES.DeviceCharacteristics & FILE_REMOVABLE_MEDIA
     (covers USB sticks, SD cards, floppies).
  2. The backing disk's STORAGE_BUS_TYPE == USB/SD/MMC (covers external USB
     SSDs/HDDs that report FIXED media but are physically removable).
Any failure falls back to signal (1); a total failure returns FALSE (do not
attach -- fail safe toward NOT touching an unknown volume).
--*/
static BOOLEAN
DlpVolumeIsRemovable(_In_ PFLT_VOLUME Volume)
{
    NTSTATUS status;
    UCHAR propBuffer[sizeof(FLT_VOLUME_PROPERTIES) + 512] = { 0 };
    PFLT_VOLUME_PROPERTIES props = (PFLT_VOLUME_PROPERTIES)propBuffer;
    ULONG returned = 0;
    PDEVICE_OBJECT diskDevice = NULL;
    BOOLEAN removable = FALSE;

    PAGED_CODE();

    /* Signal 1: device characteristics. */
    status = FltGetVolumeProperties(Volume, props, sizeof(propBuffer), &returned);
    if (NT_SUCCESS(status) || status == STATUS_BUFFER_OVERFLOW) {
        if ((props->DeviceCharacteristics & FILE_REMOVABLE_MEDIA) != 0 ||
            (props->DeviceCharacteristics & FILE_FLOPPY_DISKETTE) != 0) {
            removable = TRUE;
        }
    }

    /* Signal 2: bus type of the backing disk device (catches USB SSDs whose
     * removable flag is FALSE). Best-effort; failure leaves signal 1 intact. */
    status = FltGetDiskDeviceObject(Volume, &diskDevice);
    if (NT_SUCCESS(status) && diskDevice != NULL) {
        KEVENT event;
        IO_STATUS_BLOCK iosb = { 0 };
        STORAGE_PROPERTY_QUERY query;
        UCHAR descBuffer[sizeof(STORAGE_DEVICE_DESCRIPTOR) + 256] = { 0 };
        PIRP irp;

        RtlZeroMemory(&query, sizeof(query));
        query.PropertyId = StorageDeviceProperty;
        query.QueryType = PropertyStandardQuery;

        KeInitializeEvent(&event, NotificationEvent, FALSE);

        irp = IoBuildDeviceIoControlRequest(
            IOCTL_STORAGE_QUERY_PROPERTY,
            diskDevice,
            &query, sizeof(query),
            descBuffer, sizeof(descBuffer),
            FALSE,
            &event,
            &iosb);

        if (irp != NULL) {
            NTSTATUS ioStatus = IoCallDriver(diskDevice, irp);
            if (ioStatus == STATUS_PENDING) {
                KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
                ioStatus = iosb.Status;
            }
            if (NT_SUCCESS(ioStatus)) {
                PSTORAGE_DEVICE_DESCRIPTOR desc =
                    (PSTORAGE_DEVICE_DESCRIPTOR)descBuffer;
                if (desc->BusType == BusTypeUsb ||
                    desc->BusType == BusTypeSd ||
                    desc->BusType == BusTypeMmc) {
                    removable = TRUE;
                }
            }
        }

        ObDereferenceObject(diskDevice);
    }

    return removable;
}


/* ------------------------------------------------------------------------- *
 *  Stream-context cleanup                                                  *
 * ------------------------------------------------------------------------- */
VOID FLTAPI
DlpContextCleanup(_In_ PFLT_CONTEXT Context, _In_ FLT_CONTEXT_TYPE ContextType)
{
    UNREFERENCED_PARAMETER(Context);
    UNREFERENCED_PARAMETER(ContextType);
    /* DLP_STREAM_CONTEXT holds no pointers to free; FltMgr reclaims the
     * allocation. Present so context ref-counting / cleanup is registered. */
}


/* ------------------------------------------------------------------------- *
 *  DlpShouldSkip (item 1) -- the single top-of-callback bypass gate          *
 *                                                                            *
 *  Called FIRST in every pre/post callback that may lead to an up-call.      *
 *  Consolidates the piecemeal paging / FileObject / self-skip checks and     *
 *  ADDS the two guards the old driver proved mandatory (HARDENING-PLAN A3 +  *
 *  re-entrancy): we only ever up-call at PASSIVE_LEVEL and only when NOT      *
 *  nested inside another top-level FS operation. FltSendMessage / FltReadFile *
 *  both wait and both require PASSIVE_LEVEL; up-calling from a raised IRQL or *
 *  from inside nested FS I/O is the classic minifilter deadlock.             *
 * ------------------------------------------------------------------------- */
#define DLP_SYSTEM_PID  ((LONG)4)

static BOOLEAN
DlpShouldSkip(_In_ PFLT_CALLBACK_DATA Data,
              _In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    LONG pid;
    LONG servicePid;

    /* Paging / system-issued I/O: stay out of the page-fault path entirely. */
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)) {
        return TRUE;
    }
    /* Volume-open / no stream to score. */
    if (FltObjects->FileObject == NULL) {
        return TRUE;
    }
    /* A3: the up-call waits -> PASSIVE_LEVEL only. */
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return TRUE;
    }
    /* Re-entrancy: never up-call while nested inside another top-level FS
     * operation (the up-call and its FltReadFile would recurse the stack we are
     * already unwinding). Critical -- absent from the pre-hardening code. */
    if (IoGetTopLevelIrp() != NULL) {
        return TRUE;
    }
    /* Self-skip: never act on the agent's own I/O (it reads files to fingerprint
     * them, which would recurse back into us and deadlock the 1-connection
     * port), nor on the System process. The ServicePid==0 sentinel guards
     * thread-less I/O, for which FltGetRequestorProcessId also returns 0, from
     * being mistaken for the agent. */
    pid = (LONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
    servicePid = InterlockedCompareExchange(&gDlpData.ServicePid, 0, 0);
    if ((servicePid != 0 && pid == servicePid) || pid == DLP_SYSTEM_PID) {
        return TRUE;
    }
    return FALSE;
}


/* ------------------------------------------------------------------------- *
 *  IRP_MJ_CREATE (post) -- flag a write-capable open as a candidate         *
 * ------------------------------------------------------------------------- */
FLT_POSTOP_CALLBACK_STATUS FLTAPI
DlpPostCreate(_Inout_ PFLT_CALLBACK_DATA Data,
              _In_ PCFLT_RELATED_OBJECTS FltObjects,
              _In_opt_ PVOID CompletionContext,
              _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    NTSTATUS status;
    PDLP_STREAM_CONTEXT ctx = NULL;
    ULONG desiredAccess;
    BOOLEAN wantsWrite;
    BOOLEAN isDirectory = FALSE;

    UNREFERENCED_PARAMETER(CompletionContext);

    /* Draining / failed creates: nothing to do. */
    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    if (!NT_SUCCESS(Data->IoStatus.Status) ||
        Data->IoStatus.Status == STATUS_REPARSE) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* TEMP-DIAGNOSTIC: record every OPORD open (pid, exfil, would-skip). */
    if (KeGetCurrentIrql() == PASSIVE_LEVEL && DlpIsOpord(Data)) {
        ULONG p = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
        DlpTraceCre(p, DlpExfilLookup(p) ? 1u : 0u,
                    DlpShouldSkip(Data, FltObjects) ? 1u : 0u);
    }

    /* Item 1: single top-of-callback gate (self-skip / paging / FileObject /
     * IRQL / re-entrancy). Same discipline as the up-call sites so the bypass
     * logic cannot drift between callbacks. */
    if (DlpShouldSkip(Data, FltObjects)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* Skip directory opens -- we only score files (SPEC 2.2). */
    status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDirectory);
    if (NT_SUCCESS(status) && isDirectory) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* Read-deny (mapped-read defence): if an exfil-channel PID just opened a file,
     * enqueue an ASYNC content scan. The worker (off the create path, at PASSIVE)
     * taints the opener -> WFP cuts its egress, catching mmap-based exfil that the
     * read hooks miss (a memory-mapped read is paging I/O and never reaches
     * DlpPreRead), and seeds SensFile so the section-sync pre-op blocks the mapping
     * too. This runs for read-only opens (an mmap-read open has no write access).
     * A synchronous classify HERE would stall the create completion (FltReadFile /
     * FltSendMessage on the create path deadlocks) -- hence the async worker. */
    if (gDlpData.ExfilReadBlockEnabled == DLP_EXFILREAD_ENABLED &&
        gDlpData.ScanRundownInit) {
        ULONG rpid = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
        if (DlpExfilLookup(rpid)) {
            DlpEnqueueOpenScan(FltObjects, Data);
        }
    }

    /* Only track opens that could write: a read-only open cannot leak new
     * content onto the media. */
    desiredAccess = Data->Iopb->Parameters.Create.SecurityContext->DesiredAccess;
    wantsWrite = (desiredAccess &
                  (FILE_WRITE_DATA | FILE_APPEND_DATA | GENERIC_WRITE | DELETE)) != 0;
    if (!wantsWrite) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* Allocate + attach a stream context (idempotent: reuse if present). */
    status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject,
                                 (PFLT_CONTEXT *)&ctx);
    if (!NT_SUCCESS(status)) {
        status = FltAllocateContext(gDlpData.Filter, FLT_STREAM_CONTEXT,
                                    sizeof(DLP_STREAM_CONTEXT), NonPagedPoolNx,
                                    (PFLT_CONTEXT *)&ctx);
        if (!NT_SUCCESS(status)) {
            return FLT_POSTOP_FINISHED_PROCESSING;   /* fail-safe: just don't track */
        }
        ctx->WriteCandidate = 1;
        ctx->Dirty = 0;
        ctx->Inspected = 0;
        ctx->Epoch = InterlockedCompareExchange(&gDlpData.Epoch, 0, 0); /* item 4 */

        status = FltSetStreamContext(FltObjects->Instance, FltObjects->FileObject,
                                     FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                     (PFLT_CONTEXT)ctx, NULL);
        if (!NT_SUCCESS(status)) {
            /* Another thread attached first, or it cannot be set -- benign. */
            FltReleaseContext((PFLT_CONTEXT)ctx);
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
    } else {
        InterlockedExchange(&ctx->WriteCandidate, 1);
    }

    FltReleaseContext((PFLT_CONTEXT)ctx);
    return FLT_POSTOP_FINISHED_PROCESSING;
}


/* ------------------------------------------------------------------------- *
 *  IRP_MJ_WRITE (pre) -- mark the stream dirty; do NOT scan here            *
 * ------------------------------------------------------------------------- */
FLT_PREOP_CALLBACK_STATUS FLTAPI
DlpPreWrite(_Inout_ PFLT_CALLBACK_DATA Data,
            _In_ PCFLT_RELATED_OBJECTS FltObjects,
            _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PDLP_STREAM_CONTEXT ctx = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CompletionContext);

    /* Item 1: single top-of-callback gate. */
    if (DlpShouldSkip(Data, FltObjects)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject,
                                 (PFLT_CONTEXT *)&ctx);
    if (NT_SUCCESS(status)) {
        InterlockedExchange(&ctx->Dirty, 1);
        FltReleaseContext((PFLT_CONTEXT)ctx);
    }

    /* We never need the post-op for a write. */
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


/* ------------------------------------------------------------------------- *
 *  IRP_MJ_SET_INFORMATION (pre) -- catch rename INTO the removable volume   *
 * ------------------------------------------------------------------------- */
FLT_PREOP_CALLBACK_STATUS FLTAPI
DlpPreSetInformation(_Inout_ PFLT_CALLBACK_DATA Data,
                     _In_ PCFLT_RELATED_OBJECTS FltObjects,
                     _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    FILE_INFORMATION_CLASS infoClass;
    PDLP_STREAM_CONTEXT ctx = NULL;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CompletionContext);

    /* Item 1: single top-of-callback gate. */
    if (DlpShouldSkip(Data, FltObjects)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    /* A rename/move whose destination is on our (removable) instance means a
     * file arrived without any WRITE we would have seen -- treat it as a scan
     * candidate. Because we only attach to removable volumes, being on this
     * instance already implies the destination is removable media. */
    if (infoClass == FileRenameInformation ||
        infoClass == FileRenameInformationEx) {

        status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject,
                                     (PFLT_CONTEXT *)&ctx);
        if (!NT_SUCCESS(status)) {
            status = FltAllocateContext(gDlpData.Filter, FLT_STREAM_CONTEXT,
                                        sizeof(DLP_STREAM_CONTEXT), NonPagedPoolNx,
                                        (PFLT_CONTEXT *)&ctx);
            if (NT_SUCCESS(status)) {
                ctx->WriteCandidate = 1;
                ctx->Dirty = 1;
                ctx->Inspected = 0;
                ctx->Epoch = InterlockedCompareExchange(&gDlpData.Epoch, 0, 0); /* item 4 */
                if (!NT_SUCCESS(FltSetStreamContext(
                        FltObjects->Instance, FltObjects->FileObject,
                        FLT_SET_CONTEXT_KEEP_IF_EXISTS, (PFLT_CONTEXT)ctx, NULL))) {
                    FltReleaseContext((PFLT_CONTEXT)ctx);
                    ctx = NULL;
                }
            } else {
                ctx = NULL;
            }
        } else {
            InterlockedExchange(&ctx->WriteCandidate, 1);
            InterlockedExchange(&ctx->Dirty, 1);
        }

        if (ctx != NULL) {
            FltReleaseContext((PFLT_CONTEXT)ctx);
        }
    }

    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


/* ------------------------------------------------------------------------- *
 *  IRP_MJ_CLEANUP (pre) -- the inspection point (SPEC 2.2)                  *
 * ------------------------------------------------------------------------- */
FLT_PREOP_CALLBACK_STATUS FLTAPI
DlpPreCleanup(_Inout_ PFLT_CALLBACK_DATA Data,
              _In_ PCFLT_RELATED_OBJECTS FltObjects,
              _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    PDLP_STREAM_CONTEXT ctx = NULL;
    PDLP_INSTANCE_CONTEXT instCtx = NULL;
    ULONG volumeClass = DLP_VOL_REMOVABLE;   /* fallback: inspect-all */
    NTSTATUS status;

    UNREFERENCED_PARAMETER(CompletionContext);

    /* Item 1: the single top-of-callback gate. Supersedes the old piecemeal
     * self-skip / paging / FileObject checks and ADDS the mandatory PASSIVE_LEVEL
     * + re-entrancy (IoGetTopLevelIrp) guards -- this is the CLEANUP inspection
     * point that up-calls (FltReadFile + FltSendMessage), so it must never run
     * at raised IRQL or nested inside another top-level FS operation. */
    if (DlpShouldSkip(Data, FltObjects)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject,
                                 (PFLT_CONTEXT *)&ctx);
    if (!NT_SUCCESS(status) || ctx == NULL) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;   /* not a tracked write candidate */
    }

    /* Volume class recorded at InstanceSetup. Absent context => inspect-all
     * (fail-secure toward inspection; never silently skips a removable write). */
    status = FltGetInstanceContext(FltObjects->Instance, (PFLT_CONTEXT *)&instCtx);
    if (NT_SUCCESS(status) && instCtx != NULL) {
        volumeClass = instCtx->VolumeClass;
        FltReleaseContext((PFLT_CONTEXT)instCtx);
    }

    /* Only dirty write-candidates, and only once per stream. */
    if (InterlockedCompareExchange(&ctx->Dirty, 0, 0) != 0 &&
        InterlockedCompareExchange(&ctx->WriteCandidate, 0, 0) != 0 &&
        InterlockedCompareExchange(&ctx->Inspected, 1, 0) == 0) {

        DlpInspectStream(Data, FltObjects, ctx, volumeClass);
    }

    FltReleaseContext((PFLT_CONTEXT)ctx);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


/*++
DlpInspectStream -- resolve the name, ask user-mode for a verdict, and on BLOCK
delete the file from the media (detect-and-quarantine, SPEC 2.5). PASSIVE_LEVEL
(cleanup pre-op), so FltGetFileNameInformation / FltSendMessage / file ops are
all legal here.

VolumeClass (Tier-1 extension) selects the scope:
  * REMOVABLE / NETWORK -> inspect every dirty candidate (as always).
  * FIXED               -> the name query is done lazily here (only for a dirty
                           candidate), then quick-rejected unless the path is
                           under a configured watch prefix -- keeping the C:
                           hot path cheap.
--*/
static VOID
DlpInspectStream(_Inout_ PFLT_CALLBACK_DATA Data,
                 _In_ PCFLT_RELATED_OBJECTS FltObjects,
                 _In_ PDLP_STREAM_CONTEXT Ctx,
                 _In_ ULONG VolumeClass)
{
    NTSTATUS status;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    BOOLEAN block = FALSE;
    ULONGLONG fileId;
    ULONG pid;
    PVOID content = NULL;
    ULONG contentBytes = 0;      /* bytes actually shipped to the service   */
    BOOLEAN truncated = FALSE;   /* file was larger than the cap            */

    UNREFERENCED_PARAMETER(Ctx);

    fileId = (ULONGLONG)InterlockedIncrement64(&gDlpFileId);
    pid = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);

    /* Resolve the file name. A failed name query must fail-safe per FailMode,
     * never crash (SPEC 2.4). */
    status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo);
    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        block = (gDlpData.FailMode == DLP_FAILMODE_BLOCK);
        if (block) {
            (VOID)DlpQuarantineFile(FltObjects);
        }
        return;
    }

    (VOID)FltParseFileNameInformation(nameInfo);

    /* The write/quarantine path targets EXFIL destinations only -- removable +
     * network. A fixed-volume watch arms READ-TAINT (DlpPostRead), NOT local file
     * deletion: copying a sensitive file C:->C: is not exfiltration and must never
     * be quarantined. So the write path never inspects a fixed volume; read-taint
     * (a separate callback) still covers reads there. (Blocking writes into a
     * specific cloud-sync folder is a separate, narrower future feature.) */
    if (VolumeClass == DLP_VOL_FIXED) {
        FltReleaseFileNameInformation(nameInfo);
        return;
    }

    /* Read the stream IN-KERNEL and ship the bytes to the service (SPEC v2).
     * We are inside the FS stack at PASSIVE_LEVEL (cleanup pre-op), so this read
     * does not race the copier's exclusive handle the way a user-mode re-open
     * would -- FltReadFile issues a fresh IRP below our instance, immune to the
     * share modes on the caller's handle. Any query/alloc/read failure just
     * ships no content and fails-safe; it must NEVER crash. Factored into
     * DlpReadStreamContent (shared byte-for-byte with the read-taint worker). */
    (VOID)DlpReadStreamContent(FltObjects->Instance, FltObjects->FileObject,
                               &content, &contentBytes, &truncated);

    /* Item 10: known-bad content-hash fast path. When we shipped content, hash
     * the EXACT bytes and consult the bounded, epoch-stamped known-bad table.
     *   * hit  -> block in-kernel with NO up-call (a repeat copy of content the
     *            agent already blocked is stopped without waking user-mode);
     *   * miss -> the normal up-call, and a GENUINE agent BLOCK reply (status
     *            success, not a fail-secure default) seeds the table so the next
     *            copy takes the fast path.
     * The raw-content SHA is unrelated to the service's fingerprint math -- it
     * only fingerprints the shipped bytes for exact-repeat suppression. */
    if (contentBytes > 0 && content != NULL) {
        UCHAR sha[DLP_SHA256_LEN];

        DlpComputeSha256((const UCHAR *)content, contentBytes, sha);

        if (DlpBadHashLookup(sha)) {
            block = TRUE;   /* known-bad, current epoch -> block, no up-call */
        } else {
            NTSTATUS verdictStatus =
                DlpQueryVerdict(&nameInfo->Name, fileId, pid,
                                content, contentBytes, truncated,
                                DLP_REASON_WRITE, &block);
            if (NT_SUCCESS(verdictStatus) && block) {
                DlpBadHashInsert(sha);   /* seed the fast path */
            }
        }
    } else {
        /* Empty file or a failed read: path-only query. On any failure
         * DlpQueryVerdict sets `block` from FailMode. */
        (VOID)DlpQueryVerdict(&nameInfo->Name, fileId, pid,
                              content, contentBytes, truncated,
                              DLP_REASON_WRITE, &block);
    }

    if (content != NULL) {
        ExFreePoolWithTag(content, DLP_GENERAL_TAG);
    }

    if (block) {
        status = DlpQuarantineFile(FltObjects);
        /* The successful FltSendMessage was itself the incident signal; the
         * user-mode client raises the incident from the verdict it computed. */
        UNREFERENCED_PARAMETER(status);
    }

    FltReleaseFileNameInformation(nameInfo);
}


/*++
DlpQuarantineFile -- mark the file for deletion (detect-and-quarantine, v1).
Sets FileDispositionInformation on the current stream so the file is removed
from the media when the handle closes. This is the honest v1 model (SPEC 2.5):
the file briefly existed before deletion; true buffer-and-hold-before-commit is
a documented v2.
--*/
static NTSTATUS
DlpQuarantineFile(_In_ PCFLT_RELATED_OBJECTS FltObjects)
{
    FILE_DISPOSITION_INFORMATION dispInfo;
    dispInfo.DeleteFile = TRUE;

    return FltSetInformationFile(
        FltObjects->Instance,
        FltObjects->FileObject,
        &dispInfo,
        sizeof(dispInfo),
        FileDispositionInformation);
}


/* ========================================================================= *
 *  Item 10 -- known-bad content-hash fast path                              *
 * ========================================================================= */

/*++
Self-contained SHA-256. Kept dependency-free ON PURPOSE: the proven build recipe
links only ntoskrnl / fltMgr / hal / wdmsec, and this driver ships to air-gapped
defence sites where every added link dependency (ksecdd/CNG) is supply-chain and
lifetime surface. This is NOT the service's detection fingerprint -- that math is
untouched. It is a plain SHA-256 over the EXACT bytes we shipped to user-mode,
used only to recognise an identical repeat copy and block it without a second
up-call. Runs at PASSIVE_LEVEL (from DlpInspectStream); no pool, no I/O.
--*/
typedef struct _DLP_SHA256_CTX {
    ULONG     h[8];
    ULONGLONG len;          /* total bytes hashed                            */
    UCHAR     buf[64];      /* partial block                                 */
    ULONG     bufLen;       /* bytes currently in buf                        */
} DLP_SHA256_CTX;

static const ULONG DlpSha256K[64] = {
    0x428a2f98UL, 0x71374491UL, 0xb5c0fbcfUL, 0xe9b5dba5UL,
    0x3956c25bUL, 0x59f111f1UL, 0x923f82a4UL, 0xab1c5ed5UL,
    0xd807aa98UL, 0x12835b01UL, 0x243185beUL, 0x550c7dc3UL,
    0x72be5d74UL, 0x80deb1feUL, 0x9bdc06a7UL, 0xc19bf174UL,
    0xe49b69c1UL, 0xefbe4786UL, 0x0fc19dc6UL, 0x240ca1ccUL,
    0x2de92c6fUL, 0x4a7484aaUL, 0x5cb0a9dcUL, 0x76f988daUL,
    0x983e5152UL, 0xa831c66dUL, 0xb00327c8UL, 0xbf597fc7UL,
    0xc6e00bf3UL, 0xd5a79147UL, 0x06ca6351UL, 0x14292967UL,
    0x27b70a85UL, 0x2e1b2138UL, 0x4d2c6dfcUL, 0x53380d13UL,
    0x650a7354UL, 0x766a0abbUL, 0x81c2c92eUL, 0x92722c85UL,
    0xa2bfe8a1UL, 0xa81a664bUL, 0xc24b8b70UL, 0xc76c51a3UL,
    0xd192e819UL, 0xd6990624UL, 0xf40e3585UL, 0x106aa070UL,
    0x19a4c116UL, 0x1e376c08UL, 0x2748774cUL, 0x34b0bcb5UL,
    0x391c0cb3UL, 0x4ed8aa4aUL, 0x5b9cca4fUL, 0x682e6ff3UL,
    0x748f82eeUL, 0x78a5636fUL, 0x84c87814UL, 0x8cc70208UL,
    0x90befffaUL, 0xa4506cebUL, 0xbef9a3f7UL, 0xc67178f2UL
};

#define DLP_ROR32(x, n)  (((x) >> (n)) | ((x) << (32 - (n))))

static VOID
DlpSha256Block(_Inout_ DLP_SHA256_CTX *c, _In_reads_bytes_(64) const UCHAR *p)
{
    ULONG w[64];
    ULONG a, b, cc, d, e, f, g, hh;
    ULONG i;

    for (i = 0; i < 16; i++) {
        w[i] = ((ULONG)p[i * 4] << 24) | ((ULONG)p[i * 4 + 1] << 16) |
               ((ULONG)p[i * 4 + 2] << 8) | ((ULONG)p[i * 4 + 3]);
    }
    for (i = 16; i < 64; i++) {
        ULONG s0 = DLP_ROR32(w[i - 15], 7) ^ DLP_ROR32(w[i - 15], 18) ^ (w[i - 15] >> 3);
        ULONG s1 = DLP_ROR32(w[i - 2], 17) ^ DLP_ROR32(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = c->h[0]; b = c->h[1]; cc = c->h[2]; d = c->h[3];
    e = c->h[4]; f = c->h[5]; g = c->h[6]; hh = c->h[7];

    for (i = 0; i < 64; i++) {
        ULONG S1 = DLP_ROR32(e, 6) ^ DLP_ROR32(e, 11) ^ DLP_ROR32(e, 25);
        ULONG ch = (e & f) ^ ((~e) & g);
        ULONG t1 = hh + S1 + ch + DlpSha256K[i] + w[i];
        ULONG S0 = DLP_ROR32(a, 2) ^ DLP_ROR32(a, 13) ^ DLP_ROR32(a, 22);
        ULONG maj = (a & b) ^ (a & cc) ^ (b & cc);
        ULONG t2 = S0 + maj;
        hh = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }

    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += hh;
}

static VOID
DlpSha256Init(_Out_ DLP_SHA256_CTX *c)
{
    c->h[0] = 0x6a09e667UL; c->h[1] = 0xbb67ae85UL;
    c->h[2] = 0x3c6ef372UL; c->h[3] = 0xa54ff53aUL;
    c->h[4] = 0x510e527fUL; c->h[5] = 0x9b05688cUL;
    c->h[6] = 0x1f83d9abUL; c->h[7] = 0x5be0cd19UL;
    c->len = 0;
    c->bufLen = 0;
}

static VOID
DlpSha256Update(_Inout_ DLP_SHA256_CTX *c,
                _In_reads_bytes_(len) const UCHAR *data, _In_ ULONG len)
{
    ULONG off = 0;

    c->len += len;

    if (c->bufLen > 0) {
        while (c->bufLen < 64 && off < len) {
            c->buf[c->bufLen++] = data[off++];
        }
        if (c->bufLen == 64) {
            DlpSha256Block(c, c->buf);
            c->bufLen = 0;
        }
    }
    while (off + 64 <= len) {
        DlpSha256Block(c, data + off);
        off += 64;
    }
    /* Buffer the tail (< 64 bytes). bufLen is 0 here (or off==len), so the
     * explicit `bufLen < 64` guard is always satisfied; it is present so the
     * analyzer can prove the buf[] write stays in bounds. */
    while (off < len && c->bufLen < 64) {
        c->buf[c->bufLen++] = data[off++];
    }
}

static VOID
DlpSha256Final(_Inout_ DLP_SHA256_CTX *c, _Out_writes_(DLP_SHA256_LEN) UCHAR *out)
{
    ULONGLONG bitLen = c->len * 8ULL;
    ULONG i;
    ULONG n = c->bufLen;

    /* Update always leaves bufLen in [0,63]; clamp explicitly so the analyzer
     * (and defence-in-depth) can see every buf[] index below stays < 64. */
    if (n >= 64) {
        n = 63;
    }

    /* Append 0x80 then zero-pad to 56 mod 64. */
    c->buf[n++] = 0x80;
    if (n > 56) {
        while (n < 64) {
            c->buf[n++] = 0;
        }
        DlpSha256Block(c, c->buf);
        n = 0;
    }
    while (n < 56) {
        c->buf[n++] = 0;
    }
    /* 64-bit big-endian message length in bits. */
    for (i = 0; i < 8; i++) {
        c->buf[56 + i] = (UCHAR)((bitLen >> (56 - i * 8)) & 0xFF);
    }
    DlpSha256Block(c, c->buf);

    for (i = 0; i < 8; i++) {
        out[i * 4]     = (UCHAR)((c->h[i] >> 24) & 0xFF);
        out[i * 4 + 1] = (UCHAR)((c->h[i] >> 16) & 0xFF);
        out[i * 4 + 2] = (UCHAR)((c->h[i] >> 8) & 0xFF);
        out[i * 4 + 3] = (UCHAR)(c->h[i] & 0xFF);
    }
}

static VOID
DlpComputeSha256(_In_reads_bytes_(Len) const UCHAR *Data, _In_ ULONG Len,
                 _Out_writes_(DLP_SHA256_LEN) UCHAR *Out)
{
    DLP_SHA256_CTX c;
    DlpSha256Init(&c);
    DlpSha256Update(&c, Data, Len);
    DlpSha256Final(&c, Out);
}

/*++
DlpBadHashLookup / DlpBadHashInsert -- the bounded known-bad ring (item 10).

Spinlock-guarded (KSPIN_LOCK: valid at <= DISPATCH_LEVEL; callers are at
PASSIVE). Every entry is stamped with the Epoch it was inserted under; an entry
whose Epoch != the current gDlpData.Epoch is treated as absent, so an agent
reconnect (which bumps the epoch, item 4) implicitly clears the whole table
without walking it. Insert dedups within the current epoch and evicts oldest via
the BadHashNext ring cursor (bounded at DLP_BADHASH_MAX).
--*/
static BOOLEAN
DlpBadHashLookup(_In_reads_(DLP_SHA256_LEN) const UCHAR *Sha)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    LONG epoch = InterlockedCompareExchange(&gDlpData.Epoch, 0, 0);
    ULONG i;

    KeAcquireSpinLock(&gDlpData.BadHashLock, &oldIrql);
    for (i = 0; i < DLP_BADHASH_MAX; i++) {
        if (gDlpData.BadHash[i].Valid &&
            gDlpData.BadHash[i].Epoch == epoch &&
            RtlCompareMemory(gDlpData.BadHash[i].Sha, Sha, DLP_SHA256_LEN) ==
                DLP_SHA256_LEN) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&gDlpData.BadHashLock, oldIrql);
    return found;
}

static VOID
DlpBadHashInsert(_In_reads_(DLP_SHA256_LEN) const UCHAR *Sha)
{
    KIRQL oldIrql;
    LONG epoch = InterlockedCompareExchange(&gDlpData.Epoch, 0, 0);
    LONG slot;
    ULONG i;

    KeAcquireSpinLock(&gDlpData.BadHashLock, &oldIrql);

    /* Dedup within the current epoch. */
    for (i = 0; i < DLP_BADHASH_MAX; i++) {
        if (gDlpData.BadHash[i].Valid &&
            gDlpData.BadHash[i].Epoch == epoch &&
            RtlCompareMemory(gDlpData.BadHash[i].Sha, Sha, DLP_SHA256_LEN) ==
                DLP_SHA256_LEN) {
            KeReleaseSpinLock(&gDlpData.BadHashLock, oldIrql);
            return;
        }
    }

    slot = gDlpData.BadHashNext;
    if (slot < 0 || slot >= DLP_BADHASH_MAX) {
        slot = 0;
    }
    RtlCopyMemory(gDlpData.BadHash[slot].Sha, Sha, DLP_SHA256_LEN);
    gDlpData.BadHash[slot].Epoch = epoch;
    gDlpData.BadHash[slot].Valid = TRUE;
    gDlpData.BadHashNext = (slot + 1) % DLP_BADHASH_MAX;

    KeReleaseSpinLock(&gDlpData.BadHashLock, oldIrql);
}


/* ========================================================================= *
 *  Item 11 -- kernel tamper protection via ObRegisterCallbacks              *
 * ========================================================================= */

/* Rights stripped from any NON-agent, non-System handle opened to the agent
 * process. Without PROCESS_TERMINATE a caller cannot kill usb-guard; without
 * PROCESS_VM_WRITE / PROCESS_VM_OPERATION it cannot inject or patch it. */
#ifndef PROCESS_TERMINATE
#define PROCESS_TERMINATE     0x0001
#endif
#ifndef PROCESS_VM_OPERATION
#define PROCESS_VM_OPERATION  0x0008
#endif
#ifndef PROCESS_VM_WRITE
#define PROCESS_VM_WRITE      0x0020
#endif
#define DLP_TAMPER_STRIP_MASK \
    (PROCESS_TERMINATE | PROCESS_VM_OPERATION | PROCESS_VM_WRITE)

/*++
Pre-operation callback on PsProcessType handle opens/duplicates. When a
requestor that is NOT the agent itself, System, or a kernel-mode opener tries to
open a handle to the connected agent PID, strip the terminate/inject rights.
This is the "cannot be switched off from user-mode" guarantee -- strictly
stronger than the old driver's user-mode tamper_monitor.py, because a user-mode
attacker (even an administrator) can no longer obtain a killable handle to the
agent. AgentPid==0 (no agent connected) short-circuits: no protection, no cost.

Runs at IRQL <= APC_LEVEL in the opener's context; does no pool/I/O and takes no
locks -- just a couple of interlocked reads and an in-place mask edit.
--*/
static OB_PREOP_CALLBACK_STATUS
DlpObPreCallback(_In_ PVOID RegistrationContext,
                 _Inout_ POB_PRE_OPERATION_INFORMATION Info)
{
    LONG agentPid;
    LONG targetPid;
    LONG requestorPid;
    PACCESS_MASK desired;

    UNREFERENCED_PARAMETER(RegistrationContext);

    /* Only process-object opens are registered; guard defensively. */
    if (Info->ObjectType != *PsProcessType) {
        return OB_PREOP_SUCCESS;
    }
    /* Never touch kernel-mode handle opens (drivers, the system itself). */
    if (Info->KernelHandle) {
        return OB_PREOP_SUCCESS;
    }

    agentPid = InterlockedCompareExchange(&gDlpData.ServicePid, 0, 0);
    if (agentPid == 0) {
        return OB_PREOP_SUCCESS;   /* no agent connected -> no protection */
    }

    targetPid = (LONG)(ULONG_PTR)PsGetProcessId((PEPROCESS)Info->Object);
    if (targetPid != agentPid) {
        return OB_PREOP_SUCCESS;   /* not a handle to the agent -> leave alone */
    }

    /* The agent operating on itself, or System, keeps full access. */
    requestorPid = (LONG)(ULONG_PTR)PsGetCurrentProcessId();
    if (requestorPid == agentPid || requestorPid == DLP_SYSTEM_PID) {
        return OB_PREOP_SUCCESS;
    }

    /* Any other requestor: strip the kill/inject rights in place. */
    if (Info->Operation == OB_OPERATION_HANDLE_CREATE) {
        desired = &Info->Parameters->CreateHandleInformation.DesiredAccess;
    } else if (Info->Operation == OB_OPERATION_HANDLE_DUPLICATE) {
        desired = &Info->Parameters->DuplicateHandleInformation.DesiredAccess;
    } else {
        return OB_PREOP_SUCCESS;
    }
    *desired &= ~((ACCESS_MASK)DLP_TAMPER_STRIP_MASK);

    return OB_PREOP_SUCCESS;
}

static NTSTATUS
DlpRegisterObCallbacks(VOID)
{
    OB_OPERATION_REGISTRATION opReg;
    OB_CALLBACK_REGISTRATION cbReg;
    UNICODE_STRING altitude;

    RtlZeroMemory(&opReg, sizeof(opReg));
    opReg.ObjectType = PsProcessType;
    opReg.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
    opReg.PreOperation = DlpObPreCallback;
    opReg.PostOperation = NULL;

    /* Activity-monitor altitude range (matches the filter's family). */
    RtlInitUnicodeString(&altitude, L"320700");

    RtlZeroMemory(&cbReg, sizeof(cbReg));
    cbReg.Version = OB_FLT_REGISTRATION_VERSION;
    cbReg.OperationRegistrationCount = 1;
    cbReg.Altitude = altitude;
    cbReg.RegistrationContext = NULL;
    cbReg.OperationRegistration = &opReg;

    /* Requires the image be linked /INTEGRITYCHECK and signed; otherwise this
     * returns STATUS_ACCESS_DENIED at runtime (a fail-secure DriverEntry
     * abort). Compiles + analyzes here; the load-time check is the operator's
     * test-signed VM. */
    return ObRegisterCallbacks(&cbReg, &gDlpData.ObCallbackHandle);
}

static VOID
DlpUnregisterObCallbacks(VOID)
{
    if (gDlpData.ObCallbackHandle != NULL) {
        ObUnRegisterCallbacks(gDlpData.ObCallbackHandle);
        gDlpData.ObCallbackHandle = NULL;
    }
}


/* ========================================================================= *
 *  Read-taint -- shared in-kernel stream read (LLD §3 step 2)               *
 *                                                                           *
 *  Factored out of the write path so DlpInspectStream (CLEANUP) and the     *
 *  async scan worker read the stream IDENTICALLY: offset 0 .. min(EOF,      *
 *  DLP_MAX_CONTENT) into a fresh NonPagedPoolNx buffer the caller frees with *
 *  DLP_GENERAL_TAG. PASSIVE_LEVEL only (FltReadFile waits). On any failure   *
 *  the caller fails-safe (write path ships no content; worker adds NO taint).*
 * ------------------------------------------------------------------------- */
static NTSTATUS
DlpReadStreamContent(_In_ PFLT_INSTANCE Instance,
                     _In_ PFILE_OBJECT FileObject,
                     _Outptr_result_maybenull_ PVOID *Buffer,
                     _Out_ PULONG Length,
                     _Out_ PBOOLEAN Truncated)
{
    NTSTATUS status;
    FILE_STANDARD_INFORMATION stdInfo;
    ULONGLONG fileSize;
    ULONG readLen;
    PVOID buf = NULL;
    ULONG bytesRead = 0;
    LARGE_INTEGER offset;

    *Buffer = NULL;
    *Length = 0;
    *Truncated = FALSE;

    /* Stream size. A failed query fails-safe (no content). */
    RtlZeroMemory(&stdInfo, sizeof(stdInfo));
    status = FltQueryInformationFile(Instance, FileObject, &stdInfo,
                                     sizeof(stdInfo), FileStandardInformation,
                                     NULL);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    /* Empty file: no content, but NOT an error (the service scores what it gets;
     * the worker treats "no content" as no taint). */
    if (stdInfo.EndOfFile.QuadPart <= 0) {
        return STATUS_SUCCESS;
    }
    fileSize = (ULONGLONG)stdInfo.EndOfFile.QuadPart;

    if (fileSize > DLP_MAX_CONTENT) {
        readLen = DLP_MAX_CONTENT;
        *Truncated = TRUE;                 /* flagged so the service fail-safes */
    } else {
        readLen = (ULONG)fileSize;
    }

    /* ExAllocatePool2 is unavailable at this NTDDI baseline (the proven build
     * pins the Win10 base); ExAllocatePoolWithTag(NonPagedPoolNx) is the correct
     * tagged non-paged alloc. Suppress only the C4996 nudge (matches comms.c). */
#pragma warning(suppress: 4996)
    buf = ExAllocatePoolWithTag(NonPagedPoolNx, readLen, DLP_GENERAL_TAG);
    if (buf == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    /* Cached read from inside the FS stack (offset 0). Do not disturb the file
     * object's byte offset. Cached (not NON_CACHED) so there is no sector-align
     * constraint on an arbitrary file length. */
    offset.QuadPart = 0;
    status = FltReadFile(Instance, FileObject, &offset, readLen, buf,
                         FLTFL_IO_OPERATION_DO_NOT_UPDATE_BYTE_OFFSET,
                         &bytesRead, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(buf, DLP_GENERAL_TAG);
        return status;                     /* no leak on the error path */
    }

    *Buffer = buf;
    *Length = bytesRead;
    return STATUS_SUCCESS;
}


/* ========================================================================= *
 *  Read-taint -- taint table (LLD §4; mirrors the BadHash ring exactly)     *
 *                                                                           *
 *  One dedicated KSPIN_LOCK (gDlpData.TaintLock), TaintEpoch-stamped so an   *
 *  admin "reset taint" (epoch bump) implicitly clears the table with no walk,*
 *  ring cursor for capacity eviction, PID 0 == empty-slot sentinel. Only     *
 *  DlpTaintLookup runs at <= DISPATCH (the WFP callout); the mutators run at  *
 *  PASSIVE (worker / process-notify). No pool (static array).               *
 * ------------------------------------------------------------------------- */

BOOLEAN
DlpTaintLookup(_In_ ULONG Pid)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    LONG taintEpoch;
    ULONG i;

    /* PID 0 is the empty-slot sentinel -- never a match (mirrors the Rust
     * select_pid_rows "PID 0 never matches" invariant). */
    if (Pid == 0) {
        return FALSE;
    }

    taintEpoch = InterlockedCompareExchange(&gDlpData.TaintEpoch, 0, 0);

    /* KSPIN_LOCK is valid at <= DISPATCH; this is the ONLY taint fn the WFP
     * classifyFn calls, and it neither allocates, waits, nor does I/O. */
    KeAcquireSpinLock(&gDlpData.TaintLock, &oldIrql);
    for (i = 0; i < DLP_TAINT_MAX; i++) {
        if (gDlpData.Taint[i].Valid &&
            gDlpData.Taint[i].TaintEpoch == taintEpoch &&
            (ULONG)gDlpData.Taint[i].Pid == Pid) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&gDlpData.TaintLock, oldIrql);
    return found;
}

VOID
DlpTaintAdd(_In_ ULONG Pid)
{
    KIRQL oldIrql;
    LONG taintEpoch;
    ULONGLONG createTime = 0;
    PEPROCESS proc = NULL;
    LONG slot = -1;
    ULONG i;

    if (Pid == 0) {
        return;                            /* never taint the sentinel PID */
    }

    /* PID-reuse guard: capture the target process's create time BEFORE taking the
     * spinlock (PsLookupProcessByProcessId / PsGetProcessCreateTimeQuadPart are
     * PASSIVE-level, must NOT run under a spinlock). A failed lookup (the PID
     * already exited) leaves createTime 0 -- it is advisory: taint MATCHING keys
     * only on Pid + TaintEpoch, so the create time is a stored disambiguator for
     * a recycled PID, never consulted in the DISPATCH-level lookup. */
    if (NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)(ULONG_PTR)Pid, &proc))) {
        createTime = (ULONGLONG)PsGetProcessCreateTimeQuadPart(proc);
        ObDereferenceObject(proc);
    }

    taintEpoch = InterlockedCompareExchange(&gDlpData.TaintEpoch, 0, 0);

    KeAcquireSpinLock(&gDlpData.TaintLock, &oldIrql);

    /* Dedup within the current epoch (do not double-count a PID). */
    for (i = 0; i < DLP_TAINT_MAX; i++) {
        if (gDlpData.Taint[i].Valid &&
            gDlpData.Taint[i].TaintEpoch == taintEpoch &&
            (ULONG)gDlpData.Taint[i].Pid == Pid) {
            KeReleaseSpinLock(&gDlpData.TaintLock, oldIrql);
            return;
        }
    }

    /* Prefer a genuinely free slot; grow the live count when we take one. */
    for (i = 0; i < DLP_TAINT_MAX; i++) {
        if (!gDlpData.Taint[i].Valid) {
            slot = (LONG)i;
            break;
        }
    }
    if (slot < 0) {
        /* Table full: evict the oldest via the ring cursor (net count unchanged
         * -- we overwrite an occupied slot). A real deployment will not hold 1024
         * concurrently-tainted PIDs; an evicted PID falls back to the user-mode
         * default-deny allow-list (fail-safe). */
        slot = gDlpData.TaintNext;
        if (slot < 0 || slot >= DLP_TAINT_MAX) {
            slot = 0;
        }
        gDlpData.TaintNext = (slot + 1) % DLP_TAINT_MAX;
    } else if (gDlpData.TaintCount < DLP_TAINT_MAX) {
        InterlockedIncrement(&gDlpData.TaintCount);   /* saturating */
    }

    gDlpData.Taint[slot].Pid = (LONG)Pid;
    gDlpData.Taint[slot].TaintEpoch = taintEpoch;
    gDlpData.Taint[slot].CreateTime = createTime;
    gDlpData.Taint[slot].Valid = TRUE;

    KeReleaseSpinLock(&gDlpData.TaintLock, oldIrql);
}

VOID
DlpTaintRemove(_In_ ULONG Pid)
{
    KIRQL oldIrql;
    ULONG i;

    if (Pid == 0) {
        return;
    }

    KeAcquireSpinLock(&gDlpData.TaintLock, &oldIrql);
    /* Clear EVERY slot holding this PID (a PID can occupy a current-epoch slot
     * plus a stale-epoch duplicate after an admin reset); decrement the live
     * count for each. Process exit removes the PID from all epochs at once. */
    for (i = 0; i < DLP_TAINT_MAX; i++) {
        if (gDlpData.Taint[i].Valid && (ULONG)gDlpData.Taint[i].Pid == Pid) {
            gDlpData.Taint[i].Valid = FALSE;
            gDlpData.Taint[i].Pid = 0;
            gDlpData.Taint[i].CreateTime = 0;
            if (gDlpData.TaintCount > 0) {
                InterlockedDecrement(&gDlpData.TaintCount);
            }
        }
    }
    KeReleaseSpinLock(&gDlpData.TaintLock, oldIrql);
}

VOID
DlpTaintResetAll(VOID)
{
    /* Admin "reset taint": bump the epoch ONLY (implicit clear, like the badhash
     * epoch). NOT called on agent reconnect -- taint deliberately persists across
     * an agent restart (HLD §6). Left as an unwired admin hook by design. */
    InterlockedIncrement(&gDlpData.TaintEpoch);
}


/* ========================================================================= *
 *  Read-deny -- exfil-PID set (read-deny-LLD §2). Mirrors the taint ring:    *
 *  KSPIN_LOCK, epoch stamp, full-replace bumps the epoch. DlpExfilLookup runs *
 *  on the read hot path (DlpPreRead, PASSIVE) under the lock; DlpExfilReplace *
 *  applies the agent-pushed full set; DlpExfilRemove drops an exited PID.    *
 * ------------------------------------------------------------------------- */

BOOLEAN
DlpExfilLookup(_In_ ULONG Pid)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    LONG epoch;
    ULONG i;

    if (Pid == 0) {
        return FALSE;                      /* PID 0 is never an exfil channel   */
    }

    KeAcquireSpinLock(&gDlpData.ExfilLock, &oldIrql);
    epoch = gDlpData.ExfilEpoch;
    for (i = 0; i < DLP_EXFIL_MAX; i++) {
        if (gDlpData.Exfil[i].Valid &&
            gDlpData.Exfil[i].Epoch == epoch &&
            (ULONG)gDlpData.Exfil[i].Pid == Pid) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&gDlpData.ExfilLock, oldIrql);
    return found;
}

VOID
DlpExfilReplace(_In_reads_(Count) const ULONG *Pids, _In_ ULONG Count)
{
    KIRQL oldIrql;
    LONG epoch;
    ULONG i;
    ULONG n = Count;

    if (n > DLP_EXFIL_MAX) {
        n = DLP_EXFIL_MAX;                 /* bounded; excess dropped (agent caps too) */
    }

    KeAcquireSpinLock(&gDlpData.ExfilLock, &oldIrql);
    /* New generation: bump the epoch so any residual old entry reads as absent,
     * then overwrite the table with the new full set. */
    epoch = InterlockedIncrement(&gDlpData.ExfilEpoch);
    for (i = 0; i < DLP_EXFIL_MAX; i++) {
        if (i < n && Pids != NULL && Pids[i] != 0) {
            gDlpData.Exfil[i].Pid = (LONG)Pids[i];
            gDlpData.Exfil[i].Epoch = epoch;
            gDlpData.Exfil[i].Valid = TRUE;
        } else {
            gDlpData.Exfil[i].Pid = 0;
            gDlpData.Exfil[i].Valid = FALSE;
        }
    }
    gDlpData.ExfilCount = (LONG)n;
    KeReleaseSpinLock(&gDlpData.ExfilLock, oldIrql);
}

VOID
DlpExfilRemove(_In_ ULONG Pid)
{
    KIRQL oldIrql;
    ULONG i;

    if (Pid == 0) {
        return;
    }

    KeAcquireSpinLock(&gDlpData.ExfilLock, &oldIrql);
    for (i = 0; i < DLP_EXFIL_MAX; i++) {
        if (gDlpData.Exfil[i].Valid && (ULONG)gDlpData.Exfil[i].Pid == Pid) {
            gDlpData.Exfil[i].Pid = 0;
            gDlpData.Exfil[i].Valid = FALSE;
        }
    }
    KeReleaseSpinLock(&gDlpData.ExfilLock, oldIrql);
}


/* ========================================================================= *
 *  Read-deny -- DlpPreRead (IRP_MJ_READ pre-op, read-deny-LLD §4)            *
 *                                                                           *
 *  Denies a read ONLY when (requestor is an exfil channel) AND (content is   *
 *  sensitive) AND (file is in scope). All expensive work is gated behind      *
 *  DlpShouldSkip (PASSIVE, no re-entrancy) and the exfil-set lookup, so an    *
 *  ordinary process's reads exit after one spinlocked scan.                  *
 *                                                                           *
 *  RETURN CONTRACT: every allow/skip path returns SUCCESS_WITH_CALLBACK so   *
 *  the paired post-op (DlpPostRead / read-taint) still runs; only a deny      *
 *  returns FLT_PREOP_COMPLETE with STATUS_ACCESS_DENIED.                     *
 * ------------------------------------------------------------------------- */

/* Complete the read as denied (the tool's ReadFile fails -> its transfer aborts). */
static FLT_PREOP_CALLBACK_STATUS
DlpDenyRead(_Inout_ PFLT_CALLBACK_DATA Data)
{
    Data->IoStatus.Status = STATUS_ACCESS_DENIED;
    Data->IoStatus.Information = 0;
    return FLT_PREOP_COMPLETE;
}

/* TEMP-DIAGNOSTIC: case-insensitive ASCII substring test on a UNICODE_STRING. */
static BOOLEAN
DlpNameHas(_In_ PCUNICODE_STRING Name, _In_ PCWSTR Sub)
{
    USHORT nLen = (USHORT)(Name->Length / sizeof(WCHAR));
    USHORT sLen = 0, i, j;
    while (Sub[sLen] != 0) { sLen++; }
    if (sLen == 0 || nLen < sLen || Name->Buffer == NULL) { return FALSE; }
    for (i = 0; (USHORT)(i + sLen) <= nLen; i++) {
        for (j = 0; j < sLen; j++) {
            WCHAR a = Name->Buffer[i + j], b = Sub[j];
            if (a >= L'A' && a <= L'Z') a = (WCHAR)(a + 32);
            if (b >= L'A' && b <= L'Z') b = (WCHAR)(b + 32);
            if (a != b) { break; }
        }
        if (j == sLen) { return TRUE; }
    }
    return FALSE;
}

/* TEMP-DIAGNOSTIC: if this operation targets OPORD, resolve its name and return
 * TRUE (caller then records the access). Safe at PASSIVE. */
static BOOLEAN
DlpIsOpord(_Inout_ PFLT_CALLBACK_DATA Data)
{
    PFLT_FILE_NAME_INFORMATION ni = NULL;
    BOOLEAN hit = FALSE;
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) { return FALSE; }
    if (NT_SUCCESS(FltGetFileNameInformation(
            Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &ni)) &&
        ni != NULL) {
        (VOID)FltParseFileNameInformation(ni);
        hit = DlpNameHas(&ni->Name, L"OPORD");
        FltReleaseFileNameInformation(ni);
    }
    return hit;
}

/* Shared read-deny classifier. Returns DLP_EXFIL_DENY or DLP_EXFIL_ALLOW and
 * caches the verdict in the stream context + the cross-open SensFile/CleanFile
 * rings so neither the buffered pre-op nor the section-sync pre-op re-reads. The
 * only content read here (DlpReadStreamContent) is a cached FltReadFile that
 * lazily creates the file's data section -- guarded by DlpClassifyEnter so the
 * re-entrant DlpPreAcquireForSection on THIS thread waves that section through.
 * PASSIVE. Caller has confirmed: read-deny enabled, !DlpShouldSkip, exfil PID. */
static LONG
DlpExfilClassifyAndCache(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                         _Inout_ PFLT_CALLBACK_DATA Data,
                         _In_ ULONG Pid)
{
    NTSTATUS status;
    PDLP_STREAM_CONTEXT ctx = NULL;
    PDLP_INSTANCE_CONTEXT instCtx = NULL;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    ULONG volumeClass = DLP_VOL_REMOVABLE;   /* fallback: inspect-all           */
    LONG cached;
    ULONGLONG fileId = 0;
    PVOID content = NULL;
    ULONG contentBytes = 0;
    BOOLEAN truncated = FALSE;
    BOOLEAN block = FALSE;
    BOOLEAN guardHeld;
    UCHAR sha[DLP_SHA256_LEN];

    /* A. Get/attach the cross-open verdict cache (stream context). */
    status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject,
                                 (PFLT_CONTEXT *)&ctx);
    if (!NT_SUCCESS(status)) {
        status = FltAllocateContext(gDlpData.Filter, FLT_STREAM_CONTEXT,
                                    sizeof(DLP_STREAM_CONTEXT), NonPagedPoolNx,
                                    (PFLT_CONTEXT *)&ctx);
        if (!NT_SUCCESS(status)) {
            return gDlpData.ExfilReadFailBlock ? DLP_EXFIL_DENY : DLP_EXFIL_ALLOW;
        }
        ctx->WriteCandidate = 0;
        ctx->Dirty = 0;
        ctx->Inspected = 0;
        ctx->Epoch = InterlockedCompareExchange(&gDlpData.Epoch, 0, 0);
        ctx->ReadScanState = 0;
        ctx->ExfilVerdict = DLP_EXFIL_UNKNOWN;
        status = FltSetStreamContext(FltObjects->Instance, FltObjects->FileObject,
                                     FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                     (PFLT_CONTEXT)ctx, NULL);
        if (!NT_SUCCESS(status)) {
            /* Another thread attached first; adopt the existing context. */
            FltReleaseContext((PFLT_CONTEXT)ctx);
            ctx = NULL;
            if (!NT_SUCCESS(FltGetStreamContext(FltObjects->Instance,
                    FltObjects->FileObject, (PFLT_CONTEXT *)&ctx)) || ctx == NULL) {
                return gDlpData.ExfilReadFailBlock ? DLP_EXFIL_DENY : DLP_EXFIL_ALLOW;
            }
        }
    }

    /* B. Verdict already decided for this file (any prior open)? O(1). */
    cached = InterlockedCompareExchange(&ctx->ExfilVerdict, 0, 0);
    if (cached == DLP_EXFIL_DENY || cached == DLP_EXFIL_ALLOW) {
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return cached;
    }

    /* C. Scope: fixed volumes only under a watch prefix; removable/network all.
     *    A failed name query cannot be scoped -> allow (never break an unrelated
     *    read on a name failure); cache allow. */
    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        InterlockedExchange(&ctx->ExfilVerdict, DLP_EXFIL_ALLOW);
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return DLP_EXFIL_ALLOW;
    }
    (VOID)FltParseFileNameInformation(nameInfo);

    if (NT_SUCCESS(FltGetInstanceContext(FltObjects->Instance,
                                         (PFLT_CONTEXT *)&instCtx)) &&
        instCtx != NULL) {
        volumeClass = instCtx->VolumeClass;
        FltReleaseContext((PFLT_CONTEXT)instCtx);
    }
    if (volumeClass == DLP_VOL_FIXED &&
        !DlpConfigPathIsWatched(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        InterlockedExchange(&ctx->ExfilVerdict, DLP_EXFIL_ALLOW);   /* out of scope */
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return DLP_EXFIL_ALLOW;
    }

    /* D. Cross-open file-id caches (one FileInternalInformation query, reused for
     *    both lookups and any later seed): known sensitive -> deny; known clean ->
     *    allow. Neither reads content nor up-calls. */
    {
        FILE_INTERNAL_INFORMATION intInfo;
        RtlZeroMemory(&intInfo, sizeof(intInfo));
        if (NT_SUCCESS(FltQueryInformationFile(FltObjects->Instance,
                FltObjects->FileObject, &intInfo, sizeof(intInfo),
                FileInternalInformation, NULL))) {
            fileId = (ULONGLONG)intInfo.IndexNumber.QuadPart;
        }
    }
    if (fileId != 0 && DlpSensFileLookup(fileId, 0)) {
        InterlockedExchange(&ctx->ExfilVerdict, DLP_EXFIL_DENY);
        FltReleaseFileNameInformation(nameInfo);
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return DLP_EXFIL_DENY;
    }
    if (fileId != 0 && DlpCleanFileLookup(fileId, 0)) {
        InterlockedExchange(&ctx->ExfilVerdict, DLP_EXFIL_ALLOW);
        FltReleaseFileNameInformation(nameInfo);
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return DLP_EXFIL_ALLOW;
    }

    /* E. SYNCHRONOUS classify (first time this file is seen by an exfil PID under
     *    the current content epoch): read content in-kernel, known-bad hash, up-
     *    call. Guarded so the cached read's own data-section creation re-enters
     *    DlpPreAcquireForSection on this thread and is waved through. */
    guardHeld = DlpClassifyEnter();
    status = DlpReadStreamContent(FltObjects->Instance, FltObjects->FileObject,
                                  &content, &contentBytes, &truncated);
    if (guardHeld) {
        DlpClassifyExit();
    }
    if (!NT_SUCCESS(status) || content == NULL || contentBytes == 0) {
        if (content != NULL) {
            ExFreePoolWithTag(content, DLP_GENERAL_TAG);
        }
        FltReleaseFileNameInformation(nameInfo);
        /* Unverifiable content read by an exfil tool -> fail-safe. Do NOT seed the
         * cross-open rings on a transient failure; only cache per-file (stream ctx). */
        if (gDlpData.ExfilReadFailBlock) {
            InterlockedExchange(&ctx->ExfilVerdict, DLP_EXFIL_DENY);
            FltReleaseContext((PFLT_CONTEXT)ctx);
            return DLP_EXFIL_DENY;
        }
        InterlockedExchange(&ctx->ExfilVerdict, DLP_EXFIL_ALLOW);
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return DLP_EXFIL_ALLOW;
    }

    DlpComputeSha256((const UCHAR *)content, contentBytes, sha);
    if (DlpBadHashLookup(sha)) {
        block = TRUE;                          /* known-bad content -> deny       */
    } else {
        NTSTATUS vstatus =
            DlpQueryVerdict(&nameInfo->Name, fileId, Pid, content, contentBytes,
                            truncated, DLP_REASON_READ, &block);
        /* ONLY an exact STATUS_SUCCESS is a genuine verdict. STATUS_TIMEOUT (and
         * other IPC failures) are NT_SUCCESS-*severity* codes but mean "no verdict"
         * -- treating them as a real BLOCK would deny every read under agent load
         * AND poison the SensFile cache. On any non-SUCCESS, fail-safe per
         * ExfilReadFailBlock and seed NOTHING. */
        if (vstatus == STATUS_SUCCESS) {
            /* Genuine verdict -> seed the matching cross-open cache. */
            if (block) {
                DlpBadHashInsert(sha);         /* seed the fast path              */
                DlpSensFileInsert(fileId, 0);
            } else {
                DlpCleanFileInsert(fileId, 0); /* bound future up-calls           */
            }
        } else {
            /* Up-call failed (no client / timeout). Fail-safe; no cross-open seed. */
            block = (gDlpData.ExfilReadFailBlock != 0);
        }
    }

    ExFreePoolWithTag(content, DLP_GENERAL_TAG);
    FltReleaseFileNameInformation(nameInfo);

    if (block) {
        InterlockedExchange(&ctx->ExfilVerdict, DLP_EXFIL_DENY);
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return DLP_EXFIL_DENY;
    }
    InterlockedExchange(&ctx->ExfilVerdict, DLP_EXFIL_ALLOW);
    FltReleaseContext((PFLT_CONTEXT)ctx);
    return DLP_EXFIL_ALLOW;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI
DlpPreRead(_Inout_ PFLT_CALLBACK_DATA Data,
           _In_ PCFLT_RELATED_OBJECTS FltObjects,
           _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    ULONG pid;
    LONG verdict;

    *CompletionContext = NULL;

    /* 1. Kill-switch (default OFF). Still WITH_CALLBACK so read-taint's post-op runs. */
    if (gDlpData.ExfilReadBlockEnabled != DLP_EXFILREAD_ENABLED) {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    /* TEMP-DIAGNOSTIC: record every OPORD read (pid, exfil, would-skip). */
    if (KeGetCurrentIrql() == PASSIVE_LEVEL && DlpIsOpord(Data)) {
        ULONG p = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
        DlpTraceRd(p, DlpExfilLookup(p) ? 1u : 0u,
                   DlpShouldSkip(Data, FltObjects) ? 1u : 0u);
    }
    /* 2. Top-of-callback gate: PASSIVE + no re-entrancy + skip agent/System. */
    if (DlpShouldSkip(Data, FltObjects)) {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    /* 3. Only exfil-channel PIDs are subject to read-deny -- the common case
     *    (ordinary app) exits here after ONE spinlocked scan. */
    pid = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
    if (!DlpExfilLookup(pid)) {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }
    /* 4. Zero-length read: nothing to gate. */
    if (Data->Iopb->Parameters.Read.Length == 0) {
        return FLT_PREOP_SUCCESS_WITH_CALLBACK;
    }

    /* 5. Classify (cache-first; reads + up-calls at most once per file/epoch).
     *    DlpDenyRead completes the buffered read as STATUS_ACCESS_DENIED; every
     *    allow path returns WITH_CALLBACK so read-taint's post-op still runs. */
    verdict = DlpExfilClassifyAndCache(FltObjects, Data, pid);
    if (verdict == DLP_EXFIL_DENY) {
        return DlpDenyRead(Data);
    }
    return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}


/* ------------------------------------------------------------------------- *
 *  DlpPreAcquireForSection (IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, pre) *
 *                                                                           *
 *  The MAPPED-read half of read-deny. When an exfil PID creates a data       *
 *  section over a file, the ensuing reads are page faults (paging I/O) that   *
 *  never reach DlpPreRead -- so we block the SECTION here. This callback is   *
 *  cache-only: the verdict was seeded synchronously at DlpPostCreate (a safe  *
 *  point to read), so we never read or up-call on the delicate section path.  *
 * ------------------------------------------------------------------------- */
FLT_PREOP_CALLBACK_STATUS FLTAPI
DlpPreAcquireForSection(_Inout_ PFLT_CALLBACK_DATA Data,
                        _In_ PCFLT_RELATED_OBJECTS FltObjects,
                        _Flt_CompletionContext_Outptr_ PVOID *CompletionContext)
{
    ULONG pid;
    LONG verdict = DLP_EXFIL_UNKNOWN;
    PDLP_STREAM_CONTEXT ctx = NULL;
    ULONGLONG fileId = 0;

    *CompletionContext = NULL;

    /* 1. Kill-switch. */
    if (gDlpData.ExfilReadBlockEnabled != DLP_EXFILREAD_ENABLED) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    /* TEMP-DIAGNOSTIC: record every OPORD section-sync (pid, exfil, sync type).
     * SyncType: 0 = SyncTypeOther, 1 = SyncTypeCreateSection. */
    if (KeGetCurrentIrql() == PASSIVE_LEVEL &&
        FltObjects->FileObject != NULL && DlpIsOpord(Data)) {
        ULONG p = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
        DlpTraceSec(p, DlpExfilLookup(p) ? 1u : 0u,
                    (ULONG)Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType);
    }
    /* 2. Our OWN classification read lazily creates this file's data section on
     *    the same thread -- wave it through, or we would deny our own read. */
    if (DlpClassifyActive()) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    /* 3. Only act on a real section CREATE; other acquisitions are not mappings. */
    if (Data->Iopb->Parameters.AcquireForSectionSynchronization.SyncType
            != SyncTypeCreateSection) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    /* 4. Leave EXECUTE mappings (image / DLL load) alone -- you cannot execute a
     *    data document, and we must not interfere with code loading. Data read/
     *    copy-on-write maps (what a file transfer uses) fall through. */
    if (FlagOn(Data->Iopb->Parameters.AcquireForSectionSynchronization.PageProtection,
               PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE |
               PAGE_EXECUTE_WRITECOPY)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    /* 5. PASSIVE + FileObject + skip agent/System (paging flag is irrelevant here). */
    if (DlpShouldSkip(Data, FltObjects)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    /* 6. Only exfil-channel PIDs. */
    pid = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
    if (!DlpExfilLookup(pid)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* 7. Cache-only decision. The verdict was seeded at create (which runs to
     *    completion before the handle is returned, hence before any mapping):
     *      stream ctx  -> authoritative (DENY/ALLOW),
     *      else SensFile by file id (cross-open) -> deny,
     *      else CleanFile -> allow,
     *      else UNKNOWN -> fail-safe (ExfilReadFailBlock). */
    if (NT_SUCCESS(FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject,
                                       (PFLT_CONTEXT *)&ctx)) && ctx != NULL) {
        verdict = InterlockedCompareExchange(&ctx->ExfilVerdict, 0, 0);
        FltReleaseContext((PFLT_CONTEXT)ctx);
    }
    if (verdict == DLP_EXFIL_UNKNOWN) {
        FILE_INTERNAL_INFORMATION intInfo;
        RtlZeroMemory(&intInfo, sizeof(intInfo));
        if (NT_SUCCESS(FltQueryInformationFile(FltObjects->Instance,
                FltObjects->FileObject, &intInfo, sizeof(intInfo),
                FileInternalInformation, NULL))) {
            fileId = (ULONGLONG)intInfo.IndexNumber.QuadPart;
        }
        if (fileId != 0 && DlpSensFileLookup(fileId, 0)) {
            verdict = DLP_EXFIL_DENY;
        } else if (fileId != 0 && DlpCleanFileLookup(fileId, 0)) {
            verdict = DLP_EXFIL_ALLOW;
        }
    }

    /* Deny a KNOWN-sensitive mapping; and, when fail-secure is configured, also
     * deny an UNKNOWN one (an exfil tool mapping an in-scope file we have not yet
     * cleared -- e.g. it maps before the create-time classify seeded the verdict).
     * Our OWN re-entrant classification read was already waved through at step 2
     * (DlpClassifyActive) and the async worker runs as System (skipped at step 5),
     * so an UNKNOWN reaching here is the exfil process's real mapping -- failing it
     * secure is correct, and MmCreateSection then aborts the mmap/copy. */
    if (verdict == DLP_EXFIL_DENY ||
        (verdict == DLP_EXFIL_UNKNOWN && gDlpData.ExfilReadFailBlock)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


/* ========================================================================= *
 *  Read-taint -- known-sensitive file-id cache (LLD §4; CONTENT epoch)      *
 *                                                                           *
 *  Same ring pattern as the taint table, but stamped with the CONTENT-policy *
 *  gDlpData.Epoch (NOT TaintEpoch): an agent reconnect's epoch bump          *
 *  invalidates cached sensitivity, which is correct for a content verdict.  *
 *  VolumeId 0 is the documented "unknown volume" fallback (v1). PASSIVE.     *
 * ------------------------------------------------------------------------- */

BOOLEAN
DlpSensFileLookup(_In_ ULONGLONG FileId, _In_ ULONGLONG VolumeId)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    LONG epoch;
    ULONG i;

    if (FileId == 0) {
        return FALSE;                      /* unknown file id -> never cached */
    }

    epoch = InterlockedCompareExchange(&gDlpData.Epoch, 0, 0);

    KeAcquireSpinLock(&gDlpData.SensFileLock, &oldIrql);
    for (i = 0; i < DLP_SENSFILE_MAX; i++) {
        if (gDlpData.SensFile[i].Valid &&
            gDlpData.SensFile[i].Epoch == epoch &&
            gDlpData.SensFile[i].FileId == FileId &&
            gDlpData.SensFile[i].VolumeId == VolumeId) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&gDlpData.SensFileLock, oldIrql);
    return found;
}

VOID
DlpSensFileInsert(_In_ ULONGLONG FileId, _In_ ULONGLONG VolumeId)
{
    KIRQL oldIrql;
    LONG epoch;
    LONG slot;
    ULONG i;

    if (FileId == 0) {
        return;                            /* never cache a zero file id */
    }

    epoch = InterlockedCompareExchange(&gDlpData.Epoch, 0, 0);

    KeAcquireSpinLock(&gDlpData.SensFileLock, &oldIrql);

    /* Dedup within the current content epoch. */
    for (i = 0; i < DLP_SENSFILE_MAX; i++) {
        if (gDlpData.SensFile[i].Valid &&
            gDlpData.SensFile[i].Epoch == epoch &&
            gDlpData.SensFile[i].FileId == FileId &&
            gDlpData.SensFile[i].VolumeId == VolumeId) {
            KeReleaseSpinLock(&gDlpData.SensFileLock, oldIrql);
            return;
        }
    }

    slot = gDlpData.SensFileNext;
    if (slot < 0 || slot >= DLP_SENSFILE_MAX) {
        slot = 0;
    }
    gDlpData.SensFile[slot].FileId = FileId;
    gDlpData.SensFile[slot].VolumeId = VolumeId;
    gDlpData.SensFile[slot].Epoch = epoch;
    gDlpData.SensFile[slot].Valid = TRUE;
    gDlpData.SensFileNext = (slot + 1) % DLP_SENSFILE_MAX;

    KeReleaseSpinLock(&gDlpData.SensFileLock, oldIrql);
}


/* ------------------------------------------------------------------------- *
 *  Known-clean file-id cache (read-deny) -- exact mirror of SensFile, its    *
 *  own lock/ring, same content Epoch stamp. Bounds the classify up-call load *
 *  so an exfil PID re-opening innocent files does not re-read + re-up-call.  *
 * ------------------------------------------------------------------------- */
BOOLEAN
DlpCleanFileLookup(_In_ ULONGLONG FileId, _In_ ULONGLONG VolumeId)
{
    KIRQL oldIrql;
    BOOLEAN found = FALSE;
    LONG epoch;
    ULONG i;

    if (FileId == 0) {
        return FALSE;
    }
    epoch = InterlockedCompareExchange(&gDlpData.Epoch, 0, 0);

    KeAcquireSpinLock(&gDlpData.CleanFileLock, &oldIrql);
    for (i = 0; i < DLP_CLEANFILE_MAX; i++) {
        if (gDlpData.CleanFile[i].Valid &&
            gDlpData.CleanFile[i].Epoch == epoch &&
            gDlpData.CleanFile[i].FileId == FileId &&
            gDlpData.CleanFile[i].VolumeId == VolumeId) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&gDlpData.CleanFileLock, oldIrql);
    return found;
}

VOID
DlpCleanFileInsert(_In_ ULONGLONG FileId, _In_ ULONGLONG VolumeId)
{
    KIRQL oldIrql;
    LONG epoch;
    LONG slot;
    ULONG i;

    if (FileId == 0) {
        return;
    }
    epoch = InterlockedCompareExchange(&gDlpData.Epoch, 0, 0);

    KeAcquireSpinLock(&gDlpData.CleanFileLock, &oldIrql);
    for (i = 0; i < DLP_CLEANFILE_MAX; i++) {
        if (gDlpData.CleanFile[i].Valid &&
            gDlpData.CleanFile[i].Epoch == epoch &&
            gDlpData.CleanFile[i].FileId == FileId &&
            gDlpData.CleanFile[i].VolumeId == VolumeId) {
            KeReleaseSpinLock(&gDlpData.CleanFileLock, oldIrql);
            return;
        }
    }
    slot = gDlpData.CleanFileNext;
    if (slot < 0 || slot >= DLP_CLEANFILE_MAX) {
        slot = 0;
    }
    gDlpData.CleanFile[slot].FileId = FileId;
    gDlpData.CleanFile[slot].VolumeId = VolumeId;
    gDlpData.CleanFile[slot].Epoch = epoch;
    gDlpData.CleanFile[slot].Valid = TRUE;
    gDlpData.CleanFileNext = (slot + 1) % DLP_CLEANFILE_MAX;
    KeReleaseSpinLock(&gDlpData.CleanFileLock, oldIrql);
}


/* ------------------------------------------------------------------------- *
 *  Per-thread classification re-entrancy guard                              *
 *                                                                           *
 *  The classifier's cached FltReadFile lazily creates the file's data       *
 *  section (CcInitializeCacheMap -> MmCreateSection), re-entering            *
 *  DlpPreAcquireForSection on the SAME thread. Without a guard that inner    *
 *  section would be gated (and, under fail-block, DENIED) -- sabotaging our  *
 *  own read. We record the classifying thread ids in a small spinlocked set  *
 *  and let the section-sync pre-op wave through anything issued by a thread  *
 *  currently inside DlpExfilClassifyAndCache. Sized well above the CPU count *
 *  (concurrent classifiers are bounded by cores doing read/create work).    *
 * ------------------------------------------------------------------------- */
#define DLP_CLASSIFY_SLOTS  64
static KSPIN_LOCK gClassifyLock;
static HANDLE     gClassifyThreads[DLP_CLASSIFY_SLOTS];   /* NULL = empty slot */

static VOID
DlpClassifyGuardInit(VOID)
{
    KeInitializeSpinLock(&gClassifyLock);
    RtlZeroMemory(gClassifyThreads, sizeof(gClassifyThreads));
}

/* Mark the current thread as classifying. Returns TRUE if it was recorded (so
 * the caller must pair a DlpClassifyExit); FALSE only if the set is full, in
 * which case the caller proceeds WITHOUT re-entrancy protection (rare; the inner
 * section then falls to the cache-only fail-safe -- never a crash). */
static BOOLEAN
DlpClassifyEnter(VOID)
{
    HANDLE tid = PsGetCurrentThreadId();
    KIRQL oldIrql;
    ULONG i, slot = DLP_CLASSIFY_SLOTS;
    BOOLEAN ok = FALSE;

    KeAcquireSpinLock(&gClassifyLock, &oldIrql);
    for (i = 0; i < DLP_CLASSIFY_SLOTS; i++) {
        if (gClassifyThreads[i] == tid) {          /* already recorded (defensive) */
            KeReleaseSpinLock(&gClassifyLock, oldIrql);
            return FALSE;
        }
        if (gClassifyThreads[i] == NULL && slot == DLP_CLASSIFY_SLOTS) {
            slot = i;
        }
    }
    if (slot < DLP_CLASSIFY_SLOTS) {
        gClassifyThreads[slot] = tid;
        ok = TRUE;
    }
    KeReleaseSpinLock(&gClassifyLock, oldIrql);
    return ok;
}

static VOID
DlpClassifyExit(VOID)
{
    HANDLE tid = PsGetCurrentThreadId();
    KIRQL oldIrql;
    ULONG i;

    KeAcquireSpinLock(&gClassifyLock, &oldIrql);
    for (i = 0; i < DLP_CLASSIFY_SLOTS; i++) {
        if (gClassifyThreads[i] == tid) {
            gClassifyThreads[i] = NULL;
            break;
        }
    }
    KeReleaseSpinLock(&gClassifyLock, oldIrql);
}

static BOOLEAN
DlpClassifyActive(VOID)
{
    HANDLE tid = PsGetCurrentThreadId();
    KIRQL oldIrql;
    ULONG i;
    BOOLEAN active = FALSE;

    KeAcquireSpinLock(&gClassifyLock, &oldIrql);
    for (i = 0; i < DLP_CLASSIFY_SLOTS; i++) {
        if (gClassifyThreads[i] == tid) {
            active = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&gClassifyLock, oldIrql);
    return active;
}


/* ========================================================================= *
 *  Read-taint -- async scan worker + queue (LLD §2 enqueue, §3 worker)      *
 *                                                                           *
 *  ScanRundown is acquired at enqueue and released BY THE WORKER per job, so *
 *  Unload's single ExWaitForRundownProtectionRelease drains all in-flight +  *
 *  queued jobs. DlpFreeScanJob fully destroys a job (derefs its FILE_OBJECT  *
 *  if referenced, then frees) -- centralised so no path double-derefs.      *
 * ------------------------------------------------------------------------- */

static VOID
DlpFreeScanJob(_In_ PDLP_SCAN_JOB Job)
{
    /* FileObject is NULL only for a job dropped in DlpPostRead BEFORE it took the
     * reference (queue-full / OOM). Every enqueued job has a reference, released
     * here exactly once. */
    if (Job->FileObject != NULL) {
        ObDereferenceObject(Job->FileObject);
        Job->FileObject = NULL;
    }
    ExFreePoolWithTag(Job, DLP_JOB_TAG);
}

VOID
DlpScanEnqueue(_Inout_ __drv_aliasesMem PDLP_SCAN_JOB Job)
{
    KIRQL oldIrql;

    /* Rundown gate: a failed acquire means the driver is tearing down the scan
     * subsystem -> drop the job (deref + free), fail-safe. The acquire here pairs
     * 1:1 with the worker's per-job release. */
    if (!ExAcquireRundownProtection(&gDlpData.ScanRundown)) {
        DlpFreeScanJob(Job);
        return;
    }

    KeAcquireSpinLock(&gDlpData.ScanQueueLock, &oldIrql);
    InsertTailList(&gDlpData.ScanQueue, &Job->Link);
    InterlockedIncrement(&gDlpData.ScanQueueDepth);
    KeReleaseSpinLock(&gDlpData.ScanQueueLock, oldIrql);

    /* Signal AFTER releasing the spinlock (keep the lock region pure list ops). */
    KeReleaseSemaphore(&gDlpData.ScanSem, 0, 1, FALSE);
}

/* Dequeue one job under the queue spinlock; returns NULL when the queue is
 * empty. Never blocks. */
static PDLP_SCAN_JOB
DlpScanDequeue(VOID)
{
    KIRQL oldIrql;
    PDLP_SCAN_JOB job = NULL;
    PLIST_ENTRY entry;

    KeAcquireSpinLock(&gDlpData.ScanQueueLock, &oldIrql);
    if (!IsListEmpty(&gDlpData.ScanQueue)) {
        entry = RemoveHeadList(&gDlpData.ScanQueue);
        InterlockedDecrement(&gDlpData.ScanQueueDepth);
        job = CONTAINING_RECORD(entry, DLP_SCAN_JOB, Link);
    }
    KeReleaseSpinLock(&gDlpData.ScanQueueLock, oldIrql);
    return job;
}

static VOID
DlpProcessScanJob(_In_ PDLP_SCAN_JOB Job)
{
    NTSTATUS status;
    FILE_INTERNAL_INFORMATION intInfo;
    ULONGLONG fileId = 0;
    ULONGLONG volumeId = 0;        /* v1: "unknown volume" fallback (LLD §4)   */
    PVOID content = NULL;
    ULONG contentBytes = 0;
    BOOLEAN truncated = FALSE;
    BOOLEAN block = FALSE;
    UNICODE_STRING pathName;
    UCHAR sha[DLP_SHA256_LEN];

    /* 1. File-id -> cheapest repeat path (no read, no up-call). A detached
     *    instance makes this (and the read below) fail cleanly => no taint. */
    RtlZeroMemory(&intInfo, sizeof(intInfo));
    status = FltQueryInformationFile(Job->Instance, Job->FileObject, &intInfo,
                                     sizeof(intInfo), FileInternalInformation,
                                     NULL);
    if (NT_SUCCESS(status)) {
        fileId = (ULONGLONG)intInfo.IndexNumber.QuadPart;
        if (DlpSensFileLookup(fileId, volumeId)) {
            DlpTaintAdd(Job->Pid);         /* already known-sensitive */
            return;
        }
    }

    /* 2. Read the content in-kernel (shared helper). Any failure => NO taint
     *    (we never taint on an unreadable read -- fail-safe). */
    status = DlpReadStreamContent(Job->Instance, Job->FileObject,
                                  &content, &contentBytes, &truncated);
    if (!NT_SUCCESS(status) || content == NULL || contentBytes == 0) {
        if (content != NULL) {
            ExFreePoolWithTag(content, DLP_GENERAL_TAG);
        }
        return;
    }

    /* 3. Known-bad content-hash fast path (item-10 ring; shared meaning
     *    "sensitive content"). A hit taints with no up-call. */
    DlpComputeSha256((const UCHAR *)content, contentBytes, sha);
    if (DlpBadHashLookup(sha)) {
        DlpTaintAdd(Job->Pid);
        DlpSensFileInsert(fileId, volumeId);
        ExFreePoolWithTag(content, DLP_GENERAL_TAG);
        return;
    }

    /* 4. Up-call with Reason=READ. Ship the file name captured at enqueue: the
     *    agent selects its extractor from the extension, so an empty path made
     *    every read come back Unreadable (never matched). On any fail-safe status
     *    DlpQueryVerdict already set *block from FailMode. */
    pathName.Buffer = Job->Path;
    pathName.Length = Job->PathLength;
    pathName.MaximumLength = Job->PathLength;
    status = DlpQueryVerdict(&pathName, fileId, Job->Pid, content, contentBytes,
                             truncated, DLP_REASON_READ, &block);

    /* 5. Tag on BLOCK. Taint on any block (fail-secure). Seed the persistent
     *    caches (sensfile + known-bad hash) ONLY on a GENUINE verdict -- an EXACT
     *    STATUS_SUCCESS. STATUS_TIMEOUT is NT_SUCCESS-*severity* but means "no
     *    verdict" (FailMode set *block); seeding on it would permanently mark a
     *    file sensitive because the agent was momentarily slow, mirroring the
     *    read-deny classifier's STATUS_SUCCESS discipline. */
    if (block) {
        DlpTaintAdd(Job->Pid);
        if (status == STATUS_SUCCESS) {
            DlpSensFileInsert(fileId, volumeId);
            DlpBadHashInsert(sha);
        }
    }

    /* 6. Free the content buffer (every path frees exactly once). */
    ExFreePoolWithTag(content, DLP_GENERAL_TAG);
}

static VOID
DlpScanWorker(_In_ PVOID StartContext)
{
    PDLP_SCAN_JOB job;

    UNREFERENCED_PARAMETER(StartContext);

    for (;;) {
        KeWaitForSingleObject(&gDlpData.ScanSem, Executive, KernelMode, FALSE,
                              NULL);

        if (InterlockedCompareExchange(&gDlpData.ScanStop, 0, 0) != 0) {
            /* Drain-and-exit: consume every remaining job (each: deref + free +
             * release its rundown ref exactly once), then terminate. In practice
             * DlpStopScanWorker has already run the rundown down, so the queue is
             * empty here; this loop is the belt-and-braces path. */
            while ((job = DlpScanDequeue()) != NULL) {
                DlpFreeScanJob(job);
                ExReleaseRundownProtection(&gDlpData.ScanRundown);
            }
            PsTerminateSystemThread(STATUS_SUCCESS);
            return;                        /* not reached */
        }

        job = DlpScanDequeue();
        if (job == NULL) {
            continue;                      /* spurious wake / already drained */
        }

        DlpProcessScanJob(job);
        DlpFreeScanJob(job);
        ExReleaseRundownProtection(&gDlpData.ScanRundown);   /* pairs w/ enqueue */
    }
}

NTSTATUS
DlpStartScanWorker(VOID)
{
    NTSTATUS status;
    HANDLE threadHandle = NULL;
    OBJECT_ATTRIBUTES oa;

    /* Init the queue + semaphore + rundown BEFORE creating the thread. */
    KeInitializeSpinLock(&gDlpData.ScanQueueLock);
    InitializeListHead(&gDlpData.ScanQueue);
    KeInitializeSemaphore(&gDlpData.ScanSem, 0, MAXLONG);
    gDlpData.ScanQueueDepth = 0;
    gDlpData.ScanDropped = 0;
    gDlpData.ScanStop = 0;
    gDlpData.ScanThread = NULL;
    gDlpData.ScanThreadHandle = NULL;
    ExInitializeRundownProtection(&gDlpData.ScanRundown);

    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
    status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, &oa,
                                  NULL, NULL, DlpScanWorker, NULL);
    if (!NT_SUCCESS(status)) {
        /* No thread => leave ScanRundownInit FALSE so DlpPostRead never enqueues
         * (the caller also disables read-taint outright). Nothing to unwind. */
        return status;
    }

    /* Keep a referenced PETHREAD so Unload can KeWaitForSingleObject on it; drop
     * the HANDLE (we only need the object). */
    status = ObReferenceObjectByHandle(threadHandle, THREAD_ALL_ACCESS,
                                       *PsThreadType, KernelMode,
                                       (PVOID *)&gDlpData.ScanThread, NULL);
    ZwClose(threadHandle);
    if (!NT_SUCCESS(status)) {
        /* The thread is running but unreferenceable: signal it to exit so it
         * does not run forever. No enqueue can occur (ScanRundownInit stays
         * FALSE => DlpPostRead is a no-op), so nothing leaks. */
        InterlockedExchange(&gDlpData.ScanStop, 1);
        KeReleaseSemaphore(&gDlpData.ScanSem, 0, 1, FALSE);
        gDlpData.ScanThread = NULL;
        return status;
    }

    /* Publish readiness LAST: only now may DlpPostRead enqueue (it gates on
     * ScanRundownInit) and only now will Unload wait the rundown. */
    gDlpData.ScanRundownInit = TRUE;
    return STATUS_SUCCESS;
}

VOID
DlpStopScanWorker(VOID)
{
    /* Fold LLD §5.5 steps 3+4 in the race-free order:
     *
     * FIRST run the rundown down. ExWaitForRundownProtectionRelease makes every
     * subsequent ExAcquireRundownProtection in DlpScanEnqueue return FALSE (new
     * jobs are dropped + freed, holding no ref) AND blocks until every already-
     * acquired job has been processed + released by the STILL-RUNNING worker.
     * When it returns, the queue holds no rundown-protected job and none can be
     * added -- so no job can be orphaned when the worker exits. */
    if (gDlpData.ScanRundownInit) {
        ExWaitForRundownProtectionRelease(&gDlpData.ScanRundown);
        gDlpData.ScanRundownInit = FALSE;
    }

    /* THEN signal the now-idle worker to exit and join it. */
    if (gDlpData.ScanThread != NULL) {
        InterlockedExchange(&gDlpData.ScanStop, 1);
        KeReleaseSemaphore(&gDlpData.ScanSem, 0, 1, FALSE);
        KeWaitForSingleObject(gDlpData.ScanThread, Executive, KernelMode, FALSE,
                              NULL);
        ObDereferenceObject(gDlpData.ScanThread);
        gDlpData.ScanThread = NULL;
    }
}


/* ------------------------------------------------------------------------- *
 *  DlpEnqueueOpenScan -- async content scan for an exfil PID's file OPEN     *
 *                                                                           *
 *  Mirrors DlpPostRead's claim-once + scope + enqueue tail, but triggered at *
 *  IRP_MJ_CREATE (post) for read-deny. Enqueuing at OPEN -- not READ -- is    *
 *  what defeats mmap-based exfil: the transfer must open() the file (a normal *
 *  create we see), even though its subsequent mapped reads are paging I/O the *
 *  read hooks never see. The worker taints the opener (network cut) + seeds   *
 *  SensFile (section block). PASSIVE; caller confirmed worker-ready + exfil.  *
 * ------------------------------------------------------------------------- */
static VOID
DlpEnqueueOpenScan(_In_ PCFLT_RELATED_OBJECTS FltObjects,
                   _Inout_ PFLT_CALLBACK_DATA Data)
{
    NTSTATUS status;
    PDLP_STREAM_CONTEXT ctx = NULL;
    PDLP_INSTANCE_CONTEXT instCtx = NULL;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PDLP_SCAN_JOB job = NULL;
    ULONG volumeClass = DLP_VOL_REMOVABLE;   /* fallback: inspect-all */
    ULONG pid;

    /* Get/attach the stream context (allocate-or-get). */
    status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject,
                                 (PFLT_CONTEXT *)&ctx);
    if (!NT_SUCCESS(status)) {
        status = FltAllocateContext(gDlpData.Filter, FLT_STREAM_CONTEXT,
                                    sizeof(DLP_STREAM_CONTEXT), NonPagedPoolNx,
                                    (PFLT_CONTEXT *)&ctx);
        if (!NT_SUCCESS(status)) {
            return;                            /* fail-safe: do not track */
        }
        ctx->WriteCandidate = 0;
        ctx->Dirty = 0;
        ctx->Inspected = 0;
        ctx->Epoch = InterlockedCompareExchange(&gDlpData.Epoch, 0, 0);
        ctx->ReadScanState = 0;
        ctx->ExfilVerdict = DLP_EXFIL_UNKNOWN;
        status = FltSetStreamContext(FltObjects->Instance, FltObjects->FileObject,
                                     FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                     (PFLT_CONTEXT)ctx, NULL);
        if (!NT_SUCCESS(status)) {
            FltReleaseContext((PFLT_CONTEXT)ctx);
            return;
        }
    }

    /* Claim-once: only the first open/read of this stream enqueues one job.
     * Shared with DlpPostRead's claim so a create + first read do not double-
     * enqueue. */
    if (InterlockedCompareExchange(&ctx->ReadScanState, 1, 0) != 0) {
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return;
    }

    /* Cheap repeat path: already known-sensitive -> taint the opener now (no
     * read, no up-call, no enqueue). */
    {
        FILE_INTERNAL_INFORMATION intInfo;
        RtlZeroMemory(&intInfo, sizeof(intInfo));
        if (NT_SUCCESS(FltQueryInformationFile(FltObjects->Instance,
                FltObjects->FileObject, &intInfo, sizeof(intInfo),
                FileInternalInformation, NULL))) {
            if (DlpSensFileLookup((ULONGLONG)intInfo.IndexNumber.QuadPart, 0)) {
                pid = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
                DlpTaintAdd(pid);
                FltReleaseContext((PFLT_CONTEXT)ctx);
                return;
            }
        }
    }

    /* Scope filter (reuses the write-path config): FIXED volumes only under a
     * watch prefix; removable/network inspect everything. A failed name query
     * cannot be scoped -> do not enqueue. */
    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return;
    }
    (VOID)FltParseFileNameInformation(nameInfo);

    if (NT_SUCCESS(FltGetInstanceContext(FltObjects->Instance,
                                         (PFLT_CONTEXT *)&instCtx)) &&
        instCtx != NULL) {
        volumeClass = instCtx->VolumeClass;
        FltReleaseContext((PFLT_CONTEXT)instCtx);
    }
    if (volumeClass == DLP_VOL_FIXED &&
        !DlpConfigPathIsWatched(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return;
    }

    /* Bound the queue (drop under flood = a miss; fail-safe toward not deadlocking
     * / not growing non-paged pool). */
    if (InterlockedCompareExchange(&gDlpData.ScanQueueDepth, 0, 0) >=
        DLP_SCAN_QUEUE_MAX) {
        InterlockedIncrement(&gDlpData.ScanDropped);
        FltReleaseFileNameInformation(nameInfo);
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return;
    }

#pragma warning(suppress: 4996)
    job = (PDLP_SCAN_JOB)ExAllocatePoolWithTag(NonPagedPoolNx,
                                               sizeof(DLP_SCAN_JOB), DLP_JOB_TAG);
    if (job == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return;
    }
    RtlZeroMemory(job, sizeof(*job));
    job->Instance = FltObjects->Instance;
    job->FileObject = FltObjects->FileObject;
    ObReferenceObject(FltObjects->FileObject);
    job->Pid = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
    job->Epoch = InterlockedCompareExchange(&gDlpData.Epoch, 0, 0);

    {
        USHORT nameBytes = nameInfo->Name.Length;
        USHORT cap = (USHORT)(DLP_MAX_PATH_CHARS * sizeof(WCHAR));
        if (nameBytes > cap) {
            nameBytes = cap;
        }
        if (nameBytes > 0 && nameInfo->Name.Buffer != NULL) {
            RtlCopyMemory(job->Path, nameInfo->Name.Buffer, nameBytes);
        }
        job->PathLength = nameBytes;
    }

    FltReleaseFileNameInformation(nameInfo);
    DlpScanEnqueue(job);
    FltReleaseContext((PFLT_CONTEXT)ctx);
}


/* ========================================================================= *
 *  Read-taint -- IRP_MJ_READ post-op trigger (LLD §2)                       *
 *                                                                           *
 *  Runs <= DISPATCH / possibly nested. It must NOT read the file, up-call,   *
 *  or touch stream context at raised IRQL -- DlpShouldSkip enforces          *
 *  PASSIVE + no top-level IRP, so the whole trigger is strictly PASSIVE. It   *
 *  only claims the FIRST substantial read of a stream and ENQUEUES an async   *
 *  scan; no scan latency is added to the read. All gated on ReadTaintEnabled  *
 *  (default OFF => today's behavior) and ScanRundownInit (worker ready).     *
 * ------------------------------------------------------------------------- */
FLT_POSTOP_CALLBACK_STATUS FLTAPI
DlpPostRead(_Inout_ PFLT_CALLBACK_DATA Data,
            _In_ PCFLT_RELATED_OBJECTS FltObjects,
            _In_opt_ PVOID CompletionContext,
            _In_ FLT_POST_OPERATION_FLAGS Flags)
{
    NTSTATUS status;
    PDLP_STREAM_CONTEXT ctx = NULL;
    PDLP_INSTANCE_CONTEXT instCtx = NULL;
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    PDLP_SCAN_JOB job = NULL;
    ULONG volumeClass = DLP_VOL_REMOVABLE;   /* fallback: inspect-all */
    ULONG pid;

    UNREFERENCED_PARAMETER(CompletionContext);

    /* 1. Draining. */
    if (Flags & FLTFL_POST_OPERATION_DRAINING) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    /* 2. Kill-switch: the default-OFF gate that keeps today's FS-only behavior,
     *    plus the worker-ready gate (ScanRundownInit) that closes the window
     *    between FltStartFiltering and DlpStartScanWorker. */
    if (gDlpData.ReadTaintEnabled != DLP_READTAINT_ENABLED ||
        !gDlpData.ScanRundownInit) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    /* 3. The single top-of-callback gate (paging/self/System/IRQL/re-entrancy).
     *    It enforces PASSIVE_LEVEL + IoGetTopLevelIrp()==NULL, so an async read
     *    at DISPATCH is skipped here (caught on a later read or not at all --
     *    fail-safe); the trigger is strictly PASSIVE from here on. */
    if (DlpShouldSkip(Data, FltObjects)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    /* 4. Failed read or zero bytes: nothing substantial happened. */
    if (!NT_SUCCESS(Data->IoStatus.Status) ||
        Data->IoStatus.Information == 0) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    /* 5. Substantiality gate: a 1-byte probe read must not arm a scan. */
    if (Data->Iopb->Parameters.Read.Length < DLP_READ_MIN) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* 6. Get/attach the stream context (allocate-or-get, exactly as DlpPostCreate
     *    -- if another thread wins the set race we simply do not claim here; the
     *    winner will claim-once on the attached context). */
    status = FltGetStreamContext(FltObjects->Instance, FltObjects->FileObject,
                                 (PFLT_CONTEXT *)&ctx);
    if (!NT_SUCCESS(status)) {
        status = FltAllocateContext(gDlpData.Filter, FLT_STREAM_CONTEXT,
                                    sizeof(DLP_STREAM_CONTEXT), NonPagedPoolNx,
                                    (PFLT_CONTEXT *)&ctx);
        if (!NT_SUCCESS(status)) {
            return FLT_POSTOP_FINISHED_PROCESSING;   /* fail-safe: do not track */
        }
        ctx->WriteCandidate = 0;
        ctx->Dirty = 0;
        ctx->Inspected = 0;
        ctx->Epoch = InterlockedCompareExchange(&gDlpData.Epoch, 0, 0);
        ctx->ReadScanState = 0;

        status = FltSetStreamContext(FltObjects->Instance, FltObjects->FileObject,
                                     FLT_SET_CONTEXT_KEEP_IF_EXISTS,
                                     (PFLT_CONTEXT)ctx, NULL);
        if (!NT_SUCCESS(status)) {
            /* Another thread attached first (or it cannot be set) -- benign; that
             * thread owns the claim-once. */
            FltReleaseContext((PFLT_CONTEXT)ctx);
            return FLT_POSTOP_FINISHED_PROCESSING;
        }
    }

    /* 7. Claim-once: only the FIRST substantial read of this stream enqueues. */
    if (InterlockedCompareExchange(&ctx->ReadScanState, 1, 0) != 0) {
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* 8. Cheap repeat path: if this file id is already known-sensitive, taint the
     *    reader directly -- no scope query, no read, no up-call, no enqueue. */
    {
        FILE_INTERNAL_INFORMATION intInfo;
        RtlZeroMemory(&intInfo, sizeof(intInfo));
        if (NT_SUCCESS(FltQueryInformationFile(FltObjects->Instance,
                FltObjects->FileObject, &intInfo, sizeof(intInfo),
                FileInternalInformation, NULL))) {
            ULONGLONG fid = (ULONGLONG)intInfo.IndexNumber.QuadPart;
            if (DlpSensFileLookup(fid, 0)) {
                pid = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
                DlpTaintAdd(pid);
                FltReleaseContext((PFLT_CONTEXT)ctx);
                return FLT_POSTOP_FINISHED_PROCESSING;
            }
        }
    }

    /* 9. Scope filter (reuses the write-path config). Resolve the name; on a
     *    FIXED volume, only enqueue reads under a configured watch prefix --
     *    keeping C: reads cheap. Removable/network inspect everything. A failed
     *    name query fails-safe toward NOT enqueuing (we cannot scope it). */
    status = FltGetFileNameInformation(
        Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status) || nameInfo == NULL) {
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    (VOID)FltParseFileNameInformation(nameInfo);

    if (NT_SUCCESS(FltGetInstanceContext(FltObjects->Instance,
                                         (PFLT_CONTEXT *)&instCtx)) &&
        instCtx != NULL) {
        volumeClass = instCtx->VolumeClass;
        FltReleaseContext((PFLT_CONTEXT)instCtx);
    }
    if (volumeClass == DLP_VOL_FIXED &&
        !DlpConfigPathIsWatched(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* 10. Enqueue. Bound the queue (drop under flood = a miss; fail-safe toward
     *     not deadlocking / not growing non-paged pool without limit). Reference
     *     the FILE_OBJECT for the worker (released by DlpFreeScanJob). */
    if (InterlockedCompareExchange(&gDlpData.ScanQueueDepth, 0, 0) >=
        DLP_SCAN_QUEUE_MAX) {
        InterlockedIncrement(&gDlpData.ScanDropped);
        FltReleaseFileNameInformation(nameInfo);
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

#pragma warning(suppress: 4996)
    job = (PDLP_SCAN_JOB)ExAllocatePoolWithTag(NonPagedPoolNx,
                                               sizeof(DLP_SCAN_JOB), DLP_JOB_TAG);
    if (job == NULL) {
        FltReleaseFileNameInformation(nameInfo);
        FltReleaseContext((PFLT_CONTEXT)ctx);
        return FLT_POSTOP_FINISHED_PROCESSING;
    }
    RtlZeroMemory(job, sizeof(*job));
    job->Instance = FltObjects->Instance;    /* kept valid by the scan rundown  */
    job->FileObject = FltObjects->FileObject;
    ObReferenceObject(FltObjects->FileObject);
    job->Pid = (ULONG)(ULONG_PTR)FltGetRequestorProcessId(Data);
    job->Epoch = InterlockedCompareExchange(&gDlpData.Epoch, 0, 0);

    /* Capture the normalized name for the worker's up-call. nameInfo is still held
     * here; the worker runs after the file may be closed, so we copy the bytes now
     * (bounded to Path). Without this the up-call ships an empty path and the agent
     * can't pick the format extractor -> every read came back Unreadable. */
    {
        USHORT nameBytes = nameInfo->Name.Length;
        USHORT cap = (USHORT)(DLP_MAX_PATH_CHARS * sizeof(WCHAR));
        if (nameBytes > cap) {
            nameBytes = cap;
        }
        if (nameBytes > 0 && nameInfo->Name.Buffer != NULL) {
            RtlCopyMemory(job->Path, nameInfo->Name.Buffer, nameBytes);
        }
        job->PathLength = nameBytes;
    }

    FltReleaseFileNameInformation(nameInfo);

    /* Hands ownership of the job (and its FILE_OBJECT ref) to the queue; the
     * worker derefs + frees + releases the rundown. If the rundown is already
     * running down (Unload), DlpScanEnqueue drops the job safely. */
    DlpScanEnqueue(job);

    FltReleaseContext((PFLT_CONTEXT)ctx);
    return FLT_POSTOP_FINISHED_PROCESSING;
}


/* ========================================================================= *
 *  Read-taint -- process-exit untaint (LLD §4)                              *
 *                                                                           *
 *  Registered in DriverEntry (gated) with PsSetCreateProcessNotifyRoutineEx  *
 *  (needs /INTEGRITYCHECK, already on the link line). On process EXIT we      *
 *  untaint the PID -- freeing a taint slot and closing the PID-reuse window.  *
 *  PASSIVE_LEVEL. Registration is unregistered in Unload.                    *
 * ------------------------------------------------------------------------- */
VOID
DlpCreateProcessNotify(_In_ PEPROCESS Process,
                       _In_ HANDLE ProcessId,
                       _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    /* CreateInfo == NULL => the process is EXITING. On create we do nothing. */
    if (CreateInfo == NULL) {
        DlpTaintRemove((ULONG)(ULONG_PTR)ProcessId);
        /* Also drop an exfil-channel PID on exit (defence in depth; the agent's
         * next full-replace would clear it anyway). */
        DlpExfilRemove((ULONG)(ULONG_PTR)ProcessId);
    }
}
