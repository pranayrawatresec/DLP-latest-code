/*++

comms.c  --  DLP minifilter communication port (SPEC 2.3).

Owns the \DlpFltPort filter port that the user-mode DLP service (dlp-agent
usb-guard) connects to. Provides:
  * DlpCreateCommunicationPort / DlpCloseCommunicationPort  (lifecycle)
  * ConnectNotify / DisconnectNotify  (record the service PID for self-skip)
  * DlpQueryVerdict  (kernel -> user request via FltSendMessage, with timeout)
  * DlpReadFailMode  (registry-driven fail behavior)

Security: the port is created with a default security descriptor granting
FLT_PORT_ALL_ACCESS to Administrators and SYSTEM only, and a maximum of ONE
connection (SPEC 2.3). The verdict request carries the file path, metadata, and
(v2) up to DLP_MAX_CONTENT bytes of file content read in-kernel so the service
can fingerprint without re-opening the file. Content is capped at 4 MiB and is
NEVER logged; it exists only in the in-flight message buffer.

--*/

#include "dlpflt.h"

/* ------------------------------------------------------------------------- *
 *  Forward declarations                                                     *
 * ------------------------------------------------------------------------- */
static NTSTATUS FLTAPI DlpPortConnect(
    _In_ PFLT_PORT ClientPort,
    _In_opt_ PVOID ServerPortCookie,
    _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG SizeOfContext,
    _Outptr_result_maybenull_ PVOID *ConnectionPortCookie);

static VOID FLTAPI DlpPortDisconnect(_In_opt_ PVOID ConnectionCookie);

static VOID DlpReadDword(_In_ HANDLE Key, _In_ PCWSTR Name, _Inout_ PULONG Out);

static LONG DlpConfigExceptionFilter(_In_ ULONG Code);

static NTSTATUS FLTAPI DlpPortMessage(
    _In_opt_ PVOID PortCookie,
    _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
    _In_ ULONG InputBufferLength,
    _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
    _In_ ULONG OutputBufferLength,
    _Out_ PULONG ReturnOutputBufferLength);

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, DlpCreateCommunicationPort)
#pragma alloc_text(PAGE, DlpCloseCommunicationPort)
#pragma alloc_text(PAGE, DlpPortConnect)
#pragma alloc_text(PAGE, DlpPortDisconnect)
#pragma alloc_text(PAGE, DlpReadFailMode)
#pragma alloc_text(PAGE, DlpReadDword)
#pragma alloc_text(PAGE, DlpReadExfilPolicy)
#endif


/* ------------------------------------------------------------------------- *
 *  Port lifecycle                                                           *
 * ------------------------------------------------------------------------- */
NTSTATUS
DlpCreateCommunicationPort(_In_ PFLT_FILTER Filter)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;

    PAGED_CODE();

    /* Default SD: FLT_PORT_ALL_ACCESS to Administrators + SYSTEM only. */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    RtlInitUnicodeString(&portName, DLP_PORT_NAME);
    InitializeObjectAttributes(&oa, &portName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, sd);

    status = FltCreateCommunicationPort(
        Filter,
        &gDlpData.ServerPort,
        &oa,
        NULL,                       /* server port cookie */
        DlpPortConnect,
        DlpPortDisconnect,
        DlpPortMessage,             /* user->kernel: DLP_CONFIG + DLP_EXFIL_UPDATE */
        2);                         /* scanner (receive/reply) + push-only exfil conn */

    FltFreeSecurityDescriptor(sd);
    return status;
}

VOID
DlpCloseCommunicationPort(VOID)
{
    PAGED_CODE();

    if (gDlpData.ServerPort != NULL) {
        FltCloseCommunicationPort(gDlpData.ServerPort);
        gDlpData.ServerPort = NULL;
    }
    /* ClientPort is closed by FltMgr via DisconnectNotify; clear defensively. */
    gDlpData.ClientPort = NULL;
    InterlockedExchange(&gDlpData.ServicePid, 0);
}


/* ------------------------------------------------------------------------- *
 *  Connect / disconnect                                                     *
 * ------------------------------------------------------------------------- */
/* Per-connection role cookies. The SCANNER connection (usb-guard's receive/reply
 * loop) owns ClientPort + ServicePid; a second PUSH connection -- opened with the
 * DLP_EXFIL_VERSION context so its FilterSendMessage(exfil-set) never shares a
 * handle with the scanner's FilterGetMessage -- must NOT touch ClientPort on
 * connect or disconnect. */
#define DLP_CONN_SCAN  ((PVOID)(ULONG_PTR)1)
#define DLP_CONN_PUSH  ((PVOID)(ULONG_PTR)2)

static NTSTATUS FLTAPI
DlpPortConnect(_In_ PFLT_PORT ClientPort,
               _In_opt_ PVOID ServerPortCookie,
               _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
               _In_ ULONG SizeOfContext,
               _Outptr_result_maybenull_ PVOID *ConnectionPortCookie)
{
    ULONG connCtx = 0;

    UNREFERENCED_PARAMETER(ServerPortCookie);

    PAGED_CODE();

    /* Read the connection context to detect the push-only connection. FltMgr
     * copies the caller's context into a NONPAGED-POOL kernel buffer before it
     * invokes this callback, so ConnectionContext is a KERNEL-mode pointer -- it
     * must be read directly. (The previous ProbeForRead was wrong: ProbeForRead
     * rejects any non-user address, so it ALWAYS faulted here, the SEH forced
     * connCtx=0, and the push connection was misclassified as the scanner -- which
     * clobbered ClientPort with the push port and made every up-call time out.)
     * Keep an SEH guard purely as a belt-and-braces against a malformed buffer. */
    if (ConnectionContext != NULL && SizeOfContext >= sizeof(ULONG)) {
        __try {
            connCtx = *(const volatile ULONG *)ConnectionContext;
        } __except (DlpConfigExceptionFilter(GetExceptionCode())) {
            connCtx = 0;
        }
    }

    if (connCtx == DLP_EXFIL_VERSION) {
        /* Push-only connection: exists solely to deliver DLP_EXFIL_UPDATE via
         * DlpPortMessage on its OWN handle. Do NOT become the ClientPort. */
        *ConnectionPortCookie = DLP_CONN_PUSH;
        return STATUS_SUCCESS;
    }

    /* Scanner connection. ConnectNotify runs in the connecting process's context,
     * so PsGetCurrentProcessId() is the service PID we self-skip on (SPEC 2.4). */
    gDlpData.ClientPort = ClientPort;
    InterlockedExchange(&gDlpData.ServicePid,
                        (LONG)(ULONG_PTR)PsGetCurrentProcessId());

    /* Item 4 (H2): a fresh agent connection may carry fresh policy -- bump the
     * epoch so any known-bad hash / cached verdict from a previous session is
     * treated as a miss. Item 3 (H5): a new agent is healthy by definition, so
     * reset the circuit breaker. */
    InterlockedIncrement(&gDlpData.Epoch);
    InterlockedExchange(&gDlpData.ConsecutiveTimeouts, 0);

    *ConnectionPortCookie = DLP_CONN_SCAN;
    return STATUS_SUCCESS;
}

static VOID FLTAPI
DlpPortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    PAGED_CODE();

    /* The push-only connection closing must NOT tear down the scanner's client
     * state. Only the scanner connection clears ClientPort/ServicePid. */
    if (ConnectionCookie == DLP_CONN_PUSH) {
        return;
    }

    /* Clear client state; new scans will now honor FailMode until a client
     * reconnects. FltMgr closes the client port after this returns. */
    if (gDlpData.ClientPort != NULL) {
        FltCloseClientPort(gDlpData.Filter, &gDlpData.ClientPort);
        gDlpData.ClientPort = NULL;
    }
    InterlockedExchange(&gDlpData.ServicePid, 0);
}

/* SEH filter for the DLP_CONFIG copy: handle ONLY the faults a bad user buffer
 * can raise (access violation / misalignment from ProbeForRead or the copy) and
 * let any other exception propagate -- masking everything would hide unrelated
 * bugs (analyzer C6320). */
static LONG
DlpConfigExceptionFilter(_In_ ULONG Code)
{
    if (Code == STATUS_ACCESS_VIOLATION ||
        Code == STATUS_DATATYPE_MISALIGNMENT) {
        return EXCEPTION_EXECUTE_HANDLER;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

/* Message-notify callback (user -> kernel). Verdicts flow the other way
 * (kernel -> user, FltSendMessage); the ONE user-initiated message we accept is
 * a DLP_CONFIG that sets the scan scope (watch prefixes + fixed/network flags).
 * Anything else is rejected: the verdict protocol stays kernel->user only.
 *
 * Runs at PASSIVE_LEVEL in the caller's (service's) thread context, so the
 * InputBuffer is user memory -- probe it and copy under SEH. The ERESOURCE
 * stays at PASSIVE_LEVEL, so the user copy (which may fault) is legal while it
 * is held; the lock is released on both the normal and exception paths. */
static NTSTATUS FLTAPI
DlpPortMessage(_In_opt_ PVOID PortCookie,
               _In_reads_bytes_opt_(InputBufferLength) PVOID InputBuffer,
               _In_ ULONG InputBufferLength,
               _Out_writes_bytes_to_opt_(OutputBufferLength, *ReturnOutputBufferLength) PVOID OutputBuffer,
               _In_ ULONG OutputBufferLength,
               _Out_ PULONG ReturnOutputBufferLength)
{
    NTSTATUS status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    ULONG version = 0;

    *ReturnOutputBufferLength = 0;

    /* Two user->kernel messages share this port: DLP_CONFIG (scan scope) and
     * DLP_EXFIL_UPDATE (exfil-PID set). They are discriminated by the first ULONG:
     * DLP_CONFIG_VERSION (1) vs the DLP_EXFIL_VERSION magic. Read it first (SEH). */
    if (InputBuffer == NULL || InputBufferLength < sizeof(ULONG)) {
        return STATUS_INVALID_PARAMETER;
    }
    __try {
        ProbeForRead(InputBuffer, sizeof(ULONG), __alignof(ULONG));
        version = *(volatile ULONG *)InputBuffer;
    } __except (DlpConfigExceptionFilter(GetExceptionCode())) {
        return STATUS_INVALID_USER_BUFFER;
    }

    /* ---- DLP_DRAIN_VERSION (read-deny audit drain: kernel -> user reply) --- *
     * The guard pulls buffered cache-hit deny events. Snapshot + clear the ring
     * under its spinlock into a NonPaged copy (no user memory touched at raised
     * IRQL), then copy to the user output buffer at PASSIVE under SEH. */
    if (version == DLP_DRAIN_VERSION) {
        KIRQL oldIrql;
        LONG count, i;
        ULONG needed;
        PDLP_DENY_DRAIN_REPLY snap;

        if (OutputBuffer == NULL || OutputBufferLength < sizeof(DLP_DENY_DRAIN_REPLY)) {
            return STATUS_BUFFER_TOO_SMALL;   /* don't drain if the guard can't hold it */
        }
#pragma warning(suppress: 4996)
        snap = (PDLP_DENY_DRAIN_REPLY)ExAllocatePoolWithTag(
            NonPagedPoolNx, sizeof(DLP_DENY_DRAIN_REPLY), DLP_GENERAL_TAG);
        if (snap == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        KeAcquireSpinLock(&gDlpData.DenyRingLock, &oldIrql);
        count = gDlpData.DenyRingCount;
        if (count < 0) {
            count = 0;
        }
        if (count > DLP_DENYRING_MAX) {
            count = DLP_DENYRING_MAX;
        }
        snap->Count = (ULONG)count;
        snap->Dropped = (ULONG)gDlpData.DenyRingDropped;
        for (i = 0; i < count; i++) {
            snap->Events[i] = gDlpData.DenyRing[i];
        }
        gDlpData.DenyRingCount = 0;
        gDlpData.DenyRingDropped = 0;
        KeReleaseSpinLock(&gDlpData.DenyRingLock, oldIrql);

        needed = (ULONG)FIELD_OFFSET(DLP_DENY_DRAIN_REPLY, Events) +
                 snap->Count * (ULONG)sizeof(DLP_DENY_EVENT);
        __try {
            ProbeForWrite(OutputBuffer, needed, __alignof(ULONG));
            RtlCopyMemory(OutputBuffer, snap, needed);
            *ReturnOutputBufferLength = needed;
        } __except (DlpConfigExceptionFilter(GetExceptionCode())) {
            ExFreePoolWithTag(snap, DLP_GENERAL_TAG);
            return STATUS_INVALID_USER_BUFFER;
        }
        ExFreePoolWithTag(snap, DLP_GENERAL_TAG);
        return STATUS_SUCCESS;
    }

    /* ---- DLP_EXFIL_UPDATE (read-deny exfil-PID full-replace) --------------- */
    if (version == DLP_EXFIL_VERSION) {
        ULONG count = 0;
        ULONG *kbuf;

        if (InputBufferLength < sizeof(DLP_EXFIL_UPDATE)) {
            return STATUS_INVALID_PARAMETER;
        }
        /* DlpExfilReplace takes a spinlock and must not touch user memory, so copy
         * the PID array into a kernel buffer under SEH first. Bounded. */
#pragma warning(suppress: 4996)
        kbuf = (ULONG *)ExAllocatePoolWithTag(NonPagedPoolNx,
                                              DLP_EXFIL_MSG_MAX * sizeof(ULONG),
                                              DLP_EXFIL_TAG);
        if (kbuf == NULL) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        __try {
            PDLP_EXFIL_UPDATE in = (PDLP_EXFIL_UPDATE)InputBuffer;
            ProbeForRead(InputBuffer, sizeof(DLP_EXFIL_UPDATE), __alignof(ULONG));
            count = in->Count;
            if (count > DLP_EXFIL_MSG_MAX) {
                count = DLP_EXFIL_MSG_MAX;
            }
            RtlCopyMemory(kbuf, in->Pids, count * sizeof(ULONG));
        } __except (DlpConfigExceptionFilter(GetExceptionCode())) {
            ExFreePoolWithTag(kbuf, DLP_EXFIL_TAG);
            return STATUS_INVALID_USER_BUFFER;
        }
        DlpExfilReplace(kbuf, count);
        ExFreePoolWithTag(kbuf, DLP_EXFIL_TAG);
        return STATUS_SUCCESS;
    }

    /* ---- DLP_CONFIG (scan scope) ------------------------------------------- */
    if (version != DLP_CONFIG_VERSION || InputBufferLength < sizeof(DLP_CONFIG)) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&gDlpData.ConfigLock, TRUE);

    __try {
        PDLP_CONFIG in = (PDLP_CONFIG)InputBuffer;

        ProbeForRead(InputBuffer, sizeof(DLP_CONFIG), __alignof(ULONG));

        if (in->WatchCount > DLP_MAX_WATCH) {
            status = STATUS_INVALID_PARAMETER;
        } else {
            RtlCopyMemory(&gDlpData.Config, in, sizeof(DLP_CONFIG));
            /* Defensive clamp: never trust a count past the array bound. */
            if (gDlpData.Config.WatchCount > DLP_MAX_WATCH) {
                gDlpData.Config.WatchCount = DLP_MAX_WATCH;
            }
            InterlockedExchange(&gDlpData.ConfigValid, 1);
            status = STATUS_SUCCESS;
        }
    } __except (DlpConfigExceptionFilter(GetExceptionCode())) {
        status = STATUS_INVALID_USER_BUFFER;
    }

    ExReleaseResourceLite(&gDlpData.ConfigLock);
    KeLeaveCriticalRegion();

    return status;
}


/* ------------------------------------------------------------------------- *
 *  Scan-scope config accessors (Tier-1 extension)                           *
 *                                                                           *
 *  Readers of the DLP_CONFIG stored by DlpPortMessage. Each takes ConfigLock *
 *  SHARED (ERESOURCE => stays at PASSIVE_LEVEL, so the case-insensitive path *
 *  match is legal while held). ConfigValid short-circuits the common         *
 *  no-config case (removable-only) without touching the lock.               *
 * ------------------------------------------------------------------------- */

/* Case-insensitive watch-prefix test: does the path contain the needle (a watch
 * prefix that itself begins with '\') at a COMPONENT BOUNDARY? The needle's
 * leading '\' anchors the left boundary; here we additionally require the match
 * to be followed by end-of-path or a '\', so "\Users" matches "...\Users" and
 * "...\Users\file" but NOT "...\UsersData" (a loose substring would wrongly match
 * the latter). This makes watch_paths a folder-path match, not a substring.
 * RtlUpcaseUnicodeChar is a table lookup callable at any IRQL, safe under the
 * shared lock. Bounded by path length * needle length. */
static BOOLEAN
DlpUnicodeContainsCI(_In_ PCUNICODE_STRING Haystack,
                     _In_reads_(NeedleChars) PCWSTR Needle,
                     _In_ USHORT NeedleChars)
{
    USHORT hayChars;
    USHORT start;

    if (NeedleChars == 0 || Haystack == NULL || Haystack->Buffer == NULL) {
        return FALSE;
    }
    hayChars = (USHORT)(Haystack->Length / sizeof(WCHAR));
    if (hayChars < NeedleChars) {
        return FALSE;
    }

    for (start = 0; (USHORT)(start + NeedleChars) <= hayChars; start++) {
        USHORT j;
        for (j = 0; j < NeedleChars; j++) {
            if (RtlUpcaseUnicodeChar(Haystack->Buffer[start + j]) !=
                RtlUpcaseUnicodeChar(Needle[j])) {
                break;
            }
        }
        if (j == NeedleChars) {
            /* Right boundary: end-of-path or a path separator. */
            USHORT after = (USHORT)(start + NeedleChars);
            if (after == hayChars || Haystack->Buffer[after] == L'\\') {
                return TRUE;
            }
        }
    }
    return FALSE;
}

BOOLEAN
DlpConfigScanNetwork(VOID)
{
    BOOLEAN result;

    if (InterlockedCompareExchange(&gDlpData.ConfigValid, 0, 0) == 0) {
        return FALSE;   /* no config yet -> removable-only defaults */
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&gDlpData.ConfigLock, TRUE);
    result = (gDlpData.Config.ScanNetwork != 0);
    ExReleaseResourceLite(&gDlpData.ConfigLock);
    KeLeaveCriticalRegion();

    return result;
}

BOOLEAN
DlpConfigScanFixed(VOID)
{
    BOOLEAN result;

    if (InterlockedCompareExchange(&gDlpData.ConfigValid, 0, 0) == 0) {
        return FALSE;   /* no config yet -> never attach to fixed volumes */
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&gDlpData.ConfigLock, TRUE);
    /* Back-compat gate: fixed volumes are attached ONLY when ScanFixed is set
     * AND a non-empty watch-set is present. Empty watch-set => removable-only. */
    result = (gDlpData.Config.ScanFixed != 0 && gDlpData.Config.WatchCount > 0);
    ExReleaseResourceLite(&gDlpData.ConfigLock);
    KeLeaveCriticalRegion();

    return result;
}

BOOLEAN
DlpConfigPathIsWatched(_In_ PCUNICODE_STRING Path)
{
    BOOLEAN matched = FALSE;
    ULONG i, count;

    if (Path == NULL || Path->Buffer == NULL || Path->Length == 0) {
        return FALSE;
    }
    if (InterlockedCompareExchange(&gDlpData.ConfigValid, 0, 0) == 0) {
        return FALSE;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceSharedLite(&gDlpData.ConfigLock, TRUE);

    count = gDlpData.Config.WatchCount;
    if (count > DLP_MAX_WATCH) {
        count = DLP_MAX_WATCH;
    }
    for (i = 0; i < count; i++) {
        USHORT wlen = gDlpData.Config.WatchLen[i];
        if (wlen == 0 || wlen > DLP_WATCH_PATH_CHARS) {
            continue;
        }
        if (DlpUnicodeContainsCI(Path, gDlpData.Config.Watch[i], wlen)) {
            matched = TRUE;
            break;
        }
    }

    ExReleaseResourceLite(&gDlpData.ConfigLock);
    KeLeaveCriticalRegion();

    return matched;
}


/* ------------------------------------------------------------------------- *
 *  Kernel -> user verdict request                                           *
 * ------------------------------------------------------------------------- */

/* Item 6: build a relative (negative) 100ns timeout from a millisecond value,
 * clamping the ms input to DLP_REPLY_TIMEOUT_MS_CEILING FIRST so the *10000
 * multiply into a LONGLONG can never overflow and a wedged agent can never pin
 * a file close longer than the ceiling. */
static VOID
DlpMakeTimeoutMs(_Out_ PLARGE_INTEGER Timeout, _In_ ULONG Milliseconds)
{
    if (Milliseconds > DLP_REPLY_TIMEOUT_MS_CEILING) {
        Milliseconds = DLP_REPLY_TIMEOUT_MS_CEILING;
    }
    Timeout->QuadPart = -((LONGLONG)Milliseconds * 10000LL);
}

NTSTATUS
DlpQueryVerdict(_In_ PUNICODE_STRING Path,
                _In_ ULONGLONG FileId,
                _In_ ULONG ProcessId,
                _In_reads_bytes_opt_(ContentLength) PVOID Content,
                _In_ ULONG ContentLength,
                _In_ BOOLEAN Truncated,
                _In_ ULONG Reason,
                _Out_ PBOOLEAN Block)
{
    NTSTATUS status;
    PDLP_SCAN_REQUEST request;
    DLP_SCAN_REPLY reply;
    ULONG replyLength = sizeof(DLP_SCAN_REPLY);
    LARGE_INTEGER timeout;
    USHORT copyBytes;
    ULONG contentBytes;
    ULONG senderLength;

    /* Fail-safe default before any work. Every early return below leaves *Block
     * at this FailMode value -- fail-SECURE per registry policy (never a
     * hardcoded allow), which is where ours deliberately differs from the old
     * driver's fail-open. */
    *Block = (gDlpData.FailMode == DLP_FAILMODE_BLOCK);

    /* A3: FltSendMessage waits -> PASSIVE_LEVEL only. The cleanup pre-op caller
     * is at PASSIVE, but assert/guard here so any future higher-IRQL call site
     * fails-secure loudly rather than stalling. */
    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);
    if (KeGetCurrentIrql() != PASSIVE_LEVEL) {
        return STATUS_INVALID_DEVICE_STATE;   /* *Block already FailMode */
    }

    if (gDlpData.ClientPort == NULL) {
        return STATUS_PORT_DISCONNECTED;   /* *Block already set from FailMode */
    }

    /* Item 3 (H5): circuit breaker. After DLP_BREAKER_THRESHOLD consecutive IPC
     * timeouts, stop up-calling and apply FailMode until a live reply (or an
     * agent reconnect) clears the counter -- an agent stall must never add the
     * IPC timeout to every single file close. */
    if (InterlockedCompareExchange(&gDlpData.ConsecutiveTimeouts, 0, 0) >=
        DLP_BREAKER_THRESHOLD) {
        return STATUS_PORT_DISCONNECTED;   /* *Block already FailMode */
    }

    /* Bound the content to the wire cap. The caller already reads at most
     * DLP_MAX_CONTENT bytes, but clamp defensively so the sender length can
     * never exceed sizeof(header)+cap. */
    contentBytes = ContentLength;
    if (contentBytes > DLP_MAX_CONTENT) {
        contentBytes = DLP_MAX_CONTENT;
    }
    if (Content == NULL) {
        contentBytes = 0;
    }

    /* The v2 sender buffer is [DLP_SCAN_REQUEST header][content bytes]. It can
     * be up to sizeof(header)+4 MiB, far too large for the stack -- allocate it
     * from NonPagedPoolNx. On alloc failure, fail-safe from FailMode. */
    senderLength = sizeof(DLP_SCAN_REQUEST) + contentBytes;
    /* ExAllocatePool2 is unavailable at this NTDDI baseline (the proven build
     * recipe pins the Win10 base); ExAllocatePoolWithTag(NonPagedPoolNx) is the
     * correct tagged non-paged alloc here. Suppress only the C4996 nudge. */
#pragma warning(suppress: 4996)
    request = (PDLP_SCAN_REQUEST)ExAllocatePoolWithTag(
        NonPagedPoolNx, senderLength, DLP_GENERAL_TAG);
    if (request == NULL) {
        return STATUS_INSUFFICIENT_RESOURCES;  /* *Block already FailMode */
    }

    /* Build the request header. Path is copied inline, bounded to
     * DLP_MAX_PATH_CHARS; over-long paths are truncated and the truncation is
     * inherently visible to the service (PathLength < full name). The content
     * (read in-kernel by the caller) is appended after the header. */
    RtlZeroMemory(request, sizeof(DLP_SCAN_REQUEST));
    request->Version = DLP_MSG_VERSION;
    /* Repurposed Reserved field (offset 4): the scan reason. No wire size
     * change; the Rust mirror renames the same u32 reserved->reason. */
    request->Reserved = Reason;
    request->FileId = FileId;
    request->ProcessId = ProcessId;

    copyBytes = Path->Length;
    if (copyBytes > sizeof(request->Path)) {
        copyBytes = sizeof(request->Path);
    }
    if (Path->Buffer != NULL && copyBytes > 0) {
        RtlCopyMemory(request->Path, Path->Buffer, copyBytes);
    }
    request->PathLength = copyBytes;
    request->Pad = 0;
    request->ContentLength = contentBytes;
    request->Truncated = Truncated ? 1 : 0;

    if (contentBytes > 0) {
        /* Append content immediately after the fixed header. */
        RtlCopyMemory((PUCHAR)request + sizeof(DLP_SCAN_REQUEST),
                      Content, contentBytes);
    }

    RtlZeroMemory(&reply, sizeof(reply));
    DlpMakeTimeoutMs(&timeout, DLP_REPLY_TIMEOUT_MS);   /* item 6: clamped */

    /* Item 2 (A4): bracket the send in rundown protection so Unload can drain
     * an in-flight FltSendMessage before it closes the ports / unregisters. If
     * the acquire fails the driver is unloading -> fail-secure per FailMode.
     * The send passes &gDlpData.ClientPort (the GLOBAL) so FltCloseClientPort's
     * NULL-on-close deterministically unblocks a send waiting here. */
    if (!ExAcquireRundownProtection(&gDlpData.SendRundown)) {
        ExFreePoolWithTag(request, DLP_GENERAL_TAG);
        return STATUS_PORT_DISCONNECTED;   /* *Block already FailMode */
    }

    status = FltSendMessage(
        gDlpData.Filter,
        &gDlpData.ClientPort,
        request, senderLength,
        &reply, &replyLength,
        &timeout);

    ExReleaseRundownProtection(&gDlpData.SendRundown);

    ExFreePoolWithTag(request, DLP_GENERAL_TAG);

    /* Item 3 (H5): STATUS_TIMEOUT is an NT_SUCCESS code -- branch on it
     * explicitly and count it toward the breaker. FailMode already governs
     * *Block, so a stalled agent fails-secure per policy. */
    if (status == STATUS_TIMEOUT) {
        InterlockedIncrement(&gDlpData.ConsecutiveTimeouts);
        return STATUS_TIMEOUT;   /* *Block already FailMode */
    }
    if (!NT_SUCCESS(status)) {
        return status;           /* disconnect mid-flight etc.; *Block FailMode */
    }

    /* A live reply proves the agent is healthy -- clear the breaker. */
    InterlockedExchange(&gDlpData.ConsecutiveTimeouts, 0);

    /* Item 5: validate the reply BEFORE trusting the verdict. The reply carries
     * no version field (the frozen v2 protocol must not change), so validate
     * exact length + the echoed FileId instead, and require a known verdict.
     * Any mismatch falls back to FailMode (fail-secure). */
    if (replyLength != sizeof(DLP_SCAN_REPLY)) {
        return STATUS_INVALID_PARAMETER;   /* *Block already FailMode */
    }
    if (reply.FileId != FileId) {
        return STATUS_INVALID_PARAMETER;   /* stale/misrouted reply */
    }
    if (reply.Verdict == DLP_VERDICT_NOVERDICT) {
        /* The agent has NO verdict for this content (e.g. no verified bundle yet —
         * the startup blind window). Return a non-success status so the caller
         * (DlpExfilClassifyAndCache) fails safe per ExfilReadFailBlock AND seeds
         * NOTHING: an un-scored file must never be cached clean. Does NOT count
         * toward the IPC timeout breaker (a live reply already cleared it above). */
        return STATUS_NOT_FOUND;
    }
    if (reply.Verdict != DLP_VERDICT_ALLOW && reply.Verdict != DLP_VERDICT_BLOCK) {
        return STATUS_INVALID_PARAMETER;   /* unknown verdict -> FailMode */
    }

    /* Honor the validated service verdict. */
    *Block = (reply.Verdict == DLP_VERDICT_BLOCK);
    return STATUS_SUCCESS;
}


/* ------------------------------------------------------------------------- *
 *  FailMode from the service registry key (SPEC 2.3)                        *
 * ------------------------------------------------------------------------- */
VOID
DlpReadFailMode(_In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;
    HANDLE key = NULL;
    UNICODE_STRING valueName;
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)] = { 0 };
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    ULONG resultLength = 0;

    PAGED_CODE();

    /* Default already set by DriverEntry; only override if the value is
     * present and valid. */
    InitializeObjectAttributes(&oa, RegistryPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    status = ZwOpenKey(&key, KEY_READ, &oa);
    if (!NT_SUCCESS(status)) {
        return;
    }

    RtlInitUnicodeString(&valueName, L"FailMode");
    status = ZwQueryValueKey(key, &valueName, KeyValuePartialInformation,
                             buffer, sizeof(buffer), &resultLength);
    if (NT_SUCCESS(status) &&
        info->Type == REG_DWORD &&
        info->DataLength == sizeof(ULONG)) {
        ULONG value = *(PULONG)info->Data;
        gDlpData.FailMode =
            (value == DLP_FAILMODE_BLOCK) ? DLP_FAILMODE_BLOCK : DLP_FAILMODE_ALLOW;
    }

    ZwClose(key);
}

/* Read one REG_DWORD from the open key into *Out; leaves *Out unchanged if the
 * value is absent or not a DWORD. Helper for DlpReadExfilPolicy. */
static VOID
DlpReadDword(_In_ HANDLE Key, _In_ PCWSTR Name, _Inout_ PULONG Out)
{
    NTSTATUS status;
    UNICODE_STRING valueName;
    UCHAR buffer[sizeof(KEY_VALUE_PARTIAL_INFORMATION) + sizeof(ULONG)] = { 0 };
    PKEY_VALUE_PARTIAL_INFORMATION info = (PKEY_VALUE_PARTIAL_INFORMATION)buffer;
    ULONG resultLength = 0;

    RtlInitUnicodeString(&valueName, Name);
    status = ZwQueryValueKey(Key, &valueName, KeyValuePartialInformation,
                             buffer, sizeof(buffer), &resultLength);
    if (NT_SUCCESS(status) &&
        info->Type == REG_DWORD &&
        info->DataLength == sizeof(ULONG)) {
        *Out = *(PULONG)info->Data;
    }
}

VOID
DlpReadExfilPolicy(_In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;
    HANDLE key = NULL;
    ULONG enabled = DLP_EXFILREAD_DISABLED;
    ULONG failBlock = 1;                    /* default: deny unverifiable content */

    PAGED_CODE();

    /* Defaults already set by DriverEntry (disabled + fail-block). Only override
     * from explicit, valid REG_DWORD values -- an absent key keeps read-deny OFF. */
    InitializeObjectAttributes(&oa, RegistryPath,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    status = ZwOpenKey(&key, KEY_READ, &oa);
    if (!NT_SUCCESS(status)) {
        return;
    }

    DlpReadDword(key, L"ExfilReadBlockEnabled", &enabled);
    DlpReadDword(key, L"ExfilReadFailBlock", &failBlock);

    ZwClose(key);

    gDlpData.ExfilReadBlockEnabled =
        (enabled == DLP_EXFILREAD_ENABLED) ? DLP_EXFILREAD_ENABLED
      : (enabled == DLP_EXFILREAD_MONITOR) ? DLP_EXFILREAD_MONITOR
                                           : DLP_EXFILREAD_DISABLED;
    gDlpData.ExfilReadFailBlock = (failBlock != 0) ? 1u : 0u;
}
