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
connection (SPEC 2.3). No secrets cross the port; only a file path + metadata.

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
        DlpPortMessage,             /* user->kernel: DLP_CONFIG scan scope */
        1);                         /* max connections = 1 (SPEC 2.3) */

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
static NTSTATUS FLTAPI
DlpPortConnect(_In_ PFLT_PORT ClientPort,
               _In_opt_ PVOID ServerPortCookie,
               _In_reads_bytes_opt_(SizeOfContext) PVOID ConnectionContext,
               _In_ ULONG SizeOfContext,
               _Outptr_result_maybenull_ PVOID *ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);

    PAGED_CODE();

    /* Record the connected client port and its PID. ConnectNotify runs in the
     * connecting process's context, so PsGetCurrentProcessId() is the service
     * PID we self-skip on (SPEC 2.4). The service MUST be the connecting
     * process (dlp-agent usb-guard). */
    gDlpData.ClientPort = ClientPort;
    InterlockedExchange(&gDlpData.ServicePid,
                        (LONG)(ULONG_PTR)PsGetCurrentProcessId());

    *ConnectionPortCookie = NULL;
    return STATUS_SUCCESS;
}

static VOID FLTAPI
DlpPortDisconnect(_In_opt_ PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    PAGED_CODE();

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

    *ReturnOutputBufferLength = 0;

    /* Only a full DLP_CONFIG is accepted; nothing else. */
    if (InputBuffer == NULL || InputBufferLength < sizeof(DLP_CONFIG)) {
        return STATUS_INVALID_PARAMETER;
    }

    KeEnterCriticalRegion();
    ExAcquireResourceExclusiveLite(&gDlpData.ConfigLock, TRUE);

    __try {
        PDLP_CONFIG in = (PDLP_CONFIG)InputBuffer;

        ProbeForRead(InputBuffer, sizeof(DLP_CONFIG), __alignof(ULONG));

        if (in->Version != DLP_CONFIG_VERSION || in->WatchCount > DLP_MAX_WATCH) {
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

/* Case-insensitive test: does haystack contain the needle substring?
 * RtlUpcaseUnicodeChar is a table lookup callable at any IRQL, so this is safe
 * under the shared lock. Bounded by path length * needle length. */
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
            return TRUE;
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
NTSTATUS
DlpQueryVerdict(_In_ PUNICODE_STRING Path,
                _In_ ULONGLONG FileId,
                _In_ ULONG ProcessId,
                _Out_ PBOOLEAN Block)
{
    NTSTATUS status;
    DLP_SCAN_REQUEST request;
    DLP_SCAN_REPLY reply;
    ULONG replyLength = sizeof(DLP_SCAN_REPLY);
    LARGE_INTEGER timeout;
    USHORT copyBytes;

    /* Fail-safe default before any work. */
    *Block = (gDlpData.FailMode == DLP_FAILMODE_BLOCK);

    if (gDlpData.ClientPort == NULL) {
        return STATUS_PORT_DISCONNECTED;   /* *Block already set from FailMode */
    }

    /* Build the request. Path is copied inline, bounded to DLP_MAX_PATH_CHARS;
     * over-long paths are truncated and the truncation is inherently visible to
     * the service (PathLength < full name). Contents are NEVER sent. */
    RtlZeroMemory(&request, sizeof(request));
    request.Version = DLP_MSG_VERSION;
    request.Reserved = 0;
    request.FileId = FileId;
    request.ProcessId = ProcessId;

    copyBytes = Path->Length;
    if (copyBytes > sizeof(request.Path)) {
        copyBytes = sizeof(request.Path);
    }
    if (Path->Buffer != NULL && copyBytes > 0) {
        RtlCopyMemory(request.Path, Path->Buffer, copyBytes);
    }
    request.PathLength = copyBytes;

    RtlZeroMemory(&reply, sizeof(reply));
    timeout.QuadPart = DLP_REPLY_TIMEOUT_100NS;

    status = FltSendMessage(
        gDlpData.Filter,
        &gDlpData.ClientPort,
        &request, sizeof(request),
        &reply, &replyLength,
        &timeout);

    if (status == STATUS_SUCCESS && replyLength >= sizeof(DLP_SCAN_REPLY)) {
        /* Honor the service's verdict. */
        *Block = (reply.Verdict == DLP_VERDICT_BLOCK);
        return STATUS_SUCCESS;
    }

    /* STATUS_TIMEOUT, disconnect mid-flight, or a short/garbled reply: apply
     * FailMode. *Block is already the FailMode default; keep it. */
    return (status == STATUS_SUCCESS) ? STATUS_UNSUCCESSFUL : status;
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
