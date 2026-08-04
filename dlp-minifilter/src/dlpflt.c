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

static BOOLEAN DlpVolumeIsRemovable(_In_ PFLT_VOLUME Volume);
static BOOLEAN DlpIsServiceRequestor(_In_ PFLT_CALLBACK_DATA Data);
static NTSTATUS DlpQuarantineFile(_In_ PCFLT_RELATED_OBJECTS FltObjects);
static VOID DlpInspectStream(_Inout_ PFLT_CALLBACK_DATA Data,
                             _In_ PCFLT_RELATED_OBJECTS FltObjects,
                             _In_ PDLP_STREAM_CONTEXT Ctx,
                             _In_ ULONG VolumeClass);

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
    { IRP_MJ_WRITE,           0, DlpPreWrite,             NULL          },
    { IRP_MJ_CLEANUP,         0, DlpPreCleanup,           NULL          },
    { IRP_MJ_SET_INFORMATION, 0, DlpPreSetInformation,    NULL          },
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

    /* Scan-scope config lock. Initialize BEFORE FltStartFiltering so any early
     * InstanceSetup/CLEANUP that reads the config finds a valid lock. Until a
     * DLP_CONFIG message arrives, ConfigValid is 0 => removable-only. */
    status = ExInitializeResourceLite(&gDlpData.ConfigLock);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    gDlpData.ConfigLockInit = TRUE;

    /* Read the deployment's FailMode from the service registry key. */
    DlpReadFailMode(RegistryPath);

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

    status = FltStartFiltering(gDlpData.Filter);
    if (!NT_SUCCESS(status)) {
        DlpCloseCommunicationPort();
        FltUnregisterFilter(gDlpData.Filter);
        gDlpData.Filter = NULL;
        ExDeleteResourceLite(&gDlpData.ConfigLock);
        gDlpData.ConfigLockInit = FALSE;
        return status;
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

    DlpCloseCommunicationPort();

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
 *  Self-skip helper (SPEC 2.4)                                             *
 * ------------------------------------------------------------------------- */
static BOOLEAN
DlpIsServiceRequestor(_In_ PFLT_CALLBACK_DATA Data)
{
    LONG servicePid = InterlockedCompareExchange(&gDlpData.ServicePid, 0, 0);
    if (servicePid == 0) {
        return FALSE;   /* no client connected */
    }
    return (LONG)(ULONG_PTR)FltGetRequestorProcessId(Data) == servicePid;
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

    /* Self-skip: never track the service's own opens (SPEC 2.4). */
    if (DlpIsServiceRequestor(Data)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* Skip paging I/O and non-file targets. */
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO) ||
        FlagOn(Data->Iopb->IrpFlags, IRP_SYNCHRONOUS_PAGING_IO)) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* Skip volume-open (no file object / stream). */
    if (FltObjects->FileObject == NULL) {
        return FLT_POSTOP_FINISHED_PROCESSING;
    }

    /* Skip directory opens -- we only score files (SPEC 2.2). */
    status = FltIsDirectory(FltObjects->FileObject, FltObjects->Instance, &isDirectory);
    if (NT_SUCCESS(status) && isDirectory) {
        return FLT_POSTOP_FINISHED_PROCESSING;
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

    if (DlpIsServiceRequestor(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (FltObjects->FileObject == NULL) {
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

    if (DlpIsServiceRequestor(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (FltObjects->FileObject == NULL) {
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

    /* Self-skip FIRST -- the service reads files to fingerprint them, which
     * generates cleanup on our volume; scanning that would deadlock (SPEC 2.4).
     * Now critical on FIXED/NETWORK too, where the service reads watched files
     * on C:/shares. */
    if (DlpIsServiceRequestor(Data)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (FltObjects->FileObject == NULL) {
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

    /* Fixed-volume quick-reject: only inspect files under a configured watch
     * prefix. Removable/network fall through and inspect everything. An
     * unwatched fixed-volume write is simply released -- no verdict query. */
    if (VolumeClass == DLP_VOL_FIXED &&
        !DlpConfigPathIsWatched(&nameInfo->Name)) {
        FltReleaseFileNameInformation(nameInfo);
        return;
    }

    /* Ask the service (path + metadata only). On any failure DlpQueryVerdict
     * sets `block` from FailMode. */
    (VOID)DlpQueryVerdict(&nameInfo->Name, fileId, pid, &block);

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
