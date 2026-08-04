/*++

dlpflt.h  --  DLP filesystem minifilter, shared header.

This header defines the message contract carried over the filter communication
port \DlpFltPort (SPEC section 4). The two message-payload structs
(DLP_SCAN_REQUEST / DLP_SCAN_REPLY) are the ONLY thing shared with the
user-mode client: the Rust agent (dlp-agent/src/kguard) mirrors them with
#[repr(C)]. Keep the two definitions byte-for-byte in sync and bump Version on
any layout change.

The remaining declarations (guarded by _KERNEL_MODE) are internal to the driver
and are consumed by dlpflt.c and comms.c only.

--*/

#ifndef DLPFLT_H
#define DLPFLT_H

/* Base Windows integer/WCHAR types for the shared structs below. In the driver
 * these come from fltKernel.h; a hypothetical user-mode C consumer pulls them
 * from windows.h. (The Rust client does NOT include this header -- it mirrors
 * the structs with #[repr(C)].) */
#ifdef _KERNEL_MODE
#include <fltKernel.h>
#else
#include <windows.h>
#endif

/* ------------------------------------------------------------------------- *
 *  Shared port message contract (SPEC section 4)                            *
 *  Fixed layout; mirrored on the Rust side with #[repr(C)].                 *
 * ------------------------------------------------------------------------- */

/* Wire protocol version. Bump on ANY change to the structs below. */
#define DLP_MSG_VERSION      1

/* Verdict values carried in DLP_SCAN_REPLY.Verdict. */
#define DLP_VERDICT_ALLOW    0
#define DLP_VERDICT_BLOCK    1

/* Max path length (in WCHARs) carried inline in a scan request. Paths longer
 * than this are truncated by the driver; the truncation is flagged so the
 * service can fail-safe. 512 WCHARs comfortably covers a \Device\... name. */
#define DLP_MAX_PATH_CHARS   512

/* ------------------------------------------------------------------------- *
 *  Shared scan-scope config contract (user -> kernel, Tier-1 extension)     *
 *                                                                           *
 *  Sent user->kernel via FilterSendMessage and received by the driver's     *
 *  message-notify callback (comms.c). It widens the driver from             *
 *  removable-only to also inspecting fixed-volume WATCH PATHS and network    *
 *  (SMB) volumes. It is CONFIG, not file content: watch prefixes describe    *
 *  WHERE to look, never WHAT was found -- the "no content over the port"     *
 *  invariant (path + metadata only for verdicts) is unchanged.              *
 *                                                                           *
 *  This message has its OWN version (DLP_CONFIG_VERSION), independent of     *
 *  DLP_MSG_VERSION which governs the kernel->user scan request/reply. The    *
 *  scan request/reply layout is frozen (mirrored in the Rust kguard and     *
 *  size-locked there); do NOT bump DLP_MSG_VERSION for this addition.        *
 * ------------------------------------------------------------------------- */

/* Config-message version. Bump on any DLP_CONFIG layout change. */
#define DLP_CONFIG_VERSION   1

/* Maximum number of watch prefixes carried in one config message. */
#define DLP_MAX_WATCH        16

/* Maximum length (in WCHARs) of one watch prefix, e.g. \Users\alice\OneDrive. */
#define DLP_WATCH_PATH_CHARS 260

#pragma pack(push, 8)

/* Kernel -> user: "please score this file". Carries the path + metadata only,
 * NEVER file contents (SPEC 2.4 / 6): the service opens and reads the file. */
typedef struct _DLP_SCAN_REQUEST {
    ULONG     Version;                    /* = DLP_MSG_VERSION                */
    ULONG     Reserved;                   /* alignment / future flags         */
    ULONGLONG FileId;                     /* correlation id (per request)     */
    ULONG     ProcessId;                  /* requestor PID (for the reviewer) */
    USHORT    PathLength;                 /* valid bytes in Path (<= sizeof)  */
    WCHAR     Path[DLP_MAX_PATH_CHARS];   /* NT device path, NOT NUL-required */
} DLP_SCAN_REQUEST, *PDLP_SCAN_REQUEST;

/* User -> kernel: the verdict for a given FileId. */
typedef struct _DLP_SCAN_REPLY {
    ULONGLONG FileId;                     /* echoes the request FileId        */
    ULONG     Verdict;                    /* DLP_VERDICT_ALLOW | _BLOCK       */
} DLP_SCAN_REPLY, *PDLP_SCAN_REPLY;

/* User -> kernel: scan-scope configuration (Tier-1 extension). Pinned layout,
 * mirrored on the Rust side with #[repr(C)] and size-locked. Field order +
 * natural alignment give a stable 8368-byte struct:
 *   Version(4) ScanFixed(4) ScanNetwork(4) WatchCount(4)          @  0..16
 *   WatchLen[16] (USHORT*16 = 32)                                 @ 16..48
 *   Watch[16][260] (WCHAR = 16*260*2 = 8320)                      @ 48..8368
 * All members are <= 4-byte aligned, so #pragma pack(8) adds no padding.
 *
 * Empty config (WatchCount == 0, ScanFixed == 0) == today's removable-only
 * behavior (backward compatible): fixed volumes are not attached, network
 * volumes are attached only if ScanNetwork is set. */
typedef struct _DLP_CONFIG {
    ULONG  Version;                              /* = DLP_CONFIG_VERSION       */
    ULONG  ScanFixed;                            /* bool: inspect fixed watch  */
    ULONG  ScanNetwork;                          /* bool: inspect SMB volumes  */
    ULONG  WatchCount;                           /* active prefixes (<= 16)    */
    USHORT WatchLen[DLP_MAX_WATCH];              /* wchar length of each prefix*/
    WCHAR  Watch[DLP_MAX_WATCH][DLP_WATCH_PATH_CHARS]; /* case-insensitive      */
} DLP_CONFIG, *PDLP_CONFIG;

#pragma pack(pop)


/* ------------------------------------------------------------------------- *
 *  Internal driver declarations (kernel only)                               *
 * ------------------------------------------------------------------------- */
#ifdef _KERNEL_MODE

/* Communication port name (SPEC 2.3). Secured to Admin/SYSTEM, max 1 conn. */
#define DLP_PORT_NAME        L"\\DlpFltPort"

/* Fail mode (SPEC 2.3): what to do when the service is absent / times out.
 *   0 = allow + audit (machine stays usable; recommended for general use)
 *   1 = block         (fail-secure; recommended for classified sites)     */
#define DLP_FAILMODE_ALLOW   0
#define DLP_FAILMODE_BLOCK   1

/* How long the kernel waits for a user-mode verdict before applying FailMode
 * (relative 100ns units; 10 seconds). Bounded so a wedged/hung service can
 * never hang a file close indefinitely. */
#define DLP_REPLY_TIMEOUT_100NS  (-10LL * 1000LL * 1000LL * 10LL)

/* Stream-context pool tag ('DlpS' -> 'SplD' on a little-endian dump). */
#define DLP_STREAM_CONTEXT_TAG   'SplD'
#define DLP_INSTANCE_CONTEXT_TAG 'IplD'
#define DLP_GENERAL_TAG          'GplD'

/* Per-stream state (SPEC 2.2). Allocated from NonPagedPoolNx. A stream becomes
 * a scan candidate when opened for write; WRITE marks it Dirty; CLEANUP
 * inspects a dirty candidate exactly once. */
typedef struct _DLP_STREAM_CONTEXT {
    volatile LONG WriteCandidate;   /* opened with write access             */
    volatile LONG Dirty;            /* data written, or renamed-in          */
    volatile LONG Inspected;        /* CLEANUP already handled this stream  */
} DLP_STREAM_CONTEXT, *PDLP_STREAM_CONTEXT;

/* Volume classification recorded at InstanceSetup so CLEANUP can branch
 * cheaply without re-querying the volume (Tier-1 extension). */
#define DLP_VOL_REMOVABLE   1   /* inspect every dirty candidate            */
#define DLP_VOL_NETWORK     2   /* inspect every dirty candidate            */
#define DLP_VOL_FIXED       3   /* inspect only files under a watch prefix  */

/* Per-instance context (Tier-1 extension). One per attached volume; lets the
 * hot CLEANUP path know the volume class without a fresh volume query. */
typedef struct _DLP_INSTANCE_CONTEXT {
    ULONG VolumeClass;              /* DLP_VOL_REMOVABLE | _NETWORK | _FIXED */
} DLP_INSTANCE_CONTEXT, *PDLP_INSTANCE_CONTEXT;

/* Global driver state. Defined in dlpflt.c; the port fields are managed in
 * comms.c. */
typedef struct _DLP_FLT_DATA {
    PDRIVER_OBJECT DriverObject;
    PFLT_FILTER    Filter;

    /* Communication port (comms.c). */
    PFLT_PORT      ServerPort;      /* listening port                        */
    PFLT_PORT      ClientPort;      /* the one connected client (max 1)      */

    /* Self-skip (SPEC 2.4): PID of the connected service. Any I/O from this
     * PID is passed through untouched so the service's own file reads never
     * recurse back into us. 0 = no client connected. */
    volatile LONG  ServicePid;

    /* Fail mode, read from the service registry key at DriverEntry. */
    ULONG          FailMode;

    /* Scan-scope config (comms.c), delivered user->kernel via a DLP_CONFIG
     * message. ConfigValid gates readers; ConfigLock (an ERESOURCE, so
     * acquisition stays at PASSIVE_LEVEL) guards Config for one writer / many
     * readers. Empty/absent => removable-only behavior (back-compat). */
    ERESOURCE      ConfigLock;      /* guards Config; PASSIVE-level primitive */
    BOOLEAN        ConfigLockInit;  /* ConfigLock was ExInitializeResourceLite'd */
    volatile LONG  ConfigValid;     /* a valid DLP_CONFIG has been stored     */
    DLP_CONFIG     Config;          /* watch prefixes + ScanFixed/ScanNetwork */
} DLP_FLT_DATA, *PDLP_FLT_DATA;

extern DLP_FLT_DATA gDlpData;

/* ---- comms.c ---------------------------------------------------------- */

/* Create / tear down the communication port. */
NTSTATUS DlpCreateCommunicationPort(_In_ PFLT_FILTER Filter);
VOID     DlpCloseCommunicationPort(VOID);

/* Ask the connected service for a verdict on one file. On any failure (no
 * client, timeout, send error) *Block is set from FailMode and a non-success
 * status is returned; callers must still honor *Block. Never crashes. */
NTSTATUS DlpQueryVerdict(_In_ PUNICODE_STRING Path,
                         _In_ ULONGLONG FileId,
                         _In_ ULONG ProcessId,
                         _Out_ PBOOLEAN Block);

/* Read FailMode from the driver's service registry path (DriverEntry). */
VOID     DlpReadFailMode(_In_ PUNICODE_STRING RegistryPath);

/* ---- comms.c: scan-scope config accessors (Tier-1 extension) ---------- *
 * All read the config stored by the DLP_CONFIG message-notify callback.
 * Safe to call at PASSIVE_LEVEL (they take ConfigLock shared). Before any
 * config is received they report the removable-only defaults. */

/* Attach to network (SMB) volumes? TRUE only if a valid config set ScanNetwork. */
BOOLEAN  DlpConfigScanNetwork(VOID);

/* Attach to fixed volumes? TRUE only if a valid config set ScanFixed AND
 * supplied a non-empty watch-set (WatchCount > 0) -- the back-compat gate. */
BOOLEAN  DlpConfigScanFixed(VOID);

/* Is Path (a normalized NT name) under any configured watch prefix?
 * Case-insensitive. FALSE when no config / empty watch-set. */
BOOLEAN  DlpConfigPathIsWatched(_In_ PCUNICODE_STRING Path);

#endif /* _KERNEL_MODE */

#endif /* DLPFLT_H */
