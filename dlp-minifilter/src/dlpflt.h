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
#define DLP_MSG_VERSION      2

/* Verdict values carried in DLP_SCAN_REPLY.Verdict. */
#define DLP_VERDICT_ALLOW    0
#define DLP_VERDICT_BLOCK    1

/* Scan reason carried in DLP_SCAN_REQUEST.Reserved (repurposed as "Reason";
 * NO wire layout change -- offset 4 was already an unused reserved ULONG that
 * the Rust mirror declares and size-locks). Backward compatible: an old client
 * ignores Reserved (still scores + replies), and Reason==0 is the legacy value.
 *   WRITE = the original write/quarantine scan (the old zero value of Reserved)
 *   READ  = a read-taint scan (the driver taints the PID on a BLOCK reply and
 *           the new client additionally tears down the PID's open TCP flows).  */
#define DLP_REASON_WRITE     0
#define DLP_REASON_READ      1

/* Max path length (in WCHARs) carried inline in a scan request. Paths longer
 * than this are truncated by the driver; the truncation is flagged so the
 * service can fail-safe. 512 WCHARs comfortably covers a \Device\... name. */
#define DLP_MAX_PATH_CHARS   512

/* Max bytes of file content carried inline after the request header (v2).
 * The driver reads the stream IN-KERNEL (it is already inside the FS stack, so
 * there is no sharing conflict against a process that holds the file locked)
 * and appends up to this many bytes to the scan request. Files larger than the
 * cap are truncated to the first DLP_MAX_CONTENT bytes and flagged Truncated;
 * the service fingerprints exactly the bytes it receives. 4 MiB. */
#define DLP_MAX_CONTENT      (4 * 1024 * 1024)

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

/* Kernel -> user: "please score this file". Fixed header FOLLOWED IN THE SAME
 * message buffer by ContentLength bytes of file content (v2).
 *
 * The driver reads the stream in-kernel (from inside the FS stack, offset 0,
 * up to DLP_MAX_CONTENT bytes) and ships those bytes so the service can
 * fingerprint them WITHOUT re-opening the file -- a re-open races the copier's
 * exclusive CLEANUP lock and hits a sharing violation. Path is retained for
 * logging / incident correlation only; it is NOT how the content is obtained.
 *
 * Message layout in the sender buffer:
 *   [DLP_SCAN_REQUEST header][ContentLength bytes of file content]
 * Total sender size = sizeof(DLP_SCAN_REQUEST) + ContentLength. */
typedef struct _DLP_SCAN_REQUEST {
    ULONG     Version;                    /* = DLP_MSG_VERSION (= 2)          */
    ULONG     Reserved;                   /* alignment / future flags         */
    ULONGLONG FileId;                     /* correlation id (per request)     */
    ULONG     ProcessId;                  /* requestor PID (for the reviewer) */
    USHORT    PathLength;                 /* valid bytes in Path (<= sizeof)  */
    USHORT    Pad;                        /* explicit padding (keep 8-align)  */
    WCHAR     Path[DLP_MAX_PATH_CHARS];   /* NT device path, NOT NUL-required */
    ULONG     ContentLength;              /* bytes of content that FOLLOW this
                                           * header (<= DLP_MAX_CONTENT; may 0)*/
    ULONG     Truncated;                  /* 1 if the file exceeded the cap
                                           * (content is the first cap bytes) */
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

/* ------------------------------------------------------------------------- *
 *  Exfil-channel PID set (user -> kernel; read-deny feature, read-deny-LLD)  *
 *                                                                           *
 *  The AGENT owns the definition of "exfil channel" (a remote-access tool by *
 *  signature, OR a process holding a live non-local TCP connection) because  *
 *  signature + connection-table correlation is trivial in user mode. It      *
 *  pushes the resulting PID set here on a short interval; the driver's        *
 *  DlpPreRead consults it to decide whether to content-inspect + deny a read. *
 *  Full-replace each message. Its OWN version, independent of DLP_MSG_VERSION *
 *  and DLP_CONFIG_VERSION.                                                    *
 * ------------------------------------------------------------------------- */

/* Exfil-set message version. This doubles as a MAGIC that discriminates the
 * message from DLP_CONFIG (whose first ULONG is DLP_CONFIG_VERSION == 1) on the
 * shared port: the message-notify callback branches on the first ULONG, so this
 * MUST NOT collide with any DLP_CONFIG_VERSION. ("DlpX" bytes). */
#define DLP_EXFIL_VERSION    0x58706C44u   /* 'D''l''p''X' */
/* Max PIDs carried in one full-replace update. */
#define DLP_EXFIL_MSG_MAX    1024

/* User -> kernel: the current set of exfil-channel PIDs. */
typedef struct _DLP_EXFIL_UPDATE {
    ULONG Version;                        /* = DLP_EXFIL_VERSION                 */
    ULONG Count;                          /* valid entries (<= DLP_EXFIL_MSG_MAX)*/
    ULONG Pids[DLP_EXFIL_MSG_MAX];        /* the exfil-channel PIDs              */
} DLP_EXFIL_UPDATE, *PDLP_EXFIL_UPDATE;

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
 * never hang a file close indefinitely. Retained for back-compat; the runtime
 * path now derives its timeout from DLP_REPLY_TIMEOUT_MS via DlpMakeTimeoutMs
 * (item 6: clamp the ms input before the LONGLONG multiply). */
#define DLP_REPLY_TIMEOUT_100NS  (-10LL * 1000LL * 1000LL * 10LL)

/* IPC reply timeout, in milliseconds (item 6). Default 500 ms; DlpMakeTimeoutMs
 * clamps to DLP_REPLY_TIMEOUT_MS_CEILING so the 100ns multiply cannot overflow
 * and a wedged agent can never pin a file close for longer than the ceiling. */
#define DLP_REPLY_TIMEOUT_MS          500u
#define DLP_REPLY_TIMEOUT_MS_CEILING  60000u   /* 60 s hard ceiling */

/* Circuit-breaker threshold (item 3, H5). After this many consecutive IPC
 * timeouts the driver stops up-calling and applies FailMode until a live reply
 * (or agent reconnect) clears the counter -- an agent stall never adds the IPC
 * timeout to every single file close. */
#define DLP_BREAKER_THRESHOLD    8

/* Known-bad content-hash fast path (item 10). Bounded ring of SHA-256 digests
 * of content that the agent BLOCKED; a later copy of the same bytes blocks in
 * kernel with no user-mode round-trip. Cleared implicitly by the epoch stamp. */
#define DLP_BADHASH_MAX          256
#define DLP_SHA256_LEN           32

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
    volatile LONG Epoch;            /* gDlpData.Epoch snapshot (item 4)     */
    /* Read-taint: 0 = unseen, 1 = the first substantial read of this stream
     * has already been claimed and enqueued for an async taint scan, so later
     * reads of the same stream do NOT re-enqueue (claim-once, interlocked). */
    volatile LONG ReadScanState;
    /* Read-deny per-open verdict cache (DlpPreRead). A file transfer issues many
     * reads on ONE open; we classify the content ONCE and cache the verdict here
     * so every subsequent read of the same open is an O(1) branch (no re-read, no
     * re-up-call). Interlocked. */
    volatile LONG ExfilVerdict;     /* DLP_EXFIL_UNKNOWN | _DENY | _ALLOW */
} DLP_STREAM_CONTEXT, *PDLP_STREAM_CONTEXT;

/* DLP_STREAM_CONTEXT.ExfilVerdict states. */
#define DLP_EXFIL_UNKNOWN   0       /* not yet classified for this open          */
#define DLP_EXFIL_DENY      1       /* sensitive -> deny reads by an exfil PID    */
#define DLP_EXFIL_ALLOW     2       /* clean -> allow                             */

/* Known-bad content-hash entry (item 10). One SHA-256 of content the agent
 * blocked, stamped with the epoch it was recorded under; a stale-epoch entry is
 * treated as absent (implicit clear on agent reconnect). */
typedef struct _DLP_BADHASH_ENTRY {
    UCHAR Sha[DLP_SHA256_LEN];      /* raw SHA-256 of the shipped bytes      */
    LONG  Epoch;                    /* epoch this entry was inserted under   */
    BOOLEAN Valid;                  /* slot occupied                         */
} DLP_BADHASH_ENTRY, *PDLP_BADHASH_ENTRY;

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

/* ========================================================================= *
 *  Read-taint network-egress blocking (READTAINT-DECISION-BRIEF / LLD)      *
 *                                                                           *
 *  On a process's first substantial READ of a watched file we enqueue an    *
 *  async scan; a BLOCK verdict TAINTS the requestor PID. A WFP callout at    *
 *  ALE_AUTH_CONNECT_V4/V6 then blocks that tainted PID's outbound            *
 *  connections -- content-blind, so it works over TLS / AnyDesk / a         *
 *  malware socket. All state hangs off gDlpData so its lifetime tracks the   *
 *  driver. Everything below is gated by ReadTaintEnabled (registry, default  *
 *  0 = today's FS-only behavior).                                           *
 * ------------------------------------------------------------------------- */

/* Master switch (registry DWORD "ReadTaintEnabled", read in DriverEntry). */
#define DLP_READTAINT_DISABLED   0
#define DLP_READTAINT_ENABLED    1

/* What a tainted PID's egress does (registry DWORD "TaintedEgressPolicy"). */
#define DLP_TEP_BLOCK_ALL        0   /* block ALL outbound (default, fail-secure) */
#define DLP_TEP_BLOCK_NONLOCAL   1   /* permit RFC1918/loopback, block the rest   */

/* Bounds. The taint table and sensfile cache mirror the BadHash ring exactly
 * (bounded, spinlock, epoch). The scan queue is bounded so a read flood can
 * never grow non-paged pool without limit (excess jobs are dropped = a miss,
 * fail-safe toward not deadlocking). */
#define DLP_TAINT_MAX            1024
#define DLP_SENSFILE_MAX         512
/* Known-clean file-id cache (read-deny). Larger than SensFile: an exfil PID
 * (e.g. a browser holding a public connection) opens many innocent files under
 * the watch scope; caching "clean" cross-open bounds the classify up-call load to
 * one call per distinct file instead of one per open. */
#define DLP_CLEANFILE_MAX        4096
#define DLP_SCAN_QUEUE_MAX       256

/* Only the first read of at least this many bytes arms a scan (substantiality
 * gate) -- a 1-byte probe read does not enqueue a 4 MiB scan job. */
#define DLP_READ_MIN             512

/* Pool tags ('DlpT'/'DlpJ' -> 'TplD'/'JplD' on a little-endian tag dump). */
#define DLP_TAINT_TAG            'TplD'
#define DLP_JOB_TAG              'JplD'

/* ---- Read-deny (content-aware exfil-tool read blocking, read-deny-LLD) ---- *
 * Master switch + fail-mode (registry, read in DriverEntry). Default OFF. */
#define DLP_EXFILREAD_DISABLED   0
#define DLP_EXFILREAD_ENABLED    1

/* Kernel exfil-PID table size (holds the agent-pushed set). Bounded, spinlock,
 * epoch — mirrors the taint ring. */
#define DLP_EXFIL_MAX            1024
#define DLP_EXFIL_TAG            'XplD'   /* 'DlpX' */

/* One exfil-channel PID (agent-pushed). Epoch-stamped like the taint ring so a
 * full-replace bumps the epoch and the old set reads as absent with no walk. */
typedef struct _DLP_EXFIL_ENTRY {
    volatile LONG Pid;          /* exfil-channel PID (0 = empty slot)            */
    LONG          Epoch;        /* gDlpData.ExfilEpoch snapshot at insert        */
    BOOLEAN       Valid;
} DLP_EXFIL_ENTRY, *PDLP_EXFIL_ENTRY;

/* One tainted PID. Mirrors DLP_BADHASH_ENTRY: stamped with the TaintEpoch it
 * was inserted under; a stale-epoch entry reads as absent (admin reset bumps
 * the epoch). CreateTime is the process create-time, a PID-reuse guard. */
typedef struct _DLP_TAINT_ENTRY {
    volatile LONG Pid;          /* tainted requestor PID (0 = empty slot)        */
    LONG          TaintEpoch;   /* gDlpData.TaintEpoch snapshot at insert        */
    ULONGLONG     CreateTime;   /* PsGetProcessCreateTimeQuadPart (reuse guard)  */
    BOOLEAN       Valid;
} DLP_TAINT_ENTRY, *PDLP_TAINT_ENTRY;

/* One known-sensitive file id (cheapest repeat-read path -- no read, no
 * up-call). Stamped with the CONTENT-policy Epoch (so a policy reload via
 * agent reconnect DOES invalidate cached sensitivity, which is correct for a
 * content verdict -- unlike taint, which deliberately persists). */
typedef struct _DLP_SENSFILE_ENTRY {
    ULONGLONG FileId;           /* FILE_INTERNAL_INFORMATION.IndexNumber         */
    ULONGLONG VolumeId;         /* per-instance discriminator (0 = unknown)      */
    LONG      Epoch;            /* gDlpData.Epoch snapshot (content policy epoch) */
    BOOLEAN   Valid;
} DLP_SENSFILE_ENTRY, *PDLP_SENSFILE_ENTRY;

/* One queued async scan. Holds a referenced FILE_OBJECT + the instance so the
 * worker can FltReadFile at PASSIVE. The scan rundown (acquired at enqueue,
 * released by the worker per job) keeps the filter alive while a job runs. */
typedef struct _DLP_SCAN_JOB {
    LIST_ENTRY     Link;
    PFLT_INSTANCE  Instance;    /* not separately referenced; scan rundown guards */
    PFILE_OBJECT   FileObject;  /* ObReferenceObject'd at enqueue                 */
    ULONG          Pid;
    LONG           Epoch;       /* content-policy epoch snapshot                  */
    /* Normalized file name captured at enqueue (DlpPostRead still holds the
     * FLT_FILE_NAME_INFORMATION). The worker ships it in the up-call so the agent
     * can pick its format extractor from the extension -- an EMPTY path made every
     * read-taint scan come back Unreadable (never matched). Bytes, not NUL-term. */
    WCHAR          Path[DLP_MAX_PATH_CHARS];
    USHORT         PathLength;  /* valid bytes in Path (<= sizeof(Path))          */
} DLP_SCAN_JOB, *PDLP_SCAN_JOB;


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
     * recurse back into us. 0 = no client connected. This IS the AgentPid the
     * tamper-protection ObCallback (item 11) protects. */
    volatile LONG  ServicePid;

    /* Fail mode, read from the service registry key at DriverEntry. */
    ULONG          FailMode;

    /* ---- Hardening state (adapted from the old dlp_mflt driver) ---------- */

    /* Rundown protection around the FltSendMessage up-call (item 2, A4). The
     * send passes &gDlpData.ClientPort (the GLOBAL) so FltCloseClientPort's
     * NULL-on-close unblocks an in-flight send; Unload waits this rundown ONCE,
     * before closing ports / unregistering, so no send outlives the filter. */
    EX_RUNDOWN_REF SendRundown;
    BOOLEAN        SendRundownInit; /* ExInitializeRundownProtection done      */

    /* Policy epoch (item 4, H2). Bumped on every agent (re)connect. A cached
     * verdict / known-bad hash carrying a stale epoch is treated as a miss.
     * Starts at 1; 0 is reserved for "never decided". */
    volatile LONG  Epoch;

    /* Circuit breaker (item 3, H5). Consecutive IPC timeouts; at
     * DLP_BREAKER_THRESHOLD the up-call is short-circuited to FailMode. A live
     * reply resets it to 0. */
    volatile LONG  ConsecutiveTimeouts;

    /* Known-bad content-hash table (item 10). Bounded ring, spinlock-guarded.
     * BadHashNext is the next insert slot (ring/LRU eviction). */
    KSPIN_LOCK        BadHashLock;
    DLP_BADHASH_ENTRY BadHash[DLP_BADHASH_MAX];
    LONG              BadHashNext;

    /* Tamper-protection ObRegisterCallbacks handle (item 11). NULL until
     * registered in DriverEntry; ObUnRegisterCallbacks'd first in Unload. */
    PVOID          ObCallbackHandle;

    /* Scan-scope config (comms.c), delivered user->kernel via a DLP_CONFIG
     * message. ConfigValid gates readers; ConfigLock (an ERESOURCE, so
     * acquisition stays at PASSIVE_LEVEL) guards Config for one writer / many
     * readers. Empty/absent => removable-only behavior (back-compat). */
    ERESOURCE      ConfigLock;      /* guards Config; PASSIVE-level primitive */
    BOOLEAN        ConfigLockInit;  /* ConfigLock was ExInitializeResourceLite'd */
    volatile LONG  ConfigValid;     /* a valid DLP_CONFIG has been stored     */
    DLP_CONFIG     Config;          /* watch prefixes + ScanFixed/ScanNetwork */

    /* ---- Read-taint (all gated by ReadTaintEnabled) --------------------- */

    /* Master switch + tainted-egress policy (registry, read in DriverEntry). */
    ULONG          ReadTaintEnabled;      /* DLP_READTAINT_* */
    ULONG          TaintedEgressPolicy;   /* DLP_TEP_*       */

    /* Taint table (mirrors the BadHash ring; written by worker/process-notify
     * at PASSIVE, read by the WFP callout at <= DISPATCH under the spinlock). */
    KSPIN_LOCK      TaintLock;
    DLP_TAINT_ENTRY Taint[DLP_TAINT_MAX];
    volatile LONG   TaintEpoch;   /* starts 1; bumped ONLY by DlpTaintResetAll   */
    volatile LONG   TaintCount;   /* live entries (diagnostics / bounding)       */
    LONG            TaintNext;    /* ring cursor used only when the table is full */

    /* Known-sensitive file-id cache. */
    KSPIN_LOCK         SensFileLock;
    DLP_SENSFILE_ENTRY SensFile[DLP_SENSFILE_MAX];
    LONG               SensFileNext;      /* ring cursor                          */

    /* Known-clean file-id cache (read-deny). Mirrors SensFile (same content Epoch
     * stamp, ring, spinlock). Lets DlpExfilClassifyAndCache short-circuit a file
     * already judged clean, so an exfil PID's repeated opens do not re-read + re-
     * up-call. Only read-deny consults it. */
    KSPIN_LOCK         CleanFileLock;
    DLP_SENSFILE_ENTRY CleanFile[DLP_CLEANFILE_MAX];
    LONG               CleanFileNext;     /* ring cursor                          */

    /* Async scan queue + worker. */
    KSPIN_LOCK      ScanQueueLock;
    LIST_ENTRY      ScanQueue;
    KSEMAPHORE      ScanSem;              /* signalled once per enqueue           */
    volatile LONG   ScanQueueDepth;       /* bounded at DLP_SCAN_QUEUE_MAX        */
    volatile LONG   ScanDropped;          /* jobs dropped under flood (diag)      */
    PETHREAD        ScanThread;           /* referenced; Unload waits on it       */
    HANDLE          ScanThreadHandle;
    volatile LONG   ScanStop;             /* 1 => worker drains and exits         */
    EX_RUNDOWN_REF  ScanRundown;          /* jobs hold it; Unload waits once      */
    BOOLEAN         ScanRundownInit;

    /* WFP callout state (wfpcallout.c). Each *Added/*Reg flag guards its own
     * rollback so DlpWfpUnregister is idempotent. */
    PDEVICE_OBJECT  WfpDevice;            /* IoCreateDevice (FwpsCalloutRegister) */
    HANDLE          WfpEngine;            /* FwpmEngineOpen0 (non-dynamic)        */
    UINT32          WfpCalloutIdV4;       /* FwpsCalloutRegister2 runtime id      */
    UINT32          WfpCalloutIdV6;
    UINT64          WfpFilterIdV4;        /* FwpmFilterAdd0 id (for delete)       */
    UINT64          WfpFilterIdV6;
    BOOLEAN         WfpCalloutV4Reg;      /* FwpsCalloutRegister2 done            */
    BOOLEAN         WfpCalloutV6Reg;
    BOOLEAN         WfpProviderAdded;
    BOOLEAN         WfpSubLayerAdded;
    BOOLEAN         WfpCalloutV4Added;    /* FwpmCalloutAdd0 done                 */
    BOOLEAN         WfpCalloutV6Added;
    BOOLEAN         WfpFilterV4Added;     /* FwpmFilterAdd0 done                  */
    BOOLEAN         WfpFilterV6Added;

    /* Process-notify registration (PsSetCreateProcessNotifyRoutineEx). */
    BOOLEAN         ProcNotifyRegistered;

    /* ---- Read-deny (content-aware exfil-tool read blocking) -------------- *
     * Gated by ExfilReadBlockEnabled. The exfil-PID set is agent-pushed
     * (DLP_EXFIL_UPDATE); DlpPreRead consults it, then content-classifies +
     * denies a sensitive read. Reuses SensFile/BadHash/DlpQueryVerdict + the
     * DLP_CONFIG watch scope. */
    ULONG           ExfilReadBlockEnabled;  /* DLP_EXFILREAD_* (registry, default 0) */
    ULONG           ExfilReadFailBlock;     /* deny on unverifiable content (default 1) */
    KSPIN_LOCK      ExfilLock;
    DLP_EXFIL_ENTRY Exfil[DLP_EXFIL_MAX];
    volatile LONG   ExfilEpoch;             /* bumped on each full-replace push       */
    volatile LONG   ExfilCount;             /* live entries (diagnostics)             */

    /* TEMP-DIAGNOSTIC: per-OPORD access trace (create/read/section) -> registry. */
    WCHAR           SvcRegPath[300];
    USHORT          SvcRegPathBytes;
    BOOLEAN         SvcRegPathValid;
    volatile LONG   TrCreSeq;
    volatile LONG   TrRdSeq;
    volatile LONG   TrSecSeq;
} DLP_FLT_DATA, *PDLP_FLT_DATA;

extern DLP_FLT_DATA gDlpData;

/* ---- comms.c ---------------------------------------------------------- */

/* Create / tear down the communication port. */
NTSTATUS DlpCreateCommunicationPort(_In_ PFLT_FILTER Filter);
VOID     DlpCloseCommunicationPort(VOID);

/* Ask the connected service for a verdict on one file. Ships Path (for logging)
 * plus ContentLength bytes of file content (read in-kernel by the caller) so
 * the service never re-opens the file. Content may be NULL/0 (empty file or a
 * failed read -> the service scores what it gets). On any failure (no client,
 * timeout, send error) *Block is set from FailMode and a non-success status is
 * returned; callers must still honor *Block. Never crashes. */
NTSTATUS DlpQueryVerdict(_In_ PUNICODE_STRING Path,
                         _In_ ULONGLONG FileId,
                         _In_ ULONG ProcessId,
                         _In_reads_bytes_opt_(ContentLength) PVOID Content,
                         _In_ ULONG ContentLength,
                         _In_ BOOLEAN Truncated,
                         _In_ ULONG Reason,        /* DLP_REASON_WRITE | _READ */
                         _Out_ PBOOLEAN Block);

/* Read FailMode from the driver's service registry path (DriverEntry). */
VOID     DlpReadFailMode(_In_ PUNICODE_STRING RegistryPath);

/* Read the read-taint knobs (ReadTaintEnabled, TaintedEgressPolicy) from the
 * service registry path (DriverEntry). Same pattern as DlpReadFailMode; both
 * default to disabled/block-all and are only overridden if present + valid. */
VOID     DlpReadTaintPolicy(_In_ PUNICODE_STRING RegistryPath);

/* Read the read-deny knobs (ExfilReadBlockEnabled, ExfilReadFailBlock) from the
 * service registry path (DriverEntry). Defaults: disabled + fail-block. */
VOID     DlpReadExfilPolicy(_In_ PUNICODE_STRING RegistryPath);

/* TEMP-DIAGNOSTIC: record an OPORD access (which callback, pid, gate result). */
VOID     DlpTraceCre(_In_ ULONG Pid, _In_ ULONG Exfil, _In_ ULONG Skip);
VOID     DlpTraceRd(_In_ ULONG Pid, _In_ ULONG Exfil, _In_ ULONG Skip);
VOID     DlpTraceSec(_In_ ULONG Pid, _In_ ULONG Exfil, _In_ ULONG SyncType);

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


/* ---- Read-taint: taint table + sensfile cache (dlpflt.c) -------------- *
 * All four taint functions mirror the BadHash ring (KSPIN_LOCK, epoch stamp,
 * ring cursor, dedup). DlpTaintLookup is the ONLY one called at <= DISPATCH
 * (from the WFP callout); the rest run at PASSIVE (worker / process-notify). */
BOOLEAN  DlpTaintLookup(_In_ ULONG Pid);
VOID     DlpTaintAdd(_In_ ULONG Pid);
VOID     DlpTaintRemove(_In_ ULONG Pid);
VOID     DlpTaintResetAll(VOID);           /* admin "reset taint": epoch bump   */

BOOLEAN  DlpSensFileLookup(_In_ ULONGLONG FileId, _In_ ULONGLONG VolumeId);
VOID     DlpSensFileInsert(_In_ ULONGLONG FileId, _In_ ULONGLONG VolumeId);

/* Known-clean file-id cache (read-deny). Same ring/epoch discipline as SensFile;
 * bounds content-classify up-calls (a clean file is classified once, cross-open). */
BOOLEAN  DlpCleanFileLookup(_In_ ULONGLONG FileId, _In_ ULONGLONG VolumeId);
VOID     DlpCleanFileInsert(_In_ ULONGLONG FileId, _In_ ULONGLONG VolumeId);

/* ---- Read-deny: exfil-PID set (dlpflt.c) ----------------------------- *
 * DlpExfilLookup is called on the read hot path (DlpPreRead, PASSIVE) under the
 * spinlock; DlpExfilReplace is the full-replace applied from the DLP_EXFIL_UPDATE
 * message-notify callback (comms.c). DlpExfilRemove drops an exited PID. */
BOOLEAN  DlpExfilLookup(_In_ ULONG Pid);
VOID     DlpExfilReplace(_In_reads_(Count) const ULONG *Pids, _In_ ULONG Count);
VOID     DlpExfilRemove(_In_ ULONG Pid);

/* ---- Read-taint: async scan worker + process-notify (dlpflt.c) -------- */
NTSTATUS DlpStartScanWorker(VOID);
VOID     DlpStopScanWorker(VOID);
VOID     DlpScanEnqueue(_Inout_ __drv_aliasesMem PDLP_SCAN_JOB Job);

/* Process-create/-exit notify: untaint a PID on process exit. Registered with
 * PsSetCreateProcessNotifyRoutineEx (needs /INTEGRITYCHECK, already present). */
VOID     DlpCreateProcessNotify(_In_ PEPROCESS Process,
                                _In_ HANDLE ProcessId,
                                _In_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);

/* ---- Read-taint: WFP callout (wfpcallout.c) --------------------------- *
 * Register in DriverEntry AFTER FltStartFiltering (gated on ReadTaintEnabled);
 * unregister in Unload with the filters-first / callout-drain ordering. A
 * registration failure is non-fatal to the driver (FS protection survives). */
NTSTATUS DlpWfpRegister(VOID);
VOID     DlpWfpUnregister(VOID);

#endif /* _KERNEL_MODE */

#endif /* DLPFLT_H */
