/*++

wfpcallout.c  --  DLP read-taint network-egress blocking (WFP callout).

This is the INITGUID translation unit for the read-taint subsystem. It hangs a
WFP filtering callout at FWPM_LAYER_ALE_AUTH_CONNECT_V4 and _V6. Every outbound
connect is classified by DlpWfpClassify, which reads the connecting PID from the
WFP metadata and asks the taint table (DlpTaintLookup) whether that PID has read
sensitive content. A tainted PID's connect is BLOCKED (content-blind, so it works
over TLS / AnyDesk / any socket); a clean PID's connect is CONTINUE'd so the
existing user-mode default-deny sublayer still governs it (read-taint COMPOSES
with, never overrides, the user-mode allow-list).

The block/permit decision is the exact mirror of the pure Rust
`tcpreset.rs::tainted_egress_action`:
    clean               -> Continue
    tainted, BlockAll   -> Block
    tainted, BlockNonlocal, remote local  -> Continue (permit RFC1918/loopback/LL)
    tainted, BlockNonlocal, remote public -> Block

Everything here is only ever reached when gDlpData.ReadTaintEnabled is set;
DriverEntry calls DlpWfpRegister only under that gate. A registration failure is
non-fatal to the driver (filesystem/USB/content protection survives).

Verification boundary: this file is BUILT and statically analyzed here. It is NOT
loaded or run in this environment (WFP callout; an IRQL / flow-lifetime mistake
is a BSOD). Runtime correctness (Driver Verifier WFP/NDIS checks, unload stress)
is the operator's manual step.

--*/

#include <initguid.h>     /* instantiate the DEFINE_GUIDs in THIS TU only        */
#include "dlpflt.h"        /* pulls fltKernel.h under _KERNEL_MODE + gDlpData     */

/* fwpsk.h prototypes the packet-injection APIs in terms of NET_BUFFER_LIST, so
 * that NDIS type must exist before it is included even though this callout does
 * no packet injection. ndis.h only defines it as a WDM consumer at an explicit
 * NDIS contract version -- the exact pattern the WDK WFP callout samples use
 * (NDIS_WDM + NDIS630). This is why the link line carries ndis.lib. */
#ifndef NDIS_WDM
#define NDIS_WDM 1
#endif
#ifndef NDIS630
#define NDIS630  1
#endif
#include <ndis.h>          /* NET_BUFFER_LIST + friends that fwpsk.h prototypes   */
#include <fwpsk.h>         /* FwpsCalloutRegister2, FWPS_* classify types         */
#include <fwpmk.h>         /* FwpmEngineOpen0, FwpmFilterAdd0, FWPM_LAYER_* keys   */

/* RPC_C_AUTHN_WINNT (rpcdce.h value) -- the auth service for FwpmEngineOpen0.
 * Guarded so we do not redefine it if a WFP header already pulled it in. */
#ifndef RPC_C_AUTHN_WINNT
#define RPC_C_AUTHN_WINNT   10
#endif

/* System PID. DLP_SYSTEM_PID is a static define local to dlpflt.c and is not
 * visible across TUs, so the WFP callout carries its own copy of the same
 * constant (never block the System process's egress). */
#define DLP_WFP_SYSTEM_PID  ((LONG)4)

/* ------------------------------------------------------------------------- *
 *  New GUIDs for the read-taint WFP objects (LLD 5.1).                       *
 *  FRESH and distinct from the user-mode build's DLP_*_GUID (0x7b2e6f10...): *
 *  a separate subsystem gets its own provider / sublayer / callouts.         *
 * ------------------------------------------------------------------------- */

/* {a3f1c9d2-5e84-4b17-9c6a-1f2e3d4b5a60} */
DEFINE_GUID(DLP_WFP_PROVIDER_GUID,
    0xa3f1c9d2, 0x5e84, 0x4b17, 0x9c, 0x6a, 0x1f, 0x2e, 0x3d, 0x4b, 0x5a, 0x60);

/* {b4e2da13-6f95-4c28-8d7b-2a3f4e5c6b71} */
DEFINE_GUID(DLP_WFP_SUBLAYER_GUID,
    0xb4e2da13, 0x6f95, 0x4c28, 0x8d, 0x7b, 0x2a, 0x3f, 0x4e, 0x5c, 0x6b, 0x71);

/* {c5d3eb24-70a6-4d39-9e8c-3b4a5f6d7c82} */
DEFINE_GUID(DLP_WFP_CALLOUT_V4_GUID,
    0xc5d3eb24, 0x70a6, 0x4d39, 0x9e, 0x8c, 0x3b, 0x4a, 0x5f, 0x6d, 0x7c, 0x82);

/* {d6e4fc35-81b7-4e4a-af9d-4c5b6a7e8d93} */
DEFINE_GUID(DLP_WFP_CALLOUT_V6_GUID,
    0xd6e4fc35, 0x81b7, 0x4e4a, 0xaf, 0x9d, 0x4c, 0x5b, 0x6a, 0x7e, 0x8d, 0x93);

/* Mid filter weight (LLD 5.2): our filtering callout sits mid-stack so a
 * higher-weight terminating filter can still pre-empt it, and lower ones still
 * see the CONTINUE. Sublayer weight is a plain UINT16. */
#define DLP_WFP_FILTER_WEIGHT   0x08
#define DLP_WFP_SUBLAYER_WEIGHT 0x8000

/* Bounded retry for the FwpsCalloutUnregisterById0 drain race (LLD 5.5). */
#define DLP_WFP_UNREG_RETRIES   20
#define DLP_WFP_UNREG_DELAY_MS  5

/* ------------------------------------------------------------------------- *
 *  Locality classifier -- pure, mirrors the Rust remote_is_local assumption. *
 * ------------------------------------------------------------------------- */

/*++
DlpWfpRemoteIsLocal -- TRUE if the connect's remote address is "local"
(RFC1918 private / loopback / link-local), FALSE for a public destination.

This is the kernel half of the BlockNonlocal decision; the block/permit matrix
it feeds is the exact mirror of tcpreset.rs::tainted_egress_action. Reads the
remote-address field for the correct family off inFixedValues (the family is
carried in layerId). Pure: no locks, no I/O -- safe to call from classifyFn at
<= DISPATCH_LEVEL.
--*/
static BOOLEAN
DlpWfpRemoteIsLocal(_In_ const FWPS_INCOMING_VALUES0 *InFixed)
{
    if (InFixed->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V4) {
        /* V4 remote address arrives in HOST byte order (a.b.c.d with a in the
         * high octet). Classify against the well-known local ranges. */
        UINT32 addr =
            InFixed->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V4_IP_REMOTE_ADDRESS]
                .value.uint32;

        if ((addr & 0xFF000000u) == 0x7F000000u) return TRUE; /* 127.0.0.0/8   */
        if ((addr & 0xFF000000u) == 0x0A000000u) return TRUE; /* 10.0.0.0/8     */
        if ((addr & 0xFFF00000u) == 0xAC100000u) return TRUE; /* 172.16.0.0/12  */
        if ((addr & 0xFFFF0000u) == 0xC0A80000u) return TRUE; /* 192.168.0.0/16 */
        if ((addr & 0xFFFF0000u) == 0xA9FE0000u) return TRUE; /* 169.254.0.0/16 */
        return FALSE;
    }

    if (InFixed->layerId == FWPS_LAYER_ALE_AUTH_CONNECT_V6) {
        /* V6 remote address is a 16-byte array in NETWORK byte order. */
        const FWP_BYTE_ARRAY16 *a =
            InFixed->incomingValue[FWPS_FIELD_ALE_AUTH_CONNECT_V6_IP_REMOTE_ADDRESS]
                .value.byteArray16;
        const UINT8 *b;
        ULONG i;

        if (a == NULL) {
            return FALSE;
        }
        b = a->byteArray16;

        /* ::1 loopback -- 15 zero bytes then 0x01. */
        if (b[15] == 0x01) {
            BOOLEAN zero = TRUE;
            for (i = 0; i < 15; i++) {
                if (b[i] != 0x00) { zero = FALSE; break; }
            }
            if (zero) return TRUE;
        }
        /* fe80::/10 link-local. */
        if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80) return TRUE;
        /* fc00::/7 unique-local (the v6 analogue of RFC1918). */
        if ((b[0] & 0xFEu) == 0xFCu) return TRUE;
        return FALSE;
    }

    /* Unknown layer -- treat as non-local (fail-secure toward blocking). */
    return FALSE;
}

/* ------------------------------------------------------------------------- *
 *  classifyFn -- runs at <= DISPATCH_LEVEL and MUST NEVER BLOCK.             *
 * ------------------------------------------------------------------------- */

/*++
DlpWfpClassify -- shared v4/v6 ALE_AUTH_CONNECT classify callback.

Contract (LLD 5.3): runs at <= DISPATCH_LEVEL, no allocation, no I/O, no waits,
no ERESOURCE. The only non-trivial call is DlpTaintLookup, a bounded
spinlock scan that is legal at DISPATCH. Decision matrix is byte-for-byte
identical to tcpreset.rs::tainted_egress_action.
--*/
static VOID NTAPI
DlpWfpClassify(
    _In_ const FWPS_INCOMING_VALUES0 *InFixed,
    _In_ const FWPS_INCOMING_METADATA_VALUES0 *InMeta,
    _Inout_opt_ void *LayerData,
    _In_opt_ const void *ClassifyContext,
    _In_ const FWPS_FILTER2 *Filter,
    _In_ UINT64 FlowContext,
    _Inout_ FWPS_CLASSIFY_OUT0 *ClassifyOut)
{
    ULONG pid;
    LONG  servicePid;

    UNREFERENCED_PARAMETER(LayerData);
    UNREFERENCED_PARAMETER(ClassifyContext);
    UNREFERENCED_PARAMETER(Filter);
    UNREFERENCED_PARAMETER(FlowContext);

    /* Someone up-stack already hard-decided (a veto with the write-right
     * cleared). Do not touch the verdict. */
    if ((ClassifyOut->rights & FWPS_RIGHT_ACTION_WRITE) == 0) {
        return;
    }

    /* Default: CONTINUE, never PERMIT. A PERMIT here would override the
     * user-mode default-deny sublayer; CONTINUE lets it still decide. */
    ClassifyOut->actionType = FWP_ACTION_CONTINUE;

    /* No PID metadata -> cannot attribute the connect. Fail-safe = CONTINUE
     * (do not block blind; the user-mode allow-list still governs). */
    if (!FWPS_IS_METADATA_FIELD_PRESENT(InMeta, FWPS_METADATA_FIELD_PROCESS_ID)) {
        return;
    }
    pid = (ULONG)InMeta->processId;

    /* Never block the agent's own egress (its mTLS check-in) or System. */
    servicePid = InterlockedCompareExchange(&gDlpData.ServicePid, 0, 0);
    if ((servicePid != 0 && pid == (ULONG)servicePid) ||
        pid == (ULONG)DLP_WFP_SYSTEM_PID) {
        return;
    }

    if (DlpTaintLookup(pid)) {
        /* BlockNonlocal permits RFC1918/loopback/link-local; block the rest. */
        if (gDlpData.TaintedEgressPolicy == DLP_TEP_BLOCK_NONLOCAL &&
            DlpWfpRemoteIsLocal(InFixed)) {
            return;                                   /* CONTINUE -- permitted */
        }
        /* Hard block (veto): clear the write-right so no lower-weight filter
         * can re-permit this tainted PID's connect. */
        ClassifyOut->actionType = FWP_ACTION_BLOCK;
        ClassifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
        /* No flowContext, no data touched -- minimal work at DISPATCH. */
    }
}

/*++
DlpWfpNotify -- required by FwpsCalloutRegister2. We keep no per-filter state, so
every notification (add/delete) is a success no-op.
--*/
static NTSTATUS NTAPI
DlpWfpNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE NotifyType,
    _In_ const GUID *FilterKey,
    _Inout_ FWPS_FILTER2 *Filter)
{
    UNREFERENCED_PARAMETER(NotifyType);
    UNREFERENCED_PARAMETER(FilterKey);
    UNREFERENCED_PARAMETER(Filter);
    return STATUS_SUCCESS;
}

/* ------------------------------------------------------------------------- *
 *  Registration / teardown (PASSIVE_LEVEL, DriverEntry / Unload).           *
 * ------------------------------------------------------------------------- */

/*++
DlpWfpUnregister -- fully idempotent teardown. Safe to call from a partially
failed DlpWfpRegister and again from Unload; every action is guarded by its
rollback flag and the flag is cleared after the undo.

Ordering (LLD 5.5, the top BSOD/leak source -- follow exactly):
    filters -> callouts (FwpmCalloutDeleteByKey0) -> sublayer -> provider
    -> engine close  (all inside one management transaction)
    -> FwpsCalloutUnregisterById0 (kernel callouts; drain race, bounded retry)
    -> IoDeleteDevice.
Deleting the filters first stops new classifies before we unregister the kernel
callouts, which is what lets FwpsCalloutUnregisterById0 drain instead of BUSY.
--*/
VOID
DlpWfpUnregister(VOID)
{
    NTSTATUS status;

    PAGED_CODE();

    /* Step 1: delete the management-plane objects in a transaction. */
    if (gDlpData.WfpEngine != NULL) {
        BOOLEAN inXact = FALSE;

        status = FwpmTransactionBegin0(gDlpData.WfpEngine, 0);
        if (NT_SUCCESS(status)) {
            inXact = TRUE;
        }

        /* filters first -- stops new classifies. */
        if (gDlpData.WfpFilterV4Added) {
            FwpmFilterDeleteById0(gDlpData.WfpEngine, gDlpData.WfpFilterIdV4);
            gDlpData.WfpFilterV4Added = FALSE;
        }
        if (gDlpData.WfpFilterV6Added) {
            FwpmFilterDeleteById0(gDlpData.WfpEngine, gDlpData.WfpFilterIdV6);
            gDlpData.WfpFilterV6Added = FALSE;
        }
        /* callouts (management objects; keyed delete -- no FWPM id stored). */
        if (gDlpData.WfpCalloutV4Added) {
            FwpmCalloutDeleteByKey0(gDlpData.WfpEngine, &DLP_WFP_CALLOUT_V4_GUID);
            gDlpData.WfpCalloutV4Added = FALSE;
        }
        if (gDlpData.WfpCalloutV6Added) {
            FwpmCalloutDeleteByKey0(gDlpData.WfpEngine, &DLP_WFP_CALLOUT_V6_GUID);
            gDlpData.WfpCalloutV6Added = FALSE;
        }
        /* sublayer then provider. */
        if (gDlpData.WfpSubLayerAdded) {
            FwpmSubLayerDeleteByKey0(gDlpData.WfpEngine, &DLP_WFP_SUBLAYER_GUID);
            gDlpData.WfpSubLayerAdded = FALSE;
        }
        if (gDlpData.WfpProviderAdded) {
            FwpmProviderDeleteByKey0(gDlpData.WfpEngine, &DLP_WFP_PROVIDER_GUID);
            gDlpData.WfpProviderAdded = FALSE;
        }

        if (inXact) {
            status = FwpmTransactionCommit0(gDlpData.WfpEngine);
            if (!NT_SUCCESS(status)) {
                FwpmTransactionAbort0(gDlpData.WfpEngine);
            }
        }

        FwpmEngineClose0(gDlpData.WfpEngine);
        gDlpData.WfpEngine = NULL;
    }

    /* Step 2: unregister the kernel callouts. With the filters gone, no new
     * classify starts; a classify already in flight makes this return
     * STATUS_DEVICE_BUSY, so retry a bounded number of times with a short
     * PASSIVE delay to let it drain (never spin at raised IRQL). */
    if (gDlpData.WfpCalloutV4Reg) {
        ULONG tries;
        for (tries = 0; tries < DLP_WFP_UNREG_RETRIES; tries++) {
            status = FwpsCalloutUnregisterById0(gDlpData.WfpCalloutIdV4);
            if (status != STATUS_DEVICE_BUSY) {
                break;
            }
            {
                LARGE_INTEGER delay;
                delay.QuadPart = -(LONGLONG)DLP_WFP_UNREG_DELAY_MS * 10LL * 1000LL;
                KeDelayExecutionThread(KernelMode, FALSE, &delay);
            }
        }
        gDlpData.WfpCalloutV4Reg = FALSE;
    }
    if (gDlpData.WfpCalloutV6Reg) {
        ULONG tries;
        for (tries = 0; tries < DLP_WFP_UNREG_RETRIES; tries++) {
            status = FwpsCalloutUnregisterById0(gDlpData.WfpCalloutIdV6);
            if (status != STATUS_DEVICE_BUSY) {
                break;
            }
            {
                LARGE_INTEGER delay;
                delay.QuadPart = -(LONGLONG)DLP_WFP_UNREG_DELAY_MS * 10LL * 1000LL;
                KeDelayExecutionThread(KernelMode, FALSE, &delay);
            }
        }
        gDlpData.WfpCalloutV6Reg = FALSE;
    }

    /* Step 3: the device object that anchored the kernel callouts. */
    if (gDlpData.WfpDevice != NULL) {
        IoDeleteDevice(gDlpData.WfpDevice);
        gDlpData.WfpDevice = NULL;
    }
}

/*++
DlpWfpAddObjects -- the management-plane half of registration (LLD 5.2 step 4),
run inside a single FwpmTransaction so a mid-sequence failure leaves nothing
half-committed. Provider -> sublayer -> callouts (v4,v6) -> filters (v4,v6).
--*/
static NTSTATUS
DlpWfpAddObjects(VOID)
{
    NTSTATUS status;
    BOOLEAN  inXact = FALSE;

    FWPM_PROVIDER0 provider;
    FWPM_SUBLAYER0 sublayer;
    FWPM_CALLOUT0  callout;
    FWPM_FILTER0   filter;

    status = FwpmTransactionBegin0(gDlpData.WfpEngine, 0);
    if (!NT_SUCCESS(status)) {
        return status;
    }
    inXact = TRUE;

    /* Provider. */
    RtlZeroMemory(&provider, sizeof(provider));
    provider.providerKey = DLP_WFP_PROVIDER_GUID;
    provider.displayData.name = L"DLP Read-Taint Provider";
    provider.displayData.description = L"On-prem DLP read-taint egress provider";
    status = FwpmProviderAdd0(gDlpData.WfpEngine, &provider, NULL);
    if (!NT_SUCCESS(status)) {
        goto abort;
    }
    gDlpData.WfpProviderAdded = TRUE;

    /* Sublayer (owned by our provider, its own weight). */
    RtlZeroMemory(&sublayer, sizeof(sublayer));
    sublayer.subLayerKey = DLP_WFP_SUBLAYER_GUID;
    sublayer.displayData.name = L"DLP Read-Taint SubLayer";
    sublayer.displayData.description = L"Tainted-PID egress blocking sublayer";
    sublayer.providerKey = (GUID *)&DLP_WFP_PROVIDER_GUID;
    sublayer.weight = DLP_WFP_SUBLAYER_WEIGHT;
    status = FwpmSubLayerAdd0(gDlpData.WfpEngine, &sublayer, NULL);
    if (!NT_SUCCESS(status)) {
        goto abort;
    }
    gDlpData.WfpSubLayerAdded = TRUE;

    /* Callout (management object) v4. */
    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = DLP_WFP_CALLOUT_V4_GUID;
    callout.displayData.name = L"DLP Read-Taint Callout V4";
    callout.providerKey = (GUID *)&DLP_WFP_PROVIDER_GUID;
    callout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    status = FwpmCalloutAdd0(gDlpData.WfpEngine, &callout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        goto abort;
    }
    gDlpData.WfpCalloutV4Added = TRUE;

    /* Callout (management object) v6. */
    RtlZeroMemory(&callout, sizeof(callout));
    callout.calloutKey = DLP_WFP_CALLOUT_V6_GUID;
    callout.displayData.name = L"DLP Read-Taint Callout V6";
    callout.providerKey = (GUID *)&DLP_WFP_PROVIDER_GUID;
    callout.applicableLayer = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    status = FwpmCalloutAdd0(gDlpData.WfpEngine, &callout, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        goto abort;
    }
    gDlpData.WfpCalloutV6Added = TRUE;

    /* Filter v4: match ALL outbound connects (numFilterConditions = 0); PID
     * filtering happens in the callout. action = CALLOUT_UNKNOWN (a filtering
     * callout, not terminating-permit) so the classify's CONTINUE/BLOCK rules. */
    RtlZeroMemory(&filter, sizeof(filter));
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = DLP_WFP_SUBLAYER_GUID;
    filter.displayData.name = L"DLP Read-Taint Filter V4";
    filter.providerKey = (GUID *)&DLP_WFP_PROVIDER_GUID;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = DLP_WFP_FILTER_WEIGHT;
    filter.numFilterConditions = 0;
    filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey = DLP_WFP_CALLOUT_V4_GUID;
    status = FwpmFilterAdd0(gDlpData.WfpEngine, &filter, NULL,
                            &gDlpData.WfpFilterIdV4);
    if (!NT_SUCCESS(status)) {
        goto abort;
    }
    gDlpData.WfpFilterV4Added = TRUE;

    /* Filter v6. */
    RtlZeroMemory(&filter, sizeof(filter));
    filter.layerKey = FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    filter.subLayerKey = DLP_WFP_SUBLAYER_GUID;
    filter.displayData.name = L"DLP Read-Taint Filter V6";
    filter.providerKey = (GUID *)&DLP_WFP_PROVIDER_GUID;
    filter.weight.type = FWP_UINT8;
    filter.weight.uint8 = DLP_WFP_FILTER_WEIGHT;
    filter.numFilterConditions = 0;
    filter.action.type = FWP_ACTION_CALLOUT_UNKNOWN;
    filter.action.calloutKey = DLP_WFP_CALLOUT_V6_GUID;
    status = FwpmFilterAdd0(gDlpData.WfpEngine, &filter, NULL,
                            &gDlpData.WfpFilterIdV6);
    if (!NT_SUCCESS(status)) {
        goto abort;
    }
    gDlpData.WfpFilterV6Added = TRUE;

    status = FwpmTransactionCommit0(gDlpData.WfpEngine);
    if (!NT_SUCCESS(status)) {
        inXact = FALSE;   /* commit consumed the transaction */
        goto abort;
    }
    return STATUS_SUCCESS;

abort:
    if (inXact) {
        FwpmTransactionAbort0(gDlpData.WfpEngine);
    }
    /* The *Added flags set above refer to objects that the abort/commit-failure
     * rolled back; clear them so DlpWfpUnregister does not try to delete them. */
    gDlpData.WfpFilterV4Added = FALSE;
    gDlpData.WfpFilterV6Added = FALSE;
    gDlpData.WfpCalloutV4Added = FALSE;
    gDlpData.WfpCalloutV6Added = FALSE;
    gDlpData.WfpSubLayerAdded = FALSE;
    gDlpData.WfpProviderAdded = FALSE;
    return status;
}

/*++
DlpWfpRegister -- called from DriverEntry AFTER FltStartFiltering, only when
ReadTaintEnabled. On any failure it rolls back via DlpWfpUnregister and returns
the error; DriverEntry treats that as non-fatal (FS protection survives).

Order (LLD 5.2):
    1. IoCreateDevice (anchors the kernel callouts).
    2. FwpsCalloutRegister2 v4, v6 (kernel callouts).
    3. FwpmEngineOpen0 (non-dynamic session).
    4. transaction: provider -> sublayer -> callouts -> filters (DlpWfpAddObjects).
--*/
NTSTATUS
DlpWfpRegister(VOID)
{
    NTSTATUS      status;
    FWPS_CALLOUT2 s_callout;

    PAGED_CODE();

    /* 1. Device object -- FwpsCalloutRegister2 requires one. */
    status = IoCreateDevice(gDlpData.DriverObject,
                            0,
                            NULL,
                            FILE_DEVICE_NETWORK,
                            0,
                            FALSE,
                            &gDlpData.WfpDevice);
    if (!NT_SUCCESS(status)) {
        gDlpData.WfpDevice = NULL;
        return status;
    }

    /* 2. Kernel callouts (v4, v6) -- shared classifyFn / notifyFn. */
    RtlZeroMemory(&s_callout, sizeof(s_callout));
    s_callout.calloutKey = DLP_WFP_CALLOUT_V4_GUID;
    s_callout.classifyFn = DlpWfpClassify;
    s_callout.notifyFn = DlpWfpNotify;
    s_callout.flowDeleteFn = NULL;
    status = FwpsCalloutRegister2(gDlpData.WfpDevice, &s_callout,
                                  &gDlpData.WfpCalloutIdV4);
    if (!NT_SUCCESS(status)) {
        goto fail;
    }
    gDlpData.WfpCalloutV4Reg = TRUE;

    RtlZeroMemory(&s_callout, sizeof(s_callout));
    s_callout.calloutKey = DLP_WFP_CALLOUT_V6_GUID;
    s_callout.classifyFn = DlpWfpClassify;
    s_callout.notifyFn = DlpWfpNotify;
    s_callout.flowDeleteFn = NULL;
    status = FwpsCalloutRegister2(gDlpData.WfpDevice, &s_callout,
                                  &gDlpData.WfpCalloutIdV6);
    if (!NT_SUCCESS(status)) {
        goto fail;
    }
    gDlpData.WfpCalloutV6Reg = TRUE;

    /* 3. Management engine -- non-dynamic (objects survive handle close; we
     * delete them explicitly in DlpWfpUnregister). */
    status = FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, NULL,
                             &gDlpData.WfpEngine);
    if (!NT_SUCCESS(status)) {
        gDlpData.WfpEngine = NULL;
        goto fail;
    }

    /* 4. Provider / sublayer / callouts / filters, transacted. */
    status = DlpWfpAddObjects();
    if (!NT_SUCCESS(status)) {
        goto fail;
    }

    return STATUS_SUCCESS;

fail:
    DlpWfpUnregister();
    return status;
}
