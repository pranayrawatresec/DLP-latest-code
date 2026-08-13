# Read-Taint Network Egress Blocking — High-Level Design (HLD)

Status: DESIGN (implements `READTAINT-DECISION-BRIEF.md`). Derived from the shipped
driver (`src/dlpflt.c`, `src/comms.c`, `src/dlpflt.h`), the shipped agent port
client (`dlp-agent/src/kguard/mod.rs`), the shipped user-mode default-deny WFP
(`dlp-agent/src/netfilter/*`), and the content engine (`dlp-agent/src/detect/*`).

Verification boundary (repeated because it governs every claim below): everything
here **compiles and passes `cl /analyze` / `cargo build|test`** in this
environment. It is **NOT loaded or run** here. "Blocks", "no BSOD", "actually
tears down the flow" are the **operator's manual VM step** (test-signed VM +
Driver Verifier). Nothing in this document is a runtime claim.

---

## 1. Goal restated

Stop **any content our engine calls sensitive** from leaving the endpoint over the
network — **including encrypted channels** (HTTPS upload, AnyDesk/TeamViewer/VNC
file-transfer, a malware process's own TLS socket) — with **no proxy and no
cloud**, on machines that are **not air-gapped**.

The egress point sees only ciphertext, so we cannot fingerprint at the wire. We
fingerprint at **READ time (plaintext)**, tag the reading process, then block that
process's network egress **content-blind** — the encryption no longer matters
because the decision is "this process touched secrets", not "these bytes are
secret".

---

## 2. One driver, two existing subsystems, three new pieces

We **extend the existing `dlpflt.sys`** — we do **not** add a second driver. The
driver today is an FS minifilter that (a) blocks sensitive content copied to
USB/watched paths via a user-mode content verdict (protocol v2, content-over-port
to `usb-guard`), and (b) tamper-protects the agent with `ObRegisterCallbacks`.
Neither is regressed.

Three additions, all inside `dlpflt.sys`:

| # | New piece | Lives in | Runs at |
|---|-----------|----------|---------|
| A | **Read trigger + async taint scan** | FS minifilter side (new `IRP_MJ_READ` post-op + a worker thread) | PASSIVE (worker) |
| B | **In-kernel taint table** (shared state) | new `taint.c` | written at PASSIVE (worker/notify), read at ≤ DISPATCH (WFP) |
| C | **WFP callout** at `ALE_AUTH_CONNECT_V4/_V6` | new `wfpcallout.c` | classify at ≤ DISPATCH |

Plus one user-mode addition in the agent: on a **read-scan BLOCK**, `usb-guard`
tears down the tainted PID's **existing** TCP connections (kernel callout only
catches **new** connections). No new fingerprinting code — it reuses
`detect::verdict_bytes` exactly as the write path does.

```
                         ┌──────────────────────────── dlpflt.sys (ONE driver) ─────────────────────────────┐
  process reads          │                                                                                   │
  a sensitive file       │   IRP_MJ_READ (post) ──claim first read──▶  taint-scan QUEUE  ──▶  WORKER THREAD  │
  ───────────────────────┼──▶  DlpPostRead                                                    (PASSIVE_LEVEL) │
                         │        │ (async: read proceeds now)                                      │        │
                         │        │                                                                 ▼        │
                         │        │                         file-id cache?  content-hash ring?   FltReadFile │
                         │        │                              │ miss           │ miss           + up-call │
                         │        │                              ▼                ▼   (REUSES protocol v2)    │
                         │        │                                        ┌───────────────┐                 │
                         │        │                                        │  usb-guard    │  detect::       │
                         │        │           reply BLOCK  ◀───────────────│ verdict_bytes │  (UNCHANGED)    │
                         │        ▼                                        └───────┬───────┘                 │
                         │   DlpTaintAdd(PID) ───────────────▶ TAINT TABLE ◀───┐   │ Reason=read-scan &      │
                         │                                     (spinlock)      │   │ BLOCK  ⇒ reset PID's    │
                         │                                          ▲          │   ▼ existing TCP conns      │
                         │   WFP classifyFn (ALE_AUTH_CONNECT_V4/V6)│          │  (user-mode, agent)         │
  process opens a NEW    │        │  get PID from metadata          │          │                             │
  socket (HTTPS/AnyDesk/ ┼──▶  DlpWfpClassify ──lookup(PID)─────────┘          │                             │
  malware) ──────────────┤        │  tainted? BLOCK : CONTINUE                 │                             │
                         └─────────┼─────────────────────────────────────────┼─────────────────────────────┘
                                   ▼                                          ▼
                        composes with the EXISTING user-mode      raises a read-taint incident over the
                        default-deny allow-list (netfilter)       existing mTLS / offline-queue sink
```

---

## 3. The read → tag → block dataflow (step by step)

1. **Read trigger.** A process opens a file and issues its first substantial read.
   The new `IRP_MJ_READ` **post-op** (`DlpPostRead`) claims the "first read of this
   stream" exactly once (interlocked flag in the stream context) and — because
   scanning inline would block the read on a user-mode round-trip — **enqueues an
   asynchronous scan job** (referenced `FILE_OBJECT` + `PFLT_INSTANCE` + requestor
   PID + epoch) and lets the read complete normally.

2. **Scoping (cost control).** Read-taint is **opt-in** (registry `ReadTaintEnabled`,
   default 0 = today's behavior). When on, the job is only enqueued for files under
   the configured **watch prefixes** (reuses `DlpConfigPathIsWatched` and the frozen
   `DLP_CONFIG` watch-set already plumbed for the fixed-volume write path) unless the
   deployment selects `scope=all`. Paging I/O, the agent's own PID, and System are
   skipped by the same `DlpShouldSkip` discipline the write path uses.

3. **Verdict (reuses protocol v2).** The **worker thread** (PASSIVE_LEVEL) resolves
   the job cheapest-first:
   - **File-id cache hit** (this NTFS file id was already found sensitive) → taint
     immediately, no read, no up-call.
   - else **content-hash ring hit** (SHA-256 of the shipped bytes is already known
     sensitive — the *same* item-10 ring the write path seeds) → taint, no up-call.
   - else **up-call**: `FltReadFile` the first ≤ 4 MiB in-kernel and call the
     existing `DlpQueryVerdict` (content-over-port to `usb-guard`), with the request's
     `Reason` field set to `read-scan`. `usb-guard` scores with `detect::verdict_bytes`
     — **unchanged fingerprint math** — and replies ALLOW/BLOCK.

4. **Tag.** A BLOCK verdict → `DlpTaintAdd(pid)` inserts the PID into the taint
   table and records the file id + content hash so repeats are cheap. An ALLOW
   verdict does nothing (the process is clean w.r.t. that file).

5. **Block new egress.** The WFP callout at `ALE_AUTH_CONNECT_V4/_V6` fires on every
   **outbound connection establishment**. `DlpWfpClassify` reads the requestor PID
   from the WFP metadata, looks it up in the taint table, and returns
   **`FWP_ACTION_BLOCK`** (tainted) or **`FWP_ACTION_CONTINUE`** (clean — *continue*,
   not *permit*, so it composes with the user-mode allow-list rather than overriding
   it). This is content-blind and therefore immune to TLS/pinning.

6. **Tear down existing egress.** `ALE_AUTH_CONNECT` only fires for **new**
   connections. A process that already had a socket open and *then* read secrets
   would slip through. When `usb-guard` computes a **read-scan BLOCK** it already
   holds the offending PID (it is in the scan request), so it **immediately resets
   that PID's existing TCP connections** (see §5). The kernel keeps blocking new ones.

7. **Untaint.** `PsSetCreateProcessNotifyRoutineEx` removes a PID from the taint
   table on process exit (also bounds table growth). Taint otherwise persists (see
   §6 — deliberately **not** cleared on agent reconnect).

---

## 4. How each encrypted channel is blocked

| Channel | Why the proxy idea fails | How read-taint blocks it |
|---|---|---|
| **HTTPS upload by a native app** (browser/`curl`/custom) of a sensitive file | TLS: gateway sees ciphertext | App reads the file → worker scans → PID tainted → its next `connect()` (or its already-open keep-alive socket, via §6 reset) is blocked at `ALE_AUTH_CONNECT`. Content-blind, so TLS is irrelevant. |
| **AnyDesk / TeamViewer / VNC file-transfer** | Cert-pinned; a MITM proxy is refused by the client | Tool reads the file → tainted → connection blocked / existing flow reset. **AND** its relay host is not on the user-mode allow-list → the existing default-deny blocks it at connect too (belt and suspenders). |
| **Malware with its own encrypted socket** | Custom crypto; nothing to intercept | Malware reads the file → tainted → its socket `connect()` is blocked by the same callout. It cannot opt out of the kernel callout from user mode. |
| **AnyDesk / VNC screen VIEW (no file read)** | — | **NOT blocked. Analog hole (by physics).** No file read ⇒ no taint. Stated honestly; see §7. |

---

## 5. Interaction with the existing user-mode default-deny (netfilter)

Two independent nets, different axes:

- **User-mode default-deny allow-list** (`dlp-agent/src/netfilter`, already built):
  blocks **all** egress to **unapproved destinations**, for **every** process.
  Coarse; catches AnyDesk/malware reaching **unapproved relays** even before any
  taint. It is a WFP **filter** (BLOCK/PERMIT), no callout.
- **Kernel read-taint callout** (new): blocks a **tainted process** even to an
  **approved** destination. Fine-grained; catches the sensitive-file-to-allowed-host
  case the allow-list can't (e.g. tainted process posting to an allowed SaaS).

Together: *a clean process may reach approved destinations; a tainted process may
reach nothing; nobody may reach unapproved destinations.* No sensitive data leaves.

**Non-negotiable allow-list entries** (or the agent bricks itself): the management
server host:port and the DNS resolver(s). The agent's own processes are **never
tainted** (worker self-skip) and the callout additionally `CONTINUE`s the agent
PID defensively, so the agent's mTLS check-in and incident upload always survive —
consistent with the project's **fail-secure, never cut protection off** rule.

Precedence within WFP is by sublayer/weight; the two subsystems use **distinct
sublayers** (the user-mode build already owns `DLP_SUBLAYER_GUID`; the kernel
callout gets its **own** provider/sublayer/callout GUIDs) so neither disturbs the
other or Windows' own filters.

---

## 6. Kernel / user split and the taint-persistence decision

| Concern | Kernel (`dlpflt.sys`) | User (`usb-guard` / agent) |
|---|---|---|
| Detect sensitivity | reads bytes in-kernel; **does not** fingerprint | `detect::verdict_bytes` (the only fingerprint authority — **unchanged**) |
| Hold taint state | **taint table** (authoritative, survives agent restarts) | — |
| Block **new** egress | **WFP callout** (cannot be bypassed from user mode) | — |
| Reset **existing** egress | — | TCP reset by owning PID (reuses agent net code) |
| Default-deny by destination | — | existing netfilter allow-list |
| Incidents | — | existing mTLS / offline-queue sink |

**Design decision — taint is NOT cleared on agent reconnect.** The item-10
known-bad *hash* ring is epoch-cleared on reconnect because a cached *verdict* may
be stale. A *taint* is a different fact: "this PID has already read secrets" stays
true across an agent restart, and the WFP block does not need the agent to be
connected. Clearing taint on reconnect would be **fail-open** during every agent
restart — exactly when an attacker might restart the agent to launder a process.
So taint entries carry a `TaintEpoch` for bounding/PID-reuse hygiene, but the epoch
is bumped **only** by a deliberate admin "reset taint" control, **not** by the
per-connect `gDlpData.Epoch` bump. This diverges from the badhash ring on purpose
and is the fail-secure choice.

---

## 7. Honest limits (must ship in the product docs)

| Limit | Nature | Mitigation / honest status |
|---|---|---|
| **IPC laundering** | A helper process reads the file, passes bytes via shared memory / a pipe to a *different, clean* process that exfils. Per-PID taint misses it (full byte-taint is impractical). | Not solved by read-taint. Partially covered because the **helper** is tainted (it read the file) and the launderer's destination may be blocked by the default-deny. Documented gap. |
| **Existing-connection race** | Window between "process read secrets" and "we reset its open flow": a very fast sender may push bytes first. Async tagging **widens** it (chosen for cost); sync would narrow it. | Kernel blocks all **new** connects immediately; user-mode reset closes the open one. Residual race is small and documented. Higher-assurance closure = kernel `FwpsFlowAbort` at `ALE_FLOW_ESTABLISHED` (see LLD §7, follow-on). |
| **Kernel-privileged attacker** | Can unhook the driver, edit the taint table, or unregister the callout. | Out of scope for a driver alone. Requires **Secure Boot + EDR + least-privilege + the existing ObCallbacks tamper guard**. The endpoint is the trust boundary now that there is no air-gap. Documented. |
| **Analog hole** | VNC/AnyDesk *screen view*, a phone photo of the screen. No file read, no bytes on a socket we own. | **Unstoppable by physics.** Read-taint only catches file-read → socket-send exfil. Stated plainly. |
| **Non-file sources** | Data typed from memory, generated, or pulled from a DB the driver doesn't see as a file read. | Read-taint keys on file reads; non-file sensitive data is out of scope for this mechanism. |
| **PID reuse** | A tainted PID exits and Windows recycles the number before the exit-notify removes it. | `PsSetCreateProcessNotifyRoutineEx` exit callback removes the entry at process teardown, before the number is reusable in practice; residual window documented. |

---

## 8. Coverage check (every brief scenario, honestly)

| Scenario | Handled? | By what |
|---|---|---|
| HTTPS upload of sensitive content by a native app | ✅ | read → taint → new HTTPS connect blocked (callout) / open socket reset (agent) |
| AnyDesk/TeamViewer file-transfer | ✅ | read → taint → connect blocked / flow reset; **and** relay not allow-listed → default-deny |
| Malware reads file, sends over its own encrypted socket | ✅ | read → taint → socket connect blocked by callout (content-blind) |
| Tainted process → an **allowed** destination | ✅ | kernel callout blocks by PID even though the destination is allow-listed |
| Agent's own mTLS check-in / incident upload | ✅ (never blocked) | agent PID never tainted + callout `CONTINUE`s it; mgmt server + DNS on allow-list |
| AnyDesk **screen view** (no file read) | ❌ by physics | analog hole — stated honestly |
| IPC laundering to a clean process | ⚠️ partial | helper is tainted; launderer's destination may be default-denied; full byte-taint out of scope |
| Data pushed before we reset the open flow | ⚠️ small race | new connects blocked instantly; open flow reset; residual race documented |

---

## 9. Build & runtime-verification posture

- **Build:** adds `fwpkclnt.lib` and one INITGUID translation unit; the proven
  `cl + link` recipe (km\crt-first include order, `/kernel`, `/INTEGRITYCHECK`
  `/GUARD:CF`, `/W4 /WX` + the benign WDK `/wd` codes) is preserved. Exact diff in
  the LLD §8.
- **Runtime (operator, manual, VM only):** load test-signed; enable **Driver
  Verifier** on `dlpflt.sys` with **Pool Tracking + Force IRQL Checking + Deadlock
  Detection + DDI compliance + Low-Resource Simulation + the WFP/NDIS checks**;
  run an **unload-while-connections-open** stress and an **unload-while-scan-job-
  in-flight** stress. WFP callouts are a classic BSOD source (IRQL, flow lifetime,
  unregister races) — this is mandatory, not optional. See LLD §10.
