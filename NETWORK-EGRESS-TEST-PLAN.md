# Network Egress Protection — Complete Manual Test Plan

**Purpose:** prove, end-to-end on a VM, that sensitive data cannot leave the endpoint over the
network — including over **encrypted** channels (HTTPS, RustDesk/AnyDesk) and by **apps/malware we
have never seen**. Covers all three network layers, every positive/negative case, and the honest
failure modes.

**Prepared:** 2026-08-10. Companion to `READTAINT-DEMO-RUNBOOK.md` (kernel setup detail) and
`USB-DEMO-RUNBOOK.md` (enrollment/bundle setup). Read those for the deep dive; this is the superset
test matrix.

---

## 0. The two network-egress layers (what blocks agent-detected data)

Blocking the data the agent detects as sensitive — over ANY tool, including encrypted ones — is done
by exactly **two app-agnostic layers**. Neither needs to know which app is exfiltrating:

| Layer | Mechanism | Keys on | Catches | Blind to |
|---|---|---|---|---|
| **L2 — Read-taint** | kernel minifilter + WFP callout | the **sensitive content** the agent detects | **ANY** app/malware that reads a detected file, even over TLS/RustDesk | raw-disk/kernel reads, IPC laundering, content not detected, unscanned paths |
| **L3 — Default-deny egress** | user-mode WFP allow-list | the **destination** | any process reaching a **non-approved** destination (unknown C2) | exfil to an *approved* destination |

L2 watches the **content** the agent flags (fingerprint today, any future detector); L3 watches the
**destination**. Together they are the network data-exfil defence — that is what this plan proves.

> **Not a layer — remote-tool blocking.** A signature list (AnyDesk/RustDesk/…) is content-blind: it
> blocks the tool *itself*, not detected data. It is **decoupled and OFF by default**
> (`remote_tool_action = "detect"` → visibility only, never blocks/kills). Its only unique job is the
> **analog hole** (someone screen-views a document and photographs it — no file leaves, nothing to
> detect). Exercised only if you deliberately opt in — see the **optional** §7.

> ⚠️ **This is the first runtime exercise of the kernel WFP callout.** A driver bug = BSOD.
> **Snapshot the VM before Section 3 and after every green milestone.** A clean compile is not a
> working driver.

---

## 1. Environment & prerequisites

1. **VM with a snapshot.** Windows 10/11 x64. Take a snapshot named `clean`.
2. **Test-signing on** (admin), then reboot:
   ```powershell
   bcdedit /set testsigning on
   shutdown /r /t 0
   ```
   Desktop shows a "Test Mode" watermark after reboot — good.
3. **Reach the management server.** `Test-NetConnection <server-host> -Port 8443` → `True`.
   (If the server cert has no IP SAN, add a hosts entry — see `USB-DEMO-RUNBOOK.md` §1.)
4. **Build fresh artifacts on the host** (they include the RustDesk signature + toast work):
   ```powershell
   cd C:\Users\lianli\Downloads\DLP_GUIDE\dlp-agent ;      cargo build --release   # -> target\release\dlp-agent.exe
   cd C:\Users\lianli\Downloads\DLP_GUIDE\dlp-minifilter ; cmd /c build\build-driver.bat   # -> build\out\dlpflt.sys (37,888 bytes)
   .\tools\sign-driver.ps1                                  # test-sign the .sys
   ```
5. **Copy to the VM** (e.g. `C:\dlp\`):
   - `dlp-agent.exe`, `dlpflt.sys` (signed), `tools\*.ps1`, `ca-cert.pem`, `samples\` (OPORD + variants),
     the test cert `.cer` (import to VM `LocalMachine\Root` + `TrustedPublisher` if not already trusted).

---

## 2. Agent setup (config, enrollment, bundle)

### 2.1 Config — `C:\ProgramData\DLPAgent\agent.toml`
This one file drives every channel. Point the agent at it with
`$env:DLP_AGENT_CONFIG = "C:\ProgramData\DLPAgent\agent.toml"` (or place at the default path).

```toml
server_url    = "https://<server-host>:8443"
ca_cert_path  = "C:\\dlp\\ca-cert.pem"
state_dir     = "C:\\dlp\\state"

# usb-guard / read-taint fingerprint thresholds + WHERE reads are scanned.
[kguard]
block_at          = 0.30
coverage_block_at = 0.60
fail_block        = true          # fail-secure
scan_fixed        = true          # also scan reads on C: UNDER a watch prefix (for RT-10b)
watch_paths       = ["\\Users\\<you>\\Desktop\\classified"]  # a fixed-volume watch dir (optional)

# Network egress — default-deny (the data-exfil layer). Ships as monitor (safe).
[netfilter]
mode               = "monitor"    # flip via --enforce allowlist|blocklist at run time
remote_tool_action = "detect"     # OFF by default (visibility only). Opt in with block_network/kill.
[[netfilter.rules]]
cidr = "<server-cidr>/32"         # management server (allow-list lifeline!)
port = 8443
action = "permit"
note = "mgmt-server mTLS"
[[netfilter.rules]]
cidr = "<dns-cidr>/32"            # DNS resolver (allow-list lifeline!)
port = 53
action = "permit"
note = "DNS"

# Endpoint "blocked by DLP" toast (fires on every block; a confirmation signal).
[notify]
enabled = true
mode = "standard"
```

### 2.2 Enroll + pull the fingerprint bundle
```powershell
cd C:\dlp
$env:DLP_AGENT_CONFIG = "C:\ProgramData\DLPAgent\agent.toml"
$env:DLP_AGENT_TOKEN  = "<ENROLLMENT-TOKEN-FROM-OPERATOR>"
.\dlp-agent.exe enroll         # -> certificate stored
.\dlp-agent.exe index-update   # -> "index bundle updated version=3"
.\dlp-agent.exe status         # -> enrolled + bundle present
```
**Gate:** if enrollment or `index-update` fails, STOP — read-taint has nothing to match against.

---

## 3. Driver + read-taint enable (L2)

### 3.1 Register + configure the driver (VM, admin)
```powershell
$svc = "HKLM\SYSTEM\CurrentControlSet\Services\dlpflt"
sc.exe create dlpflt type= filesys binPath= C:\dlp\dlpflt.sys
reg add $svc /v FailMode            /t REG_DWORD /d 1 /f      # fail-secure
reg add $svc /v ReadTaintEnabled    /t REG_DWORD /d 1 /f      # 1 = ON
reg add $svc /v TaintedEgressPolicy /t REG_DWORD /d 0 /f      # 0 = BLOCK_ALL (use 1 for BLOCK_NONLOCAL)
reg add "$svc\Instances" /v DefaultInstance /t REG_SZ /d "dlpflt Instance" /f
reg add "$svc\Instances\dlpflt Instance" /v Altitude /t REG_SZ /d 265000 /f
reg add "$svc\Instances\dlpflt Instance" /v Flags    /t REG_DWORD /d 0 /f
```

### 3.2 Load + verify
```powershell
fltmc load dlpflt
fltmc filters        # EXPECT: dlpflt @ altitude 265000
```
> If you previously loaded the OLD driver (no WFP callout), `fltmc unload dlpflt` first and copy the
> NEW signed `dlpflt.sys` into place before `fltmc load`.

### 3.3 Start the guard (the verdict answerer + live-TCP teardown)
```powershell
$env:DLP_AGENT_CONFIG = "C:\ProgramData\DLPAgent\agent.toml"
.\dlp-agent.exe usb-guard        # EXPECT: "connected to \DlpFltPort"; leave running, watch it
```
**Gate:** `usb-guard` MUST stay connected. If it isn't, fail-secure makes the driver taint the reader
of *any* removable file (over-taint) — see RT-11.

### 3.4 Enable Driver Verifier (recommended for the stress cases)
```powershell
verifier /standard /driver dlpflt.sys      # then reboot; catches IRQL/pool/leak/deadlock at runtime
```

---

## 4. Test material
- **Sensitive (removable):** copy `samples\OperationHimalayanShield_OPORD.pdf` to a USB/removable drive → `E:\OPORD.pdf`.
- **Sensitive (fixed-watch):** copy it to `C:\Users\<you>\Desktop\classified\OPORD.pdf` (matches `watch_paths`).
- **Innocent control:** any unrelated file → `E:\readme.txt`.
- **EDM text:** a file containing `Name: Priya Nair, Service No: SVC100002 ...` (Demo Personnel row).

---

## 5. Test matrix — L2 Read-taint (content-driven, APP-AGNOSTIC)

For each: **taint the process by reading the sensitive file, wait ~3 s (async scan), then attempt
egress from the SAME process.** Confirm via the `usb-guard` window (a `read-taint` block +
`reset tainted process's live TCP egress`), the endpoint toast, and the console Incidents page.

| ID | Scenario | Steps | Expected |
|---|---|---|---|
| **RT-01** | Same-process HTTPS block (core proof) | Fresh admin PS: `Test-NetConnection google.com -Port 443` (→True); `[IO.File]::ReadAllBytes('E:\OPORD.pdf').Length`; `Start-Sleep 3`; `Test-NetConnection google.com -Port 443` | 2nd test **False**; `Invoke-WebRequest https://google.com` throws |
| **RT-02** | Per-PID scope (control) | Open a NEW PS window (untainted); `Test-NetConnection google.com -Port 443` | **True** — only the reader is cut, not the whole box |
| **RT-03** | Negative — innocent content | In a fresh PS: read `E:\readme.txt`; `Start-Sleep 3`; `Test-NetConnection google.com -Port 443` | **True** — no taint (content-driven, not blanket) |
| **RT-04** | **Unknown "malware" — NO signature** | Fresh PS: `curl.exe -o NUL file:///E:/OPORD.pdf` (or `Get-Content E:\OPORD.pdf`); `Start-Sleep 3`; `curl.exe https://example.com` | **blocked** — `curl.exe` is on no list; read-taint caught it purely on content. **This is the answer to "we don't know which app."** |
| **RT-05** | RustDesk copy (content-driven) | Connect a RustDesk session; copy `E:\OPORD.pdf` via file transfer | Transfer fails / session drops (see caveat A) |
| **RT-06** | Live-connection teardown | Open a long-lived TCP (e.g. `$c=[Net.Sockets.TcpClient]::new('google.com',443)`); THEN read `E:\OPORD.pdf` in the same PS | Existing connection **drops** (`reset_pid_connections`) + new connects blocked |
| **RT-07** | Substantiality gate (edge) | Read only 1 byte: `$f=[IO.File]::OpenRead('E:\OPORD.pdf'); $f.ReadByte(); $f.Close()`; try egress | **NOT** blocked — a 1-byte probe doesn't arm a 4 MiB scan |
| **RT-08** | Repeat-read fast path | After RT-01, a DIFFERENT fresh process reads `E:\OPORD.pdf`; try egress | Tainted **instantly** (no scan delay) — sensfile cache hit |
| **RT-09** | Process-exit untaint (PID reuse) | Taint a process, close it, spawn new processes until a PID is reused; that clean process egresses | **Allowed** — taint cleared on exit; no under/over-block |
| **RT-10a** | Fixed volume, NOT watched (expected miss) | Read a copy of OPORD from `C:\Temp\OPORD.pdf` (not under a watch path); try egress | **NOT** blocked — documents that C:\ reads are only scanned under a watch prefix |
| **RT-10b** | Fixed volume, WATCHED | Read `C:\Users\<you>\Desktop\classified\OPORD.pdf`; try egress | **Blocked** — watch prefix armed read-taint on a fixed volume |
| **RT-11** | Fail-secure (guard down) | Stop `usb-guard`; read `E:\readme.txt` (innocent) from a fresh PS; try egress | With guard down the driver applies FailMode=BLOCK → reader tainted (over-block). Proves killing the guard can't be used to exfiltrate. Restart guard to clear. |
| **RT-12** | `BLOCK_NONLOCAL` policy | Set `TaintedEgressPolicy=1`, reload driver; taint a process; then connect to a **LAN** host and to a **public** host | LAN/loopback **permitted**, public **blocked** |
| **RT-13** | Agent self never tainted | Confirm `usb-guard` / the service PID keep checking in while other processes are tainted | Agent traffic **never** blocked (driver skips its service PID + System) |
| **RT-14** | **Known gap — IPC laundering** | Helper process reads `E:\OPORD.pdf` and pipes bytes to a SEPARATE clean process that egresses | **NOT** blocked (single-hop taint limit — documented; child-process taint inheritance is the follow-on) |

**Caveat A (RT-05):** taint keys on the PID that *read* the file. `rustdesk.exe` usually does both the
read and the network, so it should work; if it forks file I/O to a helper PID, the teardown may miss —
that's what the L3/remote-tool layers backstop. Not a bug; a documented limit.

---

## 6. Test matrix — L3 Default-deny egress (destination-driven, APP-AGNOSTIC)

> `allowlist` is default-DENY and CAN brick connectivity. Your `[netfilter.rules]` MUST permit the
> agent's lifelines (mgmt server + DNS) or the agent cuts itself off. Test in this order.

| ID | Scenario | Steps | Expected |
|---|---|---|---|
| **DD-01** | Monitor (safe baseline) | `dlp-agent.exe net-monitor` | Nothing blocked; remote-tool processes logged as incidents; no filters installed |
| **DD-02** | **Allow-list blocks unknown dest** | `dlp-agent.exe net-monitor --enforce allowlist` (admin); from any app hit a NON-approved host (`Test-NetConnection 1.1.1.1 -Port 443`) | **Blocked** — unknown destination denied regardless of app/content. This is the unknown-C2 answer. |
| **DD-03** | Allow-list lifelines intact (self-DoS check) | While allowlist is enforced: `dlp-agent.exe once` (check-in) + DNS resolve | **Succeed** — mgmt server + DNS permits keep the agent alive |
| **DD-04** | Approved destination allowed | While allowlist enforced: connect to the permitted mgmt `host:8443` | **Allowed** |
| **DD-05** | Blocklist mode | `dlp-agent.exe net-monitor --enforce blocklist`; add a deny rule for a test host | That host **blocked**, everything else **allowed** (default-permit) |

---

## 7. (Optional, opt-in) Remote-tool block — hygiene, NOT a data-exfil layer

> This is **off by default** (`remote_tool_action = "detect"` → visibility only). It does NOT block
> agent-detected data (L2/L3 do that); it only forbids the *tool itself*, for the analog-hole case.
> To run these cases you must **opt in**: set `[netfilter] remote_tool_action = "block_network"` (or
> `"kill"`) in `agent.toml`, then `net-monitor --enforce blocklist`.

| ID | Scenario | Steps | Expected |
|---|---|---|---|
| **RTL-01** | RustDesk blocked by name | `net-monitor --enforce blocklist` with RustDesk running | `rustdesk.exe` egress blocked (app-id WFP); can't reach relay |
| **RTL-02** | Kill override | Set `[netfilter] remote_tool_action = "kill"` (or per-tool override); rerun | RustDesk process **terminated** (admin) |
| **RTL-03** | **Renamed tool defeats the signature — read-taint still catches it** | Rename `rustdesk.exe` → `svchost2.exe`; run it; blocklist misses it; now copy `E:\OPORD.pdf` with it | Signature **misses** (proves lists don't scale), but **read-taint blocks the copy** on content — the two layers together |
| **RTL-04** | Incident labeling | After RTL-01, check the console Incidents page | Network incident, channel `network`, tool `rustdesk` |

---

## 8. Composition test (layers together)

| ID | Scenario | Expected |
|---|---|---|
| **CX-01** | Read-taint COMPOSES with allow-list | With `--enforce allowlist` AND read-taint on: a **tainted** process is blocked **even to an approved destination** (kernel callout returns BLOCK), while a **clean** process still reaches approved destinations. Read-taint returns CONTINUE (not PERMIT), so it never overrides the allow-list. |

---

## 9. Edge cases & failure modes (must exercise before claiming runtime-safe)

| ID | Case | Expected / note |
|---|---|---|
| **EF-01** | **USB-yank / volume dismount while a read scan is queued** | No BSOD; `FltReadFile` fails cleanly. This is the one by-design teardown race the review flagged — exercise with Driver Verifier ON. |
| **EF-02** | Scan-queue flood | Read hundreds of files fast; excess scan jobs are **dropped** (a miss, fail-safe) — no non-paged-pool growth, no hang |
| **EF-03** | IPv6 egress | Tainted process's **new** v6 connects blocked by the callout; note user-mode can't reset live v6 flows (no `SetTcp6Entry`) — documented residual |
| **EF-04** | Circuit breaker | Wedge/stop the guard mid-run: after N consecutive IPC timeouts the driver stops up-calling and applies FailMode; a live reply clears it |
| **EF-05** | Epoch invalidation on reconnect | Restart `usb-guard`; cached sensfile entries invalidate (policy epoch bump); taint (deliberately) persists |
| **EF-06** | Driver unload under load | While reads/taints are active: `fltmc unload dlpflt` drains the worker + WFP teardown in order, no leak/BSOD (Verifier ON) |
| **EF-07** | Toast delivery from Session 0 | Blocks fire the endpoint toast into the interactive session (CreateProcessAsUserW); with no interactive user, toast is skipped, block still stands |

---

## 10. How to read the results (confirmation signals)

- **`usb-guard` console:** `read-taint block ...`, `reset tainted process's live TCP egress`,
  `kguard incident reported kind=Match`.
- **Endpoint toast:** "Blocked by DLP · File · Channel · Ref" pops for the user (unless `mode=covert`).
- **Console Incidents page** (`incident_reviewer` login): channel, action=`blocked`, detection type,
  matched document + containment; the human ref `INC-xxxxxx`.
- **WFP filters installed:** `netsh wfp show filters` (look for the DLP sublayer / app-id blocks).
- **Reachability:** `Test-NetConnection <host> -Port <p>` → `TcpTestSucceeded` True/False.
- **Filter attach:** `fltmc filters` / `fltmc instances`.

---

## 11. Teardown / rollback
```powershell
# stop usb-guard + net-monitor (Ctrl-C)
fltmc unload dlpflt
verifier /reset            # if you enabled Driver Verifier (then reboot)
reg delete HKLM\SYSTEM\CurrentControlSet\Services\dlpflt /v ReadTaintEnabled /f
reg delete HKLM\SYSTEM\CurrentControlSet\Services\dlpflt /v TaintedEgressPolicy /f
# or simply roll back the VM snapshot
bcdedit /set testsigning off ; shutdown /r /t 0
```

---

## 12. Results log (fill in)

| ID | Result (PASS/FAIL/DEVIATION) | Notes (what you saw, logs) |
|---|---|---|
| RT-01 | | |
| RT-02 | | |
| RT-03 | | |
| RT-04 | | |
| RT-05 | | |
| RT-06 | | |
| RT-07 | | |
| RT-08 | | |
| RT-09 | | |
| RT-10a | | |
| RT-10b | | |
| RT-11 | | |
| RT-12 | | |
| RT-13 | | |
| RT-14 (gap) | | |
| DD-01 | | |
| DD-02 | | |
| DD-03 | | |
| DD-04 | | |
| DD-05 | | |
| RTL-01 | | |
| RTL-02 | | |
| RTL-03 | | |
| RTL-04 | | |
| CX-01 | | |
| EF-01..07 | | |

**Bring back anything that BSODs, doesn't block, over-blocks, or deadlocks** — capture the `usb-guard`
log line + the exact step, and we fix + rebuild. A clean compile is not a working driver; this matrix
is where it becomes one.

---

## Appendix — honest limits that STAND regardless of results
- **Analog hole:** screen-view over RustDesk/RDP + a phone camera — no software stops this.
- **Kernel-privileged malware** can unhook the driver / read raw disk beneath the filter → needs EDR +
  Secure Boot + least-privilege (defence-in-depth, not anti-rootkit).
- **IPC laundering & derived files** (single-hop taint) — RT-14; child-process taint inheritance +
  derived-file propagation are the documented follow-ons.
- **Encrypted-at-rest content** the agent never sees as matching plaintext won't taint.
- "Zero exfiltration" is never claimed. The posture is **read-taint (content) + default-deny
  (destination) + EDR/least-privilege**, layered — with optional, opt-in remote-tool/device hygiene
  for the analog-hole case.
