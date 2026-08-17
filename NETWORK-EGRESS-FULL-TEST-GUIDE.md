# On-Prem DLP — Full Network-Egress Test Guide (from scratch)

**Purpose:** a single self-contained runbook that goes from **nothing** → management server up →
admin + roles → fingerprint bundle + enrollment token → agent enrolled on a VM → kernel read-deny
loaded → **network-egress test matrix** (read-deny + default-deny, app-agnostic / unknown-malware
cases, edge + failure modes; plus the optional, opt-in remote-tool hygiene).

**Prepared:** 2026-08-10. **Revised 2026-08-13:** the read-taint layer was removed; **read-deny**
(deny an exfil-classified process the *read* of flagged content — the bytes never reach the tool) is
now the sole content-driven network-exfil layer. Deep read-deny detail + the VirtualBox walkthrough
live in `VM-COPY-BLOCK-RUNBOOK.md` and `dlp-minifilter/docs/read-deny-LLD.md`; USB/enrollment/bundle
setup in `USB-DEMO-RUNBOOK.md`.

**Two machines:**
- **HOST** — runs the management server (Node + Postgres) and builds the agent + driver.
- **VM** — the endpoint under test. **Snapshot it** — the kernel driver is unproven at runtime; a bug
  is a BSOD.

---

## 0. The two network-egress layers (what blocks agent-detected data)

Blocking the data the agent detects as sensitive — over ANY tool, including encrypted ones — is done
by exactly **two app-agnostic layers**. Neither needs to know which app is exfiltrating:

| Layer | Mechanism | Keys on | Catches | Blind to |
|---|---|---|---|---|
| **L2 — Read-deny** | kernel minifilter `DlpPreRead` / section-sync + agent exfil-PID tracker | the **sensitive content** an **exfil-channel process** reads | an exfil tool (RustDesk/AnyDesk/VNC, an unknown process holding a public connection, or a VM worker) trying to read a flagged file — the bytes never leave the disk | reads by non-exfil processes, content not detected, unscanned paths |
| **L3 — Default-deny egress** | user-mode WFP allow-list | the **destination** | any process reaching a **non-approved** destination (unknown C2) | exfil to an *approved* destination |

L2 keys on **who is reading + what they read** (an exfil-classified PID reading flagged content is
DENIED the read); L3 keys on the **destination**. Together they are the network data-exfil defence —
that is what this plan proves.

> **Not a layer — remote-tool blocking.** A signature list (AnyDesk/RustDesk/…) is content-blind: it
> blocks the tool *itself*, not detected data. It is **decoupled and OFF by default**
> (`remote_tool_action = "detect"` → visibility only). Its only unique job is the **analog hole**
> (someone screen-views a document and photographs it — no file leaves, nothing to detect). The same
> signature set also feeds L2 as one of the exfil-PID classifiers. Exercised as a *block* only if you
> deliberately opt in — see the **optional** §7.

> ⚠️ **This is the first runtime exercise of the kernel read-deny path.** A driver bug = BSOD.
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
4. **Build fresh artifacts on the host:**
   ```powershell
   cd D:\DLP_GUIDE\dlp-agent ;      cargo build --release   # -> target\release\dlp-agent.exe
   cd D:\DLP_GUIDE\dlp-minifilter ; cmd /c build\build-driver.bat   # -> build\out\dlpflt.sys (35,840 bytes)
   .\tools\sign-driver.ps1                                  # test-sign the .sys
   ```
5. **Copy to the VM** (e.g. `C:\dlp\`):
   - `dlp-agent.exe`, `dlpflt.sys` (signed), `tools\*.ps1`, `ca-cert.pem`, `samples\` (OPORD + variants),
     the test cert `.cer` (import to VM `LocalMachine\Root` + `TrustedPublisher` if not already trusted).

---

## 2. Agent setup (config, enrollment, bundle)

### 2.1 Config — `C:\ProgramData\DLPAgent\agent.toml`
This one file drives every channel.

```toml
server_url    = "https://<server-host>:8443"
ca_cert_path  = "C:\\dlp\\ca-cert.pem"
state_dir     = "C:\\dlp\\state"

# usb-guard thresholds + WHERE reads are scanned (read-deny scope on fixed volumes).
[kguard]
block_at          = 0.30
coverage_block_at = 0.60
fail_block        = true          # fail-secure
scan_fixed        = true          # also scope read-deny to C: reads UNDER a watch prefix (for RD-fixed)
watch_paths       = ["\\Users\\<you>\\Desktop\\classified"]  # a fixed-volume watch dir (optional)
exfil_read_block  = true          # run the exfil-PID tracker + push the set to the driver

# Network egress — default-deny (the destination layer). Ships as monitor (safe).
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

# Endpoint "blocked by DLP" toast (a confirmation signal).
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
**Gate:** if enroll/index-update fail, STOP — read-deny has nothing to match against.

---

## 3. Driver + read-deny enable (L2)

### 3.1 Register + configure the driver (VM, admin)
```powershell
$svc = "HKLM\SYSTEM\CurrentControlSet\Services\dlpflt"
sc.exe create dlpflt type= filesys binPath= C:\dlp\dlpflt.sys
reg add $svc /v FailMode              /t REG_DWORD /d 1 /f      # fail-secure
reg add $svc /v ExfilReadBlockEnabled /t REG_DWORD /d 1 /f      # 1 = read-deny ON (default 0)
reg add $svc /v ExfilReadFailBlock    /t REG_DWORD /d 1 /f      # deny exfil-PID reads of unverifiable content
reg add "$svc\Instances" /v DefaultInstance /t REG_SZ /d "dlpflt Instance" /f
reg add "$svc\Instances\dlpflt Instance" /v Altitude /t REG_SZ /d 265000 /f
reg add "$svc\Instances\dlpflt Instance" /v Flags    /t REG_DWORD /d 0 /f
```

### 3.2 (Recommended) Driver Verifier for the stress cases
```powershell
verifier /standard /driver dlpflt.sys      # then reboot; catches IRQL/pool/leak/deadlock
```

### 3.3 Load + verify
```powershell
fltmc load dlpflt
fltmc filters        # EXPECT: dlpflt @ altitude 265000
```
> If an OLD `dlpflt.sys` is loaded: `fltmc unload dlpflt`, copy the NEW signed one, reload.

### 3.4 Start the guard (verdict answerer + exfil-PID pusher) — leave running
```powershell
$env:DLP_AGENT_CONFIG = "C:\ProgramData\DLPAgent\agent.toml"
.\dlp-agent.exe usb-guard        # EXPECT "connected to \DlpFltPort"; watch this window
```
Every ~2 s expect `pushed exfil-channel PID set to driver count=… pids=[…]`.
**Gate:** the guard MUST stay connected — see RD-fail for what happens if it isn't.

### 3.5 Stage test material
- **Sensitive (removable):** `samples\OperationHimalayanShield_OPORD.pdf` → USB/removable `E:\OPORD.pdf`.
- **Sensitive (fixed-watch):** same file → `C:\Users\<you>\Desktop\classified\OPORD.pdf`.
- **Innocent control:** any unrelated file → `E:\readme.txt`.

---

## 4. Network-egress test matrix

## D1 — L2 Read-deny (content + exfil-channel driven, APP-AGNOSTIC)

The definitive walkthrough (Test A: fake-hypervisor via `LoadLibrary`; Test B: real VirtualBox
shared-folder / drag-drop / clipboard-paste denial; the substrate-detection notes) is
`VM-COPY-BLOCK-RUNBOOK.md`. The compact matrix:

| ID | Scenario | Steps | Expected |
|---|---|---|---|
| **RD-01** | Exfil tool reads sensitive (core) | RustDesk/AnyDesk session up; use its file transfer to send `E:\OPORD.pdf` | **read denied** — transfer fails; guard logs `exfil-read-denied` |
| **RD-02** | Exfil tool reads innocent | same tool, transfer `E:\readme.txt` | **allowed** — transfers fine (content-driven, not a process ban) |
| **RD-03** | Non-exfil app reads sensitive | Notepad/Word opens `E:\OPORD.pdf` locally | **allowed** — not an exfil channel |
| **RD-04** | **Unknown tool, NO signature (behavioral)** | a process with a live PUBLIC TCP connection reads `E:\OPORD.pdf` | **denied** — caught on the behavioral exfil signal, not a name list |
| **RD-05** | VM worker (shared folder / drag-drop / clipboard) | VirtualBox guest copies `E:\OPORD.pdf` from a host share | **denied** — host-side read by the VM worker PID is denied (see VM-COPY-BLOCK Test B) |
| **RD-mmap** | Mapped-read exfil | a tool that memory-maps the file rather than `ReadFile`s it | **denied at the section** (`ACQUIRE_FOR_SECTION_SYNCHRONIZATION` pre-op) |
| **RD-fixed** | Fixed volume, WATCHED | exfil tool reads `C:\Users\<you>\Desktop\classified\OPORD.pdf` | **denied** — watch prefix scoped read-deny on C: |
| **RD-fixed-miss** | Fixed volume, NOT watched | exfil tool reads `C:\Temp\OPORD.pdf` | **allowed** — C: reads only scoped under a watch prefix (documented) |
| **RD-fail** | Fail-secure (guard down) | stop `usb-guard`; exfil PID reads an unverifiable file | with `ExfilReadFailBlock=1` the read is denied — killing the guard can't be used to exfiltrate. Restart guard to clear |
| **RD-off** | Default off | set `ExfilReadBlockEnabled=0`, reload driver; repeat RD-01 | **nothing denied** — opt-in, fail-safe |

## D2 — L3 Default-deny egress (destination-driven, APP-AGNOSTIC)
> `allowlist` is default-DENY and can brick connectivity — your `[netfilter.rules]` MUST permit the
> mgmt server + DNS lifelines. Test in order.

| ID | Scenario | Steps | Expected |
|---|---|---|---|
| **DD-01** | Monitor baseline | `dlp-agent net-monitor` | Nothing blocked; remote-tool processes logged; no filters installed |
| **DD-02** | **Allow-list blocks unknown dest** | `dlp-agent net-monitor --enforce allowlist` (admin); `Test-NetConnection 1.1.1.1 -Port 443` | **Blocked** — unknown destination denied. *The unknown-C2 answer.* |
| **DD-03** | Lifelines intact (self-DoS check) | While enforced: `dlp-agent once` + DNS resolve | **Succeed** |
| **DD-04** | Approved dest allowed | While enforced: connect to permitted mgmt `host:8443` | **Allowed** |
| **DD-05** | Blocklist mode | `dlp-agent net-monitor --enforce blocklist` + a deny rule for a test host | that host **blocked**, rest **allowed** |

## D3 — (Optional, opt-in) Remote-tool block — hygiene, NOT a data-exfil layer

> **Off by default** (`remote_tool_action = "detect"` → visibility only, never blocks/kills). It does
> NOT block agent-detected data — L2 (read-deny) + L3 (default-deny) do. It only forbids the *tool
> itself*, and its sole unique value is the analog hole (screen-view + photograph). To run these
> cases, **opt in**: set `[netfilter] remote_tool_action = "block_network"` (or `"kill"`) in
> `agent.toml`, then `net-monitor --enforce blocklist`.

| ID | Scenario | Steps | Expected |
|---|---|---|---|
| **RTL-01** | RustDesk blocked by name | `net-monitor --enforce blocklist`, RustDesk running | `rustdesk.exe` egress blocked (app-id WFP) |
| **RTL-02** | Kill override | `[netfilter] remote_tool_action="kill"`; rerun | RustDesk **terminated** |
| **RTL-03** | **Renamed tool defeats signature — read-deny still catches** | Rename `rustdesk.exe`→`svchost2.exe`; run; blocklist misses; the renamed tool holds a public connection so it is still an exfil PID; it reads `E:\OPORD.pdf` | Signature **misses**, but read-deny **denies the read** on the behavioral signal |
| **RTL-04** | Incident labeling | Check Incidents page after RTL-01 | channel `network`, tool `rustdesk` |

---

## D4 — Edge / failure modes (exercise with Driver Verifier ON)

| ID | Case | Expected |
|---|---|---|
| **EF-01** | USB-yank / dismount while a classify read is in flight | No BSOD; `FltReadFile` fails cleanly; classify fails-safe per `ExfilReadFailBlock` |
| **EF-02** | Exfil PID re-reads many innocent files | each classified once (CleanFile cache); no per-open up-call storm |
| **EF-03** | Agent self never denied | `usb-guard`/service keeps checking in while an exfil PID is denied | agent I/O is skip-self (never denied) |
| **EF-04** | Circuit breaker | wedge/stop the guard mid-run: after N IPC timeouts the driver short-circuits to fail-safe; a live reply clears it |
| **EF-05** | Epoch invalidation | Restart `usb-guard` → SensFile/CleanFile caches invalidate (content epoch bump) |
| **EF-06** | Unload under load | `fltmc unload dlpflt` during active classifies: no leak/BSOD (Verifier ON) |
| **EF-07** | Toast from Session 0 | Block toast reaches the interactive session; none logged-in → toast skipped, block stands |

---

# PART E — Reading the results

- **`usb-guard` window:** `pushed exfil-channel PID set`, `exfil-read-denied` (a denied read),
  `kguard incident reported kind=Match`.
- **Endpoint toast:** "Blocked by DLP · File · Channel · Ref INC-xxxx" (unless `mode=covert`).
- **Console Incidents page:** log in as the `incident_reviewer`. Denied reads show channel, action
  `blocked`, note `exfil-read-denied`, the matched document + containment.
- **WFP filters (L3):** `netsh wfp show filters` (DLP sublayer / app-id blocks).
- **Reachability:** `Test-NetConnection <host> -Port <p>` → `TcpTestSucceeded`.
- **Filter attach:** `fltmc filters` / `fltmc instances`.

---

# PART F — Teardown / rollback (VM)
```powershell
# Ctrl-C usb-guard + net-monitor
fltmc unload dlpflt
verifier /reset                 # if enabled (then reboot)
reg delete HKLM\SYSTEM\CurrentControlSet\Services\dlpflt /v ExfilReadBlockEnabled /f
reg delete HKLM\SYSTEM\CurrentControlSet\Services\dlpflt /v ExfilReadFailBlock /f
bcdedit /set testsigning off ; shutdown /r /t 0
# — or just roll back the VM snapshot.
```

---

## Appendix — honest limits (stand regardless of results)
- **Analog hole:** screen-view over RustDesk/RDP + a phone camera — unstoppable by software.
- **Kernel-privileged malware** can unhook the driver / read raw disk beneath the filter → needs EDR +
  Secure Boot + least-privilege.
- **Non-exfil laundering:** a non-exfil helper process reads the file, then hands the bytes to an
  exfil tool via IPC — read-deny keys on the *reader's* exfil status, so a clean reader is not denied.
  Backstopped by L3 default-deny on the destination; documented gap.
- **Encrypted-at-rest** content the agent never sees as matching plaintext won't be flagged.
- **This is the first runtime exercise of the kernel read-deny path** — a clean compile is not a
  working driver. Snapshot; keep Verifier on; bring back anything that BSODs, over-blocks, or deadlocks.
- "Zero exfiltration" is never claimed. The posture is **read-deny (content + exfil-channel) +
  default-deny (destination) + EDR/least-privilege**, layered — with optional, opt-in remote-tool
  hygiene for the analog-hole case.
