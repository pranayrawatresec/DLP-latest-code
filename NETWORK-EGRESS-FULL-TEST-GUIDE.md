# On-Prem DLP — Full Network-Egress Test Guide (from scratch)

**Purpose:** a single self-contained runbook that goes from **nothing** → management server up →
admin + roles → fingerprint bundle + enrollment token → agent enrolled on a VM → kernel read-taint
loaded → **complete network-egress test matrix** (read-taint + default-deny, app-agnostic /
unknown-malware cases, edge + failure modes; plus the optional, opt-in remote-tool hygiene).

**Prepared:** 2026-08-10. Supersedes the split runbooks (`USB-DEMO-RUNBOOK.md`,
`READTAINT-DEMO-RUNBOOK.md`, `NETWORK-EGRESS-TEST-PLAN.md`) for the network test — everything you need
is here.

**Two machines:**
- **HOST** — runs the management server (Node + Postgres) and builds the agent + driver.
- **VM** — the endpoint under test. **Snapshot it** — the kernel driver is unproven at runtime; a bug
  is a BSOD.

---

# PART A — Management server (HOST)

## A0. Prerequisites (HOST)
- Node.js 18+ and Docker Desktop.
- Rust toolchain (`cargo`) to build the agent.
- WDK + MSVC (already present here) to build the driver via `build\build-driver.bat`.
- Working dir: `C:\Users\lianli\Downloads\DLP_GUIDE\dlp-management-server` unless noted.

## A1. Start PostgreSQL
```powershell
cd C:\Users\lianli\Downloads\DLP_GUIDE\dlp-management-server
docker compose up -d           # container dlp-server-postgres on 127.0.0.1:5432 (db/user dlp)
docker ps --format '{{.Names}}' # expect dlp-server-postgres
```

## A2. Apply database migrations
```powershell
npm install                    # first time only
npm run migrate                # applies 001..005 (incl. incident enrichment)
```

## A3. Initialise the internal CA
```powershell
npm run init-ca                # generates the CA (ca/ca-cert.pem) used for mTLS + bundle signing
```

## A4. Create the first sysadmin (CLI only — no open signup)
```powershell
$env:DLP_ADMIN_EMAIL = "admin@yourorg.test"
$env:DLP_ADMIN_PASSWORD = "change-me-please-12+"   # min 12 chars
npm run bootstrap-admin        # creates ONE sysadmin; "Log in through the console UI."
```
(Omit the env vars to be prompted interactively with no echo.)

## A5. Start the server processes
Open three terminals in `dlp-management-server`:
```powershell
npm start            # console API  -> http://localhost:3001   (bin/www, PORT=3001)
npm run agent-server # agent mTLS   -> https://<host>:8443      (enrollment + check-in + bundle)
npm run worker       # fingerprint worker (extracts + fingerprints uploaded docs, compiles bundles)
```
And the console UI (frontend), in `dlp-management-frontend`:
```powershell
cd ..\dlp-management-frontend
npm install          # first time
npm run dev          # Vite dev server (proxies /api -> :3001). Open the printed http://localhost:5173
```

## A6. Log in + create the working roles
1. Browse to the Vite URL, log in as the sysadmin from A4.
2. **Administrators → add users** (separation of duties — sysadmin cannot do these itself):
   - a **`policy_author`** (needed to register documents + by `provision-demo`),
   - an **`incident_reviewer`** (needed to view the incident detail during the test).
   > sysadmin deliberately holds **neither** `incidents.read` nor `protect:write` — that's the RBAC
   > separation. You will log in as the reviewer in Part E to see blocked-file incidents.

## A7. Provision the detection bundle + an enrollment token (manual, via the UI — you do this yourself)
Do this yourself in the console UI. It spans **two roles** (separation of duties): the
**`policy_author`** registers + compiles the fingerprint bundle; the **`sysadmin`** mints the
enrollment token.

**Log in as `policy_author`:**
1. **Protected documents → New collection** — name it (e.g. "Ops") and set a classification level.
2. **Register document** — upload `samples\OperationHimalayanShield_OPORD.pdf` into that collection.
3. Wait for the **fingerprint worker** (from A5, `npm run worker`) to process it — the document's
   status turns to *ready / fingerprinted* (refresh the page). This is the step that turns the PDF
   into IDM fingerprints.
4. **Protected documents → Compile index** — builds + CA-signs the bundle. Note the **bundle version**
   (it increments on every compile; the agent pulls the latest signed version).
   > Optional, and NOT needed for these network tests: an EDM source can be added the same way — the
   > RT cases here only use the OPORD IDM document.

**Log in as `sysadmin`:**
5. **Enrollment tokens → New token** — set uses (e.g. 3) and expiry (e.g. 72h). **Copy the token value
   now** (it is shown once). That is the `<ENROLLMENT-TOKEN>` you paste in B4.

> Automated alternative (only if you ever want the one-shot instead of doing it yourself):
> `node scripts/provision-demo.js` from `dlp-management-server` does all of the above in one command
> (OPORD IDM + Demo Personnel EDM + token) and prints the values.

## A8. Confirm server state
- `http://localhost:3001` reachable; Vite UI logs in.
- The OPORD document shows *fingerprinted*, and **Compile index** produced a new signed bundle version.
- You copied an enrollment token from the **Enrollment tokens** page.
- `agent-server` listening on `:8443`.

---

# PART B — Endpoint agent (VM)

## B1. VM prerequisites
1. **Snapshot the VM** (`clean`).
2. **Enable test-signing** + reboot:
   ```powershell
   bcdedit /set testsigning on
   shutdown /r /t 0
   ```
3. **Reach the server.** `Test-NetConnection <host> -Port 8443` → `True`. If the server cert has no
   IP SAN, add a hosts entry mapping the server hostname to the HOST LAN IP
   (`C:\Windows\System32\drivers\etc\hosts`), then re-test.

## B2. Build artifacts (HOST) and copy to the VM
```powershell
# On the HOST:
cd C:\Users\lianli\Downloads\DLP_GUIDE\dlp-agent ;      cargo build --release   # target\release\dlp-agent.exe
cd C:\Users\lianli\Downloads\DLP_GUIDE\dlp-minifilter ; cmd /c build\build-driver.bat   # build\out\dlpflt.sys (37,888 bytes)
.\tools\sign-driver.ps1        # test-sign dlpflt.sys (creates/uses the test cert)
```
Copy to the VM `C:\dlp\`:
`dlp-agent.exe`, signed `dlpflt.sys`, `ca-cert.pem` (from `dlp-management-server\ca\ca-cert.pem`),
`samples\` (OPORD + variants), and the test code-signing `.cer`.
Import the `.cer` on the VM to `LocalMachine\Root` **and** `TrustedPublisher` (once).

## B3. Agent config — `C:\ProgramData\DLPAgent\agent.toml` (VM)
```toml
server_url    = "https://<host>:8443"
ca_cert_path  = "C:\\dlp\\ca-cert.pem"
state_dir     = "C:\\dlp\\state"

[kguard]                     # read-taint fingerprint thresholds + WHERE reads are scanned
block_at          = 0.30
coverage_block_at = 0.60
fail_block        = true
scan_fixed        = true     # also scan C: reads UNDER a watch prefix (needed for RT-10b)
watch_paths       = ["\\Users\\<you>\\Desktop\\classified"]

[netfilter]                  # default-deny egress (the data-exfil layer). Ships as monitor (safe).
mode               = "monitor"
remote_tool_action = "detect"          # OFF by default (visibility only). Opt in with block_network/kill.
[[netfilter.rules]]
cidr = "<server-cidr>/32"    # ALLOW-LIST LIFELINE: mgmt server
port = 8443
action = "permit"
note = "mgmt-server mTLS"
[[netfilter.rules]]
cidr = "<dns-cidr>/32"       # ALLOW-LIST LIFELINE: DNS
port = 53
action = "permit"
note = "DNS"

[notify]                     # endpoint "blocked by DLP" toast (a confirmation signal)
enabled = true
mode = "standard"
```

## B4. Enroll + pull the fingerprint bundle (VM)
```powershell
cd C:\dlp
$env:DLP_AGENT_CONFIG = "C:\ProgramData\DLPAgent\agent.toml"
$env:DLP_AGENT_TOKEN  = "<ENROLLMENT-TOKEN-FROM-A7>"
.\dlp-agent.exe enroll         # keypair + CSR -> CA-signed client cert; first check-in
.\dlp-agent.exe index-update   # downloads bundle v3, verifies CA signature, caches it
.\dlp-agent.exe status         # enrolled + bundle present
```
**Gate:** if enroll/index-update fail, STOP — read-taint has no policy to match.

---

# PART C — Kernel driver + read-taint enable (VM, admin)

## C1. Register + configure the driver
```powershell
$svc = "HKLM\SYSTEM\CurrentControlSet\Services\dlpflt"
sc.exe create dlpflt type= filesys binPath= C:\dlp\dlpflt.sys
reg add $svc /v FailMode            /t REG_DWORD /d 1 /f      # fail-secure
reg add $svc /v ReadTaintEnabled    /t REG_DWORD /d 1 /f      # 1 = ON (default is OFF)
reg add $svc /v TaintedEgressPolicy /t REG_DWORD /d 0 /f      # 0 = BLOCK_ALL (1 = BLOCK_NONLOCAL)
reg add "$svc\Instances" /v DefaultInstance /t REG_SZ /d "dlpflt Instance" /f
reg add "$svc\Instances\dlpflt Instance" /v Altitude /t REG_SZ /d 265000 /f
reg add "$svc\Instances\dlpflt Instance" /v Flags    /t REG_DWORD /d 0 /f
```

## C2. (Recommended) Driver Verifier for the stress cases
```powershell
verifier /standard /driver dlpflt.sys   # then reboot; catches IRQL/pool/leak/deadlock at runtime
```

## C3. Load + verify
```powershell
fltmc load dlpflt
fltmc filters        # EXPECT: dlpflt @ altitude 265000
```
> If an OLD `dlpflt.sys` (no WFP callout) is loaded: `fltmc unload dlpflt`, copy the NEW signed one, reload.

## C4. Start the guard (verdict answerer + live-TCP teardown) — leave running
```powershell
$env:DLP_AGENT_CONFIG = "C:\ProgramData\DLPAgent\agent.toml"
.\dlp-agent.exe usb-guard     # EXPECT "connected to \DlpFltPort"; watch this window during tests
```
**Gate:** `usb-guard` must stay connected — see RT-11 for what happens if it isn't.

## C5. Stage test material
- **Sensitive (removable):** `samples\OperationHimalayanShield_OPORD.pdf` → USB/removable `E:\OPORD.pdf`.
- **Sensitive (fixed-watch):** same file → `C:\Users\<you>\Desktop\classified\OPORD.pdf`.
- **Sensitive (fixed-UNwatched):** same file → `C:\Temp\OPORD.pdf`.
- **Innocent control:** any unrelated file → `E:\readme.txt`.

---

# PART D — Network-egress test matrix

**Method for read-taint cases:** in the SAME process, (1) baseline-connect, (2) read the sensitive
file, (3) wait ~3 s (async scan), (4) attempt egress again. Confirm via `usb-guard` log
(`read-taint block`, `reset tainted process's live TCP egress`), the toast, and the Incidents page.

## D1 — L2 Read-taint (content-driven, APP-AGNOSTIC)

| ID | Scenario | Steps | Expected |
|---|---|---|---|
| **RT-01** | Same-process HTTPS block (core) | `Test-NetConnection google.com -Port 443`(→True); `[IO.File]::ReadAllBytes('E:\OPORD.pdf').Length`; `Start-Sleep 3`; re-test | 2nd → **False**; `Invoke-WebRequest https://google.com` throws |
| **RT-02** | Per-PID scope (control) | NEW PS window; `Test-NetConnection google.com -Port 443` | **True** — only the reader is cut |
| **RT-03** | Negative — innocent content | Fresh PS: read `E:\readme.txt`; sleep 3; test-connect | **True** — no taint |
| **RT-04** | **Unknown "malware", NO signature** | Fresh PS: `curl.exe -o NUL file:///E:/OPORD.pdf`; sleep 3; `curl.exe https://example.com` | **blocked** — caught purely on content. *The unknown-app answer.* |
| **RT-05** | RustDesk copy (content) | RustDesk session up; copy `E:\OPORD.pdf` via file transfer | Transfer fails / session drops (caveat A) |
| **RT-06** | Live-connection teardown | `$c=[Net.Sockets.TcpClient]::new('google.com',443)`; THEN read `E:\OPORD.pdf` same PS | Existing connection **drops** + new connects blocked |
| **RT-07** | Substantiality gate | `$f=[IO.File]::OpenRead('E:\OPORD.pdf'); $f.ReadByte(); $f.Close()`; test-connect | **NOT** blocked — 1-byte probe doesn't arm a scan |
| **RT-08** | Repeat-read fast path | After RT-01, a DIFFERENT fresh process reads `E:\OPORD.pdf`; test-connect | Tainted **instantly** (sensfile cache) |
| **RT-09** | Exit untaint / PID reuse | Taint a process, close it, spawn processes until PID reused; that process egresses | **Allowed** — taint cleared on exit |
| **RT-10a** | Fixed, UNwatched (miss) | Read `C:\Temp\OPORD.pdf`; test-connect | **NOT** blocked — C: reads only scanned under a watch prefix |
| **RT-10b** | Fixed, WATCHED | Read `C:\Users\<you>\Desktop\classified\OPORD.pdf`; test-connect | **Blocked** |
| **RT-11** | Fail-secure (guard down) | Stop `usb-guard`; fresh PS read `E:\readme.txt`; test-connect | Reader tainted (FailMode=BLOCK) — killing the guard can't exfiltrate. Restart guard to clear. |
| **RT-12** | `BLOCK_NONLOCAL` | Set `TaintedEgressPolicy=1`, reload driver; taint a process; connect to LAN host vs public host | LAN/loopback **permitted**, public **blocked** |
| **RT-13** | Agent self never tainted | Confirm `usb-guard`/service keeps checking in while others are tainted | Agent traffic **never** blocked |
| **RT-14** | **Known gap — IPC laundering** | Helper reads OPORD, pipes bytes to a SEPARATE clean process that egresses | **NOT** blocked (single-hop limit — documented) |

**Caveat A (RT-05):** taint keys on the PID that *read* the file; `rustdesk.exe` usually does both the
read and the network, but if it forks file I/O the teardown may miss — that's what L3/remote-tool backstop.

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
> NOT block agent-detected data — L2 (read-taint) + L3 (default-deny) do. It only forbids the *tool
> itself*, and its sole unique value is the analog hole (screen-view + photograph). To run these
> cases, **opt in**: set `[netfilter] remote_tool_action = "block_network"` (or `"kill"`) in
> `agent.toml`, then `net-monitor --enforce blocklist`.

| ID | Scenario | Steps | Expected |
|---|---|---|---|
| **RTL-01** | RustDesk blocked by name | `net-monitor --enforce blocklist`, RustDesk running | `rustdesk.exe` egress blocked (app-id WFP) |
| **RTL-02** | Kill override | `[netfilter] remote_tool_action="kill"`; rerun | RustDesk **terminated** |
| **RTL-03** | **Renamed tool defeats signature — read-taint still catches** | Rename `rustdesk.exe`→`svchost2.exe`; run; blocklist misses; copy `E:\OPORD.pdf` with it | Signature **misses**, read-taint **blocks the copy** on content |
| **RTL-04** | Incident labeling | Check Incidents page after RTL-01 | channel `network`, tool `rustdesk` |

## D4 — Composition

| ID | Scenario | Expected |
|---|---|---|
| **CX-01** | Read-taint composes with allow-list | Under `--enforce allowlist` + read-taint: a **tainted** process is blocked **even to an approved dest**; a **clean** process still reaches approved dests (callout returns CONTINUE, never PERMIT) |

## D5 — Edge / failure modes (exercise with Driver Verifier ON)

| ID | Case | Expected |
|---|---|---|
| **EF-01** | USB-yank / dismount while a scan is queued | No BSOD; `FltReadFile` fails cleanly (the by-design teardown race) |
| **EF-02** | Scan-queue flood | Excess jobs dropped (a miss, fail-safe) — no pool growth, no hang |
| **EF-03** | IPv6 egress | New v6 connects blocked by callout; live v6 flows can't be user-mode reset (documented residual) |
| **EF-04** | Circuit breaker | After N consecutive IPC timeouts the driver short-circuits to FailMode; a live reply clears it |
| **EF-05** | Epoch invalidation | Restart `usb-guard` → sensfile cache invalidates; taint persists by design |
| **EF-06** | Unload under load | `fltmc unload dlpflt` during active taints: worker drain + WFP teardown ordered, no leak/BSOD |
| **EF-07** | Toast from Session 0 | Block toast reaches the interactive session; none logged-in → toast skipped, block stands |

---

# PART E — Reading the results

- **`usb-guard` window:** `read-taint block`, `reset tainted process's live TCP egress`,
  `kguard incident reported kind=Match`.
- **Endpoint toast:** "Blocked by DLP · File · Channel · Ref INC-xxxx" (unless `mode=covert`).
- **Console Incidents page:** log in to the Vite UI **as the `incident_reviewer`** (Part A6). The new
  **Incidents** tab lists every blocked/audited file: time, endpoint, user, channel, file, detection
  type, action, status. Click a row for the matched document + containment + ranges; set a triage
  status. (Auditor sees the list only; sysadmin sees neither — separation of duties.)
- **WFP filters:** `netsh wfp show filters` (DLP sublayer / app-id blocks).
- **Reachability:** `Test-NetConnection <host> -Port <p>` → `TcpTestSucceeded`.
- **Filter attach:** `fltmc filters` / `fltmc instances`.

---

# PART F — Teardown / rollback (VM)
```powershell
# Ctrl-C usb-guard + net-monitor
fltmc unload dlpflt
verifier /reset                 # if enabled (then reboot)
reg delete HKLM\SYSTEM\CurrentControlSet\Services\dlpflt /v ReadTaintEnabled /f
reg delete HKLM\SYSTEM\CurrentControlSet\Services\dlpflt /v TaintedEgressPolicy /f
bcdedit /set testsigning off ; shutdown /r /t 0
# — or just roll back the VM snapshot.
```
Server (HOST): `Ctrl-C` the three node processes + Vite; `docker compose stop` (data persists in
`./data/postgres`).

---

# PART G — Results log (fill in)

| ID | Result (PASS/FAIL/DEVIATION) | Notes (log line, exact step) |
|---|---|---|
| A1–A8 (server up) | | |
| B4 (enrolled + bundle) | | |
| C3–C4 (driver loaded + guard) | | |
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

---

## Appendix — honest limits (stand regardless of results)
- **Analog hole:** screen-view over RustDesk/RDP + a phone camera — unstoppable by software.
- **Kernel-privileged malware** can unhook the driver / read raw disk beneath the filter → needs EDR +
  Secure Boot + least-privilege.
- **IPC laundering & derived files** (single-hop taint, RT-14) — child-process taint inheritance +
  derived-file propagation are the documented follow-ons.
- **Encrypted-at-rest content** never seen as matching plaintext won't taint.
- **This is the first runtime exercise of the kernel WFP callout** — a clean compile is not a working
  driver. Snapshot; keep Verifier on; bring back anything that BSODs, over-blocks, or deadlocks.
- "Zero exfiltration" is never claimed. The posture is **read-taint (content) + default-deny
  (destination) + EDR/least-privilege**, layered — with optional, opt-in remote-tool/device hygiene
  for the analog-hole case.
