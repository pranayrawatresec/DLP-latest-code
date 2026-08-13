# Read-Taint Network-Egress Block — VM Test Runbook

**Goal:** prove that when a process **reads sensitive content**, its **network egress is cut** —
HTTPS blocked, and AnyDesk blocked. Content-blind at the socket, so TLS/encryption does not matter.

This builds on `USB-DEMO-RUNBOOK.md` (same VM, same test cert, same enrolled agent + bundle v3).
Do that setup first if you haven't. **Snapshot the VM before you start** — a driver bug = BSOD.

---

## How it works (so you know what you're watching)

1. A process reads a file on a **removable drive** whose bytes match the bundle (the OPORD).
2. The kernel driver's async worker fingerprints the content → **BLOCK** → **taints that PID**.
3. The in-kernel **WFP callout** then vetoes that PID's **new outbound connects** (HTTPS/AnyDesk/any
   socket), and `usb-guard` **tears down its already-open TCP flows**.
4. Taint is cleared when the process exits.

**It is asynchronous** — expect a **~1–3 s delay** between the read and egress being cut.

---

## 0. Key preconditions (miss one and it silently won't fire)

- **You must use the NEW driver.** The `dlpflt.sys` from the USB demo has no WFP callout. Rebuild
  (`build\build-driver.bat` → 37,888 bytes), re-sign, and replace it on the VM.
- **The file must be on a REMOVABLE volume** (USB stick / removable VHD). On a fixed `C:` drive
  read-taint only fires under a configured watch prefix. Removable inspects everything → simplest.
- **`usb-guard` must be running and connected** with bundle v3 loaded. If it isn't, the fail-secure
  default makes the driver treat *every* removable read as sensitive and taint the reader of *any*
  file. With `usb-guard` up, only real OPORD/EDM content taints.

---

## 1. Replace + re-sign the driver (host → VM)

On the **host** (new build already done):
```powershell
cd C:\Users\lianli\Downloads\DLP_GUIDE\dlp-minifilter
.\tools\sign-driver.ps1                 # re-sign the new build\out\dlpflt.sys with the existing test cert
# copy build\out\dlpflt.sys to the VM (e.g. C:\dlp\dlpflt.sys), overwriting the old one
```
The test cert is already trusted on the VM from the USB demo, so no new cert import is needed.

## 2. Enable read-taint in the registry (VM, admin)

The driver reads these REG_DWORDs from its service key at load:
```powershell
$svc = "HKLM\SYSTEM\CurrentControlSet\Services\dlpflt"
reg add $svc /v ReadTaintEnabled    /t REG_DWORD /d 1 /f   # 1 = ON
reg add $svc /v TaintedEgressPolicy /t REG_DWORD /d 0 /f   # 0 = BLOCK_ALL (strongest); 1 = allow LAN/loopback
```
> If you registered the driver manually last time (sc.exe create + Instances/Altitude 265000), those
> keys are still there — you're only ADDING the two values above.

## 3. Reload the driver so it re-reads the knobs + registers the WFP callout (VM, admin)
```powershell
fltmc unload dlpflt          # if currently loaded
copy /Y C:\dlp\dlpflt.sys <the path the service binPath points at>   # ensure the NEW .sys is in place
fltmc load   dlpflt
fltmc filters                # EXPECT: dlpflt, altitude 265000
```
DriverEntry now reads `ReadTaintEnabled=1`, starts the scan worker, and registers the ALE_AUTH_CONNECT
WFP callout. (WFP-register failure is non-fatal — FS protection still runs — but then egress won't
block; if the tests below don't block, that's the first thing to suspect.)

## 4. Start the guard (VM, admin) — leave running
```powershell
cd C:\dlp
# same env vars as the USB demo (server url, ca, state dir) so the cached bundle v3 loads
.\dlp-agent.exe usb-guard
```
Expect: `connected to \DlpFltPort`. Leave this window open and watch it during the tests.

## 5. Stage the sensitive file on a removable drive
Plug in a USB stick (or attach a removable VHD) — say it mounts as `E:`. Put the OPORD on it:
```
E:\OperationHimalayanShield_OPORD.pdf
```

---

## TEST A — HTTPS egress is cut for a tainted process (the core proof)

Open a **fresh, elevated PowerShell** (this is the "attacker" process). Then:

```powershell
# A1. BASELINE — prove THIS process can reach the internet before tainting:
Test-NetConnection www.google.com -Port 443        # EXPECT: TcpTestSucceeded : True

# A2. TAINT this process by reading the sensitive file (one big read >= 512 bytes):
[System.IO.File]::ReadAllBytes('E:\OperationHimalayanShield_OPORD.pdf').Length   # prints 8757

# A3. Wait for the async scan to taint this PID:
Start-Sleep -Seconds 3

# A4. RE-TEST from the SAME process — egress is now cut:
Test-NetConnection www.google.com -Port 443        # EXPECT: TcpTestSucceeded : False
Invoke-WebRequest https://www.google.com -UseBasicParsing -TimeoutSec 8   # EXPECT: fails/timeouts
```

**Control (proves it's PID-scoped, not a global outage):** open a **NEW** PowerShell (untainted) and
run `Test-NetConnection www.google.com -Port 443` → **True**. Only the process that read the file is cut.

**In the `usb-guard` window** you should see a `read-taint` block and
`reset tainted process's live TCP egress`. The incident is labelled `read-taint`.

| Check | Expected |
|---|---|
| Baseline connect (before read) | **succeeds** |
| Same process, after reading OPORD | **blocked** (TcpTestSucceeded False, IWR throws) |
| A different, fresh process | **succeeds** (taint is per-PID) |
| Reading an **innocent** file instead | **NOT blocked** (no taint — proves it's content-driven) |

---

## TEST B — AnyDesk is blocked

Two independent mechanisms — do either or both:

### B1. Content-driven (read-taint): AnyDesk can't send the sensitive file
1. Establish an AnyDesk session to a peer (host or second VM).
2. Use AnyDesk's **file transfer** to send `E:\OperationHimalayanShield_OPORD.pdf`.
3. AnyDesk reads the file → its PID is tainted → its live session is torn down and new connects are
   blocked → **the transfer fails / the session drops.**

> Honest caveat: AnyDesk runs as several processes (UI + service). Read-taint cuts the **PID that read
> the file**. If AnyDesk's file-reader PID differs from its network PID, B1 may not cut the exact
> socket — which is exactly why B2 exists as the deterministic control on a defence endpoint.

### B2. Policy-driven (remote-tool block): AnyDesk not allowed at all — deterministic
> This is **optional, opt-in hygiene — NOT one of the data-exfil layers** (read-taint + default-deny
> are). It is content-blind (blocks the tool itself) and only helps the analog-hole case, so it is
> **off by default** (`remote_tool_action = "detect"`). To run it, first set
> `[netfilter] remote_tool_action = "block_network"` (or `"kill"`) in `agent.toml`.

In a separate elevated window:
```powershell
cd C:\dlp
.\dlp-agent.exe net-monitor --enforce blocklist
```
With AnyDesk running, its egress is blocked by app-id (and terminated if the policy is `kill`),
**regardless of content**. This is the reliable "AnyDesk is blocked on this machine" demo. Start
AnyDesk and watch it fail to connect / get killed; the tool logs a network incident (metadata only).

---

## 6. Teardown
```powershell
# Ctrl-C usb-guard and net-monitor
fltmc unload dlpflt
reg delete HKLM\SYSTEM\CurrentControlSet\Services\dlpflt /v ReadTaintEnabled /f
reg delete HKLM\SYSTEM\CurrentControlSet\Services\dlpflt /v TaintedEgressPolicy /f
```
Or just roll back the VM snapshot.

---

## Record results (this is the FIRST runtime test of the WFP callout)
For each check in Test A + B: **PASS / FAIL / DEVIATION** + notes. A clean compile is not a working
driver. Bring back anything that **BSODs, doesn't block, blocks too much, or deadlocks** and we fix +
rebuild. Also run **Driver Verifier** on `dlpflt.sys` (Pool Tracking + Force IRQL + Deadlock + DDI +
WFP/NDIS) and especially exercise **USB-yank / volume-dismount while a read scan is queued** — that is
the one by-design teardown race the review flagged.

**Honest limits that still stand:** taint is single-hop (the reader's PID only — a tainted process that
spawns a *child* to do the sending, or writes a derived file another process reads, is not yet caught);
the screen-view analog hole; a kernel-privileged adversary that unhooks the driver.
