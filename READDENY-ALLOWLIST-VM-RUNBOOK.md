# Read-Deny "Allowlist Posture" — VM Manual Test Runbook

**Goal:** prove on a VM that, with the **allowlist posture**, a process that is **NOT on the
sanctioned-reader allowlist** (an unknown tool / AnyDesk / RustDesk / malware) is **denied the read**
of a sensitive file — the bytes never reach it — while a **sanctioned** app reads the same file
normally, and everyone reads innocent files normally.

Builds on the existing read-deny setup (`VM-COPY-BLOCK-RUNBOOK.md`, `NETWORK-EGRESS-FULL-TEST-GUIDE.md`
§3). The ONLY new things are two agent settings (`exfil_posture = "allowlist"` + a
`[[trusted_readers]]` list) — the kernel driver is unchanged (`dlpflt.sys`, 35,840 bytes).

> **Snapshot the VM before you start.** The driver touches the file-read path; a bug is a BSOD.
> Test-signing must be ON (see the USB demo runbook).

---

## The one thing that makes the demo reliable: timing

`DlpPreRead` denies a read only if the reader's PID is **already in the pushed untrusted set**. The
agent recomputes + pushes that set every ~2 s. A brand-new process that reads a file within its first
second may win the race (its PID wasn't pushed yet). A **real** exfil tool (AnyDesk/RustDesk) is
long-running and already connected, so it is always in the set before a transfer — reliable.

To reproduce that deterministically with a shell: **launch the untrusted reader and leave it open,
wait ~4 s (watch the guard log push its PID), THEN do the read from that same window.**

---

## 0. Prerequisites (once)

On the VM, as Administrator, with the server reachable (host `desktop-k8e7f5d`):

1. **Fresh agent build with this feature** — copy the current `dlp-agent.exe`
   (`dlp-agent\target\release\dlp-agent.exe`) to `C:\dlp\`. **This is the ONLY new binary** — the
   whole feature is in the agent.
2. **Driver — UNCHANGED by this feature.** Any read-deny-capable `dlpflt.sys` works. If read-deny was
   already loaded and working from earlier testing, keep it — nothing to copy. If unsure, use the
   current `dlp-minifilter\build\out\dlpflt.sys` (35,840 bytes; that size is from the read-taint
   removal, not this feature), test-signed, in place.
3. **Enrolled + bundle cached** (so files can be scored as "sensitive"):
   ```powershell
   cd C:\dlp
   $env:DLP_AGENT_CONFIG = "C:\ProgramData\DLPAgent\agent.toml"
   $env:DLP_AGENT_TOKEN  = "<ENROLLMENT-TOKEN>"
   .\dlp-agent.exe enroll
   .\dlp-agent.exe index-update   # -> "index bundle updated version=3"
   ```
4. A **removable drive** (USB stick or removable VHD) — say it mounts as `E:`. Read-deny always
   scopes removable volumes, so no watch-path config is needed for this test.

---

## 1. Turn on read-deny in the driver (registry, read at load)

```powershell
$svc = "HKLM\SYSTEM\CurrentControlSet\Services\dlpflt"
reg add $svc /v FailMode              /t REG_DWORD /d 1 /f   # fail-secure
reg add $svc /v ExfilReadBlockEnabled /t REG_DWORD /d 1 /f   # read-deny ON (default 0)
reg add $svc /v ExfilReadFailBlock    /t REG_DWORD /d 1 /f   # deny unverifiable content by untrusted PIDs
# (Instances/Altitude 265000 as in the USB demo if registering fresh.)

fltmc unload dlpflt   # if already loaded
fltmc load   dlpflt
fltmc filters         # EXPECT: dlpflt @ altitude 265000
```

The knobs are read at `DriverEntry`, so **set them before `fltmc load`** (reload if you change them).

---

## 2. Agent config — turn on the allowlist posture + a local allowlist

Edit `C:\ProgramData\DLPAgent\agent.toml`. The allowlist here is **local** (no console needed for the
test); in production the console-authored list is merged in over mTLS.

```toml
server_url   = "https://desktop-k8e7f5d:8443"
ca_cert_path = "C:\\dlp\\ca-cert.pem"
state_dir    = "C:\\dlp\\state"

[kguard]
exfil_read_block = true          # run the untrusted-reader pusher
exfil_posture    = "allowlist"   # push every process NOT on the allowlist below

# --- the sanctioned-reader allowlist: who MAY read sensitive content ---
[[trusted_readers]]
path = "C:\\Windows"             # the OS (so the machine stays usable)
note = "Windows"

[[trusted_readers]]
name = "dlp-agent.exe"           # the agent itself
note = "DLP agent"

# NOTE we deliberately do NOT allowlist our test 'reader.exe' yet — that is the
# untrusted process the demo denies. (Step 5 adds it to prove the list drives it.)

[notify]
enabled = true
mode = "standard"
```

> Keep `C:\Windows` on the list or the OS gets denied sensitive reads (harmless but noisy). Add your
> real editors/AV/backup in a real deployment (see `agent.example.toml`).

---

## 3. Start the guard (leave running, watch it)

```powershell
cd C:\dlp
$env:DLP_AGENT_CONFIG = "C:\ProgramData\DLPAgent\agent.toml"
.\dlp-agent.exe usb-guard
```

EXPECT:
- `connected to \DlpFltPort`
- every ~2 s: `pushed untrusted-reader PID set to driver posture=allowlist count=N pids=[...]`
  — **`posture=allowlist` and a large `count`** (most processes) confirm the new posture is live.

---

## 4. Stage the test files on the removable drive

```
E:\OperationHimalayanShield_OPORD.pdf     <- sensitive (matches bundle v3)
E:\innocent.txt                           <- anything clean
```

Prepare the two readers (a trusted one and an untrusted one). `cmd.exe` copied elsewhere still runs
its built-ins (`type`, `copy`), and — crucially — the copy is NOT under `C:\Windows` and is not named
`cmd.exe`, so the allowlist treats it as **untrusted**:

```powershell
copy C:\Windows\System32\cmd.exe C:\Users\%USERNAME%\Downloads\reader.exe
```

---

## TEST A — untrusted reader is DENIED the sensitive file (the core proof)

1. Launch the untrusted reader and **leave the window open**:
   ```
   C:\Users\<you>\Downloads\reader.exe
   ```
2. In the **guard window**, wait until you see `reader.exe`'s PID appear in the pushed set (~2-4 s).
   (Find its PID with `tasklist | findstr reader` in another window if you want to confirm.)
3. Now, **inside the reader.exe window**, try to take the file out:
   ```
   copy E:\OperationHimalayanShield_OPORD.pdf C:\Users\%USERNAME%\Downloads\stolen.pdf
   type E:\OperationHimalayanShield_OPORD.pdf
   ```
   **EXPECT: `Access is denied.`** for both — the read is refused, nothing is copied. The guard logs
   an `exfil-read-denied` incident; the endpoint shows a "Blocked by DLP" toast.
4. Control — innocent content still reads (proves it is CONTENT-driven, not a process ban):
   ```
   type E:\innocent.txt
   ```
   **EXPECT: the file prints normally.**

| Check | Expected |
|---|---|
| Untrusted reader copies/reads OPORD | **Access denied** + guard `exfil-read-denied` incident |
| Untrusted reader reads innocent.txt | succeeds |

---

## TEST B — a SANCTIONED reader reads the SAME file normally

Use the real `C:\Windows\System32\cmd.exe` (sanctioned by the `C:\Windows` path rule). Open it, wait
~4 s (it is on the allowlist, so it is NOT in the pushed set), then:

```
type E:\OperationHimalayanShield_OPORD.pdf
copy E:\OperationHimalayanShield_OPORD.pdf C:\Users\%USERNAME%\Documents\ok.pdf
```
**EXPECT: both succeed** — the same sensitive file, read by a trusted app, is allowed. This is the
allowlist flip in one screen: trusted app OK, untrusted tool denied, same file.

---

## TEST C — the real thing (AnyDesk / RustDesk)

1. Install AnyDesk or RustDesk on the VM and connect a session from another machine.
2. From the remote side, use the tool's **file transfer** to pull
   `E:\OperationHimalayanShield_OPORD.pdf`.
3. **EXPECT: the transfer fails** — the tool's host-side read is denied (it is not on the allowlist,
   and it was long-running so its PID was already pushed). Innocent files transfer fine.

> Real tools memory-MAP the file; the driver's section-sync pre-op denies that path too, so mmap-based
> transfer is covered, not just `ReadFile`.

---

## TEST D — prove the allowlist DRIVES it (add the reader, it's allowed)

1. Stop `usb-guard` (Ctrl-C). Add the untrusted reader to the allowlist in `agent.toml`:
   ```toml
   [[trusted_readers]]
   name = "reader.exe"
   note = "demo: now trusted"
   ```
2. Restart `usb-guard`. Re-run TEST A step 3.
   **EXPECT: now ALLOWED** — the copy succeeds. Removing it again -> denied again. This proves the
   admin's allowlist, not a hard-coded list, decides who may read.

   (In production you do this in the console — Trusted applications page — and `run-endpoint` picks it
   up live at the next check-in; standalone `usb-guard` is startup-only, so restart it.)

---

## Reading the results (confirmation signals)

- **Guard window:** `pushed untrusted-reader PID set ... posture=allowlist count=N`, and on a denied
  read `kguard incident reported ... note=exfil-read-denied`.
- **Endpoint toast:** "Blocked by DLP - File - usb-kguard - Ref INC-xxxx".
- **Console Incidents** (login as `incident_reviewer`): channel `usb-kguard`, action `blocked`, note
  `exfil-read-denied`, the matched document + containment.

---

## Teardown

```powershell
# Ctrl-C usb-guard
fltmc unload dlpflt
reg delete HKLM\SYSTEM\CurrentControlSet\Services\dlpflt /v ExfilReadBlockEnabled /f
reg delete HKLM\SYSTEM\CurrentControlSet\Services\dlpflt /v ExfilReadFailBlock /f
del C:\Users\%USERNAME%\Downloads\reader.exe
```
Or roll back the VM snapshot.

---

## If something is off

- **Nothing is denied:** confirm `ExfilReadBlockEnabled=1` was set **before** `fltmc load`; confirm the
  guard logs `posture=allowlist`; confirm `reader.exe`'s PID is actually in the pushed set (the timing
  race — leave the window open longer before reading).
- **Everything on E: is denied, even innocent files:** the bundle isn't loaded (`index-update`), so
  the guard can't tell sensitive from innocent and `ExfilReadFailBlock=1` denies unverifiable reads by
  untrusted PIDs. Fix the bundle.
- **The OS gets sluggish / apps misbehave:** the allowlist is too narrow — make sure `C:\Windows`
  (and your real editors/AV/backup) are on it. Only reads of SENSITIVE files are ever denied, but a
  too-narrow list denies legit apps.
- **A copied system exe is still "trusted":** you added a `publisher = "..."` rule — a byte-identical
  copy keeps its catalog/embedded signature, so a Microsoft-signed copy still matches a Microsoft
  publisher rule. For this demo use PATH/NAME rules (as above), not a publisher rule.

## Honest limits (unchanged, state them)
Screen-view + phone camera (analog hole), kernel-privileged malware, and laundering through a *trusted*
app (a macro in an allowlisted Word handing bytes to a tool) are out of scope for a read-gate — layer
with EDR + least-privilege. This proves the file-read chokepoint only.
