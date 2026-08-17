# Hypervisor Copy-Block (Read-Deny Rule 3) — Manual Test Runbook

**Goal:** prove that a file the detection engine classifies as sensitive (IDM/EDM) **cannot be
copied into any VM** — shared folder, drag-and-drop, or clipboard file paste — because the
hypervisor's VM worker process is auto-classified as an exfil channel and the kernel driver
**denies its reads** of sensitive content.

This is the **read-deny** path (per-open verdict, cached) — no scan delay, no repeated scans. Builds on `USB-DEMO-RUNBOOK.md` setup (enrolled agent, bundle v3, test-signed
driver). **Snapshot the test box before you start.**

---

## How it works (what you're watching)

1. The agent's exfil tracker (every ~2 s) now flags any process with a **hypervisor runtime
   module** loaded — `WinHvPlatform.dll` / System32 `vid.dll` (Hyper-V, WSL2, Docker, QEMU-whpx),
   `VBoxVMM.dll` (VirtualBox VM worker), `vmwarebase.dll` (VMware) — and pushes its PID to the
   driver. **No product-name list**: any hypervisor must load one of these substrates.
2. Every host→guest file path (shared folder, drag-and-drop, clipboard file transfer) is a
   **host-side read by that worker PID**.
3. On that PID's first read of a file, `DlpPreRead` classifies the content **once** (IDM/EDM
   verdict via `usb-guard`), caches it, and returns **ACCESS DENIED** for sensitive content.
   The guest sees an I/O error; clean files copy normally.

---

## 0. Preconditions (miss one and it silently won't fire)

- **New agent build** — must include exfil rule 3 (`src/exfil.rs`, `hypervisor_pids()`):
  `cargo build --release` and copy the new `dlp-agent.exe` to the test box.
- **Driver with read-deny** (`DlpPreRead` + `DlpPreAcquireForSection`) loaded, and the knob ON
  (step 2). Absent knob = read-deny OFF (shipped default).
- **Sensitive file on a REMOVABLE volume** (USB stick / removable VHD). Default scan scope is
  removable-only until a watch config arrives.
- **`usb-guard` running with bundle v3** and `exfil_read_block = true` (step 3). Without the
  guard, `ExfilReadFailBlock=1` fail-secure denies exfil-PID reads of *everything* removable.

## 1. Registry knobs (test box, admin)

```powershell
$svc = "HKLM\SYSTEM\CurrentControlSet\Services\dlpflt"
reg add $svc /v ExfilReadBlockEnabled /t REG_DWORD /d 1 /f   # read-deny ON
reg add $svc /v ExfilReadFailBlock    /t REG_DWORD /d 1 /f   # fail-secure on unreadable (default)
```

## 2. Reload the driver so DriverEntry re-reads the knobs (admin)

```powershell
fltmc unload dlpflt
fltmc load   dlpflt
fltmc filters                # EXPECT: dlpflt, altitude 265000
```

## 3. Agent config + start the guard (admin, leave running)

In `C:\ProgramData\DLPAgent\agent.toml` add/confirm:

```toml
[kguard]
exfil_read_block = true
```

Then (same env as the USB demo so cached bundle v3 loads):

```powershell
cd C:\dlp
.\dlp-agent.exe usb-guard
```

Expect `connected to \DlpFltPort`, and every ~2 s a log line:
`pushed exfil-channel PID set to driver  count=… pids=[…]`. Watch this window throughout.

## 4. Stage the files on the removable drive (say `E:`)

```
E:\OperationHimalayanShield_OPORD.pdf     ← sensitive (matches bundle)
E:\innocent.txt                           ← anything clean
```

---

## TEST A — substrate detection, no VirtualBox needed (5 min)

The rule fires on the *module load*, so any process that loads a hypervisor runtime becomes an
exfil channel — simulate one with PowerShell:

```powershell
# A1. This fresh PowerShell can read the OPORD (it's not an exfil channel):
[System.IO.File]::ReadAllBytes('E:\OperationHimalayanShield_OPORD.pdf').Length   # EXPECT: 8757

# A2. Make THIS process "a hypervisor" by loading the WHP runtime:
Add-Type -Namespace W -Name K32 -MemberDefinition '[DllImport("kernel32")] public static extern IntPtr LoadLibrary(string name);'
[W.K32]::LoadLibrary("$env:SystemRoot\System32\WinHvPlatform.dll")   # EXPECT: non-zero handle
$PID                                                                  # note the PID

# A3. Wait for the ~2 s pusher, then confirm the guard log shows this PID in the pushed set:
Start-Sleep -Seconds 5

# A4. Re-read the SAME file from the SAME process — now DENIED:
[System.IO.File]::ReadAllBytes('E:\OperationHimalayanShield_OPORD.pdf')   # EXPECT: access denied

# A5. Clean file still reads — proves it's content-driven, not a process ban:
Get-Content E:\innocent.txt                                               # EXPECT: succeeds
```

**Control:** a NEW PowerShell (no LoadLibrary) reads the OPORD fine — the deny is scoped to
hypervisor-classified PIDs.

> If A2 returns handle 0, that Windows build lacks `WinHvPlatform.dll`; use
> `"$env:SystemRoot\System32\vid.dll"` instead (needs the Hyper-V feature installed).

| Check | Expected |
|---|---|
| Fresh process reads OPORD | succeeds |
| Same process after loading WHP runtime | **denied** (guard logs a read-deny block incident) |
| Same flagged process reads innocent file | succeeds |
| New process reads OPORD | succeeds |

---

## TEST B — real VirtualBox end-to-end (the demo)

> If the test box is itself a VM, enable nested virtualization first
> (VirtualBox outer: `VBoxManage modifyvm <vm> --nested-hw-virt on`; VMware outer:
> "Virtualize Intel VT-x/EPT"). A physical machine needs nothing.

1. Install VirtualBox + a small guest (any Windows/Linux) with **Guest Additions**.
2. Shared folder: map host `E:\` → guest share `dlptest` (auto-mount). Also enable
   **Drag'n'Drop: Host to Guest** and **Shared Clipboard: Bidirectional** for the extra tests.
3. Power the VM on. In the guard window, within ~2 s the pushed PID set must grow — verify it's
   the worker: `tasklist /m VBoxVMM.dll` → EXPECT `VirtualBoxVM.exe` (or `VBoxHeadless.exe`).
4. **Inside the guest**, copy from the share:
   - `copy \\vboxsvr\dlptest\innocent.txt C:\` → **succeeds**
   - `copy \\vboxsvr\dlptest\OperationHimalayanShield_OPORD.pdf C:\` → **fails with an I/O /
     access error** — the host-side read by `VirtualBoxVM.exe` was denied. Guard logs the block.
5. **Drag-and-drop** the OPORD from the host desktop into the guest window → transfer **fails**
   (clean file transfers fine).
6. **Clipboard file paste**: copy the OPORD in host Explorer, paste inside the guest → **fails**;
   innocent file pastes fine.

| Check | Expected |
|---|---|
| VM powers on → PID appears in pushed set | within ~2 s |
| Guest copies innocent file from share | succeeds |
| Guest copies OPORD from share | **blocked**, incident in guard log |
| Drag-and-drop OPORD into guest | **blocked** |
| Clipboard file-paste OPORD into guest | **blocked** |

---

## Troubleshooting

- **Nothing blocks:** check `ExfilReadBlockEnabled=1` was set **before** `fltmc load` (read at
  DriverEntry only), and that the guard log shows the hypervisor PID in `pushed exfil-channel
  PID set`. If the PID is missing, the module scan couldn't open the process — run the guard
  elevated / as SYSTEM.
- **Everything on E: blocks, even innocent files:** guard not running or bundle not loaded —
  that's `ExfilReadFailBlock` fail-secure working as designed.
- **OPORD on `C:` doesn't block:** expected — default scan scope is removable-only.
- **Known gaps (by design, for the report):** pure-software emulation (QEMU TCG) loads no
  substrate; plain **text** paste into a guest isn't a file read (clipboard channel's job);
  guest network egress in bridged mode bypasses host WFP. First and last are closed by
  reader-allowlist / device-control policy, not this rule.
