# DLP Filesystem Minifilter (`dlpflt.sys`) — Production Build Spec

**Goal:** a Windows filesystem **minifilter** kernel driver that intercepts file writes to
**removable media**, asks the user-mode DLP agent for a content verdict (reusing the existing
`detect::verdict()` engine), and **blocks/quarantines** files that contain protected content —
true pre-commit-ish enforcement, not just audit.

**Verification boundary (read first):**
- This environment CAN compile+link the driver to a real `.sys` and run static analysis. The build
  recipe in §7 is **already proven working on this machine** (a smoke driver built to a valid `.sys`).
- This environment **cannot load or run** a kernel driver (needs test-signing + reboot; a bug = BSOD).
  Runtime correctness — no bugcheck, correct blocking, no deadlock/recursion — is **manual testing by
  the operator on a test-signed VM or spare machine** (§8). Do NOT claim runtime behavior as verified.

Model the driver on Microsoft's canonical **`scanner`/`avscan` minifilter sample** (scan-on-access,
send to a user-mode scanner over a communication port, block on bad verdict) — adapted for DLP.

---

## 1. Components to produce (under `dlp-minifilter/`)
```
dlp-minifilter/
  src/
    dlpflt.c        driver: DriverEntry, registration, instance setup, op callbacks
    comms.c         communication port: create/connect/disconnect, send-message/reply
    dlpflt.h        shared header: port message structs (SHARED with the user-mode client)
  dlpflt.inf        minifilter INF (service + altitude + instance)
  build/
    build-driver.bat   the PROVEN cl+link recipe from §7 (produces dlpflt.sys)
    analyze.bat        cl /analyze static-analysis pass (must be clean)
  tools/
    make-testcert.ps1  create a test code-signing cert, trust it (root + publisher)
    sign-driver.ps1    signtool sign the .sys (+ .cat)
    install.ps1        install via INF, load with fltmc; prints the testsigning/reboot steps
    uninstall.ps1      fltmc unload + remove
  README.md          build + test-sign + install + MANUAL TEST guide (§8)
```
Plus, in the existing **Rust agent** (`dlp-agent/`), the **user-mode port client** that answers the
driver — a new module `src/kguard/` + a `usb-guard` subcommand — reusing `detect::verdict()`.

---

## 2. Driver architecture (`dlpflt.c`)

### 2.1 Registration & instance attachment
- `FltRegisterFilter` with an `FLT_REGISTRATION` providing `Unload`, instance
  setup/teardown, contexts, and the operation callbacks below; then `FltStartFiltering`.
- **`InstanceSetupCallback` — attach ONLY to removable volumes.** Query volume properties
  (`FltGetVolumeProperties` → `DeviceCharacteristics & FILE_REMOVABLE_MEDIA`; also treat USB bus type
  as removable). Return `STATUS_FLT_DO_NOT_ATTACH` for fixed/OS/network volumes. This is a **safety +
  performance hard requirement** — never sit in the path of the system disk.
- `InstanceQueryTeardown` → allow; handle teardown start/complete cleanly.

### 2.2 Operation callbacks (the interception)
- `IRP_MJ_CREATE` (post-op): if the create opened a file (not directory) with write access on our
  removable instance, allocate/attach a **stream context** flagged "write-candidate". Skip paging I/O,
  volume-open, directory, and reparse opens.
- `IRP_MJ_WRITE` (pre-op): mark the stream context **dirty** (data was written). Do NOT scan here — the
  full file isn't present yet.
- `IRP_MJ_CLEANUP` (pre-op): **the inspection point** — last handle close, all writes flushed, file
  fully present on the media. If the stream is dirty, on our removable instance, a real file, and the
  requestor is **not our trusted service** (§2.4): resolve the name, **send it to user-mode** (§2.3),
  await the verdict. On **BLOCK** → delete the file from the media (set
  `FileDispositionInformation`/`FltDeleteFile`) and raise an incident signal; on ALLOW → let cleanup
  proceed.
- `IRP_MJ_SET_INFORMATION` (pre-op): catch **rename INTO** the removable volume (a move is not a
  write) — treat the renamed-in file as a scan candidate at cleanup or immediately.

### 2.3 Communication port (`comms.c`)
- `FltCreateCommunicationPort` named e.g. `\DlpFltPort`, secured to Admin/SYSTEM only, max 1
  connection.
- `ConnectNotify`: record the connecting client's **process id** (for skip-self, §2.4) and port.
- `DisconnectNotify`: clear client state.
- Kernel→user request via `FltSendMessage` carrying the **file path (UNICODE)** + op metadata (NOT
  file contents — the service opens and reads the file itself; keeps messages small). Wait for the
  reply with a **timeout**.
- **Fail mode (config, registry `FailMode`):** if the service is absent, disconnected, or times out —
  `0 = allow + audit` (machine stays usable) or `1 = block` (defence, fail-secure). Default is a
  deployment choice; document the tradeoff. Recommend `1` for classified sites, `0` for general.

### 2.4 Correctness & safety (production-grade — non-negotiable)
- **Recursion / self-skip:** the user-mode service reads the file to fingerprint it, generating I/O on
  our volume. Record the service PID at connect; in every callback, if
  `FltGetRequestorProcessId() == servicePid` → `FLT_PREOP_SUCCESS_NO_CALLBACK` (never scan our own
  reads). Without this the driver deadlocks/recurses.
- **IRQL:** `FltSendMessage` and file reads are at `PASSIVE_LEVEL`; CLEANUP pre-op is passive — OK.
- **Skip non-targets:** paging I/O (`FLT_IS_PAGING_FILE`/`FLTFL_CALLBACK_DATA_...`), directories,
  volume/stream opens, named pipes, reparse points.
- **Contexts:** allocate from `NonPagedPool`(NX); register context cleanup; free on teardown; correct
  ref-counting; no leaks.
- **Unload:** `Unload` closes the port then `FltUnregisterFilter`; instance teardown detaches; nothing
  left registered.
- **No content up the port:** only the path + metadata; the service reads the file.
- **Bounded:** kernel does no fingerprinting and no large allocations; the service enforces size caps.
- Every `Flt*`/name-info call is null-checked and failure-handled; a failed name query must
  fail-safe per `FailMode`, never crash.

### 2.5 Blocking model (v1) — honest
Scan-on-CLEANUP + **delete-if-sensitive**. The file briefly exists on the media before deletion
(detect-and-quarantine at kernel level). True **buffer-and-hold before commit** (zero-residue
prevention) is a documented **v2**, not this build. State this plainly in the README.

---

## 3. User-mode port client (Rust, in `dlp-agent/`)
- New `src/kguard/mod.rs` + `usb-guard` subcommand in `main.rs`.
- Connect to `\DlpFltPort` via `FilterConnectCommunicationPort`; loop `FilterGetMessage` →
  parse the path from the driver's message struct (layout defined in `dlpflt.h`, mirrored in Rust) →
  `detect::verdict(path, &bundle)` on the cached bundle → apply policy thresholds
  (block if `containment ≥ block_at` OR `coverage ≥ coverage_block_at` OR any EDM row hit) →
  `FilterReplyMessage` with `{allow|block}` → raise an incident (reuse the existing mTLS incident path
  / offline queue from the `usb` module).
- Uses the `windows` crate `Win32_Storage_InstallableFileSystems` feature
  (`FilterConnectCommunicationPort`, `FilterGetMessage`, `FilterReplyMessage`). This side **compiles
  and is verified here**; full runtime needs the loaded driver (manual).
- **Skip-self** relies on this process's PID being the one the driver records at connect — document
  that `usb-guard` must be the connecting process.

---

## 4. Shared message contract (`dlpflt.h`, mirrored in Rust)
Define fixed-layout structs used by BOTH sides:
```
typedef struct _DLP_SCAN_REQUEST {
  ULONG   Version;          // = 1
  ULONG   Reserved;
  ULONGLONG FileId;         // correlation id
  ULONG   ProcessId;        // requestor
  USHORT  PathLength;       // bytes
  WCHAR   Path[512];        // volume-relative or full DOS path
} DLP_SCAN_REQUEST;
typedef struct _DLP_SCAN_REPLY {
  ULONGLONG FileId;
  ULONG   Verdict;          // 0 = allow, 1 = block
} DLP_SCAN_REPLY;
```
Both structs are `#pragma pack`-stable; the Rust side uses `#[repr(C)]` mirrors. Keep versioned.

---

## 5. INF + altitude
- `dlpflt.inf`: a minifilter service INF (`ServiceType = 2` filesystem filter, `StartType`,
  `LoadOrderGroup = "FSFilter Content Screener"`), an `AddRegistry` `Instances` section with a
  **default instance** and an **Altitude**.
- **Altitude:** DLP content screeners live in the **"FSFilter Content Screener" 260000–269998** load
  order group / altitude band — use an unused test altitude there (e.g. `265000`) for development.
  Production requires a **Microsoft-assigned altitude** — note this in the README.

## 6. DO NOT
- **DO NOT** attempt to load/start the driver in this environment; build + static-analyze only.
- **DO NOT** attach to fixed/OS/network volumes — removable only (`InstanceSetup` gate).
- **DO NOT** send file contents up the port (path + metadata only).
- **DO NOT** scan the service's own I/O (self-skip by PID) — omission = deadlock.
- **DO NOT** fingerprint or do heavy work in the kernel — that's the user-mode service's job.
- **DO NOT** change anything under `dlp-agent/src/detect/` (frozen contract).
- **DO NOT** claim runtime/loading/blocking behavior as tested — it is manual (§8).
- **DO NOT** hardcode secrets; the port is secured to Admin/SYSTEM.

---

## 7. PROVEN build recipe (already verified on THIS machine — use verbatim)
Toolchain present: MSVC `14.51.36231`, Windows Kit `10.0.26100.0`, `fltMgr.lib`, `signtool`,
`stampinf`, `fltmc`. The VS **WDK project targets are NOT installed**, so build by invoking cl+link
directly (this exact recipe produced a valid `.sys`):
```bat
set MSVC=C:\Program Files\Microsoft Visual Studio\18\Community\VC\Tools\MSVC\14.51.36231
set SDKROOT=C:\Program Files (x86)\Windows Kits\10
set SDKVER=10.0.26100.0
set PATH=%MSVC%\bin\Hostx64\x64;%PATH%
rem km\crt FIRST so kernel CRT headers shadow MSVC's user-mode ones (critical).
set INCLUDE=%SDKROOT%\Include\%SDKVER%\km\crt;%MSVC%\include;%SDKROOT%\Include\%SDKVER%\km;%SDKROOT%\Include\%SDKVER%\shared
set LIB=%MSVC%\lib\x64;%SDKROOT%\Lib\%SDKVER%\km\x64

cl.exe /nologo /c /W4 /WX /wd4324 /wd4201 /wd4214 /Od /GF /Gy /GR- /GS /kernel ^
  /D_WIN64 /D_AMD64_ /DAMD64 /DNTDDI_VERSION=0x0A000000 /D_WIN32_WINNT=0x0A00 <sources>.c

link.exe /NOLOGO /OUT:dlpflt.sys /DRIVER /SUBSYSTEM:NATIVE,10.00 /ENTRY:GsDriverEntry ^
  /NODEFAULTLIB /RELEASE <objs>.obj fltMgr.lib ntoskrnl.lib hal.lib wdmsec.lib BufferOverflowFastFailK.lib
```
- `/kernel` auto-defines `_KERNEL_MODE` (do NOT define it again — warns).
- `/WX` is ON; the WDK headers emit benign `C4324/C4201/C4214` → disabled above. Keep `/WX` for driver
  quality; only add a `/wd` for a benign **system-header** warning, never to hide a warning in OUR code.
- Add `analyze.bat` = same cl line **+ `/analyze`** for static analysis; it must be clean on our code.

---

## 8. MANUAL TEST (operator, on a TEST machine/VM — NOT automated here)
Document these in README.md; they are the runtime verification this environment cannot do:
1. `bcdedit /set testsigning on` && reboot (test VM only).
2. Run `tools/make-testcert.ps1`, `tools/sign-driver.ps1`.
3. `tools/install.ps1` → `fltmc filters` shows `dlpflt` attached; start `dlp-agent usb-guard`.
4. Plug a USB stick → copy the sample OPORD → expect the copy to be **blocked/removed** and an
   incident raised; copy an innocent file → allowed.
5. Kill `usb-guard` → confirm `FailMode` behavior (allow+audit or block) matches config.
6. `tools/uninstall.ps1` → `fltmc` clean; `bcdedit /set testsigning off`.

---

## 9. Acceptance criteria (what "done" means for THIS build)
1. `build/build-driver.bat` compiles + links `dlpflt.sys` with **`/W4 /WX` clean** (real output).
2. `build/analyze.bat` (`cl /analyze`) reports **no warnings in our source** (system-header noise
   suppressed only via `/wd` for benign known codes).
3. The Rust `usb-guard` client **`cargo build`s clean** and all existing agent tests still pass
   (`detect/` untouched).
4. `dlpflt.inf` is well-formed (stampinf/`inf2cat` or at least structurally valid; note if inf2cat
   absent).
5. Sign/install/uninstall scripts exist and are correct-by-review (they run only on the operator's
   test box).
6. README documents build, test-sign, install, the MANUAL TEST (§8), the blocking model honesty
   (§2.5), the fail-mode tradeoff, and the altitude note.
7. Honest final report: what actually compiled (paste real output), what is manual-only (loading,
   blocking, no-BSOD), and every deviation from this spec.
```
