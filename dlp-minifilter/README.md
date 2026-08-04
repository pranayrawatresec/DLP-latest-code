# DLP Filesystem Minifilter (`dlpflt.sys`)

A Windows filesystem **minifilter** kernel driver that intercepts writes to
**removable media**, asks the user-mode DLP agent for a content verdict (reusing
the frozen `detect::verdict()` engine), and **deletes/quarantines** files that
contain protected content. Modeled on Microsoft's canonical `scanner`/`avscan`
minifilter sample, adapted for DLP.

Two halves:

| Half | Where | Language | Role |
|---|---|---|---|
| `dlpflt.sys` | `dlp-minifilter/` (this dir) | C (kernel) | attach to removable volumes, intercept, send path up, delete on BLOCK |
| `usb-guard` | `dlp-agent/` (`src/kguard`) | Rust (user) | connect to `\DlpFltPort`, score the file, reply allow/block, raise incident |

---

## ⚠️ Verification boundary — read first

This repo can **compile + link** the driver to a real `.sys` and run `cl /analyze`,
and can `cargo build` the Rust client. It **cannot load or run** the driver: that
needs test-signing + a reboot, and a kernel bug is a bugcheck (BSOD).

**What is verified here (mechanically):**
- `dlpflt.sys` compiles and links `/W4 /WX`-clean (real output below).
- `cl /analyze` is clean on our source.
- `usb-guard` (`cargo build`) compiles clean; the wire structs are size-locked to
  the C header; all agent tests pass.

**What is NOT verified here — the operator's MANUAL test (section "Manual test"):**
- The driver loading without a bugcheck.
- Correct blocking / quarantine of a sensitive file.
- No deadlock / recursion (self-skip actually working at runtime).
- `FailMode` behavior end to end.

Never treat "it built" as "it runs correctly." The runtime claims are the
operator's, on a throwaway test VM.

---

## Layout

```
dlp-minifilter/
  src/
    dlpflt.h     shared port message contract (mirrored in Rust) + kernel decls
    dlpflt.c     DriverEntry, registration, InstanceSetup (removable-only),
                 CREATE/WRITE/CLEANUP/SET_INFORMATION callbacks, quarantine
    comms.c      \DlpFltPort: create/connect/disconnect, FltSendMessage, FailMode
  dlpflt.inf     minifilter INF (Content Screener group, default instance, altitude)
  build/
    build-driver.bat   the proven cl+link recipe -> build/out/dlpflt.sys
    analyze.bat        same cl line + /analyze (clean on our source)
  tools/
    make-testcert.ps1  create + trust a TEST code-signing cert
    sign-driver.ps1    signtool test-sign the .sys (+ .cat if inf2cat present)
    install.ps1        install via INF, load with fltmc (prints testsigning steps)
    uninstall.ps1      fltmc unload + delete service
  README.md
```

The user-mode client lives in the agent: `dlp-agent/src/kguard/mod.rs`, driven by
`dlp-agent usb-guard`.

---

## Build

The Visual Studio **WDK MSBuild targets are not installed** on the build machine,
so we invoke `cl` + `link` directly with the exact, proven include/lib order.

```bat
cd dlp-minifilter
build\build-driver.bat        REM -> build\out\dlpflt.sys
build\analyze.bat             REM cl /analyze; must print "ANALYZE CLEAN"
```

Toolchain (fixed): MSVC `14.51.36231`, Windows Kit `10.0.26100.0`.

- `INCLUDE` puts `km\crt` **first** so kernel CRT headers shadow the user-mode
  ones. `/kernel` auto-defines `_KERNEL_MODE` (never redefine it).
- `/WX` stays on. `/wd4324 /wd4201 /wd4214` suppress **benign WDK
  system-header** warnings only. `analyze.bat` additionally suppresses
  `C28160/C6387/C28252/C28253/C28230/C28285` — all emitted **inside** the WDK
  headers (`wdm.h` / `ntddk.h`), never in our code.

Build the Rust client from the agent:

```bat
cd dlp-agent
cargo build
```

---

## Test-sign + install (operator, TEST machine only)

Run these on a **disposable test VM or spare box**, elevated. In order:

```powershell
# 0. Build first (above): build\out\dlpflt.sys must exist.

# 1. Create + trust a TEST code-signing cert (Root + TrustedPublisher).
tools\make-testcert.ps1

# 2. Test-sign the driver (embedded .sys signature; +.cat if inf2cat present).
tools\sign-driver.ps1

# 3. Enable test signing, then REBOOT (a test-signed driver won't load otherwise).
bcdedit /set testsigning on
Restart-Computer

# 4. After reboot: install the INF and load the filter.
tools\install.ps1
fltmc filters      # expect 'dlpflt' at altitude 265000
```

Test certs are for development only — production drivers are signed through the
Windows Hardware Dev Center attestation/EV process, not a self-signed cert.

### Uninstall

```powershell
tools\uninstall.ps1
bcdedit /set testsigning off
Restart-Computer
```

---

## Manual test (runtime verification this repo cannot do — SPEC §8)

On the test machine, after install:

1. `bcdedit /set testsigning on` and reboot (test VM only).
2. `tools\make-testcert.ps1`, then `tools\sign-driver.ps1`.
3. `tools\install.ps1` → `fltmc filters` shows `dlpflt` attached; then start the
   client: `dlp-agent usb-guard` (this process becomes the driver's skip-self
   identity — see below).
4. Plug in a USB stick → copy a **sensitive** sample (e.g. a protected OPORD that
   the cached bundle matches) → expect the copy to be **removed** from the stick
   and an incident raised. Copy an **innocent** file → it stays.
5. Kill `usb-guard` → copy a file again → confirm the `FailMode` behavior
   (allow+audit vs block) matches the configured value.
6. `tools\uninstall.ps1` → `fltmc filters` clean; `bcdedit /set testsigning off`.

If step 4 bugchecks, capture the minidump — do **not** assume the build being
clean means the runtime is correct.

---

## How it works (and its honest limits)

### Interception points (`dlpflt.c`)
- **`InstanceSetup`** attaches by volume class (Tier-1 extension):
  - **Removable** — always attached. A volume is removable if
    `FILE_REMOVABLE_MEDIA` is set OR its backing disk's bus type is USB/SD/MMC
    (catches external USB SSDs that lie about being fixed).
  - **Network (SMB redirector)** — attached **only if** the user-mode config set
    `ScanNetwork` (a copy to a share is an egress target).
  - **Fixed / OS** — attached **only if** the config set `ScanFixed` **and**
    supplied a non-empty watch-set (`WatchCount > 0`); otherwise
    `STATUS_FLT_DO_NOT_ATTACH`. **With no config delivered, the driver behaves
    exactly as before: removable-only.** This empty-watch-set = removable-only
    invariant is the back-compat / safety guarantee — the driver never sits in
    the system-disk path by default.
  - Raw/unknown filesystems are skipped in every class.
  The volume class is stashed in a per-instance context so `CLEANUP` can branch
  without re-querying the volume.
- **`IRP_MJ_CREATE` (post)** flags a write-capable, non-directory open with a
  per-stream context.
- **`IRP_MJ_WRITE` (pre)** marks the stream dirty. It does **not** scan — the
  full file isn't present yet.
- **`IRP_MJ_CLEANUP` (pre)** is the **inspection point**: last handle closing,
  writes flushed, file fully on the media. A dirty candidate (not from the
  service) is sent up the port; on **BLOCK** the file is deleted. On **fixed**
  instances the name query is done lazily (only for a dirty candidate) and the
  file is **quick-rejected unless its path is under a configured watch prefix**
  (case-insensitive) — so the C: hot path stays cheap. Removable/network
  instances inspect every dirty candidate.
- **`IRP_MJ_SET_INFORMATION` (pre)** catches **rename INTO** the volume (a move
  isn't a write) and marks the destination a candidate.

### Self-skip (why it can't deadlock itself)
The service reads each file to fingerprint it, which generates I/O on the very
volume we filter. At connect, the driver records the connecting process's PID
(`\DlpFltPort`, ConnectNotify). Every callback passes that PID's I/O straight
through (`FLT_PREOP_SUCCESS_NO_CALLBACK`). **`usb-guard` must therefore be the
process that connects** — do not proxy the port through another process, or the
skip-self PID will be wrong and the driver can recurse/deadlock.

### Blocking model (v1) — honest
This is **scan-on-CLEANUP + delete-if-sensitive**: the file *briefly exists* on
the stick, then is removed (`FileDispositionInformation`). It is
**detect-and-quarantine at kernel level**, not zero-residue prevention. True
**buffer-and-hold-before-commit** (nothing ever lands on the media) is a
documented **v2**, not this build. Don't market v1 as pre-commit prevention.

### Fail mode (registry `FailMode`) — the tradeoff
When the service is absent, disconnected, or times out (10 s), the driver applies
`FailMode`, read from its service key at `DriverEntry`:

| `FailMode` | Behavior | Use when |
|---|---|---|
| `0` (default, shipped in INF) | **allow + audit** — the file is permitted; the machine stays usable | general / productivity sites |
| `1` | **block / fail-secure** — no verdict means no write | classified / defence sites |

The user-mode client has a matching `[kguard] fail_block` knob for the case where
it *is* connected but has no verified bundle (or a file can't be read): it answers
per `fail_block` (default `false` = allow+audit, to match the shipped
`FailMode=0`). Set both to the fail-secure option together for classified
deployments.

### Altitude
The INF uses development altitude **`265000`** in the **"FSFilter Content
Screener" (260000–269998)** band. **Production requires a Microsoft-assigned
altitude** — request one via the sysdev *Allocated Filter Altitudes* process and
replace both the INF `Altitude` string and the load-order group instance before
shipping.

---

## Wire contract (`dlpflt.h` ↔ Rust)

The port carries **path + metadata only — never file contents** (the service
opens and reads the file itself). Two fixed-layout structs, `#pragma pack(8)` in
C and `#[repr(C)]` in Rust, are size-locked on the Rust side (a compile-time
assertion in `kguard/mod.rs`):

```
DLP_SCAN_REQUEST = 1048 bytes  (Version, Reserved, FileId, ProcessId,
                                PathLength, Path[512])   Path @ offset 22
DLP_SCAN_REPLY   =   16 bytes  (FileId, Verdict)
```

Bump `DLP_MSG_VERSION` on any layout change; the client warns and fails-safe on a
version mismatch.

### Scan-scope config (`DLP_CONFIG`, user → kernel)

The one **user → kernel** message the driver accepts is a `DLP_CONFIG`
(`DLP_CONFIG_VERSION`, **independent of** `DLP_MSG_VERSION` — the frozen scan
request/reply layout is unchanged). It is delivered by the user-mode guard via
`FilterSendMessage` after it connects, and the driver's message-notify callback
validates and stores it under an `ERESOURCE` (probed and copied under SEH):

```
DLP_CONFIG (8368 bytes): Version, ScanFixed, ScanNetwork, WatchCount,
                         WatchLen[16], Watch[16][260]   (case-insensitive prefixes)
```

- `ScanFixed` + a non-empty `Watch[]` set open fixed-volume watch paths (e.g.
  `\Users\alice\OneDrive`, `\Dropbox`, `\Google Drive`, a staging dir).
- `ScanNetwork` opens SMB volumes.
- **It carries only WHERE to look — never file content.** The "no content over
  the port" invariant (path + metadata only for verdicts) is unchanged.
- **Empty / never-sent** ⇒ `WatchCount == 0`, `ScanFixed == 0` ⇒ removable-only
  (backward compatible).

Watch matching is a **case-insensitive substring** test against the normalized
NT path (so a volume-relative prefix like `\Users\alice\OneDrive` matches a
`\Device\HarddiskVolumeN\Users\alice\OneDrive\...` name). The user-mode config
builder (`usb-guard` / agent config) is responsible for supplying sensible watch
prefixes.

### CD/DVD burn — honest limit (no dedicated hook)

IMAPI stages files to a system-volume staging folder before committing them to
disc. Covering that staging folder as a **fixed-volume watch path** catches those
staging writes **partially**. True burn-time interception (an IMAPI COM hook) is
a **separate mechanism, deferred** — this build does **not** claim full CD/DVD
coverage, and there is no dedicated IMAPI hook.

### ⚠️ Extended attach raises runtime risk — VM only

Attaching to fixed and network volumes puts the (unloadable-here) driver on more
of the I/O path than the removable-only build. All runtime behavior remains
**operator-manual on a throwaway test VM** (loading, blocking, self-skip, no
bugcheck, fixed/network performance). Nothing about fixed/network runtime is
verified in this repo — only that it **compiles + links `/W4 /WX`-clean and
`cl /analyze`-clean**. Remember: empty watch-set = safe removable-only.

---

## Real build output observed

```
build\build-driver.bat
  === SUCCESS ===
  Directory of C:\Users\lianli\Downloads\DLP_GUIDE\dlp-minifilter\build\out
  dlpflt.sys        19,968 bytes

build\analyze.bat
  === ANALYZE CLEAN ===

dlp-agent> cargo build
  Finished `dev` profile [unoptimized + debuginfo] target(s)
dlp-agent> cargo test
  all suites pass (lib 40, bins/kguard 7, extract 21, golden_vectors 6, usb_audit 6, ...)
```

`inf2cat` note: if the WDK's `inf2cat` is absent on the operator box, `sign-driver.ps1`
skips the `.cat` and relies on the embedded `.sys` signature, which is sufficient
to load under `bcdedit /set testsigning on`. The INF itself is structurally valid
(`ServiceType=2`, `LoadOrderGroup="FSFilter Content Screener"`, default instance +
altitude); validate with `stampinf`/`inf2cat` where available.
