# Endpoint install (production)

Turns a working build into a one-command endpoint install — no hand-typed
`reg add` / `sc create` / `fltmc` steps. This is the payload + logic a real
MSI/WiX package wraps; for defence/air-gapped sites the PowerShell package is the
deployable unit (copy the folder, run one command, or push via GPO/SCCM/Intune).

## 1. Build the package (on the build box)

```powershell
cd dlp-agent
cargo build --release                      # -> target\release\dlp-agent.exe
# build + sign the driver first so the package includes it:
#   dlp-minifilter\build\build-driver.bat  then  dlp-minifilter\tools\sign-driver.ps1
powershell -ExecutionPolicy Bypass -File packaging\build-package.ps1
```

`packaging\out\` now holds the payload: `dlp-agent.exe`, `ca-cert.pem`,
`agent.toml` (template), and — if the signed driver was present —
`dlpflt.sys` + `dlpflt.inf` (+ `dlpflt.cat`).

## 2. Install on an endpoint (elevated)

Mint a one-time enrollment token in the console (Enrollment page), copy
`packaging\out\` to the endpoint, then:

```powershell
powershell -ExecutionPolicy Bypass -File packaging\install-endpoint.ps1 `
    -Token "dlpenr_..." -Server "https://dlp.corp.local:8443"
```

The installer (idempotent) then:

1. Installs the minifilter from `dlpflt.inf`, sets it **auto-start** (re-loads
   every boot; the boot-seed re-attaches the watched volume), and loads it.
2. Copies the agent to `C:\Program Files\DLP Agent` and the pinned CA to the
   state dir.
3. Writes `C:\ProgramData\DLPAgent\agent.toml` (the agent's default config path).
4. **Enrolls** — the agent generates its key **locally** (never leaves the box),
   sends only a CSR, and stores the DPAPI-sealed client cert.
5. Registers + starts the **`DLPAgent` LocalSystem service** (depends on
   `FltMgr`). The running SYSTEM agent then writes the driver's read-deny knobs
   and attaches the fixed volume **from console policy** — nothing set by hand.
6. Best-effort registers the toast AppUserModelID for notifications.

## 3. Verify / remove

```powershell
fltmc filters                       # expect 'dlpflt'
sc query DLPAgent                   # expect RUNNING
& 'C:\Program Files\DLP Agent\dlp-agent.exe' status   # enrolled certificate

# uninstall (keeps identity/cert unless -PurgeState):
powershell -ExecutionPolicy Bypass -File packaging\uninstall-endpoint.ps1 [-PurgeState]
```

## What is central (not installer-set)

Read-deny **mode** (off/enforce/monitor), **scan scope** (fixed-volume watch
paths), **fail-secure posture**, and the **trusted-reader allowlist** are all
console policy, delivered over mTLS on first check-in and re-applied on every
resync. The installer only guarantees the driver + SYSTEM agent are present and
enrolled so that policy can flow down. Per-machine/per-group targeting is done
from the console (assign the machine to a group on the Agents page).

> `dlpflt.sys` in the package is the **separately-signed release** binary from
> the build/signing pipeline — it is not committed to git (see Productionization
> P5/P6). On a fresh box, the test-signed driver additionally needs
> `bcdedit /set testsigning on` + reboot; a production EV/attestation-signed
> driver does not.
