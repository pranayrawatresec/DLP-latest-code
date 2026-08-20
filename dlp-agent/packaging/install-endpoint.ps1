<#
.SYNOPSIS
    Production endpoint installer -- installs the DLP kernel minifilter + the agent
    as a LocalSystem service, provisions config, and enrolls. No manual steps.

.DESCRIPTION
    This is the "no hand-typed commands" installer the product ships (the payload a
    real MSI/WiX carries). Run ELEVATED on the target endpoint. It is idempotent --
    safe to re-run to repair/upgrade an install.

    Steps (each skipped if already done):
      1. Install the kernel minifilter from dlpflt.inf  -> creates the 'dlpflt'
         service (FailMode default from the INF), sets it to auto-start so it
         re-loads every boot, and loads it now with fltmc.
      2. Copy the agent exe to $InstallDir and the pinned CA to the state dir.
      3. Write agent.toml to the agent's default config path with the server URL,
         one-time enrollment token, CA path and state dir.
      4. Enroll: the agent generates its key locally (never leaves the machine),
         sends only a CSR, and stores the DPAPI-sealed cert.
      5. install-service (LocalSystem, depends on FltMgr) + start it. The running
         SYSTEM agent then writes the driver's read-deny knobs and attaches the
         watched fixed volume FROM CONSOLE POLICY -- no manual reg/fltmc needed.
      6. Best-effort: register the toast AppUserModelID so notifications render.

    The driver's read-deny mode / scan-scope / fail-secure posture are CENTRAL
    (console policy), delivered over mTLS on first check-in; the installer never
    sets them by hand.

.PARAMETER Token
    One-time enrollment token minted in the console (Enrollment page).

.PARAMETER Server
    Server base URL, e.g. https://dlp.corp.local:8443. Host MUST be in the server
    certificate SAN. Defaults to https://localhost:8443 for a local test.

.PARAMETER PackageDir
    Folder holding the payload: dlp-agent.exe, ca-cert.pem, agent.toml (template),
    dlpflt.sys, dlpflt.inf [, dlpflt.cat]. Defaults to this script's folder + \out.

.PARAMETER InstallDir
    Where the agent exe is installed. Default 'C:\Program Files\DLP Agent'.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File packaging\install-endpoint.ps1 `
        -Token "dlpenr_ab12..." -Server "https://dlp.corp.local:8443"
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Token,
    [string]$Server        = 'https://localhost:8443',
    [string]$PackageDir    = '',
    [string]$InstallDir    = 'C:\Program Files\DLP Agent',
    [string]$StateDir      = 'C:\ProgramData\DLPAgent',
    [string]$DriverService = 'dlpflt',
    [string]$AgentService  = 'DLPAgent',
    [string]$Aumid         = 'Resec.DLP.Agent'
)

$ErrorActionPreference = 'Stop'
function Info($m)  { Write-Host $m -ForegroundColor Cyan }
function Ok($m)    { Write-Host $m -ForegroundColor Green }
function Warn($m)  { Write-Warning $m }

# --- 0. Preconditions ------------------------------------------------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)) {
    throw "Run this installer elevated (Administrator)."
}
if ([string]::IsNullOrEmpty($PackageDir)) { $PackageDir = Join-Path $PSScriptRoot 'out' }
$exeSrc = Join-Path $PackageDir 'dlp-agent.exe'
$caSrc  = Join-Path $PackageDir 'ca-cert.pem'
$sysSrc = Join-Path $PackageDir 'dlpflt.sys'
$infSrc = Join-Path $PackageDir 'dlpflt.inf'
$tmlSrc = Join-Path $PackageDir 'agent.toml'
foreach ($f in @($exeSrc, $caSrc, $tmlSrc)) {
    if (-not (Test-Path $f)) { throw "Package incomplete -- missing $f. Run build-package.ps1." }
}
$haveDriver = (Test-Path $sysSrc) -and (Test-Path $infSrc)
if (-not $haveDriver) {
    Warn "Driver payload (dlpflt.sys/.inf) not in the package -- skipping driver install."
    Warn "The agent guard cannot connect to the minifilter until the driver is installed."
}

Info "=== DLP endpoint install ==="
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $StateDir   | Out-Null

# --- 1. Kernel minifilter -------------------------------------------------
if ($haveDriver) {
    $svc = Get-Service -Name $DriverService -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        Info "Installing minifilter from $infSrc ..."
        # The INF's [SourceDisksFiles] expects dlpflt.sys beside the INF.
        $stagedSys = Join-Path (Split-Path $infSrc -Parent) 'dlpflt.sys'
        if ((Resolve-Path $sysSrc).Path -ne $stagedSys) { Copy-Item $sysSrc $stagedSys -Force }
        & RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 (Resolve-Path $infSrc).Path
        Start-Sleep -Seconds 1
    } else {
        Info "Driver service '$DriverService' already present -- leaving its install."
    }
    # Auto-start so the filter re-loads every boot (boot-seed then re-attaches C:).
    & sc.exe config $DriverService start= auto | Out-Null
    # Load now if not already attached.
    $loaded = (& fltmc.exe filters) -match "^\s*$DriverService\s"
    if (-not $loaded) {
        Info "Loading filter ..."
        & fltmc.exe load $DriverService
        if ($LASTEXITCODE -ne 0) {
            Warn "fltmc load returned $LASTEXITCODE (test-signing off + reboot needed, or signature not trusted). Continuing."
        } else { Ok "Filter loaded." }
    } else { Info "Filter already loaded." }
}

# --- 2. Files: agent exe + pinned CA --------------------------------------
$exeDst = Join-Path $InstallDir 'dlp-agent.exe'
Copy-Item $exeSrc $exeDst -Force
$caDst = Join-Path $StateDir 'ca-cert.pem'
Copy-Item $caSrc $caDst -Force
Ok "Installed agent -> $exeDst"

# --- 3. Config at the agent's DEFAULT path (so the SYSTEM service finds it) -
$configPath = Join-Path $StateDir 'agent.toml'
(Get-Content $tmlSrc -Raw).
    Replace('__SERVER__', $Server).
    Replace('__TOKEN__',  $Token).
    Replace('__CA__',     ($caDst    -replace '\\','\\')).
    Replace('__STATE__',  ($StateDir -replace '\\','\\')) |
    Set-Content -Path $configPath -Encoding utf8
Ok "Wrote config -> $configPath"

# --- 4. Enroll (local keygen -> CSR -> DPAPI-sealed cert; idempotent) ------
Info "Enrolling (generating machine key locally; only a CSR leaves the box) ..."
$env:DLP_AGENT_CONFIG = $configPath
& $exeDst enroll
if ($LASTEXITCODE -ne 0) { throw "Enrollment failed ($LASTEXITCODE). Check the token and that $Server is reachable and its SAN matches." }
& $exeDst status

# --- 5. Agent as LocalSystem service --------------------------------------
$asvc = Get-Service -Name $AgentService -ErrorAction SilentlyContinue
if ($null -eq $asvc) {
    Info "Registering service '$AgentService' (LocalSystem, depends on FltMgr) ..."
    & $exeDst install-service
    if ($LASTEXITCODE -ne 0) { throw "install-service failed ($LASTEXITCODE)." }
} else {
    Info "Service '$AgentService' already registered."
}
# The service reads the default config path; make sure DLP_AGENT_CONFIG is also
# set machine-wide so a SYSTEM-launched process resolves the same file.
[Environment]::SetEnvironmentVariable('DLP_AGENT_CONFIG', $configPath, 'Machine')
& sc.exe config $AgentService start= auto | Out-Null
Info "Starting '$AgentService' ..."
& sc.exe start $AgentService | Out-Null

# --- 6. Toast AppUserModelID (best-effort; notifications only) -------------
try {
    $key = "HKLM:\SOFTWARE\Classes\AppUserModelId\$Aumid"
    New-Item -Path $key -Force | Out-Null
    New-ItemProperty -Path $key -Name 'DisplayName' -Value 'DLP Endpoint Agent' -PropertyType String -Force | Out-Null
    Ok "Registered toast AppUserModelID '$Aumid'."
} catch { Warn "Toast AUMID registration skipped: $($_.Exception.Message)" }

Ok "`n=== Install complete ==="
Info "Verify:"
Info "    fltmc filters                 # expect '$DriverService'"
Info "    sc query $AgentService         # expect RUNNING"
Info "    & '$exeDst' status             # expect an enrolled certificate"
Info "The driver's read-deny mode + scan scope arrive from console policy on first check-in."
