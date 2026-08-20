<#
.SYNOPSIS
    Remove the DLP endpoint agent + kernel minifilter installed by
    install-endpoint.ps1. Run ELEVATED. Idempotent.

.PARAMETER PurgeState
    Also delete C:\ProgramData\DLPAgent (config, pinned CA, DPAPI-sealed identity
    and cached policy). WITHOUT this the machine identity/cert is kept so a
    reinstall does not re-enroll. WITH it the machine must re-enroll next install.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File packaging\uninstall-endpoint.ps1
    powershell -ExecutionPolicy Bypass -File packaging\uninstall-endpoint.ps1 -PurgeState
#>
[CmdletBinding()]
param(
    [switch]$PurgeState,
    [string]$InstallDir    = 'C:\Program Files\DLP Agent',
    [string]$StateDir      = 'C:\ProgramData\DLPAgent',
    [string]$DriverService = 'dlpflt',
    [string]$AgentService  = 'DLPAgent',
    [string]$Aumid         = 'Resec.DLP.Agent'
)

$ErrorActionPreference = 'Continue'   # best-effort teardown; keep going on errors
function Info($m) { Write-Host $m -ForegroundColor Cyan }
function Ok($m)   { Write-Host $m -ForegroundColor Green }

$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
        [Security.Principal.WindowsBuiltinRole]::Administrator)) {
    throw "Run this uninstaller elevated (Administrator)."
}

Info "=== DLP endpoint uninstall ==="

# 1. Agent service -- stop + delete. Prefer the agent's own uninstall (cleans its
#    service registration the same way it created it), fall back to sc.exe.
$exeDst = Join-Path $InstallDir 'dlp-agent.exe'
if (Get-Service -Name $AgentService -ErrorAction SilentlyContinue) {
    Info "Stopping + removing service '$AgentService' ..."
    & sc.exe stop $AgentService | Out-Null
    Start-Sleep -Seconds 2
    if (Test-Path $exeDst) { & $exeDst uninstall-service 2>$null | Out-Null }
    if (Get-Service -Name $AgentService -ErrorAction SilentlyContinue) { & sc.exe delete $AgentService | Out-Null }
    Ok "Agent service removed."
}
[Environment]::SetEnvironmentVariable('DLP_AGENT_CONFIG', $null, 'Machine')

# 2. Minifilter -- unload + delete the service.
if (Get-Service -Name $DriverService -ErrorAction SilentlyContinue) {
    Info "Unloading + removing minifilter '$DriverService' ..."
    & fltmc.exe unload $DriverService 2>$null
    & sc.exe delete $DriverService | Out-Null
    Ok "Minifilter removed (driver binary in System32\drivers is left for the OS to reclaim)."
}

# 3. Toast AUMID.
$key = "HKLM:\SOFTWARE\Classes\AppUserModelId\$Aumid"
if (Test-Path $key) { Remove-Item -Path $key -Recurse -Force -ErrorAction SilentlyContinue }

# 4. Installed files.
if (Test-Path $InstallDir) { Remove-Item -Path $InstallDir -Recurse -Force -ErrorAction SilentlyContinue }

# 5. State -- only on explicit request (holds the machine identity/cert).
if ($PurgeState) {
    if (Test-Path $StateDir) { Remove-Item -Path $StateDir -Recurse -Force -ErrorAction SilentlyContinue }
    Ok "Purged state dir $StateDir (machine will re-enroll on next install)."
} else {
    Info "Kept state dir $StateDir (identity/cert preserved). Use -PurgeState to remove it."
}

Ok "=== Uninstall complete ==="
