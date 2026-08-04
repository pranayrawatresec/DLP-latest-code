# Simulates installing + first-run of the agent on a PC, from the package.
# Each -PcName gets its OWN state dir, so you can pretend one machine is several
# different PCs (each enrolls separately and gets its own certificate).
#
#   powershell -ExecutionPolicy Bypass -File packaging\install.ps1 `
#       -Token "dlpenr_..." -PcName PC-01 [-Server https://localhost:8443]
#
# On a REAL different PC: copy packaging\out\ over, then run this with the
# server's reachable address (which MUST be in the server certificate's SAN).

param(
    [Parameter(Mandatory = $true)][string]$Token,
    [string]$PcName = 'PC-01',
    [string]$Server = 'https://localhost:8443',
    [string]$PackageDir = ''
)

$ErrorActionPreference = 'Stop'
if ([string]::IsNullOrEmpty($PackageDir)) { $PackageDir = Join-Path $PSScriptRoot 'out' }
$exe = Join-Path $PackageDir 'dlp-agent.exe'
$ca  = Join-Path $PackageDir 'ca-cert.pem'
if (-not (Test-Path $exe)) { Write-Host "Run build-package.ps1 first." -ForegroundColor Yellow; exit 1 }

# Each simulated PC gets an isolated state dir + config (like C:\ProgramData\DLPAgent).
$stateDir = Join-Path $env:TEMP "dlp-agent-pcs\$PcName"
New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
$configPath = Join-Path $stateDir 'agent.toml'

(Get-Content (Join-Path $PackageDir 'agent.toml') -Raw).
    Replace('__SERVER__', $Server).
    Replace('__TOKEN__',  $Token).
    Replace('__CA__',     ($ca      -replace '\\','\\')).
    Replace('__STATE__',  ($stateDir -replace '\\','\\')) |
    Set-Content -Path $configPath -Encoding utf8

Write-Host "== Installing agent as '$PcName' ==" -ForegroundColor Cyan
Write-Host "   config:    $configPath"
Write-Host "   state dir: $stateDir`n"

$env:DLP_AGENT_CONFIG = $configPath
Write-Host "-- enrolling --" -ForegroundColor Cyan
& $exe enroll
Write-Host "`n-- status (your certificate) --" -ForegroundColor Cyan
& $exe status
Write-Host "`nDone. Run a live check-in loop with:" -ForegroundColor Green
Write-Host "    `$env:DLP_AGENT_CONFIG='$configPath'; & '$exe' run"
