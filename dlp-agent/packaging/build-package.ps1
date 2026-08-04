# Assembles the agent "install package" — the payload a real MSI would carry.
# Output: packaging/out/  { dlp-agent.exe, ca-cert.pem, agent.toml (template) }
#
# In production this is what the WiX/MSI build produces per customer (their CA
# baked in). Here it copies your dev server's CA so you can test end to end.
#
#   powershell -ExecutionPolicy Bypass -File packaging\build-package.ps1

$ErrorActionPreference = 'Stop'
$agentRoot  = Split-Path $PSScriptRoot -Parent
$repoRoot   = Split-Path $agentRoot -Parent
$serverCa   = Join-Path $repoRoot 'dlp-management-server\ca\ca-cert.pem'
$exe        = Join-Path $agentRoot 'target\release\dlp-agent.exe'
$out        = Join-Path $PSScriptRoot 'out'

if (-not (Test-Path $exe)) {
    Write-Host "Release binary not found. Build it first:" -ForegroundColor Yellow
    Write-Host "    cd dlp-agent; cargo build --release"
    exit 1
}
if (-not (Test-Path $serverCa)) {
    Write-Host "Server CA not found at $serverCa" -ForegroundColor Yellow
    Write-Host "    Initialise it first:  cd dlp-management-server; npm run init-ca"
    exit 1
}

New-Item -ItemType Directory -Force -Path $out | Out-Null
Copy-Item $exe     (Join-Path $out 'dlp-agent.exe') -Force
Copy-Item $serverCa (Join-Path $out 'ca-cert.pem')  -Force

# agent.toml template — install.ps1 fills TOKEN and SERVER at "install" time.
@'
# Written by the installer on the target PC.
server_url = "__SERVER__"
enrollment_token = "__TOKEN__"
ca_cert_path = "__CA__"
state_dir = "__STATE__"
checkin_interval_seconds = 300
'@ | Set-Content -Path (Join-Path $out 'agent.toml') -Encoding utf8

Write-Host "Package assembled in: $out" -ForegroundColor Green
Get-ChildItem $out | Select-Object Name, Length | Format-Table -AutoSize
Write-Host "This folder is the MSI payload. Copy it to a target PC (or use install.ps1)."
