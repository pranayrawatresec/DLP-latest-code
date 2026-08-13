# setup-encrypt-vm.ps1 - enable encrypt-on-write on the already-provisioned demo VM.
# Run ONCE as Administrator on the VM, AFTER provision-vm.ps1 (driver + enrollment
# + usb-guard task already in place).
#
# It: swaps in the fixed dlp-agent.exe (baseline + no-reseal + guard/sealer
# coexistence), generates a local dev keyring, adds the USB encrypt whitelist to
# agent.toml, and restarts the guard so it is whitelist-aware. Then you run the
# sealer (usb-monitor) in a visible window and copy files to the stick.
#
# The kernel guard MUST keep running: the driver is FailMode=1 (fail-secure), so
# with no guard answering, ALL removable writes are DENIED and nothing can be
# copied to seal. Guard + sealer run together (that is the intended product mode).
#
# Copy to the VM first (e.g. C:\dlp\): the NEW dlp-agent.exe and this script.
#
# Usage:
#   .\setup-encrypt-vm.ps1 -Serial 0F7D00D16030 [-Source C:\dlp]
# Confirm the serial the VM sees: run '.\dlp-agent.exe usb-monitor' for a few
# seconds and read the "removable device arrived ... serial=..." line.

param(
    [Parameter(Mandatory = $true)] [string]$Serial,   # pen drive serial as the VM sees it
    [string]$Source = "C:\dlp"                         # where the new dlp-agent.exe was copied
)

$ErrorActionPreference = "Stop"
$Base = "C:\ProgramData\DLPAgent"

# --- 0. sanity ---------------------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}
if (-not (Test-Path "$Source\dlp-agent.exe")) { throw "missing $Source\dlp-agent.exe (copy the NEW build here first)" }
if (-not (Test-Path "$Base\agent.toml"))      { throw "agent.toml not found - run provision-vm.ps1 first" }

# --- 1. stop guard task + any running agent so we can swap the exe -----------
try { Stop-ScheduledTask -TaskName "DLP Agent Guard" } catch {}
Get-Process -Name dlp-agent -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# --- 2. swap in the fixed exe ------------------------------------------------
Copy-Item "$Source\dlp-agent.exe" "$Base\dlp-agent.exe" -Force
Write-Host "agent exe updated"

# --- 3. dev keyring (generated locally; raw key stays on THIS box) -----------
# Seal and decrypt on this same VM use this one keyring, so it is self-consistent.
# DEV ONLY: plaintext key bytes on disk. Never deploy.
if (-not (Test-Path "$Base\dev-keyring.json")) {
    $b = New-Object byte[] 32; (New-Object Random).NextBytes($b)
    $kek = [Convert]::ToBase64String($b)
    @"
{ "activeKeyId": "class-internal/v1", "keys": { "class-internal/v1": "$kek" }, "destroyed": [] }
"@ | Out-File -Encoding ascii "$Base\dev-keyring.json"
    Write-Host "dev keyring created"
} else {
    Write-Host "dev keyring already present - keeping it"
}

# --- 4. add [usb] encrypt whitelist + [crypto] to agent.toml (idempotent) ----
$toml = Get-Content "$Base\agent.toml" -Raw
if ($toml -match '(?m)^\[crypto\]') {
    Write-Host "agent.toml already has [crypto] - leaving config as-is"
} else {
    @"

[usb]
enabled = true

[[usb.rules]]
match_serial = "$Serial"
action = "encrypt"
mode = "encrypt_sensitive"
on_block_band = "seal"
note = "encrypt-on-write test stick"

[crypto]
default_key_id = "class-internal/v1"
keyfile = "C:\\ProgramData\\DLPAgent\\dev-keyring.json"
"@ | Add-Content -Encoding ascii "$Base\agent.toml"
    Write-Host "agent.toml: added encrypt whitelist for serial $Serial"
}

# --- 5. restart the guard (now coexistence-aware, reads the encrypt rule) -----
Start-ScheduledTask -TaskName "DLP Agent Guard"
Start-Sleep -Seconds 2
$g = Get-CimInstance Win32_Process -Filter "Name='dlp-agent.exe'" |
     Where-Object { $_.CommandLine -match 'usb-guard' }
Write-Host "guard restarted: $([bool]$g)"

Write-Host ""
Write-Host "=================================================================="
Write-Host " Encrypt-on-write enabled. Now, in THIS admin window, run the sealer:"
Write-Host ""
Write-Host "     & '$Base\dlp-agent.exe' usb-monitor"
Write-Host ""
Write-Host " Leave it running. Then:"
Write-Host "   * copy a SENSITIVE file to the stick  -> becomes <name>.dlpenc"
Write-Host "   * copy a CLEAN file to the stick      -> stays plaintext"
Write-Host "   * decrypt:  & '$Base\dlp-agent.exe' decrypt <path>\<name>.dlpenc -o <out>"
Write-Host " Files already on the stick are baselined (left alone); only NEW"
Write-Host " copies are sealed."
Write-Host "=================================================================="
