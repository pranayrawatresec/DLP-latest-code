# provision-vm.ps1 - one-time "installer" for the demo VM.
# Run ONCE as Administrator on the VM. After it finishes (and on every reboot),
# DLP protection is on with zero user interaction - the end user just uses the
# PC and sees a "Blocked by DLP" toast when they try to exfiltrate.
#
# This is the demo-grade stand-in for the future MSI + Windows service. It does
# EVERYTHING, including the kernel driver:
#   1. hosts entry so the server cert SAN verifies
#   2. agent files + agent.toml into C:\ProgramData\DLPAgent (no env vars)
#   3. kernel minifilter: trust the signing cert, install INF, FailMode=1
#      (fail-secure) BEFORE first load, load-at-boot, load now
#   4. enroll + fetch the index bundle (consumes one token use)
#   5. usb-guard + heartbeat as hidden SYSTEM scheduled tasks (boot-persistent)
#
# The driver is SIGNED ON THE BUILD HOST - the VM only trusts the cert and
# loads. No signtool/WDK needed here. ONE prerequisite that cannot be scripted
# without a reboot: test-signing must already be ON (bcdedit /set testsigning on
# + reboot). This script checks and stops if it is not.
#
# Copy to the VM (e.g. C:\dlp\): dlp-agent.exe, ca-cert.pem, dlpflt.sys,
# dlpflt.inf, dlpflt-signer.cer, and this script.
#
# Usage:
#   .\provision-vm.ps1 -Token "dlpenr_..." -ServerIp 192.168.x.x [-Source C:\dlp]

param(
    [Parameter(Mandatory = $true)]  [string]$Token,     # enrollment token from the operator
    [Parameter(Mandatory = $true)]  [string]$ServerIp,  # LAN IP of the host running the management server
    [string]$Source = "C:\dlp"                          # where the artifacts were copied
)

$ErrorActionPreference = "Stop"
$Base = "C:\ProgramData\DLPAgent"
$ServerHost = "desktop-k8e7f5d"   # must match the server certificate SAN
$SvcKey = "HKLM:\SYSTEM\CurrentControlSet\Services\dlpflt"

# --- 0. sanity -----------------------------------------------------------------
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
        ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}
foreach ($f in @("dlp-agent.exe", "ca-cert.pem", "dlpflt.sys", "dlpflt.inf", "dlpflt-signer.cer")) {
    if (-not (Test-Path "$Source\$f")) { throw "missing artifact: $Source\$f" }
}
$bcd = & bcdedit /enum "{current}" | Out-String
if ($bcd -notmatch "testsigning\s+Yes") {
    throw "Test-signing is OFF. Run 'bcdedit /set testsigning on', REBOOT, then re-run this script."
}

# --- 1. hosts entry so the cert SAN verifies -----------------------------------
$hostsFile = "$env:SystemRoot\System32\drivers\etc\hosts"
if (-not (Select-String -Path $hostsFile -Pattern $ServerHost -Quiet)) {
    Add-Content -Path $hostsFile -Value "$ServerIp   $ServerHost" -Encoding ascii
    Write-Host "hosts: added $ServerIp -> $ServerHost"
}

# --- 2. install agent files + config to ProgramData (the product layout) -------
New-Item -ItemType Directory -Force -Path $Base | Out-Null
Copy-Item "$Source\dlp-agent.exe" "$Base\dlp-agent.exe" -Force
Copy-Item "$Source\ca-cert.pem"  "$Base\ca-cert.pem"  -Force

# agent.toml - the agent reads this automatically; no env vars anywhere.
# enrollment_token is only honoured until the cert exists, ignored afterwards.
@"
server_url = "https://${ServerHost}:8443"
enrollment_token = "$Token"
ca_cert_path = "C:\\ProgramData\\DLPAgent\\ca-cert.pem"
state_dir = "C:\\ProgramData\\DLPAgent"
checkin_interval_seconds = 300

[kguard]
scan_fixed = true
watch_paths = ["\\Users", "\\Data"]

[notify]
enabled = true
mode = "standard"
org_name = "Data Loss Prevention"
aumid = "Resec.DLP.Agent"
dedup_secs = 5
max_per_minute = 20
"@ | Out-File -FilePath "$Base\agent.toml" -Encoding utf8

# Register the toast AppUserModelID machine-wide. Windows only renders toasts
# for a registered AUMID; without this the "Blocked by DLP" toast is silently
# dropped. (The future MSI does this via a Start-Menu shortcut instead.)
$aumidKey = "HKLM:\SOFTWARE\Classes\AppUserModelId\Resec.DLP.Agent"
New-Item -Path $aumidKey -Force | Out-Null
Set-ItemProperty -Path $aumidKey -Name DisplayName -Value "Data Loss Prevention"
Write-Host "toast: registered AUMID Resec.DLP.Agent"

# --- 3. kernel minifilter: trust cert, install INF, fail-secure, load ----------
$loaded = [bool](fltmc filters | Select-String "dlpflt")
$installed = Test-Path $SvcKey

if (-not $installed) {
    # Trust the build host's test signing cert (public cert only - no key):
    # Root so the chain validates, TrustedPublisher so the INF installs silently.
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 "$Source\dlpflt-signer.cer"
    foreach ($storeName in @("Root", "TrustedPublisher")) {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "LocalMachine")
        $store.Open("ReadWrite"); $store.Add($cert); $store.Close()
    }
    Write-Host "driver: trusted signing cert $($cert.Thumbprint)"

    # The INF's [SourceDisksFiles] expects dlpflt.sys beside the INF.
    $infPath = (Resolve-Path "$Source\dlpflt.inf").Path
    Copy-Item "$Source\dlpflt.sys" (Join-Path (Split-Path $infPath) "dlpflt.sys") -Force
    & RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 $infPath
    Start-Sleep -Seconds 2
    if (-not (Test-Path $SvcKey)) { throw "INF install did not create the dlpflt service key" }
    Write-Host "driver: INF installed"
}

# Fail-secure + boot-load - BEFORE (re)loading, so DriverEntry reads the final
# values on its very first load. The INF ships FailMode=0 (allow+audit) and
# demand-start; product behaviour is fail-secure + load at every boot.
Set-ItemProperty -Path $SvcKey -Name FailMode -Value 1 -Type DWord
sc.exe config dlpflt start= system | Out-Null
Write-Host "driver: FailMode=1 (fail-secure), StartType=system (loads at boot)"

if ($loaded) {
    # Was already loaded (pre-provisioning manual install) - reload to pick up FailMode=1.
    fltmc unload dlpflt | Out-Null
}
fltmc load dlpflt
if ($LASTEXITCODE -ne 0) { throw "fltmc load failed ($LASTEXITCODE) - is test-signing really on after a reboot?" }
$alt = fltmc filters | Select-String "dlpflt"
Write-Host "driver: loaded -> $alt"

# --- 4. enroll + fetch the index bundle (one-time, uses the token) -------------
& "$Base\dlp-agent.exe" once          ; if ($LASTEXITCODE -ne 0) { throw "enrollment failed" }
& "$Base\dlp-agent.exe" index-update  ; if ($LASTEXITCODE -ne 0) { throw "index-update failed" }
& "$Base\dlp-agent.exe" status

# --- 5. install the unified DLPAgent Windows service ---------------------------
# ONE supervised LocalSystem service (run-endpoint) that hosts the kernel guard +
# user-mode sealer + check-in + whitelist re-sync as coordinated threads sharing
# one whitelist view and one sealer-liveness signal. Replaces the old two
# scheduled tasks (guard + heartbeat) and the separate usb-monitor. The guard
# stands aside for the in-process sealer only while the sealer is healthy;
# otherwise a seal-eligible write is BLOCKED (fail secure). Depends on FltMgr.
# Remove any prior task-based install so the two approaches never both run.
foreach ($t in @("DLP Agent Guard", "DLP Agent Heartbeat")) {
    try { Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue } catch {}
    try { Unregister-ScheduledTask -TaskName $t -Confirm:$false -ErrorAction SilentlyContinue } catch {}
}
# Re-install cleanly (ignore "not present" on first run).
try { & "$Base\dlp-agent.exe" uninstall-service | Out-Null } catch {}
& "$Base\dlp-agent.exe" install-service ; if ($LASTEXITCODE -ne 0) { throw "install-service failed" }
sc.exe start DLPAgent | Out-Null
Write-Host "service: DLPAgent installed (auto-start, LocalSystem) and started"

# --- 6. verify ------------------------------------------------------------------
Start-Sleep -Seconds 4
$svc = Get-Service -Name DLPAgent -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-Host ""
    Write-Host "PROVISIONED OK - DLPAgent service Running (guard + sealer + check-in + re-sync)."
    Write-Host "Reboot survives. Logs: $Base\logs\dlp-agent.log"
    Write-Host "Whitelist a stick in the console (Trusted USB devices); the service syncs it live."
} else {
    $st = if ($svc) { $svc.Status } else { "not installed" }
    Write-Warning "DLPAgent service is '$st' - check '$Base\logs\dlp-agent.log' and 'sc query DLPAgent'."
}
