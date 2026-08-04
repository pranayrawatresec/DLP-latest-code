<#
.SYNOPSIS
    Install + load the DLP minifilter on a TEST machine (SPEC section 8).

.DESCRIPTION
    Runs on the operator's test-signed VM/spare box ONLY -- never in the build
    environment. Copies the (test-signed) driver, installs the INF, and loads
    the filter with fltmc. Prints the test-signing / reboot prerequisites.

    PREREQUISITES (must already be done, in order):
      1. build\build-driver.bat            -> build\out\dlpflt.sys
      2. tools\make-testcert.ps1           -> trust a test cert
      3. tools\sign-driver.ps1             -> test-sign the .sys (+ .cat)
      4. bcdedit /set testsigning on  AND REBOOT   (this script reminds you)

.PARAMETER InfPath
    Path to dlpflt.inf. Default the repo copy.

.PARAMETER SysPath
    Path to the signed driver. Default build\out\dlpflt.sys.
#>
[CmdletBinding()]
param(
    [string]$InfPath = "$PSScriptRoot\..\dlpflt.inf",
    [string]$SysPath = "$PSScriptRoot\..\build\out\dlpflt.sys",
    [string]$ServiceName = "dlpflt"
)

$ErrorActionPreference = "Stop"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "Run this script elevated (Administrator)."
    }
}

Assert-Admin

if (-not (Test-Path $InfPath)) { throw "INF not found: $InfPath" }
if (-not (Test-Path $SysPath)) { throw "Driver not found: $SysPath (build + sign it first)." }
$InfPath = (Resolve-Path $InfPath).Path
$SysPath = (Resolve-Path $SysPath).Path

# --- Test-signing gate: warn loudly if it is not enabled. -------------------
$tsOn = $false
try {
    $bcd = & bcdedit /enum "{current}" 2>$null | Out-String
    if ($bcd -match "testsigning\s+Yes") { $tsOn = $true }
} catch { }

Write-Host "==================================================================="
Write-Host " DLP minifilter install (TEST machine)"
Write-Host "==================================================================="
if (-not $tsOn) {
    Write-Warning "Test signing does NOT appear to be enabled."
    Write-Host   "  Run, then REBOOT, then re-run this script:"
    Write-Host   "      bcdedit /set testsigning on"
    Write-Host   "  (A test-signed driver will not load until test signing is on.)"
    Write-Host   ""
}

# --- Stage the driver next to the INF's expected source, then install. ------
# The INF's [SourceDisksFiles] expects dlpflt.sys beside the INF.
$infDir = Split-Path -Parent $InfPath
$stagedSys = Join-Path $infDir "dlpflt.sys"
if ((Resolve-Path $SysPath).Path -ne (Join-Path $infDir "dlpflt.sys")) {
    Copy-Item $SysPath $stagedSys -Force
    Write-Host "Staged signed driver -> $stagedSys"
}

Write-Host "Installing INF: $InfPath"
# DefaultInstall section, NT amd64. 128=DIRFLAG, 132 = install + no UI backup.
& RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 $InfPath
Start-Sleep -Seconds 1

Write-Host "Loading filter with fltmc..."
& fltmc load $ServiceName
if ($LASTEXITCODE -ne 0) {
    Write-Warning "fltmc load returned $LASTEXITCODE. Common causes: test signing off (reboot needed), or signature not trusted."
} else {
    Write-Host "Loaded."
}

Write-Host ""
Write-Host "Verify attachment:"
Write-Host "    fltmc filters      # expect 'dlpflt' at altitude 265000"
Write-Host "    fltmc instances    # expect an instance on your removable volume"
Write-Host ""
Write-Host "Then start the user-mode client (it MUST be the connecting process):"
Write-Host "    dlp-agent usb-guard"
Write-Host ""
Write-Host "To remove:  tools\uninstall.ps1"
