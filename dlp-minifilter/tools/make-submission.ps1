<#
.SYNOPSIS
    Build the Partner Center attestation submission CAB for dlpflt.

.DESCRIPTION
    Produces build\submission\dlpflt.cab -- the single file you upload to
    Partner Center (Drivers -> Submit new hardware) for attestation signing.

    Order is load-bearing and must not change:

        build -> stampinf -> Inf2Cat -> makecab -> (you) sign the CAB

    Inf2Cat records the HASH of every file into dlpflt.cat. Anything that
    modifies dlpflt.sys or dlpflt.inf after Inf2Cat runs silently invalidates
    the catalog, and Partner Center rejects the package.

    This script deliberately does NOT sign anything. Signing needs the EV token
    PIN, which must be typed by a human into the SafeNet dialog -- never scripted
    (repeated wrong PINs lock the token permanently) and never placed on a
    command line (CLAUDE.md: secrets are never hard-coded or logged). The script
    prints the exact signtool command to run when it finishes.

    The repo copy of dlpflt.inf is NOT modified; stampinf runs on the staged copy.

.PARAMETER Version
    DriverVer version stamped into the staged INF. Bump this for every
    submission -- two submissions sharing a version are painful to tell apart
    later.

.PARAMETER SysPath
    Driver binary to submit. Default build\out\dlpflt.sys.

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File tools\make-submission.ps1 -Version 1.0.0.1
#>
[CmdletBinding()]
param(
    [string]$Version = "1.0.0.0",
    [string]$SysPath,
    [string]$InfPath,
    # Embed the EV signature in dlpflt.sys before the catalog is built. Needs the
    # token; prompts for the PIN once. Use for production submissions.
    [switch]$EmbedSign,
    [string]$EVThumbprint = "2CE7FCBEF04C279943F175A936E7588D298D254A",
    [string]$TimestampUrl = "http://rfc3161timestamp.globalsign.com/advanced"
)

$ErrorActionPreference = "Stop"

# $PSScriptRoot is not reliably populated in param() defaults under
# `powershell -File` on 5.1, so resolve the script's own location here.
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$mfRoot    = (Resolve-Path (Join-Path $scriptDir "..")).Path
if (-not $SysPath) { $SysPath = Join-Path $mfRoot "build\out\dlpflt.sys" }
if (-not $InfPath) { $InfPath = Join-Path $mfRoot "dlpflt.inf" }
$stage  = Join-Path $mfRoot "build\submission"
$pkg    = Join-Path $stage  "dlpflt"

function Find-Tool($name, $arch) {
    $kitBin = "C:\Program Files (x86)\Windows Kits\10\bin"
    if (-not (Test-Path $kitBin)) { throw "Windows Kits not found at $kitBin" }
    # Newest SDK version first.
    $hit = Get-ChildItem $kitBin -Directory |
           Where-Object { $_.Name -match '^10\.' } |
           Sort-Object { [version]$_.Name } -Descending |
           ForEach-Object { Join-Path $_.FullName "$arch\$name" } |
           Where-Object { Test-Path $_ } |
           Select-Object -First 1
    if (-not $hit) { throw "$name not found under $kitBin ($arch)." }
    return $hit
}

# Inf2Cat ships x86-only; stampinf we take x64.
$inf2cat  = Find-Tool "Inf2Cat.exe"  "x86"
$stampinf = Find-Tool "stampinf.exe" "x64"
$signtool = Find-Tool "signtool.exe" "x64"

Write-Host "=== tools ===" -ForegroundColor Cyan
Write-Host "  inf2cat  : $inf2cat"
Write-Host "  stampinf : $stampinf"

if (-not (Test-Path $SysPath)) {
    throw "Driver not found: $SysPath  (run build\build-driver.bat first)."
}
if (-not (Test-Path $InfPath)) { throw "INF not found: $InfPath" }

# --- 1. Stage a clean folder ------------------------------------------------
# Never build the CAB in the repo root: makecab drops setup.inf/setup.rpt
# beside itself, which is how two stray files ended up committed in August.
Write-Host "`n=== stage ===" -ForegroundColor Cyan
Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $pkg | Out-Null
Copy-Item $SysPath $pkg -Force
Copy-Item $InfPath $pkg -Force
Write-Host "  staged -> $pkg"

$stagedSys = Join-Path $pkg "dlpflt.sys"
$stagedInf = Join-Path $pkg "dlpflt.inf"

# --- 2. Strip any signature from the staged binary ---------------------------
# A leftover self-signed TEST signature has no business in a package going to
# Microsoft. A clean build has none, so only strip when one is actually there
# (signtool remove errors with 0x57 on an unsigned file).
if ((Get-AuthenticodeSignature $stagedSys).Status -ne "NotSigned") {
    Write-Host "  stripping existing signature from staged dlpflt.sys"
    & $signtool remove /s $stagedSys | Out-Null
} else {
    Write-Host "  staged dlpflt.sys is unsigned (clean build) -- nothing to strip"
}

# --- 2b. Optionally embed the EV signature in the staged binary --------------
# Must happen BEFORE Inf2Cat: the catalog records the file's hash, so signing
# after would invalidate it. Off by default because it needs the token PIN;
# pass -EmbedSign for the production submission.
#
# NOTE (open question, worth checking on the next round trip): it is not
# established whether Microsoft's attestation PRESERVES a pre-existing embedded
# signature as a secondary signature or REPLACES it. Verify what comes back with
#   signtool verify /all /pa dlpflt.sys
# and record the answer in build\submissions\.
if ($EmbedSign) {
    Write-Host "`n=== embed-sign staged dlpflt.sys (EV token PIN prompt) ===" -ForegroundColor Cyan
    & $signtool sign /fd SHA256 /sha1 $EVThumbprint /tr $TimestampUrl /td SHA256 /v $stagedSys
    if ($LASTEXITCODE -ne 0) { throw "embed-sign failed ($LASTEXITCODE)." }
    & $signtool verify /pa /v $stagedSys | Select-String "Issued to:|Successfully"
}

# --- 3. Stamp DriverVer on the STAGED inf (repo copy untouched) --------------
Write-Host "`n=== stampinf (DriverVer) ===" -ForegroundColor Cyan
& $stampinf -f $stagedInf -d "*" -v $Version -a "amd64"
if ($LASTEXITCODE -ne 0) { throw "stampinf failed ($LASTEXITCODE)." }
(Select-String -Path $stagedInf -Pattern "DriverVer").Line | ForEach-Object { Write-Host "  $_" }

# --- 4. Generate the (unsigned) catalog --------------------------------------
# Do NOT sign this .cat. Microsoft replaces it with their signed version -- that
# returned catalog is the entire point of the submission.
Write-Host "`n=== Inf2Cat (signability test + catalog) ===" -ForegroundColor Cyan
& $inf2cat /driver:$pkg /os:10_X64 /verbose 2>&1 |
    Where-Object { $_ -match "Signability|Errors|Warnings|None|error|warning" }
if ($LASTEXITCODE -ne 0) { throw "Inf2Cat failed ($LASTEXITCODE) -- INF is not signable." }

$cat = Join-Path $pkg "dlpflt.cat"
if (-not (Test-Path $cat)) { throw "Inf2Cat produced no dlpflt.cat." }

# --- 5. Build the CAB --------------------------------------------------------
# DestinationDir=dlpflt puts the files in a dlpflt\ folder INSIDE the cab.
# Partner Center wants them foldered, not loose at the cab root.
Write-Host "`n=== makecab ===" -ForegroundColor Cyan
$ddf = Join-Path $stage "dlpflt.ddf"
@'
.OPTION EXPLICIT
.Set CabinetFileCountThreshold=0
.Set FolderFileCountThreshold=0
.Set FolderSizeThreshold=0
.Set MaxCabinetSize=0
.Set MaxDiskFileCount=0
.Set MaxDiskSize=0
.Set CompressionType=MSZIP
.Set Cabinet=on
.Set Compress=on
.Set CabinetNameTemplate=dlpflt.cab
.Set DiskDirectoryTemplate=.
.Set DestinationDir=dlpflt
.\dlpflt\dlpflt.inf
.\dlpflt\dlpflt.cat
.\dlpflt\dlpflt.sys
'@ | Set-Content -Path $ddf -Encoding ascii

Push-Location $stage
try {
    & makecab /f dlpflt.ddf | Select-Object -Last 4
    if ($LASTEXITCODE -ne 0) { throw "makecab failed ($LASTEXITCODE)." }
} finally { Pop-Location }

$cab = Join-Path $stage "dlpflt.cab"
if (-not (Test-Path $cab)) { throw "makecab produced no dlpflt.cab." }

# --- 6. Verify the CAB actually contains all three files ---------------------
# This is the check that was missed in August: that CAB held inf+sys only, with
# no catalog, so there was nothing for Microsoft to sign.
Write-Host "`n=== CAB contents ===" -ForegroundColor Cyan
# makecab's own setup.inf manifest shows the in-cab paths INCLUDING the folder
# prefix; `expand -D` lists the names but strips the directory, so the manifest
# is the better evidence that the files are foldered rather than loose.
$manifest = Join-Path $stage "setup.inf"
$entries  = @(Select-String -Path $manifest -Pattern "^1,1,dlpflt\\" | ForEach-Object { $_.Line })
$entries | ForEach-Object { Write-Host "  $_" }

$missing = @("dlpflt.inf","dlpflt.cat","dlpflt.sys") |
           Where-Object { ($entries -join "`n") -notmatch [regex]::Escape("dlpflt\$_") }
if ($missing) { throw "CAB is missing: $($missing -join ', ') -- do NOT upload this." }
Write-Host "  all 3 files present, foldered under dlpflt\ -- OK" -ForegroundColor Green

Write-Host "`n=== OK ===" -ForegroundColor Green
Get-Item $cab | Select-Object FullName, Length, LastWriteTime | Format-List

Write-Host "NEXT -- sign the CAB with the EV token, then upload it." -ForegroundColor Yellow
Write-Host "Type the PIN into the SafeNet dialog when it appears. Do not script it.`n"
Write-Host "  & `"$signtool`" sign /fd SHA256 ``"
Write-Host "      /sha1 $EVThumbprint ``"
Write-Host "      /tr $TimestampUrl /td SHA256 /v ``"
Write-Host "      `"$cab`"`n"
Write-Host "  & `"$signtool`" verify /pa /v `"$cab`"`n"
Write-Host "Then upload $cab at https://partner.microsoft.com/dashboard/hardware"
