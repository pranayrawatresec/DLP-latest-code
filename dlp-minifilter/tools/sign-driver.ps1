<#
.SYNOPSIS
    Test-sign dlpflt.sys (and build + sign a catalog) with the test PFX from
    make-testcert.ps1 (SPEC section 8).

.DESCRIPTION
    Development / test-signing only. Uses signtool (embedded /sys signature) and,
    if available, inf2cat/stampinf to produce dlpflt.cat. If inf2cat is not
    present (WDK not installed), the catalog step is skipped with a note; the
    embedded .sys signature alone is enough to load the driver under
    `bcdedit /set testsigning on`.

.PARAMETER PfxPath
    Path to the test PFX (from make-testcert.ps1).

.PARAMETER Password
    PFX password (SecureString). Prompted if omitted.

.PARAMETER SysPath
    Path to the built driver. Default build\out\dlpflt.sys.

.PARAMETER TimestampUrl
    RFC3161 timestamp URL. Optional and ignored on air-gapped sites (a test
    signature does not require a timestamp).
#>
[CmdletBinding()]
param(
    [string]$PfxPath  = "$PSScriptRoot\dlpflt-test.pfx",
    [System.Security.SecureString]$Password,
    [string]$SysPath  = "$PSScriptRoot\..\build\out\dlpflt.sys",
    [string]$TimestampUrl = ""
)

$ErrorActionPreference = "Stop"

function Find-Tool($name) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    # Probe the Windows Kit bin for the current SDK version.
    $kitBin = "C:\Program Files (x86)\Windows Kits\10\bin"
    if (Test-Path $kitBin) {
        $hit = Get-ChildItem -Path $kitBin -Recurse -Filter $name -ErrorAction SilentlyContinue |
               Where-Object { $_.FullName -match "x64" } | Select-Object -First 1
        if ($hit) { return $hit.FullName }
    }
    return $null
}

if (-not (Test-Path $SysPath)) { throw "Driver not found: $SysPath (run build\build-driver.bat first)." }
if (-not (Test-Path $PfxPath)) { throw "PFX not found: $PfxPath (run tools\make-testcert.ps1 first)." }
if (-not $Password) { $Password = Read-Host -AsSecureString "PFX password" }

$signtool = Find-Tool "signtool.exe"
if (-not $signtool) { throw "signtool.exe not found (install the Windows SDK/WDK signing tools)." }
Write-Host "signtool: $signtool"

# Convert SecureString -> plaintext only for the signtool arg, then clear it.
$bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
$plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
try {
    $sysDir  = Split-Path -Parent $SysPath
    $infPath = Join-Path (Split-Path -Parent $sysDir) "..\dlpflt.inf" | Resolve-Path -ErrorAction SilentlyContinue

    # Optional: stampinf sets DriverVer in the INF (harmless if absent).
    $stampinf = Find-Tool "stampinf.exe"
    if ($stampinf -and $infPath) {
        Write-Host "stampinf: setting DriverVer in dlpflt.inf"
        & $stampinf -f $infPath.Path -d "*" -v "1.0.0.0" | Out-Null
    }

    # Build a catalog if inf2cat is available.
    $inf2cat = Find-Tool "inf2cat.exe"
    $catPath = Join-Path $sysDir "dlpflt.cat"
    if ($inf2cat -and $infPath) {
        # inf2cat wants the directory containing the INF + SYS. Stage them.
        $stage = Join-Path $sysDir "cat-stage"
        New-Item -ItemType Directory -Force -Path $stage | Out-Null
        Copy-Item $SysPath $stage -Force
        Copy-Item $infPath.Path $stage -Force
        Write-Host "inf2cat: building catalog"
        & $inf2cat /driver:$stage /os:10_X64 /verbose
        $staged = Join-Path $stage "dlpflt.cat"
        if (Test-Path $staged) {
            Copy-Item $staged $catPath -Force
            & $signtool sign /fd SHA256 /f $PfxPath /p $plain $catPath
            Write-Host "Signed catalog -> $catPath"
        } else {
            Write-Warning "inf2cat produced no .cat; continuing with embedded .sys signature only."
        }
    } else {
        Write-Warning "inf2cat not found (WDK absent) -- skipping catalog. Embedded .sys signature is sufficient for test-signing."
    }

    # Embedded signature on the .sys itself.
    $args = @("sign", "/fd", "SHA256", "/f", $PfxPath, "/p", $plain)
    if ($TimestampUrl) { $args += @("/tr", $TimestampUrl, "/td", "SHA256") }
    $args += $SysPath
    & $signtool @args
    Write-Host "Signed driver -> $SysPath"

    Write-Host ""
    Write-Host "Verify:  signtool verify /v /pa `"$SysPath`"  (test cert: use /pa)"
}
finally {
    if ($bstr) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    $plain = $null
}
