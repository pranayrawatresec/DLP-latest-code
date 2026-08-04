<#
.SYNOPSIS
    Unload + remove the DLP minifilter from a TEST machine (SPEC section 8).

.DESCRIPTION
    Unloads the filter with fltmc and deletes the service. Leaves test signing
    as-is; disable it separately when finished:  bcdedit /set testsigning off
    (then reboot).

.PARAMETER ServiceName
    Filter/service name. Default "dlpflt".
#>
[CmdletBinding()]
param(
    [string]$ServiceName = "dlpflt"
)

$ErrorActionPreference = "Continue"

function Assert-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        throw "Run this script elevated (Administrator)."
    }
}

Assert-Admin

Write-Host "Unloading filter '$ServiceName'..."
& fltmc unload $ServiceName
if ($LASTEXITCODE -ne 0) {
    Write-Warning "fltmc unload returned $LASTEXITCODE (was it loaded? is a handle open?)."
} else {
    Write-Host "Unloaded."
}

Write-Host "Deleting service '$ServiceName'..."
& sc.exe delete $ServiceName | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Warning "sc delete returned $LASTEXITCODE (service may already be gone)."
} else {
    Write-Host "Service deleted."
}

Write-Host ""
Write-Host "Confirm removal:"
Write-Host "    fltmc filters      # 'dlpflt' should be absent"
Write-Host ""
Write-Host "When done testing, disable test signing and reboot:"
Write-Host "    bcdedit /set testsigning off"
