<#
.SYNOPSIS
    Create a self-signed TEST code-signing certificate for dlpflt.sys and trust
    it (Trusted Root + Trusted Publisher) on THIS test machine only.

.DESCRIPTION
    Development / test-signing only (SPEC section 8). The resulting cert is NOT
    valid for production: production drivers are signed through the Windows
    Hardware Dev Center attestation/EV process, not a self-signed cert.

    Run elevated (Administrator). After running you must also enable test signing
    and reboot:  bcdedit /set testsigning on   (see install.ps1).

.PARAMETER Subject
    Certificate subject CN. Default "DLP Minifilter Test".

.PARAMETER PfxPath
    Where to export the PFX (with private key) used by sign-driver.ps1.

.PARAMETER Password
    PFX export password (a SecureString). Prompted if omitted.
#>
[CmdletBinding()]
param(
    [string]$Subject = "DLP Minifilter Test",
    [string]$PfxPath = "$PSScriptRoot\dlpflt-test.pfx",
    [System.Security.SecureString]$Password
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

if (-not $Password) {
    $Password = Read-Host -AsSecureString "PFX export password"
}

Write-Host "Creating test code-signing certificate '$Subject'..."
# Code-signing EKU (1.3.6.1.5.5.7.3.3); machine store so it can sign a driver.
$cert = New-SelfSignedCertificate `
    -Subject "CN=$Subject" `
    -Type CodeSigningCert `
    -KeyUsage DigitalSignature `
    -KeyExportPolicy Exportable `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -NotAfter (Get-Date).AddYears(3) `
    -HashAlgorithm SHA256

Write-Host "  Thumbprint: $($cert.Thumbprint)"

# Trust it on THIS machine: Root (so the chain validates) + TrustedPublisher
# (so the driver package installs without a prompt under test signing).
$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root","LocalMachine")
$rootStore.Open("ReadWrite"); $rootStore.Add($cert); $rootStore.Close()

$pubStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher","LocalMachine")
$pubStore.Open("ReadWrite"); $pubStore.Add($cert); $pubStore.Close()

Export-PfxCertificate -Cert $cert -FilePath $PfxPath -Password $Password | Out-Null
Write-Host "Exported PFX -> $PfxPath"
Write-Host ""
Write-Host "Next:"
Write-Host "  1. tools\sign-driver.ps1 -PfxPath '$PfxPath'"
Write-Host "  2. bcdedit /set testsigning on   (then REBOOT this test machine)"
Write-Host "  3. tools\install.ps1"
