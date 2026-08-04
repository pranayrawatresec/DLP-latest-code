<#
.SYNOPSIS
    Registers the DLP Upload Guard native messaging host for Chrome and Edge.

.DESCRIPTION
    Chrome/Edge locate a native messaging host by reading a per-host registry
    value that points at the host's JSON manifest. This script:
      1. Writes a launcher .cmd next to dlp-agent.exe that runs
         `dlp-agent.exe browser-host` (Chrome cannot pass a subcommand argument
         through the manifest "path", so a wrapper is required).
      2. Materialises com.dlp.browser_host.json into the install dir with the
         correct absolute path and the real extension id.
      3. Registers the manifest under the NativeMessagingHosts registry key for
         both Chrome and Edge, at HKCU (per-user) or HKLM (all users).

    HONEST NOTE: this only wires up the native host + registry. It does NOT
    install the browser extension itself — that is force-installed via enterprise
    policy (see README.md). And it does not verify anything end-to-end; that
    needs a real browser (manual).

.PARAMETER AgentExe
    Full path to dlp-agent.exe. Default: C:\Program Files\DLP\dlp-agent.exe

.PARAMETER ExtensionId
    The extension's 32-char id (from chrome://extensions with Developer mode, or
    the fixed id derived from your packed .crt key). Required — the host will
    reject connections from any other origin.

.PARAMETER Scope
    'User' (HKCU, default) or 'Machine' (HKLM, needs elevation).

.EXAMPLE
    .\install-native-host.ps1 -ExtensionId abcdefghijklmnopabcdefghijklmnop
#>

[CmdletBinding()]
param(
    [string]$AgentExe = 'C:\Program Files\DLP\dlp-agent.exe',
    [Parameter(Mandatory = $true)][string]$ExtensionId,
    [ValidateSet('User', 'Machine')][string]$Scope = 'User'
)

$ErrorActionPreference = 'Stop'
$HostName = 'com.dlp.browser_host'

if ($ExtensionId -notmatch '^[a-p]{32}$') {
    Write-Warning "ExtensionId '$ExtensionId' does not look like a 32-char Chrome extension id (a-p). Continuing, but connections will fail if it is wrong."
}

$installDir = Split-Path -Parent $AgentExe
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
}

# 1) launcher wrapper: Chrome runs this; it invokes the browser-host subcommand.
$cmdPath = Join-Path $installDir 'dlp-browser-host.cmd'
$exeName = Split-Path -Leaf $AgentExe
$cmdBody = "@echo off`r`n`"%~dp0$exeName`" browser-host`r`n"
Set-Content -Path $cmdPath -Value $cmdBody -Encoding Ascii
Write-Host "Wrote launcher: $cmdPath"

# 2) materialise the host manifest with real path + extension id.
$manifest = [ordered]@{
    name            = $HostName
    description     = 'DLP Upload Guard native messaging host (dlp-agent browser-host).'
    path            = $cmdPath
    type            = 'stdio'
    allowed_origins = @("chrome-extension://$ExtensionId/")
}
$manifestPath = Join-Path $installDir "$HostName.json"
$manifest | ConvertTo-Json -Depth 5 | Set-Content -Path $manifestPath -Encoding utf8
Write-Host "Wrote host manifest: $manifestPath"

# 3) registry registration for Chrome + Edge.
$root = if ($Scope -eq 'Machine') { 'HKLM:' } else { 'HKCU:' }
$browserKeys = @(
    "$root\Software\Google\Chrome\NativeMessagingHosts\$HostName",
    "$root\Software\Microsoft\Edge\NativeMessagingHosts\$HostName"
)

foreach ($key in $browserKeys) {
    New-Item -Path $key -Force | Out-Null
    # The default (unnamed) value of the key must be the manifest path.
    Set-ItemProperty -Path $key -Name '(default)' -Value $manifestPath
    Write-Host "Registered: $key"
}

Write-Host ''
Write-Host 'Done. Native host registered for Chrome and Edge.' -ForegroundColor Green
Write-Host 'Reminder: the extension itself is force-installed via enterprise policy (see README.md).'
Write-Host 'This script performs no browser end-to-end test — verify manually in a real browser.'
