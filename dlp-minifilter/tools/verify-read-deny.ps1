<#
.SYNOPSIS
    Automated read-deny / open-deny acceptance probes (matrix rows T1-T3, T5, T6).
    Run ON THE VM with the agent running and read-deny = enforce. Prints PASS/FAIL
    per row and exits non-zero if any row fails. Replaces hand-poking the VM.

.DESCRIPTION
    Uses two untrusted test tools that must already be staged in -PublicDir:
      * openprobe.exe  (built from tools\openprobe.rs) -- opens WITHOUT reading,
        isolating open-deny (FltCancelFileOpen) from read-deny.
      * reader2.exe    -- a copy of cmd.exe (untrusted by path) used to copy/read.
    Both are flagged untrusted by the agent because they run from a non-allowlisted
    directory; each probe waits out the agent's ~2 s PID-push window.

    This script only READS a sensitive file and WRITES to throwaway paths under
    -PublicDir; it changes no policy and loads no driver. Snapshot not required.

.PARAMETER SensitiveFile
    A file the current bundle classifies sensitive (e.g. OPORD.pdf).

.PARAMETER CleanFile
    A non-sensitive file. Defaults to a generated plain-text file.

.PARAMETER PublicDir
    Where the probes live and scratch files go. Default C:\Users\Public.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$SensitiveFile,
    [string]$CleanFile = '',
    [string]$PublicDir = 'C:\Users\Public'
)

$ErrorActionPreference = 'Stop'
# openprobe.exe (UNSIGNED, so untrusted regardless of path) is the only reader we
# use. A cmd.exe copy like reader2.exe is catalog-signed by "Microsoft Windows"
# and the starter allowlist trusts that publisher, so it is (correctly) NOT
# untrusted anymore -- it cannot test untrusted-read blocking.
$openprobe = Join-Path $PublicDir 'openprobe.exe'
if (-not (Test-Path $openprobe)) { Write-Host "MISSING probe: $openprobe (build tools\openprobe.rs and stage it)" -ForegroundColor Red; exit 2 }
if (-not (Test-Path $SensitiveFile)) { Write-Host "MISSING sensitive file: $SensitiveFile" -ForegroundColor Red; exit 2 }
if ([string]::IsNullOrEmpty($CleanFile)) {
    $CleanFile = Join-Path $PublicDir 'vrd_clean.txt'
    'plain non-sensitive text' | Set-Content -Path $CleanFile -Encoding ascii
}

$results = @()
function Row($id, $desc, $pass, $detail) {
    $script:results += [pscustomobject]@{ Id = $id; Desc = $desc; Pass = $pass; Detail = $detail }
    $tag = if ($pass) { 'PASS' } else { 'FAIL' }
    $col = if ($pass) { 'Green' } else { 'Red' }
    Write-Host ("  {0}  {1}  {2} -- {3}" -f $tag, $id, $desc, $detail) -ForegroundColor $col
}
function Probe-Open($mode, $path) {
    $out = Join-Path $PublicDir ("_vrd_{0}.txt" -f ([guid]::NewGuid().ToString('N').Substring(0,8)))
    Start-Process -FilePath $openprobe -ArgumentList $mode, $path -NoNewWindow -Wait -RedirectStandardOutput $out
    $r = (Get-Content $out -Raw).Trim(); Remove-Item $out -Force -ErrorAction SilentlyContinue; return $r
}
Write-Host "== read-deny acceptance probes ==" -ForegroundColor Cyan

# Fresh, uncached copy of the sensitive file (trusted cmd copy -> not classified yet)
$fresh = Join-Path $PublicDir 'vrd_sens_fresh.pdf'
cmd /c copy /Y "`"$SensitiveFile`"" "`"$fresh`"" | Out-Null

# T2 open-deny fresh (do this BEFORE T1 so it's the first untrusted touch)
$t2 = Probe-Open 'open' $fresh
Row 'T2' 'open-deny fresh'  ($t2 -match 'OPEN-DENIED') $t2

# T3 open-deny cached (2nd + 3rd open of the now-classified file)
$t3a = Probe-Open 'open' $fresh
$t3b = Probe-Open 'open' $fresh
Row 'T3' 'open-deny cached' (($t3a -match 'OPEN-DENIED') -and ($t3b -match 'OPEN-DENIED')) "$t3a / $t3b"

# T5 empty/new overwrite must NOT be cancelled (no data loss, #4)
$t5a = Probe-Open 'overwrite'    (Join-Path $PublicDir 'vrd_ow1.dat')
$t5b = Probe-Open 'overwrite-rw' (Join-Path $PublicDir 'vrd_ow2.dat')
Row 'T5' 'empty/new overwrite OK' (($t5a -match 'OPEN-OK') -and ($t5b -match 'OPEN-OK')) "$t5a / $t5b"

# T1 direct read of sensitive by untrusted -> blocked (open-deny cancels the
# read-capable open in enforce mode, so the bytes never leave)
$t1 = Probe-Open 'read' $fresh
Row 'T1' 'direct read sensitive blocked' ($t1 -match 'READ-DENIED') $t1

# T6 clean read by untrusted -> allowed
$t6 = Probe-Open 'read' $CleanFile
Row 'T6' 'clean read allowed' ($t6 -match 'READ-OK') $t6

Remove-Item $fresh -Force -ErrorAction SilentlyContinue

$fail   = ($results | Where-Object { -not $_.Pass }).Count
$passed = ($results | Where-Object { $_.Pass }).Count
$summaryColor = 'Green'; if ($fail -gt 0) { $summaryColor = 'Red' }
Write-Host ("`n{0} passed, {1} failed, {2} total" -f $passed, $fail, $results.Count) -ForegroundColor $summaryColor
if ($fail -gt 0) { exit 1 } else { exit 0 }
