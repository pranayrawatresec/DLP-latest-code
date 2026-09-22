# Stages the V6.2.01 document-classifier artifacts onto an endpoint (or a test VM)
# and PROVES the copy landed intact.
#
# WHY THIS SCRIPT EXISTS AT ALL: model.onnx is 268,023,580 bytes. A 256 MB copy
# over a VM shared folder, an RDP drive redirect, a USB stick or a flaky SMB share
# is the one file in this product that plausibly arrives TRUNCATED. A truncated
# ONNX graph does not fail cleanly -- ONNX Runtime may still open it, the session
# may still build, and the agent then classifies with half a model and reports
# labels that are quietly wrong. Wrong labels in a DLP product mean a NUC document
# reported as ADM and allowed out. So every artifact is SHA-256 verified against
# the values recorded in Document_classification/README.md section 2 and
# deployment_manifest.json, the bad copy is DELETED, and the script exits non-zero.
# "Staged but unverified" is not an outcome this script offers.
#
#   powershell -ExecutionPolicy Bypass -File scripts\stage-ml-model.ps1 `
#       -InstallRoot 'C:\dlp' -WhatIf                # dry run: says what it would do
#   powershell -ExecutionPolicy Bypass -File scripts\stage-ml-model.ps1 `
#       -InstallRoot 'C:\dlp' -RuntimeDll 'C:\stage\onnxruntime.dll'
#
# WHAT LANDS WHERE (the layout src/ml/engine.rs documents, MlConfig::under):
#
#     <InstallRoot>\model\model.onnx          the graph            268,023,580 B
#     <InstallRoot>\model\model.onnx.json     labels + geometry          1,985 B
#     <InstallRoot>\model\tokenizer.json      WordPiece vocabulary     466,062 B
#     <InstallRoot>\runtime\onnxruntime.dll   ONNX Runtime (optional)  ~18,000 KB
#
# The sidecar is NOT optional even though the task brief lists two files: the
# agent derives its path from the model path (model.onnx -> model.onnx.json) and
# reads the label space, chunk geometry, max_chars and model version FROM IT, so
# the graph and its labels can never drift apart. A staged model without its
# sidecar loads nothing.
#
# The tokenizer is RENAMED on the way in (backbone\tokenizer.json ->
# model\tokenizer.json). That is deliberate: the agent's [ml] defaults look for it
# beside the weights, so an endpoint carries one model directory rather than the
# repository's two.
#
# ONNX Runtime is OPTIONAL here and only here. dlp-agent links no ONNX Runtime at
# build time (`ort` with default-features = false, "load-dynamic") -- it dlopen()s
# the library at first use, resolving <ml root>\runtime\onnxruntime.dll, then
# $ORT_DYLIB_PATH, then the OS loader path. Pass -RuntimeDll to co-locate it (the
# air-gapped answer: one file, signed and inventoried with the rest of the
# payload). Omit it on a dev box that already has ORT_DYLIB_PATH set.
#
# PowerShell 5.1 compatible on purpose -- this runs on a bare Windows endpoint
# with nothing installed. No ternary, no ??, no && / ||.

[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # The Document_classification package. Defaults to the copy in this repo.
    [string] $SourceRoot,

    # Where the agent is installed. The MSI default is C:\Program Files\DLPAgent;
    # the test VMs in the runbooks use C:\dlp.
    [string] $InstallRoot = 'C:\Program Files\DLPAgent',

    # ONNX Runtime shared library to co-locate. Optional -- see the header.
    [string] $RuntimeDll,

    # Re-copy and re-verify even when the destination already hashes correctly.
    [switch] $Force
)

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# The expected artifacts.
#
# These SHA-256 values are the ones published in Document_classification/README.md
# section 2 and repeated in deployment_manifest.json. They are baked in HERE, in
# the script, on purpose: a manifest that travelled with a tampered model would
# happily agree with it. The manifest is still cross-checked below (section 1) so
# a divergence is reported rather than assumed away -- but the constants in this
# file are the authority.
# ---------------------------------------------------------------------------
$artifacts = @(
    [pscustomobject]@{
        Name   = 'ONNX graph'
        From   = 'model\model.onnx'
        To     = 'model\model.onnx'
        Sha256 = '6bb36568c1e782569c3c64a8f0dd41c8e463c76d64917e6dbf8b7ed5339e29ef'
        Size   = 268023580
        Key    = 'onnx_sha256'
    },
    [pscustomobject]@{
        Name   = 'label space + chunk geometry (sidecar)'
        From   = 'model\model.onnx.json'
        To     = 'model\model.onnx.json'
        Sha256 = '4c37bfa10feec6a1ccd0878e95b4fe2a1b04f8c6bfe29818a8ab061d0dfcd4a2'
        Size   = 1985
        Key    = $null
    },
    [pscustomobject]@{
        Name   = 'WordPiece tokenizer'
        From   = 'backbone\tokenizer.json'
        To     = 'model\tokenizer.json'
        Sha256 = 'ce64fce797c24f68df90b40a3f74f579b336a493db14bd583fd520ea0d8c9a98'
        Size   = 466062
        Key    = $null
    }
)

$modelVersion = 'V6.2.01'

function Write-Step($text) {
    Write-Host ""
    Write-Host $text -ForegroundColor Cyan
}

function Fail($text) {
    Write-Host ""
    Write-Host "FAILED: $text" -ForegroundColor Red
    exit 1
}

# Hash a file the way the README does. Returned lower-case so string compares are
# not a case trap.
function Get-Sha256($path) {
    return (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLowerInvariant()
}

# ---------------------------------------------------------------------------
# 0. Resolve the source package
# ---------------------------------------------------------------------------
if (-not $SourceRoot) {
    $repoRoot   = Split-Path $PSScriptRoot -Parent
    $SourceRoot = Join-Path $repoRoot 'Document_classification'
}
if (-not (Test-Path -LiteralPath $SourceRoot)) {
    Fail "source package not found at '$SourceRoot'. Pass -SourceRoot <path to Document_classification>."
}
$SourceRoot = (Resolve-Path -LiteralPath $SourceRoot).Path

Write-Host "Staging the $modelVersion document classifier" -ForegroundColor Green
Write-Host "  source:  $SourceRoot"
Write-Host "  install: $InstallRoot"
if ($WhatIfPreference) {
    Write-Host "  MODE:    -WhatIf -- nothing will be written" -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 1. Cross-check the manifest against the constants above
#
# Advisory, not fatal on its own: if the manifest disagrees with this script, one
# of the two has moved and a human has to decide which. Staging continues against
# the script's constants (which is what the per-file verification then enforces),
# so a stale manifest cannot let a wrong model through.
# ---------------------------------------------------------------------------
$manifestPath = Join-Path $SourceRoot 'deployment_manifest.json'
if (Test-Path -LiteralPath $manifestPath) {
    $manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
    if ($manifest.model_version -ne $modelVersion) {
        Write-Host "  WARNING: manifest model_version is '$($manifest.model_version)', this script stages '$modelVersion'." -ForegroundColor Yellow
    }
    foreach ($a in $artifacts) {
        if ($a.Key) {
            $declared = $manifest.$($a.Key)
            if ($declared -and ($declared.ToLowerInvariant() -ne $a.Sha256)) {
                Write-Host "  WARNING: manifest $($a.Key) = $declared" -ForegroundColor Yellow
                Write-Host "           this script expects  $($a.Sha256)" -ForegroundColor Yellow
                Write-Host "           Someone re-exported the model. Do not stage until this is resolved." -ForegroundColor Yellow
            }
        }
    }
} else {
    Write-Host "  NOTE: no deployment_manifest.json beside the package -- verifying against the built-in hashes only." -ForegroundColor Yellow
}

# ---------------------------------------------------------------------------
# 2. Verify the SOURCE before copying anything
#
# Order matters. Hashing the source first means a bad source is reported as a bad
# source, not as a bad copy -- and 256 MB is not written to the endpoint at all.
# ---------------------------------------------------------------------------
Write-Step "1/3  Verifying the source package"
foreach ($a in $artifacts) {
    $src = Join-Path $SourceRoot $a.From
    if (-not (Test-Path -LiteralPath $src)) {
        Fail "missing from the source package: $src`n        The package must contain model\model.onnx, model\model.onnx.json and backbone\tokenizer.json."
    }
    $len = (Get-Item -LiteralPath $src).Length
    if ($len -ne $a.Size) {
        Fail "$($a.From) is $len bytes, expected $($a.Size). The source package is itself truncated or modified -- re-obtain it; do not stage it."
    }
    $hash = Get-Sha256 $src
    if ($hash -ne $a.Sha256) {
        Fail "$($a.From) SHA-256 mismatch in the SOURCE package.`n        expected $($a.Sha256)`n        actual   $hash`n        This is not a copy problem. The package is wrong -- re-obtain it."
    }
    Write-Host ("  OK  {0,-38} {1,13} bytes  {2}" -f $a.From, $len, $hash.Substring(0, 16) + "...")
}

# ---------------------------------------------------------------------------
# 3. Copy, then verify what actually landed
# ---------------------------------------------------------------------------
Write-Step "2/3  Staging into $InstallRoot"

$modelDir = Join-Path $InstallRoot 'model'
if ($PSCmdlet.ShouldProcess($modelDir, 'create directory')) {
    New-Item -ItemType Directory -Force -Path $modelDir | Out-Null
}

$staged  = 0
$skipped = 0
foreach ($a in $artifacts) {
    $src = Join-Path $SourceRoot  $a.From
    $dst = Join-Path $InstallRoot $a.To

    # Idempotent: a correct file already in place is left alone. Re-copying 256 MB
    # on every rollout run is a needless window in which the file is half-written.
    if ((-not $Force) -and (Test-Path -LiteralPath $dst)) {
        $existing = Get-Sha256 $dst
        if ($existing -eq $a.Sha256) {
            Write-Host ("  --  {0,-38} already staged and verified" -f $a.To)
            $skipped = $skipped + 1
            continue
        }
        Write-Host ("  !!  {0,-38} present but WRONG -- replacing" -f $a.To) -ForegroundColor Yellow
    }

    if (-not $PSCmdlet.ShouldProcess($dst, "copy $($a.From) ($($a.Size) bytes) and verify SHA-256")) {
        continue
    }

    Copy-Item -LiteralPath $src -Destination $dst -Force

    # THE POINT OF THE SCRIPT. Hash what landed, not what we sent.
    $landedLen  = (Get-Item -LiteralPath $dst).Length
    $landedHash = Get-Sha256 $dst
    if (($landedLen -ne $a.Size) -or ($landedHash -ne $a.Sha256)) {
        # Delete it. A half-copied model that stays on disk is worse than no model:
        # no model reports status "unavailable" and the channels honour failBlock,
        # while a corrupt one may load and label documents wrongly in silence.
        Remove-Item -LiteralPath $dst -Force -ErrorAction SilentlyContinue
        Fail ("the copy of $($a.To) did not survive the transfer -- REMOVED.`n" +
              "        expected $($a.Size) bytes / $($a.Sha256)`n" +
              "        actual   $landedLen bytes / $landedHash`n" +
              "        Copy again over a reliable path (avoid VM shared folders and RDP drive`n" +
              "        redirection for the 256 MB graph; a robocopy /Z or a local disk beats both).")
    }
    Write-Host ("  OK  {0,-38} {1,13} bytes  verified" -f $a.To, $landedLen) -ForegroundColor Green
    $staged = $staged + 1
}

# ---------------------------------------------------------------------------
# 4. ONNX Runtime (optional)
#
# No hash is pinned for this one and that is deliberate: api-17 pins the ONNX
# Runtime API surface, not a build, so a site may (and should) update the DLL for
# a CVE without a change here. What the script does instead is report the hash and
# version it staged, so the rollout record says which binary is on the endpoint.
# ---------------------------------------------------------------------------
Write-Step "3/3  ONNX Runtime"
if ($RuntimeDll) {
    if (-not (Test-Path -LiteralPath $RuntimeDll)) {
        Fail "-RuntimeDll '$RuntimeDll' does not exist."
    }
    $runtimeDir = Join-Path $InstallRoot 'runtime'
    $runtimeDst = Join-Path $runtimeDir 'onnxruntime.dll'
    if ($PSCmdlet.ShouldProcess($runtimeDst, 'copy ONNX Runtime and verify')) {
        New-Item -ItemType Directory -Force -Path $runtimeDir | Out-Null
        Copy-Item -LiteralPath $RuntimeDll -Destination $runtimeDst -Force

        $srcHash = Get-Sha256 $RuntimeDll
        $dstHash = Get-Sha256 $runtimeDst
        if ($srcHash -ne $dstHash) {
            Remove-Item -LiteralPath $runtimeDst -Force -ErrorAction SilentlyContinue
            Fail "the ONNX Runtime copy did not match its source -- REMOVED. Copy again."
        }
        $ver = (Get-Item -LiteralPath $runtimeDst).VersionInfo.FileVersion
        Write-Host ("  OK  runtime\onnxruntime.dll  {0,13} bytes  version {1}" -f (Get-Item -LiteralPath $runtimeDst).Length, $ver) -ForegroundColor Green
        Write-Host "      SHA-256 $dstHash  (record this in the rollout log)"
    }
} else {
    Write-Host "  skipped -- no -RuntimeDll given." -ForegroundColor Yellow
    Write-Host "  The agent will resolve ONNX Runtime from, in order:"
    Write-Host "     1. $InstallRoot\runtime\onnxruntime.dll   (the shipped location; pass -RuntimeDll to put it there)"
    Write-Host "     2. `$env:ORT_DYLIB_PATH"
    Write-Host "     3. onnxruntime.dll next to dlp-agent.exe, then the OS loader path"
    Write-Host "  With none of those present the model cannot load: the ML signal reports"
    Write-Host "  status 'unavailable' (never a crash) and egress channels honour failBlock."
}

# ---------------------------------------------------------------------------
# 5. What to do next
# ---------------------------------------------------------------------------
Write-Host ""
if ($WhatIfPreference) {
    Write-Host "Dry run complete -- nothing was written." -ForegroundColor Yellow
    exit 0
}

Write-Host "Staged $staged artifact(s), $skipped already correct. All SHA-256 verified." -ForegroundColor Green
Write-Host ""
Write-Host "Point the agent at them -- in $InstallRoot\agent.toml (or C:\ProgramData\DLPAgent\agent.toml):"
Write-Host ""
Write-Host "    [ml]"
Write-Host "    enabled        = true"
Write-Host ("    model_path     = `"{0}`"" -f (Join-Path $InstallRoot 'model\model.onnx').Replace('\', '\\'))
Write-Host ("    tokenizer_path = `"{0}`"" -f (Join-Path $InstallRoot 'model\tokenizer.json').Replace('\', '\\'))
Write-Host "    intra_threads  = 1"
Write-Host ""
Write-Host "Then prove the model runs on this box before arguing about thresholds:"
Write-Host ""
Write-Host "    dlp-agent.exe classify --text `"The quarterly budget variance and expenditure forecast`""
Write-Host ""
Write-Host "EXPECT: 'model: $modelVersion' and a label line. See ML-CLASSIFICATION-RUNBOOK.md."
