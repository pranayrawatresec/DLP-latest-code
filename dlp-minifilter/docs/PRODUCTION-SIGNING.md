# Production driver signing

The minifilter (`dlpflt.sys`) is currently **test-signed** — a self-signed cert
from `tools/make-testcert.ps1`, applied by `tools/sign-driver.ps1`, and it only
loads on a machine with `bcdedit /set testsigning on` (+ reboot). That is fine
for the VM/lab and is what the audit's VM verifications use. **It must not ship.**
A production endpoint has Secure Boot / test-signing OFF and will refuse a
test-signed kernel driver.

This is an **external procurement + portal** task (a purchased certificate and
Microsoft's signing service) — it cannot be done from this repo. This runbook is
the checklist for whoever owns the release.

## Why kernel drivers are special

Since Windows 10 1607, a kernel-mode driver that loads on a clean retail machine
must be **signed by Microsoft** (the cross-signing-only era is over). An EV code-
signing certificate alone is **not** enough to *load* a driver — it is the key
that lets you *submit* the driver to Microsoft for signing. Two routes:

| Route | What you get | When |
|---|---|---|
| **Attestation signing** (Partner Center) | Microsoft signs your `.sys`/`.cat` for Windows 10/11 (no hardware lab). | Software-only filesystem minifilter like ours — **this is our route.** |
| **WHQL / HLK certification** | Full compatibility logo + broader OS coverage. | Only if a customer contract requires the logo. |

## One-time setup

1. **Obtain an EV (or OV, for Azure Trusted Signing) code-signing certificate**
   from a CA (DigiCert, Sectigo, …). EV keys live on an approved HSM/token or in
   Azure Key Vault. Budget lead time — EV vetting takes days to weeks.
2. **Enrol in the Microsoft Partner Center "Windows Hardware" program** and
   validate the company with the EV cert (a one-time code-signed blob).
3. **Request a Microsoft-assigned filter Altitude** via the sysdev "Allocated
   Filter Altitudes" process, and replace the dev placeholder `265000` in
   `dlpflt.inf` (`[Strings] Altitude`) with the assigned value. (Tracked as its
   own productionization item.)

## Per-release signing (attestation)

Steps 1–2 are automated by **`tools\make-submission.ps1`**, which enforces the
load-bearing order (build → embed-sign → stampinf → Inf2Cat → makecab) and
refuses to finish if the catalog is missing from the CAB.

1. Build the release driver: `build\build-driver.bat` → `build\out\dlpflt.sys`.
2. `powershell -File tools\make-submission.ps1 -Version <x.y.z.w> -EmbedSign`
   → `build\submission\dlpflt.cab`. `-EmbedSign` adds the EV signature to
   `dlpflt.sys` itself (prompts for the token PIN once); omit it for throwaway
   trial submissions.
3. **EV-sign the CAB** with the code-signing cert. The script prints the exact
   command. Type the PIN by hand — never script it (the eToken locks
   permanently after repeated wrong PINs) and never put it on a command line.
4. Upload the signed CAB to Partner Center → **Hardware → Submit new hardware**.
   Uploading a CAB (rather than an HLKX) routes it to attestation automatically.
   The page prints *"Leave all checkboxes blank for Attestation Signing"* but
   then **requires at least one OS on upload** — select the **x64 client entries
   from 1607 onward** only. Not ARM64 (no binary), not x86, not 1506/1511 (TH2),
   and leave "Perform test-signing" unchecked.
5. Download the **Microsoft-signed** package. Microsoft signs **both** the
   catalog and the binary: `dlpflt.cat` is replaced, and `dlpflt.sys` comes back
   **larger** with an embedded signature (measured 2026-09-23: 39,424 → 49,888
   bytes). Only `dlpflt.inf` returns byte-identical — that is the one to
   hash-check against what you submitted.
6. **Verify** on a clean, test-signing-OFF machine:
   `signtool verify /v /kp dlpflt.sys` and
   `signtool verify /v /kp /c dlpflt.cat dlpflt.sys` must both name
   *Microsoft Windows Hardware Compatibility Publisher*, and `fltmc load dlpflt`
   must succeed **without** `bcdedit`.
7. Record the submission in `build\submissions\dlpflt-<version>.txt` (cert used,
   file hashes submitted and returned, deviations from production).

## Packaging hand-off

`packaging\build-package.ps1` picks up `dlp-minifilter\build\out\dlpflt.sys`
(+ `.cat`) into the endpoint package; `install-endpoint.ps1` installs it via the
INF. For production, drop the **Microsoft-signed** `.sys` + `.cat` into
`build\out\` before running `build-package.ps1`, and remove the test-signing
reminder from the operator docs (a production-signed driver needs no test-signing
and no reboot-to-enable).

## Do NOT

- Ship the self-signed test cert or its `.cer` files to customers.
- Rely on `bcdedit /set testsigning on` in production (it weakens the boot trust
  chain and many secured/defence endpoints forbid it via policy).
- Re-sign a Microsoft-signed `.sys` — the Microsoft catalog covers it; re-signing
  the binary invalidates the attestation.

## Status

**Proven end to end, 2026-09-23.** A GlobalSign EV certificate
(`CN=RESEC SYSTEMS PRIVATE LIMITED`, SafeNet eToken) is in hand, Partner Center
is enrolled, and submission `dlpflt 1.0.0.1` came back Microsoft-signed and was
verified loading on the test VM with **test signing off** — driver attached,
agent connected to `\DlpFltPort`, `kguard scan decide` and incident reporting
live. Round trip is ~20 minutes. See `driver-ev-signing-guide.html` at the repo
root for the full walkthrough and `build\submissions\` for per-release records.

The test-signing pipeline (`make-testcert.ps1` / `sign-driver.ps1`) stays for
lab/VM use.

### Still open before shipping to a customer

- **Microsoft-assigned altitude.** `[Strings] Altitude` is still the dev
  placeholder `265000`. Request via `fsfcomm@microsoft.com`; this is the last
  blocker and has days of lead time.
- **Windows Server.** Attestation covers Windows 10 1607+ / Windows 11 **client**
  only. Any Server deployment needs full WHQL/HLK — a much larger project.
  Confirm against customer contracts.
- **Embedded-signature survival.** Unknown whether Microsoft preserves a
  pre-existing EV signature on `dlpflt.sys` as a secondary signature or replaces
  it. Check `signtool verify /all /pa` on the next `-EmbedSign` submission.
- **HVCI / Memory Integrity** compatibility is untested.
