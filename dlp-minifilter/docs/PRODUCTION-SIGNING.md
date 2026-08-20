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

1. Build the release driver: `build\build-driver.bat` → `build\out\dlpflt.sys`.
2. Create the CAB containing `dlpflt.sys` + `dlpflt.inf` (and a generated
   `dlpflt.cat` placeholder) per the Partner Center attestation layout.
3. **EV-sign the CAB** with the code-signing cert
   (`signtool sign /fd sha256 /a /n "<Company>" /tr <RFC3161-TSA> /td sha256 dlpflt.cab`).
   Modern alternative: **Azure Trusted Signing** (`Trusted Signing` account +
   `signtool` with the dlib), which avoids holding an HSM token.
4. Upload the signed CAB to Partner Center → **Hardware → Submit new driver**,
   target the Windows versions you support, choose **attestation**.
5. Download the **Microsoft-signed** package. The returned `dlpflt.cat` is the
   Microsoft-signed catalog; ship it alongside the (unchanged) `dlpflt.sys` and
   `dlpflt.inf`.
6. **Verify** on a clean, test-signing-OFF machine:
   `signtool verify /v /kp /c dlpflt.cat dlpflt.sys` should show the Microsoft
   signature, and `fltmc load dlpflt` should succeed **without** `bcdedit`.

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

External (cert purchase + Partner Center). The test-signing pipeline
(`make-testcert.ps1` / `sign-driver.ps1`) stays for lab/VM use; this runbook is
the production path. Nothing in the codebase blocks it — it is a release/ops
action, gated on the EV cert and Partner Center enrolment.
