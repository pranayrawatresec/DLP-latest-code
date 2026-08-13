# USB IDM + EDM Kernel-Block — Prod Demo Runbook

**Prepared:** 2026-08-05. Server-side is provisioned and the full non-kernel chain is already
verified on the host with the real agent binary + real token (enroll → bundle v3 → IDM 1.0 → EDM
row 2). This runbook is the VM half: load the kernel driver and block a sensitive copy to USB.

## Provisioned state (ready now)
- **Bundle v3** — OPORD (IDM, 224 fingerprints) + "Demo Personnel" (EDM, 5 rows).
- **Enrollment token** — 3 uses / 72h (1 used in host verification; **2 left**). Get the live value
  from the operator (it is intentionally NOT written to any committed file). Re-mint anytime:
  `cd dlp-management-server && node scripts/provision-demo.js`.
- **Server** — host `desktop-k8e7f5d`; mTLS `:8443` (`npm run agent-server`), console `:3001`
  (`npm start`), worker (`npm run worker`), Postgres (docker). CA: `dlp-management-server/ca/ca-cert.pem`.
- **Server cert SANs:** `desktop-k8e7f5d`, `localhost` (NO IP SAN — see step 1).

## Test material
- IDM: `samples/OperationHimalayanShield_OPORD.pdf` (+ `samples/variants/*` for evasion).
- EDM: a text file containing `Name: Priya Nair, Service No: SVC100002 posted to Northern Command`.
- Innocent control: any unrelated file (a recipe, a readme).

---

## 0. Safety (read first)
- **Use a VM with a snapshot.** The driver is compile-verified only; a bug = BSOD. Snapshot before C.
- You will **disable driver-signature enforcement** (test-signing) on the VM — dev only; turn it back
  off after.
- The kernel `FailMode` default is **BLOCK** (fail-secure): if `usb-guard` isn't running/answering,
  removable writes are DENIED. That is intended — it means killing the user-mode guard cannot be used
  to exfiltrate; it locks the USB instead.

## 1. VM prerequisites
1. **Networking to the server host.** The VM must reach `desktop-k8e7f5d`. Because the server cert has
   no IP SAN, add a hosts entry on the VM (admin):
   ```
   # C:\Windows\System32\drivers\etc\hosts  (on the VM)
   <HOST-LAN-IP>   desktop-k8e7f5d
   ```
   Confirm: `Test-NetConnection desktop-k8e7f5d -Port 8443` → TcpTestSucceeded True.
   (Ensure the host firewall allows inbound 8443 + 3001 from the VM.)
   *Alternative:* run the whole server stack on the VM and use `https://localhost:8443`.
2. **Enable test-signing** (VM, admin), then reboot:
   ```
   bcdedit /set testsigning on
   shutdown /r /t 0
   ```
   After reboot the desktop shows a "Test Mode" watermark — good.
3. **Copy artifacts to the VM** (e.g. `C:\dlp\`):
   - `dlp-agent\target\release\dlp-agent.exe`
   - `dlp-minifilter\build\out\dlpflt.sys`
   - `dlp-minifilter\dlpflt.inf`, `dlp-minifilter\tools\*.ps1`
   - `dlp-management-server\ca\ca-cert.pem`
   - `samples\` (OPORD + variants)

## 2. Enroll the agent (VM) — the real enrollment token flow
```powershell
cd C:\dlp
$env:DLP_AGENT_SERVER_URL = "https://desktop-k8e7f5d:8443"
$env:DLP_AGENT_CA_CERT    = "C:\dlp\ca-cert.pem"
$env:DLP_AGENT_STATE_DIR  = "C:\dlp\state"
$env:DLP_AGENT_TOKEN      = "<ENROLLMENT-TOKEN-FROM-OPERATOR>"

.\dlp-agent.exe once           # enroll: keypair + CSR -> CA-signed cert, first check-in
.\dlp-agent.exe index-update   # downloads bundle v3, verifies CA signature, caches it
.\dlp-agent.exe status         # shows enrolled agent id + certificate
```
Expected: `enrolled — certificate stored`; `index bundle updated version=3`.

## 3. Load the kernel driver (VM, admin)
```powershell
cd C:\dlp   # where the tools + dlpflt.sys are
.\make-testcert.ps1     # create a test code-signing cert, trust it (root + publisher)
.\sign-driver.ps1       # sign dlpflt.sys with the test cert
.\install.ps1           # install via INF + load
fltmc filters           # EXPECT: dlpflt listed, altitude 265000
```
If `install.ps1` needs a stamped INF/.cat first, run stampinf/inf2cat per `dlp-minifilter/README.md`.

## 4. Start the user-mode guard (VM, admin) — the verdict answerer
```powershell
# same env vars as step 2 (server url, ca, state dir)
.\dlp-agent.exe usb-guard
```
Expected: `connected to \DlpFltPort — this PID is the driver's skip-self identity`;
`sent DLP_CONFIG watch-set to driver`. Leave it running in this window.

## 5. THE DEMO — copy to a USB stick (VM)
Plug a USB stick into the VM (or attach a USB passthrough / a VHD mounted removable).

| Action | Expected result |
|---|---|
| Copy `OperationHimalayanShield_OPORD.pdf` to the stick | **BLOCKED** — file is removed (quarantined); `usb-guard` logs a block; incident appears in the console (channel `usb-kguard`, IDM match, containment 1.0) |
| Copy a variant (`variants\4_truncated_60pct.txt`) | **BLOCKED** — partial copy still over threshold |
| Copy the EDM text file (`...SVC100002...`) | **BLOCKED** — EDM row hit (Demo Personnel row 2) |
| Copy an innocent unrelated file | **ALLOWED** — stays on the stick, no incident |
| **Kill `usb-guard`, then copy anything** | **BLOCKED** — kernel `FailMode` denies all removable writes (fail-secure); this proves user-mode cannot be switched off to exfiltrate |

> v1 model is detect-and-quarantine: the file may flash into existence then vanish (deleted on
> handle close). True never-lands prevention is the v2 buffer-and-hold model.

## 6. Show incidents in the console
On the host, log into the console (`http://desktop-k8e7f5d:3001`) as an `incident_reviewer` (or query
`/api/incidents`) → each block shows the document, version, containment/coverage, and — for IDM — the
matched seq ranges (the "which pages leaked" forensic view). EDM hits show the source + row + fields.

## 7. Teardown (VM)
```powershell
# stop usb-guard (Ctrl-C)
.\uninstall.ps1            # fltmc unload + remove
fltmc filters             # dlpflt gone
bcdedit /set testsigning off ; shutdown /r /t 0
```
Or just roll back the VM snapshot.

---

## Record results
For each row in step 5: PASS / FAIL / DEVIATION + notes. This is the FIRST real runtime test of the
driver — a clean compile is not a working driver. Bring back anything that BSODs, doesn't block, or
deadlocks, and we fix + rebuild. The honest limits still stand (screen-view analog hole,
kernel-privileged adversary, encrypted-to-allowed-destination).
