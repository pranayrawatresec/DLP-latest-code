# Encrypt-on-Write — Production-Grade Deployment & Usage Runbook

> **Prepared 2026-08-13.** The real steps an **admin** and an **end user** follow.
> Reflects the unified `DLPAgent` Windows service + server-driven whitelist (M6).
> Supersedes `ENCRYPT-DEMO-RUNBOOK.md` (that one is the pre-service, local-keyfile
> path). Engineering detail: `ENCRYPT-ON-WRITE-AS-BUILT.md`.
>
> **Status caveat:** this is the FIRST real run of the unified service on the VM.
> Each step lists what to expect and what to check if it doesn't. Record PASS/FAIL.

---

## Roles

- **Admin / IT** (sysadmin + policy_author): runs the server, provisions the endpoint once, creates the key, whitelists devices in the console.
- **End user**: just uses the PC. Plugs in a stick, copies files. Sees encryption / a block toast.

---

## PART A — Server side (customer premises). Admin, once.

The management server is already provisioned on the host. For a clean prod-grade run, confirm:

1. **Postgres up**, migrations 006 + 007 applied.
   `docker ps` shows `dlp-server-postgres` healthy.
2. **mTLS agent server** on `:8443` (`npm run agent-server`), **console** on `:3001` (`npm start`), **frontend** (Vite / the console).
3. **`DLP_ORG_ROOT_KEY`** set in `dlp-management-server/.env` (64 hex chars). Without it, key creation and key delivery return `503` (fail-secure).
   Check: `Select-String -Path .env -Pattern '^DLP_ORG_ROOT_KEY='` returns a line.
4. **A sysadmin account** exists (created once via `npm run bootstrap-admin`).
5. **An enrollment token** for the endpoint. Mint one in the console (Enrollment tokens → Create) or `node scripts/provision-demo.js`. Copy the `dlpenr_...` value.

> Expected: all four services reachable; a valid `dlpenr_...` token in hand.
> If it fails: `docker compose up -d`; restart the node processes; re-check `.env`.

---

## PART B — Provision the endpoint. Admin, once per PC.

On the **endpoint** (the VM), as **Administrator**.

**B0. One-time prereq that needs a reboot:** test-signing must be ON (the driver is test-signed for this phase). If the desktop has no "Test Mode" watermark:
```powershell
bcdedit /set testsigning on
shutdown /r /t 0
```

**B1.** Copy the payload folder `demo-vm\vm-payload\` from the host to the VM as `C:\dlp` (contains the current `dlp-agent.exe`, `dlpflt.sys`, `dlpflt.inf`, `dlpflt-signer.cer`, `ca-cert.pem`, `provision-vm.ps1`, `samples\`).

**B2.** Run the provisioner (use the token from A5 and the host's LAN IP):
```powershell
cd C:\dlp
powershell -ExecutionPolicy Bypass -File .\provision-vm.ps1 -Token "dlpenr_..." -ServerIp 192.168.1.3
```
This: adds the `desktop-k8e7f5d` hosts entry, installs agent files + `agent.toml` + toast AUMID into `C:\ProgramData\DLPAgent`, trusts the driver cert, installs the minifilter with **FailMode=1** (fail-secure) + boot-start, enrolls the agent (consumes one token use), then **installs and starts the `DLPAgent` Windows service** (guard + sealer + check-in + whitelist re-sync in one LocalSystem process).

> Expected final line: `PROVISIONED OK - DLPAgent service Running`.
> Check:
> - `sc query DLPAgent` → `STATE : 4 RUNNING`
> - `fltmc filters | findstr dlpflt` → listed at altitude 265000
> - `Get-Content C:\ProgramData\DLPAgent\logs\dlp-agent.log -Tail 20` → shows `synced trusted config from server destinations=0 keys=0` (0 is correct — nothing whitelisted yet) and the guard connected to `\DlpFltPort`.
> If it fails: read the log; `install-service failed` usually means the enroll step failed (token expired / server unreachable — test `Test-NetConnection desktop-k8e7f5d -Port 8443`). `fltmc load failed` means test-signing isn't really on after reboot.

---

## PART C — Create the key + whitelist the device. Admin, in the console.

**C1. Encryption key.** One org key covers every stick (keys are org-wide, not per-device). If `class-internal/v1` already exists (active), reuse it — skip to C2. To create one (there is **no key-creation UI yet** — known gap; use a sysadmin API call):
```
POST /api/encryption/keys    body: { "classification": "internal" }
```
(Run it with a sysadmin session cookie — e.g. from the browser devtools console on the logged-in console, or `Invoke-RestMethod` with the session cookie.)

**C2. Find the stick's serial as the endpoint sees it.** Plug the stick into the VM; the running service logs the arrival:
```powershell
Get-Content C:\ProgramData\DLPAgent\logs\dlp-agent.log -Tail 30 | Select-String "removable device arrived"
```
Copy the `serial=XXXX` value (USB passthrough can differ from the host — always use what the endpoint logs).

**C3. Whitelist it in the console UI.** Log in as `policy_author` → **Trusted USB devices** → **Add device**:
- **Matcher:** Serial → the value from C2
- **Mode:** Encrypt sensitive
- **When highly sensitive (block-band):** choose per policy —
  - **"Encrypt it onto this device"** = even top-secret files are sealed (not blocked)
  - **"Block it"** (default) = top-band files are blocked; only mid-band files seal
- **Key:** `class-internal/v1`
- Save. The row should show your block-band choice.

> Expected: within one check-in interval (≤ 5 min) the endpoint log shows `synced trusted config from server destinations=1 keys=1`. No restart needed — the service re-syncs live.
> Speed it up: `sc stop DLPAgent; sc start DLPAgent` forces an immediate sync.
> If `destinations=0` persists: the serial in the UI doesn't match what the endpoint logs, or the VM can't reach `:8443`.

---

## PART D — End user uses the PC. (This is the actual product experience.)

No commands — the user just copies files. Expected results:

| Stick | File | Result |
|---|---|---|
| **Whitelisted** | a clean file (recipe, readme) | copies normally, stays plaintext |
| Whitelisted | a **sensitive** file (e.g. the OPORD) | becomes `<name>.dlpenc`; plaintext gone. (Or **blocked** if you chose "Block it" for block-band and the file is a full match) |
| **Not whitelisted** | a clean file | copies normally |
| Not whitelisted | a **sensitive** file | **blocked** — does not stay on the stick; user gets a "Blocked by DLP" toast |

> The sealed file appears a second or two after the copy (settle window) — that plaintext window is the documented v1 limit (kernel M8 closes it).
> Check on the endpoint log: `allowed-pending-seal` (guard stood aside) then the sealer's seal, or `kernel-blocked` for a non-whitelisted sensitive file.
> If a sensitive file COPIES to a non-whitelisted stick: confirm its containment ≥ 0.15 (files 0.05–0.15 copy by design), or that it's actually not whitelisted.

---

## PART E — Open a sealed file. End user / admin, on any enrolled endpoint.

```powershell
& 'C:\ProgramData\DLPAgent\dlp-agent.exe' decrypt E:\<name>.dlpenc -o C:\Users\Public\<name>
start C:\Users\Public\<name>
```
Offline — uses the keyring the service already synced; no server call needed.

> Expected: `decrypted: ...`, matching `sha256`, and a `Decrypted` audit incident.
> Negative test (prove the "lost stick is useless" guarantee): take the `.dlpenc` to a PC **without** the agent / a different org → it's garbage; `decrypt` there → `DecryptDenied`, exit non-zero, nothing written.

---

## PART F — Admin monitoring. Console.

- **Incidents** (`incident_reviewer`): seal incidents (channel `usb`, action `encrypted`, key id, hashes), block incidents, decrypt incidents, and `allowed-pending-seal` audit records.
- **Audit log** (`auditor`): key creation, every whitelist change, every key delivery to an agent, every decrypt.

---

## Fail-secure behaviours to verify (the safety story)

1. **Stop the service, then copy a file to any stick** → the driver's FailMode=1 denies all removable writes (nothing copies). Restart: `sc start DLPAgent`.
2. **Whitelisted stick, but kill only the seal capability** (e.g. destroy the key in the console so the endpoint can't seal): a sensitive file is **blocked** (`seal-unavailable-blocked`), never left as plaintext.
3. **Destroy the key** (`POST /api/encryption/keys/<id>/destroy`) → previously sealed media can no longer be decrypted anywhere (`DecryptDenied`). This is crypto-shredding.

---

## Teardown / re-test
```powershell
sc stop DLPAgent
& 'C:\ProgramData\DLPAgent\dlp-agent.exe' uninstall-service
fltmc unload dlpflt
```
Or roll back the VM snapshot.

## Honest limitations (state these)
- **Settle-window:** a sealed file exists in plaintext on the stick for ~1–2s before sealing (kernel M8 closes it — do not claim never-lands).
- **0.05–0.15 containment residual:** a mildly-sensitive file seals on a trusted stick but copies on an untrusted one (owner-chosen 0.15 block line).
- **Serials are spoofable** — which is exactly why `encrypt` is a stronger whitelist action than plain allow (a spoofed "trusted" stick still only receives ciphertext).
- **Key creation has no UI yet** (API only); phone (MTP) / USB-tethering device blocks are off under the unified service (out of scope of the content matrix).
