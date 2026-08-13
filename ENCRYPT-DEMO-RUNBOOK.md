# Encrypt-on-Write (Trusted USB Destination) — Prod Demo Runbook

**Prepared:** 2026-08-12. M1–M4 of the encrypt-on-write spec are built and machine-verified
(`cargo test`: 259 passed / 0 failed, incl. `crypto_envelope` 19, `decrypt_path` 5, `golden_vectors` 6;
server `npm run test:encryption`: 22 passed / 0 failed). This runbook is the **M5 operator gate**: prove
on real hardware that a whitelisted stick receives only `.dlpenc` envelopes, that an enrolled endpoint
can open them (audited), and that a machine without the key cannot.

What is machine-verified vs what YOU verify here:
- **Machine-verified (tests):** envelope format + tamper matrix, seal/open round-trip, `decide_seal`
  decision table, seal-in-place on a temp dir (plaintext removed, incident shape), decrypt-denied on
  missing key, server RBAC/route/migration behaviour.
- **Operator-verified (this runbook):** a real USB stick, real settle timing, the console UI flow,
  and the cross-machine decrypt story. Record PASS/FAIL per row in step 6.

## Provisioned state you need (server host)
- **Postgres up** (`docker compose up -d` in `dlp-management-server/`) with migration
  `006_encryption_keys.sql` applied (the encryption test suite ran against it — if
  `npm run test:encryption` passes, the schema is there).
- **Console** `:3001` (`npm start`) and the frontend build.
- **mTLS agent server** `:8443` (`npm run agent-server`) — only needed for incidents to land live;
  seal/decrypt themselves are **offline** (cached keyring, no server round-trip ever).
- **`DLP_ORG_ROOT_KEY`** in the server `.env`: 64 hex chars (32 bytes). Without it, key creation
  returns 503 (fail secure — no default key). Generate once, keep out of git:
  ```powershell
  -join ((1..32) | ForEach-Object { '{0:x2}' -f (Get-Random -Max 256) })
  ```
- An enrolled agent (see `USB-DEMO-RUNBOOK.md` step 2 for the enroll flow). The kernel driver is
  **not** required for this demo — sealing is the user-mode `usb-monitor` channel.

## 1. Create a key and whitelist the stick (console)
1. Find the stick's serial. Plug it into the agent machine and either read the `usb-monitor` startup
   log (it prints device identity per volume) or:
   ```powershell
   Get-CimInstance Win32_DiskDrive | Where-Object MediaType -eq 'Removable Media' |
     Select-Object Model, SerialNumber
   ```
2. Create the KEK (sysadmin — there is no key-creation page yet; use the API with a sysadmin session):
   ```
   POST /api/encryption/keys      body: { "classification": "internal" }
   ```
   Response is metadata only (`id` like `class-internal/v1`, state `active`). The server stores the
   KEK **wrapped under the ORK**; raw key bytes never appear in any response or log.
3. Whitelist the stick in the console: log in as a `policy_author`, open the sidebar page
   **“Trusted USB devices”** (`/trusted-destinations`). Add an entry: channel USB, matcher = the
   stick's serial (or VID:PID, lowercase hex4), mode `encrypt_all`, pick the active key. The key
   dropdown only offers `active` keys; the key id is treated as an opaque string end-to-end —
   nothing ever parses it.

> **Dev-mode honesty (until M6 key sync):** the agent does NOT fetch the KEK from the server yet.
> The server-side key row is what the whitelist UI references; the agent seals with a **local dev
> keyfile** whose key id must match. Two machines that share the same dev keyfile can exchange
> sealed files; that keyfile is the demo's key-distribution channel.

## 2. Agent config (both machines)
Create the dev keyring (git-ignored, DEV ONLY — it holds raw KEK bytes in plaintext):
```powershell
$kek = [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Max 256 }))
@"
{ "activeKeyId": "class-internal/v1",
  "keys": { "class-internal/v1": "$kek" },
  "destroyed": [] }
"@ | Out-File -Encoding ascii C:\ProgramData\DLPAgent\dev-keyring.json
```
Copy the SAME file to machine B (that is the "same org" for this demo).

`agent.toml` (spec §3.2 / §4.1; see `agent.example.toml` for the commented version):
```toml
[usb]
enabled = true

[[usb.rules]]
match_serial = "<YOUR-STICK-SERIAL>"
action = "encrypt"
mode = "encrypt_all"
note = "demo courier stick"

[[usb.rules]]                      # second stick, if you have one, for the
match_serial = "<STICK-2-SERIAL>"  # encrypt_sensitive row of the demo table
action = "encrypt"                 # mode defaults to encrypt_sensitive

[crypto]
default_key_id = "class-internal/v1"
keyfile = "C:\\ProgramData\\DLPAgent\\dev-keyring.json"   # DEV ONLY
```

Start the channel on machine A:
```powershell
.\dlp-agent.exe usb-monitor
```
If the keyfile is unreadable you'll see `keyring load failed — sealing disabled (fail secure)` —
files on Encrypt volumes then raise `EnforcementFailed` instead of passing in plaintext. Fix the
keyfile; do not proceed with that warning showing.

## 3. Test material
- Sensitive: `samples/OperationHimalayanShield_OPORD.pdf` (IDM 1.0 against bundle v3).
- Innocent control: any unrelated file (a recipe, a readme).
- An `encrypt_sensitive`-ruled stick needs the cached bundle (`dlp-agent index-update` first);
  `encrypt_all` needs no bundle at all.

## 4. THE DEMO — copy to the whitelisted stick

| Action | Expected result |
|---|---|
| Copy any file to the `encrypt_all` stick | After the settle window (a few seconds) the file becomes `<name>.dlpenc`; **plaintext original is gone**. Incident: channel `usb`, action `encrypted`, note `sealed-post-write`, carries `keyId` + both SHA-256s |
| Copy `...OPORD.pdf` to the `encrypt_sensitive` stick | Sealed to `.dlpenc` (verdict in seal band / EDM hit / unreadable ⇒ seal; fail secure) |
| Copy the innocent file to the `encrypt_sensitive` stick | **Stays plaintext** — clean verdict passes untouched; whitelist ≠ ciphertext-everything in this mode |
| Try opening the `.dlpenc` in Notepad / another org's PC | Garbage / refused — AES-256-GCM envelope; header is authenticated, tampering makes open fail |
| On enrolled machine B (same keyfile): `.\dlp-agent.exe decrypt E:\plan.docx.dlpenc -o C:\demo\plan.docx` | Original bytes restored (`decrypted: ...` with matching plaintext SHA-256); a `decrypt` audit incident is recorded **before** the plaintext is written |
| On machine B, remove the keyfile (or use a keyring without `class-internal/v1`), decrypt again | **Refused**, non-zero exit; `DecryptDenied` incident (unknown/destroyed key id). No partial plaintext is ever written |
| Break the incident path (server down AND local queue dir unwritable), decrypt | **Nothing is written** — no un-audited decrypt, fail secure. (Server merely down is fine: incident queues locally, decrypt proceeds) |

`dlp-agent decrypt --help` shows the exact syntax: `dlp-agent decrypt <file.dlpenc> [-o <out>]`.
Decrypt is fully offline — cached keyring only, no server round-trip.

## 5. Show it in the console
Log in as `incident_reviewer` → incident feed shows the seal incidents (key id, plaintext +
sealed hashes, `sealed-post-write` note) and the decrypt incidents. Every trusted-destination
change and key creation from step 1 is in the append-only audit log.

> Known gap (M6, already tracked): the server currently maps agent `actionTaken:"encrypted"` to
> null and does not persist `keyId`/`sealedSha256` columns — verify those fields in the agent's
> incident log / raw POST body if the console row looks thin.

## 6. Record results
For each row in step 4: PASS / FAIL / DEVIATION + notes. This is the first real-hardware run of
the sealer — the temp-dir tests can't see real USB settle timing or AV interference.

## Honest limitations (state these in the demo)
- **Settle-window plaintext gap:** the OS writes plaintext first; we seal seconds later
  (incident note `sealed-post-write`). A yanked stick inside that window carries plaintext.
  Closing it is the kernel milestone M8 — do not claim never-lands protection.
- **Serials are spoofable.** That is precisely why `encrypt` is a better whitelist action than
  `allow_audited`: even a spoofed "trusted" stick receives only ciphertext.
- **Dev keyfile is plaintext key material** on disk — demo only, git-ignored. On Windows the agent
  re-seals it at rest via DPAPI (machine scope) after first use, but the source keyfile itself is
  plaintext until server key sync (M6) removes the need for it. Never deploy it.
- Key destruction is single-person (sysadmin) in v1, heavily audited; the code keeps a request/
  execute split so a two-person confirm can be inserted later.
- Web-upload/webmail sealing is M7; only the USB channel is live in this runbook.

## 7. Running the kernel guard and the sealer together

New 2026-08-12: `usb-guard` (the kernel minifilter client) and `usb-monitor` (the sealer) now work
**simultaneously**. Both fixes are user-mode only — the driver and wire protocol are frozen
(`DLP_MSG_VERSION` stays 2). Two things changed in the guard's `decide()`:

1. **Sealed-envelope passthrough.** Content beginning with the `.dlpenc` magic (`DLPE`) is allowed
   with no incident, on every volume and for **both** scan reasons (write and read). The monitor
   runs as a different PID than the guard — only the guard's PID is skip-self in the driver — so
   without this the guard scanned the sealer's own `.dlpenc.tmp` writes, read the ciphertext as
   Unreadable, and under `[kguard] fail_block = true` quarantined the envelope it had just been
   given. An envelope is already the strongest protected state; scanning ciphertext is noise, and
   reading an envelope must never taint the reader either.
2. **Whitelist-aware write scans.** For WRITE scans only (read-taint is untouched), the guard
   resolves the target volume's device identity (NT path → drive letter via a cached
   `QueryDosDeviceW` map → the same IOCTL identity lookup the monitor uses) and evaluates the same
   `[[usb.rules]]` matrix. On an `action = "encrypt"` destination it applies `decide_seal` and
   stands aside for the sealer instead of quarantining what the monitor is about to armour.

Combined behaviour on a write to an `action = "encrypt"` volume (driver loaded, monitor running):

| File / verdict | Guard (kernel) | Monitor (sealer) |
|---|---|---|
| Block band, rule default (`on_block_band = "block"`) | **BLOCK** — kernel quarantine, incident `kernel-blocked`, exactly as before | never sees the file |
| Block band, rule opt-in (`on_block_band = "seal"`) | ALLOW; incident kind `Match`, action `audited`, note `allowed-pending-seal` | seals to `.dlpenc`, incident `sealed-post-write` |
| Seal band / EDM hit / unreadable | ALLOW + `allowed-pending-seal` incident (`UnreadableOnRemovable` for unreadable) | seals |
| Clean file (`encrypt_sensitive`) | ALLOW, no incident — today's clean path | passes plaintext through |
| No bundle cached | ALLOW + metadata-only `allowed-pending-seal` incident (instead of `fail_block`) | seals fail-secure without a bundle |
| `.dlpenc` envelope bytes (the sealer's own output) | ALLOW, no incident — passthrough | n/a, already sealed |

Gates and honest limitations:

- **The override only applies when `[usb] enabled = true`.** With the monitor channel off there is
  nobody to seal — an allow-pending-seal would just strand plaintext on the stick — so the guard's
  behaviour is exactly as before (fail secure). Non-encrypt devices, read-taint scans, and volumes
  whose device cannot be resolved also keep today's behaviour exactly; the guard never guesses a
  whitelist match.
- **The settle-window plaintext gap still applies.** Between the kernel's allow and the monitor's
  seal, the plaintext sits on the stick for the settle window (seconds). M8 (kernel-assisted seal)
  closes this — do not claim never-lands protection while demoing the combined mode.
- **If the monitor dies after the kernel's allow,** the plaintext stays on the stick — but the
  incident trail shows the kernel's `allowed-pending-seal` with no matching `sealed-post-write`,
  so the gap is visible to a reviewer, never silent.
