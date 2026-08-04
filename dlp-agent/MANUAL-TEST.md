# Manual end-to-end test — token → package → install → certificate

Do the whole flow by hand. This uses the real agent binary. Two honest caveats:

- **There is no MSI or Windows service yet.** The `packaging/out/` folder *is* the
  payload an MSI would install; you run the binary directly instead of via a
  service. (Service + MSI are the next build step.)
- **"Different PC" on one machine is simulated** by giving each install its own
  `-PcName` (→ its own state dir = its own identity). For a *truly* different PC,
  see Part H.

Run everything in **PowerShell**.

---

## 0. Start the four pieces (one terminal each)

```powershell
cd dlp-management-server; docker compose up -d      # PostgreSQL
cd dlp-management-server; npm start                 # console API  :3001
cd dlp-management-server; npm run agent-server      # agent mTLS   :8443
cd dlp-management-frontend; npm run dev             # console UI   :5173
```

Build the agent once:

```powershell
cd dlp-agent; cargo build --release
```

---

## 1. Generate a token (in the console — your hands)

1. Open http://localhost:5173, sign in as `vipul@resecsystems.io` / `//
`.
2. **Enrollment tokens → Create token.** Description "manual test", Max uses **5**, 3 days.
3. **Copy the token** from the reveal panel (`dlpenr_…`). This is the secret you put in the package.

---

## 2. Build the package (the MSI payload)

```powershell
cd dlp-agent
powershell -ExecutionPolicy Bypass -File packaging\build-package.ps1
```

Look in `packaging\out\` — `dlp-agent.exe`, `ca-cert.pem`, `agent.toml`. That folder
is exactly what an MSI would drop on a PC.

---

## 3. Put the token in the package & "install" on PC-01

```powershell
powershell -ExecutionPolicy Bypass -File packaging\install.ps1 -Token "dlpenr_PASTE_HERE" -PcName "PC-01"
```

Watch it: generate key + CSR → enroll → **and print your certificate** (subject
`dlp-agent-<id>`, issuer `DLP Internal CA`, serial, expiry, DPAPI-sealed key). The
private key was made on the machine and never sent — only the CSR went out.

---

## 4. See it in the console

Go to the console **Agents** page → `PC-01`'s machine appears, status **active**,
with its certificate expiry. (Refresh if needed.)

---

## 5. Run the live check-in loop

```powershell
$cfg = "$env:TEMP\dlp-agent-pcs\PC-01\agent.toml"
$env:DLP_AGENT_CONFIG = $cfg
& .\packaging\out\dlp-agent.exe run
```

It checks in over mutual TLS every interval. Watch the Agents page — **Last seen**
updates. Leave it running or Ctrl-C.

---

## 6. Simulate a *different* PC (same or a new token)

```powershell
powershell -ExecutionPolicy Bypass -File packaging\install.ps1 -Token "dlpenr_PASTE_HERE" -PcName "PC-02"
```

A **second** agent appears in the console with a **different id and certificate** —
and the token's "uses" count goes up (5 → check the Enrollment tokens page). One
token, many PCs, each with a unique identity.

---

## 7. Retire a PC (revocation, fail-secure)

1. Console **Agents → PC-01 → Retire**.
2. Back in PC-01's `run` window (or run `once`), the next check-in is **refused**
   (`403 agent retired`). The agent doesn't fall open — it keeps retrying on cached
   state. De-enrolled from the server, no access to the PC needed.

---

## 8. A REAL different PC (VM or another Windows machine)

1. On the **server** box, make sure the server certificate covers the address the
   other PC will use. The dev cert only lists `localhost`, `127.0.0.1`, and this
   machine's hostname. For a real remote PC, re-init the CA with the server's real
   name/IP:
   ```powershell
   # in dlp-management-server, set the reachable name, then re-init:
   Remove-Item -Recurse -Force ca      # WARNING: orphans any existing agents
   $env:AGENT_SERVER_DNS = "dlp-server.mylab.local"   # or the server's IP
   npm run init-ca
   ```
   Open port **8443** on the server's firewall.
2. Copy `dlp-agent\packaging\out\` to the other PC.
3. On that PC, mint a fresh token in the console and run:
   ```powershell
   powershell -ExecutionPolicy Bypass -File install.ps1 `
       -Token "dlpenr_…" -PcName "REAL-PC" -Server "https://dlp-server.mylab.local:8443" -PackageDir .
   ```
   It enrolls across the network, gets its certificate, and appears in the console.

---

## What each step proves

| Step | Proves |
|---|---|
| 3 | key made locally, token spent, CA-signed cert issued & sealed |
| 4–5 | mutual-TLS check-in; the console sees the live agent |
| 6 | one token → many PCs, each a unique, individually-revocable identity |
| 7 | server-side revocation; fail-secure (never opens up) |
| 8 | it works across a real network with CA pinning |

Reset between runs: delete `%TEMP%\dlp-agent-pcs`, and retire/clear agents in the console.

---

# USB Channel — MANUAL TEST (live hardware; NOT automated)

These steps exercise the parts of the USB removable-media channel
(`docs/usb-channel-spec.md`) that **cannot** run in `cargo test`: real device
arrival/removal, live IOCTL identity, and live enforcement (which modifies the
machine). They are **manual** — the automated suite does not claim them.
Everything the automated suite covers (policy matrix, descriptor parsing, the
settle/dedup/incident pipeline, enforcement *planning*, watcher diff, the
offline queue) is in `cargo test`; the steps below are not.

Run on Windows; use an Administrator/SYSTEM shell for the enforcement steps.
Have a spare, writable USB stick and, ideally, a cached signed bundle
(`dlp-agent index-update`) so `verdict()` has something to match.

## U0. Preconditions
- `dlp-agent enroll` done (so incidents POST over mTLS), OR expect incidents
  **queued locally** under `state_dir\usb-incident-queue\`.
- A `[usb]` config section, e.g. `enabled = true`, `default_action = "read_only"`.

## U1. Device arrival is detected (audit-only, the default)
1. `dlp-agent usb-monitor`
2. Plug a USB stick → **expect** a `removable device arrived` log with drive
   letter, serial, `bus="usb"`. Unplug → `removable device removed`.
3. Plug an **external USB SSD/HDD** (often reports `DRIVE_FIXED`) → it must still
   be classed removable (bus-type rule, spec §3.1 / edge 1). The **internal OS
   disk must NOT** appear.

## U2. Copying a sensitive file raises an incident
1. With a bundle cached, copy a protected document onto the stick.
2. **Expect** ~`settle_ms` later a `usb incident reported` log (enrolled) or a
   queued file (offline). Wire body: `{channel:"usb", fileName, fileSha256, verdict}`.
3. Innocent file → **no** incident. File > `max_file_bytes` → `SkippedTooLarge`
   note, file not read. Encrypted archive → `unreadable-on-removable` (fail-secure).

## U3. Partial-copy / settle
- Copy a large file and watch the log **during** the copy: no scan until the
  file is stable for `settle_ms`; a file still growing at `settle_timeout_secs`
  is scanned once, noted `settled-by-timeout`.

## U4. Offline queue + flush
1. Stop the server (or run before enrolling); copy a sensitive file → an
   incident file appears under `state_dir\usb-incident-queue\`.
2. Restart the server, run `dlp-agent usb-monitor` again → **expect**
   `flushed queued usb incidents` and an emptied queue.

## U5. Live enforcement (⚠️ modifies the machine — use a VM/spare box)
> Automated tests NEVER do this (dry-run only). These set real state.
1. Read-only: `dlp-agent usb-monitor --enforce` with `default_action="read_only"`,
   `[usb] enabled=true`, as Administrator. Try to write to the stick → **denied**
   (WriteProtect=1 under `HKLM\SYSTEM\CurrentControlSet\Control\StorageDevicePolicies`).
   Revert (clear WriteProtect) and re-plug → writes succeed (edge 14).
2. Block: `default_action="block"` → the volume is dismounted/unavailable.
3. Non-admin `--enforce` → **expect** `enforcement failed — degrading to audit`
   + an `EnforcementFailed` incident; the monitor keeps running (§3.4 / edge 13).

## U6. MTP phone (informational only)
- An MTP phone (no drive letter) is **out of scope** for content scanning in
  this build (edge 10). No file contents are inspected; full MTP control is
  design-only (needs WPD).

## Deviations / follow-ups (honest notes)
- `run_monitor` takes an injected incident **sink** in addition to
  `(cfg, storage, enforce)`, keeping the mTLS POST + offline queue in the binary
  and out of the library (reuses the main.rs report path; keeps the loop
  network-decoupled). The spec's 3-arg sketch is otherwise honoured.
- `Block` is implemented as **volume dismount** (FSCTL_DISMOUNT_VOLUME);
  `CM_Disable_DevNode` is the design-only stronger alternative (§3.4), not wired.
- Device context + action-taken live in the **local** record only; the server
  wire contract is unchanged (§4 permits deferring that — noted as follow-up).
- Metadata-only incidents (`SkippedTooLarge`, `EnforcementFailed`,
  `MtpDevicePresent`) carry no `verdict`, so they are logged rather than POSTed
  (the server contract requires a verdict). Follow-up: accept verdict-less notes.
- `WM_DEVICECHANGE` is intentionally not implemented (polling only) so no message
  loop can reach a test path (§3.2 / §7).
