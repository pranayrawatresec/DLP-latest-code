# DLP — Session Summary + Manual Test Plan

**Built:** 2026-08-05 (this session) · **Manual testing:** next session
**Two committed checkpoints:** `09e38d4` (detection + Tier 1) · `ca7c2d4` (Tier 2 core), on branch
`feat/detection-engine-and-tier1-channels`.

This one document = (A) what we built today, (B) what is already proven vs what needs manual
testing, (C) the ordered runbook to test tomorrow, (D) safety rules. Deep detail lives in
`DONE-2026-08-04.md`, `DONE-2026-08-05.md`, and the per-component specs/READMEs.

---

## A. What we built today

| # | Component | Where | Status |
|---|---|---|---|
| 1 | **Detection engine** (IDM fingerprinting + EDM), server + Rust agent | `dlp-management-server/lib`, `dlp-agent/src/detect` | ✅ **runtime-verified** (ran end-to-end) |
| 2 | **Protected-content repository + console UI** (collections, register, compile, publish banner) | server `routes/protected.js`, frontend `pages/ProtectedDocuments.jsx` | ✅ runtime-verified |
| 3 | **Signed index bundle + mTLS distribution + incidents** | server `lib/indexBundle.js`, agent `detect/bundle.rs` | ✅ runtime-verified |
| 4 | **USB channel — user-mode** (device control + copy audit) | `dlp-agent/src/usb` | 🧪 build-verified, **live USB manual** |
| 5 | **Clipboard channel** (text/files/HTML, empty-clipboard block) | `dlp-agent/src/clipboard` | 🧪 build-verified, **live manual** |
| 6 | **Device control ext** (MTP/WPD block, USB tethering block) | `dlp-agent/src/usb/enforce.rs` | 🧪 build-verified, **live registry manual** |
| 7 | **Kernel minifilter** `dlpflt.sys` (removable + SMB + fixed/sync) | `dlp-minifilter/` | 🧪 **compile/analyze-verified, runtime MANUAL (VM only)** |
| 8 | **Tier 2 network egress control** (user-mode WFP, allow/block) | `dlp-agent/src/netfilter` | 🧪 build-verified, **live WFP manual (admin)** |
| 9 | **Remote-access-tool block/kill** (AnyDesk/TeamViewer/VNC/RDP…) | `dlp-agent/src/netfilter/remote_tools.rs` | 🧪 build-verified, **live manual** |
| 10 | **Browser upload hook** (MV3 extension + native host) | `dlp-browser-ext/`, `dlp-agent/src/browser_host.rs` | 🧪 build-verified, **browser e2e manual** |

**Automated verification (already done, re-run independently):** 179 agent tests + 151 server tests
pass; `dlpflt.sys` compiles/links/`cl /analyze` clean; extension manifest valid MV3. Golden vectors
intact throughout (fingerprint math unchanged).

### The honest limit (do not forget while testing)
This stack contains the **majority** of exfil but does **NOT** make it impossible:
- **Screen-view over VNC/AnyDesk/RDP** = analog hole — the attacker reads/photographs the screen; we
  block the tool's file-transfer/clipboard and can kill it, but not their eyes.
- **Privileged (admin/kernel) payload** can unhook the agent — that's EDR's job.
- **Encrypted data to an ALLOWED destination** is content-blind — lever is allowlisting + fail-secure.
Highest assurance = this DLP **+** EDR + least-privilege + air-gap.

---

## B. Prerequisites for tomorrow (set up first)

1. **A dedicated TEST machine or VM with a snapshot.** The minifilter and WFP touch the kernel/network
   stack — a bug can BSOD or cut networking. **Never test the driver or `--enforce allowlist` on your
   main machine.** Take a VM snapshot before starting so you can roll back.
2. **Admin/SYSTEM shell** on the test box (device control, WFP, driver load all need it).
3. **Server side running** (can be your dev box, reachable from the test box or same box):
   `docker compose up -d`, `npm start` (:3001), `npm run agent-server` (:8443), `npm run worker`.
4. **A compiled agent** on the test box: `cargo build --release` in `dlp-agent` → `dlp-agent.exe`.
5. **Test artifacts:** `samples/OperationHimalayanShield_OPORD.pdf` + `samples/variants/`.
6. **For the driver:** `bcdedit /set testsigning on` + reboot (VM), then the sign scripts.
7. **For remote-tool tests:** install AnyDesk or TeamViewer on the VM.
8. **For the browser test:** Chrome or Edge on the VM.

---

## C. Manual test runbook (ordered — do these tomorrow)

> Tick each. Record actual vs expected. Stop and note anything that deviates.

### C0. Sanity — detection already works (quick re-demo, ~5 min)
Ref `dlp-management-server/docs/MANUAL-TEST-detection.md`. Register the OPORD via the console
(login `priya@`, policy_author), Compile index, then:
```
dlp-agent.exe scan --bundle <latest .dlpx> --file <a copy of the OPORD> --json
```
- [ ] Expected: `idm` match, correct title, high containment. (This is the foundation everything else feeds.)

### C1. USB channel — user-mode (`MANUAL-TEST.md` U0–U6)
```
dlp-agent.exe usb-monitor            # audit-only
dlp-agent.exe usb-monitor --enforce  # live (admin)
```
- [ ] Plug a USB stick → arrival detected, device identity (serial/bus) logged.
- [ ] Copy the OPORD to the stick → incident raised (audit mode).
- [ ] `--enforce` + policy read_only → write to the stick denied.
- [ ] External USB SSD (reports as fixed) → still treated as removable (bus-type).
- [ ] Unplug → auditor stops cleanly.

### C2. Clipboard channel
```
dlp-agent.exe clipboard-monitor            # audit
dlp-agent.exe clipboard-monitor --enforce  # empties clipboard on sensitive copy
```
- [ ] Copy an OPORD paragraph → incident (coverage high). `--enforce` → paste yields nothing.
- [ ] Copy an innocent paragraph → no incident. Copy a sensitive file (Ctrl+C in Explorer) → detected.

### C3. Device control — MTP / tethering (admin)
- [ ] With `mtp_action=block` + `--enforce`: connect a phone (MTP) → read/write denied (WPD registry
      `Deny_Read`/`Deny_Write` set). Revert clears it.
- [ ] USB tethering device → blocked.

### C4. Kernel minifilter (VM ONLY — BSOD risk) — `dlp-minifilter/README.md`
```
# VM: bcdedit /set testsigning on ; reboot
tools/make-testcert.ps1 ; tools/sign-driver.ps1 ; tools/install.ps1
fltmc filters            # dlpflt attached at altitude 265000
dlp-agent.exe usb-guard  # user-mode port client
```
- [ ] Driver loads, no bugcheck. `fltmc` shows it attached.
- [ ] Copy OPORD to USB → **blocked/quarantined** + incident. Innocent file → allowed.
- [ ] Configure a fixed-volume watch path (e.g. a sync folder) → copy OPORD there → caught.
      Empty watch-set → only removable is filtered (back-compat).
- [ ] Kill `usb-guard` → confirm FailMode behavior. Then `tools/uninstall.ps1`, `fltmc` clean.

### C5. Tier 2 — network egress control (admin, VM) — `dlp-agent/docs/tier2-plan.md`
```
dlp-agent.exe net-monitor                       # monitor (audit) — SAFE default
dlp-agent.exe net-monitor --enforce blocklist   # block specific dests/apps
dlp-agent.exe net-monitor --enforce allowlist   # DEFAULT-DENY — DoS RISK, snapshot first
```
- [ ] monitor mode → intended verdicts logged, nothing blocked.
- [ ] blocklist a test destination/app → that connection blocked, others fine.
- [ ] allowlist mode (snapshot!) → only approved dests reachable, all else blocked; incident on blocks.

### C6. Remote-access-tool block/kill (VM, with AnyDesk/TeamViewer installed)
- [ ] `detect` → incident when the tool runs. `block-network` → tool can't reach its relay (WFP
      app-id block). `kill` → process terminated.
- [ ] **Confirm the honest limit:** if a session already shows the screen, killing the tool does not
      undo what was viewed. Note this in results.

### C7. Browser upload hook (Chrome/Edge on VM) — `dlp-browser-ext/README.md`
```
install-native-host.ps1        # registers com.dlp.browser_host for Chrome+Edge
# load dlp-browser-ext as an unpacked extension (or force-install)
dlp-agent.exe browser-host     # (invoked by the browser via native messaging)
```
- [ ] Try to upload the OPORD to a test web form → **blocked** with a notice; incident (channel
      web-upload). Upload an innocent file → allowed.

---

## D. Safety rules (read before C4–C6)
- **VM + snapshot for C4 (driver) and C5 allowlist / C6 kill.** These can BSOD or sever networking.
- **`allowlist` is default-deny** — it can cut the machine off entirely. Have console/out-of-band
  access to roll back.
- **Test-signing is dev-only** — turn it back off (`bcdedit /set testsigning off`) when done.
- If anything bluescreens or loses network: roll back the snapshot; capture the state for diagnosis.

---

## E. After testing — feed results back
For each item: PASS / FAIL / DEVIATION + notes. Anything that fails at runtime is a real bug to fix
(the code is only compile/test-verified, not runtime-proven). Bring the list back and we fix, then
re-test. Remember: a clean compile is not a working driver — C4–C7 are where the real proof happens.
