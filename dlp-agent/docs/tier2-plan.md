# Tier 2 — Plan, Threat Model & Honest Scope

**Date:** 2026-08-05
**Goal (as requested):** stop a malicious/infected endpoint (incl. VNC/AnyDesk-driven) from
exfiltrating sensitive data over the network — "capture everything."

## 0. The honest threat-model boundary (read first — non-negotiable)
No endpoint DLP can guarantee zero exfiltration against every adversary. This is documented in
`egress-channels.html` §5 (Tier 4) and holds regardless of how much we build:
- **Screen-viewing (VNC/AnyDesk/RDP view)** = the analog hole. The attacker *reads* the screen and
  photographs it. Software cannot stop it. We CAN block their file-transfer + clipboard and kill the
  tool; we CANNOT stop their eyes on a shared screen.
- **Privileged payload (admin/SYSTEM/kernel)** can unhook the agent or read raw disk beneath our
  filters. DLP is defence-in-depth WITH EDR / least-privilege / OS hardening — not anti-rootkit.
- **Encrypted exfil to an ALLOWED destination** is content-blind. The lever is destination
  allowlisting + fail-secure, not content inspection.

**Achievable posture:** make exfil very hard and catch the overwhelming majority — allowlist-only
network egress, remote-tool blocking, file/clipboard/USB controls (already built), fail-secure on
encrypted-to-unknown. For the highest assurance, this is layered with EDR + least-privilege + air-gap.
We will NOT claim "100% / nothing can ever leave."

---

## 1. Tier 2 mechanisms (from egress-channels.html)
| # | Mechanism | Tier 2 channels | This plan |
|---|---|---|---|
| ③ | Network filter (WFP) | any dest blocklist, FTP/SFTP, git/CLI, remote-tool relays | **BUILD NOW (user-mode WFP)** — the core containment |
| ⑧ | Remote-access control | RDP/Citrix, **AnyDesk/TeamViewer/VNC** | **BUILD NOW** — process + network block/kill |
| B4 | Fail-secure on unreadable egress | encrypted archive to unknown dest | **BUILD NOW** — policy |
| ④ | Browser hook | web upload, webmail, cloud web UI | **BUILD NOW (artifact)** — extension + native host; e2e manual |
| ③k | WFP content callout (kernel) | inspect INSIDE flows | **DESIGN + compile-verify (follow-on)** |
| ④ | Outlook / desktop email (MAPI/VSTO) | desktop mail | **DESIGN only** — separate .NET stack, follow-on |

---

## 2. BUILD NOW — the verifiable core (user-mode Rust in dlp-agent)

### 2.1 Network egress control (③) — `dlp-agent/src/netfilter/`
User-mode WFP (`FwpmEngineOpen`, `FwpmFilterAdd0` at `FWPM_LAYER_ALE_AUTH_CONNECT_V4/V6`,
`FWP_ACTION_BLOCK`/`PERMIT`, conditions `FWPM_CONDITION_ALE_APP_ID`, `IP_REMOTE_ADDRESS`,
`IP_REMOTE_PORT`). No kernel callout needed for BLOCK/PERMIT.
- **Modes:** `monitor` (add no blocking filters, just enumerate + log intended verdict),
  `allowlist` (default-deny: PERMIT only approved dests/apps, BLOCK the rest),
  `blocklist` (PERMIT all except blocked dests/apps/remote-tools).
- **Rules (from config, later server-authored):** allow/deny by app path (app-id), remote IP/CIDR,
  remote port, plus a built-in **remote-access-tool set** (§2.2).
- **WFP hygiene:** own sublayer + provider (GUIDs), filters weighted, **transactional add**
  (`FwpmTransactionBegin/Commit`), and a `--persist` option (BOOTTIME vs dynamic session). Clean
  teardown removes only our provider/sublayer/filters. `FWPM_SESSION_FLAG_DYNAMIC` for
  auto-cleanup-on-exit in test/monitor mode.
- **Fail-secure:** in `allowlist` mode, if the agent/policy is absent, default is BLOCK non-allowlisted
  (configurable; document DoS tradeoff — allowlist mode can break a machine, so ship `monitor` default
  and require explicit `--enforce allowlist`).
- **Incidents:** a blocked/anomalous connection → incident (channel `network`), metadata only
  (app, remote ip/port, bytes if known) — never packet contents.

### 2.2 Remote-access-tool control (⑧) — `dlp-agent/src/netfilter/remote_tools.rs` + process
- **Signature set:** process image names + publisher + known relay domains/IP ranges + default ports
  for AnyDesk, TeamViewer, VNC (RealVNC/TightVNC/UltraVNC), Chrome Remote Desktop, RDP-out (mstsc),
  Splashtop, LogMeMe. (Ports are unreliable — tools fall back to 443 — so rely on **app-id/process**
  primarily, relays secondarily.)
- **Actions:** `detect` (incident only), `block-network` (WFP app-id BLOCK so the tool can't reach its
  relay), `kill` (terminate the process). Config-selectable per tool; default `block-network` for
  defence.
- **Note honestly:** blocking the tool's network/killing it does NOT retroactively stop a session that
  already shared the screen (analog hole). Documented.

### 2.3 Fail-secure egress policy (B4) — shared policy helper
Extend the policy shape: for file-bearing channels, `unreadable` (encrypted container) + destination
NOT allowlisted ⇒ BLOCK. Ties the minifilter/clipboard verdict to the network destination decision.

### 2.4 Wiring / config / CLI
- `net-monitor [--enforce <monitor|allowlist|blocklist>]` subcommand (default `monitor`). Independent
  of check-in loop. `--enforce` gated + admin-required + documented DoS risk.
- `[netfilter]` config: mode, allow/deny rules, remote_tool_action per tool, persist.
- Extend `windows` crate features: `Win32_NetworkManagement_WindowsFilteringPlatform`,
  `Win32_System_Rpc` (GUIDs), `Win32_NetworkManagement_IpHelper` (owner/PID→conn), process enum.

### 2.5 Tests (verifiable here)
- Rule-decision engine (pure): allowlist/blocklist/remote-tool matching by app/ip/port → PERMIT/BLOCK,
  first-match, default per mode. ≥12 cases.
- Remote-tool signature matcher: image-name/relay/port → tool id + action.
- WFP filter-spec builder: given a rule, produce the correct `FWPM_FILTER0` fields (conditions/action/
  weight) — unit-test the STRUCT we would add WITHOUT calling `FwpmFilterAdd` (dry-run), same pattern
  as the usb enforce dry-run. Live WFP add is `--enforce` + admin, MANUAL.
- Fail-secure policy decisions.
- All existing agent tests still pass; `cargo build --release` clean.

---

## 3. BUILD NOW — Browser upload hook (④) — `dlp-browser-ext/`
Content visibility on the web-upload channel (the TLS-blind spot of WFP).
- **Extension (MV3, Chrome/Edge):** `manifest.json`, background service worker intercepting
  `<input type=file>` / drag-drop / fetch-with-body on upload; reads the file/text, sends to the
  native host, blocks the upload on a BLOCK verdict (cancel the form / strip the payload).
- **Native messaging host (Rust, in dlp-agent):** `browser-host` subcommand speaking the native
  messaging protocol (4-byte length + JSON on stdio), runs `detect::verdict`/`verdict_text`, replies
  allow/block, raises an incident.
- **Registration:** native-host manifest + registry install script; the extension is enterprise
  force-installed via policy (documented).
- **Verification:** the native host `cargo build`s + a protocol unit test (framing + verdict) here;
  the extension is lint/structure-checked; **true end-to-end needs a real browser → MANUAL.** Honestly
  labelled. Coverage is Chrome/Edge; Firefox is a follow-on.

---

## 4. DESIGN + follow-on (NOT fully built/verified in this pass — honest)
- **WFP content-inspection callout (③ kernel)** — to inspect INSIDE non-TLS or proxy-terminated flows;
  a kernel callout driver like the minifilter (compile-verifiable, runtime-manual). Big; follow-on.
- **Outlook / desktop email (④)** — MAPI/VSTO .NET add-in; separate toolchain. Follow-on.
- **TLS interception proxy** — the alternative to per-app hooks for web/mail content; heavy (breaks
  pinning), a deployment decision. Documented, not built.

---

## 5. DO NOT
- DO NOT claim "no exfiltration possible" / "put in production, nothing leaks" — see §0.
- DO NOT execute live WFP adds / process kills in automated tests — dry-run/pure-logic only; live
  behind `--enforce` + admin, MANUAL.
- DO NOT default to `allowlist` (default-deny) enforcement — it can brick a machine; default `monitor`.
- DO NOT log packet/file/clipboard CONTENT; incidents carry metadata only.
- DO NOT change the fingerprint math / `detect/` except reuse of existing public fns.
- DO NOT add heavy crates; extend the `windows` crate features.

## 6. Acceptance criteria (this pass)
1. `cargo build --release` clean; ALL existing agent tests pass (detect/ untouched incl. golden).
2. netfilter rule-engine + remote-tool matcher + WFP-filter-spec dry-run + fail-secure tests pass.
3. `net-monitor --help` documents modes, `--enforce` gating + DoS risk, audit-only default.
4. browser native host `browser-host` builds + protocol unit test passes; extension structure valid.
5. No content logging (grep-confirmed).
6. Honest report: real build/test output; MET/NOT per criterion; MANUAL-only (live WFP, live kill,
   browser e2e); design-only follow-ons; the §0 threat-model limits restated.
