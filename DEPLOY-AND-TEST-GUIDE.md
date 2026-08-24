# DLP — Deploy & Acceptance Test Guide (follow-along)

One guide to **hand the product over and prove it works**, end to end. Follow it
top to bottom. Every test is written as **Setup → Action → Expected → Confirm**
with a ☐ box to tick. Where a channel only *audits* by default or isn't built, it
says so plainly — no test claims a block that won't happen.

**Legend**
- 🟢 **ENFORCES** — blocks by default once configured as noted.
- 🟡 **MONITOR/CONFIG** — audits only unless you flip a specific switch (called out).
- ⚪ **NOT BUILT** — no enforcement exists yet; don't test for a block.

**Where to look when confirming a result (all channels):**
- **Toast** on the endpoint ("… blocked by DLP policy") — unless notify `mode="covert"`.
- **Endpoint log:** `C:\ProgramData\DLPAgent\logs\dlp-agent.log` (metadata only, never content).
- **Console:** the **Incidents** page (`GET /api/incidents`); the **Agents** page for check-in; the **Audit** view for the hash-chained log.

---

# Part 1 — Build the test bench

You need **two machines**: the **server** (management/console) and one **endpoint**
(a clean Windows VM). Snapshot the endpoint VM first so you can reset.

## 1.1 Stand up the server
Full detail in `ON-PREM-DEPLOYMENT-GUIDE.md` (Phase B). Condensed:

```bash
cd dlp-management-server
docker compose up -d                 # PostgreSQL 17
#   set .env: DATABASE_URL, DLP_BLOB_MASTER_KEY, DLP_ORG_ROOT_KEY, AGENT_SERVER_DNS
npm run migrate                      # 16/16 incl. the pw_hash fix
AGENT_SERVER_DNS=192.168.1.3 npm run init-ca
npm run bootstrap-admin              # first sysadmin
npm run agent-server                 # mTLS :8443   (agents)
npm start                            # console API :3001
npm run worker                       # fingerprint/index jobs
```
☐ `npm run migrate` ends `done (16 applied)`; `bootstrap-admin` prints "Created sysadmin".

## 1.2 Configure policy in the console
Log in as sysadmin, then:

1. **Create a `policy_author`** account (Users). ☐
2. **Register a sensitive test document (IDM):** create a collection → upload a
   test classified file (e.g. `OPORD.pdf`) → **Compile index**. Wait for the
   worker to build a signed bundle. ☐
3. **Read-deny policy → `enforce`**, fixed-volume scan **on**, watch path e.g.
   `C:\Users`. ☐
4. **Trusted-reader allowlist:** confirm the seeded starter list is present
   (Microsoft publishers + agent path). ☐
5. **Mint an enrollment token** (Enrollment page) → copy `dlpenr_…`. ☐

## 1.3 Install the endpoint
Copy `dlp-agent\packaging\out\` + the installer scripts to the VM. Test-signed
driver? enable test-signing first: `bcdedit /set testsigning on` + reboot
(production uses the MS-signed driver — no test-signing). Then **elevated**:

```powershell
powershell -ExecutionPolicy Bypass -File install-endpoint.ps1 `
    -Token "dlpenr_..." -Server "https://192.168.1.3:8443" -PackageDir .\out
```
☐ `fltmc filters` shows `dlpflt`; `sc query DLPAgent` = RUNNING; the machine shows
`enrolled → active` on the console Agents page.

## 1.4 Stage the test tools
On the endpoint, put a **sensitive file** (`OPORD.pdf`) on the Desktop, and stage
`openprobe.exe` (from `dlp-minifilter\tools\openprobe.rs`) + `verify-read-deny.ps1`
into `C:\Users\Public`. ☐

> **What the installed `DLPAgent` service enforces:** read-deny/open-deny (kernel),
> USB **content** writes, and encrypt-on-write sealing. **Clipboard** and
> **network** are *separate* monitors (run them by hand for their tests — §D/§E).

---

# Part 2 — Feature tests

## A. Whitelisting — trusted-reader allowlist  🟢

The core question: *only sanctioned apps may read sensitive content; everything
else is denied.*

**A1 — Untrusted app is blocked.**
- Setup: read-deny = enforce; `OPORD.pdf` sensitive & in scope.
- Action: `openprobe read C:\Users\pranay\Desktop\OPORD.pdf` (unsigned = untrusted).
- Expected: `READ-DENIED` (the read-capable open is cancelled). ☐
- Confirm: toast + a `Match` incident on the console.

**A2 — Trusted (Microsoft-signed) app is allowed.**
- Action: open the same file with Notepad/WordPad (signed "Microsoft Windows",
  on the starter allowlist).
- Expected: opens normally, **no** block, **no** incident. ☐
- *Why:* Authenticode publisher trust — a signed app is sanctioned by publisher,
  not by path. (This is also why a `cmd.exe` copy is trusted — don't use it as an
  "untrusted" tool; use the unsigned `openprobe`.)

**A3 — Add your app to the allowlist and watch it take effect.**
- Action: in the console add a **publisher** rule for a test app (find its signer
  CN with `Get-AuthenticodeSignature`), wait one resync (~5 min or restart agent).
- Expected: that app can now read sensitive files; before the rule it was blocked. ☐

**A4 — Name-only rule is flagged weak (informational).**
- Action: add a `name` rule (e.g. `winword.exe`) in the console.
- Expected: the UI shows the amber "name-only rules are easy to fake" caution. ☐

**A5 — Central lockdown (fail-secure, optional/advanced).**
- Setup: set `readersAuthority=central` with an **empty** list.
- Expected: **everything** untrusted → all sensitive reads denied (Option A
  fail-secure). Restore your list afterward. ☐

## B. Read-deny / open-deny (kernel)  🟢

**B1 — Automated acceptance harness (covers A1, open-deny, empty-file, clean).**
- Action: `powershell -ExecutionPolicy Bypass -File C:\Users\Public\verify-read-deny.ps1 -SensitiveFile "C:\Users\pranay\Desktop\OPORD.pdf"`
- Expected: **5/5 PASS** (T1 read-denied, T2/T3 open-deny fresh+cached, T5 overwrite OK, T6 clean read OK). ☐

**B2 — RustDesk/AnyDesk delegate case (the open-cancel).**
- Action: `openprobe open OPORD.pdf` three times.
- Expected: `OPEN-DENIED` **every** time (incl. the 2nd/3rd cached opens) — no
  handle is ever handed out for a delegate to read through. ☐

**B3 — Monitor mode raises visibility without blocking.**
- Setup: console read-deny = **monitor**; wait a resync.
- Action: `openprobe read OPORD.pdf`.
- Expected: read **succeeds**, but a would-block incident appears on the console.
  Set it back to **enforce** after. ☐

**B4 — Per-group targeting.**
- Setup: create a "monitor" group in the console, assign this machine to it (Agents
  page), keep Default = enforce; wait a resync.
- Expected: this machine now behaves as monitor while a Default machine still
  blocks. ☐

## C. USB / removable media  🟢 (content)  🟡 (device-control)

> Get a real **removable** volume on the VM: VMware → *Removable Devices* → connect
> a physical USB stick to the guest (a fixed virtual disk won't be seen as
> removable). Removable volumes are **always in read-deny scope** (no watch-path
> needed).

**C1 — Copy a sensitive file to USB is blocked (kernel content block). 🟢**
- Setup: `DLPAgent` service running (kernel guard active), driver loaded.
- Action: copy `OPORD.pdf` to the USB stick.
- Expected: the **write is denied** at the filesystem (copy fails/quarantined) —
  blocks when content containment ≥ `0.15`. Toast + `Match` incident
  (`action_taken=Blocked`, note `kernel-blocked`). ☐
- *Note:* the user-mode copy-auditor alone only **audits**; the **kernel** does the
  block. So this test proves the kernel path.

**C2 — Device control: force a stick read-only / block it. 🟡**
- Setup: run `dlp-agent usb-monitor --enforce` (elevated) with `[usb] enabled=true`
  and a rule `action="read_only"` (or `block`).
- Action: insert the stick.
- Expected: `read_only` → the stick becomes non-writable; `block` → it dismounts. ☐

**C3 — Encrypt-on-write (sealing) to a courier stick. 🟢**
- Setup: a `[[usb.rules]]` entry for that device with `action="encrypt"`; a keyring
  available (synced DPAPI keyring, or dev keyfile).
- Action: write a sensitive file to that stick.
- Expected: it lands as `name.dlpenc` (plaintext removed); incident
  `action_taken=Encrypted`. ☐

**C4 — Open a sealed file (authorized decrypt).**
- Action: `dlp-agent decrypt file.dlpenc -o out` on an endpoint whose keyring has
  the key.
- Expected: plaintext written, **audit incident recorded first**; a wrong/shredded
  key → `DecryptDenied`, nothing written, non-zero exit. ☐

## D. Clipboard  🟡 (audits by default — must be switched to block)

**D1 — Default is audit-only (verify the honest default).**
- Setup: `dlp-agent clipboard-monitor --enforce` with default `[clipboard]`.
- Action: copy sensitive text.
- Expected: **NOT blocked** (default `default_action="allow_audited"`); an audit
  incident only. ☐

**D2 — Turn on blocking.**
- Setup: `[clipboard] enabled=true`, `default_action="block"`, run
  `clipboard-monitor --enforce`.
- Action: copy sensitive text, then paste.
- Expected: clipboard is cleared; paste yields **"Copy blocked by DLP policy"**;
  `Match` incident (hashes/metadata only, never the text). ☐

## E. Network / web-upload egress  🟡

**E1 — WFP egress control (destination-based, content-blind).**
- ⚠️ **Allowlist the mgmt server first** (`192.168.1.3:8443` + DNS) or the agent
  bricks its own check-in.
- Setup: `dlp-agent net-monitor --enforce allowlist` (elevated) with rules
  permitting only sanctioned destinations.
- Action: try to reach a non-allowlisted destination; also launch a remote-access
  tool (AnyDesk/TeamViewer).
- Expected: non-permitted egress is blocked at connect; remote-tool processes are
  blocked/killed. *Incidents here are logged locally, not posted.* ☐

**E2 — Browser web-upload (content-aware).**
- Setup: load the MV3 browser extension + native host (`dlp-agent browser-host`);
  a detection bundle must be present.
- Action: attempt to upload the sensitive file via the browser.
- Expected: upload **cancelled** (`verdict=block`); a `web-upload` incident (url +
  hashes). *No bundle → fail-**open** (allows, audits) so the browser isn't
  bricked — verify this honestly.* ☐

## F. Encryption / sealing  🟢
Covered by **C3** (seal-on-write) and **C4** (decrypt). No standalone command —
sealing is automatic on `action="encrypt"` USB destinations; `decrypt` opens.

## G. Print  ⚪ NOT BUILT
There is **no** print/spooler monitoring in the product today. Do not test for a
print block; note it as a roadmap item.

## H. Console, incidents & audit  🟢

**H1 — Agent visibility.** Agents page shows this machine `active`, last check-in
recent, its group + delivered policy. ☐

**H2 — Incidents flow.** The blocks from §A–§C appear on the **Incidents** page
(metadata for `auditor`/`incident_reviewer`; full detail for `incident_reviewer`
with `incidents.read`). ☐

**H3 — Separation of duties.** Log in as `sysadmin` → you **cannot** read
incident evidence (403, audited). Log in as `auditor` → you **can** read the audit
log but not manage users. ☐

**H4 — Fail-secure.** Stop `agent-server` on the server. Re-run **A1** on the
endpoint → still **blocked** (agent enforces cached policy). Restart the server;
the queued incidents flush. ☐

---

# Part 3 — Sign-off sheet

| # | Test | Expected | Pass |
|---|---|---|---|
| A1 | untrusted read | READ-DENIED | ☐ |
| A2 | trusted read | allowed, no incident | ☐ |
| A3 | add publisher rule | app allowed after resync | ☐ |
| B1 | harness | 5/5 | ☐ |
| B2 | open-deny cached | DENIED ×3 | ☐ |
| B3 | monitor mode | allowed + incident | ☐ |
| B4 | per-group | monitor vs enforce | ☐ |
| C1 | USB sensitive write | blocked (kernel) | ☐ |
| C2 | device read-only/block | stick RO / dismounted | ☐ |
| C3 | seal-on-write | `.dlpenc`, plaintext gone | ☐ |
| C4 | decrypt | plaintext + audit; bad key denied | ☐ |
| D1 | clipboard default | audit-only (no block) | ☐ |
| D2 | clipboard block | cleared + notice | ☐ |
| E1 | net allowlist | non-permitted egress blocked | ☐ |
| E2 | web upload | cancelled (bundle present) | ☐ |
| H1–H4 | console/audit/fail-secure | as stated | ☐ |

---

# Appendix — honest posture (tell the customer)

| Channel | Default | Enforces when |
|---|---|---|
| Whitelisting + read-deny/open-deny | policy-driven | console `enforce` + driver + agent |
| USB content write | kernel-decided | service running + driver; blocks ≥0.15 containment |
| USB device control | dry-run | `usb-monitor --enforce` + `[usb] enabled` + admin |
| Encrypt-on-write | on `encrypt` dests | rule `action="encrypt"` + keyring |
| Clipboard | **audit only** | `enabled` + `--enforce` + `default_action="block"` |
| Network (WFP) | **monitor** | `--enforce allowlist/blocklist` (allowlist the server!) |
| Web upload | block if bundle, else **fail-open** | cached bundle present |
| Print | **not built** | — |

Clipboard and network are currently **standalone monitors**, not folded into the
`DLPAgent` service — run them explicitly for their tests. `[webupload]
trusted_origins` is parsed but not yet wired.
