# On-Premise Deployment & Handover Guide

How a customer stands up the DLP product **entirely on their own premises**, with
**no internet** and **no vendor access to their systems** — from a blank server to
protected endpoints. This is the runbook the vendor hands over with the software.

> **Handover model.** The vendor ships software + docs. The customer's admins run
> every step below. The customer's **internal CA is generated on the customer's own
> server** and never leaves it; the vendor never sees customer keys, data, policy,
> or incidents (data residency). Every feature works offline.

---

## 0. Pre-flight — what must be true before you start

| Requirement | Why | How |
|---|---|---|
| **Windows driver is Microsoft-signed** | Test-signed drivers won't load on a hardened/Secure-Boot endpoint. | Vendor completes `dlp-minifilter/docs/PRODUCTION-SIGNING.md` (attestation signing) **before** shipping. Lab/PoC may use test-signing + `bcdedit /set testsigning on`. |
| **PostgreSQL 17 available offline** | `docker compose up` pulls `postgres:17` from Docker Hub — a blocker on an air-gapped host. | Pre-seed the image (`docker save postgres:17 > pg17.tar` on a connected box → `docker load < pg17.tar` on-site), **or** install PostgreSQL 17 natively and just set `DATABASE_URL`. |
| **Node dependencies present** | Air-gapped sites can't `npm install`. | `node_modules/` is **vendored in the shipped server tree** — no install needed. Verify it's present. Node LTS runtime must be installed on the server host. |
| **Fresh secrets generated** | The shipped `.env`/compose carry dev placeholders. | Regenerate per install: DB password, `DLP_BLOB_MASTER_KEY`, `DLP_ORG_ROOT_KEY` (§2). Never reuse the samples. |
| **Console behind TLS** | The admin API (`bin/www`, port 3001) is plain HTTP. | Terminate TLS in front of it (reverse proxy) and set `NODE_ENV=production` so session cookies are `Secure`. The **agent** port (8443) is already mTLS. |
| **Licensing** | Phase-3 licence enforcement is **not built yet** — no licence file/dongle is required to run today. | Track for the licensing phase; nothing blocks deployment now. |

---

## Phase A — Vendor prepares the handover kit

The kit contains:

1. **Server tree** `dlp-management-server/` **with `node_modules/` vendored** (no
   install on-site).
2. **Agent binary** `dlp-agent.exe` (release build) + the **packaging scripts**
   (`packaging/build-package.ps1`, `install-endpoint.ps1`, `uninstall-endpoint.ps1`).
3. **Microsoft-signed driver** `dlpflt.sys` + `dlpflt.inf` + `dlpflt.cat`.
4. **PostgreSQL 17** offline image (or a note to install it natively).
5. **These runbooks** + `packaging/README-endpoint-install.md` +
   `dlp-management-server/docs/trusted-readers-starter-list.md`.

> The **agent package is finalized on the customer's side** (Phase D), because it
> bakes in the customer's CA — which doesn't exist until Phase B.

---

## Phase B — Customer stands up the management server

On the server host (customer premises). Run order:
`Postgres → migrate → init-ca → bootstrap-admin → start services`.

```bash
cd dlp-management-server

# 1. Database (offline image pre-loaded, or native PG17). Dev uses docker:
docker compose up -d               # Postgres 17, bound to 127.0.0.1:5432

# 2. Configure secrets in .env (regenerate ALL — see §2 below)
#    DATABASE_URL, DLP_BLOB_MASTER_KEY, DLP_ORG_ROOT_KEY, AGENT_SERVER_DNS ...

# 3. Schema (idempotent, tracked in schema_migrations)
npm run migrate                    # applies migrations/001..NNN

# 4. Internal CA — generates the customer's OWN root CA + agent-listener server cert
AGENT_SERVER_DNS=dlp.customer.local  npm run init-ca
#    -> writes ca/: ca-key.pem, ca-cert.pem, server-key.pem, server-cert.pem, ca-meta.json
#    Set CA_KEY_PASSPHRASE to encrypt the CA key at rest (recommended).

# 5. First sysadmin (the ONLY account made outside the console; no signup page)
npm run bootstrap-admin            # prompts email + password (min 12 chars)

# 6. Start the two listeners + the fingerprint worker (as services / pm2 / nssm)
npm run agent-server               # HTTPS mTLS for agents on :8443
npm start                          # console API on :3001 (put behind TLS)
npm run worker                     # processes fingerprint/index jobs
```

**Back up `ca/ca-key.pem` offline and securely.** It signs both agent certificates
and the detection-index bundles — losing it forces every agent to re-enroll.

### Server config (`.env`)

| Var | Required | Meaning |
|---|---|---|
| `DATABASE_URL` | ✅ | `postgres://dlp:<pw>@127.0.0.1:5432/dlp` |
| `DLP_BLOB_MASTER_KEY` | ✅ | 64 hex chars — AES-256-GCM key for the encrypted evidence/document blob store |
| `DLP_ORG_ROOT_KEY` | ✅ | 64 hex chars — root of the KEK hierarchy for encrypt-on-write; agent key delivery fails secure without it |
| `AGENT_SERVER_DNS` | rec | DNS/IP the agents dial — **must** be in the server cert SAN (init-ca puts it there) |
| `CA_KEY_PASSPHRASE` | rec | encrypts `ca-key.pem` at rest |
| `PORT` / `AGENT_PORT` | — | console 3001 / agent 8443 (defaults) |
| `NODE_ENV=production` | rec | makes console session cookies `Secure` |

Generate a 64-hex key: `node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"`

---

## Phase C — Customer configures policy (console)

Log in to the console as the sysadmin. All actions are RBAC-gated and audited
(append-only hash-chained log). Separation of duties: **sysadmin manages
users/config but cannot read incidents/evidence**; `policy_author` owns policy;
`incident_reviewer` reads incidents/evidence; `auditor` reads the audit log.

1. **Create staff accounts** — `POST /api/users` (sysadmin): a `policy_author`, an
   `incident_reviewer`, an `auditor`. No open signup ever.
2. **Register sensitive content** (as `policy_author`/`protect:write`):
   - **IDM (documents):** create a collection → upload classified documents
     (`POST /api/protected/collections`, then `POST /api/protected/documents`).
     The worker fingerprints them (content is encrypted at rest; never leaves).
   - **EDM (structured data):** define a source schema → upload the CSV
     (`POST /api/protected/edm-sources`, then `PUT .../data`). The worker
     salt-hashes the cells and **deletes the plaintext upload**.
   - **Compile the detection bundle:** `POST /api/protected/index/compile`. The
     worker builds a **CA-signed** `bundle-vN.dlpx`; agents fetch and
     signature-verify it over mTLS.
3. **Read-deny policy** (`policy_author`): set mode (off / monitor / enforce),
   fail-secure posture, and the fixed-volume scan scope. Global (id=1) plus
   optional per-group overrides.
4. **Trusted-reader allowlist** (`policy_author`): a spoof-resistant starter list
   ships seeded (Microsoft publishers + the agent path). Curate per
   `docs/trusted-readers-starter-list.md` — add the site's PDF viewer/browser/AV/
   backup by **publisher** where possible.
5. **Groups** (optional): create endpoint groups for staged rollout or
   department-specific policy; machines are assigned on the Agents page.
6. **Mint enrollment tokens** (sysadmin, `enrollment.manage`):
   `POST /api/enrollment-tokens` → a one-time `dlpenr_...` token (256-bit, ~72h
   default, shown once). One per batch/deployment wave.

---

## Phase D — Customer rolls out endpoints

On the customer's build/admin box:

```powershell
# Finalize the agent package WITH the customer's CA baked in
cd dlp-agent
powershell -ExecutionPolicy Bypass -File packaging\build-package.ps1
#   -> packaging\out\ : dlp-agent.exe, ca-cert.pem (customer CA), agent.toml, dlpflt.sys/.inf/.cat
```

On each endpoint (or pushed by **GPO / SCCM / Intune** — the machine-side step is
an automated installer parameter, not hand-typed CLI):

```powershell
powershell -ExecutionPolicy Bypass -File install-endpoint.ps1 `
    -Token "dlpenr_..." -Server "https://dlp.customer.local:8443" -PackageDir .\out
```

The installer (elevated, idempotent) installs the minifilter (auto-start),
provisions config + CA, **enrolls** (the agent generates its private key **locally**
and sends only a CSR — the key never leaves the endpoint), and starts the
**DLPAgent LocalSystem service**. The agent checks in over mTLS, downloads the
signed detection bundle + policy + allowlist, and begins enforcing. Read-deny mode
and scan scope flow **from console policy** — nothing is set by hand on the box.
See `packaging/README-endpoint-install.md`.

**Verify** an endpoint: `fltmc filters` shows `dlpflt`; `sc query DLPAgent` is
RUNNING; the machine appears on the console Agents page (`enrolled → active`).
Acceptance probes: `dlp-minifilter/tools/verify-read-deny.ps1` (see
`READ-DENY-TEST-MATRIX.md`).

---

## Phase E — Operate

- **Incidents & evidence:** `incident_reviewer` reviews incidents and reads/exports
  encrypted evidence (every access audited). Highest classifications can run
  metadata-only.
- **Audit:** `auditor` reads the append-only, hash-chained audit log.
- **Fail-secure:** if the server is unreachable or a licence lapses (once
  licensing ships), agents **keep enforcing cached policy**; admin actions are
  restricted rather than protection being switched off.
- **CA custody:** keep `ca-key.pem` backed up offline; rotate staff accounts and
  prune the trusted-reader list periodically.

---

## Known gaps (be honest with the customer)

1. **Licensing/seat-metering is not implemented** (Phase 3). The schema exists but
   there is no import/enforcement. Deployment works without it today.
2. **Offline dependency bundling is manual** — pre-seed the Postgres image (or
   install PG natively); `node_modules` is vendored but the Node runtime must be
   installed.
3. **Console API is plain HTTP** — must be fronted with TLS in production.
4. **No down-migrations / migration checksums** — migrations are forward-only.
5. **Production driver signing is an external step** (EV cert + Partner Center) —
   must be done before the kit ships (`PRODUCTION-SIGNING.md`).
