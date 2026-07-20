# On-Premise Endpoint DLP — Project Guide

## What this project is

We are building an on-premise **Data Leak Prevention (DLP)** product for Windows
endpoints, sold to defence/government/critical-infrastructure customers. It stops
sensitive data (classified documents, plans) leaving an organisation through its
employees' PCs (USB, email, web upload, cloud sync, print, clipboard).

Two components:

1. **Management server** (`dlp-management-server/`) — Node.js + Express + PostgreSQL.
   Runs on the customer's premises. It is the brain: internal certificate authority,
   policies, licence enforcement, incident + evidence storage, audit log, admin console.
   All agents connect to it; all PC incident reports land here.
2. **Windows agent** (not started yet) — will be written in **Rust**. Runs on every
   employee PC, enforces policy, reports incidents to the management server over mTLS.

The full design rationale is in `Docs/DLP_Engineering_Auth_Subscription.pdf`
(internal engineering guide). Read it before making architectural decisions.

## Non-negotiable product rules (from the guide)

- **Everything stays on the customer's premises.** The vendor never receives customer
  data (data residency). Every feature must work **with no internet access**
  (firewalled / air-gapped sites).
- **Authentication and authorization are two separate gates.** Never let "logged in"
  imply "allowed to".
- **Fail secure, not fail open.** If the licence lapses or the server is unreachable,
  agents keep enforcing cached policy; we restrict admin actions instead of
  switching protection off.
- **Sensitive data is encrypted and access-audited at every step.** Evidence blobs
  are AES-256 encrypted, stored outside the database, RBAC-gated, every access audited.
- **The audit log is append-only and tamper-evident** (hash-chained). Never add
  UPDATE/DELETE paths to it.
- **Secrets are never hard-coded or logged** (enrollment tokens, passwords, keys).
- **Never roll our own licence cryptography** — a licensing SDK (Wibu CodeMeter /
  Thales Sentinel) will handle signing, dongles, node-locking (Phase 3).
- Licence generation happens in a separate **back-office tool at the vendor** (not in
  this repo); the management server only verifies and enforces licences.

## Build phases (from the guide, §5) and current status

1. **Foundation** ← WE ARE HERE — Express server, PostgreSQL schema (auth +
   licensing tables only for now; policy/incident/evidence tables come as later
   migrations), local-account admin login (email + password), RBAC,
   tamper-evident audit log.
2. **Secure channel** — internal CA, agent enrollment (one-time token → client
   certificate), mutual TLS, agent check-in.
3. **Licensing** — licensing SDK integration, activation (online + offline file
   round-trip), seat metering, per-agent entitlement tokens, fail-secure behaviour.
4. **Evidence storage** — encrypted blob store, key management, retention,
   metadata-only mode for highest classifications, crypto-shredding.
5. **Dashboard & audit views** — incident feeds, drill-downs, licence consumption,
   reports.
6. **Hardening** — HSM, FIPS-validated crypto, offline update pipeline, pentest.

## RBAC model (four roles, separation of duties)

| Role | May do |
|---|---|
| `policy_author` | read/write policies |
| `incident_reviewer` | read incidents, read/export evidence (every access audited) |
| `auditor` | read audit log, read incident metadata, read licence state |
| `sysadmin` | manage users/roles, system config, licence import — **cannot read evidence** |

No open signup ever: the first sysadmin is created via a CLI command on the server box.
Flag (don't block) users holding role combinations that break separation of duties.

## Tech stack & repo layout

```
DLP_GUIDE/
  CLAUDE.md                    ← this file
  Docs/                        ← the engineering guide PDF
  dlp-management-server/       ← the Node/Express server (plain JS, CommonJS)
    app.js, bin/www            ← express-generator layout
    routes/                    ← Express routers
    docker-compose.yml         ← PostgreSQL 17 for development
    data/postgres/             ← bind-mounted DB files — NEVER commit, NEVER edit
```

- **Server:** plain JavaScript (CommonJS), Express 4, `pg` for PostgreSQL,
  `bcryptjs` for password hashing, `dotenv` for config. No ORM — hand-written SQL.
- **Keep the dependency tree small.** This ships to air-gapped defence sites; every
  npm package is supply-chain surface. Justify each new dependency.
- **Database (dev):** PostgreSQL 17 in Docker. `docker compose up -d` from
  `dlp-management-server/`. Container `dlp-server-postgres`, bound to
  `127.0.0.1:5432` only, db/user `dlp`, password in `docker-compose.yml` (dev only).
  Data persists in `data/postgres/` across container removal.
- Config/secrets go in `.env` (git-ignored), never in source.

## Commands

```bash
cd dlp-management-server
docker compose up -d      # start PostgreSQL (data persists in ./data/postgres)
npm start                 # run server with nodemon
```

## Conventions for code written here

- Two-gate pattern on every route: authenticate (session) first, then authorize
  (permission check middleware) — 401 vs 403 respectively; log denied attempts to
  the audit log.
- Every state-changing admin action writes an audit entry (actor, action, target,
  timestamp, prev_hash chain).
- Parameterised SQL only (`$1, $2…`) — never string-interpolate into queries.
- Don't log request bodies on auth routes (passwords) or anything containing
  enrollment tokens / session ids.
- Unrelated Docker artifacts exist on this machine (old `dlp-postgres` container,
  `Desktop/dlp` project) — leave them alone; ours is `dlp-server-postgres`.
