# Manual Test Guide — Content Detection Pipeline (IDM + EDM)

This walks the **entire detection pipeline by hand**: register protected content →
server fingerprints it → compile a signed index bundle → the real Rust agent scans
files against it → evasion attempts are caught → an incident round-trips back to a
reviewer with page-level forensics. Every step says *what happens under the hood*,
*what you should see*, and *how to verify it really happened*.

The automated equivalent of this whole guide is `npm run e2e:detection` (7 checks).
Unit suites: `test:fingerprint`, `test:extract`, `test:blobstore`, `test:idm`,
`test:edm`, `test:bundle`.

---

## 0. What you are testing

```
 policy_author (HTTP, cookie session :3000)          Rust agent (dlp-agent.exe)
 ─────────────────────────────────────────           ─────────────────────────
 register document / EDM CSV                          scan --bundle --file
        │ 202 (async)                                        │
        ▼                                                    ▼
 encrypted blob store (AES-256-GCM)                   extract → normalize
        │                                             → shingle k=8 → FNV-1a
        ▼                                             → winnow w=8 → lookup
 processing_jobs (Postgres SKIP LOCKED queue)                │
        │  npm run worker                                    ▼
        ▼                                             verdict JSON (IDM containment,
 extract → canonicalize → shingle → winnow            EDM rows, unreadable reason)
        │                                                    │ --report (mTLS :8443)
        ▼                                                    ▼
 document_fingerprints / edm_hashes                   detection_incidents
        │  POST /index/compile                               │
        ▼                                                    ▼
 signed .dlpx bundle (data/index/)  ──────────▶       incident_reviewer resolves
 (check-in advertises it, GET /agent/index)           matched seq ranges + title
```

Prerequisites (already true on the dev box): `dlp-server-postgres` container up,
`npm run migrate` applied (4 migrations), CA initialized (`ca/ca-cert.pem` exists),
`.env` contains `DLP_BLOB_MASTER_KEY`, agent built (`cargo build --release` in
`dlp-agent/`).

---

## 1. Start the three server processes

Three terminals in `dlp-management-server/`:

| Terminal | Command | What it is |
|---|---|---|
| T1 | `npm start` | Console API on **:3000**. Cookie-session admin API — humans only. |
| T2 | `npm run agent-server` | mTLS listener on **:8443**. Certificate-authenticated — agents only. Serves enroll, check-in, `GET /agent/index`, `POST /agent/incidents`. |
| T3 | `npm run worker` | The pipeline worker. Polls `processing_jobs` every 2s with `FOR UPDATE SKIP LOCKED`; runs extraction, fingerprinting, EDM ingestion, and bundle compilation. Logs exactly one line per job (ids + status, never content). |

> If T3 is not running, registrations sit at `pending` forever — that is the
> most common "it's broken" during manual testing.

---

## 2. Accounts — why you need two logins

RBAC is deliberately split (separation of duties):

- **`policy_author`** holds `protect:write` — the only role that can register
  protected content or trigger a compile. **`sysadmin` cannot.**
- **`incident_reviewer`** reads incidents.
- **`auditor`** reads the audit log.

Create a policy_author (once) using a sysadmin session:

```powershell
$sa = $null
Invoke-RestMethod -SessionVariable sa -Method Post http://localhost:3000/api/auth/login `
  -ContentType 'application/json' -Body '{"email":"<sysadmin email>","password":"<password>"}'

Invoke-RestMethod -WebSession $sa -Method Post http://localhost:3000/api/users `
  -ContentType 'application/json' `
  -Body '{"email":"author@resecsystems.io","password":"Author-Pass-12345","roles":["policy_author"]}'
```

Then log in as the author — the `$pa` session drives sections 3–6:

```powershell
$pa = $null
Invoke-RestMethod -SessionVariable pa -Method Post http://localhost:3000/api/auth/login `
  -ContentType 'application/json' -Body '{"email":"author@resecsystems.io","password":"Author-Pass-12345"}'
```

**Negative test now, while you have the sysadmin session:** repeat any
`/api/protected/...` POST with `$sa` → expect **403**, and the denial appears in
the audit log (section 8). No session at all → **401**. That's the two-gate
pattern working.

---

## 3. Register a protected document (the IDM pipeline)

### 3.1 Create a collection

```powershell
$col = Invoke-RestMethod -WebSession $pa -Method Post http://localhost:3000/api/protected/collections `
  -ContentType 'application/json' `
  -Body '{"name":"Army Operations","classification":"secret","description":"manual test"}'
```

Expect `201` with an id. Policies will later reference collections, not files.

### 3.2 Register a document

Use any real `.docx`, `.pdf` (text layer), `.txt`, `.xlsx`, or `.pptx`:

```powershell
Invoke-RestMethod -WebSession $pa -Method Post `
  "http://localhost:3000/api/protected/documents?collectionId=$($col.id)&title=Deployment Order" `
  -InFile "C:\path\to\DeploymentOrder.docx" -ContentType 'application/octet-stream' `
  -Headers @{ 'X-Filename' = 'DeploymentOrder.docx' }
```

Expect **202** `{ documentId, versionId, status: "pending" }` — the API returns
immediately; heavy work is async.

**What just happened, in one transaction:** the raw bytes were SHA-256'd and
written to the **encrypted blob store** (`data/blobs/<shard>/<uuid>`, AES-256-GCM,
per-blob key wrapped by `DLP_BLOB_MASTER_KEY`); rows were inserted into
`protected_documents` (status `pending`) and `document_versions` (v1); a
`fingerprint_document` job was queued; an audit entry was written (title only —
never content).

### 3.3 Watch the worker process it

T3 prints the job line. The document status walks
`pending → extracting → fingerprinting → ready`:

- **extracting** — format-bounded text extraction (docx/xlsx/pptx are unzipped
  and text nodes pulled; pdf text layer via pdf-parse; encrypted or unknown
  formats fail with a reason code).
- **fingerprinting** — canonicalization (Unicode NFKC → lowercase → punctuation
  runs collapse to single spaces → word tokens), **k=8 word shingles**, 64-bit
  **FNV-1a** rolling hash per shingle, **winnowing w=8** (keep the window
  minimum, rightmost tie-break) — ~22% of shingle hashes survive as the
  document's fingerprint set, stored with positions.

### 3.4 Verify

```powershell
Invoke-RestMethod -WebSession $pa "http://localhost:3000/api/protected/documents?collectionId=$($col.id)"
```

Expect `status: "ready"` and a nonzero fingerprint count. See the actual
fingerprints (hash + position) in the DB:

```powershell
docker exec dlp-server-postgres psql -U dlp -d dlp -c `
  "select count(*), min(seq), max(seq) from document_fingerprints;"
```

**Failure-path test:** register 4 KB of random bytes named `.docx` → after 3
worker retries the document lands at `status: "failed"` with a machine reason
code (e.g. `corrupt-container`), never a stack trace of content.

**Versioning test:** re-register a different file under the *same title in the
same collection* → a **v2** row appears; v1 stays matchable until retired.

---

## 4. Register an EDM source (structured data)

### 4.1 Declare the schema, then upload the CSV

```powershell
$src = Invoke-RestMethod -WebSession $pa -Method Post http://localhost:3000/api/protected/edm-sources `
  -ContentType 'application/json' -Body (@'
{"name":"Personnel","schema":[
  {"name":"full_name","type":"text","primary":true},
  {"name":"service_no","type":"id","primary":true},
  {"name":"unit","type":"text","primary":false}]}
'@)

@'
full_name,service_no,unit
Rajesh Sharma,SVC100001,Leh Sector
Priya Nair,SVC100002,Northern Command
Arun Mehta,SVC100003,Leh Sector
'@ | Set-Content -Encoding utf8 personnel.csv

Invoke-RestMethod -WebSession $pa -Method Put `
  "http://localhost:3000/api/protected/edm-sources/$($src.id)/data" `
  -InFile personnel.csv -ContentType 'text/csv'
```

**Under the hood:** source creation generates a random 32-byte salt. The worker
normalizes every cell by its declared type (text → same canonicalizer as IDM;
id → strip separators, uppercase; number → canonical digits; date → ISO), hashes
each as `SHA-256(salt ‖ field_id ‖ value)` truncated to 64 bits, bulk-inserts
into `edm_hashes` — and then **deletes the plaintext CSV blob from disk**. The
server keeps only irreversible hashes.

### 4.2 Verify

- `GET /api/protected/edm-sources` → `status: "ready"`, `row_count: 3`, and note
  the response **never contains the salt or any hash**.
- Plaintext really gone: `Get-ChildItem data\blobs -Recurse` — the CSV's blob
  file no longer exists.
- `docker exec ... "select count(*) from edm_hashes;"` → 9 (3 rows × 3 fields).

---

## 5. Compile the signed index bundle

```powershell
Invoke-RestMethod -WebSession $pa -Method Post http://localhost:3000/api/protected/index/compile
```

The worker gathers every `ready` document version + EDM source and writes a
versioned **`.dlpx`** file to `data/index/`:
`magic → JSON header (params k/w, docs table, EDM schemas + salts) → Bloom filter
→ sorted IDM hash section → sorted EDM hash section → RSA-SHA256 signature by
the management CA`. Format spec: `docs/index-bundle-format.md`.

Verify: the file exists, and `index_bundles` has a new row with its sha256.
Note what's **not** in it: no text, no filenames of content, no plaintext
EDM values — hashes only. This is the only artifact endpoints ever receive.

---

## 6. Scan with the real agent — the evasion gauntlet

### 6.1 Point the binary at the bundle (quick path, no enrollment)

```powershell
cd C:\Users\lianli\Downloads\DLP_GUIDE\dlp-agent
$env:DLP_AGENT_SERVER_URL = "https://localhost:8443"
$env:DLP_AGENT_CA_CERT    = "..\dlp-management-server\ca\ca-cert.pem"
$env:DLP_AGENT_STATE_DIR  = "$env:TEMP\dlp-agent-state"
$bundle = (Get-ChildItem ..\dlp-management-server\data\index\*.dlpx |
           Sort-Object LastWriteTime | Select-Object -Last 1).FullName

.\target\release\dlp-agent.exe scan --bundle $bundle --file "C:\path\to\suspect-file" --json
```

The agent **verifies the bundle's CA signature before loading it** — corrupt one
byte of a copy and scan refuses it (fail secure; try it).

### 6.2 The test matrix — make copies of your registered document and try to sneak them past

| # | Evasion attempt | Expected verdict |
|---|---|---|
| 1 | Exact copy, renamed `MeetingNotes.docx` | IDM match, containment ≈ 1.0 — filenames are never fingerprinted |
| 2 | Open in Word, Save-As different format / change fonts, margins | containment ≈ 1.0 — formatting is stripped by canonicalization |
| 3 | Add blank lines, change case, swap punctuation | > 0.95 — NFKC + punctuation collapse absorbs it |
| 4 | Append a new paragraph (logo text, "for discussion only") | > 0.9 — original shingles all still present |
| 5 | Delete a page / ~25% of content | 0.6–0.9 — containment measures *how much of the protected doc remains* |
| 6 | Copy 3 paragraphs into a fresh document | proportional containment, correct source doc identified |
| 7 | Full rewrite in your own words | < 0.2 — **expected miss**; that's the future semantic layer's job |
| 8 | Text file containing `Rajesh Sharma ... SVC100001` | EDM fires: source Personnel, row 1, fields `[full_name, service_no]` — two fields of the same row within the proximity window |
| 9 | Only the name, *or* only the service number | no EDM hit — single field below `min_fields: 2` threshold (false-positive control) |
| 10 | Fields from *different* rows (Rajesh + SVC100002) | no EDM hit — same-row rule |
| 11 | Unrelated document (recipe, news article) | empty verdict: zero IDM, zero EDM |
| 12 | Password-protected zip / encrypted office file | `extraction: unreadable, reason: encrypted-container` — the fail-secure hook a policy will turn into *block* |

Read the `--json` output: `idm[]` carries `versionId`, `title`, `containment`,
`coverage`, `matchedHashes`; `edm[]` carries source, `rowId`, field names.

---

## 7. The full distribution + incident loop (enrolled path)

This proves the production path: bundle travels over mTLS, verdict comes back as
an incident.

1. As sysadmin: `POST /api/enrollment-tokens` → copy the one-time token.
2. ```powershell
   $env:DLP_AGENT_TOKEN = "<token>"
   .\target\release\dlp-agent.exe once           # enroll: CSR → CA-signed client cert; first check-in
   .\target\release\dlp-agent.exe index-update   # check-in sees index.latest → downloads via GET /agent/index
                                                 # → verifies signature → atomically swaps state-dir index.dlpx
   .\target\release\dlp-agent.exe scan --bundle "$env:DLP_AGENT_STATE_DIR\index.dlpx" `
     --file "C:\path\to\MeetingNotes.docx" --json --report --channel usb-audit
   ```
3. `--report` POSTs the verdict to `/agent/incidents` over mTLS (client cert =
   agent identity — no shared secrets).
4. As an **incident_reviewer**:
   ```powershell
   Invoke-RestMethod -WebSession $rev http://localhost:3000/api/incidents
   Invoke-RestMethod -WebSession $rev http://localhost:3000/api/incidents/<id>
   ```
   The detail resolves `matchedHashes` against the server's stored positions →
   `resolved_json` shows **which document, which version, containment, and the
   matched seq ranges** — the "pages 17–19" forensic story. The agent never had
   positions; only the server can produce this.

---

## 8. Audit trail check

As auditor (or any role with audit read): `GET /api/audit`. You should find,
hash-chained in order: `user.create`, `protected_collection.create`,
`protected_document.register`, `edm_source.create`, `edm_source.ingest`, the
compile trigger, `incident.read` — and the **403 denials** from section 2.
Registering documents changed the fleet's screening behaviour; the log proves
who did it and when.

---

## 9. Troubleshooting

| Symptom | Cause |
|---|---|
| Document stuck at `pending` | Worker (T3) not running |
| 401 on everything | Session cookie missing — use `-WebSession`, not fresh calls |
| 403 on `/api/protected` POSTs | Logged in as sysadmin/auditor — needs `policy_author` |
| `DLP_BLOB_MASTER_KEY` error at startup | `.env` missing the key |
| Agent scan: signature/parse error | Bundle file truncated or tampered — recompile / recopy |
| `scan` can't load CA | `DLP_AGENT_CA_CERT` must point at `dlp-management-server/ca/ca-cert.pem` |
| EDM never fires | Check field normalization types match the data; 2-field same-row proximity rule; text cells match only up to 4-word values |

Known limits (by design, documented in `docs/fingerprinting.html`): scanned/image
PDFs need the future OCR phase; full paraphrase needs the semantic layer; the
bundle is signed but not yet encrypted at rest on the agent.
