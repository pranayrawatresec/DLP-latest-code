'use strict';
// End-to-end harness for the IDM registration pipeline:
//
//   HTTP register (routes/protected.js) → encrypted blob (lib/blobStore.js)
//   → processing_jobs queue → worker (bin/fingerprint-worker.js)
//   → extract (lib/extractText.js) → fingerprint (lib/fingerprint.js)
//   → document_fingerprints rows → containment matching.
//
// Runs against the REAL dev database with the REAL Express app on an
// ephemeral port; the worker is spawned as a real child process in --once
// mode (it owns its own pool and calls pool.end()). Creates throwaway
// users/collections/documents and cleans them up. Audit rows are
// append-only and intentionally remain.
require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const pool = require('../db/pool');
const { containment } = require('../lib/fingerprint');
const { verifyChain } = require('../lib/audit');
const app = require('../app');

const SERVER_ROOT = path.join(__dirname, '..');
const WORKER = path.join(SERVER_ROOT, 'bin', 'fingerprint-worker.js');
const TAG = 'idmtest_' + crypto.randomBytes(4).toString('hex');
const PW = 'test-Password-123456';
const results = [];
let passed = 0;
let failed = 0;
let server;
let baseUrl;

async function check(id, name, fn) {
  try {
    const detail = (await fn()) || '';
    results.push({ id, name, status: 'PASS', detail: String(detail) });
    passed++;
    console.log(`  PASS  ${id}  ${name}`);
  } catch (err) {
    results.push({ id, name, status: 'FAIL', detail: err.message });
    failed++;
    console.log(`  FAIL  ${id}  ${name}\n        ${err.message}`);
  }
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'assertion failed');
}

async function makeUser(kind, roleName) {
  const email = `${TAG}_${kind}@test.local`;
  const hash = await bcrypt.hash(PW, 10);
  const u = await pool.query(
    `insert into admin_users (email, display_name, pw_hash) values ($1,$2,$3) returning id`,
    [email, `${TAG} ${kind}`, hash]
  );
  await pool.query(
    `insert into user_roles (user_id, role_id, granted_by)
     select $1, id, 'test' from roles where name = $2`,
    [u.rows[0].id, roleName]
  );
  return { id: u.rows[0].id, email };
}

// Real login → returns the session Cookie header value.
async function login(email) {
  const res = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: PW }),
  });
  assert(res.status === 200, `login failed for ${email}: ${res.status}`);
  const setCookie = res.headers.get('set-cookie') || '';
  const m = setCookie.match(/dlp_session=[^;]+/);
  assert(m, 'no session cookie returned');
  return m[0];
}

function api(pathname, { cookie, method = 'GET', body } = {}) {
  return fetch(`${baseUrl}${pathname}`, {
    method,
    headers: {
      ...(cookie ? { Cookie: cookie } : {}),
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
}

// Raw-binary document registration (the real client shape).
function registerDoc(cookie, collectionId, title, buffer, filename) {
  const q = `collectionId=${encodeURIComponent(collectionId)}&title=${encodeURIComponent(title)}`;
  return fetch(`${baseUrl}/api/protected/documents?${q}`, {
    method: 'POST',
    headers: {
      Cookie: cookie,
      'Content-Type': 'application/octet-stream',
      'X-Filename': filename,
    },
    body: buffer,
  });
}

// Spawn the real worker in --once mode; it drains all currently-eligible jobs.
function runWorkerOnce() {
  const r = spawnSync(process.execPath, [WORKER, '--once'], {
    cwd: SERVER_ROOT,
    encoding: 'utf8',
    timeout: 120000,
  });
  assert(r.status === 0, `worker exited ${r.status}: ${r.stderr}`);
  return r.stdout;
}

async function docRow(documentId) {
  const { rows } = await pool.query(
    `select id, status, failure_reason, current_version from protected_documents where id = $1`,
    [documentId]
  );
  assert(rows.length === 1, `document ${documentId} not found`);
  return rows[0];
}

async function fingerprintHashes(versionId) {
  const { rows } = await pool.query(
    `select hash from document_fingerprints where version_id = $1 order by seq`,
    [versionId]
  );
  return rows.map((r) => r.hash); // pg returns BIGINT as decimal strings
}

// ---------------------------------------------------------------------
// Test corpus: a deterministic ~50-sentence base document, plus a mutated
// copy (case/punctuation/whitespace churn + one extra paragraph) that IDM
// must still recognise with high containment.
// ---------------------------------------------------------------------
function baseText() {
  const sentences = [];
  for (let i = 1; i <= 50; i++) {
    sentences.push(
      `Section ${i}: the deployment plan requires unit ${i} to hold position ` +
        `alpha ${i} until the supply convoy clears checkpoint bravo ${i}.`
    );
  }
  return 'OPERATION PLAN (TEST DATA ONLY)\n\n' + sentences.join('\n');
}

function mutatedText() {
  // Case, punctuation, and whitespace changes normalize away in IDM;
  // one genuinely new paragraph is appended.
  return (
    baseText()
      .toUpperCase()
      .replace(/:/g, ' -- ')
      .replace(/\./g, ' !!\n')
      .replace(/ /g, '  ') +
    '\n\nAnnex Z: this paragraph exists only in the mutated copy and ' +
    'talks about entirely unrelated logistics rehearsal schedules.'
  );
}

async function main() {
  console.log('\nIDM registration pipeline — end-to-end suite\n');

  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;

  const author = await makeUser('author', 'policy_author');
  const auditor = await makeUser('auditor', 'auditor');
  const authorCookie = await login(author.email);
  const auditorCookie = await login(auditor.email);

  let collectionId;
  const docs = {}; // name -> { documentId, versionId }

  // ============ a. register through the HTTP routes ============
  await check('I01', 'POST collection as policy_author → 201', async () => {
    const res = await api('/api/protected/collections', {
      cookie: authorCookie,
      method: 'POST',
      body: { name: `${TAG} plans`, classification: 'secret', description: 'e2e test data' },
    });
    assert(res.status === 201, `status ${res.status}`);
    const j = await res.json();
    assert(j.id && j.name === `${TAG} plans`, 'bad collection body');
    collectionId = j.id;
    return `collection ${j.id.slice(0, 8)}`;
  });

  await check('I02', 'register .txt document → 202 pending, job queued', async () => {
    const res = await registerDoc(
      authorCookie, collectionId, 'Base Plan', Buffer.from(baseText(), 'utf8'), 'base-plan.txt'
    );
    assert(res.status === 202, `status ${res.status}`);
    const j = await res.json();
    assert(j.documentId && j.versionId && j.status === 'pending', JSON.stringify(j));
    docs.base = j;
    const doc = await docRow(j.documentId);
    assert(doc.status === 'pending', `doc status ${doc.status}`);
    const job = await pool.query(
      `select state, kind from processing_jobs where ref_id = $1`, [j.versionId]
    );
    assert(job.rows.length === 1, 'no job enqueued');
    assert(job.rows[0].state === 'queued' && job.rows[0].kind === 'fingerprint_document',
      `job ${JSON.stringify(job.rows[0])}`);
    return '202, pending, fingerprint_document queued';
  });

  await check('I03', 'register .docx fixture → 202 pending', async () => {
    const docx = fs.readFileSync(path.join(__dirname, 'fixtures', 'extract', 'sample.docx'));
    const res = await registerDoc(authorCookie, collectionId, 'Docx Plan', docx, 'sample.docx');
    assert(res.status === 202, `status ${res.status}`);
    docs.docx = await res.json();
    assert(docs.docx.status === 'pending', 'not pending');
    return `202, version ${docs.docx.versionId.slice(0, 8)}`;
  });

  // c-setup. Mutated copy registered BEFORE the worker run so one --once
  // pass drains all three readable documents.
  await check('I04', 'register mutated copy as a second document → 202', async () => {
    const res = await registerDoc(
      authorCookie, collectionId, 'Mutated Plan',
      Buffer.from(mutatedText(), 'utf8'), 'mutated-plan.txt'
    );
    assert(res.status === 202, `status ${res.status}`);
    docs.mutated = await res.json();
    return `202, version ${docs.mutated.versionId.slice(0, 8)}`;
  });

  // d-setup. Random bytes under a .docx name — unreadable (corrupt-container).
  await check('I05', 'register random bytes named .docx → 202 (fails later)', async () => {
    const res = await registerDoc(
      authorCookie, collectionId, 'Broken Doc', crypto.randomBytes(4096), 'broken.docx'
    );
    assert(res.status === 202, `status ${res.status}`);
    docs.broken = await res.json();
    return `202, version ${docs.broken.versionId.slice(0, 8)}`;
  });

  // ============ b. worker → ready + fingerprints ============
  await check('I06', 'worker --once: .txt and .docx documents reach ready', async () => {
    runWorkerOnce();
    const base = await docRow(docs.base.documentId);
    const docx = await docRow(docs.docx.documentId);
    assert(base.status === 'ready', `base status ${base.status} (${base.failure_reason})`);
    assert(docx.status === 'ready', `docx status ${docx.status} (${docx.failure_reason})`);
    assert(base.current_version === 1 && docx.current_version === 1, 'current_version not set');
    return 'both ready, current_version 1';
  });

  await check('I07', 'document_fingerprints rows exist for both versions (count > 0)', async () => {
    const baseHashes = await fingerprintHashes(docs.base.versionId);
    const docxHashes = await fingerprintHashes(docs.docx.versionId);
    assert(baseHashes.length > 0, 'no fingerprints for .txt version');
    assert(docxHashes.length > 0, 'no fingerprints for .docx version');
    const jobs = await pool.query(
      `select state from processing_jobs where ref_id in ($1, $2)`,
      [docs.base.versionId, docs.docx.versionId]
    );
    assert(jobs.rows.every((r) => r.state === 'done'), 'jobs not done');
    return `txt ${baseHashes.length}, docx ${docxHashes.length} fingerprints; jobs done`;
  });

  // ============ c. containment(original, mutated) > 0.9 ============
  await check('I08', 'containment(original, mutated) > 0.9 from DB fingerprint sets', async () => {
    const mut = await docRow(docs.mutated.documentId);
    assert(mut.status === 'ready', `mutated status ${mut.status} (${mut.failure_reason})`);
    const a = await fingerprintHashes(docs.base.versionId);
    const b = await fingerprintHashes(docs.mutated.versionId);
    assert(a.length > 0 && b.length > 0, 'empty fingerprint set');
    const c = containment(a, b);
    assert(c > 0.9, `containment ${c.toFixed(3)} <= 0.9`);
    return `containment ${c.toFixed(3)} (${a.length} vs ${b.length} hashes)`;
  });

  // ============ d. unreadable file → retries exhausted → failed ============
  await check('I09', 'unreadable .docx: job retries then fails; document failed with reason code', async () => {
    // First worker pass already failed it once (attempt 1) and requeued with
    // 10s/20s linear backoff. Zero the backoff via SQL between passes so the
    // test doesn't sleep — the retry PATH itself is exercised for real.
    for (let pass = 2; pass <= 3; pass++) {
      const bumped = await pool.query(
        `update processing_jobs set run_after = now()
          where ref_id = $1 and state = 'queued' returning attempts`,
        [docs.broken.versionId]
      );
      assert(bumped.rows.length === 1, `job not requeued before pass ${pass}`);
      assert(bumped.rows[0].attempts === pass - 1, `attempts ${bumped.rows[0].attempts} before pass ${pass}`);
      runWorkerOnce();
    }
    const job = await pool.query(
      `select state, attempts, last_error from processing_jobs where ref_id = $1`,
      [docs.broken.versionId]
    );
    assert(job.rows[0].state === 'failed', `job state ${job.rows[0].state}`);
    assert(job.rows[0].attempts === 3, `attempts ${job.rows[0].attempts}`);
    const doc = await docRow(docs.broken.documentId);
    assert(doc.status === 'failed', `doc status ${doc.status}`);
    assert(doc.failure_reason === 'corrupt-container',
      `failure_reason ${JSON.stringify(doc.failure_reason)}`);
    return `3 attempts, job failed, reason 'corrupt-container'`;
  });

  // ============ e. RBAC gates ============
  await check('I10', 'auditor (no protect:write) POST → 403 and denial audited', async () => {
    const res = await api('/api/protected/collections', {
      cookie: auditorCookie,
      method: 'POST',
      body: { name: `${TAG} sneaky`, classification: 'secret' },
    });
    assert(res.status === 403, `expected 403, got ${res.status}`);
    const denied = await pool.query(
      `select 1 from audit_log where action = 'authz.denied' and actor = $1
         and detail->>'required' = 'protect:write' limit 1`,
      [auditor.email]
    );
    assert(denied.rows.length === 1, 'denial not audited');
    return '403 + authz.denied logged';
  });

  await check('I11', 'unauthenticated register → 401', async () => {
    const col = await fetch(`${baseUrl}/api/protected/collections`, { method: 'POST' });
    assert(col.status === 401, `collections → ${col.status}`);
    const doc = await registerDoc('', collectionId, 'Anon', Buffer.from('x'), 'x.txt');
    assert(doc.status === 401, `documents → ${doc.status}`);
    return 'both endpoints 401';
  });

  await check('I12', 'auditor CAN read the registry (protect:read), metadata only', async () => {
    const res = await api(`/api/protected/documents?collectionId=${collectionId}`, {
      cookie: auditorCookie,
    });
    assert(res.status === 200, `status ${res.status}`);
    const list = await res.json();
    assert(list.length === 4, `expected 4 documents, got ${list.length}`);
    const text = JSON.stringify(list);
    assert(!text.includes('blob_ref') && !text.includes(baseText().slice(0, 40)),
      'list leaked blob refs or content');
    return `${list.length} documents, metadata only`;
  });

  // ============ independent invariants ============
  await check('I13', 'register + collection-create actions audited; chain intact', async () => {
    const c = await pool.query(
      `select count(*)::int n from audit_log
        where action = 'protected_document.register' and actor = $1`,
      [author.email]
    );
    assert(c.rows[0].n === 4, `register audits ${c.rows[0].n}`);
    const broken = await verifyChain();
    assert(broken === null, `chain broken at seq ${broken}`);
    return `4 register audits, AUDIT CHAIN INTACT`;
  });

  // ---- cleanup (audit rows are append-only and remain) ----
  const versions = await pool.query(
    `select v.id, v.blob_ref from document_versions v
      join protected_documents d on d.id = v.document_id
     where d.collection_id = $1`,
    [collectionId]
  );
  for (const v of versions.rows) {
    await pool.query('delete from processing_jobs where ref_id = $1', [v.id]);
    // Blob files are outside the DB — remove this run's encrypted blobs too.
    try {
      fs.rmSync(path.join(SERVER_ROOT, 'data', 'blobs', ...v.blob_ref.split('/')), { force: true });
    } catch {}
  }
  await pool.query(
    `delete from document_versions where document_id in
       (select id from protected_documents where collection_id = $1)`,
    [collectionId] // fingerprints cascade with their version
  );
  await pool.query('delete from protected_documents where collection_id = $1', [collectionId]);
  await pool.query('delete from protected_collections where id = $1', [collectionId]);
  await pool.query(`delete from admin_users where email like $1`, [`${TAG}_%@test.local`]);
  await new Promise((r) => server.close(r));

  console.log(`\n${passed} passed, ${failed} failed, ${results.length} total\n`);
  fs.writeFileSync(
    path.join(__dirname, '.idm-results.json'),
    JSON.stringify({ generatedAt: new Date().toISOString(), passed, failed, results }, null, 2)
  );
  await pool.end();
  process.exit(failed === 0 ? 0 : 1);
}

main().catch(async (err) => {
  console.error(err);
  try { await pool.query(`delete from admin_users where email like $1`, [`${TAG}_%@test.local`]); } catch {}
  process.exit(1);
});
