'use strict';
// EDM authoring suite (fingerprinting doc §4, Step 3):
//
//   unit: typed normalization (lib/edm.js normalizeField), salted hashing
//   (hashField vs an independent inline SHA-256 implementation), CSV parser
//   edge cases — then end-to-end: HTTP source registration + CSV upload
//   (routes/protected.js) → processing_jobs → worker 'ingest_edm_source'
//   (bin/fingerprint-worker.js) → edm_hashes rows, with the temporary
//   upload blob PROVABLY deleted from disk (plaintext is not retained).
//
// Runs against the REAL dev database with the REAL Express app on an
// ephemeral port; the worker is spawned as a real child process in --once
// mode. Creates throwaway users/sources and cleans them up. Audit rows are
// append-only and intentionally remain.
require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const pool = require('../db/pool');
const { normalizeField, hashField, parseCsv, ingestCsv } = require('../lib/edm');
const app = require('../app');

const SERVER_ROOT = path.join(__dirname, '..');
const WORKER = path.join(SERVER_ROOT, 'bin', 'fingerprint-worker.js');
const TAG = 'edmtest_' + crypto.randomBytes(4).toString('hex');
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

// Raw CSV upload (the real client shape).
function putCsv(cookie, sourceId, csvText) {
  return fetch(`${baseUrl}/api/protected/edm-sources/${sourceId}/data`, {
    method: 'PUT',
    headers: { Cookie: cookie, 'Content-Type': 'text/csv' },
    body: Buffer.from(csvText, 'utf8'),
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

async function sourceRow(id) {
  const { rows } = await pool.query(
    `select id, salt_hex, temp_blob_ref, row_count, status, failure_reason
       from edm_sources where id = $1`,
    [id]
  );
  assert(rows.length === 1, `edm source ${id} not found`);
  return rows[0];
}

function blobPath(ref) {
  return path.join(SERVER_ROOT, 'data', 'blobs', ...ref.split('/'));
}

// Independent hash implementation for the vectors: builds the whole message
// buffer by hand and converts hex → signed BigInt via two's complement,
// deliberately NOT sharing any code path with lib/edm.js hashField.
function independentHash(saltHex, fieldId, value) {
  const message = Buffer.concat([
    Buffer.from(saltHex, 'hex'),
    Buffer.from([(fieldId >> 8) & 0xff, fieldId & 0xff]),
    Buffer.from(value, 'utf8'),
  ]);
  const hex = crypto.createHash('sha256').update(message).digest('hex');
  let v = BigInt('0x' + hex.slice(0, 16));
  if (v >= 2n ** 63n) v -= 2n ** 64n; // two's complement → signed
  return v;
}

// ---------------------------------------------------------------------
// Test dataset: small personnel export. Row 2 has an empty rank cell and
// row 4 has an unparseable date — both cells must be skipped, so the
// expected hash count is rows×fields minus those two.
// ---------------------------------------------------------------------
const SCHEMA = [
  { name: 'full_name', type: 'text', primary: true },
  { name: 'service_no', type: 'id', primary: true },
  { name: 'rank', type: 'text', primary: false },
  { name: 'salary', type: 'number', primary: false },
  { name: 'dob', type: 'date', primary: false },
];
const CSV_V1 =
  'full_name,service_no,rank,salary,dob\r\n' +
  '"Smith, John",AB-12345,Corporal,"52,300.50",14/03/1988\r\n' +
  'Jane Doe,cd 67890,,61000,1990-07-02\r\n' +
  '"O""Brien, Pat",EF.11111,Major,"70,250",5 Mar 1979\r\n' +
  'Sam Low,GH-22222,Sergeant,48000,notadate\r\n';
const CSV_V1_ROWS = 4;
const CSV_V1_HASHES = 4 * 5 - 2; // one empty rank + one unparseable dob

const CSV_V2 =
  'full_name,service_no,rank,salary,dob\n' +
  'Alex Rees,ZZ-90000,Captain,55000,01/01/1985\n';

async function main() {
  console.log('\nEDM authoring — unit + end-to-end suite\n');

  // ============ unit: typed normalization ============
  await check('E01', 'normalizeField text reuses the IDM canonicalisation', async () => {
    assert(normalizeField('  Smith,   JOHN!! ', 'text') === 'smith john', 'punctuation/case');
    assert(normalizeField('Ｆｕｌｌ－Ｗｉｄｔｈ', 'text') === 'full width', 'NFKC fold');
    assert(normalizeField('', 'text') === null, 'empty → null');
    assert(normalizeField('!!!', 'text') === null, 'punctuation-only → null');
    return 'case/punct/NFKC fold to fingerprint.normalize canonical form';
  });

  await check('E02', 'normalizeField id strips non-alphanumerics, uppercases', async () => {
    assert(normalizeField('ab-12 34', 'id') === 'AB1234', 'separators stripped');
    assert(normalizeField('  ef.11111 ', 'id') === 'EF11111', 'dots stripped');
    assert(normalizeField('--- ---', 'id') === null, 'no alphanumerics → null');
    return 'AB1234 / EF11111 / null';
  });

  await check('E03', 'normalizeField number canonical digit string', async () => {
    assert(normalizeField('52,300.50', 'number') === '52300.5', 'grouping + trailing zero');
    assert(normalizeField('007', 'number') === '7', 'leading zeros');
    assert(normalizeField('61000', 'number') === '61000', 'plain int unchanged');
    assert(normalizeField('-0', 'number') === '0', 'negative zero');
    assert(normalizeField('1 234 567', 'number') === '1234567', 'space grouping');
    assert(normalizeField('12a4', 'number') === null, 'garbage → null');
    return 'grouping stripped, no leading zeros, decimal kept';
  });

  await check('E04', 'normalizeField date: 4 accepted formats + unparseable → null', async () => {
    assert(normalizeField('14/03/1988', 'date') === '1988-03-14', 'dd/mm/yyyy');
    assert(normalizeField('14-03-1988', 'date') === '1988-03-14', 'dd-mm-yyyy');
    assert(normalizeField('1988-03-14', 'date') === '1988-03-14', 'yyyy-mm-dd');
    assert(normalizeField('5 Mar 1979', 'date') === '1979-03-05', 'dd Mon yyyy');
    assert(normalizeField('notadate', 'date') === null, 'garbage → null');
    assert(normalizeField('31/02/2001', 'date') === null, 'impossible day → null');
    assert(normalizeField('14/13/1988', 'date') === null, 'month 13 → null');
    return 'all four formats → ISO; junk/impossible dates → null';
  });

  // ============ unit: salted hash vs independent implementation ============
  await check('E05', 'hashField matches 2 independently computed vectors', async () => {
    const saltHex = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
    const salt = Buffer.from(saltHex, 'hex');
    const v1 = hashField(salt, 0, 'smith john');
    const e1 = independentHash(saltHex, 0, 'smith john');
    assert(v1 === e1, `vector 1: ${v1} !== ${e1}`);
    const v2 = hashField(salt, 259, '1988-03-14'); // fieldId > 255 exercises the high byte
    const e2 = independentHash(saltHex, 259, '1988-03-14');
    assert(v2 === e2, `vector 2: ${v2} !== ${e2}`);
    assert(typeof v1 === 'bigint' && BigInt.asIntN(64, v1) === v1, 'not a signed 64-bit BigInt');
    assert(v1 !== hashField(salt, 1, 'smith john'), 'fieldId not bound into hash');
    return `${v1} / ${v2} (both match independent SHA-256 computation)`;
  });

  // ============ unit: CSV parser edge cases ============
  await check('E06', 'CSV parser: quotes, embedded commas/quotes/newlines, CRLF', async () => {
    const rows = parseCsv('a,b,c\r\n"x,y","he said ""hi""","line1\nline2"\r\nplain,,end\r\n');
    assert(rows.length === 3, `rows ${rows.length}`);
    assert(rows[1][0] === 'x,y', 'embedded comma');
    assert(rows[1][1] === 'he said "hi"', 'escaped quotes');
    assert(rows[1][2] === 'line1\nline2', 'embedded newline');
    assert(rows[2][1] === '', 'empty cell preserved');
    let threw = false;
    try { parseCsv('a,"unterminated\nb,c'); } catch { threw = true; }
    assert(threw, 'unterminated quote did not throw');
    return '3 rows parsed; unterminated quote throws';
  });

  await check('E07', 'ingestCsv: header must match schema; empty/null cells skipped', async () => {
    const salt = crypto.randomBytes(32);
    const { entries, rowCount } = ingestCsv(CSV_V1, SCHEMA, salt);
    assert(rowCount === CSV_V1_ROWS, `rowCount ${rowCount}`);
    assert(entries.length === CSV_V1_HASHES, `entries ${entries.length}, expected ${CSV_V1_HASHES}`);
    assert(!entries.some((e) => e.rowId === 2 && e.fieldId === 2), 'empty rank not skipped');
    assert(!entries.some((e) => e.rowId === 4 && e.fieldId === 4), 'bad dob not skipped');
    let err = null;
    try { ingestCsv('wrong,header\n1,2\n', SCHEMA, salt); } catch (e) { err = e; }
    assert(err && err.reason === 'csv-header-mismatch', `header mismatch: ${err && err.reason}`);
    return `${rowCount} rows, ${entries.length} hashes; header mismatch rejected`;
  });

  // ============ end-to-end ============
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;

  const author = await makeUser('author', 'policy_author');
  const auditor = await makeUser('auditor', 'auditor');
  const authorCookie = await login(author.email);
  const auditorCookie = await login(auditor.email);

  let sourceId;
  let firstBlobFile; // absolute path of the v1 upload blob — must be deleted

  await check('E08', 'POST /edm-sources as policy_author → 201, no salt in response', async () => {
    const res = await api('/api/protected/edm-sources', {
      cookie: authorCookie,
      method: 'POST',
      body: { name: `${TAG} personnel`, schema: SCHEMA },
    });
    assert(res.status === 201, `status ${res.status}`);
    const j = await res.json();
    assert(j.id && j.status === 'empty' && j.row_count === 0, JSON.stringify(j));
    sourceId = j.id;
    const row = await sourceRow(sourceId);
    assert(/^[0-9a-f]{64}$/.test(row.salt_hex), 'salt not stored as 64 hex chars');
    const text = JSON.stringify(j);
    assert(!text.includes(row.salt_hex) && !text.toLowerCase().includes('salt'),
      'response leaked the salt');
    return `source ${j.id.slice(0, 8)}, 32-byte salt stored server-side only`;
  });

  await check('E09', 'POST validation: no primary field / bad type / empty schema → 400', async () => {
    const noPrimary = await api('/api/protected/edm-sources', {
      cookie: authorCookie, method: 'POST',
      body: { name: `${TAG} x1`, schema: [{ name: 'a', type: 'text', primary: false }] },
    });
    assert(noPrimary.status === 400, `no-primary → ${noPrimary.status}`);
    const badType = await api('/api/protected/edm-sources', {
      cookie: authorCookie, method: 'POST',
      body: { name: `${TAG} x2`, schema: [{ name: 'a', type: 'blob', primary: true }] },
    });
    assert(badType.status === 400, `bad-type → ${badType.status}`);
    const empty = await api('/api/protected/edm-sources', {
      cookie: authorCookie, method: 'POST', body: { name: `${TAG} x3`, schema: [] },
    });
    assert(empty.status === 400, `empty-schema → ${empty.status}`);
    return 'all three rejected with 400';
  });

  await check('E10', 'auditor (no protect:write) POST → 403 and denial audited', async () => {
    const res = await api('/api/protected/edm-sources', {
      cookie: auditorCookie,
      method: 'POST',
      body: { name: `${TAG} sneaky`, schema: SCHEMA },
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

  await check('E11', 'PUT csv → 202 ingesting, job queued, encrypted blob on disk', async () => {
    const res = await putCsv(authorCookie, sourceId, CSV_V1);
    assert(res.status === 202, `status ${res.status}`);
    const j = await res.json();
    assert(j.status === 'ingesting', JSON.stringify(j));
    const row = await sourceRow(sourceId);
    assert(row.status === 'ingesting', `status ${row.status}`);
    assert(row.temp_blob_ref, 'temp_blob_ref not set');
    firstBlobFile = blobPath(row.temp_blob_ref);
    assert(fs.existsSync(firstBlobFile), 'upload blob missing from disk');
    // The on-disk blob is ENCRYPTED — the plaintext CSV must not be findable.
    const onDisk = fs.readFileSync(firstBlobFile);
    assert(!onDisk.includes(Buffer.from('Smith', 'utf8')), 'blob on disk contains plaintext');
    const job = await pool.query(
      `select state, kind from processing_jobs where ref_id = $1`, [sourceId]
    );
    assert(job.rows.length === 1 && job.rows[0].state === 'queued'
      && job.rows[0].kind === 'ingest_edm_source', JSON.stringify(job.rows));
    return '202, ingesting, ingest_edm_source queued, blob encrypted at rest';
  });

  await check('E12', 'worker --once → ready, row_count, hash count, BLOB DELETED', async () => {
    runWorkerOnce();
    const row = await sourceRow(sourceId);
    assert(row.status === 'ready', `status ${row.status} (${row.failure_reason})`);
    assert(row.row_count === CSV_V1_ROWS, `row_count ${row.row_count}`);
    assert(row.temp_blob_ref === null, `temp_blob_ref ${row.temp_blob_ref}`);
    const n = await pool.query(
      `select count(*)::int n from edm_hashes where source_id = $1`, [sourceId]
    );
    assert(n.rows[0].n === CSV_V1_HASHES,
      `edm_hashes ${n.rows[0].n}, expected ${CSV_V1_HASHES} (rows × non-empty fields)`);
    // MANDATORY: the plaintext export is not retained — file gone from disk.
    assert(!fs.existsSync(firstBlobFile), `upload blob still on disk: ${firstBlobFile}`);
    return `ready, ${row.row_count} rows, ${n.rows[0].n} hashes, upload blob deleted`;
  });

  await check('E13', 'stored hashes match hashField on normalized cells', async () => {
    const row = await sourceRow(sourceId);
    const salt = Buffer.from(row.salt_hex, 'hex');
    // Row 1: full_name "Smith, John" (text, field 0) and dob 14/03/1988 (date, field 4).
    const expectName = hashField(salt, 0, normalizeField('Smith, John', 'text')).toString();
    const expectDob = hashField(salt, 4, normalizeField('14/03/1988', 'date')).toString();
    const got = await pool.query(
      `select field_id, hash::text as hash from edm_hashes
        where source_id = $1 and row_id = 1 order by field_id`,
      [sourceId]
    );
    assert(got.rows.length === 5, `row 1 has ${got.rows.length} cells`);
    assert(got.rows[0].hash === expectName, `name hash ${got.rows[0].hash} !== ${expectName}`);
    assert(got.rows[4].hash === expectDob, `dob hash ${got.rows[4].hash} !== ${expectDob}`);
    return 'row 1 name+dob hashes reproduce from salt + normalized values';
  });

  await check('E14', 're-ingest replaces the hash set (v2: 1 row, 5 hashes)', async () => {
    const before = await pool.query(
      `select hash::text as hash from edm_hashes where source_id = $1 limit 1`, [sourceId]
    );
    const res = await putCsv(authorCookie, sourceId, CSV_V2);
    assert(res.status === 202, `status ${res.status}`);
    const mid = await sourceRow(sourceId);
    const secondBlob = blobPath(mid.temp_blob_ref);
    runWorkerOnce();
    const row = await sourceRow(sourceId);
    assert(row.status === 'ready', `status ${row.status} (${row.failure_reason})`);
    assert(row.row_count === 1, `row_count ${row.row_count}`);
    assert(row.temp_blob_ref === null, 'temp_blob_ref not nulled');
    assert(!fs.existsSync(secondBlob), 'second upload blob still on disk');
    const n = await pool.query(
      `select count(*)::int n,
              count(*) filter (where hash::text = $2)::int old
         from edm_hashes where source_id = $1`,
      [sourceId, before.rows[0].hash]
    );
    assert(n.rows[0].n === 5, `edm_hashes ${n.rows[0].n}, expected 5`);
    assert(n.rows[0].old === 0, 'an old v1 hash survived the re-ingest');
    return `5 fresh hashes, v1 hashes fully replaced, v2 blob deleted too`;
  });

  await check('E15', 'GET /edm-sources as auditor: fields+counts, never the salt', async () => {
    const res = await api('/api/protected/edm-sources', { cookie: auditorCookie });
    assert(res.status === 200, `status ${res.status}`);
    const list = await res.json();
    const mine = list.find((s) => s.id === sourceId);
    assert(mine, 'source missing from list');
    assert(mine.name === `${TAG} personnel` && mine.status === 'ready' && mine.row_count === 1,
      JSON.stringify(mine));
    assert(Array.isArray(mine.fields) && mine.fields.length === 5
      && mine.fields[0].name === 'full_name' && mine.fields[0].type === 'text',
      'fields not listed');
    const row = await sourceRow(sourceId);
    const text = JSON.stringify(list);
    assert(!text.includes(row.salt_hex), 'list leaked a salt');
    assert(!text.toLowerCase().includes('salt') && !text.includes('blob'),
      'list leaked salt/blob fields');
    return `${list.length} source(s) listed, metadata only`;
  });

  await check('E16', 'unauthenticated requests → 401', async () => {
    const post = await fetch(`${baseUrl}/api/protected/edm-sources`, { method: 'POST' });
    assert(post.status === 401, `POST → ${post.status}`);
    const put = await putCsv('', sourceId, CSV_V2);
    assert(put.status === 401, `PUT → ${put.status}`);
    return 'both endpoints 401';
  });

  await check('E17', 'create + ingest audited with counts/sizes only', async () => {
    const created = await pool.query(
      `select detail from audit_log where action = 'edm_source.create' and actor = $1 and target = $2`,
      [author.email, sourceId]
    );
    assert(created.rows.length === 1, `create audits ${created.rows.length}`);
    assert(created.rows[0].detail.fieldCount === 5, 'fieldCount missing');
    const ingests = await pool.query(
      `select detail from audit_log where action = 'edm_source.ingest' and actor = $1 and target = $2`,
      [author.email, sourceId]
    );
    assert(ingests.rows.length === 2, `ingest audits ${ingests.rows.length}`);
    const text = JSON.stringify([created.rows, ingests.rows]);
    assert(!text.includes('Smith') && !text.includes('52300'), 'audit leaked cell values');
    return '1 create + 2 ingest audits, no cell values anywhere';
  });

  // ---- cleanup (audit rows are append-only and remain) ----
  if (sourceId) {
    await pool.query('delete from processing_jobs where ref_id = $1', [sourceId]);
    const leftover = await sourceRow(sourceId).catch(() => null);
    if (leftover && leftover.temp_blob_ref) {
      try { fs.rmSync(blobPath(leftover.temp_blob_ref), { force: true }); } catch {}
    }
    await pool.query('delete from edm_sources where id = $1', [sourceId]); // hashes cascade
  }
  await pool.query(`delete from admin_users where email like $1`, [`${TAG}_%@test.local`]);
  await new Promise((r) => server.close(r));

  console.log(`\n${passed} passed, ${failed} failed, ${results.length} total\n`);
  fs.writeFileSync(
    path.join(__dirname, '.edm-results.json'),
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
