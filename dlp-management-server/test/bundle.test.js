'use strict';
// Index bundle + incidents suite (Step 4 + server half of Step 6):
//
//   fixture: byte-determinism of the golden bundle, parse + signature
//   roundtrip, tamper detection, bloom soundness, sort order.
//   end-to-end: register docs + EDM source → worker → POST
//   /api/protected/index/compile → worker 'compile_index' → index_bundles
//   row + signed file → mTLS agent check-in advertises the version →
//   GET /agent/index streams it → POST /agent/incidents → console
//   GET /api/incidents/:id lazily resolves seq ranges/containment.
//
// Runs against the REAL dev database, the REAL console app on an ephemeral
// port, and a REAL in-process mTLS listener with the actual CA material.
// Creates throwaway users/agents/documents and cleans them up. Audit rows
// are append-only and intentionally remain.
require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const https = require('https');
const { spawnSync } = require('child_process');
const forge = require('node-forge');
const pool = require('../db/pool');
const ca = require('../lib/ca');
const et = require('../lib/enrollmentTokens');
const { verifyChain } = require('../lib/audit');
const { containment } = require('../lib/fingerprint');
const bundleLib = require('../lib/indexBundle');
const { fixtureData } = require('../scripts/gen-bundle-fixture');
const app = require('../app');
const agentApp = require('../agent/agentApp');

const SERVER_ROOT = path.join(__dirname, '..');
const WORKER = path.join(SERVER_ROOT, 'bin', 'fingerprint-worker.js');
const FIXTURE_DIR = path.join(__dirname, 'fixtures', 'bundle-sample');
const TAG = 'bndtest_' + crypto.randomBytes(4).toString('hex');
const PW = 'test-Password-123456';
const results = [];
let passed = 0;
let failed = 0;
let server; // console app
let agentServer; // mTLS listener
let baseUrl;
let AGENT_PORT;

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

function registerDoc(cookie, collectionId, title, buffer, filename) {
  const q = `collectionId=${encodeURIComponent(collectionId)}&title=${encodeURIComponent(title)}`;
  return fetch(`${baseUrl}/api/protected/documents?${q}`, {
    method: 'POST',
    headers: { Cookie: cookie, 'Content-Type': 'application/octet-stream', 'X-Filename': filename },
    body: buffer,
  });
}

function runWorkerOnce() {
  const r = spawnSync(process.execPath, [WORKER, '--once'], {
    cwd: SERVER_ROOT,
    encoding: 'utf8',
    timeout: 120000,
  });
  assert(r.status === 0, `worker exited ${r.status}: ${r.stderr}`);
  return r.stdout;
}

// mTLS request against the in-process agent listener; binary:true collects
// the raw body as a Buffer (bundle download).
function agentRequest({ pathname, method = 'POST', body, key, cert, binary = false }) {
  return new Promise((resolve, reject) => {
    const data = body != null ? JSON.stringify(body) : null;
    const req = https.request(
      {
        host: '127.0.0.1',
        port: AGENT_PORT,
        path: pathname,
        method,
        key,
        cert,
        ca: ca.loadCaCertificatePem(),
        rejectUnauthorized: true,
        servername: 'localhost',
        agent: false,
        headers: {
          'Content-Type': 'application/json',
          Connection: 'close',
          ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
        },
      },
      (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          const buf = Buffer.concat(chunks);
          resolve({
            status: res.statusCode,
            headers: res.headers,
            buffer: buf,
            body: binary || buf.length === 0 ? null : JSON.parse(buf.toString('utf8')),
          });
        });
      }
    );
    req.setTimeout(15000, () => req.destroy(new Error('request timeout')));
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// Independent range collapse (deliberately re-implemented here, not shared
// with lib/incidents.js): maximal runs of adjacent-in-seq-order fingerprints
// whose hash is matched.
function independentRanges(allRows, matchedSet) {
  const ranges = [];
  let start = null;
  let last = null;
  for (const r of allRows) {
    if (matchedSet.has(r.hash)) {
      if (start === null) start = r.seq;
      last = r.seq;
    } else if (start !== null) {
      ranges.push([start, last]);
      start = null;
    }
  }
  if (start !== null) ranges.push([start, last]);
  return ranges;
}

// Independent sorted-order + bloom soundness scan over a parsed bundle.
function scanBundle(parsed) {
  const toU64 = (h) => BigInt.asUintN(64, h);
  for (let i = 1; i < parsed.idm.length; i++) {
    assert(toU64(parsed.idm[i].hash) >= toU64(parsed.idm[i - 1].hash), `idm unsorted at ${i}`);
  }
  for (let i = 1; i < parsed.edm.length; i++) {
    assert(toU64(parsed.edm[i].hash) >= toU64(parsed.edm[i - 1].hash), `edm unsorted at ${i}`);
  }
  let misses = 0;
  for (const e of parsed.idm) if (!parsed.bloomHas(e.hash)) misses++;
  for (const e of parsed.edm) if (!parsed.bloomHas(e.hash)) misses++;
  assert(misses === 0, `${misses} bloom false negatives`);
  return { idm: parsed.idm.length, edm: parsed.edm.length };
}

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

const EDM_SCHEMA = [
  { name: 'callsign', type: 'text', primary: true },
  { name: 'asset_no', type: 'id', primary: true },
];
const EDM_CSV = 'callsign,asset_no\nRed Falcon,XX-1001\nBlue Heron,YY-2002\n';

async function main() {
  console.log('\nIndex bundle + incidents — fixture & end-to-end suite\n');
  if (!ca.caExists()) {
    console.error('No CA — run: npm run init-ca');
    process.exit(1);
  }
  const fixtureBundle = fs.readFileSync(path.join(FIXTURE_DIR, 'sample.bundle'));
  const fixtureCaPem = fs.readFileSync(path.join(FIXTURE_DIR, 'ca-cert.pem'), 'utf8');
  const expected = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, 'expected.json'), 'utf8'));

  // ============ fixture / format ============
  await check('B01', 'fixture regeneration is byte-deterministic (unsigned prefix)', async () => {
    const a = bundleLib.buildBundle(fixtureData(), { sign: false });
    const b = bundleLib.buildBundle(fixtureData(), { sign: false });
    assert(a.equals(b), 'two rebuilds differ');
    assert(
      a.equals(fixtureBundle.subarray(0, a.length)),
      'rebuild differs from committed sample.bundle prefix'
    );
    return `${a.length} unsigned bytes identical across rebuilds and vs committed fixture`;
  });

  await check('B02', 'fixture parses, signature verifies, expected.json holds', async () => {
    const p = bundleLib.verifyAndParseBundle(fixtureBundle, fixtureCaPem);
    assert(
      JSON.stringify(p.header) === JSON.stringify(expected.header),
      'header differs from expected.json'
    );
    assert(p.bloom.mBits === expected.bloom.mBits && p.bloom.kHashes === expected.bloom.kHashes,
      'bloom params differ');
    for (const pr of expected.present) {
      assert(p.bloomHas(pr.hash), `present ${pr.hash} bloom-negative`);
      const got = pr.section === 'idm'
        ? p.lookupIdm(pr.hash).map((m) => ({ docIndex: m.docIndex, versionId: m.doc.versionId, title: m.doc.title }))
        : p.lookupEdm(pr.hash).map((m) => ({ sourceIndex: m.sourceIndex, sourceId: m.source.sourceId, rowId: m.rowId, fieldId: m.fieldId }));
      assert(JSON.stringify(got) === JSON.stringify(pr.matches),
        `lookup mismatch for ${pr.hash}: ${JSON.stringify(got)}`);
    }
    for (const h of expected.absentBloomNegative) {
      assert(!p.bloomHas(h), `absent ${h} should be bloom-negative`);
      assert(p.lookupIdm(h).length === 0 && p.lookupEdm(h).length === 0, `absent ${h} found`);
    }
    for (const h of expected.absentBloomPositive) {
      assert(p.bloomHas(h), `absent ${h} should be bloom-POSITIVE`);
      assert(p.lookupIdm(h).length === 0 && p.lookupEdm(h).length === 0, `absent ${h} found`);
    }
    return `header + ${expected.present.length} present + ${expected.absentBloomNegative.length}+${expected.absentBloomPositive.length} absent hashes all as expected`;
  });

  await check('B03', 'any tampered byte breaks the signature (fail closed)', async () => {
    // Flip one byte in three different regions: header JSON, idm section,
    // and the signature itself.
    for (const at of [20, Math.floor(fixtureBundle.length / 2), fixtureBundle.length - 3]) {
      const t = Buffer.from(fixtureBundle);
      t[at] ^= 0x01;
      let threw = false;
      try {
        bundleLib.verifyAndParseBundle(t, fixtureCaPem);
      } catch {
        threw = true;
      }
      assert(threw, `tamper at byte ${at} not detected`);
    }
    return 'tampering at 3 offsets rejected';
  });

  await check('B04', 'fixture: sections sorted (unsigned u64) + ZERO bloom false negatives', async () => {
    const p = bundleLib.verifyAndParseBundle(fixtureBundle, fixtureCaPem);
    const n = scanBundle(p);
    return `${n.idm} idm + ${n.edm} edm entries sorted, all bloom-positive`;
  });

  // ============ end-to-end setup ============
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
  const tls = ca.loadServerTlsMaterial();
  agentServer = https.createServer(
    { key: tls.key, cert: tls.cert, ca: tls.ca, requestCert: true, rejectUnauthorized: false, minVersion: 'TLSv1.2' },
    agentApp
  );
  await new Promise((r) => agentServer.listen(0, '127.0.0.1', r));
  AGENT_PORT = agentServer.address().port;

  const author = await makeUser('author', 'policy_author');
  const auditor = await makeUser('auditor', 'auditor');
  const authorCookie = await login(author.email);
  const auditorCookie = await login(auditor.email);

  const preVersion = await bundleLib.latestBundleVersion(); // cleanup boundary

  let collectionId;
  let doc; // { documentId, versionId }
  let edmSourceId;
  let bundleRow; // index_bundles row created by the compile
  let bundleFile; // Buffer of the compiled bundle
  let enrolled; // { agentId, keyPem, certPem }
  let incidentId;
  let matchedHashes; // hashes the fake agent "detected"
  let expectRanges;
  let expectContainment;

  await check('B05', 'setup: docs + EDM source registered and processed to ready', async () => {
    let res = await api('/api/protected/collections', {
      cookie: authorCookie,
      method: 'POST',
      body: { name: `${TAG} plans`, classification: 'secret' },
    });
    assert(res.status === 201, `collection ${res.status}`);
    collectionId = (await res.json()).id;

    res = await registerDoc(authorCookie, collectionId, 'Bundle Base Plan',
      Buffer.from(baseText(), 'utf8'), 'base.txt');
    assert(res.status === 202, `doc ${res.status}`);
    doc = await res.json();

    res = await api('/api/protected/edm-sources', {
      cookie: authorCookie,
      method: 'POST',
      body: { name: `${TAG} assets`, schema: EDM_SCHEMA },
    });
    assert(res.status === 201, `edm source ${res.status}`);
    edmSourceId = (await res.json()).id;
    res = await fetch(`${baseUrl}/api/protected/edm-sources/${edmSourceId}/data`, {
      method: 'PUT',
      headers: { Cookie: authorCookie, 'Content-Type': 'text/csv' },
      body: Buffer.from(EDM_CSV, 'utf8'),
    });
    assert(res.status === 202, `edm upload ${res.status}`);

    runWorkerOnce();
    const d = await pool.query('select status from protected_documents where id = $1', [doc.documentId]);
    const s = await pool.query('select status from edm_sources where id = $1', [edmSourceId]);
    assert(d.rows[0].status === 'ready', `doc ${d.rows[0].status}`);
    assert(s.rows[0].status === 'ready', `edm ${s.rows[0].status}`);
    return 'document + edm source ready';
  });

  await check('B06', 'POST /api/protected/index/compile → 202 queued + audited; auditor → 403', async () => {
    const denied = await api('/api/protected/index/compile', { cookie: auditorCookie, method: 'POST' });
    assert(denied.status === 403, `auditor got ${denied.status}`);
    const res = await api('/api/protected/index/compile', { cookie: authorCookie, method: 'POST' });
    assert(res.status === 202, `status ${res.status}`);
    const j = await res.json();
    assert(j.jobId && j.status === 'queued', JSON.stringify(j));
    const job = await pool.query(
      `select state, kind from processing_jobs where id = $1`, [j.jobId]
    );
    assert(job.rows[0].kind === 'compile_index' && job.rows[0].state === 'queued', 'job not queued');
    const aud = await pool.query(
      `select 1 from audit_log where action = 'index_bundle.compile' and actor = $1 and target = $2`,
      [author.email, j.jobId]
    );
    assert(aud.rows.length === 1, 'compile not audited');
    return '403 for auditor; 202 + compile_index queued + audited for author';
  });

  await check('B07', 'worker compiles: index_bundles row, signed file on disk, sha256 matches', async () => {
    const out = runWorkerOnce();
    assert(/compile_index .* done/.test(out), `worker output: ${out.trim().split('\n').pop()}`);
    bundleRow = await bundleLib.latestBundle();
    assert(bundleRow && bundleRow.version === preVersion + 1,
      `latest version ${bundleRow && bundleRow.version}, expected ${preVersion + 1}`);
    const file = path.join(bundleLib.INDEX_DIR, bundleRow.file_ref);
    assert(fs.existsSync(file), `bundle file missing: ${bundleRow.file_ref}`);
    bundleFile = fs.readFileSync(file);
    assert(bundleFile.length === Number(bundleRow.size_bytes), 'size_bytes mismatch');
    const sha = crypto.createHash('sha256').update(bundleFile).digest('hex');
    assert(sha === bundleRow.sha256, 'sha256 mismatch');
    return `bundle v${bundleRow.version}, ${bundleFile.length} bytes, sha256 ok`;
  });

  await check('B08', 'compiled bundle parses + verifies; contains our doc, EDM source, salt; sound', async () => {
    const p = bundleLib.verifyAndParseBundle(bundleFile, ca.loadCaCertificatePem());
    assert(p.header.bundleVersion === bundleRow.version, 'header version mismatch');
    const myDoc = p.header.docs.find((d) => d.versionId === doc.versionId);
    assert(myDoc && myDoc.title === 'Bundle Base Plan' && myDoc.collectionId === collectionId,
      'our document missing from header.docs');
    const mySrc = p.header.edmSources.find((s) => s.sourceId === edmSourceId);
    assert(mySrc && mySrc.fields.length === 2 && mySrc.fields[0].name === 'callsign',
      'our edm source missing');
    const salt = await pool.query('select salt_hex from edm_sources where id = $1', [edmSourceId]);
    assert(p.header.edmSalts[edmSourceId] === salt.rows[0].salt_hex, 'salt missing/mismatched');
    assert(p.header.scope.includes(collectionId), 'collection not in scope');
    // Our doc's distinct hashes and all EDM hashes must be present + sound.
    const dbFp = await pool.query(
      `select distinct hash::text as hash from document_fingerprints where version_id = $1`,
      [doc.versionId]
    );
    for (const r of dbFp.rows) {
      assert(p.lookupIdm(r.hash).some((m) => m.doc.versionId === doc.versionId),
        `db hash ${r.hash} not in bundle idm`);
    }
    const dbEdm = await pool.query(
      `select row_id, field_id, hash::text as hash from edm_hashes where source_id = $1`,
      [edmSourceId]
    );
    for (const r of dbEdm.rows) {
      assert(p.lookupEdm(r.hash).some(
        (m) => m.source.sourceId === edmSourceId && m.rowId === r.row_id && m.fieldId === r.field_id
      ), `db edm hash ${r.hash} not in bundle`);
    }
    const n = scanBundle(p); // sorted + zero bloom false negatives over ALL entries
    // and tampering the real bundle must fail too
    const t = Buffer.from(bundleFile);
    t[Math.floor(t.length / 3)] ^= 0xff;
    let threw = false;
    try { bundleLib.verifyAndParseBundle(t, ca.loadCaCertificatePem()); } catch { threw = true; }
    assert(threw, 'tampered compiled bundle accepted');
    return `${n.idm} idm + ${n.edm} edm entries verified against DB; tamper rejected`;
  });

  // ============ distribution over mTLS ============
  await check('B09', 'agent enrolls; check-in advertises index.latest = compiled version', async () => {
    const tok = await et.createToken({ description: TAG, maxUses: 1, createdBy: TAG });
    const keys = forge.pki.rsa.generateKeyPair(2048);
    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = keys.publicKey;
    csr.setSubject([{ name: 'commonName', value: `${TAG}-pc` }]);
    csr.sign(keys.privateKey, forge.md.sha256.create());
    const enroll = await agentRequest({
      pathname: '/agent/enroll',
      body: {
        token: tok.token,
        csrPem: forge.pki.certificationRequestToPem(csr),
        hostname: `${TAG}-pc`,
        agentVersion: '0.0.1-test',
      },
    });
    assert(enroll.status === 201, `enroll ${enroll.status}: ${JSON.stringify(enroll.body)}`);
    enrolled = {
      agentId: enroll.body.agentId,
      keyPem: forge.pki.privateKeyToPem(keys.privateKey),
      certPem: enroll.body.certificate,
    };
    const checkin = await agentRequest({
      pathname: '/agent/checkin',
      body: { agentVersion: '0.0.1-test' },
      key: enrolled.keyPem,
      cert: enrolled.certPem,
    });
    assert(checkin.status === 200, `checkin ${checkin.status}`);
    assert(checkin.body.index && checkin.body.index.latest === bundleRow.version,
      `index.latest ${JSON.stringify(checkin.body.index)}, expected ${bundleRow.version}`);
    return `enrolled ${enrolled.agentId.slice(0, 8)}; index.latest = ${checkin.body.index.latest}`;
  });

  await check('B10', 'GET /agent/index streams the exact bundle over mTLS; no cert → 401', async () => {
    const anon = await agentRequest({ pathname: '/agent/index', method: 'GET', binary: true });
    assert(anon.status === 401, `no-cert status ${anon.status}`);
    const res = await agentRequest({
      pathname: '/agent/index',
      method: 'GET',
      binary: true,
      key: enrolled.keyPem,
      cert: enrolled.certPem,
    });
    assert(res.status === 200, `status ${res.status}`);
    assert(res.headers['x-bundle-version'] === String(bundleRow.version), 'version header wrong');
    assert(res.buffer.equals(bundleFile), 'streamed bytes differ from the bundle file');
    const sha = crypto.createHash('sha256').update(res.buffer).digest('hex');
    assert(sha === res.headers['x-bundle-sha256'], 'sha256 header wrong');
    return `${res.buffer.length} bytes streamed, byte-identical, headers ok`;
  });

  // ============ incidents ============
  await check('B11', 'POST /agent/incidents (mTLS) → 201; row bound to the CERT identity', async () => {
    // The "detection": a contiguous run of the base doc's stored fingerprints.
    const { rows } = await pool.query(
      `select seq, hash::text as hash from document_fingerprints
        where version_id = $1 order by seq`,
      [doc.versionId]
    );
    assert(rows.length > 20, `only ${rows.length} fingerprints`);
    matchedHashes = rows.slice(5, 13).map((r) => r.hash); // 8 adjacent fingerprints
    const matchedSet = new Set(matchedHashes);
    expectRanges = independentRanges(rows, matchedSet);
    const allHashes = rows.map((r) => r.hash);
    expectContainment = containment(allHashes, [...matchedSet]);

    const noCert = await agentRequest({
      pathname: '/agent/incidents',
      body: { channel: 'usb', verdict: {} },
    });
    assert(noCert.status === 401, `no-cert status ${noCert.status}`);

    const res = await agentRequest({
      pathname: '/agent/incidents',
      key: enrolled.keyPem,
      cert: enrolled.certPem,
      body: {
        channel: 'usb',
        fileName: 'leaked-copy.txt',
        fileSha256: crypto.createHash('sha256').update('x').digest('hex'),
        verdict: {
          bundleVersion: bundleRow.version,
          idm: [{ versionId: doc.versionId, matchedHashes }],
          edm: [],
        },
      },
    });
    assert(res.status === 201 && res.body.id, `status ${res.status}: ${JSON.stringify(res.body)}`);
    incidentId = res.body.id;
    const row = await pool.query(
      'select agent_id, channel, resolved_json from detection_incidents where id = $1',
      [incidentId]
    );
    assert(row.rows[0].agent_id === enrolled.agentId, 'incident not bound to cert identity');
    assert(row.rows[0].resolved_json === null, 'should not be resolved yet');
    const aud = await pool.query(
      `select 1 from audit_log where action = 'agent.incident_reported' and target = $1`,
      [incidentId]
    );
    assert(aud.rows.length === 1, 'incident report not audited');
    return `incident ${incidentId.slice(0, 8)} stored unresolved, audited`;
  });

  await check('B12', 'GET /api/incidents/:id resolves lazily: title, containment, seq RANGES correct', async () => {
    const res = await api(`/api/incidents/${incidentId}`, { cookie: auditorCookie });
    assert(res.status === 200, `status ${res.status}`);
    const j = await res.json();
    assert(j.hostname === `${TAG}-pc` && j.channel === 'usb', 'metadata wrong');
    assert(j.resolved && Array.isArray(j.resolved.idm) && j.resolved.idm.length === 1,
      `resolved: ${JSON.stringify(j.resolved)}`);
    const r = j.resolved.idm[0];
    assert(r.versionId === doc.versionId && r.title === 'Bundle Base Plan', 'wrong doc resolved');
    assert(Math.abs(r.containment - expectContainment) < 1e-9,
      `containment ${r.containment}, expected ${expectContainment}`);
    assert(JSON.stringify(r.seqRanges) === JSON.stringify(expectRanges),
      `seqRanges ${JSON.stringify(r.seqRanges)}, expected ${JSON.stringify(expectRanges)}`);
    // persisted + audited
    const row = await pool.query(
      'select resolved_json from detection_incidents where id = $1', [incidentId]
    );
    assert(row.rows[0].resolved_json !== null, 'resolution not persisted');
    const aud = await pool.query(
      `select count(*)::int n from audit_log where action = 'incident.read' and actor = $1 and target = $2`,
      [auditor.email, incidentId]
    );
    assert(aud.rows[0].n === 1, `incident.read audits ${aud.rows[0].n}`);
    // list shows it as resolved
    const list = await api('/api/incidents', { cookie: auditorCookie });
    assert(list.status === 200, `list ${list.status}`);
    const mine = (await list.json()).find((i) => i.id === incidentId);
    assert(mine && mine.resolved === true, 'incident missing/unresolved in list');
    return `containment ${r.containment.toFixed(3)}, ranges ${JSON.stringify(r.seqRanges)}`;
  });

  await check('B13', 'incidents API gates: unauthenticated → 401; audit chain intact', async () => {
    const anon = await fetch(`${baseUrl}/api/incidents`);
    assert(anon.status === 401, `list anon ${anon.status}`);
    const anon2 = await fetch(`${baseUrl}/api/incidents/${incidentId}`);
    assert(anon2.status === 401, `detail anon ${anon2.status}`);
    const broken = await verifyChain();
    assert(broken === null, `chain broken at seq ${broken}`);
    return '401s enforced, AUDIT CHAIN INTACT';
  });

  // ---- cleanup (audit rows are append-only and remain) ----
  try {
    await pool.query('delete from detection_incidents where agent_id in (select id from agents where hostname like $1)', [`${TAG}%`]);
    await pool.query('delete from agents where hostname like $1', [`${TAG}%`]);
    await pool.query('delete from enrollment_tokens where created_by = $1', [TAG]);
    const bundles = await pool.query(
      'delete from index_bundles where version > $1 returning file_ref', [preVersion]
    );
    for (const b of bundles.rows) {
      try { fs.rmSync(path.join(bundleLib.INDEX_DIR, b.file_ref), { force: true }); } catch {}
    }
    await pool.query(`delete from processing_jobs where kind = 'compile_index' and state = 'done'`);
    if (collectionId) {
      const versions = await pool.query(
        `select v.id, v.blob_ref from document_versions v
          join protected_documents d on d.id = v.document_id
         where d.collection_id = $1`,
        [collectionId]
      );
      for (const v of versions.rows) {
        await pool.query('delete from processing_jobs where ref_id = $1', [v.id]);
        try {
          fs.rmSync(path.join(SERVER_ROOT, 'data', 'blobs', ...v.blob_ref.split('/')), { force: true });
        } catch {}
      }
      await pool.query(
        `delete from document_versions where document_id in
           (select id from protected_documents where collection_id = $1)`,
        [collectionId]
      );
      await pool.query('delete from protected_documents where collection_id = $1', [collectionId]);
      await pool.query('delete from protected_collections where id = $1', [collectionId]);
    }
    if (edmSourceId) {
      await pool.query('delete from processing_jobs where ref_id = $1', [edmSourceId]);
      await pool.query('delete from edm_sources where id = $1', [edmSourceId]);
    }
    await pool.query(`delete from admin_users where email like $1`, [`${TAG}_%@test.local`]);
  } catch (err) {
    console.error('cleanup error:', err.message);
  }
  await new Promise((r) => server.close(r));
  await new Promise((r) => agentServer.close(r));

  console.log(`\n${passed} passed, ${failed} failed, ${results.length} total\n`);
  fs.writeFileSync(
    path.join(__dirname, '.bundle-results.json'),
    JSON.stringify({ generatedAt: new Date().toISOString(), passed, failed, results }, null, 2)
  );
  await pool.end();
  process.exit(failed === 0 ? 0 : 1);
}

main().catch(async (err) => {
  console.error(err);
  try { await pool.query(`delete from admin_users where email like $1`, [`${TAG}_%@test.local`]); } catch {}
  try { await pool.query('delete from agents where hostname like $1', [`${TAG}%`]); } catch {}
  process.exit(1);
});
