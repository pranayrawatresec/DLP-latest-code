'use strict';
// Cross-language detection E2E — the FULL loop, server (Node) + agent (Rust):
//
//   register a .docx + a personnel EDM source over HTTP as policy_author
//   → worker fingerprints/ingests → compile a signed index bundle
//   → run the REAL Rust agent binary (`dlp-agent scan`) against the bundle:
//       mutated copy of the docx   → top IDM match, containment > 0.85
//       text with a personnel row  → EDM source fires (both fields, right row)
//       innocent text              → zero matches
//       random bytes named .docx   → unreadable verdict (corrupt-container)
//   → POST the real Rust verdict as an incident from an enrolled fake agent
//   → GET /api/incidents/:id as incident_reviewer → resolved seq ranges/title.
//
// Runs against the REAL dev database, the REAL console app on an ephemeral
// port, an in-process mTLS listener with the actual CA material, and the
// compiled agent binary (dlp-agent/target/{release|debug}/dlp-agent.exe,
// overridable via DLP_AGENT_BIN). Creates throwaway users/agents/documents
// and cleans them up. Audit rows are append-only and intentionally remain.
require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const zlib = require('zlib');
const { spawnSync } = require('child_process');
const forge = require('node-forge');
const pool = require('../db/pool');
const ca = require('../lib/ca');
const et = require('../lib/enrollmentTokens');
const bundleLib = require('../lib/indexBundle');
const app = require('../app');
const agentApp = require('../agent/agentApp');

const SERVER_ROOT = path.join(__dirname, '..');
const WORKER = path.join(SERVER_ROOT, 'bin', 'fingerprint-worker.js');
const AGENT_REPO = path.join(SERVER_ROOT, '..', 'dlp-agent');
const TAG = 'e2edet_' + crypto.randomBytes(4).toString('hex');
const PW = 'test-Password-123456';
const DOC_TITLE = 'E2E Exercise Plan';
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

// ---------- the real agent binary ----------
function findAgentBinary() {
  if (process.env.DLP_AGENT_BIN) return process.env.DLP_AGENT_BIN;
  const exe = process.platform === 'win32' ? 'dlp-agent.exe' : 'dlp-agent';
  for (const profile of ['release', 'debug']) {
    const p = path.join(AGENT_REPO, 'target', profile, exe);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

// ---------- minimal .docx builder (stored zip, no deps) ----------
function makeZip(entries) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const e of entries) {
    const nameBuf = Buffer.from(e.name, 'utf8');
    const crc = zlib.crc32(e.data) >>> 0;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4); // version needed
    lh.writeUInt16LE(0, 8); // method 0 = stored
    lh.writeUInt16LE(0x21, 12); // date: 1980-01-01
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(e.data.length, 18);
    lh.writeUInt32LE(e.data.length, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    locals.push(lh, nameBuf, e.data);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4);
    ch.writeUInt16LE(20, 6);
    ch.writeUInt16LE(0x21, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(e.data.length, 20);
    ch.writeUInt32LE(e.data.length, 24);
    ch.writeUInt16LE(nameBuf.length, 28);
    ch.writeUInt32LE(offset, 42);
    centrals.push(ch, nameBuf);
    offset += 30 + nameBuf.length + e.data.length;
  }
  const centralBuf = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralBuf, eocd]);
}

const xmlEscape = (s) =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function makeDocx(text) {
  const paragraphs = text
    .split('\n')
    .map((p) => `<w:p><w:r><w:t xml:space="preserve">${xmlEscape(p)}</w:t></w:r></w:p>`)
    .join('');
  const documentXml =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
    '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">' +
    `<w:body>${paragraphs}</w:body></w:document>`;
  const contentTypes =
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">' +
    '<Default Extension="xml" ContentType="application/xml"/>' +
    '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>' +
    '</Types>';
  return makeZip([
    { name: '[Content_Types].xml', data: Buffer.from(contentTypes, 'utf8') },
    { name: 'word/document.xml', data: Buffer.from(documentXml, 'utf8') },
  ]);
}

// ---------- test content ----------
// ~500 words of varied "exercise plan" prose.
function baseDocText() {
  const paras = ['EXERCISE EMBER SENTINEL — MOVEMENT PLAN (E2E TEST DATA ONLY)'];
  for (let i = 1; i <= 10; i++) {
    paras.push(
      `Serial ${i}: at h-hour plus ${i}, the number ${i} supply column departs staging area ` +
        `${String.fromCharCode(64 + (((i - 1) % 26) + 1))} under escort from patrol ${i * 3}, ` +
        `holds short of checkpoint ${i * 7} until the route is declared clear, and reports ` +
        `arrival at the forward holding position to the operations room before first light on ` +
        `day ${1 + (i % 5)} of the exercise.`
    );
  }
  return paras.join('\n');
}

// Case/punctuation churn + one extra paragraph — the fingerprints must
// survive this (normalization absorbs case/punctuation entirely).
function mutatedDocText() {
  const mangled = baseDocText()
    .split('\n')
    .map((line, i) => {
      let out = line.replace(/:/g, ' -').replace(/,/g, ';').replace(/\./g, '!');
      if (i % 3 === 0) out = out.toUpperCase();
      return out;
    });
  mangled.push(
    'Annex Z (added by the copyist): distribution of this plan is restricted to exercise ' +
      'participants only, and all printed copies must be returned to the registry for ' +
      'destruction once endex has been declared by the directing staff.'
  );
  return mangled.join('\n');
}

const INNOCENT_TEXT =
  'Grandma’s lemon shortbread: cream the butter with caster sugar until pale and fluffy, ' +
  'fold in the flour and a pinch of salt, then rest the dough in a cool place for half an hour. ' +
  'Roll it out to the thickness of a pound coin, cut into fingers, prick each one with a fork ' +
  'and bake in a moderate oven until the edges turn the colour of pale straw. Dust with sugar ' +
  'while still warm and let them crisp up on a wire rack before serving with a pot of tea.';

const EDM_SCHEMA = [
  { name: 'full_name', type: 'text', primary: true },
  { name: 'service_no', type: 'id', primary: true },
  { name: 'unit', type: 'text', primary: false },
];
const EDM_CSV =
  'full_name,service_no,unit\n' +
  'Arun Mehta,SVC100001,1 Armoured Brigade\n' +
  'Beatrice Okafor,SVC200045,Fleet Support Group\n' +
  'Priya Sharma,SVC900123,5 Signals Regiment\n' + // row 3 — the scan target
  'Daniel Whitfield,SVC300777,Air Mobility Wing\n' +
  'Elena Petrova,SVC400888,Coastal Defence Battery\n';
const EDM_HIT_ROW = 3;

const EDM_HIT_TEXT =
  'Routine posting memorandum (E2E test data only).\n' +
  'Name: Priya Sharma, Service No: SVC900123.\n' +
  'The member has requested a posting to the training establishment effective next quarter. ' +
  'No other personnel are referenced in this memorandum.';

// ---------- infrastructure helpers (test-suite conventions) ----------
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

function agentRequest({ pathname, method = 'POST', body, key, cert }) {
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
            body: buf.length === 0 ? null : JSON.parse(buf.toString('utf8')),
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

// Run `dlp-agent scan --json` and parse its verdict. The agent never
// contacts the server here — env-only config with a pinned CA is enough.
function agentScan(agentBin, tmpDir, bundlePath, filePath) {
  const r = spawnSync(agentBin, ['scan', '--bundle', bundlePath, '--file', filePath, '--json'], {
    encoding: 'utf8',
    timeout: 120000,
    env: {
      ...process.env,
      DLP_AGENT_CONFIG: path.join(tmpDir, 'no-such-config.toml'),
      DLP_AGENT_SERVER_URL: 'https://127.0.0.1:1', // never dialled by scan
      DLP_AGENT_CA_CERT: path.join(tmpDir, 'ca.pem'),
      DLP_AGENT_STATE_DIR: path.join(tmpDir, 'agent-state'),
    },
  });
  assert(r.status === 0, `agent scan exited ${r.status}: ${r.stderr}`);
  const start = r.stdout.indexOf('{');
  assert(start >= 0, `no JSON in agent output: ${r.stdout}`);
  return JSON.parse(r.stdout.slice(start));
}

async function main() {
  console.log('\nCross-language detection E2E — server pipeline + real Rust agent\n');
  if (!ca.caExists()) {
    console.error('No CA — run: npm run init-ca');
    process.exit(1);
  }
  const agentBin = findAgentBinary();
  if (!agentBin) {
    console.error(
      'Agent binary not found — build it first: cd ../dlp-agent && cargo build --release ' +
        '(or set DLP_AGENT_BIN)'
    );
    process.exit(1);
  }
  console.log(`  agent binary: ${agentBin}\n`);

  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'dlp-e2e-'));
  fs.mkdirSync(path.join(tmpDir, 'agent-state'), { recursive: true });
  fs.writeFileSync(path.join(tmpDir, 'ca.pem'), ca.loadCaCertificatePem());

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
  const reviewer = await makeUser('reviewer', 'incident_reviewer');
  const authorCookie = await login(author.email);
  const reviewerCookie = await login(reviewer.email);

  const preVersion = await bundleLib.latestBundleVersion(); // cleanup boundary

  let collectionId;
  let doc; // { documentId, versionId }
  let edmSourceId;
  let bundleRow;
  let bundlePath; // the compiled bundle copied out for the agent
  let mutatedVerdict; // real Rust verdict for the mutated docx
  let enrolled; // { agentId, keyPem, certPem }
  let incidentId;

  // ---- a. register document + EDM source, worker to ready ----
  await check('D01', 'register ~500-word .docx + personnel EDM source; worker → ready', async () => {
    let res = await api('/api/protected/collections', {
      cookie: authorCookie,
      method: 'POST',
      body: { name: `${TAG} plans`, classification: 'secret' },
    });
    assert(res.status === 201, `collection ${res.status}`);
    collectionId = (await res.json()).id;

    const baseText = baseDocText();
    const words = baseText.split(/\s+/).length;
    assert(words > 400 && words < 700, `unexpected word count ${words}`);
    res = await registerDoc(authorCookie, collectionId, DOC_TITLE, makeDocx(baseText), 'plan.docx');
    assert(res.status === 202, `doc register ${res.status}`);
    doc = await res.json();

    res = await api('/api/protected/edm-sources', {
      cookie: authorCookie,
      method: 'POST',
      body: { name: `${TAG} personnel`, schema: EDM_SCHEMA },
    });
    assert(res.status === 201, `edm source ${res.status}`);
    edmSourceId = (await res.json()).id;
    res = await fetch(`${baseUrl}/api/protected/edm-sources/${edmSourceId}/data`, {
      method: 'PUT',
      headers: { Cookie: authorCookie, 'Content-Type': 'text/csv' },
      body: Buffer.from(EDM_CSV, 'utf8'),
    });
    assert(res.status === 202, `edm upload ${res.status}`);

    // --once drains all eligible jobs; loop in case a retry was scheduled.
    let d, s;
    for (let i = 0; i < 5; i++) {
      runWorkerOnce();
      d = (await pool.query('select status, failure_reason from protected_documents where id = $1', [doc.documentId])).rows[0];
      s = (await pool.query('select status, failure_reason, row_count from edm_sources where id = $1', [edmSourceId])).rows[0];
      if (d.status === 'ready' && s.status === 'ready') break;
      await pool.query(`update processing_jobs set run_after = now() where state = 'queued'`);
    }
    assert(d.status === 'ready', `doc ${d.status} (${d.failure_reason})`);
    assert(s.status === 'ready' && s.row_count === 5, `edm ${s.status} rows ${s.row_count}`);
    return `document ready (${words} words), edm source ready (5 rows)`;
  });

  // ---- b. compile the signed index bundle, copy it out ----
  await check('D02', 'compile_index job → signed bundle row + file copied out', async () => {
    const res = await api('/api/protected/index/compile', { cookie: authorCookie, method: 'POST' });
    assert(res.status === 202, `compile ${res.status}`);
    runWorkerOnce();
    bundleRow = await bundleLib.latestBundle();
    assert(bundleRow && bundleRow.version === preVersion + 1,
      `latest version ${bundleRow && bundleRow.version}, expected ${preVersion + 1}`);
    const src = path.join(bundleLib.INDEX_DIR, bundleRow.file_ref);
    assert(fs.existsSync(src), `bundle file missing: ${bundleRow.file_ref}`);
    bundlePath = path.join(tmpDir, 'index.dlpx');
    fs.copyFileSync(src, bundlePath);
    const sha = crypto.createHash('sha256').update(fs.readFileSync(bundlePath)).digest('hex');
    assert(sha === bundleRow.sha256, 'copied bundle sha256 mismatch');
    return `bundle v${bundleRow.version} (${bundleRow.size_bytes} bytes) copied for the agent`;
  });

  // ---- c. the REAL Rust agent scans ----
  await check('D03', 'agent scan: mutated .docx → top IDM match is our doc, containment > 0.85', async () => {
    const f = path.join(tmpDir, 'mutated-plan.docx');
    fs.writeFileSync(f, makeDocx(mutatedDocText()));
    mutatedVerdict = agentScan(agentBin, tmpDir, bundlePath, f);
    assert(mutatedVerdict.extraction.status === 'ok' && mutatedVerdict.extraction.format === 'docx',
      `extraction ${JSON.stringify(mutatedVerdict.extraction)}`);
    assert(mutatedVerdict.idm.length >= 1, 'no idm matches');
    const top = mutatedVerdict.idm[0];
    assert(top.versionId === doc.versionId,
      `top match ${top.versionId} (${top.title}), expected ${doc.versionId}`);
    assert(top.containment > 0.85, `containment ${top.containment} <= 0.85`);
    assert(top.matchedHashes.length === top.matchedCount, 'matchedHashes/count mismatch');
    return `containment ${top.containment.toFixed(3)} (${top.matchedCount}/${top.totalCount}), title ${JSON.stringify(top.title)}`;
  });

  await check('D04', 'agent scan: personnel text → EDM row 3 fires with BOTH fields', async () => {
    const f = path.join(tmpDir, 'posting-note.txt');
    fs.writeFileSync(f, EDM_HIT_TEXT, 'utf8');
    const v = agentScan(agentBin, tmpDir, bundlePath, f);
    assert(v.extraction.status === 'ok', `extraction ${JSON.stringify(v.extraction)}`);
    const hit = v.edm.find((s) => s.sourceId === edmSourceId);
    assert(hit, `our source did not fire: ${JSON.stringify(v.edm)}`);
    const row = hit.rowsHit.find((r) => r.rowId === EDM_HIT_ROW);
    assert(row, `row ${EDM_HIT_ROW} not hit: ${JSON.stringify(hit.rowsHit)}`);
    assert(row.fields.includes('full_name') && row.fields.includes('service_no'),
      `fields ${JSON.stringify(row.fields)}`);
    assert(v.idm.length === 0, `unexpected idm matches: ${v.idm.length}`);
    return `source ${JSON.stringify(hit.name)} row ${row.rowId} fields ${JSON.stringify(row.fields)}`;
  });

  await check('D05', 'agent scan: innocent text → zero IDM and zero EDM matches', async () => {
    const f = path.join(tmpDir, 'innocent.txt');
    fs.writeFileSync(f, INNOCENT_TEXT, 'utf8');
    const v = agentScan(agentBin, tmpDir, bundlePath, f);
    assert(v.extraction.status === 'ok', `extraction ${JSON.stringify(v.extraction)}`);
    assert(v.idm.length === 0, `idm matched: ${JSON.stringify(v.idm.map((m) => m.title))}`);
    assert(v.edm.length === 0, `edm matched: ${JSON.stringify(v.edm)}`);
    return 'clean file scores zero everywhere';
  });

  await check('D06', 'agent scan: random bytes named .docx → unreadable verdict with reason', async () => {
    const f = path.join(tmpDir, 'garbage.docx');
    fs.writeFileSync(f, crypto.randomBytes(4096));
    const v = agentScan(agentBin, tmpDir, bundlePath, f);
    assert(v.extraction.status === 'unreadable', `extraction ${JSON.stringify(v.extraction)}`);
    assert(v.extraction.reason === 'corrupt-container',
      `reason ${v.extraction.reason}, expected corrupt-container`);
    assert(v.idm.length === 0 && v.edm.length === 0, 'matches on an unreadable file');
    return `unreadable (${v.extraction.reason}), exit code 0 — a verdict, not an error`;
  });

  // ---- d. incident round-trip with the REAL Rust verdict ----
  await check('D07', 'enrolled agent posts the Rust verdict; reviewer resolves seq ranges + title', async () => {
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
        agentVersion: '0.1.0-e2e',
      },
    });
    assert(enroll.status === 201, `enroll ${enroll.status}: ${JSON.stringify(enroll.body)}`);
    enrolled = {
      agentId: enroll.body.agentId,
      keyPem: forge.pki.privateKeyToPem(keys.privateKey),
      certPem: enroll.body.certificate,
    };

    const res = await agentRequest({
      pathname: '/agent/incidents',
      key: enrolled.keyPem,
      cert: enrolled.certPem,
      body: {
        channel: 'e2e-scan',
        fileName: mutatedVerdict.fileName,
        fileSha256: mutatedVerdict.fileSha256,
        verdict: mutatedVerdict, // verbatim Rust agent output
      },
    });
    assert(res.status === 201 && res.body.id, `incident ${res.status}: ${JSON.stringify(res.body)}`);
    incidentId = res.body.id;

    const detail = await api(`/api/incidents/${incidentId}`, { cookie: reviewerCookie });
    assert(detail.status === 200, `incident read ${detail.status}`);
    const j = await detail.json();
    assert(j.hostname === `${TAG}-pc` && j.channel === 'e2e-scan', 'incident metadata wrong');
    assert(j.resolved && Array.isArray(j.resolved.idm) && j.resolved.idm.length === 1,
      `resolved: ${JSON.stringify(j.resolved)}`);
    const r = j.resolved.idm[0];
    assert(r.versionId === doc.versionId && r.title === DOC_TITLE,
      `resolved doc ${r.versionId} ${JSON.stringify(r.title)}`);
    assert(Array.isArray(r.seqRanges) && r.seqRanges.length > 0 &&
      r.seqRanges.every((x) => Array.isArray(x) && x.length === 2 && x[0] <= x[1]),
      `seqRanges ${JSON.stringify(r.seqRanges)}`);
    assert(r.containment > 0.85, `resolved containment ${r.containment}`);
    const persisted = await pool.query(
      'select resolved_json from detection_incidents where id = $1', [incidentId]
    );
    assert(persisted.rows[0].resolved_json !== null, 'resolution not persisted');
    return `incident ${incidentId.slice(0, 8)} resolved: ${JSON.stringify(r.title)}, ` +
      `containment ${r.containment.toFixed(3)}, ${r.seqRanges.length} seq range(s)`;
  });

  // ---- e. cleanup (audit rows are append-only and remain) ----
  try {
    await pool.query(
      'delete from detection_incidents where agent_id in (select id from agents where hostname like $1)',
      [`${TAG}%`]
    );
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
    fs.rmSync(tmpDir, { recursive: true, force: true });
  } catch (err) {
    console.error('cleanup error:', err.message);
  }
  await new Promise((r) => server.close(r));
  await new Promise((r) => agentServer.close(r));

  console.log(`\n${passed} passed, ${failed} failed, ${results.length} total\n`);
  fs.writeFileSync(
    path.join(SERVER_ROOT, 'test', '.detection-e2e-results.json'),
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
