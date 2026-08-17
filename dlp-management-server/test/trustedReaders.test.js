'use strict';
// Test harness for the sanctioned-reader allowlist API (routes/trustedReaders.js)
// plus the agent-facing delivery endpoint (GET /agent/trusted-readers). Mirrors
// the two-server pattern of agentTrustedConfig.test.js: the admin app over plain
// HTTP (login cookies) and the agentApp over REAL mTLS (a genuinely enrolled
// agent).
//
//   A. HTTP + RBAC: 401 anon; read for author/sysadmin/auditor; write only for
//      policy_author (auditor/sysadmin write -> 403 + audited).
//   B. CRUD + validation: create/list/delete; bad matchType/value/duplicate/id.
//      Every mutation audited.
//   C. Agent delivery: GET /agent/trusted-readers over mTLS returns
//      {matchType, value}, requires a client cert (no cert -> 401), audited.
//   D. Invariant: the audit hash-chain stays intact.
//
// Creates its own tagged users/readers/agents and cleans them up. Audit rows are
// append-only and intentionally remain.
require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const https = require('https');
const forge = require('node-forge');
const pool = require('../db/pool');
const ca = require('../lib/ca');
const et = require('../lib/enrollmentTokens');
const { verifyChain } = require('../lib/audit');

const app = require('../app');
const agentApp = require('../agent/agentApp');

const TAG = 'rdrtest_' + crypto.randomBytes(4).toString('hex');
const PW = 'test-Password-123456';
const results = [];
let passed = 0;
let failed = 0;
let adminServer;
let baseUrl;
let mtlsServer;
let PORT;

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

async function login(email) {
  const res = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: PW }),
  });
  assert(res.status === 200, `login failed for ${email}: ${res.status}`);
  const m = (res.headers.get('set-cookie') || '').match(/dlp_session=[^;]+/);
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

// mTLS HTTPS helper (mirrors agentTrustedConfig.test.js).
function request({ pathname, method = 'GET', body, key, cert, verifyServer = false }) {
  return new Promise((resolve, reject) => {
    const data = body != null ? JSON.stringify(body) : null;
    const req = https.request(
      {
        host: '127.0.0.1', port: PORT, path: pathname, method, key, cert,
        ca: verifyServer ? ca.loadCaCertificatePem() : undefined,
        rejectUnauthorized: Boolean(verifyServer),
        servername: 'localhost', agent: false,
        headers: {
          'Content-Type': 'application/json', Connection: 'close',
          ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
        },
      },
      (res) => {
        let b = '';
        res.on('data', (c) => (b += c));
        res.on('end', () => resolve({ status: res.statusCode, body: b ? JSON.parse(b) : null }));
      }
    );
    req.setTimeout(15000, () => req.destroy(new Error('request timeout')));
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

function csrFrom(keys, cn) {
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;
  csr.setSubject([{ name: 'commonName', value: cn }]);
  csr.sign(keys.privateKey, forge.md.sha256.create());
  return {
    csrPem: forge.pki.certificationRequestToPem(csr),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

async function cleanup(emails) {
  await pool.query(`delete from trusted_readers where value like $1 or note like $1`, [`${TAG}%`]);
  await pool.query(`delete from agents where hostname like $1`, [`${TAG}%`]);
  await pool.query(`delete from enrollment_tokens where created_by = $1`, [TAG]);
  if (emails) await pool.query(`delete from admin_users where email like $1`, [`${TAG}_%@test.local`]);
}

async function main() {
  console.log('\nSanctioned-reader allowlist API - test & edge-case suite\n');
  if (!ca.caExists()) {
    console.error('No CA - run: npm run init-ca');
    process.exit(1);
  }
  await cleanup(false);

  await new Promise((r) => { adminServer = app.listen(0, '127.0.0.1', r); });
  baseUrl = `http://127.0.0.1:${adminServer.address().port}`;
  const tls = ca.loadServerTlsMaterial();
  mtlsServer = https.createServer(
    { key: tls.key, cert: tls.cert, ca: tls.ca, requestCert: true, rejectUnauthorized: false, minVersion: 'TLSv1.2' },
    agentApp
  );
  await new Promise((r) => mtlsServer.listen(0, '127.0.0.1', r));
  PORT = mtlsServer.address().port;

  const sysadmin = await makeUser('sysadmin', 'sysadmin');
  const author = await makeUser('author', 'policy_author');
  const auditor = await makeUser('auditor', 'auditor');
  const sysCookie = await login(sysadmin.email);
  const authorCookie = await login(author.email);
  const auditorCookie = await login(auditor.email);

  // ============ A. RBAC gates ============
  await check('R01', 'anon GET trusted-readers -> 401', async () => {
    const res = await api('/api/trusted-readers');
    assert(res.status === 401, `expected 401, got ${res.status}`);
  });

  await check('R02', 'GET: author, sysadmin, auditor all 200', async () => {
    for (const [who, cookie] of [['author', authorCookie], ['sysadmin', sysCookie], ['auditor', auditorCookie]]) {
      const res = await api('/api/trusted-readers', { cookie });
      assert(res.status === 200, `${who}: expected 200, got ${res.status}`);
      assert(Array.isArray((await res.json()).readers), `${who}: missing readers array`);
    }
    return 'all three read roles allowed';
  });

  await check('R03', 'POST as auditor -> 403 + audited', async () => {
    const res = await api('/api/trusted-readers', {
      cookie: auditorCookie, method: 'POST', body: { matchType: 'name', value: `${TAG}_x.exe` },
    });
    assert(res.status === 403, `expected 403, got ${res.status}`);
    const denied = await pool.query(
      `select 1 from audit_log where action = 'authz.denied' and actor = $1
         and detail->>'required' = 'trusted_readers:write' limit 1`,
      [auditor.email]);
    assert(denied.rows.length === 1, 'denial not audited');
    return '403 + authz.denied logged';
  });

  await check('R04', 'POST as sysadmin -> 403 (write is policy_author only)', async () => {
    const res = await api('/api/trusted-readers', {
      cookie: sysCookie, method: 'POST', body: { matchType: 'name', value: `${TAG}_y.exe` },
    });
    assert(res.status === 403, `expected 403, got ${res.status}`);
  });

  // ============ B. CRUD + validation ============
  await check('R05', 'POST invalid bodies -> 400', async () => {
    const bads = [
      {},
      { matchType: 'sha256', value: 'abc' },          // unknown matchType
      { matchType: 'publisher' },                      // missing value
      { matchType: 'name', value: '' },                // empty value
      { matchType: 'path', value: 'x'.repeat(513) },   // too long
      { matchType: 'name', value: 'abcd.exe' },  // control character
    ];
    for (let i = 0; i < bads.length; i++) {
      const res = await api('/api/trusted-readers', { cookie: authorCookie, method: 'POST', body: bads[i] });
      assert(res.status === 400, `case ${i}: expected 400, got ${res.status}`);
    }
    return `${bads.length} invalid bodies rejected`;
  });

  let readerId;
  await check('R06', 'POST publisher reader -> 201 camelCase + audited', async () => {
    const res = await api('/api/trusted-readers', {
      cookie: authorCookie, method: 'POST',
      body: { matchType: 'publisher', value: `${TAG} Microsoft`, note: `${TAG} office+os` },
    });
    assert(res.status === 201, `expected 201, got ${res.status}`);
    const { reader: r } = await res.json();
    readerId = r.id;
    assert(r.matchType === 'publisher' && r.value === `${TAG} Microsoft`, 'shape wrong');
    assert(r.createdBy === author.email && r.createdAt, 'createdBy/createdAt missing');
    const a = await pool.query(
      `select 1 from audit_log where action = 'trusted_reader.create' and target = $1`, [String(r.id)]);
    assert(a.rows.length === 1, 'creation not audited');
    return `reader ${r.id} created + audited`;
  });

  await check('R07', 'duplicate (same matchType+value) -> 409', async () => {
    const res = await api('/api/trusted-readers', {
      cookie: authorCookie, method: 'POST',
      body: { matchType: 'publisher', value: `${TAG} Microsoft` },
    });
    assert(res.status === 409, `expected 409, got ${res.status}`);
    return 'set semantics: duplicate rejected';
  });

  await check('R08', 'GET includes the new reader', async () => {
    const res = await api('/api/trusted-readers', { cookie: auditorCookie });
    const found = (await res.json()).readers.find((r) => r.id === readerId);
    assert(found && found.value === `${TAG} Microsoft`, 'created reader not listed');
    return 'listed';
  });

  await check('R09', 'DELETE -> 204; repeat -> 404; malformed id -> 404; audited', async () => {
    const res = await api(`/api/trusted-readers/${readerId}`, { cookie: authorCookie, method: 'DELETE' });
    assert(res.status === 204, `expected 204, got ${res.status}`);
    const again = await api(`/api/trusted-readers/${readerId}`, { cookie: authorCookie, method: 'DELETE' });
    assert(again.status === 404, `repeat: expected 404, got ${again.status}`);
    const mal = await api('/api/trusted-readers/not-a-number', { cookie: authorCookie, method: 'DELETE' });
    assert(mal.status === 404, `malformed: expected 404, got ${mal.status}`);
    const a = await pool.query(
      `select 1 from audit_log where action = 'trusted_reader.delete' and target = $1`, [String(readerId)]);
    assert(a.rows.length === 1, 'deletion not audited');
    return '204 / 404 / 404, delete audited';
  });

  // ============ C. Agent delivery (real mTLS) ============
  const keys2048 = forge.pki.rsa.generateKeyPair(2048);
  const enroll = await (async () => {
    const tok = await et.createToken({ description: TAG, maxUses: 1, createdBy: TAG });
    const { csrPem, keyPem } = csrFrom(keys2048, 'agent-cn');
    const res = await request({
      pathname: '/agent/enroll', method: 'POST',
      body: { token: tok.token, csrPem, hostname: `${TAG}-pc1` },
    });
    assert(res.status === 201, `enroll failed: ${res.status}`);
    return { agentId: res.body.agentId, keyPem, certPem: res.body.certificate };
  })();
  const agentTls = { key: enroll.keyPem, cert: enroll.certPem, verifyServer: true };

  await check('R10', 'GET /agent/trusted-readers delivers {matchType,value} + audited', async () => {
    await api('/api/trusted-readers', {
      cookie: authorCookie, method: 'POST',
      body: { matchType: 'path', value: `${TAG}\\Program Files\\Office`, note: `${TAG} office path` },
    });
    const res = await request({ pathname: '/agent/trusted-readers', method: 'GET', ...agentTls });
    assert(res.status === 200, `expected 200, got ${res.status}`);
    assert(Array.isArray(res.body.readers), 'missing readers array');
    const mine = res.body.readers.find((r) => r.value === `${TAG}\\Program Files\\Office`);
    assert(mine && mine.matchType === 'path', 'delivered reader shape wrong');
    assert(mine.id === undefined && mine.createdBy === undefined, 'agent payload should be {matchType,value} only');
    const a = await pool.query(
      `select 1 from audit_log where action = 'agent.readers_delivered' and target = $1`, [enroll.agentId]);
    assert(a.rows.length >= 1, 'delivery not audited');
    return `delivered ${res.body.readers.length} reader(s), audited`;
  });

  await check('R11', 'GET /agent/trusted-readers WITHOUT a client cert -> 401', async () => {
    const res = await request({ pathname: '/agent/trusted-readers', method: 'GET' });
    assert(res.status === 401, `expected 401, got ${res.status}`);
    return 'no cert -> 401';
  });

  // ============ D. Invariant ============
  await check('R12', 'audit hash-chain intact after all operations', async () => {
    const broken = await verifyChain();
    assert(broken === null, `chain broken at seq ${broken}`);
    return 'AUDIT CHAIN INTACT';
  });

  await cleanup(true);
  await new Promise((r) => adminServer.close(r));
  await new Promise((r) => mtlsServer.close(r));

  console.log(`\n${passed} passed, ${failed} failed, ${results.length} total\n`);
  fs.writeFileSync(
    path.join(__dirname, '.trustedReaders-results.json'),
    JSON.stringify({ generatedAt: new Date().toISOString(), passed, failed, results }, null, 2)
  );
  await pool.end();
  process.exit(failed === 0 ? 0 : 1);
}

main().catch(async (err) => {
  console.error(err);
  try { await cleanup(true); } catch { /* ignore */ }
  try { if (adminServer) adminServer.close(); } catch { /* ignore */ }
  try { if (mtlsServer) mtlsServer.close(); } catch { /* ignore */ }
  try { await pool.end(); } catch { /* already closing */ }
  process.exit(1);
});
