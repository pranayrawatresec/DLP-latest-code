'use strict';
// M6 test harness — agent-facing trusted-config delivery + on_block_band.
//
// Covers the pinned M6 contract:
//   * GET /agent/trusted-config over REAL mTLS returns destinations plus the
//     UNWRAPPED KEKs (decoded length exactly 32 bytes), includes referenced +
//     rotated keys, EXCLUDES destroyed keys, and 503s with no ORK (fail secure).
//   * unwrapKek(wrapKek(x)) === x (crypto layout unit check).
//   * on_block_band: POST validation (block default, seal allowed, other 400)
//     round-tripped through the admin POST/GET.
//   * audit: one agent.keys_delivered entry per delivery (ids only).
//
// Two in-process servers: the admin app over plain HTTP (login cookies) and the
// agentApp over HTTPS with the real CA (client certs). Creates its own tagged
// users/keys/destinations/agents and cleans them up. Audit rows remain.
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

// Deterministic test ORK — set BEFORE the apps are required.
process.env.DLP_ORG_ROOT_KEY = crypto.randomBytes(32).toString('hex');
const app = require('../app');
const agentApp = require('../agent/agentApp');

const TAG = 'cfgtest_' + crypto.randomBytes(4).toString('hex');
const CLS_MAIN = `${TAG}m`; // referenced by a destination
const CLS_ROT = `${TAG}r`; // rotated, never referenced (must still be delivered)
const CLS_DEAD = `${TAG}d`; // destroyed (must NOT be delivered)
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
function assert(cond, msg) { if (!cond) throw new Error(msg || 'assertion failed'); }

// --- local mirrors of the server wrap/unwrap (crypto-layout unit check) ---
function wrapKek(kek, ork) {
  const nonce = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', ork, nonce);
  const ct = Buffer.concat([c.update(kek), c.final()]);
  return Buffer.concat([nonce, ct, c.getAuthTag()]);
}
function unwrapKek(wrapped, ork) {
  const nonce = wrapped.subarray(0, 12);
  const tag = wrapped.subarray(wrapped.length - 16);
  const ct = wrapped.subarray(12, wrapped.length - 16);
  const d = crypto.createDecipheriv('aes-256-gcm', ork, nonce);
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

// --- admin HTTP helpers ---
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

// --- mTLS HTTPS helper (mirrors enrollment.test.js) ---
function request({ pathname, method = 'POST', body, key, cert, verifyServer = false }) {
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

let KEYS2048;
function csrFrom(keys, cn) {
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;
  csr.setSubject([{ name: 'commonName', value: cn }]);
  csr.sign(keys.privateKey, forge.md.sha256.create());
  return { csrPem: forge.pki.certificationRequestToPem(csr), keyPem: forge.pki.privateKeyToPem(keys.privateKey) };
}

async function cleanup(emails) {
  await pool.query(
    `delete from trusted_destinations where key_id in
       (select id from encryption_keys where classification like $1)`, [`${TAG}%`]);
  await pool.query(`delete from encryption_keys where classification like $1`, [`${TAG}%`]);
  await pool.query(
    `delete from detection_incidents where agent_id in (select id from agents where hostname like $1)`,
    [`${TAG}%`]);
  await pool.query(`delete from agents where hostname like $1`, [`${TAG}%`]);
  await pool.query(`delete from enrollment_tokens where created_by = $1`, [TAG]);
  if (emails) await pool.query(`delete from admin_users where email like $1`, [`${TAG}_%@test.local`]);
}

async function main() {
  console.log('\nAgent trusted-config (M6) — test & edge-case suite\n');
  if (!ca.caExists()) { console.error('No CA — run: npm run init-ca'); process.exit(1); }
  await cleanup(false);

  // admin (plain HTTP) + agent (mTLS) servers
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
  const sysCookie = await login(sysadmin.email);
  const authorCookie = await login(author.email);

  // Enroll a real agent over mTLS to obtain a client cert + agent row.
  KEYS2048 = forge.pki.rsa.generateKeyPair(2048);
  const enroll = await (async () => {
    const tok = await et.createToken({ description: TAG, maxUses: 1, createdBy: TAG });
    const { csrPem, keyPem } = csrFrom(KEYS2048, 'agent-cn');
    const res = await request({ pathname: '/agent/enroll', body: { token: tok.token, csrPem, hostname: `${TAG}-pc1` } });
    assert(res.status === 201, `enroll failed: ${res.status}`);
    return { agentId: res.body.agentId, keyPem, certPem: res.body.certificate };
  })();
  const agentTls = { key: enroll.keyPem, cert: enroll.certPem, verifyServer: true };

  // Helper: create a key via the admin API, return its id.
  async function createKey(classification) {
    const res = await api('/api/encryption/keys', { cookie: sysCookie, method: 'POST', body: { classification } });
    assert(res.status === 201, `key create ${classification}: ${res.status}`);
    return (await res.json()).key.id;
  }

  // ---- unit: unwrapKek(wrapKek(x)) === x ----
  await check('C01', 'unwrapKek(wrapKek(x)) === x; decoded length 32', async () => {
    const ork = crypto.randomBytes(32);
    const x = crypto.randomBytes(32);
    const round = unwrapKek(wrapKek(x, ork), ork);
    assert(Buffer.compare(round, x) === 0, 'round trip mismatch');
    assert(round.length === 32, `length ${round.length}`);
    return 'GCM wrap/unwrap identity';
  });

  // ---- on_block_band validation + round trip through admin POST/GET ----
  let mainKeyId;
  await check('C02', 'on_block_band defaults to block when omitted', async () => {
    mainKeyId = await createKey(CLS_MAIN);
    const res = await api('/api/encryption/trusted-destinations', {
      cookie: authorCookie, method: 'POST',
      body: { channel: 'usb', matcher: { serial: `${TAG}-S1` }, mode: 'encrypt_all', keyId: mainKeyId },
    });
    assert(res.status === 201, `expected 201, got ${res.status}`);
    const { destination: d } = await res.json();
    assert(d.onBlockBand === 'block', `default onBlockBand is ${d.onBlockBand}`);
    return 'default block';
  });

  let sealDestId;
  await check('C03', 'onBlockBand:seal accepted, round-trips through GET; audit records it', async () => {
    const res = await api('/api/encryption/trusted-destinations', {
      cookie: authorCookie, method: 'POST',
      body: { channel: 'usb', matcher: { vid: '0951', pid: '1666' }, mode: 'encrypt_sensitive', keyId: mainKeyId, onBlockBand: 'seal' },
    });
    assert(res.status === 201, `expected 201, got ${res.status}`);
    const { destination: d } = await res.json();
    sealDestId = d.id;
    assert(d.onBlockBand === 'seal', `onBlockBand is ${d.onBlockBand}`);
    const g = await api('/api/encryption/trusted-destinations', { cookie: authorCookie });
    const found = (await g.json()).destinations.find((x) => x.id === sealDestId);
    assert(found && found.onBlockBand === 'seal', 'seal not round-tripped through GET');
    const a = await pool.query(
      `select 1 from audit_log where action='trusted_destination.create' and target=$1 and detail->>'onBlockBand'='seal'`,
      [String(sealDestId)]);
    assert(a.rows.length === 1, 'onBlockBand not in create audit detail');
    return 'seal round-trip + audited';
  });

  await check('C04', 'invalid onBlockBand → 400', async () => {
    for (const bad of ['quarantine', 'BLOCK', '', 1, true]) {
      const res = await api('/api/encryption/trusted-destinations', {
        cookie: authorCookie, method: 'POST',
        body: { channel: 'usb', matcher: { serial: `${TAG}-bad` }, mode: 'encrypt_all', keyId: mainKeyId, onBlockBand: bad },
      });
      assert(res.status === 400, `onBlockBand=${JSON.stringify(bad)}: expected 400, got ${res.status}`);
    }
    return '5 invalid onBlockBand rejected';
  });

  // ---- trusted-config delivery ----
  await check('C05', 'GET /agent/trusted-config → 200 with destinations + unwrapped 32-byte keys', async () => {
    const res = await request({ pathname: '/agent/trusted-config', method: 'GET', ...agentTls });
    assert(res.status === 200, `expected 200, got ${res.status}`);
    const { destinations, keys } = res.body;
    assert(Array.isArray(destinations) && destinations.length >= 2, `destinations ${destinations && destinations.length}`);
    const mine = destinations.find((d) => d.channel === 'usb' && d.onBlockBand === 'seal');
    assert(mine && mine.keyId === mainKeyId && mine.matcher.vid === '0951', 'seal destination not delivered correctly');
    assert(Array.isArray(keys) && keys.length >= 1, 'no keys delivered');
    for (const k of keys) {
      assert(typeof k.id === 'string' && typeof k.keyB64 === 'string', 'bad key shape');
      assert(Buffer.from(k.keyB64, 'base64').length === 32, `key ${k.id} decoded length != 32`);
    }
    const referenced = keys.find((k) => k.id === mainKeyId);
    assert(referenced, 'referenced key not delivered');
    return `${destinations.length} destinations, ${keys.length} keys`;
  });

  await check('C06', 'delivery audited once: agent.keys_delivered (ids only), destinationCount set', async () => {
    const before = await pool.query(
      `select count(*)::int n from audit_log where action='agent.keys_delivered' and target=$1`, [enroll.agentId]);
    const res = await request({ pathname: '/agent/trusted-config', method: 'GET', ...agentTls });
    assert(res.status === 200, `expected 200, got ${res.status}`);
    const after = await pool.query(
      `select count(*)::int n from audit_log where action='agent.keys_delivered' and target=$1`, [enroll.agentId]);
    assert(after.rows[0].n === before.rows[0].n + 1, 'not exactly one delivery audit row added');
    const row = await pool.query(
      `select detail from audit_log where action='agent.keys_delivered' and target=$1 order by seq desc limit 1`,
      [enroll.agentId]);
    const detail = row.rows[0].detail;
    assert(Array.isArray(detail.keyIds) && detail.keyIds.includes(mainKeyId), 'keyIds missing in audit');
    assert(typeof detail.destinationCount === 'number', 'destinationCount missing');
    // No key material bytes anywhere in the audit detail.
    const dumped = JSON.stringify(detail);
    const wrapped = await pool.query(`select encode(wrapped_kek,'base64') b64 from encryption_keys where id=$1`, [mainKeyId]);
    assert(!dumped.includes(wrapped.rows[0].b64), 'wrapped bytes leaked into audit!');
    return 'audited, ids only';
  });

  await check('C07', 'rotated-but-unreferenced key IS delivered; active-unreferenced key is NOT', async () => {
    const rotId = await createKey(CLS_ROT);        // v1 active, unreferenced
    await createKey(CLS_ROT);                       // v2 active -> v1 becomes rotated
    const res = await request({ pathname: '/agent/trusted-config', method: 'GET', ...agentTls });
    const keys = res.body.keys;
    assert(keys.find((k) => k.id === rotId), 'rotated unreferenced key not delivered');
    assert(!keys.find((k) => k.id === `class-${CLS_ROT}/v2`), 'active unreferenced key wrongly delivered');
    return 'rotated included, active-unreferenced excluded';
  });

  await check('C08', 'destroyed key is NEVER delivered (even if referenced)', async () => {
    // Point a fresh destination at a dedicated key, then destroy that key.
    const deadKey = await createKey(CLS_DEAD);
    const dres = await api('/api/encryption/trusted-destinations', {
      cookie: authorCookie, method: 'POST',
      body: { channel: 'usb', matcher: { serial: `${TAG}-dead` }, mode: 'encrypt_all', keyId: deadKey },
    });
    assert(dres.status === 201, `dest for dead key: ${dres.status}`);
    const drow = await api(`/api/encryption/keys/${encodeURIComponent(deadKey)}/destroy`, { cookie: sysCookie, method: 'POST' });
    assert(drow.status === 200, `destroy: ${drow.status}`);
    const res = await request({ pathname: '/agent/trusted-config', method: 'GET', ...agentTls });
    assert(res.status === 200, `expected 200, got ${res.status}`);
    assert(!res.body.keys.find((k) => k.id === deadKey), 'destroyed key delivered!');
    // The destination is still listed (references a now-destroyed key) but no
    // key bytes for it are handed out — fail secure.
    assert(res.body.destinations.find((d) => d.keyId === deadKey), 'destination row unexpectedly gone');
    return 'destroyed key excluded from keys[]';
  });

  await check('C09', 'no ORK configured → 503 fail secure, no keys delivered', async () => {
    const saved = process.env.DLP_ORG_ROOT_KEY;
    delete process.env.DLP_ORG_ROOT_KEY;
    try {
      const res = await request({ pathname: '/agent/trusted-config', method: 'GET', ...agentTls });
      assert(res.status === 503, `expected 503, got ${res.status}`);
      assert(/not configured/.test(res.body.error), `unexpected error: ${res.body.error}`);
    } finally {
      process.env.DLP_ORG_ROOT_KEY = saved;
    }
    return '503, nothing delivered';
  });

  await check('C10', 'trusted-config WITHOUT a client cert → 401', async () => {
    const res = await request({ pathname: '/agent/trusted-config', method: 'GET' });
    assert(res.status === 401, `expected 401, got ${res.status}`);
    return 'no cert → 401';
  });

  await check('C11', 'POST /agent/incidents accepts encrypted + persists key_id/sealed_sha256', async () => {
    const sealedHash = crypto.randomBytes(32).toString('hex');
    const res = await request({
      pathname: '/agent/incidents', method: 'POST', ...agentTls,
      body: {
        channel: 'usb', verdict: { idm: [], edm: [] }, fileName: 'plan.docx',
        actionTaken: 'encrypted', keyId: mainKeyId, sealedSha256: sealedHash,
      },
    });
    assert(res.status === 201, `expected 201, got ${res.status}`);
    const row = await pool.query(
      `select action_taken, key_id, sealed_sha256 from detection_incidents where id=$1`, [res.body.id]);
    assert(row.rows[0].action_taken === 'encrypted', `action_taken ${row.rows[0].action_taken}`);
    assert(row.rows[0].key_id === mainKeyId, 'key_id not persisted');
    assert(row.rows[0].sealed_sha256 === sealedHash, 'sealed_sha256 not persisted');
    return 'encrypted incident persisted';
  });

  await check('C12', 'audit hash-chain intact after all operations', async () => {
    const broken = await verifyChain();
    assert(broken === null, `chain broken at seq ${broken}`);
    return 'AUDIT CHAIN INTACT';
  });

  await cleanup(true);
  await new Promise((r) => adminServer.close(r));
  await new Promise((r) => mtlsServer.close(r));

  console.log(`\n${passed} passed, ${failed} failed, ${results.length} total\n`);
  fs.writeFileSync(
    path.join(__dirname, '.agent-trusted-config-results.json'),
    JSON.stringify({ generatedAt: new Date().toISOString(), passed, failed, results }, null, 2)
  );
  await pool.end();
  process.exit(failed === 0 ? 0 : 1);
}

main().catch(async (err) => {
  console.error(err);
  try { await cleanup(true); } catch {}
  try { if (adminServer) adminServer.close(); } catch {}
  try { if (mtlsServer) mtlsServer.close(); } catch {}
  process.exit(1);
});
