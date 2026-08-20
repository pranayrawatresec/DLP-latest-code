'use strict';
// Test harness for endpoint GROUPS + per-group policy targeting.
//   A. RBAC: 401 anon; groups:read for author/sysadmin/auditor; groups:write only
//      for policy_author (auditor/sysadmin create -> 403 + audited).
//   B. CRUD + validation: create/list/rename/delete; duplicate name; Default group
//      is undeletable.
//   C. Per-group policy: set a non-default group's override; the Default (id=1) is
//      untouched; a fresh group inherits Default until customised.
//   D. Delivery (real mTLS): an agent ASSIGNED to a group gets the group's policy;
//      an UNASSIGNED agent (NULL group) gets the Default. Proves targeting works
//      end-to-end and is backward compatible.
//   E. Invariant: the audit hash-chain stays intact.
// Mirrors trustedReaders.test.js (admin app over HTTP + agentApp over real mTLS).
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

const TAG = 'grptest_' + crypto.randomBytes(4).toString('hex');
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

async function enrollAgent(hostname) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const tok = await et.createToken({ description: TAG, maxUses: 1, createdBy: TAG });
  const { csrPem, keyPem } = csrFrom(keys, 'agent-cn');
  const res = await request({
    pathname: '/agent/enroll', method: 'POST',
    body: { token: tok.token, csrPem, hostname },
  });
  assert(res.status === 201, `enroll ${hostname} failed: ${res.status}`);
  return { agentId: res.body.agentId, tls: { key: keyPem, cert: res.body.certificate, verifyServer: true } };
}

async function cleanup(emails) {
  await pool.query(`delete from trusted_readers where value like $1 or note like $1`, [`${TAG}%`]);
  await pool.query(`delete from groups where name like $1`, [`${TAG}%`]);
  await pool.query(`delete from agents where hostname like $1`, [`${TAG}%`]);
  await pool.query(`delete from enrollment_tokens where created_by = $1`, [TAG]);
  if (emails) await pool.query(`delete from admin_users where email like $1`, [`${TAG}_%@test.local`]);
}

async function main() {
  console.log('\nEndpoint groups + per-group policy targeting - test suite\n');
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

  // ============ A. RBAC ============
  await check('G01', 'anon GET /api/groups -> 401', async () => {
    const res = await api('/api/groups');
    assert(res.status === 401, `expected 401, got ${res.status}`);
  });

  await check('G02', 'GET groups: author, sysadmin, auditor all 200', async () => {
    for (const [who, cookie] of [['author', authorCookie], ['sysadmin', sysCookie], ['auditor', auditorCookie]]) {
      const res = await api('/api/groups', { cookie });
      assert(res.status === 200, `${who}: expected 200, got ${res.status}`);
      const { groups } = await res.json();
      assert(Array.isArray(groups) && groups.some((g) => g.isDefault), `${who}: Default group missing`);
    }
    return 'read allowed for all three; Default present';
  });

  await check('G03', 'POST group as auditor -> 403 (write = policy_author) + audited', async () => {
    const res = await api('/api/groups', { cookie: auditorCookie, method: 'POST', body: { name: `${TAG}_x` } });
    assert(res.status === 403, `expected 403, got ${res.status}`);
    const denied = await pool.query(
      `select 1 from audit_log where action='authz.denied' and actor=$1 and detail->>'required'='groups:write' limit 1`,
      [auditor.email]);
    assert(denied.rows.length === 1, 'denial not audited');
    return '403 + authz.denied logged';
  });

  // ============ B. CRUD ============
  let pilotId;
  await check('G04', 'POST group (author) -> 201 + audited', async () => {
    const res = await api('/api/groups', {
      cookie: authorCookie, method: 'POST',
      body: { name: `${TAG}_pilot`, description: 'pilot ring' },
    });
    assert(res.status === 201, `expected 201, got ${res.status}`);
    const { group } = await res.json();
    pilotId = group.id;
    assert(group.name === `${TAG}_pilot` && group.isDefault === false, 'shape wrong');
    const a = await pool.query(`select 1 from audit_log where action='group.create' and target=$1`, [String(pilotId)]);
    assert(a.rows.length === 1, 'create not audited');
    return `group ${pilotId} created`;
  });

  await check('G05', 'duplicate group name -> 409', async () => {
    const res = await api('/api/groups', { cookie: authorCookie, method: 'POST', body: { name: `${TAG}_pilot` } });
    assert(res.status === 409, `expected 409, got ${res.status}`);
    return 'unique name enforced';
  });

  await check('G05b', 'DB rejects over-length group name (length check lives in DB)', async () => {
    let code = null;
    try {
      await pool.query(`insert into groups (name, created_by) values ($1, 'test')`, [`${TAG}_${'z'.repeat(70)}`]);
    } catch (e) {
      code = e.code;
    }
    assert(code === '23514', `over-length name: expected 23514, got ${code}`);
    return 'DB rejects over-length group name (23514)';
  });

  await check('G06', 'new group lists with 0 machines and no override', async () => {
    const res = await api('/api/groups', { cookie: authorCookie });
    const g = (await res.json()).groups.find((x) => x.id === pilotId);
    assert(g && g.agentCount === 0 && g.hasPolicyOverride === false, 'listing wrong');
    return 'agentCount=0, hasPolicyOverride=false';
  });

  // ============ C. Per-group policy ============
  const PILOT_PATH = `\\${TAG}`; // distinctive watch path proving the override is delivered
  await check('G07', 'set + read a group policy override (Default id=1 untouched)', async () => {
    const before = await pool.query('select mode, watch_paths from read_deny_policy where id = 1');
    const put = await api(`/api/read-deny-policy/group/${pilotId}`, {
      cookie: authorCookie, method: 'PUT',
      body: { mode: 'enforce', posture: 'allowlist', scanFixed: true, watchPaths: [PILOT_PATH], failBlock: false, readersAuthority: 'merge' },
    });
    assert(put.status === 200, `PUT expected 200, got ${put.status}`);
    const get = await api(`/api/read-deny-policy/group/${pilotId}`, { cookie: authorCookie });
    const j = await get.json();
    assert(j.hasOverride === true && j.inheritsDefault === false, 'override flags wrong');
    assert(j.policy.mode === 'enforce' && j.policy.watchPaths.includes(PILOT_PATH), 'override policy wrong');
    // The global Default (id=1) must be byte-for-byte unchanged.
    const after = await pool.query('select mode, watch_paths from read_deny_policy where id = 1');
    assert(before.rows[0].mode === after.rows[0].mode, 'DEFAULT policy mode changed!');
    assert(JSON.stringify(before.rows[0].watch_paths) === JSON.stringify(after.rows[0].watch_paths), 'DEFAULT watch_paths changed!');
    return 'override set; Default untouched';
  });

  // ============ D. Delivery over real mTLS ============
  const assigned = await enrollAgent(`${TAG}-assigned`);
  const unassigned = await enrollAgent(`${TAG}-unassigned`);

  await check('G08', 'assign an agent to the group (agents.manage) + audited', async () => {
    const res = await api(`/api/agents/${assigned.agentId}/group`, {
      cookie: sysCookie, method: 'PUT', body: { groupId: pilotId },
    });
    assert(res.status === 200, `expected 200, got ${res.status}`);
    // policy_author lacks agents.manage -> assignment is 403 (separation of duties)
    const denied = await api(`/api/agents/${assigned.agentId}/group`, {
      cookie: authorCookie, method: 'PUT', body: { groupId: pilotId },
    });
    assert(denied.status === 403, `author assign expected 403, got ${denied.status}`);
    const a = await pool.query(`select 1 from audit_log where action='agent.group_assign' and target=$1`, [assigned.agentId]);
    assert(a.rows.length >= 1, 'assignment not audited');
    return 'assigned by sysadmin; author 403';
  });

  await check('G09', 'DELIVERY: assigned agent gets group policy; unassigned gets Default', async () => {
    const a = await request({ pathname: '/agent/read-deny-policy', method: 'GET', ...assigned.tls });
    assert(a.status === 200, `assigned: expected 200, got ${a.status}`);
    assert(a.body.policy.mode === 'enforce' && a.body.policy.watchPaths.includes(PILOT_PATH),
      `assigned agent did NOT get the group policy: ${JSON.stringify(a.body.policy)}`);

    const u = await request({ pathname: '/agent/read-deny-policy', method: 'GET', ...unassigned.tls });
    assert(u.status === 200, `unassigned: expected 200, got ${u.status}`);
    assert(!(u.body.policy.watchPaths || []).includes(PILOT_PATH),
      `unassigned agent LEAKED the group policy: ${JSON.stringify(u.body.policy)}`);
    return 'per-group delivery correct; unassigned isolated from the group override';
  });

  await check('G09b', 'per-group readers: global reaches all, group-scoped only its group', async () => {
    const globalName = `${TAG}_glob.exe`
    const g = await api('/api/trusted-readers', {
      cookie: authorCookie, method: 'POST', body: { matchType: 'name', value: globalName },
    })
    assert(g.status === 201, `global reader create: ${g.status}`)
    const pilotName = `${TAG}_pilotonly.exe`
    const p = await api('/api/trusted-readers', {
      cookie: authorCookie, method: 'POST', body: { matchType: 'name', value: pilotName, groupId: pilotId },
    })
    assert(p.status === 201, `pilot reader create: ${p.status}`)

    const av = (await request({ pathname: '/agent/trusted-readers', method: 'GET', ...assigned.tls })).body.readers.map((r) => r.value)
    const uv = (await request({ pathname: '/agent/trusted-readers', method: 'GET', ...unassigned.tls })).body.readers.map((r) => r.value)

    assert(av.includes(globalName), 'assigned agent missing the GLOBAL reader')
    assert(uv.includes(globalName), 'unassigned agent missing the GLOBAL reader')
    assert(av.includes(pilotName), 'assigned agent missing its group-scoped reader')
    assert(!uv.includes(pilotName), 'unassigned agent LEAKED the pilot-only reader')
    return 'global delivered to both; group reader only to the assigned agent'
  })

  await check('G10', 'reset override -> group inherits Default; assigned agent follows', async () => {
    const del = await api(`/api/read-deny-policy/group/${pilotId}`, { cookie: authorCookie, method: 'DELETE' });
    assert(del.status === 204, `reset expected 204, got ${del.status}`);
    const a = await request({ pathname: '/agent/read-deny-policy', method: 'GET', ...assigned.tls });
    assert(!(a.body.policy.watchPaths || []).includes(PILOT_PATH),
      'assigned agent still got the removed override');
    return 'override cleared; assigned agent inherits Default';
  });

  await check('G11', 'Default group cannot be deleted -> 400', async () => {
    const list = await (await api('/api/groups', { cookie: authorCookie })).json();
    const def = list.groups.find((g) => g.isDefault);
    const res = await api(`/api/groups/${def.id}`, { cookie: authorCookie, method: 'DELETE' });
    assert(res.status === 400, `expected 400, got ${res.status}`);
    return 'Default protected';
  });

  await check('G12', 'DELETE group -> 204; assigned machine returns to Default', async () => {
    const res = await api(`/api/groups/${pilotId}`, { cookie: authorCookie, method: 'DELETE' });
    assert(res.status === 204, `expected 204, got ${res.status}`);
    const row = await pool.query('select group_id from agents where id = $1', [assigned.agentId]);
    assert(row.rows[0].group_id === null, 'agent group_id not reset to NULL on group delete');
    return '204; agent returned to Default (group_id NULL)';
  });

  // ============ E. Invariant ============
  await check('G13', 'audit hash-chain intact after all operations', async () => {
    const broken = await verifyChain();
    assert(broken === null, `chain broken at seq ${broken}`);
    return 'AUDIT CHAIN INTACT';
  });

  await cleanup(true);
  await new Promise((r) => adminServer.close(r));
  await new Promise((r) => mtlsServer.close(r));

  console.log(`\n${passed} passed, ${failed} failed, ${results.length} total\n`);
  fs.writeFileSync(
    path.join(__dirname, '.groups-results.json'),
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
