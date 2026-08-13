'use strict';
// Test harness for the encrypt-on-write admin API (routes/encryption.js).
//
// Three levels of verification (pattern: enrollmentTokens.test.js):
//   A. HTTP + RBAC — the real Express app on an ephemeral port, real login
//      cookies: 401 anon, 403 wrong-role (audited), matcher validation.
//   B. Key lifecycle — create/rotate/destroy; ORK missing => 503 fail-secure.
//   C. Independent invariants — DB inspected directly: wrapped_kek never
//      leaves the server, destroy really overwrites the bytes, audit chain
//      stays intact.
//
// Creates its own throwaway users/keys/destinations and cleans them up.
// Audit-log rows are append-only and intentionally remain.
require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const pool = require('../db/pool');
const { verifyChain } = require('../lib/audit');

// Deterministic test ORK — set BEFORE the app is required. A throwaway random
// value, NOT a real key; never persisted anywhere.
process.env.DLP_ORG_ROOT_KEY = crypto.randomBytes(32).toString('hex');
const app = require('../app');

const TAG = 'enctest_' + crypto.randomBytes(4).toString('hex');
const CLASS1 = `${TAG}a`; // classifications must match ^[a-z0-9][a-z0-9_-]{0,63}$
const CLASS2 = `${TAG}b`;
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

async function cleanup(emails) {
  // FK order: destinations reference keys.
  await pool.query(
    `delete from trusted_destinations where key_id in
       (select id from encryption_keys where classification like $1)`,
    ['enctest_%']
  );
  await pool.query(`delete from encryption_keys where classification like $1`, ['enctest_%']);
  if (emails) {
    await pool.query(`delete from admin_users where email like $1`, [`${TAG}_%@test.local`]);
  }
}

async function main() {
  console.log('\nEncrypt-on-write API — test & edge-case suite\n');

  // Leftovers from a crashed previous run would skew the "active key" tests.
  await cleanup(false);

  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;

  const sysadmin = await makeUser('sysadmin', 'sysadmin');
  const author = await makeUser('author', 'policy_author');
  const auditor = await makeUser('auditor', 'auditor');
  const sysCookie = await login(sysadmin.email);
  const authorCookie = await login(author.email);
  const auditorCookie = await login(auditor.email);

  // ============ A. RBAC gates ============
  await check('X01', 'anon GET trusted-destinations → 401', async () => {
    const res = await api('/api/encryption/trusted-destinations');
    assert(res.status === 401, `expected 401, got ${res.status}`);
  });

  await check('X02', 'anon POST keys → 401', async () => {
    const res = await api('/api/encryption/keys', { method: 'POST', body: { classification: CLASS1 } });
    assert(res.status === 401, `expected 401, got ${res.status}`);
  });

  await check('X03', 'GET trusted-destinations: author, sysadmin, auditor all 200', async () => {
    for (const [who, cookie] of [['author', authorCookie], ['sysadmin', sysCookie], ['auditor', auditorCookie]]) {
      const res = await api('/api/encryption/trusted-destinations', { cookie });
      assert(res.status === 200, `${who}: expected 200, got ${res.status}`);
      const j = await res.json();
      assert(Array.isArray(j.destinations), `${who}: missing destinations array`);
    }
    return 'all three read roles allowed';
  });

  await check('X04', 'POST trusted-destinations as auditor → 403 + audited', async () => {
    const res = await api('/api/encryption/trusted-destinations', {
      cookie: auditorCookie, method: 'POST',
      body: { channel: 'usb', matcher: { serial: 'S1' }, mode: 'encrypt_all' },
    });
    assert(res.status === 403, `expected 403, got ${res.status}`);
    const denied = await pool.query(
      `select 1 from audit_log where action = 'authz.denied' and actor = $1
         and detail->>'required' = 'trusted_destinations:write' limit 1`,
      [auditor.email]
    );
    assert(denied.rows.length === 1, 'denial not audited');
    return '403 + authz.denied logged';
  });

  await check('X05', 'POST trusted-destinations as sysadmin → 403 (write is policy_author only)', async () => {
    const res = await api('/api/encryption/trusted-destinations', {
      cookie: sysCookie, method: 'POST',
      body: { channel: 'usb', matcher: { serial: 'S1' }, mode: 'encrypt_all' },
    });
    assert(res.status === 403, `expected 403, got ${res.status}`);
  });

  await check('X06', 'POST keys as policy_author → 403 (manage is sysadmin only)', async () => {
    const res = await api('/api/encryption/keys', {
      cookie: authorCookie, method: 'POST', body: { classification: CLASS1 },
    });
    assert(res.status === 403, `expected 403, got ${res.status}`);
  });

  // ============ B. Key lifecycle ============
  await check('X07', 'POST keys without ORK configured → 503, nothing created', async () => {
    const saved = process.env.DLP_ORG_ROOT_KEY;
    delete process.env.DLP_ORG_ROOT_KEY;
    try {
      const res = await api('/api/encryption/keys', {
        cookie: sysCookie, method: 'POST', body: { classification: CLASS1 },
      });
      assert(res.status === 503, `expected 503, got ${res.status}`);
      const j = await res.json();
      assert(/not configured/.test(j.error), `unexpected error: ${j.error}`);
    } finally {
      process.env.DLP_ORG_ROOT_KEY = saved;
    }
    const n = await pool.query(`select count(*)::int n from encryption_keys where classification = $1`, [CLASS1]);
    assert(n.rows[0].n === 0, 'a key row was created without an ORK!');
    return 'fail secure: 503, no row';
  });

  await check('X08', 'POST destination with NO active key and no keyId → 409', async () => {
    const active = await pool.query(`select count(*)::int n from encryption_keys where state = 'active'`);
    if (active.rows[0].n > 0) {
      return `SKIPPED — ${active.rows[0].n} pre-existing active key(s) in dev DB`;
    }
    const res = await api('/api/encryption/trusted-destinations', {
      cookie: authorCookie, method: 'POST',
      body: { channel: 'usb', matcher: { serial: 'S1' }, mode: 'encrypt_all' },
    });
    assert(res.status === 409, `expected 409, got ${res.status}`);
    return '409, no silent default';
  });

  let key1v1;
  await check('X09', 'POST keys → 201, id class-<c>/v1, active; wrapped_kek stored as 60 bytes', async () => {
    const res = await api('/api/encryption/keys', {
      cookie: sysCookie, method: 'POST', body: { classification: CLASS1 },
    });
    assert(res.status === 201, `expected 201, got ${res.status}`);
    const j = await res.json();
    key1v1 = j.key;
    assert(j.key.id === `class-${CLASS1}/v1`, `unexpected id ${j.key.id}`);
    assert(j.key.version === 1 && j.key.state === 'active', 'wrong version/state');
    const row = await pool.query(
      `select octet_length(wrapped_kek) as len from encryption_keys where id = $1`, [j.key.id]);
    assert(row.rows[0].len === 60, `wrapped_kek is ${row.rows[0].len} bytes, expected 60 (12 nonce + 32 ct + 16 tag)`);
    const a = await pool.query(
      `select 1 from audit_log where action = 'encryption_key.create' and target = $1 and actor = $2`,
      [j.key.id, sysadmin.email]);
    assert(a.rows.length === 1, 'key creation not audited');
    return `${j.key.id} created + audited`;
  });

  await check('X10', 'invalid classification → 400', async () => {
    for (const bad of ['', 'Has Spaces', 'UPPER', '-leading', 'a'.repeat(70), 42, null]) {
      const res = await api('/api/encryption/keys', {
        cookie: sysCookie, method: 'POST', body: { classification: bad },
      });
      assert(res.status === 400, `classification ${JSON.stringify(bad)}: expected 400, got ${res.status}`);
    }
    return '6 bad classifications rejected';
  });

  let key1v2;
  await check('X11', 'rotate: same classification again → v2 active, v1 rotated', async () => {
    const res = await api('/api/encryption/keys', {
      cookie: sysCookie, method: 'POST', body: { classification: CLASS1 },
    });
    assert(res.status === 201, `expected 201, got ${res.status}`);
    key1v2 = (await res.json()).key;
    assert(key1v2.id === `class-${CLASS1}/v2` && key1v2.state === 'active', `unexpected ${JSON.stringify(key1v2)}`);
    const v1 = await pool.query(`select state from encryption_keys where id = $1`, [key1v1.id]);
    assert(v1.rows[0].state === 'rotated', `v1 state is ${v1.rows[0].state}, expected rotated`);
    return 'v1 → rotated, v2 → active';
  });

  await check('X12', 'GET keys lists metadata, NEVER wrapped_kek bytes', async () => {
    const res = await api('/api/encryption/keys', { cookie: auditorCookie });
    assert(res.status === 200, `expected 200, got ${res.status}`);
    const text = JSON.stringify(await res.json());
    assert(!/wrapped/i.test(text) && !/kek/i.test(text), 'response mentions wrapped/kek material');
    const row = await pool.query(
      `select encode(wrapped_kek, 'base64') b64, encode(wrapped_kek, 'hex') hex
         from encryption_keys where id = $1`, [key1v2.id]);
    assert(!text.includes(row.rows[0].b64) && !text.includes(row.rows[0].hex),
      'wrapped_kek bytes leaked into the key list!');
    return 'metadata only';
  });

  // ============ Matcher validation ============
  await check('X13', 'matcher validation: bad shapes all 400', async () => {
    const bads = [
      { channel: 'usb', mode: 'encrypt_all' },                                        // no matcher
      { channel: 'usb', matcher: 'serial=X', mode: 'encrypt_all' },                   // not an object
      { channel: 'usb', matcher: { serial: '' }, mode: 'encrypt_all' },               // empty serial
      { channel: 'usb', matcher: { vid: '0951' }, mode: 'encrypt_all' },              // pid missing
      { channel: 'usb', matcher: { vid: 'zzzz', pid: '1666' }, mode: 'encrypt_all' }, // non-hex vid
      { channel: 'usb', matcher: { vid: '0951', pid: '16660' }, mode: 'encrypt_all' },// pid too long
      { channel: 'usb', matcher: { serial: 'X', extra: 1 }, mode: 'encrypt_all' },    // unknown key
      { channel: 'usb', matcher: { serial: 'X' }, mode: 'plaintext' },                // bad mode
      { channel: 'usb', matcher: { serial: 'X' } },                                   // mode missing
      { channel: 'email', matcher: { serial: 'X' }, mode: 'encrypt_all' },            // channel not in v1
    ];
    for (const [i, body] of bads.entries()) {
      const res = await api('/api/encryption/trusted-destinations', {
        cookie: authorCookie, method: 'POST', body,
      });
      assert(res.status === 400, `case ${i}: expected 400, got ${res.status}`);
    }
    return `${bads.length} invalid bodies rejected`;
  });

  // ============ Destinations ============
  await check('X14', 'default keyId with multiple active keys → 409 (ambiguous)', async () => {
    const r2 = await api('/api/encryption/keys', {
      cookie: sysCookie, method: 'POST', body: { classification: CLASS2 },
    });
    assert(r2.status === 201, `second classification key: ${r2.status}`);
    const res = await api('/api/encryption/trusted-destinations', {
      cookie: authorCookie, method: 'POST',
      body: { channel: 'usb', matcher: { serial: 'AMBIG' }, mode: 'encrypt_all' },
    });
    assert(res.status === 409, `expected 409, got ${res.status}`);
    return 'refused to guess between active keys';
  });

  let destId;
  await check('X15', 'POST destination with explicit keyId → 201 with camelCase shape', async () => {
    const res = await api('/api/encryption/trusted-destinations', {
      cookie: authorCookie, method: 'POST',
      body: {
        channel: 'usb', matcher: { vid: '0951', pid: '1666' },
        mode: 'encrypt_sensitive', keyId: key1v2.id, note: 'courier stick test',
      },
    });
    assert(res.status === 201, `expected 201, got ${res.status}`);
    const { destination: d } = await res.json();
    destId = d.id;
    assert(d.channel === 'usb', 'channel wrong');
    assert(d.matcher.vid === '0951' && d.matcher.pid === '1666', 'matcher wrong');
    assert(d.mode === 'encrypt_sensitive' && d.keyId === key1v2.id, 'mode/keyId wrong');
    assert(d.createdBy === author.email && d.createdAt, 'createdBy/createdAt missing');
    const a = await pool.query(
      `select 1 from audit_log where action = 'trusted_destination.create' and target = $1`,
      [String(d.id)]);
    assert(a.rows.length === 1, 'creation not audited');
    return `destination ${d.id} created + audited`;
  });

  await check('X16', 'POST destination with rotated keyId → 400 (only active keys usable)', async () => {
    const res = await api('/api/encryption/trusted-destinations', {
      cookie: authorCookie, method: 'POST',
      body: { channel: 'usb', matcher: { serial: 'ROT' }, mode: 'encrypt_all', keyId: key1v1.id },
    });
    assert(res.status === 400, `expected 400, got ${res.status}`);
  });

  await check('X17', 'GET trusted-destinations includes the new entry', async () => {
    const res = await api('/api/encryption/trusted-destinations', { cookie: auditorCookie });
    const j = await res.json();
    const found = j.destinations.find((d) => d.id === destId);
    assert(found && found.keyId === key1v2.id, 'created destination not listed');
    return `${j.destinations.length} listed`;
  });

  await check('X18', 'DELETE destination → 204; repeat → 404; malformed id → 404; audited', async () => {
    const res = await api(`/api/encryption/trusted-destinations/${destId}`, {
      cookie: authorCookie, method: 'DELETE',
    });
    assert(res.status === 204, `expected 204, got ${res.status}`);
    const again = await api(`/api/encryption/trusted-destinations/${destId}`, {
      cookie: authorCookie, method: 'DELETE',
    });
    assert(again.status === 404, `repeat: expected 404, got ${again.status}`);
    const mal = await api('/api/encryption/trusted-destinations/not-a-number', {
      cookie: authorCookie, method: 'DELETE',
    });
    assert(mal.status === 404, `malformed: expected 404, got ${mal.status}`);
    const a = await pool.query(
      `select 1 from audit_log where action = 'trusted_destination.delete' and target = $1`,
      [String(destId)]);
    assert(a.rows.length === 1, 'deletion not audited');
    return '204 / 404 / 404, delete audited';
  });

  // ============ Destroy (single-person, owner decision) ============
  await check('X19', 'destroy as policy_author → 403', async () => {
    const res = await api(`/api/encryption/keys/${encodeURIComponent(key1v2.id)}/destroy`, {
      cookie: authorCookie, method: 'POST',
    });
    assert(res.status === 403, `expected 403, got ${res.status}`);
  });

  await check('X20', 'destroy as sysadmin → wrapped bytes overwritten, state destroyed, both steps audited', async () => {
    const before = await pool.query(
      `select encode(wrapped_kek, 'hex') hex from encryption_keys where id = $1`, [key1v2.id]);
    const res = await api(`/api/encryption/keys/${encodeURIComponent(key1v2.id)}/destroy`, {
      cookie: sysCookie, method: 'POST',
    });
    assert(res.status === 200, `expected 200, got ${res.status}`);
    const { key } = await res.json();
    assert(key.state === 'destroyed' && key.destroyedBy === sysadmin.email && key.destroyedAt,
      `bad destroy result ${JSON.stringify(key)}`);
    const after = await pool.query(
      `select encode(wrapped_kek, 'hex') hex, state, destroyed_by from encryption_keys where id = $1`,
      [key1v2.id]);
    assert(after.rows[0].hex !== before.rows[0].hex, 'wrapped_kek bytes NOT overwritten!');
    assert(after.rows[0].hex.length === before.rows[0].hex.length, 'overwrite changed length');
    assert(after.rows[0].state === 'destroyed' && after.rows[0].destroyed_by === sysadmin.email,
      'DB state/destroyed_by wrong');
    const req_ = await pool.query(
      `select 1 from audit_log where action = 'encryption_key.destroy_requested' and target = $1`, [key1v2.id]);
    const eff = await pool.query(
      `select 1 from audit_log where action = 'encryption_key.destroyed' and target = $1`, [key1v2.id]);
    assert(req_.rows.length === 1 && eff.rows.length === 1, 'request+effect not both audited');
    return 'crypto-shredded; request AND effect audited';
  });

  await check('X21', 'destroy again → 409; unknown key → 404', async () => {
    const again = await api(`/api/encryption/keys/${encodeURIComponent(key1v2.id)}/destroy`, {
      cookie: sysCookie, method: 'POST',
    });
    assert(again.status === 409, `repeat: expected 409, got ${again.status}`);
    const unknown = await api(`/api/encryption/keys/${encodeURIComponent('class-nope/v9')}/destroy`, {
      cookie: sysCookie, method: 'POST',
    });
    assert(unknown.status === 404, `unknown: expected 404, got ${unknown.status}`);
    return '409 / 404';
  });

  // ============ C. Independent invariants ============
  await check('X22', 'audit hash-chain still intact after all operations', async () => {
    const broken = await verifyChain();
    assert(broken === null, `chain broken at seq ${broken}`);
    return 'AUDIT CHAIN INTACT';
  });

  // ---- cleanup (audit rows are append-only and remain) ----
  await cleanup(true);
  await new Promise((r) => server.close(r));

  console.log(`\n${passed} passed, ${failed} failed, ${results.length} total\n`);
  fs.writeFileSync(
    path.join(__dirname, '.encryption-results.json'),
    JSON.stringify({ generatedAt: new Date().toISOString(), passed, failed, results }, null, 2)
  );
  await pool.end();
  process.exit(failed === 0 ? 0 : 1);
}

main().catch(async (err) => {
  console.error(err);
  try { await cleanup(true); } catch {}
  process.exit(1);
});
