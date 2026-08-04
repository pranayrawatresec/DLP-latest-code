'use strict';
// Comprehensive test + edge-case harness for the enrollment-token layer.
//
// Three levels of verification:
//   A. Library — the token lifecycle and the ATOMIC one-time-use guard,
//      including a concurrency race test.
//   B. HTTP + RBAC — the real Express app on an ephemeral port, driven with
//      real login cookies (sysadmin allowed, policy_author forbidden, anon 401).
//   C. Independent invariants — inspecting the DATABASE directly to prove the
//      raw token is never stored and the audit chain stays intact.
//
// Creates its own throwaway users/tokens and cleans them up. Audit-log rows
// are append-only and intentionally remain.
require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const pool = require('../db/pool');
const et = require('../lib/enrollmentTokens');
const { verifyChain } = require('../lib/audit');
const app = require('../app');

const TAG = 'ettest_' + crypto.randomBytes(4).toString('hex');
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

async function main() {
  console.log('\nEnrollment tokens — test & edge-case suite\n');

  // Boot the real app on an ephemeral port.
  await new Promise((resolve) => {
    server = app.listen(0, '127.0.0.1', resolve);
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;

  const sysadmin = await makeUser('sysadmin', 'sysadmin');
  const author = await makeUser('author', 'policy_author');
  const sysCookie = await login(sysadmin.email);
  const authorCookie = await login(author.email);

  // ============ A. Library: lifecycle & atomic use ============
  await check('E01', 'createToken returns a prefixed 256-bit token, once', () => {
    return et.createToken({ description: 'A', createdBy: TAG }).then((t) => {
      assert(t.token.startsWith(et.TOKEN_PREFIX), 'missing prefix');
      const secret = t.token.slice(et.TOKEN_PREFIX.length);
      assert(secret.length >= 43, 'token too short for 256-bit');
      assert(/^[A-Za-z0-9_-]+$/.test(secret), 'not base64url');
      return `${t.token.slice(0, 12)}… (id ${t.id.slice(0, 8)})`;
    });
  });

  await check('E02', 'DB stores ONLY the SHA-256 hash, never the raw token', async () => {
    const t = await et.createToken({ description: 'hashcheck', maxUses: 1, createdBy: TAG });
    const row = await pool.query('select token_hash from enrollment_tokens where id = $1', [t.id]);
    assert(row.rows[0].token_hash === crypto.createHash('sha256').update(t.token).digest('hex'),
      'stored hash != sha256(token)');
    // Prove the raw token appears in NO column of the row.
    const full = await pool.query('select * from enrollment_tokens where id = $1', [t.id]);
    const asText = JSON.stringify(full.rows[0]);
    assert(!asText.includes(t.token), 'raw token found in DB row!');
    return 'hash-only storage confirmed';
  });

  await check('E03', 'valid token redeems; use_count increments', async () => {
    const t = await et.createToken({ maxUses: 1, createdBy: TAG });
    const r = await et.redeemToken(t.token);
    assert(r.ok && r.useCount === 1, `redeem failed: ${JSON.stringify(r)}`);
    return 'redeemed, use_count 0→1';
  });

  await check('E04', 'maxUses=3: three redeems succeed, fourth is exhausted', async () => {
    const t = await et.createToken({ maxUses: 3, createdBy: TAG });
    for (let i = 1; i <= 3; i++) {
      const r = await et.redeemToken(t.token);
      assert(r.ok && r.useCount === i, `use ${i} failed`);
    }
    const over = await et.redeemToken(t.token);
    assert(!over.ok && over.reason === 'exhausted', `4th should be exhausted, got ${JSON.stringify(over)}`);
    return '3/3 used, 4th exhausted';
  });

  await check('E05', 'unknown token is rejected as unknown_token', async () => {
    const r = await et.redeemToken(et.TOKEN_PREFIX + crypto.randomBytes(32).toString('base64url'));
    assert(!r.ok && r.reason === 'unknown_token', JSON.stringify(r));
  });

  await check('E06', 'revoked token cannot be redeemed', async () => {
    const t = await et.createToken({ maxUses: 5, createdBy: TAG });
    await et.revokeToken(t.id);
    const r = await et.redeemToken(t.token);
    assert(!r.ok && r.reason === 'revoked', JSON.stringify(r));
  });

  await check('E07', 'expired token cannot be redeemed', async () => {
    const t = await et.createToken({ maxUses: 5, expiresInHours: 1, createdBy: TAG });
    // Force expiry in the DB (independent of wall clock).
    await pool.query(`update enrollment_tokens set expires_at = now() - interval '1 minute' where id = $1`, [t.id]);
    const r = await et.redeemToken(t.token);
    assert(!r.ok && r.reason === 'expired', JSON.stringify(r));
  });

  await check('E08', 'RACE: maxUses=1 with 25 concurrent redeems → exactly ONE wins', async () => {
    const t = await et.createToken({ maxUses: 1, createdBy: TAG });
    const attempts = await Promise.all(Array.from({ length: 25 }, () => et.redeemToken(t.token)));
    const wins = attempts.filter((a) => a.ok).length;
    assert(wins === 1, `expected exactly 1 winner, got ${wins}`);
    const row = await pool.query('select use_count from enrollment_tokens where id = $1', [t.id]);
    assert(row.rows[0].use_count === 1, `use_count overshot to ${row.rows[0].use_count}`);
    return '1 winner / 24 rejected; no double-spend';
  });

  // ============ Validation ============
  await check('E09', 'validation: maxUses=0 rejected', async () => {
    let ok = false;
    try { await et.createToken({ maxUses: 0, createdBy: TAG }); } catch (e) { ok = e.validation; }
    assert(ok, 'maxUses=0 should be a ValidationError');
  });
  await check('E10', 'validation: negative expiry rejected', async () => {
    let ok = false;
    try { await et.createToken({ expiresInHours: -5, createdBy: TAG }); } catch (e) { ok = e.validation; }
    assert(ok, 'negative expiry should be a ValidationError');
  });
  await check('E11', 'validation: maxUses over cap rejected', async () => {
    let ok = false;
    try { await et.createToken({ maxUses: et.MAX_USES_CAP + 1, createdBy: TAG }); } catch (e) { ok = e.validation; }
    assert(ok, 'over-cap maxUses should be a ValidationError');
  });

  // ============ B. HTTP + RBAC ============
  await check('E12', 'POST create as sysadmin → 201 with token + warning', async () => {
    const res = await api('/api/enrollment-tokens', {
      cookie: sysCookie, method: 'POST', body: { description: 'rollout wave 1', maxUses: 50 },
    });
    assert(res.status === 201, `status ${res.status}`);
    const j = await res.json();
    assert(j.token && j.token.startsWith(et.TOKEN_PREFIX), 'no token in response');
    assert(/once/i.test(j.warning), 'missing one-time warning');
    return `201, id ${j.id.slice(0, 8)}`;
  });

  await check('E13', 'POST create as policy_author → 403 (RBAC) + audited', async () => {
    const res = await api('/api/enrollment-tokens', {
      cookie: authorCookie, method: 'POST', body: { maxUses: 1 },
    });
    assert(res.status === 403, `expected 403, got ${res.status}`);
    const denied = await pool.query(
      `select 1 from audit_log where action = 'authz.denied' and actor = $1
         and detail->>'required' = 'enrollment.manage' limit 1`,
      [author.email]
    );
    assert(denied.rows.length === 1, 'denial not audited');
    return '403 + authz.denied logged';
  });

  await check('E14', 'POST create unauthenticated → 401', async () => {
    const res = await api('/api/enrollment-tokens', { method: 'POST', body: { maxUses: 1 } });
    assert(res.status === 401, `expected 401, got ${res.status}`);
  });

  await check('E15', 'GET list never leaks token or hash', async () => {
    const res = await api('/api/enrollment-tokens', { cookie: sysCookie });
    assert(res.status === 200, `status ${res.status}`);
    const list = await res.json();
    assert(Array.isArray(list) && list.length > 0, 'empty list');
    const text = JSON.stringify(list);
    assert(!/token_hash/.test(text) && !text.includes(et.TOKEN_PREFIX), 'list leaked secret material');
    assert('status' in list[0] && 'remaining' in list[0], 'list missing computed fields');
    return `${list.length} tokens, metadata only`;
  });

  await check('E16', 'revoke via API → 200; token then unusable', async () => {
    const created = await (await api('/api/enrollment-tokens', {
      cookie: sysCookie, method: 'POST', body: { maxUses: 3 },
    })).json();
    const res = await api(`/api/enrollment-tokens/${created.id}/revoke`, { cookie: sysCookie, method: 'POST' });
    assert(res.status === 200, `revoke status ${res.status}`);
    const r = await et.redeemToken(created.token);
    assert(!r.ok && r.reason === 'revoked', 'revoked token still redeemable');
    return 'revoked then rejected';
  });

  await check('E17', 'revoke unknown id → 404; malformed id → 404', async () => {
    const unknown = await api(`/api/enrollment-tokens/${crypto.randomUUID()}/revoke`, { cookie: sysCookie, method: 'POST' });
    assert(unknown.status === 404, `unknown → ${unknown.status}`);
    const malformed = await api('/api/enrollment-tokens/not-a-uuid/revoke', { cookie: sysCookie, method: 'POST' });
    assert(malformed.status === 404, `malformed → ${malformed.status}`);
    return 'both 404, no 500';
  });

  await check('E18', 'API validation: maxUses=0 → 400', async () => {
    const res = await api('/api/enrollment-tokens', { cookie: sysCookie, method: 'POST', body: { maxUses: 0 } });
    assert(res.status === 400, `expected 400, got ${res.status}`);
  });

  // ============ C. Independent invariants ============
  await check('E19', 'audit log has create + revoke events for this run', async () => {
    const c = await pool.query(
      `select count(*)::int n from audit_log where action = 'enrollment_token.create' and actor = $1`,
      [sysadmin.email]
    );
    const v = await pool.query(
      `select count(*)::int n from audit_log where action = 'enrollment_token.revoke' and actor = $1`,
      [sysadmin.email]
    );
    assert(c.rows[0].n >= 2 && v.rows[0].n >= 1, `create=${c.rows[0].n} revoke=${v.rows[0].n}`);
    return `create ${c.rows[0].n}, revoke ${v.rows[0].n}`;
  });

  await check('E20', 'audit hash-chain still intact after all operations', async () => {
    const broken = await verifyChain();
    assert(broken === null, `chain broken at seq ${broken}`);
    return 'AUDIT CHAIN INTACT';
  });

  // ---- cleanup (audit rows are append-only and remain) ----
  await pool.query(`delete from enrollment_tokens where created_by in ($1,$2,$3)`, [TAG, sysadmin.email, author.email]);
  await pool.query(`delete from admin_users where email like $1`, [`${TAG}_%@test.local`]);
  await new Promise((r) => server.close(r));

  console.log(`\n${passed} passed, ${failed} failed, ${results.length} total\n`);
  fs.writeFileSync(
    path.join(__dirname, '.tokens-results.json'),
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
