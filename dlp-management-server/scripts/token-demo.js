'use strict';
// =====================================================================
// Manual, narrated walkthrough of the enrollment-token lifecycle — run it
// to SEE what the layer does. Uses the library directly against the dev DB
// and cleans up the tokens it creates (audit rows are append-only and remain).
//
//   node scripts/token-demo.js
//
// It focuses on token MECHANICS. RBAC (sysadmin-only) is enforced at the HTTP
// route and is proven separately in  npm run test:tokens.
// =====================================================================
require('dotenv').config();
const crypto = require('crypto');
const pool = require('./../db/pool');
const et = require('../lib/enrollmentTokens');

const line = (c = '─') => console.log(c.repeat(70));
const step = (n, t) => { console.log(''); line('═'); console.log(`  STEP ${n}:  ${t}`); line('═'); };
const say = (s) => console.log('  ' + s);
const good = (s) => console.log('  \x1b[32m✓ ' + s + '\x1b[0m');
const bad = (s) => console.log('  \x1b[31m✗ ' + s + '\x1b[0m');

async function main() {
  const created = [];
  console.log('');
  line('━');
  console.log('   ENROLLMENT TOKENS — MANUAL WALKTHROUGH');
  line('━');

  // STEP 1 — mint
  step(1, 'A sysadmin MINTS a token (raw value shown ONCE)');
  say('In production this is POST /api/enrollment-tokens (sysadmin only).');
  const t = await et.createToken({ description: 'demo rollout', maxUses: 2, expiresInHours: 24, createdBy: 'cli:token-demo' });
  created.push(t.id);
  good(`token: ${t.token}`);
  say(`id ${t.id}   maxUses ${t.maxUses}   expires ${new Date(t.expiresAt).toISOString()}`);
  say('This raw string goes into the installer config. It is never shown again.');

  // STEP 2 — DB stores only the hash
  step(2, 'The database stores ONLY a SHA-256 hash — never the token');
  const row = await pool.query('select token_hash, use_count, max_uses from enrollment_tokens where id = $1', [t.id]);
  const expectHash = crypto.createHash('sha256').update(t.token).digest('hex');
  say(`sha256(token)      = ${expectHash}`);
  say(`stored token_hash  = ${row.rows[0].token_hash}`);
  row.rows[0].token_hash === expectHash
    ? good('they match — and the raw token is nowhere in the DB')
    : bad('hash mismatch');
  say(`use_count ${row.rows[0].use_count} / ${row.rows[0].max_uses}`);

  // STEP 3 — redeem (agent enrolls)
  step(3, 'An AGENT redeems the token (this is what enrollment will call)');
  const r1 = await et.redeemToken(t.token);
  good(`redeem #1 → ok=${r1.ok}, use_count now ${r1.useCount}/${r1.maxUses}`);
  const r2 = await et.redeemToken(t.token);
  good(`redeem #2 → ok=${r2.ok}, use_count now ${r2.useCount}/${r2.maxUses}`);

  // STEP 4 — exhaustion
  step(4, 'A 3rd redeem is refused — the token is used up');
  const r3 = await et.redeemToken(t.token);
  !r3.ok && r3.reason === 'exhausted'
    ? good(`refused: reason="${r3.reason}" (internal; the agent just sees a generic rejection)`)
    : bad(`expected exhausted, got ${JSON.stringify(r3)}`);

  // STEP 5 — unknown / forged token
  step(5, 'A guessed / forged token is refused');
  const fake = et.TOKEN_PREFIX + crypto.randomBytes(32).toString('base64url');
  const rf = await et.redeemToken(fake);
  !rf.ok && rf.reason === 'unknown_token' ? good(`refused: reason="${rf.reason}"`) : bad('forged token not refused');

  // STEP 6 — revoke
  step(6, 'A sysadmin REVOKES a token → immediately unusable');
  const t2 = await et.createToken({ description: 'to be revoked', maxUses: 5, createdBy: 'cli:token-demo' });
  created.push(t2.id);
  say(`minted ${t2.id.slice(0, 8)} with 5 uses`);
  await et.revokeToken(t2.id);
  const rr = await et.redeemToken(t2.token);
  !rr.ok && rr.reason === 'revoked' ? good(`after revoke, redeem refused: reason="${rr.reason}"`) : bad('revoked token still worked');

  // STEP 7 — concurrency / no double-spend
  step(7, 'RACE: 20 agents try the SAME single-use token at once');
  const t3 = await et.createToken({ description: 'race', maxUses: 1, createdBy: 'cli:token-demo' });
  created.push(t3.id);
  const attempts = await Promise.all(Array.from({ length: 20 }, () => et.redeemToken(t3.token)));
  const wins = attempts.filter((a) => a.ok).length;
  const finalRow = await pool.query('select use_count from enrollment_tokens where id = $1', [t3.id]);
  wins === 1 && finalRow.rows[0].use_count === 1
    ? good(`exactly 1 winner / 19 rejected — no double-spend (use_count=${finalRow.rows[0].use_count})`)
    : bad(`double-spend! winners=${wins}, use_count=${finalRow.rows[0].use_count}`);

  // cleanup
  await pool.query('delete from enrollment_tokens where id = any($1)', [created]);
  console.log('');
  line('━');
  console.log('   DONE. Demo tokens cleaned up (audit entries are append-only and remain).');
  console.log('   Full automated suite incl. RBAC over HTTP:  npm run test:tokens');
  line('━');
  await pool.end();
}

main().catch(async (e) => { console.error(e); try { await pool.end(); } catch {} process.exit(1); });
