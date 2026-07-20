// Tamper-evident audit writer.
// Every entry is chained to the previous one: hash = sha256(prev_hash + entry).
// A Postgres advisory lock serializes writers so the chain never forks.
// If auditing fails the caller's action fails too (fail secure) — a security
// product must not perform unauditable actions.
const crypto = require('crypto');
const pool = require('../db/pool');

const AUDIT_CHAIN_LOCK = 42;

// Canonical JSON: object keys sorted recursively. Required because the detail
// column is jsonb and Postgres does not preserve key order — verification must
// re-serialize to exactly the bytes that were hashed.
function canonicalJson(value) {
  if (Array.isArray(value)) {
    return '[' + value.map(canonicalJson).join(',') + ']';
  }
  if (value !== null && typeof value === 'object') {
    const keys = Object.keys(value).sort();
    return (
      '{' +
      keys.map((k) => JSON.stringify(k) + ':' + canonicalJson(value[k])).join(',') +
      '}'
    );
  }
  return JSON.stringify(value);
}

function entryString(ts, actor, action, target, detail) {
  return canonicalJson({ ts, actor, action, target, detail });
}

async function audit(actor, action, target = null, detail = {}) {
  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query('select pg_advisory_xact_lock($1)', [AUDIT_CHAIN_LOCK]);
    const { rows } = await client.query(
      'select hash from audit_log order by seq desc limit 1'
    );
    const prevHash = rows.length ? rows[0].hash : 'genesis';
    const ts = new Date().toISOString();
    const entry = entryString(ts, actor, action, target, detail);
    const hash = crypto
      .createHash('sha256')
      .update(prevHash + entry)
      .digest('hex');
    await client.query(
      `insert into audit_log (ts, actor, action, target, detail, prev_hash, hash)
       values ($1, $2, $3, $4, $5, $6, $7)`,
      [ts, actor, action, target, JSON.stringify(detail), prevHash, hash]
    );
    await client.query('commit');
  } catch (err) {
    await client.query('rollback');
    throw err;
  } finally {
    client.release();
  }
}

// Walks the whole chain and recomputes every hash. Returns the first broken
// sequence number, or null if the chain is intact.
async function verifyChain() {
  const { rows } = await pool.query(
    'select seq, ts, actor, action, target, detail, prev_hash, hash from audit_log order by seq'
  );
  let prevHash = 'genesis';
  for (const row of rows) {
    const entry = entryString(
      row.ts.toISOString(),
      row.actor,
      row.action,
      row.target,
      row.detail
    );
    const expected = crypto
      .createHash('sha256')
      .update(prevHash + entry)
      .digest('hex');
    if (row.prev_hash !== prevHash || row.hash !== expected) return row.seq;
    prevHash = row.hash;
  }
  return null;
}

module.exports = { audit, verifyChain };
