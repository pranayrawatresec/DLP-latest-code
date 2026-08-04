'use strict';
// =====================================================================
// Enrollment tokens (Plane 2 ↔ Plane 3 seam, guide §2.2 step 1)
//
// A one-time bootstrap secret a sysadmin mints and bakes into the agent
// installer. On first run the agent spends it to enroll and receive its
// certificate. This module owns the token lifecycle:
//   createToken   — sysadmin mints one (raw value returned ONCE)
//   listTokens    — metadata only; never the token or its hash
//   revokeToken   — soft revoke (row kept for audit history)
//   redeemToken   — the agent spends it; ATOMIC one-time-use consume
//
// Security model:
//   * 256-bit CSPRNG token, prefixed for leak-scanners.
//   * Only SHA-256(token) is stored. A fast hash is correct here — the token
//     has full entropy, so there is nothing to brute-force (unlike a
//     password, which is why passwords use bcrypt and this does not).
//   * Redemption is a single atomic conditional UPDATE — race-safe against
//     concurrent agents trying to spend the last use.
//   * The raw token is never persisted or logged after creation.
//
// Pure data layer: it does not enforce RBAC or write the audit log — the
// route (routes/enrollmentTokens.js) and the future enrollment endpoint own
// authorization and auditing. Keeps this unit-testable in isolation.
// =====================================================================
const crypto = require('crypto');
const pool = require('../db/pool');

const TOKEN_PREFIX = 'dlpenr_'; // "dlp enrollment" — aids secret-scanning tools
const TOKEN_ENTROPY_BYTES = 32; // 256-bit
const DEFAULT_EXPIRY_HOURS = 72;
const MAX_EXPIRY_HOURS = 24 * 365; // 1 year hard cap
const MAX_USES_CAP = 10000;
const DESCRIPTION_MAX = 500;

class ValidationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ValidationError';
    this.validation = true;
  }
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isUuid(v) {
  return typeof v === 'string' && UUID_RE.test(v);
}

function hashToken(raw) {
  return crypto.createHash('sha256').update(String(raw)).digest('hex');
}

function generateToken() {
  return TOKEN_PREFIX + crypto.randomBytes(TOKEN_ENTROPY_BYTES).toString('base64url');
}

// Derive a human-meaningful status from a row (never stored — computed).
function statusOf(row, nowMs = Date.now()) {
  if (row.revoked) return 'revoked';
  if (row.expires_at && new Date(row.expires_at).getTime() <= nowMs) return 'expired';
  if (row.use_count >= row.max_uses) return 'exhausted';
  return 'active';
}

// Mint a token. Returns the RAW token exactly once — the caller must surface
// it to the operator and never store or log it.
async function createToken({ description = '', maxUses = 1, expiresInHours = DEFAULT_EXPIRY_HOURS, createdBy } = {}) {
  if (!createdBy || typeof createdBy !== 'string') {
    throw new ValidationError('createdBy is required');
  }
  const uses = Number(maxUses);
  if (!Number.isInteger(uses) || uses < 1) {
    throw new ValidationError('maxUses must be an integer >= 1');
  }
  if (uses > MAX_USES_CAP) {
    throw new ValidationError(`maxUses must be <= ${MAX_USES_CAP}`);
  }
  const hours = Number(expiresInHours);
  if (!Number.isFinite(hours) || hours <= 0) {
    throw new ValidationError('expiresInHours must be a positive number');
  }
  if (hours > MAX_EXPIRY_HOURS) {
    throw new ValidationError(`expiresInHours must be <= ${MAX_EXPIRY_HOURS}`);
  }
  const desc = String(description || '').trim().slice(0, DESCRIPTION_MAX);

  const raw = generateToken();
  const expiresAt = new Date(Date.now() + hours * 3600 * 1000);
  const { rows } = await pool.query(
    `insert into enrollment_tokens (token_hash, description, max_uses, created_by, expires_at)
     values ($1, $2, $3, $4, $5)
     returning id, description, max_uses, created_at, expires_at`,
    [hashToken(raw), desc, uses, createdBy, expiresAt]
  );
  const r = rows[0];
  return {
    id: r.id,
    description: r.description,
    maxUses: r.max_uses,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
    token: raw, // ONLY appearance of the raw value
  };
}

async function listTokens() {
  const { rows } = await pool.query(
    `select id, description, max_uses, use_count, created_by, created_at, expires_at, revoked
       from enrollment_tokens
      order by created_at desc`
  );
  return rows.map((r) => ({
    id: r.id,
    description: r.description,
    maxUses: r.max_uses,
    useCount: r.use_count,
    remaining: Math.max(0, r.max_uses - r.use_count),
    createdBy: r.created_by,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
    revoked: r.revoked,
    status: statusOf(r),
  }));
}

// Soft revoke — the row stays for audit history. Idempotent.
async function revokeToken(id) {
  if (!isUuid(id)) return { notFound: true };
  const upd = await pool.query(
    `update enrollment_tokens set revoked = true
      where id = $1 and revoked = false
      returning id`,
    [id]
  );
  if (upd.rows.length) return { revoked: true, id };
  const exists = await pool.query('select 1 from enrollment_tokens where id = $1', [id]);
  if (exists.rows.length === 0) return { notFound: true };
  return { revoked: true, id, alreadyRevoked: true };
}

// Spend a token (the agent's enrollment call, next phase, will use this).
// The single conditional UPDATE is the crux: Postgres row-locks the matched
// row, so under concurrency only ONE caller can move use_count from k -> k+1
// while the guard (use_count < max_uses) still holds. No double-spend.
//
// On failure we return a reason for the AUDIT LOG only; the enrollment
// endpoint maps every failure to one generic response so a token-guessing
// attacker learns nothing.
// `db` lets the caller run redemption inside an existing transaction (the
// enrollment endpoint does this so token-consume + agent-insert + CSR-sign
// commit or roll back together — a failed enrollment never wastes a use).
async function redeemToken(rawToken, { db = pool } = {}) {
  if (!rawToken || typeof rawToken !== 'string') {
    return { ok: false, reason: 'missing_token' };
  }
  const tokenHash = hashToken(rawToken);
  const { rows } = await db.query(
    `update enrollment_tokens
        set use_count = use_count + 1
      where token_hash = $1
        and revoked = false
        and (expires_at is null or expires_at > now())
        and use_count < max_uses
      returning id, use_count, max_uses`,
    [tokenHash]
  );
  if (rows.length) {
    return { ok: true, tokenId: rows[0].id, useCount: rows[0].use_count, maxUses: rows[0].max_uses };
  }
  // Classify the failure for auditing (best-effort, outside the hot path).
  const found = await db.query(
    'select revoked, expires_at, use_count, max_uses from enrollment_tokens where token_hash = $1',
    [tokenHash]
  );
  if (found.rows.length === 0) return { ok: false, reason: 'unknown_token' };
  return { ok: false, reason: statusOf(found.rows[0]) }; // revoked | expired | exhausted
}

module.exports = {
  createToken,
  listTokens,
  revokeToken,
  redeemToken,
  statusOf,
  hashToken,
  isUuid,
  TOKEN_PREFIX,
  DEFAULT_EXPIRY_HOURS,
  MAX_EXPIRY_HOURS,
  MAX_USES_CAP,
  ValidationError,
};
