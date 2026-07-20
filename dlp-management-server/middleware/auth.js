// Authentication gate (gate 1 of 2 — authorization is lib/rbac.js).
// The cookie carries the raw session token; the DB stores only its SHA-256.
const crypto = require('crypto');
const pool = require('../db/pool');
const { permissionsFor } = require('../lib/rbac');

const SESSION_COOKIE = 'dlp_session';

function hashToken(raw) {
  return crypto.createHash('sha256').update(raw).digest('hex');
}

// Attaches req.user if a valid, unexpired session cookie is present.
// Never rejects — route guards decide what anonymous users may do.
async function attachUser(req, res, next) {
  try {
    const raw = req.cookies[SESSION_COOKIE];
    if (!raw) return next();
    const tokenHash = hashToken(raw);
    const { rows } = await pool.query(
      `select s.token_hash, s.expires_at,
              u.id, u.email, u.display_name, u.disabled
         from sessions s
         join admin_users u on u.id = s.user_id
        where s.token_hash = $1`,
      [tokenHash]
    );
    if (rows.length === 0) return next();
    const row = rows[0];
    if (row.disabled || new Date(row.expires_at) <= new Date()) {
      await pool.query('delete from sessions where token_hash = $1', [tokenHash]);
      res.clearCookie(SESSION_COOKIE);
      return next();
    }
    const rolesRes = await pool.query(
      `select r.name from user_roles ur join roles r on r.id = ur.role_id
        where ur.user_id = $1 order by r.name`,
      [row.id]
    );
    const roles = rolesRes.rows.map((r) => r.name);
    req.user = {
      id: row.id,
      email: row.email,
      displayName: row.display_name,
      roles,
      permissions: permissionsFor(roles),
      sessionTokenHash: tokenHash,
    };
    next();
  } catch (err) {
    next(err);
  }
}

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'authentication required' });
  next();
}

module.exports = { attachUser, requireAuth, hashToken, SESSION_COOKIE };
