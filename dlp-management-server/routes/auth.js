const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const pool = require('../db/pool');
const { audit } = require('../lib/audit');
const { requireAuth, hashToken, SESSION_COOKIE } = require('../middleware/auth');

const router = express.Router();

const SESSION_TTL_MS = 12 * 60 * 60 * 1000; // 12h absolute lifetime
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_MINUTES = 15;

// Compared against when the email is unknown, so response timing does not
// reveal whether an account exists.
const DUMMY_HASH = bcrypt.hashSync(crypto.randomBytes(16).toString('hex'), 12);

// POST /api/auth/login  { email, password }
router.post('/login', async (req, res, next) => {
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password required' });
    }

    const { rows } = await pool.query(
      `select id, email, pw_hash, disabled, failed_attempts, locked_until
         from admin_users where email = $1`,
      [email]
    );
    const user = rows[0];

    // One generic failure message for every rejection reason — do not leak
    // whether the account exists, is disabled, or is locked.
    const reject = async (reason) => {
      await audit(email, 'auth.login_failed', null, { reason, ip: req.ip });
      return res.status(401).json({ error: 'invalid credentials' });
    };

    if (!user) {
      await bcrypt.compare(password, DUMMY_HASH); // equalize timing
      return reject('unknown_email');
    }
    if (user.disabled) return reject('account_disabled');
    if (user.locked_until && new Date(user.locked_until) > new Date()) {
      return reject('account_locked');
    }

    const ok = await bcrypt.compare(password, user.pw_hash);
    if (!ok) {
      const attempts = user.failed_attempts + 1;
      if (attempts >= MAX_FAILED_ATTEMPTS) {
        await pool.query(
          `update admin_users set failed_attempts = 0,
                  locked_until = now() + make_interval(mins => $2)
            where id = $1`,
          [user.id, LOCKOUT_MINUTES]
        );
        await audit(email, 'auth.lockout', null, {
          after_attempts: attempts,
          minutes: LOCKOUT_MINUTES,
          ip: req.ip,
        });
      } else {
        await pool.query(
          'update admin_users set failed_attempts = $2 where id = $1',
          [user.id, attempts]
        );
      }
      return reject('wrong_password');
    }

    // Success: reset counters, mint session.
    await pool.query(
      'update admin_users set failed_attempts = 0, locked_until = null where id = $1',
      [user.id]
    );
    const token = crypto.randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
    await pool.query(
      `insert into sessions (token_hash, user_id, expires_at, ip, user_agent)
       values ($1, $2, $3, $4, $5)`,
      [hashToken(token), user.id, expiresAt, req.ip, req.get('user-agent') || null]
    );
    await audit(email, 'auth.login', null, { ip: req.ip });

    res.cookie(SESSION_COOKIE, token, {
      httpOnly: true,
      sameSite: 'strict',
      secure: process.env.NODE_ENV === 'production',
      maxAge: SESSION_TTL_MS,
      path: '/',
    });

    const rolesRes = await pool.query(
      `select r.name from user_roles ur join roles r on r.id = ur.role_id
        where ur.user_id = $1 order by r.name`,
      [user.id]
    );
    res.json({
      email: user.email,
      roles: rolesRes.rows.map((r) => r.name),
      expiresAt: expiresAt.toISOString(),
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/logout
router.post('/logout', requireAuth, async (req, res, next) => {
  try {
    await pool.query('delete from sessions where token_hash = $1', [
      req.user.sessionTokenHash,
    ]);
    await audit(req.user.email, 'auth.logout');
    res.clearCookie(SESSION_COOKIE);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

// GET /api/auth/me
router.get('/me', requireAuth, (req, res) => {
  res.json({
    id: req.user.id,
    email: req.user.email,
    displayName: req.user.displayName,
    roles: req.user.roles,
    permissions: req.user.permissions,
  });
});

module.exports = router;
