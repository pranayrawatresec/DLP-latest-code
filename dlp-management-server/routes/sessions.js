// Session visibility and instant revocation — the reason we chose
// server-side sessions over JWTs.
const express = require('express');
const pool = require('../db/pool');
const { audit } = require('../lib/audit');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../lib/rbac');

const router = express.Router();
router.use(requireAuth, requirePermission('sessions.manage'));

// GET /api/sessions — all live sessions
router.get('/', async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `select s.token_hash, s.created_at, s.expires_at, s.ip, s.user_agent, u.email
         from sessions s join admin_users u on u.id = s.user_id
        where s.expires_at > now()
        order by s.created_at desc`
    );
    res.json(
      rows.map((s) => ({
        id: s.token_hash, // this is the hash — the raw token never leaves the client
        email: s.email,
        createdAt: s.created_at,
        expiresAt: s.expires_at,
        ip: s.ip,
        userAgent: s.user_agent,
        current: s.token_hash === req.user.sessionTokenHash,
      }))
    );
  } catch (err) {
    next(err);
  }
});

// DELETE /api/sessions/:id — kill one session now
router.delete('/:id', async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `delete from sessions where token_hash = $1
       returning (select email from admin_users where id = sessions.user_id) as email`,
      [req.params.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'session not found' });
    await audit(req.user.email, 'session.revoke', rows[0].email);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
