// Admin user management. Two gates on every route: requireAuth (authN),
// then requirePermission('users.manage') (authZ) — sysadmin only.
const express = require('express');
const bcrypt = require('bcryptjs');
const pool = require('../db/pool');
const { audit } = require('../lib/audit');
const { requireAuth } = require('../middleware/auth');
const { requirePermission, sodWarning } = require('../lib/rbac');

const router = express.Router();
router.use(requireAuth, requirePermission('users.manage'));

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD_LENGTH = 12;

async function validRoleIds(client, names) {
  const { rows } = await client.query(
    'select id, name from roles where name = any($1)',
    [names]
  );
  if (rows.length !== names.length) return null;
  return rows;
}

// GET /api/users — list users, roles, separation-of-duties warnings
router.get('/', async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `select u.id, u.email, u.display_name, u.disabled, u.mfa_enrolled, u.created_at,
              coalesce(array_agg(r.name order by r.name)
                       filter (where r.name is not null), '{}') as roles
         from admin_users u
         left join user_roles ur on ur.user_id = u.id
         left join roles r on r.id = ur.role_id
        group by u.id
        order by u.created_at`
    );
    res.json(
      rows.map((u) => ({
        id: u.id,
        email: u.email,
        displayName: u.display_name,
        disabled: u.disabled,
        mfaEnrolled: u.mfa_enrolled,
        createdAt: u.created_at,
        roles: u.roles,
        sodWarning: sodWarning(u.roles),
      }))
    );
  } catch (err) {
    next(err);
  }
});

// POST /api/users  { email, password, displayName?, roles: [] }
router.post('/', async (req, res, next) => {
  const client = await pool.connect();
  try {
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');
    const displayName = String(req.body.displayName || '').trim();
    const roles = Array.isArray(req.body.roles) ? req.body.roles : [];

    if (!EMAIL_RE.test(email)) {
      return res.status(400).json({ error: 'valid email required' });
    }
    if (password.length < MIN_PASSWORD_LENGTH) {
      return res
        .status(400)
        .json({ error: `password must be at least ${MIN_PASSWORD_LENGTH} characters` });
    }
    if (roles.length === 0) {
      return res.status(400).json({ error: 'at least one role required' });
    }
    const roleRows = await validRoleIds(client, roles);
    if (!roleRows) return res.status(400).json({ error: 'unknown role' });

    const pwHash = await bcrypt.hash(password, 12);
    await client.query('begin');
    const inserted = await client.query(
      `insert into admin_users (email, display_name, pw_hash)
       values ($1, $2, $3) returning id`,
      [email, displayName, pwHash]
    );
    const userId = inserted.rows[0].id;
    for (const role of roleRows) {
      await client.query(
        'insert into user_roles (user_id, role_id, granted_by) values ($1, $2, $3)',
        [userId, role.id, req.user.email]
      );
    }
    await client.query('commit');
    await audit(req.user.email, 'user.create', email, { roles });
    res.status(201).json({ id: userId, email, roles, sodWarning: sodWarning(roles) });
  } catch (err) {
    await client.query('rollback').catch(() => {});
    if (err.code === '23505') {
      return res.status(409).json({ error: 'email already exists' });
    }
    next(err);
  } finally {
    client.release();
  }
});

// PATCH /api/users/:id  { disabled?, roles? }
router.patch('/:id', async (req, res, next) => {
  const client = await pool.connect();
  try {
    const targetId = req.params.id;
    const { rows } = await client.query(
      'select id, email from admin_users where id = $1',
      [targetId]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'user not found' });
    const target = rows[0];

    if (targetId === req.user.id) {
      // An admin cannot disable themselves or edit their own roles — prevents
      // both accidental lockout and quiet self-privilege changes.
      return res.status(400).json({ error: 'cannot modify your own account' });
    }

    const changes = {};
    await client.query('begin');

    if (typeof req.body.disabled === 'boolean') {
      await client.query('update admin_users set disabled = $2 where id = $1', [
        targetId,
        req.body.disabled,
      ]);
      changes.disabled = req.body.disabled;
      if (req.body.disabled) {
        // Disabling revokes every live session immediately.
        await client.query('delete from sessions where user_id = $1', [targetId]);
        changes.sessionsRevoked = true;
      }
    }

    if (Array.isArray(req.body.roles)) {
      if (req.body.roles.length === 0) {
        await client.query('rollback');
        return res.status(400).json({ error: 'at least one role required' });
      }
      const roleRows = await validRoleIds(client, req.body.roles);
      if (!roleRows) {
        await client.query('rollback');
        return res.status(400).json({ error: 'unknown role' });
      }
      await client.query('delete from user_roles where user_id = $1', [targetId]);
      for (const role of roleRows) {
        await client.query(
          'insert into user_roles (user_id, role_id, granted_by) values ($1, $2, $3)',
          [targetId, role.id, req.user.email]
        );
      }
      changes.roles = req.body.roles;
    }

    await client.query('commit');
    await audit(req.user.email, 'user.update', target.email, changes);
    res.json({ ok: true, changes });
  } catch (err) {
    await client.query('rollback').catch(() => {});
    next(err);
  } finally {
    client.release();
  }
});

module.exports = router;
