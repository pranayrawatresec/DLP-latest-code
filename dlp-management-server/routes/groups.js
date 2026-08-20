'use strict';
// Endpoint GROUPS — per-machine/per-group policy targeting. A group is a named set
// of endpoints that can carry its own read-deny policy (see routes/readDenyPolicy.js
// /group/:groupId). One seeded "Default" group holds every unassigned machine and
// uses the global read_deny_policy (id=1). Two gates on every route: requireAuth
// (401) then requirePermission (403, denials audited). RBAC:
//   * groups:read   - policy_author, sysadmin, auditor
//   * groups:write  - policy_author  (create/rename/delete)
// Machine → group assignment lives on the agents resource (agents.manage), a
// deliberate separation of duties. Mutations + their audit entry are one atomic
// transaction. Parameterised SQL only.
const express = require('express');
const pool = require('../db/pool');
const { writeChainEntry, AUDIT_CHAIN_LOCK } = require('../lib/audit');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../lib/rbac');

const router = express.Router();
router.use(requireAuth);

// A group name: short, printable, trimmed, unique (DB-enforced).
function validateName(raw) {
  const name = typeof raw === 'string' ? raw.trim() : '';
  if (!name) return { ok: false, error: 'name is required' };
  if (name.length > 64) return { ok: false, error: 'name must be at most 64 characters' };
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f]/.test(name)) return { ok: false, error: 'name contains control characters' };
  return { ok: true, name };
}
function cleanDescription(raw) {
  if (raw === undefined || raw === null) return null;
  const s = String(raw).trim();
  return s ? s.slice(0, 256) : null;
}

function groupJson(row) {
  return {
    id: row.id,
    name: row.name,
    description: row.description,
    isDefault: row.is_default,
    agentCount: row.agent_count,
    hasPolicyOverride: row.has_policy_override,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

// GET /api/groups — every group with its machine count and whether it has a custom
// policy. The Default group's count includes machines with no explicit group.
router.get('/', requirePermission('groups:read'), async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `select g.id, g.name, g.description, g.is_default, g.created_at, g.updated_at,
              (select count(*) from agents a
                 where a.group_id = g.id or (g.is_default and a.group_id is null))::int
                 as agent_count,
              (o.group_id is not null) as has_policy_override
         from groups g
         left join group_read_deny_policy o on o.group_id = g.id
        order by g.is_default desc, lower(g.name) asc`
    );
    res.json({ groups: rows.map(groupJson) });
  } catch (err) {
    next(err);
  }
});

// POST /api/groups — create a group.
router.post('/', requirePermission('groups:write'), async (req, res, next) => {
  const v = validateName((req.body || {}).name);
  if (!v.ok) return res.status(400).json({ error: v.error });
  const description = cleanDescription((req.body || {}).description);

  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query('select pg_advisory_xact_lock($1)', [AUDIT_CHAIN_LOCK]);
    let rows;
    try {
      ({ rows } = await client.query(
        `insert into groups (name, description, is_default, created_by)
         values ($1, $2, false, $3)
         returning id, name, description, is_default, created_at, updated_at`,
        [v.name, description, req.user.email]
      ));
    } catch (err) {
      if (err && err.code === '23505') {
        await client.query('rollback');
        return res.status(409).json({ error: 'a group with that name already exists' });
      }
      throw err;
    }
    await writeChainEntry(client, req.user.email, 'group.create', String(rows[0].id), {
      name: rows[0].name,
    });
    await client.query('commit');
    res.status(201).json({ group: groupJson({ ...rows[0], agent_count: 0, has_policy_override: false }) });
  } catch (err) {
    try {
      await client.query('rollback');
    } catch (_) {
      /* already unwound */
    }
    next(err);
  } finally {
    client.release();
  }
});

// PUT /api/groups/:id — rename / re-describe. The Default group can be re-described
// but not renamed away from being the catch-all; is_default is immutable here.
router.put('/:id', requirePermission('groups:write'), async (req, res, next) => {
  const id = /^\d+$/.test(req.params.id) ? Number(req.params.id) : NaN;
  if (!Number.isInteger(id) || id <= 0) return res.status(404).json({ error: 'group not found' });
  const v = validateName((req.body || {}).name);
  if (!v.ok) return res.status(400).json({ error: v.error });
  const description = cleanDescription((req.body || {}).description);

  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query('select pg_advisory_xact_lock($1)', [AUDIT_CHAIN_LOCK]);
    let rows;
    try {
      ({ rows } = await client.query(
        `update groups set name = $2, description = $3, updated_at = now()
          where id = $1
        returning id, name, description, is_default, created_at, updated_at`,
        [id, v.name, description]
      ));
    } catch (err) {
      if (err && err.code === '23505') {
        await client.query('rollback');
        return res.status(409).json({ error: 'a group with that name already exists' });
      }
      throw err;
    }
    if (rows.length === 0) {
      await client.query('rollback');
      return res.status(404).json({ error: 'group not found' });
    }
    await writeChainEntry(client, req.user.email, 'group.update', String(id), { name: v.name });
    await client.query('commit');
    res.json({ group: groupJson({ ...rows[0], agent_count: null, has_policy_override: null }) });
  } catch (err) {
    try {
      await client.query('rollback');
    } catch (_) {
      /* already unwound */
    }
    next(err);
  } finally {
    client.release();
  }
});

// DELETE /api/groups/:id — remove a group. The Default group can never be deleted.
// Machines in the group return to Default (agents.group_id ON DELETE SET NULL) and
// any per-group policy override is removed (ON DELETE CASCADE).
router.delete('/:id', requirePermission('groups:write'), async (req, res, next) => {
  const id = /^\d+$/.test(req.params.id) ? Number(req.params.id) : NaN;
  if (!Number.isInteger(id) || id <= 0) return res.status(404).json({ error: 'group not found' });

  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query('select pg_advisory_xact_lock($1)', [AUDIT_CHAIN_LOCK]);
    const g = await client.query('select name, is_default from groups where id = $1', [id]);
    if (g.rows.length === 0) {
      await client.query('rollback');
      return res.status(404).json({ error: 'group not found' });
    }
    if (g.rows[0].is_default) {
      await client.query('rollback');
      return res.status(400).json({ error: 'the Default group cannot be deleted' });
    }
    await client.query('delete from groups where id = $1', [id]);
    await writeChainEntry(client, req.user.email, 'group.delete', String(id), {
      name: g.rows[0].name,
    });
    await client.query('commit');
    res.status(204).end();
  } catch (err) {
    try {
      await client.query('rollback');
    } catch (_) {
      /* already unwound */
    }
    next(err);
  } finally {
    client.release();
  }
});

module.exports = router;
