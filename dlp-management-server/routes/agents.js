'use strict';
// Agent fleet visibility + lifecycle (console side). Read is available to
// sysadmin and auditor; retiring (revocation) is sysadmin-only. Two gates on
// every route: requireAuth then requirePermission.
const express = require('express');
const pool = require('../db/pool');
const { audit, writeChainEntry, AUDIT_CHAIN_LOCK } = require('../lib/audit');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../lib/rbac');
const { isUuid } = require('../lib/enrollmentTokens');

const router = express.Router();
router.use(requireAuth);

// GET /api/agents — fleet list (with each machine's group; NULL group_id = Default)
router.get('/', requirePermission('agents.read'), async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `select a.id, a.hostname, a.os, a.agent_version, a.status,
              a.cert_serial, a.cert_not_after, a.enrolled_at, a.last_seen,
              a.group_id, g.name as group_name
         from agents a
         left join groups g on g.id = a.group_id
        order by (a.last_seen is null), a.last_seen desc, a.enrolled_at desc`
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// PUT /api/agents/:id/group — assign an endpoint to a group (fleet management, so
// gated on agents.manage — a separation of duties from policy authoring). A null
// groupId returns the machine to the Default group. Mutation + audit are atomic.
router.put('/:id/group', requirePermission('agents.manage'), async (req, res, next) => {
  if (!isUuid(req.params.id)) return res.status(404).json({ error: 'agent not found' });
  const raw = req.body ? req.body.groupId : undefined;
  let groupId = null; // null/''/undefined => Default (unassign)
  if (raw !== null && raw !== undefined && raw !== '') {
    groupId = Number(raw);
    if (!Number.isInteger(groupId) || groupId <= 0) {
      return res.status(400).json({ error: 'groupId must be a positive integer or null' });
    }
  }
  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query('select pg_advisory_xact_lock($1)', [AUDIT_CHAIN_LOCK]);
    if (groupId !== null) {
      const g = await client.query('select 1 from groups where id = $1', [groupId]);
      if (g.rows.length === 0) {
        await client.query('rollback');
        return res.status(400).json({ error: 'unknown group' });
      }
    }
    const { rows } = await client.query(
      `update agents set group_id = $2 where id = $1 returning hostname`,
      [req.params.id, groupId]
    );
    if (rows.length === 0) {
      await client.query('rollback');
      return res.status(404).json({ error: 'agent not found' });
    }
    await writeChainEntry(client, req.user.email, 'agent.group_assign', req.params.id, {
      groupId,
      hostname: rows[0].hostname,
    });
    await client.query('commit');
    res.json({ ok: true, groupId });
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

// POST /api/agents/:id/retire — de-enroll (revocation). The agent is refused
// at its next check-in (fail-secure) without touching the PC.
router.post('/:id/retire', requirePermission('agents.manage'), async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'agent not found' });
    const { rows } = await pool.query(
      `update agents set status = 'retired'
        where id = $1 and status <> 'retired'
        returning hostname`,
      [req.params.id]
    );
    if (rows.length === 0) {
      const exists = await pool.query('select 1 from agents where id = $1', [req.params.id]);
      if (exists.rows.length === 0) return res.status(404).json({ error: 'agent not found' });
      return res.json({ ok: true, alreadyRetired: true });
    }
    await audit(req.user.email, 'agent.retire', req.params.id, { hostname: rows[0].hostname });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
