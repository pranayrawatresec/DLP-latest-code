'use strict';
// Agent fleet visibility + lifecycle (console side). Read is available to
// sysadmin and auditor; retiring (revocation) is sysadmin-only. Two gates on
// every route: requireAuth then requirePermission.
const express = require('express');
const pool = require('../db/pool');
const { audit } = require('../lib/audit');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../lib/rbac');
const { isUuid } = require('../lib/enrollmentTokens');

const router = express.Router();
router.use(requireAuth);

// GET /api/agents — fleet list
router.get('/', requirePermission('agents.read'), async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `select id, hostname, os, agent_version, status,
              cert_serial, cert_not_after, enrolled_at, last_seen
         from agents
        order by (last_seen is null), last_seen desc, enrolled_at desc`
    );
    res.json(rows);
  } catch (err) {
    next(err);
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
