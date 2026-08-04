'use strict';
// Audit log read + integrity verification (console side). Gated by
// 'audit.read' — which, by separation of duties, ONLY the auditor role holds
// (not even sysadmin). Reading the log is intentionally not itself audited, to
// avoid a recursive self-logging loop on every page view.
const express = require('express');
const pool = require('../db/pool');
const { verifyChain } = require('../lib/audit');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../lib/rbac');

const router = express.Router();
router.use(requireAuth, requirePermission('audit.read'));

// GET /api/audit/verify — recompute the whole hash chain and report integrity.
router.get('/verify', async (req, res, next) => {
  try {
    const broken = await verifyChain();
    const c = await pool.query('select count(*)::int n from audit_log');
    res.json({ intact: broken === null, brokenAt: broken, count: c.rows[0].n });
  } catch (err) {
    next(err);
  }
});

// GET /api/audit?limit=&offset=&actor=&action= — newest first, filterable.
router.get('/', async (req, res, next) => {
  try {
    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 500);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);

    const filters = [];
    const params = [];
    if (req.query.actor) {
      params.push(`%${req.query.actor}%`);
      filters.push(`actor ilike $${params.length}`);
    }
    if (req.query.action) {
      params.push(String(req.query.action));
      filters.push(`action = $${params.length}`);
    }
    const whereSql = filters.length ? `where ${filters.join(' and ')}` : '';

    const listParams = [...params, limit, offset];
    const list = await pool.query(
      `select seq, ts, actor, action, target, detail, hash
         from audit_log ${whereSql}
        order by seq desc
        limit $${params.length + 1} offset $${params.length + 2}`,
      listParams
    );
    const totalRes = await pool.query(`select count(*)::int n from audit_log ${whereSql}`, params);
    const actionsRes = await pool.query('select distinct action from audit_log order by action');

    res.json({
      entries: list.rows,
      total: totalRes.rows[0].n,
      limit,
      offset,
      availableActions: actionsRes.rows.map((r) => r.action),
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
