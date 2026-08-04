'use strict';
// Detection incident review API (console side). Incidents are REPORTED by
// agents on the mTLS surface (agent/agentApp.js POST /agent/incidents);
// this router is where humans read them. Two gates on every route:
// requireAuth (authN 401), then requirePermission (authZ 403, denials
// audited). Reads use 'protect:read' (all four roles). Detail reads are
// audited ('incident.read') and resolve the verdict lazily on first read.
const express = require('express');
const pool = require('../db/pool');
const { audit } = require('../lib/audit');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../lib/rbac');
const { isUuid } = require('../lib/enrollmentTokens');
const { resolveIncident } = require('../lib/incidents');

const router = express.Router();
router.use(requireAuth);

// GET /api/incidents — newest first, metadata only (no verdict payloads).
router.get('/', requirePermission('protect:read'), async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `select i.id, i.agent_id, a.hostname, i.channel, i.file_name,
              i.file_sha256, i.reported_at,
              (i.resolved_json is not null) as resolved
         from detection_incidents i
         join agents a on a.id = i.agent_id
        order by i.reported_at desc
        limit 500`
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// GET /api/incidents/:id — full detail. The verdict is resolved lazily on
// the first read (matched seq ranges, titles, containment) and stored;
// every read is audited.
router.get('/:id', requirePermission('protect:read'), async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'incident not found' });
    const { rows } = await pool.query(
      `select i.id, i.agent_id, a.hostname, i.channel, i.file_name,
              i.file_sha256, i.reported_at, i.verdict_json, i.resolved_json
         from detection_incidents i
         join agents a on a.id = i.agent_id
        where i.id = $1`,
      [req.params.id]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'incident not found' });
    const row = rows[0];

    let resolved = row.resolved_json;
    if (!resolved) {
      resolved = await resolveIncident(row.id);
    }
    await audit(req.user.email, 'incident.read', row.id, {
      channel: row.channel,
      agentId: row.agent_id,
    });

    res.json({
      id: row.id,
      agent_id: row.agent_id,
      hostname: row.hostname,
      channel: row.channel,
      file_name: row.file_name,
      file_sha256: row.file_sha256,
      reported_at: row.reported_at,
      verdict: row.verdict_json,
      resolved,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
