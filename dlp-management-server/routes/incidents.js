'use strict';
// Detection incident review API (console side). Incidents are REPORTED by
// agents on the mTLS surface (agent/agentApp.js POST /agent/incidents); this
// router is where humans read + triage them. Two gates on every route:
// requireAuth (authN 401), then requirePermission (authZ 403, denials audited).
//
// RBAC (separation of duties — guide §2.3):
//   * LIST is metadata only            -> 'incidents.read_metadata' (auditor + reviewer)
//   * DETAIL resolves match ranges     -> 'incidents.read'          (reviewer only)
//   * STATUS triage                    -> 'incidents.read'          (reviewer only)
// sysadmin and policy_author hold NEITHER, so they cannot read incidents — the
// deliberate separation the guide requires (this router previously gated on
// 'protect:read', which sysadmin also holds; that hole is now closed).
const express = require('express');
const pool = require('../db/pool');
const { audit } = require('../lib/audit');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../lib/rbac');
const { isUuid } = require('../lib/enrollmentTokens');
const { resolveIncident } = require('../lib/incidents');

const router = express.Router();
router.use(requireAuth);

// The reviewer triage states (mirrors the DB check constraint in migration 005).
const STATUSES = new Set(['new', 'reviewing', 'resolved', 'false_positive']);

// Human-facing reference a user can quote from their endpoint toast / helpdesk.
function reference(seq) {
  return seq == null ? null : `INC-${String(seq).padStart(6, '0')}`;
}

// GET /api/incidents — newest first, METADATA ONLY (no verdict payloads).
// Filters (all optional): channel, status, agentId, q (file-name search).
// Pagination: limit (default 100, max 500), offset (default 0).
router.get('/', requirePermission('incidents.read_metadata'), async (req, res, next) => {
  try {
    const where = [];
    const params = [];
    const push = (sql, val) => {
      params.push(val);
      where.push(sql.replace('$?', `$${params.length}`));
    };

    const channel = typeof req.query.channel === 'string' ? req.query.channel.slice(0, 64) : '';
    if (channel) push('i.channel = $?', channel);

    const status = typeof req.query.status === 'string' ? req.query.status : '';
    if (status && STATUSES.has(status)) push('i.status = $?', status);

    const agentId = typeof req.query.agentId === 'string' ? req.query.agentId : '';
    if (agentId && isUuid(agentId)) push('i.agent_id = $?', agentId);

    const q = typeof req.query.q === 'string' ? req.query.q.trim().slice(0, 128) : '';
    if (q) push('i.file_name ilike $?', `%${q}%`);

    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 100, 1), 500);
    const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);

    const whereSql = where.length ? `where ${where.join(' and ')}` : '';
    const { rows } = await pool.query(
      `select i.id, i.seq, i.agent_id, a.hostname, i.channel, i.file_name,
              i.file_sha256, i.action_taken, i.os_user, i.detection_type,
              i.status, i.reported_at,
              (i.resolved_json is not null) as resolved
         from detection_incidents i
         join agents a on a.id = i.agent_id
        ${whereSql}
        order by i.reported_at desc, i.seq desc
        limit ${limit} offset ${offset}`,
      params
    );
    res.json(rows.map((r) => ({ ...r, reference: reference(r.seq) })));
  } catch (err) {
    next(err);
  }
});

// GET /api/incidents/:id — full detail. The verdict is resolved lazily on the
// first read (matched seq ranges, titles, containment) and stored; every read is
// audited. Detail is reviewer-only (it exposes WHERE in the document matched).
router.get('/:id', requirePermission('incidents.read'), async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'incident not found' });
    const { rows } = await pool.query(
      `select i.id, i.seq, i.agent_id, a.hostname, i.channel, i.file_name,
              i.file_sha256, i.action_taken, i.os_user, i.detection_type,
              i.status, i.status_note, i.status_by, i.status_at,
              i.reported_at, i.verdict_json, i.resolved_json
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
      reference: reference(row.seq),
      agent_id: row.agent_id,
      hostname: row.hostname,
      channel: row.channel,
      file_name: row.file_name,
      file_sha256: row.file_sha256,
      action_taken: row.action_taken,
      os_user: row.os_user,
      detection_type: row.detection_type,
      status: row.status,
      status_note: row.status_note,
      status_by: row.status_by,
      status_at: row.status_at,
      reported_at: row.reported_at,
      verdict: row.verdict_json,
      resolved,
    });
  } catch (err) {
    next(err);
  }
});

// PATCH /api/incidents/:id/status — reviewer triage. Body: { status, note? }.
// State change is audited (actor + from/to). Reviewer-only.
router.patch('/:id/status', requirePermission('incidents.read'), async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'incident not found' });
    const body = req.body || {};
    const status = typeof body.status === 'string' ? body.status : '';
    if (!STATUSES.has(status)) {
      return res
        .status(400)
        .json({ error: 'status must be one of new|reviewing|resolved|false_positive' });
    }
    const note = typeof body.note === 'string' ? body.note.slice(0, 1000) : null;

    const prev = await pool.query('select status from detection_incidents where id = $1', [
      req.params.id,
    ]);
    if (prev.rows.length === 0) return res.status(404).json({ error: 'incident not found' });

    const { rows } = await pool.query(
      `update detection_incidents
          set status = $1, status_note = $2, status_by = $3, status_at = now()
        where id = $4
        returning id, seq, status, status_note, status_by, status_at`,
      [status, note, req.user.email, req.params.id]
    );
    await audit(req.user.email, 'incident.status_changed', req.params.id, {
      from: prev.rows[0].status,
      to: status,
    });
    res.json({ ...rows[0], reference: reference(rows[0].seq) });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
