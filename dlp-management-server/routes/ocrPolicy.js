'use strict';
// Endpoint OCR / image-inspection policy — one global switch the agent honors on
// every channel (clipboard, USB, read-deny/RDP, browser upload). Two gates on every
// route: requireAuth (401) then requirePermission (403, denials audited). RBAC:
//   * ocr_policy:read   - policy_author, sysadmin, auditor
//   * ocr_policy:write  - policy_author
//
// Update + audit commit in ONE transaction. Parameterised SQL only. Singleton
// (id = 1). Metadata only — no secrets, never image content.
const express = require('express');
const pool = require('../db/pool');
const { writeChainEntry, AUDIT_CHAIN_LOCK } = require('../lib/audit');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../lib/rbac');

const router = express.Router();
router.use(requireAuth);

const MAX_PIXELS_CAP = 100000000; // 100 MP hard ceiling (sanity)

function policyJson(row) {
  return {
    enabled: row.enabled,
    maxPixels: Number(row.max_pixels),
    failBlock: row.fail_block,
    updatedBy: row.updated_by,
    updatedAt: row.updated_at,
  };
}

function validatePolicy(body) {
  if (typeof body.enabled !== 'boolean') return { ok: false, error: 'enabled must be true or false' };
  if (typeof body.failBlock !== 'boolean') return { ok: false, error: 'failBlock must be true or false' };
  let maxPixels = 8000000;
  if (body.maxPixels !== undefined) {
    maxPixels = Number(body.maxPixels);
    if (!Number.isInteger(maxPixels) || maxPixels < 100000 || maxPixels > MAX_PIXELS_CAP) {
      return { ok: false, error: `maxPixels must be an integer between 100000 and ${MAX_PIXELS_CAP}` };
    }
  }
  return { ok: true, enabled: body.enabled, maxPixels, failBlock: body.failBlock };
}

// GET /api/ocr-policy — the current policy.
router.get('/', requirePermission('ocr_policy:read'), async (req, res, next) => {
  try {
    const { rows } = await pool.query('select * from ocr_policy where id = 1');
    if (rows.length === 0) return res.status(404).json({ error: 'policy not initialised' });
    res.json({ policy: policyJson(rows[0]) });
  } catch (err) {
    next(err);
  }
});

// PUT /api/ocr-policy — replace the policy (whole object).
router.put('/', requirePermission('ocr_policy:write'), async (req, res, next) => {
  const v = validatePolicy(req.body || {});
  if (!v.ok) return res.status(400).json({ error: v.error });

  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query('select pg_advisory_xact_lock($1)', [AUDIT_CHAIN_LOCK]);
    const { rows } = await client.query(
      `update ocr_policy
          set enabled=$1, max_pixels=$2, fail_block=$3, updated_by=$4, updated_at=now()
        where id = 1
      returning *`,
      [v.enabled, v.maxPixels, v.failBlock, req.user.email]
    );
    await writeChainEntry(client, req.user.email, 'ocr_policy.update', 'ocr', {
      enabled: v.enabled,
      maxPixels: v.maxPixels,
      failBlock: v.failBlock,
    });
    await client.query('commit');
    res.json({ policy: policyJson(rows[0]) });
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
