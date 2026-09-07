'use strict';
// Endpoint CLIPBOARD policy — managed in the console, applied by the per-session
// clipboard helper the DLPAgent service auto-spawns (no command line). Two gates on
// every route: requireAuth (401) then requirePermission (403, denials audited).
// RBAC:
//   * clipboard_policy:read   - policy_author, sysadmin, auditor
//   * clipboard_policy:write  - policy_author
//
// The update and its audit entry commit in ONE transaction (atomic tamper-
// evidence). Parameterised SQL only. A single global row (id = 1). Metadata only —
// no secrets, and NEVER any clipboard content.
const express = require('express');
const pool = require('../db/pool');
const { writeChainEntry, AUDIT_CHAIN_LOCK } = require('../lib/audit');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../lib/rbac');

const router = express.Router();
router.use(requireAuth);

// off = inert; monitor = classify + incident but ALLOW (audit); enforce = BLOCK
// (clear the clipboard on a sensitive copy). Model A (strict) — destination-agnostic.
const MODES = new Set(['off', 'monitor', 'enforce']);

function policyJson(row) {
  return {
    mode: row.mode,
    // Block images (CF_DIB/BITMAP) wholesale — not content-inspectable without OCR.
    blockImages: row.block_images,
    // Fail-secure: block when a verdict can't be produced (no bundle / classify fail).
    failBlock: row.fail_block,
    updatedBy: row.updated_by,
    updatedAt: row.updated_at,
  };
}

function validatePolicy(body) {
  const mode = typeof body.mode === 'string' ? body.mode.trim() : '';
  if (!MODES.has(mode)) return { ok: false, error: 'mode must be off|monitor|enforce' };
  if (typeof body.blockImages !== 'boolean') return { ok: false, error: 'blockImages must be true or false' };
  if (typeof body.failBlock !== 'boolean') return { ok: false, error: 'failBlock must be true or false' };
  return { ok: true, mode, blockImages: body.blockImages, failBlock: body.failBlock };
}

// GET /api/clipboard-policy — the current policy.
router.get('/', requirePermission('clipboard_policy:read'), async (req, res, next) => {
  try {
    const { rows } = await pool.query('select * from clipboard_policy where id = 1');
    if (rows.length === 0) return res.status(404).json({ error: 'policy not initialised' });
    res.json({ policy: policyJson(rows[0]) });
  } catch (err) {
    next(err);
  }
});

// PUT /api/clipboard-policy — replace the policy (whole object).
router.put('/', requirePermission('clipboard_policy:write'), async (req, res, next) => {
  const v = validatePolicy(req.body || {});
  if (!v.ok) return res.status(400).json({ error: v.error });

  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query('select pg_advisory_xact_lock($1)', [AUDIT_CHAIN_LOCK]);
    const { rows } = await client.query(
      `update clipboard_policy
          set mode=$1, block_images=$2, fail_block=$3, updated_by=$4, updated_at=now()
        where id = 1
      returning *`,
      [v.mode, v.blockImages, v.failBlock, req.user.email]
    );
    await writeChainEntry(client, req.user.email, 'clipboard_policy.update', 'clipboard', {
      mode: v.mode,
      blockImages: v.blockImages,
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
