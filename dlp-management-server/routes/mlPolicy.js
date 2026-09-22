'use strict';
// ML document-classification policy — the admin console surface over the agent's
// ONNX classifier (model V6.2.01, 29 frozen business-function classes). The admin
// marks which classes count as sensitive here; a model hit on a marked class at or
// above its threshold makes a document sensitive. This is a SECOND, INDEPENDENT
// signal ORed with IDM/EDM fingerprinting — it can only ADD sensitivity, never
// downgrade a fingerprint hit.
//
// It also carries `denyUnclassified` (migration 022) — the one genuinely dangerous
// switch here. The endpoint's kernel read path only LOOKS UP cached classifications
// (no budget to infer); this decides whether a MISS falls back to fingerprints
// (false, the default and today's behaviour) or denies the read outright (true,
// safe only after the discovery sweep has covered the estate).
//
// Two gates on every route: requireAuth (401) then requirePermission (403, denials
// audited). RBAC:
//   * ml_policy:read   - policy_author, sysadmin, auditor
//   * ml_policy:write  - policy_author
//
// The policy row, its label set and the audit entry commit in ONE transaction
// (atomic tamper-evidence). Parameterised SQL only. Singleton (id = 1).
// Metadata only — label ids, thresholds and counts; never document text.
const express = require('express');
const pool = require('../db/pool');
const { writeChainEntry, AUDIT_CHAIN_LOCK } = require('../lib/audit');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../lib/rbac');

const router = express.Router();
router.use(requireAuth);

const ACTIONS = new Set(['audit', 'block']);
const MAX_LABELS = 29; // the model's whole label space — you cannot select more than exists

// NUMERIC comes back from pg as a string (arbitrary precision). The wire shape is a
// JSON number, so convert on the way out and keep NULL as null (inherit the floor).
function confidenceJson(v) {
  return v === null || v === undefined ? null : Number(v);
}

function policyJson(row, labelRows) {
  return {
    enabled: row.enabled,
    minConfidence: Number(row.min_confidence),
    action: row.action,
    failBlock: row.fail_block,
    // The posture switch (migration 022). On the endpoint's kernel READ path a
    // cache miss means "the classifier has not seen this file yet"; this says
    // whether that denies the read or falls back to fingerprints alone.
    denyUnclassified: row.deny_unclassified ?? false,
    modelVersion: row.model_version,
    labels: labelRows.map((r) => ({
      id: r.label_id,
      minConfidence: confidenceJson(r.min_confidence),
    })),
    updatedBy: row.updated_by,
    updatedAt: row.updated_at,
  };
}

// A confidence is a probability in (0,1]. 0 is rejected deliberately: a zero floor
// would mark every document of that class sensitive regardless of what the model
// actually believes.
function validConfidence(v) {
  return typeof v === 'number' && Number.isFinite(v) && v > 0 && v <= 1;
}

function validatePolicy(body) {
  if (typeof body.enabled !== 'boolean') return { ok: false, error: 'enabled must be true or false' };
  if (typeof body.failBlock !== 'boolean') return { ok: false, error: 'failBlock must be true or false' };

  const action = typeof body.action === 'string' ? body.action.trim() : '';
  if (!ACTIONS.has(action)) return { ok: false, error: 'action must be audit|block' };

  if (!validConfidence(body.minConfidence)) {
    return { ok: false, error: 'minConfidence must be a number greater than 0 and at most 1' };
  }

  // denyUnclassified is OPTIONAL on the wire. A console built before this field
  // existed must keep saving policies rather than getting a 400 — and the value it
  // omits defaults to the SAFE reading (false = no new denials), never to the
  // dangerous one. Present-but-not-a-boolean is still a 400: that is a client bug,
  // and silently coercing "false" or 0 into a posture decision is exactly the kind
  // of guess this switch must never make.
  let denyUnclassified = false;
  if (body.denyUnclassified !== undefined && body.denyUnclassified !== null) {
    if (typeof body.denyUnclassified !== 'boolean') {
      return { ok: false, error: 'denyUnclassified must be true or false' };
    }
    denyUnclassified = body.denyUnclassified;
  }

  // The label set may be EMPTY — an enabled policy with no classes selected is inert,
  // which is a legitimate (and safe) state to save while an admin is deciding. The
  // audit entry carries labelCount so the transition is still visible.
  const raw = body.labels;
  if (!Array.isArray(raw) || raw.length > MAX_LABELS) {
    return { ok: false, error: `labels must be an array of at most ${MAX_LABELS} entries` };
  }
  const labels = [];
  const seen = new Set();
  for (const entry of raw) {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      return { ok: false, error: 'each label must be an object { id, minConfidence }' };
    }
    const id = typeof entry.id === 'string' ? entry.id.trim() : '';
    if (!id) return { ok: false, error: 'each label needs an id' };
    if (seen.has(id)) return { ok: false, error: `duplicate label ${JSON.stringify(id)}` };
    seen.add(id);

    let minConfidence = null;
    if (entry.minConfidence !== undefined && entry.minConfidence !== null) {
      if (!validConfidence(entry.minConfidence)) {
        return {
          ok: false,
          error: `minConfidence for ${JSON.stringify(id)} must be null or a number greater than 0 and at most 1`,
        };
      }
      minConfidence = entry.minConfidence;
    }
    labels.push({ id, minConfidence });
  }
  return {
    ok: true,
    enabled: body.enabled,
    minConfidence: body.minConfidence,
    action,
    failBlock: body.failBlock,
    denyUnclassified,
    labels,
  };
}

// Read the selected classes in the model's own index order — the console renders
// them in that order and the audit entry records them in it, so two identical
// selections always produce the same detail bytes.
async function selectedLabels(sql) {
  const { rows } = await sql.query(
    `select s.label_id, s.min_confidence
       from ml_sensitive_labels s
       join ml_labels l on l.id = s.label_id
      order by l.idx`
  );
  return rows;
}

// GET /api/ml-policy — the current policy plus its selected label set.
router.get('/', requirePermission('ml_policy:read'), async (req, res, next) => {
  try {
    const { rows } = await pool.query('select * from ml_policy where id = 1');
    if (rows.length === 0) return res.status(404).json({ error: 'policy not initialised' });
    const labels = await selectedLabels(pool);
    res.json({ policy: policyJson(rows[0], labels) });
  } catch (err) {
    next(err);
  }
});

// GET /api/ml-policy/labels — the model's frozen label space (all 29). Served from
// the DB mirror so an air-gapped console with no model file can still list them.
router.get('/labels', requirePermission('ml_policy:read'), async (req, res, next) => {
  try {
    const { rows } = await pool.query('select id, idx, name, domain from ml_labels order by idx');
    res.json({
      labels: rows.map((r) => ({ id: r.id, index: r.idx, name: r.name, domain: r.domain })),
    });
  } catch (err) {
    next(err);
  }
});

// PUT /api/ml-policy — replace the WHOLE policy, label set included. Delete+insert
// rather than a diff: the console always sends the complete selection, and one
// replace keeps the saved state exactly what the admin saw.
router.put('/', requirePermission('ml_policy:write'), async (req, res, next) => {
  const v = validatePolicy(req.body || {});
  if (!v.ok) return res.status(400).json({ error: v.error });

  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query('select pg_advisory_xact_lock($1)', [AUDIT_CHAIN_LOCK]);

    // Reject unknown ids before touching anything — a typo'd class must not
    // silently drop out of the selection and quietly narrow protection.
    if (v.labels.length) {
      const { rows: known } = await client.query('select id from ml_labels where id = any($1)', [
        v.labels.map((l) => l.id),
      ]);
      if (known.length !== v.labels.length) {
        const ids = new Set(known.map((r) => r.id));
        const unknown = v.labels.map((l) => l.id).filter((id) => !ids.has(id));
        await client.query('rollback');
        return res.status(400).json({ error: `unknown label ${JSON.stringify(unknown[0])}` });
      }
    }

    const { rows } = await client.query(
      `update ml_policy
          set enabled=$1, min_confidence=$2, action=$3, fail_block=$4,
              deny_unclassified=$5, updated_by=$6, updated_at=now()
        where id = 1
      returning *`,
      [v.enabled, v.minConfidence, v.action, v.failBlock, v.denyUnclassified, req.user.email]
    );
    if (rows.length === 0) {
      await client.query('rollback');
      return res.status(404).json({ error: 'policy not initialised' });
    }

    await client.query('delete from ml_sensitive_labels');
    for (const l of v.labels) {
      await client.query(
        `insert into ml_sensitive_labels (label_id, min_confidence, added_by, added_at)
         values ($1, $2, $3, now())`,
        [l.id, l.minConfidence, req.user.email]
      );
    }

    const labels = await selectedLabels(client);
    await writeChainEntry(client, req.user.email, 'ml_policy.update', 'ml', {
      enabled: v.enabled,
      minConfidence: v.minConfidence,
      action: v.action,
      failBlock: v.failBlock,
      // The posture switch is the most consequential thing on this page: turning it
      // on denies the first exfil-channel read of every file the endpoint has not
      // classified yet. It is audited on EVERY save, not only on the transition, so
      // the log answers "what was the posture at time T" without replaying deltas.
      denyUnclassified: v.denyUnclassified,
      // Enabling ML with nothing selected is allowed (it is inert) — labelCount
      // makes that transition, and every later widening of it, visible in the log.
      labelCount: labels.length,
      labels: labels.map((r) => r.label_id),
    });

    await client.query('commit');
    res.json({ policy: policyJson(rows[0], labels) });
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
