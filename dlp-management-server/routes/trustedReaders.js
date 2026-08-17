'use strict';
// Sanctioned-reader allowlist admin API (read-deny "allowlist posture").
//
// The applications allowed to read sensitive content locally on endpoints. Every
// process NOT matching one of these is treated as an untrusted reader and denied
// the read of sensitive files by the kernel minifilter. This is policy, so it is
// authored by a policy_author and readable by the roles that review policy.
//
// Two gates on every route: requireAuth (authN 401) then requirePermission
// (authZ 403, denials audited). RBAC:
//   * trusted_readers:read   â€” policy_author, sysadmin, auditor
//   * trusted_readers:write  â€” policy_author
//
// Metadata only â€” no secrets, no content. Parameterised SQL only; every
// state-changing action writes an audit entry.
const express = require('express');
const pool = require('../db/pool');
const { audit } = require('../lib/audit');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../lib/rbac');

const router = express.Router();
router.use(requireAuth);

const MATCH_TYPES = new Set(['publisher', 'path', 'name']);

// Validate + normalize one reader rule. Returns { ok, matchType, value } or
// { ok:false, error }. Values are trimmed and length-capped; a path/name is a
// printable string, a publisher is a signer display name â€” all kept tame so a
// stray control char can't smuggle past the agent's matcher.
function validateReader(body) {
  const matchType = typeof body.matchType === 'string' ? body.matchType.trim() : '';
  if (!MATCH_TYPES.has(matchType)) {
    return { ok: false, error: 'matchType must be publisher|path|name' };
  }
  const raw = typeof body.value === 'string' ? body.value.trim() : '';
  if (!raw) return { ok: false, error: 'value must be a non-empty string' };
  if (raw.length > 512) return { ok: false, error: 'value must be at most 512 chars' };
  // Reject control characters (the agent matches these against process image
  // paths / signer names; control chars are never legitimate there).
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f]/.test(raw)) {
    return { ok: false, error: 'value must not contain control characters' };
  }
  return { ok: true, matchType, value: raw };
}

function readerJson(row) {
  return {
    id: row.id,
    matchType: row.match_type,
    value: row.value,
    note: row.note,
    createdBy: row.created_by,
    createdAt: row.created_at,
  };
}

// GET /api/trusted-readers â€” the allowlist, newest first.
router.get('/', requirePermission('trusted_readers:read'), async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `select id, match_type, value, note, created_by, created_at
         from trusted_readers
        order by created_at desc, id desc`
    );
    res.json({ readers: rows.map(readerJson) });
  } catch (err) {
    next(err);
  }
});

// POST /api/trusted-readers â€” add a sanctioned application.
// Body: { matchType:'publisher'|'path'|'name', value, note? }.
router.post('/', requirePermission('trusted_readers:write'), async (req, res, next) => {
  try {
    const body = req.body || {};
    const v = validateReader(body);
    if (!v.ok) return res.status(400).json({ error: v.error });
    const note = typeof body.note === 'string' ? body.note.slice(0, 1000) : null;

    let rows;
    try {
      ({ rows } = await pool.query(
        `insert into trusted_readers (match_type, value, note, created_by)
         values ($1, $2, $3, $4)
         returning id, match_type, value, note, created_by, created_at`,
        [v.matchType, v.value, note, req.user.email]
      ));
    } catch (err) {
      if (err && err.code === '23505') {
        // UNIQUE (match_type, value) â€” the same rule already exists.
        return res.status(409).json({ error: 'that reader is already on the allowlist' });
      }
      throw err;
    }

    const reader = readerJson(rows[0]);
    await audit(req.user.email, 'trusted_reader.create', String(reader.id), {
      matchType: reader.matchType,
      value: reader.value,
    });
    res.status(201).json({ reader });
  } catch (err) {
    next(err);
  }
});

// DELETE /api/trusted-readers/:id â€” remove a sanctioned application.
router.delete('/:id', requirePermission('trusted_readers:write'), async (req, res, next) => {
  try {
    if (!/^\d{1,10}$/.test(req.params.id)) {
      return res.status(404).json({ error: 'reader not found' });
    }
    const { rows } = await pool.query(
      `delete from trusted_readers where id = $1
       returning id, match_type, value`,
      [parseInt(req.params.id, 10)]
    );
    if (rows.length === 0) return res.status(404).json({ error: 'reader not found' });
    await audit(req.user.email, 'trusted_reader.delete', String(rows[0].id), {
      matchType: rows[0].match_type,
      value: rows[0].value,
    });
    res.status(204).end();
  } catch (err) {
    next(err);
  }
});

module.exports = router;
