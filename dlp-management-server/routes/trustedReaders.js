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
//   * trusted_readers:read   - policy_author, sysadmin, auditor
//   * trusted_readers:write  - policy_author
//
// Metadata only - no secrets, no content. Parameterised SQL only. Every
// state-changing action writes its audit entry in the SAME transaction as the
// mutation (atomic tamper-evidence): the change and its record commit or fail
// together.
const express = require('express');
const pool = require('../db/pool');
const { writeChainEntry, AUDIT_CHAIN_LOCK } = require('../lib/audit');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../lib/rbac');

const router = express.Router();
router.use(requireAuth);

const MATCH_TYPES = new Set(['publisher', 'path', 'name']);
// A rule is either an 'allow' (trusted reader) or a 'deny' override (blocked even
// if an allow rule — e.g. a publisher — would otherwise trust it). Deny wins on
// the endpoint. 'allow' is the default so an omitted kind is back-compatible.
const KINDS = new Set(['allow', 'deny']);
const INT4_MAX = 2147483647;

// Unify separators to backslash and strip trailing separators.
function normalizePath(raw) {
  return raw.replace(/\//g, '\\').replace(/\\+$/g, '');
}

// Validate + normalize one reader rule. Returns { ok, matchType, value } or
// { ok:false, error }. Beyond trimming/length/control-char checks, this rejects
// STRUCTURALLY dangerous rules per type: a whole-volume path (which would trust
// every program and silently disable read-deny), a name containing separators,
// or a publisher that is actually a path. This is the last line against a single
// rule neutralizing the entire control.
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

  if (matchType === 'path') {
    const p = normalizePath(raw);
    const isDrive = /^[A-Za-z]:\\/.test(p); // C:\...
    const isUnc = /^\\\\[^\\]+\\[^\\]+/.test(p); // \\server\share\...
    if (!isDrive && !isUnc) {
      return {
        ok: false,
        error: 'path must be an absolute path, e.g. C:\\Program Files\\App',
      };
    }
    // Require at least one folder below the drive/share root. A bare root (C:\,
    // \\server\share) would match every program under the whole volume and turn
    // read-deny off. (C:\Windows is depth 1 and allowed - that is the OS rule.)
    let tail = isDrive ? p.slice(3) : p.replace(/^\\\\[^\\]+\\[^\\]+/, '');
    tail = tail.replace(/^\\+/, '');
    const depth = tail.split('\\').filter(Boolean).length;
    if (depth < 1) {
      return {
        ok: false,
        error:
          'path is too broad (a drive/share root would trust every program) - point it at a specific folder, e.g. C:\\Program Files\\App',
      };
    }
    return { ok: true, matchType, value: p }; // store the normalized form
  }

  if (matchType === 'name') {
    if (/[\\/]/.test(raw)) {
      return {
        ok: false,
        error: 'name must be a bare file name with no path separators, e.g. winword.exe',
      };
    }
    return { ok: true, matchType, value: raw };
  }

  // publisher: an Authenticode signer display name, not a path.
  if (/^[A-Za-z]:\\/.test(raw) || raw.startsWith('\\\\')) {
    return { ok: false, error: 'publisher must be a signer name (e.g. "Adobe Inc."), not a path' };
  }
  return { ok: true, matchType, value: raw };
}

function readerJson(row) {
  return {
    id: row.id,
    kind: row.kind || 'allow',
    matchType: row.match_type,
    value: row.value,
    note: row.note,
    // group_id NULL = global (applies to every group); a set id = only that group.
    groupId: row.group_id ?? null,
    groupName: row.group_name ?? null,
    createdBy: row.created_by,
    createdAt: row.created_at,
  };
}

// GET /api/trusted-readers - the allowlist, newest first. Optional ?groupId filter:
//   absent   => ALL readers (overview, each carrying its group);
//   'global' => only global (group_id NULL) readers;
//   <n>      => only that group's readers.
router.get('/', requirePermission('trusted_readers:read'), async (req, res, next) => {
  try {
    const scope = req.query.groupId;
    let where = '';
    const params = [];
    if (scope === 'global') {
      where = 'where tr.group_id is null';
    } else if (scope !== undefined && /^\d+$/.test(scope)) {
      where = 'where tr.group_id = $1';
      params.push(Number(scope));
    }
    const { rows } = await pool.query(
      `select tr.id, tr.kind, tr.match_type, tr.value, tr.note, tr.group_id, tr.created_by, tr.created_at,
              g.name as group_name
         from trusted_readers tr
         left join groups g on g.id = tr.group_id
         ${where}
        order by tr.created_at desc, tr.id desc`,
      params
    );
    res.json({ readers: rows.map(readerJson) });
  } catch (err) {
    next(err);
  }
});

// POST /api/trusted-readers - add a sanctioned application.
// Body: { matchType:'publisher'|'path'|'name', value, note? }.
router.post('/', requirePermission('trusted_readers:write'), async (req, res, next) => {
  const body = req.body || {};
  const v = validateReader(body);
  if (!v.ok) return res.status(400).json({ error: v.error });
  const note = typeof body.note === 'string' ? body.note.slice(0, 1000) : null;

  // kind: 'allow' (default) or 'deny' (override). An omitted kind stays 'allow'
  // so existing callers are unaffected.
  const kind = body.kind === undefined || body.kind === null || body.kind === '' ? 'allow' : String(body.kind).trim();
  if (!KINDS.has(kind)) {
    return res.status(400).json({ error: "kind must be 'allow' or 'deny'" });
  }

  // groupId: absent/null/'' => global (NULL). Otherwise a positive integer group
  // (validated to exist below). Global rules apply to every group; a scoped rule
  // applies only to that group.
  let groupId = null;
  if (body.groupId !== undefined && body.groupId !== null && body.groupId !== '') {
    groupId = Number(body.groupId);
    if (!Number.isInteger(groupId) || groupId <= 0) {
      return res.status(400).json({ error: 'groupId must be a positive integer or null (global)' });
    }
  }

  const client = await pool.connect();
  try {
    await client.query('begin');
    // One transaction holding the chain lock: dedup + insert + audit are atomic.
    await client.query('select pg_advisory_xact_lock($1)', [AUDIT_CHAIN_LOCK]);

    if (groupId !== null) {
      const g = await client.query('select 1 from groups where id = $1', [groupId]);
      if (g.rows.length === 0) {
        await client.query('rollback');
        return res.status(400).json({ error: 'unknown group' });
      }
    }

    // Case-insensitive dedup, SCOPED to the same group bucket (global rows bucket
    // together via coalesce(group_id,0)), so "winword.exe" and "WINWORD.EXE" collide
    // within a scope but a global + a per-group copy may coexist. The DB's functional
    // UNIQUE index (migration 013) is the hard backstop (23505 below).
    // Dedup is scoped to (group bucket, kind, match_type, lower(value)) — matching
    // the DB's functional unique index (migration 018). The same matcher may thus
    // exist once as an allow and once as a deny (deny wins on the endpoint).
    const dup = await client.query(
      `select 1 from trusted_readers
        where coalesce(group_id,0) = coalesce($1,0) and kind = $2 and match_type = $3 and lower(value) = lower($4)
        limit 1`,
      [groupId, kind, v.matchType, v.value]
    );
    if (dup.rows.length) {
      await client.query('rollback');
      return res.status(409).json({ error: `that ${kind === 'deny' ? 'blocked application' : 'reader'} is already on the list` });
    }

    let rows;
    try {
      ({ rows } = await client.query(
        `insert into trusted_readers (kind, match_type, value, note, group_id, created_by)
         values ($1, $2, $3, $4, $5, $6)
         returning id, kind, match_type, value, note, group_id, created_by, created_at`,
        [kind, v.matchType, v.value, note, groupId, req.user.email]
      ));
    } catch (err) {
      if (err && err.code === '23505') {
        await client.query('rollback');
        return res.status(409).json({ error: `that ${kind === 'deny' ? 'blocked application' : 'reader'} is already on the list` });
      }
      throw err;
    }

    const reader = readerJson(rows[0]);
    // Distinct audit actions for allow vs deny so the trail reads clearly.
    const action = kind === 'deny' ? 'trusted_reader.deny.create' : 'trusted_reader.create';
    await writeChainEntry(client, req.user.email, action, String(reader.id), {
      kind,
      matchType: reader.matchType,
      value: reader.value,
      groupId,
    });
    await client.query('commit');
    res.status(201).json({ reader });
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

// DELETE /api/trusted-readers/:id - remove a sanctioned application.
router.delete('/:id', requirePermission('trusted_readers:write'), async (req, res, next) => {
  // Digits only AND within int4 range - an out-of-range id must be a clean 404,
  // not a Postgres 22003 error surfaced as 500.
  if (!/^\d+$/.test(req.params.id)) {
    return res.status(404).json({ error: 'reader not found' });
  }
  const id = Number(req.params.id);
  if (id < 1 || id > INT4_MAX) {
    return res.status(404).json({ error: 'reader not found' });
  }

  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query('select pg_advisory_xact_lock($1)', [AUDIT_CHAIN_LOCK]);
    const { rows } = await client.query(
      `delete from trusted_readers where id = $1
       returning id, kind, match_type, value`,
      [id]
    );
    if (rows.length === 0) {
      await client.query('rollback');
      return res.status(404).json({ error: 'reader not found' });
    }
    const delKind = rows[0].kind || 'allow';
    const delAction = delKind === 'deny' ? 'trusted_reader.deny.delete' : 'trusted_reader.delete';
    await writeChainEntry(client, req.user.email, delAction, String(rows[0].id), {
      kind: delKind,
      matchType: rows[0].match_type,
      value: rows[0].value,
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
