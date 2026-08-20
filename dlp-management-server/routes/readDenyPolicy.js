'use strict';
// Endpoint READ-DENY policy — managed in the console, applied by the agent to the
// kernel driver (no command line). Two gates on every route: requireAuth (401)
// then requirePermission (403, denials audited). RBAC:
//   * read_deny_policy:read   - policy_author, sysadmin, auditor
//   * read_deny_policy:write  - policy_author
//
// The update and its audit entry commit in ONE transaction (atomic tamper-
// evidence). Parameterised SQL only. A single global row (id = 1).
const express = require('express');
const pool = require('../db/pool');
const { writeChainEntry, AUDIT_CHAIN_LOCK } = require('../lib/audit');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../lib/rbac');

const router = express.Router();
router.use(requireAuth);

const MODES = new Set(['off', 'monitor', 'enforce']);
const POSTURES = new Set(['allowlist', 'blocklist']);
const READER_AUTHORITIES = new Set(['central', 'merge']);

function policyJson(row) {
  return {
    mode: row.mode,
    posture: row.posture,
    scanFixed: row.scan_fixed,
    watchPaths: row.watch_paths,
    failBlock: row.fail_block,
    // Whether the console list is the WHOLE reader allowlist ('central') or is
    // unioned with each endpoint's local rules ('merge', default). #9.
    readersAuthority: row.readers_authority,
    updatedBy: row.updated_by,
    updatedAt: row.updated_at,
  };
}

// A watch path is a folder prefix on the fixed volume, e.g. "\Users". It must be
// backslash-anchored, printable, and bounded. "\" (the whole volume) IS allowed —
// unlike a bare drive root in a TRUST rule, watching everything is a deliberate
// (heavy) protection choice, not a bypass.
function normalizeWatchPath(raw) {
  const s = raw.trim().replace(/\//g, '\\').replace(/\\+$/g, '');
  return s === '' ? '\\' : s;
}
function validWatchPath(p) {
  if (typeof p !== 'string') return false;
  const s = p.trim();
  if (!s || s.length > 260) return false;
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f\x7f]/.test(s)) return false;
  return /^[\\/]/.test(s); // must start with a path separator
}

function validatePolicy(body) {
  const mode = typeof body.mode === 'string' ? body.mode.trim() : '';
  if (!MODES.has(mode)) return { ok: false, error: 'mode must be off|monitor|enforce' };

  const posture = typeof body.posture === 'string' ? body.posture.trim() : '';
  if (!POSTURES.has(posture)) return { ok: false, error: 'posture must be allowlist|blocklist' };

  if (typeof body.scanFixed !== 'boolean') return { ok: false, error: 'scanFixed must be true or false' };
  if (typeof body.failBlock !== 'boolean') return { ok: false, error: 'failBlock must be true or false' };

  // Reader-allowlist authority (#9). Optional for back-compat: an older client
  // that omits it keeps the default 'merge' (today's union behaviour) — it can
  // never silently flip a site to 'central'.
  let readersAuthority = 'merge';
  if (body.readersAuthority !== undefined) {
    readersAuthority = typeof body.readersAuthority === 'string' ? body.readersAuthority.trim() : '';
    if (!READER_AUTHORITIES.has(readersAuthority)) {
      return { ok: false, error: 'readersAuthority must be central|merge' };
    }
  }

  const wp = body.watchPaths;
  if (!Array.isArray(wp) || wp.length > 16) {
    return { ok: false, error: 'watchPaths must be an array of at most 16 folder prefixes' };
  }
  const watchPaths = [];
  for (const p of wp) {
    if (!validWatchPath(p)) {
      return {
        ok: false,
        error: `invalid watch path ${JSON.stringify(p)} — use a folder prefix like \\Users`,
      };
    }
    watchPaths.push(normalizeWatchPath(p));
  }
  // Watching the fixed drive with no folders selected would attach C: but inspect
  // nothing — almost certainly a mistake. Guide the admin to pick folders.
  if (body.scanFixed && watchPaths.length === 0) {
    return {
      ok: false,
      error: 'pick at least one folder to watch (e.g. \\Users), or turn off fixed-drive scanning',
    };
  }
  return {
    ok: true,
    mode,
    posture,
    scanFixed: body.scanFixed,
    watchPaths,
    failBlock: body.failBlock,
    readersAuthority,
  };
}

// GET /api/read-deny-policy — the current policy.
router.get('/', requirePermission('read_deny_policy:read'), async (req, res, next) => {
  try {
    const { rows } = await pool.query('select * from read_deny_policy where id = 1');
    if (rows.length === 0) return res.status(404).json({ error: 'policy not initialised' });
    res.json({ policy: policyJson(rows[0]) });
  } catch (err) {
    next(err);
  }
});

// PUT /api/read-deny-policy — replace the policy (whole object).
router.put('/', requirePermission('read_deny_policy:write'), async (req, res, next) => {
  const v = validatePolicy(req.body || {});
  if (!v.ok) return res.status(400).json({ error: v.error });

  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query('select pg_advisory_xact_lock($1)', [AUDIT_CHAIN_LOCK]);
    const { rows } = await client.query(
      `update read_deny_policy
          set mode=$1, posture=$2, scan_fixed=$3, watch_paths=$4, fail_block=$5,
              readers_authority=$6, updated_by=$7, updated_at=now()
        where id = 1
      returning *`,
      [
        v.mode,
        v.posture,
        v.scanFixed,
        JSON.stringify(v.watchPaths),
        v.failBlock,
        v.readersAuthority,
        req.user.email,
      ]
    );
    await writeChainEntry(client, req.user.email, 'read_deny_policy.update', 'read-deny', {
      mode: v.mode,
      posture: v.posture,
      scanFixed: v.scanFixed,
      watchPaths: v.watchPaths,
      failBlock: v.failBlock,
      readersAuthority: v.readersAuthority,
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
