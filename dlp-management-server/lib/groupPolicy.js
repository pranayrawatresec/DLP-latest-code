'use strict';
// Per-group read-deny policy resolution (per-machine/per-group targeting).
//
// The Default group's policy lives, unchanged, in read_deny_policy (id=1). A
// non-default group may have an OVERRIDE row in group_read_deny_policy; if it has
// none it INHERITS the Default. An agent with group_id = NULL is in the Default
// group. This helper returns the single effective policy row for a group id,
// resolving override-or-inherit in one query so the agent endpoint and the console
// can never disagree.
const pool = require('../db/pool');

const POLICY_FALLBACK = {
  mode: 'off',
  posture: 'blocklist',
  scan_fixed: false,
  watch_paths: [],
  fail_block: false,
  readers_authority: 'merge',
};

// Effective policy for `groupId` (null => Default). `db` may be a pool or a client
// (so callers can resolve inside their own transaction). Returns a row shaped like
// read_deny_policy (snake_case columns).
async function effectivePolicyForGroup(groupId, db = pool) {
  const { rows } = await db.query(
    `SELECT COALESCE(o.mode, r.mode)                           AS mode,
            COALESCE(o.posture, r.posture)                     AS posture,
            COALESCE(o.scan_fixed, r.scan_fixed)               AS scan_fixed,
            COALESCE(o.watch_paths, r.watch_paths)             AS watch_paths,
            COALESCE(o.fail_block, r.fail_block)               AS fail_block,
            COALESCE(o.readers_authority, r.readers_authority) AS readers_authority
       FROM read_deny_policy r
       LEFT JOIN group_read_deny_policy o ON o.group_id = $1
      WHERE r.id = 1`,
    [groupId ?? null]
  );
  return rows[0] || { ...POLICY_FALLBACK };
}

// The camelCase wire shape the agent + console consume.
function policyJson(row) {
  return {
    mode: row.mode,
    posture: row.posture,
    scanFixed: row.scan_fixed,
    watchPaths: row.watch_paths,
    failBlock: row.fail_block,
    readersAuthority: row.readers_authority || 'merge',
  };
}

module.exports = { effectivePolicyForGroup, policyJson, POLICY_FALLBACK };
