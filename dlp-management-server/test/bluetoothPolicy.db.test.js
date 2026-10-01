'use strict';
// Transaction-local tables shadow real policy tables. No production policy or
// migration history is changed. Requires the usual local test PostgreSQL.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const pool = require('../db/pool');
const { effectivePolicyForGroup, policyJson } = require('../lib/groupPolicy');

test('migration and SQL resolve default, override, and inherited Bluetooth modes', async () => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query(`CREATE TEMP TABLE read_deny_policy (
      id int, mode text, posture text, scan_fixed boolean, watch_paths jsonb,
      fail_block boolean, readers_authority text, deny_remote_sessions boolean
    ) ON COMMIT DROP`);
    await client.query(`CREATE TEMP TABLE group_read_deny_policy (
      group_id int, mode text, posture text, scan_fixed boolean, watch_paths jsonb,
      fail_block boolean, readers_authority text, deny_remote_sessions boolean
    ) ON COMMIT DROP`);
    await client.query(fs.readFileSync(path.join(__dirname, '../migrations/023_bluetooth_channel.sql'), 'utf8'));
    await client.query(`INSERT INTO read_deny_policy
      (id, mode, posture, scan_fixed, watch_paths, fail_block, readers_authority, deny_remote_sessions)
      VALUES (1, 'off', 'allowlist', false, '[]', false, 'merge', false)`);
    assert.equal(policyJson(await effectivePolicyForGroup(null, client)).bluetoothMode, 'off');
    await client.query("UPDATE read_deny_policy SET bluetooth_mode='enforce'");
    await client.query('INSERT INTO group_read_deny_policy (group_id) VALUES (10)');
    let policy = policyJson(await effectivePolicyForGroup(10, client));
    assert.equal(policy.mode, 'off');
    assert.equal(policy.bluetoothMode, 'enforce');
    await client.query("UPDATE group_read_deny_policy SET bluetooth_mode='monitor' WHERE group_id=10");
    assert.equal(policyJson(await effectivePolicyForGroup(10, client)).bluetoothMode, 'monitor');
    assert.equal(policyJson(await effectivePolicyForGroup(11, client)).bluetoothMode, 'enforce');
    await client.query('UPDATE group_read_deny_policy SET bluetooth_mode=COALESCE($1, bluetooth_mode)', [null]);
    assert.equal(policyJson(await effectivePolicyForGroup(10, client)).bluetoothMode, 'monitor');
    await client.query('DELETE FROM group_read_deny_policy WHERE group_id=10');
    assert.equal(policyJson(await effectivePolicyForGroup(10, client)).bluetoothMode, 'enforce');
  } finally {
    await client.query('ROLLBACK');
    client.release();
  }
});
test.after(async () => { await pool.end(); });
