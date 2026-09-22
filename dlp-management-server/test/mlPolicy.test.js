'use strict';
// Test harness for the ML document-classification policy (routes/mlPolicy.js)
// plus the agent-facing delivery endpoint (GET /agent/ml-policy) and the
// detection_type derivation in POST /agent/incidents. Mirrors the two-server
// pattern of trustedReaders.test.js: the admin app over plain HTTP (login
// cookies) and the agentApp over REAL mTLS (a genuinely enrolled agent).
//
//   A. Label space: ml_labels mirrors taxonomy v6_2_01 exactly — 29 rows,
//      indices 0..28, ids/names byte-identical to registry.lock.json, and the
//      13/3/13 display grouping. The model's head is trained to that order, so
//      a drifted mirror would mislabel every incident in the console.
//   B. HTTP + RBAC: 401 anon; read for author/sysadmin/auditor; write only for
//      policy_author (auditor/sysadmin write -> 403 + audited).
//   C. Round-trip + validation: PUT then GET returns EXACTLY what was PUT
//      (per-label override included); unknown id / bad confidence / bad action /
//      duplicate ids all 400. Every save audited as 'ml_policy.update'.
//   C2. The denyUnclassified posture (migration 022) — the one switch here that
//      can deny the first read of every legacy file on an endpoint. Asserts the
//      column DEFAULT is false, that it round-trips and is audited, that a client
//      omitting it gets 200 + false (never a 400, and never a silent "deny"), and
//      that a non-boolean is REJECTED rather than coerced.
//   D. Agent delivery: GET /agent/ml-policy over mTLS. Asserts the confidences
//      are JSON NUMBERS — pg hands NUMERIC back as a STRING, and "0.800" on the
//      wire would break the agent's `confidence >= threshold` comparison
//      (serde would reject it outright). No cert -> 401.
//   E. Fusion badge: POST /agent/incidents derives detection_type. A verdict
//      with NO ml key must still yield exactly today's value (backward
//      compatibility with every agent shipped before this feature); an
//      ml.sensitive verdict composes 'idm+edm+ml' — which the plain-text
//      detection_type column must store untruncated.
//   F. Invariant: the audit hash-chain stays intact.
//
// Creates its own tagged users/agents and cleans them up, and SNAPSHOTS the
// ml_policy singleton + its label set on entry so a dev database is left exactly
// as it was found. Audit rows are append-only and intentionally remain.
require('dotenv').config();
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const https = require('https');
const forge = require('node-forge');
const pool = require('../db/pool');
const ca = require('../lib/ca');
const et = require('../lib/enrollmentTokens');
const { verifyChain } = require('../lib/audit');

const app = require('../app');
const agentApp = require('../agent/agentApp');

// The frozen label space, from the taxonomy lock the model was trained against.
// The DB mirror in migration 021 must agree with this file exactly.
const LOCK = JSON.parse(
  fs.readFileSync(
    path.join(__dirname, '..', '..', 'Document_classification', 'taxonomy', 'v6_2_01', 'registry.lock.json'),
    'utf8'
  )
);
// The UI grouping from the shared contract (display only, 13/3/13 = 29).
const DOMAINS = {
  general: 'ADM GOV INS OPS FIN COM POL ANA PUB OOD PER MED LEG'.split(' '),
  education: 'STU TCH EXM'.split(' '),
  defence: 'INT WPN AVI NAV SIG CYB SPC LOG ACQ DIP TRN MNT NUC'.split(' '),
};

const TAG = 'mltest_' + crypto.randomBytes(4).toString('hex');
const PW = 'test-Password-123456';
const results = [];
let passed = 0;
let failed = 0;
let adminServer;
let baseUrl;
let mtlsServer;
let PORT;
let snapshot; // the ml_policy singleton + label set as we found it

async function check(id, name, fn) {
  try {
    const detail = (await fn()) || '';
    results.push({ id, name, status: 'PASS', detail: String(detail) });
    passed++;
    console.log(`  PASS  ${id}  ${name}`);
  } catch (err) {
    results.push({ id, name, status: 'FAIL', detail: err.message });
    failed++;
    console.log(`  FAIL  ${id}  ${name}\n        ${err.message}`);
  }
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'assertion failed');
}

async function makeUser(kind, roleName) {
  const email = `${TAG}_${kind}@test.local`;
  const hash = await bcrypt.hash(PW, 10);
  const u = await pool.query(
    `insert into admin_users (email, display_name, pw_hash) values ($1,$2,$3) returning id`,
    [email, `${TAG} ${kind}`, hash]
  );
  await pool.query(
    `insert into user_roles (user_id, role_id, granted_by)
     select $1, id, 'test' from roles where name = $2`,
    [u.rows[0].id, roleName]
  );
  return { id: u.rows[0].id, email };
}

async function login(email) {
  const res = await fetch(`${baseUrl}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password: PW }),
  });
  assert(res.status === 200, `login failed for ${email}: ${res.status}`);
  const m = (res.headers.get('set-cookie') || '').match(/dlp_session=[^;]+/);
  assert(m, 'no session cookie returned');
  return m[0];
}

function api(pathname, { cookie, method = 'GET', body } = {}) {
  return fetch(`${baseUrl}${pathname}`, {
    method,
    headers: {
      ...(cookie ? { Cookie: cookie } : {}),
      ...(body ? { 'Content-Type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });
}

// mTLS HTTPS helper (mirrors trustedReaders.test.js). Returns the RAW body too:
// the NUMERIC-as-string defect is invisible after JSON.parse coerces nothing, so
// D02 inspects the bytes on the wire as well as the parsed types.
function request({ pathname, method = 'GET', body, key, cert, verifyServer = false }) {
  return new Promise((resolve, reject) => {
    const data = body != null ? JSON.stringify(body) : null;
    const req = https.request(
      {
        host: '127.0.0.1', port: PORT, path: pathname, method, key, cert,
        ca: verifyServer ? ca.loadCaCertificatePem() : undefined,
        rejectUnauthorized: Boolean(verifyServer),
        servername: 'localhost', agent: false,
        headers: {
          'Content-Type': 'application/json', Connection: 'close',
          ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
        },
      },
      (res) => {
        let b = '';
        res.on('data', (c) => (b += c));
        res.on('end', () => resolve({ status: res.statusCode, raw: b, body: b ? JSON.parse(b) : null }));
      }
    );
    req.setTimeout(15000, () => req.destroy(new Error('request timeout')));
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

function csrFrom(keys, cn) {
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;
  csr.setSubject([{ name: 'commonName', value: cn }]);
  csr.sign(keys.privateKey, forge.md.sha256.create());
  return {
    csrPem: forge.pki.certificationRequestToPem(csr),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

// Take the singleton and its label set as we found them, so the suite can put a
// shared dev database back exactly the way it was (these are global settings,
// not tagged rows we can simply delete).
async function takeSnapshot() {
  const p = await pool.query('select * from ml_policy where id = 1');
  const l = await pool.query('select label_id, min_confidence, added_by from ml_sensitive_labels');
  return { policy: p.rows[0] || null, labels: l.rows };
}

async function restoreSnapshot() {
  if (!snapshot) return;
  await pool.query('delete from ml_sensitive_labels');
  if (snapshot.policy) {
    const p = snapshot.policy;
    await pool.query(
      `update ml_policy set enabled=$1, min_confidence=$2, action=$3, fail_block=$4,
              deny_unclassified=$5, model_version=$6, updated_by=$7, updated_at=$8 where id = 1`,
      [p.enabled, p.min_confidence, p.action, p.fail_block, p.deny_unclassified,
       p.model_version, p.updated_by, p.updated_at]
    );
  }
  for (const l of snapshot.labels) {
    await pool.query(
      `insert into ml_sensitive_labels (label_id, min_confidence, added_by) values ($1,$2,$3)`,
      [l.label_id, l.min_confidence, l.added_by]
    );
  }
}

async function cleanup(emails) {
  await restoreSnapshot();
  await pool.query(
    `delete from detection_incidents where agent_id in (select id from agents where hostname like $1)`,
    [`${TAG}%`]
  );
  await pool.query(`delete from agents where hostname like $1`, [`${TAG}%`]);
  await pool.query(`delete from enrollment_tokens where created_by = $1`, [TAG]);
  if (emails) await pool.query(`delete from admin_users where email like $1`, [`${TAG}_%@test.local`]);
}

async function main() {
  console.log('\nML document-classification policy - test & edge-case suite\n');
  if (!ca.caExists()) {
    console.error('No CA - run: npm run init-ca');
    process.exit(1);
  }
  snapshot = await takeSnapshot();
  await cleanup(false);

  await new Promise((r) => { adminServer = app.listen(0, '127.0.0.1', r); });
  baseUrl = `http://127.0.0.1:${adminServer.address().port}`;
  const tls = ca.loadServerTlsMaterial();
  mtlsServer = https.createServer(
    { key: tls.key, cert: tls.cert, ca: tls.ca, requestCert: true, rejectUnauthorized: false, minVersion: 'TLSv1.2' },
    agentApp
  );
  await new Promise((r) => mtlsServer.listen(0, '127.0.0.1', r));
  PORT = mtlsServer.address().port;

  const sysadmin = await makeUser('sysadmin', 'sysadmin');
  const author = await makeUser('author', 'policy_author');
  const auditor = await makeUser('auditor', 'auditor');
  const sysCookie = await login(sysadmin.email);
  const authorCookie = await login(author.email);
  const auditorCookie = await login(auditor.email);

  // ============ A. The frozen label space ============
  await check('M01', 'ml_labels mirrors registry.lock.json exactly (29, 0..28)', async () => {
    const { rows } = await pool.query('select id, idx, name, domain from ml_labels order by idx');
    assert(rows.length === LOCK.width, `expected ${LOCK.width} rows, got ${rows.length}`);
    assert(LOCK.labels.length === LOCK.width, `lock width ${LOCK.width} != ${LOCK.labels.length} labels`);
    for (let i = 0; i < LOCK.labels.length; i++) {
      const L = LOCK.labels[i];
      const R = rows[i];
      assert(R.idx === i, `row ${i}: idx ${R.idx} (indices must be contiguous 0..28)`);
      assert(R.idx === L.index, `row ${i}: db idx ${R.idx} != lock index ${L.index}`);
      assert(R.id === L.id, `idx ${i}: db id ${R.id} != lock id ${L.id}`);
      assert(R.name === L.name, `${L.id}: db name ${JSON.stringify(R.name)} != lock ${JSON.stringify(L.name)}`);
    }
    return `${rows.length} labels identical to the v6_2_01 lock`;
  });

  await check('M02', 'domain grouping is the contract 13 general / 3 education / 13 defence', async () => {
    const { rows } = await pool.query('select id, domain from ml_labels');
    const byId = new Map(rows.map((r) => [r.id, r.domain]));
    for (const [domain, ids] of Object.entries(DOMAINS)) {
      for (const id of ids) {
        assert(byId.has(id), `contract domain ${domain} names unknown label ${id}`);
        assert(byId.get(id) === domain, `${id}: db domain ${byId.get(id)} != contract ${domain}`);
      }
    }
    const counts = rows.reduce((a, r) => ((a[r.domain] = (a[r.domain] || 0) + 1), a), {});
    assert(counts.general === 13 && counts.education === 3 && counts.defence === 13,
      `counts wrong: ${JSON.stringify(counts)}`);
    return '13 / 3 / 13';
  });

  await check('M03', 'singleton ml_policy row exists and defaults are inert (disabled)', async () => {
    const { rows } = await pool.query('select * from ml_policy');
    assert(rows.length === 1 && rows[0].id === 1, `expected exactly one row id=1, got ${rows.length}`);
    // Checked against the SNAPSHOT (the suite may have run before), not live state.
    assert(snapshot.policy && snapshot.policy.model_version === 'V6.2.01',
      `model_version ${snapshot.policy && snapshot.policy.model_version} != V6.2.01`);
    return `singleton present, model_version ${rows[0].model_version}`;
  });

  await check('M03b', 'deny_unclassified column exists and its COLUMN DEFAULT is false', async () => {
    // Migration 022's default is the whole safety story: an estate that upgrades
    // without touching the console must not start denying first reads. Read the
    // catalogue, not the live row — a previous run of this suite may have set it.
    const { rows } = await pool.query(
      `select column_default, is_nullable, data_type
         from information_schema.columns
        where table_name = 'ml_policy' and column_name = 'deny_unclassified'`
    );
    assert(rows.length === 1, 'ml_policy.deny_unclassified is missing (migration 022 not applied?)');
    assert(rows[0].data_type === 'boolean', `data_type ${rows[0].data_type}`);
    assert(rows[0].is_nullable === 'NO', 'deny_unclassified must be NOT NULL (null is not a posture)');
    assert(/false/i.test(rows[0].column_default || ''), `column default is ${rows[0].column_default}, must be false`);
    return 'boolean NOT NULL DEFAULT false';
  });

  // ============ B. RBAC gates ============
  await check('M04', 'anon GET policy + labels -> 401', async () => {
    for (const p of ['/api/ml-policy', '/api/ml-policy/labels']) {
      const res = await api(p);
      assert(res.status === 401, `${p}: expected 401, got ${res.status}`);
    }
    return 'both surfaces 401 without a session';
  });

  await check('M05', 'GET policy + labels: author, sysadmin, auditor all 200', async () => {
    for (const [who, cookie] of [['author', authorCookie], ['sysadmin', sysCookie], ['auditor', auditorCookie]]) {
      const pol = await api('/api/ml-policy', { cookie });
      assert(pol.status === 200, `${who} policy: expected 200, got ${pol.status}`);
      const lab = await api('/api/ml-policy/labels', { cookie });
      assert(lab.status === 200, `${who} labels: expected 200, got ${lab.status}`);
      assert((await lab.json()).labels.length === 29, `${who}: labels count wrong`);
    }
    return 'all three read roles allowed, 29 labels each';
  });

  await check('M06', 'GET /api/ml-policy/labels returns all 29 in model index order', async () => {
    const res = await api('/api/ml-policy/labels', { cookie: authorCookie });
    const { labels } = await res.json();
    assert(labels.length === 29, `expected 29, got ${labels.length}`);
    labels.forEach((l, i) => {
      assert(l.index === i, `position ${i} has index ${l.index}`);
      assert(l.id === LOCK.labels[i].id, `position ${i}: ${l.id} != ${LOCK.labels[i].id}`);
      assert(l.name === LOCK.labels[i].name, `${l.id}: name ${l.name}`);
      assert(['general', 'education', 'defence'].includes(l.domain), `${l.id}: domain ${l.domain}`);
    });
    return `29 labels, ADM..NUC, index 0..28`;
  });

  await check('M07', 'PUT as auditor -> 403 + audited', async () => {
    const res = await api('/api/ml-policy', {
      cookie: auditorCookie, method: 'PUT',
      body: { enabled: true, minConfidence: 0.7, action: 'audit', failBlock: true, labels: [] },
    });
    assert(res.status === 403, `expected 403, got ${res.status}`);
    const denied = await pool.query(
      `select 1 from audit_log where action = 'authz.denied' and actor = $1
         and detail->>'required' = 'ml_policy:write' limit 1`,
      [auditor.email]);
    assert(denied.rows.length === 1, 'denial not audited');
    return '403 + authz.denied logged';
  });

  await check('M08', 'PUT as sysadmin -> 403 (write is policy_author only)', async () => {
    const res = await api('/api/ml-policy', {
      cookie: sysCookie, method: 'PUT',
      body: { enabled: true, minConfidence: 0.7, action: 'audit', failBlock: true, labels: [] },
    });
    assert(res.status === 403, `expected 403, got ${res.status}`);
    return 'separation of duties: sysadmin cannot author policy';
  });

  // ============ C. Round-trip + validation ============
  // The selection under test: two defence classes and one general one, with a
  // RAISED per-label floor on NUC (a nuclear hit should need more certainty than
  // the site-wide default) and inheritance (null) on the other two.
  const SAVED = {
    enabled: true,
    minConfidence: 0.75,
    action: 'block',
    failBlock: true,
    // The dangerous posture switch stays OFF in the shared fixture — the dedicated
    // M14..M17 checks below arm and disarm it explicitly, so every other check in
    // this file asserts against the default-safe reading.
    denyUnclassified: false,
    labels: [
      { id: 'FIN', minConfidence: null },
      { id: 'INT', minConfidence: null },
      { id: 'NUC', minConfidence: 0.925 },
    ],
  };

  await check('M09', 'PUT a policy as policy_author -> 200 and echoes what was sent', async () => {
    const res = await api('/api/ml-policy', { cookie: authorCookie, method: 'PUT', body: SAVED });
    const payload = await res.json();
    assert(res.status === 200, `expected 200, got ${res.status} ${JSON.stringify(payload)}`);
    const { policy } = payload;
    assert(policy.enabled === true && policy.action === 'block' && policy.failBlock === true, 'scalars wrong');
    assert(policy.minConfidence === 0.75, `minConfidence ${policy.minConfidence} (${typeof policy.minConfidence})`);
    assert(policy.modelVersion === 'V6.2.01', `modelVersion ${policy.modelVersion}`);
    assert(policy.updatedBy === author.email, `updatedBy ${policy.updatedBy}`);
    return `3 classes saved by ${author.email}`;
  });

  await check('M10', 'GET returns EXACTLY what was PUT (label order = model index order)', async () => {
    const res = await api('/api/ml-policy', { cookie: auditorCookie });
    const { policy } = await res.json();
    assert(policy.enabled === SAVED.enabled, `enabled ${policy.enabled}`);
    assert(policy.action === SAVED.action, `action ${policy.action}`);
    assert(policy.failBlock === SAVED.failBlock, `failBlock ${policy.failBlock}`);
    assert(policy.minConfidence === SAVED.minConfidence, `minConfidence ${policy.minConfidence}`);
    assert(policy.denyUnclassified === false, `denyUnclassified ${JSON.stringify(policy.denyUnclassified)}`);
    // FIN idx 6, INT idx 14, NUC idx 28 — the route sorts by ml_labels.idx.
    assert(JSON.stringify(policy.labels) === JSON.stringify(SAVED.labels),
      `labels round-trip mismatch:\n  got  ${JSON.stringify(policy.labels)}\n  sent ${JSON.stringify(SAVED.labels)}`);
    // NUMERIC-as-string would survive a loose compare but not this one.
    assert(typeof policy.minConfidence === 'number', 'policy minConfidence is not a JSON number');
    for (const l of policy.labels) {
      assert(l.minConfidence === null || typeof l.minConfidence === 'number',
        `${l.id}: minConfidence is ${typeof l.minConfidence}, not a number/null`);
    }
    return 'byte-identical round-trip, confidences are JSON numbers';
  });

  await check('M11', "save audited as 'ml_policy.update' with the label set", async () => {
    const { rows } = await pool.query(
      `select detail from audit_log where action = 'ml_policy.update' and actor = $1
        order by seq desc limit 1`, [author.email]);
    assert(rows.length === 1, "no 'ml_policy.update' audit entry");
    const d = rows[0].detail;
    assert(d.labelCount === 3, `labelCount ${d.labelCount}`);
    assert(JSON.stringify(d.labels) === JSON.stringify(['FIN', 'INT', 'NUC']), `labels ${JSON.stringify(d.labels)}`);
    assert(d.enabled === true && d.action === 'block' && d.minConfidence === 0.75, 'audited scalars wrong');
    // Metadata only — the audit detail must never carry document text.
    assert(d.text === undefined && d.snippet === undefined, 'audit detail carries content');
    return `audited: ${d.labelCount} classes, action ${d.action}`;
  });

  await check('M12', 'invalid PUT bodies -> 400 (and nothing is saved)', async () => {
    const base = { enabled: true, minConfidence: 0.7, action: 'audit', failBlock: true, labels: [] };
    const bads = [
      [{ ...base, labels: [{ id: 'ZZZ' }] }, 'unknown label id'],
      [{ ...base, labels: [{ id: 'fin' }] }, 'wrong-case label id (ids are frozen upper-case)'],
      [{ ...base, minConfidence: 0 }, 'minConfidence 0 (would mark every doc of the class sensitive)'],
      [{ ...base, minConfidence: 1.5 }, 'minConfidence 1.5 (not a probability)'],
      [{ ...base, minConfidence: -0.2 }, 'negative minConfidence'],
      [{ ...base, minConfidence: '0.8' }, 'minConfidence as a string'],
      [{ ...base, action: 'nuke' }, 'unknown action'],
      [{ ...base, labels: [{ id: 'FIN' }, { id: 'FIN', minConfidence: 0.9 }] }, 'duplicate label ids'],
      [{ ...base, labels: [{ id: 'FIN', minConfidence: 0 }] }, 'per-label minConfidence 0'],
      [{ ...base, labels: [{ id: 'FIN', minConfidence: 1.01 }] }, 'per-label minConfidence > 1'],
      [{ ...base, enabled: 'yes' }, 'enabled not a boolean'],
      [{ ...base, failBlock: 1 }, 'failBlock not a boolean'],
      [{ ...base, labels: 'FIN' }, 'labels not an array'],
      [{ ...base, labels: [{}] }, 'label without an id'],
      [{ ...base, labels: ['FIN'] }, 'label entry not an object'],
      [{}, 'empty body'],
    ];
    for (const [body, why] of bads) {
      const res = await api('/api/ml-policy', { cookie: authorCookie, method: 'PUT', body });
      assert(res.status === 400, `${why}: expected 400, got ${res.status}`);
    }
    // A rejected PUT must leave the previously saved policy untouched — a bad
    // request must never silently narrow protection.
    const after = await api('/api/ml-policy', { cookie: authorCookie });
    const { policy } = await after.json();
    assert(policy.labels.length === 3 && policy.action === 'block', 'a rejected PUT mutated the policy');
    return `${bads.length} invalid bodies rejected, saved policy intact`;
  });

  await check('M13', 'an EMPTY label set is a legal (inert) save', async () => {
    // Enabled with nothing selected must be savable: an admin mid-decision has a
    // safe state, and the ML signal contributes nothing until classes are chosen.
    const res = await api('/api/ml-policy', {
      cookie: authorCookie, method: 'PUT',
      body: { enabled: true, minConfidence: 0.7, action: 'audit', failBlock: true, labels: [] },
    });
    assert(res.status === 200, `expected 200, got ${res.status}`);
    assert((await res.json()).policy.labels.length === 0, 'labels not cleared');
    // Put the real selection back for the agent-delivery checks below.
    const back = await api('/api/ml-policy', { cookie: authorCookie, method: 'PUT', body: SAVED });
    assert(back.status === 200, `restore: expected 200, got ${back.status}`);
    return 'enabled + zero classes accepted (inert), then restored';
  });

  // ============ C2. The denyUnclassified posture switch (migration 022) ============
  // The one control on this page that can take an estate offline: with it on, the
  // endpoint DENIES an exfil-channel read of any file its classifier has not seen.
  await check('M14', 'denyUnclassified round-trips true and is audited', async () => {
    const res = await api('/api/ml-policy', {
      cookie: authorCookie, method: 'PUT', body: { ...SAVED, denyUnclassified: true },
    });
    assert(res.status === 200, `expected 200, got ${res.status}`);
    assert((await res.json()).policy.denyUnclassified === true, 'PUT response did not echo true');

    const get = await api('/api/ml-policy', { cookie: auditorCookie });
    const { policy } = await get.json();
    assert(policy.denyUnclassified === true, `GET returned ${JSON.stringify(policy.denyUnclassified)}`);
    assert(typeof policy.denyUnclassified === 'boolean', 'denyUnclassified is not a JSON boolean');

    // Audited on every save, not only on the transition — an auditor must be able
    // to answer "what was the posture at time T" without replaying deltas.
    const { rows } = await pool.query(
      `select detail from audit_log where action = 'ml_policy.update' and actor = $1
        order by seq desc limit 1`, [author.email]);
    assert(rows.length === 1 && rows[0].detail.denyUnclassified === true,
      `audit detail denyUnclassified ${JSON.stringify(rows[0] && rows[0].detail.denyUnclassified)}`);
    return 'true saved, read back and audited';
  });

  await check('M15', 'a client that OMITS denyUnclassified keeps working and gets FALSE', async () => {
    // Backward compatibility with a console built before migration 022 — but the
    // value it does not send must default to the SAFE reading, never the dangerous
    // one. It is armed above, so this also proves an omission DISARMS rather than
    // silently preserving a denial posture the operator can no longer see.
    const body = { ...SAVED };
    delete body.denyUnclassified;
    const res = await api('/api/ml-policy', { cookie: authorCookie, method: 'PUT', body });
    assert(res.status === 200, `expected 200, got ${res.status} ${JSON.stringify(await res.json())}`);
    const get = await api('/api/ml-policy', { cookie: authorCookie });
    const { policy } = await get.json();
    assert(policy.denyUnclassified === false, `omitted field became ${JSON.stringify(policy.denyUnclassified)}`);
    return 'omitted -> 200 and false (safe default), not a 400';
  });

  await check('M16', 'a non-boolean denyUnclassified -> 400 (never coerced)', async () => {
    // "false", 0 and 1 are all client bugs. Coercing any of them would let a posture
    // decision be made by a type conversion instead of by an operator.
    for (const v of ['true', 'false', 0, 1, 'yes', {}, []]) {
      const res = await api('/api/ml-policy', {
        cookie: authorCookie, method: 'PUT', body: { ...SAVED, denyUnclassified: v },
      });
      assert(res.status === 400, `denyUnclassified=${JSON.stringify(v)}: expected 400, got ${res.status}`);
    }
    // A rejected PUT must not have moved the posture.
    const get = await api('/api/ml-policy', { cookie: authorCookie });
    assert((await get.json()).policy.denyUnclassified === false, 'a rejected PUT changed the posture');
    return '7 non-boolean values rejected, posture unchanged';
  });

  await check('M17', 'explicit null is treated as absent (false), not an error', async () => {
    const res = await api('/api/ml-policy', {
      cookie: authorCookie, method: 'PUT', body: { ...SAVED, denyUnclassified: null },
    });
    assert(res.status === 200, `expected 200, got ${res.status}`);
    assert((await res.json()).policy.denyUnclassified === false, 'null did not read as false');
    return 'null -> false';
  });

  // ============ D. Agent delivery (real mTLS) ============
  const keys2048 = forge.pki.rsa.generateKeyPair(2048);
  const enroll = await (async () => {
    const tok = await et.createToken({ description: TAG, maxUses: 1, createdBy: TAG });
    const { csrPem, keyPem } = csrFrom(keys2048, 'agent-cn');
    const res = await request({
      pathname: '/agent/enroll', method: 'POST',
      body: { token: tok.token, csrPem, hostname: `${TAG}-pc1` },
    });
    assert(res.status === 201, `enroll failed: ${res.status}`);
    return { agentId: res.body.agentId, keyPem, certPem: res.body.certificate };
  })();
  const agentTls = { key: enroll.keyPem, cert: enroll.certPem, verifyServer: true };

  await check('D01', 'GET /agent/ml-policy delivers the policy + audited', async () => {
    const res = await request({ pathname: '/agent/ml-policy', method: 'GET', ...agentTls });
    assert(res.status === 200, `expected 200, got ${res.status}`);
    const p = res.body.policy;
    assert(p, 'no policy in response');
    assert(p.enabled === true && p.action === 'block' && p.failBlock === true, 'scalars wrong');
    // Delivered EXPLICITLY, and false here — an agent must never have to infer the
    // posture from a missing key, and a missing key must never read as "deny".
    assert(p.denyUnclassified === false, `denyUnclassified ${JSON.stringify(p.denyUnclassified)}`);
    assert(/"denyUnclassified":false/.test(res.raw), `denyUnclassified not present in: ${res.raw}`);
    assert(p.modelVersion === 'V6.2.01', `modelVersion ${p.modelVersion}`);
    assert(JSON.stringify(p.labels) === JSON.stringify(SAVED.labels),
      `labels: got ${JSON.stringify(p.labels)}`);
    // Console provenance must not leak to an endpoint.
    assert(p.updatedBy === undefined && p.updatedAt === undefined, 'admin provenance leaked to the agent');
    const a = await pool.query(
      `select 1 from audit_log where action = 'agent.ml_policy_delivered' and target = $1`, [enroll.agentId]);
    assert(a.rows.length >= 1, 'delivery not audited');
    return `${p.labels.length} classes delivered, audited`;
  });

  await check('D02', 'minConfidence is a JSON NUMBER on the wire, not a pg NUMERIC string', async () => {
    // The likeliest defect in the whole feature: node-postgres returns NUMERIC as
    // a STRING. Serde on the agent types these as f64, so "0.925" is a hard parse
    // failure — the agent would fall back to its cached policy and silently drift.
    const res = await request({ pathname: '/agent/ml-policy', method: 'GET', ...agentTls });
    const p = res.body.policy;
    assert(typeof p.minConfidence === 'number', `policy.minConfidence is ${typeof p.minConfidence}`);
    for (const l of p.labels) {
      assert(l.minConfidence === null || typeof l.minConfidence === 'number',
        `${l.id}.minConfidence is ${typeof l.minConfidence} (${JSON.stringify(l.minConfidence)})`);
    }
    const nuc = p.labels.find((l) => l.id === 'NUC');
    assert(nuc && nuc.minConfidence === 0.925, `NUC override ${JSON.stringify(nuc && nuc.minConfidence)}`);
    // Inspect the raw bytes too: a quoted number survives JSON.parse as a string,
    // but this catches the inverse mistake of stringifying on the way out.
    assert(!/"minConfidence"\s*:\s*"/.test(res.raw), `a quoted minConfidence is present in: ${res.raw}`);
    assert(/"minConfidence":0\.925/.test(res.raw), `NUC override not an unquoted number in: ${res.raw}`);
    return 'unquoted numbers on the wire (policy floor + per-label override)';
  });

  await check('D03', 'GET /agent/ml-policy WITHOUT a client cert -> 401', async () => {
    const res = await request({ pathname: '/agent/ml-policy', method: 'GET' });
    assert(res.status === 401, `expected 401, got ${res.status}`);
    return 'no cert -> 401';
  });

  await check('D04', 'an ARMED denyUnclassified reaches the agent and the delivery is audited', async () => {
    // The delivery half of the posture record: the console save says an admin armed
    // it, this says WHICH endpoints actually received it, and when.
    const put = await api('/api/ml-policy', {
      cookie: authorCookie, method: 'PUT', body: { ...SAVED, denyUnclassified: true },
    });
    assert(put.status === 200, `arm failed: ${put.status}`);

    const res = await request({ pathname: '/agent/ml-policy', method: 'GET', ...agentTls });
    assert(res.status === 200, `expected 200, got ${res.status}`);
    assert(res.body.policy.denyUnclassified === true,
      `agent got ${JSON.stringify(res.body.policy.denyUnclassified)}`);
    assert(/"denyUnclassified":true/.test(res.raw), `not an unquoted boolean in: ${res.raw}`);

    const a = await pool.query(
      `select detail from audit_log where action = 'agent.ml_policy_delivered' and target = $1
        order by seq desc limit 1`, [enroll.agentId]);
    assert(a.rows.length === 1 && a.rows[0].detail.denyUnclassified === true,
      `delivery audit detail ${JSON.stringify(a.rows[0] && a.rows[0].detail)}`);

    // Disarm again so the rest of the suite (and a dev database between the PUT and
    // restoreSnapshot) is never left holding a denial posture.
    const off = await api('/api/ml-policy', { cookie: authorCookie, method: 'PUT', body: SAVED });
    assert(off.status === 200, `disarm failed: ${off.status}`);
    return 'armed policy delivered over mTLS + audited, then disarmed';
  });

  // ============ E. Fusion badge on POST /agent/incidents ============
  async function report(verdict) {
    const res = await request({
      pathname: '/agent/incidents', method: 'POST', ...agentTls,
      body: { channel: 'usb', verdict, fileName: `${TAG}.docx`, actionTaken: 'blocked' },
    });
    assert(res.status === 201, `incident report failed: ${res.status}`);
    const { rows } = await pool.query(
      'select detection_type from detection_incidents where id = $1', [res.body.id]);
    return rows[0].detection_type;
  }

  await check('E01', 'a verdict with NO ml key yields exactly today\'s detection_type', async () => {
    // Backward compatibility: every agent shipped before this feature.
    assert(await report({ idm: [{}], edm: [] }) === 'idm', 'idm only');
    assert(await report({ idm: [], edm: [{}] }) === 'edm', 'edm only');
    assert(await report({ idm: [{}], edm: [{}] }) === 'idm+edm', 'both');
    assert(await report({ idm: [], edm: [] }) === null, 'neither -> null');
    return 'idm / edm / idm+edm / null unchanged';
  });

  await check('E02', 'ml.sensitive composes the detection_type (OR, never AND)', async () => {
    const ok = (labelId) => ({ status: 'ok', modelVersion: 'V6.2.01', labelId, confidence: 0.99, sensitive: true });
    assert(await report({ idm: [], edm: [], ml: ok('FIN') }) === 'ml', 'ml alone');
    assert(await report({ idm: [{}], edm: [], ml: ok('FIN') }) === 'idm+ml', 'idm+ml');
    assert(await report({ idm: [], edm: [{}], ml: ok('INT') }) === 'edm+ml', 'edm+ml');
    return 'ml / idm+ml / edm+ml';
  });

  await check('E03', "'idm+edm+ml' stores untruncated in detection_type", async () => {
    const id = 'idm+edm+ml';
    const got = await report({
      idm: [{}], edm: [{}],
      ml: { status: 'ok', modelVersion: 'V6.2.01', labelId: 'NUC', confidence: 0.997, sensitive: true },
    });
    assert(got === id, `expected ${id}, got ${JSON.stringify(got)} (length ${got && got.length})`);
    return `${id} (${id.length} chars) stored intact`;
  });

  await check('E04', 'a non-hit ml block never adds to detection_type', async () => {
    // status != ok, or sensitive false, is not a hit. ML can only ADD sensitivity;
    // it must never invent one, and it must never downgrade a fingerprint hit.
    const cases = [
      [{ status: 'unavailable', reason: 'model_not_loaded', sensitive: false }, null],
      [{ status: 'skipped', reason: 'read_path_skip', sensitive: false }, null],
      [{ status: 'empty', reason: 'no_text', sensitive: false }, null],
      [{ status: 'ok', labelId: 'PUB', confidence: 0.99, sensitive: false }, null],
      // A fingerprint hit stands on its own regardless of what ML said.
      [{ status: 'unavailable', reason: 'load_failed', sensitive: false }, 'idm+edm', true],
    ];
    for (const [ml, expect, withFp] of cases) {
      const got = await report({ idm: withFp ? [{}] : [], edm: withFp ? [{}] : [], ml });
      assert(got === expect, `ml.status=${ml.status} sensitive=${ml.sensitive}: expected ${expect}, got ${got}`);
    }
    return 'unavailable / skipped / empty / sensitive:false contribute nothing';
  });

  await check('E05', 'the ml block persists verbatim in verdict_json (metadata only)', async () => {
    const ml = { status: 'ok', modelVersion: 'V6.2.01', labelId: 'FIN', labelName: 'Finance',
                 confidence: 0.9981, sensitive: true, chunks: 1, tokens: 24, reason: null };
    const res = await request({
      pathname: '/agent/incidents', method: 'POST', ...agentTls,
      body: { channel: 'usb', verdict: { idm: [], edm: [], ml }, fileName: `${TAG}.docx` },
    });
    assert(res.status === 201, `expected 201, got ${res.status}`);
    const { rows } = await pool.query(
      'select verdict_json from detection_incidents where id = $1', [res.body.id]);
    const stored = rows[0].verdict_json.ml;
    // Field-by-field, not JSON.stringify: JSONB normalises object KEY ORDER
    // (shortest key first, then bytewise), so the serialised text legitimately
    // differs while every value is preserved.
    assert(Object.keys(stored).sort().join() === Object.keys(ml).sort().join(),
      `key set changed: ${Object.keys(stored).sort().join()}`);
    for (const [k, v] of Object.entries(ml)) {
      assert(stored[k] === v, `ml.${k}: stored ${JSON.stringify(stored[k])} != sent ${JSON.stringify(v)}`);
    }
    return 'JSONB preserved every field of the additive ml block';
  });

  // ============ F. Invariant ============
  await check('F01', 'audit hash-chain intact after all operations', async () => {
    const broken = await verifyChain();
    assert(broken === null, `chain broken at seq ${broken}`);
    return 'AUDIT CHAIN INTACT';
  });

  await cleanup(true);
  await new Promise((r) => adminServer.close(r));
  await new Promise((r) => mtlsServer.close(r));

  console.log(`\n${passed} passed, ${failed} failed, ${results.length} total\n`);
  fs.writeFileSync(
    path.join(__dirname, '.mlPolicy-results.json'),
    JSON.stringify({ generatedAt: new Date().toISOString(), passed, failed, results }, null, 2)
  );
  await pool.end();
  process.exit(failed === 0 ? 0 : 1);
}

main().catch(async (err) => {
  console.error(err);
  try { await cleanup(true); } catch { /* ignore */ }
  try { if (adminServer) adminServer.close(); } catch { /* ignore */ }
  try { if (mtlsServer) mtlsServer.close(); } catch { /* ignore */ }
  try { await pool.end(); } catch { /* already closing */ }
  process.exit(1);
});
