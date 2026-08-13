'use strict';
// Demo provisioning for the USB IDM+EDM kernel-block demo. Uses the server's
// own libs + the real worker pipeline (no password needed): ensures a personnel
// EDM source is ingested, compiles a fresh signed bundle (OPORD IDM + Personnel
// EDM), and mints an enrollment token. Prints everything the VM agent needs.
require('dotenv').config();
const crypto = require('crypto');
const { execSync } = require('child_process');
const path = require('path');
const pool = require('../db/pool');
const { putBlob } = require('../lib/blobStore');
const { createToken } = require('../lib/enrollmentTokens');

const PERSONNEL_CSV = [
  'full_name,service_no,unit',
  'Rajesh Sharma,SVC100001,Leh Sector',
  'Priya Nair,SVC100002,Northern Command',
  'Arun Mehta,SVC100003,Leh Sector',
  'Vikram Singh,SVC100004,Eastern Command',
  'Anjali Rao,SVC100005,Leh Sector',
].join('\n');

const SCHEMA = [
  { name: 'full_name', type: 'text', primary: true },
  { name: 'service_no', type: 'id', primary: true },
  { name: 'unit', type: 'text', primary: false },
];

function runWorkerOnce() {
  execSync('node bin/fingerprint-worker.js --once', {
    cwd: path.join(__dirname, '..'),
    stdio: 'inherit',
  });
}

(async () => {
  // 1. policy_author identity for created_by (read-only lookup).
  const author = await pool.query(
    `select u.id, u.email from admin_users u
       join user_roles ur on ur.user_id = u.id
       join roles r on r.id = ur.role_id
      where r.name = 'policy_author' order by u.email limit 1`
  );
  if (author.rows.length === 0) throw new Error('no policy_author account found');
  const createdBy = author.rows[0].id;
  console.log(`provisioning as policy_author ${author.rows[0].email}`);

  // 2. Ensure the Personnel EDM source exists + is ingested.
  let src = await pool.query(`select id, status from edm_sources where name = 'Demo Personnel'`);
  if (src.rows.length === 0) {
    const saltHex = crypto.randomBytes(32).toString('hex');
    const ins = await pool.query(
      `insert into edm_sources (name, schema_json, salt_hex, created_by)
       values ($1, $2, $3, $4) returning id`,
      ['Demo Personnel', JSON.stringify(SCHEMA), saltHex, createdBy]
    );
    src = { rows: [{ id: ins.rows[0].id, status: 'empty' }] };
    console.log('created EDM source "Demo Personnel"');
  }
  const sourceId = src.rows[0].id;

  const ready = await pool.query(`select status, row_count from edm_sources where id = $1`, [sourceId]);
  if (ready.rows[0].status !== 'ready') {
    const blob = await putBlob(Buffer.from(PERSONNEL_CSV, 'utf8'));
    await pool.query(
      `update edm_sources set status='ingesting', failure_reason=null, temp_blob_ref=$2 where id=$1`,
      [sourceId, blob.ref]
    );
    await pool.query(`insert into processing_jobs (kind, ref_id) values ('ingest_edm_source', $1)`, [sourceId]);
    console.log('queued EDM ingest — running worker...');
    runWorkerOnce();
  }

  // 3. Compile a fresh bundle (OPORD IDM + Personnel EDM).
  await pool.query(`insert into processing_jobs (kind) values ('compile_index')`);
  console.log('queued compile_index — running worker...');
  runWorkerOnce();

  // 4. Mint an enrollment token for the VM agent.
  const token = await createToken({
    description: 'VM USB kernel-block demo',
    maxUses: 3,
    expiresInHours: 72,
    createdBy,
  });

  // 5. Report everything the VM needs.
  const bundle = await pool.query(`select version, built_at from index_bundles order by version desc limit 1`);
  const edm = await pool.query(`select name, status, row_count from edm_sources where id=$1`, [sourceId]);
  const doc = await pool.query(`select title, status from protected_documents order by created_at desc limit 1`);
  const caPath = path.resolve(__dirname, '..', 'ca', 'ca-cert.pem');

  console.log('\n============ DEMO READY ============');
  console.log('IDM document :', doc.rows[0].title, `(${doc.rows[0].status})`);
  console.log('EDM source   :', edm.rows[0].name, `(${edm.rows[0].status}, ${edm.rows[0].row_count} rows)`);
  console.log('Bundle       : v' + bundle.rows[0].version, 'built', bundle.rows[0].built_at);
  console.log('CA cert      :', caPath);
  console.log('Server (mTLS): https://<SERVER-HOST>:8443   (agent-server)');
  console.log('Console      : http://<SERVER-HOST>:3001    (npm start)');
  console.log('\nENROLLMENT TOKEN (one of 3 uses, 72h):');
  console.log('  ' + token.token);
  console.log('\nEDM test line: "Name: Priya Nair, Service No: SVC100002"');
  console.log('====================================\n');

  await pool.end();
})().catch((e) => { console.error('PROVISION FAILED:', e.message); process.exit(1); });
