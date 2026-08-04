#!/usr/bin/env node
'use strict';
// Background worker for the protected-document ingest pipeline.
// Polls processing_jobs (a minimal DB-backed queue) and runs
// 'fingerprint_document' jobs: decrypt blob → extract text → fingerprint →
// store hashes. Multiple workers are safe: jobs are claimed with
// FOR UPDATE SKIP LOCKED.
//
//   npm run worker            — poll forever (2s idle interval)
//   npm run worker -- --once  — drain currently-eligible jobs, then exit
//
// Logs carry ids + status only — never document content, text, or filenames.
require('dotenv').config();
const pool = require('../db/pool');
const { getBlob, deleteBlob } = require('../lib/blobStore');
const { extractText } = require('../lib/extractText');
const { fingerprint } = require('../lib/fingerprint');
const { ingestCsv } = require('../lib/edm');
const { compileBundle } = require('../lib/indexBundle');

const POLL_INTERVAL_MS = 2000;
const MAX_ATTEMPTS = 3;
const FINGERPRINT_BATCH_SIZE = 1000; // rows per multi-row INSERT (3 params each)

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Claim exactly one eligible job (queued, due) and mark it running, in its
// own transaction so concurrent workers skip each other's claims.
async function claimJob() {
  const client = await pool.connect();
  try {
    await client.query('begin');
    const { rows } = await client.query(
      `select id, kind, ref_id, attempts
         from processing_jobs
        where state = 'queued' and run_after <= now()
        order by created_at, id
        limit 1
        for update skip locked`
    );
    if (rows.length === 0) {
      await client.query('commit');
      return null;
    }
    await client.query(`update processing_jobs set state = 'running' where id = $1`, [
      rows[0].id,
    ]);
    await client.query('commit');
    return rows[0];
  } catch (err) {
    await client.query('rollback').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

async function setDocumentStatus(documentId, status) {
  await pool.query(`update protected_documents set status = $2 where id = $1`, [
    documentId,
    status,
  ]);
}

// fingerprint_document: ref_id is a document_versions.id.
// Returns { documentId, fingerprintCount }.
async function processFingerprintDocument(job) {
  const { rows } = await pool.query(
    `select id, document_id, version_no, blob_ref, original_filename
       from document_versions
      where id = $1`,
    [job.ref_id]
  );
  if (rows.length === 0) {
    const err = new Error('version not found');
    err.permanent = true;
    throw err;
  }
  const version = rows[0];
  const documentId = version.document_id;

  try {
    await setDocumentStatus(documentId, 'extracting');
    const plaintext = await getBlob(version.blob_ref);
    const { text } = await extractText(plaintext, version.original_filename || 'document.txt');

    await setDocumentStatus(documentId, 'fingerprinting');
    const { fingerprints } = fingerprint(text);

    // Replace this version's hashes and mark the document ready, atomically.
    const client = await pool.connect();
    try {
      await client.query('begin');
      await client.query('delete from document_fingerprints where version_id = $1', [
        version.id,
      ]);
      for (let i = 0; i < fingerprints.length; i += FINGERPRINT_BATCH_SIZE) {
        const batch = fingerprints.slice(i, i + FINGERPRINT_BATCH_SIZE);
        const values = [];
        const params = [];
        for (let j = 0; j < batch.length; j++) {
          const base = j * 3;
          values.push(`($${base + 1}, $${base + 2}, $${base + 3})`);
          // pg carries BIGINT as strings; hashes are signed 64-bit BigInts.
          params.push(version.id, batch[j].hash.toString(), batch[j].seq);
        }
        await client.query(
          `insert into document_fingerprints (version_id, hash, seq) values ${values.join(', ')}`,
          params
        );
      }
      await client.query(
        `update protected_documents
            set status = 'ready', failure_reason = null, current_version = $2
          where id = $1`,
        [documentId, version.version_no]
      );
      await client.query('commit');
    } catch (err) {
      await client.query('rollback').catch(() => {});
      throw err;
    } finally {
      client.release();
    }
    return { documentId, fingerprintCount: fingerprints.length };
  } catch (err) {
    err.documentId = documentId;
    throw err;
  }
}

// ingest_edm_source: ref_id is an edm_sources.id. Decrypt the temporary
// CSV upload → typed-normalize + salt-hash every non-empty cell → replace
// the source's hash rows → DELETE the upload blob (the doc's contract:
// plaintext exports are NOT retained once the hashes exist).
// Returns { sourceId, rowCount, hashCount }.
const EDM_BATCH_SIZE = 1000; // rows per multi-row INSERT (4 params each)

async function processIngestEdmSource(job) {
  const { rows } = await pool.query(
    `select id, schema_json, salt_hex, temp_blob_ref from edm_sources where id = $1`,
    [job.ref_id]
  );
  if (rows.length === 0) {
    const err = new Error('edm source not found');
    err.permanent = true;
    throw err;
  }
  const source = rows[0];

  try {
    if (!source.temp_blob_ref) {
      const err = new Error('no pending upload for edm source');
      err.permanent = true;
      throw err;
    }
    const csvText = (await getBlob(source.temp_blob_ref)).toString('utf8');
    const salt = Buffer.from(source.salt_hex, 'hex');
    // ingestCsv throws with err.permanent + err.reason (a code, never cell
    // content) on malformed exports — bad data will not fix itself on retry.
    const { entries, rowCount } = ingestCsv(csvText, source.schema_json, salt);

    // Replace this source's hashes and mark it ready, atomically. The
    // temp_blob_ref is nulled in the same transaction; the file itself is
    // unlinked right after commit (deletion is mandatory, see below).
    const client = await pool.connect();
    try {
      await client.query('begin');
      await client.query('delete from edm_hashes where source_id = $1', [source.id]);
      for (let i = 0; i < entries.length; i += EDM_BATCH_SIZE) {
        const batch = entries.slice(i, i + EDM_BATCH_SIZE);
        const values = [];
        const params = [];
        for (let j = 0; j < batch.length; j++) {
          const base = j * 4;
          values.push(`($${base + 1}, $${base + 2}, $${base + 3}, $${base + 4})`);
          // pg carries BIGINT as strings; hashes are signed 64-bit BigInts.
          params.push(source.id, batch[j].rowId, batch[j].fieldId, batch[j].hash.toString());
        }
        await client.query(
          `insert into edm_hashes (source_id, row_id, field_id, hash) values ${values.join(', ')}`,
          params
        );
      }
      await client.query(
        `update edm_sources
            set status = 'ready', failure_reason = null, row_count = $2, temp_blob_ref = null
          where id = $1`,
        [source.id, rowCount]
      );
      await client.query('commit');
    } catch (err) {
      await client.query('rollback').catch(() => {});
      throw err;
    } finally {
      client.release();
    }

    // Mandatory: the plaintext export must not be retained. deleteBlob is
    // idempotent (already-gone counts as deleted); any real unlink failure
    // fails the job so an operator sees the retention problem.
    try {
      await deleteBlob(source.temp_blob_ref);
    } catch (unlinkErr) {
      const err = new Error('edm upload blob could not be deleted');
      err.permanent = true;
      err.reason = 'blob-delete-failed';
      throw err;
    }
    return { sourceId: source.id, rowCount, hashCount: entries.length };
  } catch (err) {
    err.sourceId = source.id;
    throw err;
  }
}

async function markJobDone(jobId) {
  await pool.query(
    `update processing_jobs set state = 'done', finished_at = now() where id = $1`,
    [jobId]
  );
}

// Failure: retry with linear backoff (10s * attempts) up to MAX_ATTEMPTS,
// then fail the job and the document. failure_reason carries the reason code
// only (e.g. 'no-text-layer') — never content.
async function markJobFailed(job, err) {
  const attempts = job.attempts + 1;
  const reason =
    err && (err.unreadable || err.reason)
      ? err.reason
      : String((err && err.message) || 'error');
  const lastError = reason.slice(0, 500);
  const permanent = Boolean(err && err.permanent);

  if (!permanent && attempts < MAX_ATTEMPTS) {
    await pool.query(
      `update processing_jobs
          set state = 'queued', attempts = $2, last_error = $3,
              run_after = now() + interval '10 seconds' * $2::int
        where id = $1`,
      [job.id, attempts, lastError]
    );
    return { status: 'requeued', attempts };
  }
  await pool.query(
    `update processing_jobs
        set state = 'failed', attempts = $2, last_error = $3, finished_at = now()
      where id = $1`,
    [job.id, attempts, lastError]
  );
  if (err && err.documentId) {
    await pool.query(
      `update protected_documents set status = 'failed', failure_reason = $2 where id = $1`,
      [err.documentId, lastError]
    );
  }
  if (err && err.sourceId) {
    await pool.query(
      `update edm_sources set status = 'failed', failure_reason = $2 where id = $1`,
      [err.sourceId, lastError]
    );
  }
  return { status: 'failed', attempts };
}

async function runJob(job) {
  try {
    let summary;
    if (job.kind === 'fingerprint_document') {
      const result = await processFingerprintDocument(job);
      summary = `${result.fingerprintCount} fingerprints`;
    } else if (job.kind === 'ingest_edm_source') {
      const result = await processIngestEdmSource(job);
      summary = `${result.rowCount} rows, ${result.hashCount} hashes`;
    } else if (job.kind === 'compile_index') {
      // compile_index: no ref_id — compiles everything currently 'ready'
      // into the next signed bundle version (lib/indexBundle.js).
      const result = await compileBundle();
      summary =
        `bundle v${result.version}: ${result.counts.docs} docs, ` +
        `${result.counts.idm} idm, ${result.counts.edm} edm hashes`;
    } else {
      const err = new Error(`unknown job kind: ${job.kind}`);
      err.permanent = true;
      throw err;
    }
    await markJobDone(job.id);
    console.log(`[worker] job ${job.id} ${job.kind} ${job.ref_id} -> done (${summary})`);
  } catch (err) {
    try {
      const outcome = await markJobFailed(job, err);
      console.log(
        `[worker] job ${job.id} ${job.kind} ${job.ref_id} -> ${outcome.status} ` +
          `(attempt ${outcome.attempts}: ${err.unreadable || err.reason ? err.reason : err.message})`
      );
    } catch (dbErr) {
      // Could not record the failure (e.g. DB down) — leave the job 'running';
      // it needs operator attention rather than silent loss.
      console.error(`[worker] job ${job.id} failed and could not be recorded:`, dbErr.message);
    }
  }
}

async function main() {
  const once = process.argv.includes('--once');
  console.log(`[worker] fingerprint worker started${once ? ' (--once)' : ''}`);
  let stopping = false;
  const stop = () => {
    stopping = true;
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);

  while (!stopping) {
    let job = null;
    try {
      job = await claimJob();
    } catch (err) {
      console.error('[worker] claim failed:', err.message);
    }
    if (!job) {
      if (once) break;
      await sleep(POLL_INTERVAL_MS);
      continue;
    }
    await runJob(job);
  }
  await pool.end();
  console.log('[worker] stopped');
}

main().catch((err) => {
  console.error('[worker] fatal:', err);
  process.exit(1);
});
