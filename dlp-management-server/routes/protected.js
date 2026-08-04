'use strict';
// Protected-document registry API (console side). Registers the classified
// documents the DLP agents must recognise (IDM fingerprinting pipeline).
// Two gates on every route: requireAuth (authN 401), then
// requirePermission (authZ 403, denials audited). Writes are policy_author
// only ('protect:write'); reads are open to all four roles ('protect:read').
// Document CONTENT is never logged, never audited, never returned by these
// routes — it goes straight into the encrypted blob store.
const crypto = require('crypto');
const path = require('path');
const express = require('express');
const pool = require('../db/pool');
const { audit } = require('../lib/audit');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../lib/rbac');
const { isUuid } = require('../lib/enrollmentTokens');
const { putBlob } = require('../lib/blobStore');
const { FIELD_TYPES } = require('../lib/edm');

const router = express.Router();
router.use(requireAuth);

// express.raw() does not exist in Express ~4.16 (added in 4.17) — collect the
// raw document bytes ourselves, bounded. If an upstream parser (express.json)
// already consumed the body, fall through: the handler's Buffer.isBuffer
// check turns that into the same 400 as any other non-binary body.
const MAX_DOCUMENT_BYTES = 100 * 1024 * 1024;
function rawBody(req, res, next) {
  if (req._body || req.readableEnded) return next();
  const chunks = [];
  let size = 0;
  let done = false;
  req.on('data', (chunk) => {
    if (done) return;
    size += chunk.length;
    if (size > MAX_DOCUMENT_BYTES) {
      done = true;
      res.status(413).json({ error: 'document too large' });
      req.destroy();
      return;
    }
    chunks.push(chunk);
  });
  req.on('end', () => {
    if (done) return;
    done = true;
    req.body = Buffer.concat(chunks);
    next();
  });
  req.on('error', (err) => {
    if (done) return;
    done = true;
    next(err);
  });
}

// POST /api/protected/collections  { name, classification, description? }
router.post('/collections', requirePermission('protect:write'), async (req, res, next) => {
  try {
    const body = req.body || {};
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    const classification =
      typeof body.classification === 'string' ? body.classification.trim() : '';
    const description = typeof body.description === 'string' ? body.description.trim() : '';
    if (!name) return res.status(400).json({ error: 'name is required' });
    if (!classification) return res.status(400).json({ error: 'classification is required' });

    let row;
    try {
      const { rows } = await pool.query(
        `insert into protected_collections (name, classification, description, created_by)
         values ($1, $2, $3, $4)
         returning id, name, classification, description, created_at`,
        [name, classification, description, req.user.id]
      );
      row = rows[0];
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ error: 'a collection with that name already exists' });
      }
      throw err;
    }
    await audit(req.user.email, 'protected_collection.create', row.id, {
      name: row.name,
      classification: row.classification,
    });
    res.status(201).json(row);
  } catch (err) {
    next(err);
  }
});

// GET /api/protected/collections — list with document counts + status rollup
router.get('/collections', requirePermission('protect:read'), async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `select c.id, c.name, c.classification, c.description, c.created_at,
              count(d.id)::int as document_count,
              count(d.id) filter (where d.status = 'pending')::int as pending_count,
              count(d.id) filter (where d.status in ('extracting', 'fingerprinting'))::int
                as processing_count,
              count(d.id) filter (where d.status = 'ready')::int as ready_count,
              count(d.id) filter (where d.status = 'failed')::int as failed_count
         from protected_collections c
         left join protected_documents d on d.collection_id = c.id
        group by c.id
        order by c.name`
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// POST /api/protected/documents?collectionId=<uuid>&title=<text>
// Raw binary body (the document itself, up to 100mb). Original filename in the
// X-Filename header (basename only is kept — clients cannot choose paths).
// Re-registering an existing title in the same collection creates a NEW
// version of that document and re-queues fingerprinting.
router.post(
  '/documents',
  requirePermission('protect:write'),
  rawBody,
  async (req, res, next) => {
    try {
      const collectionId = req.query.collectionId;
      const title = typeof req.query.title === 'string' ? req.query.title.trim() : '';
      if (!collectionId || !isUuid(collectionId)) {
        return res.status(400).json({ error: 'collectionId query parameter must be a uuid' });
      }
      if (!title) return res.status(400).json({ error: 'title query parameter is required' });
      if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
        return res.status(400).json({ error: 'request body must be the raw document bytes' });
      }

      // Keep only the basename — never trust client-supplied paths.
      const rawFilename = req.get('x-filename') || '';
      const originalFilename = rawFilename ? path.win32.basename(rawFilename.trim()) : null;
      const mime = req.get('content-type') || null;

      const collection = await pool.query('select id from protected_collections where id = $1', [
        collectionId,
      ]);
      if (collection.rows.length === 0) {
        return res.status(404).json({ error: 'collection not found' });
      }

      // Encrypt-and-store first (blobStore has no transaction hook); a rollback
      // below at worst orphans one blob file, never leaks plaintext.
      const blob = await putBlob(req.body);

      const client = await pool.connect();
      let documentId;
      let versionId;
      let versionNo;
      try {
        await client.query('begin');
        // Same title in the same collection = a new version of that document.
        // Lock the document row so concurrent uploads cannot race version_no.
        const existing = await client.query(
          `select id from protected_documents
            where collection_id = $1 and title = $2
            for update`,
          [collectionId, title]
        );
        if (existing.rows.length > 0) {
          documentId = existing.rows[0].id;
          const next = await client.query(
            `select coalesce(max(version_no), 0) + 1 as version_no
               from document_versions where document_id = $1`,
            [documentId]
          );
          versionNo = next.rows[0].version_no;
          await client.query(
            `update protected_documents
                set status = 'pending', failure_reason = null
              where id = $1`,
            [documentId]
          );
        } else {
          const created = await client.query(
            `insert into protected_documents (collection_id, title, status, created_by)
             values ($1, $2, 'pending', $3)
             returning id`,
            [collectionId, title, req.user.id]
          );
          documentId = created.rows[0].id;
          versionNo = 1;
        }
        const version = await client.query(
          `insert into document_versions
             (document_id, version_no, blob_ref, sha256, size_bytes, mime,
              original_filename, registered_by)
           values ($1, $2, $3, $4, $5, $6, $7, $8)
           returning id`,
          [
            documentId,
            versionNo,
            blob.ref,
            blob.sha256,
            blob.sizeBytes,
            mime,
            originalFilename,
            req.user.id,
          ]
        );
        versionId = version.rows[0].id;
        await client.query(
          `insert into processing_jobs (kind, ref_id) values ('fingerprint_document', $1)`,
          [versionId]
        );
        await client.query('commit');
      } catch (err) {
        await client.query('rollback').catch(() => {});
        throw err;
      } finally {
        client.release();
      }

      // Audit records metadata only — never the document content.
      await audit(req.user.email, 'protected_document.register', documentId, {
        title,
        version: versionNo,
        collectionId,
        sizeBytes: blob.sizeBytes,
      });
      res.status(202).json({ documentId, versionId, status: 'pending' });
    } catch (err) {
      next(err);
    }
  }
);

// GET /api/protected/documents?collectionId=<uuid> — registry list (metadata only)
router.get('/documents', requirePermission('protect:read'), async (req, res, next) => {
  try {
    const collectionId = req.query.collectionId;
    if (collectionId && !isUuid(collectionId)) {
      return res.status(400).json({ error: 'collectionId must be a uuid' });
    }
    const params = [];
    let where = '';
    if (collectionId) {
      params.push(collectionId);
      where = 'where d.collection_id = $1';
    }
    const { rows } = await pool.query(
      `select d.id, d.collection_id, d.title, d.status, d.failure_reason,
              d.current_version, d.created_at,
              coalesce(fc.fingerprint_count, 0) as fingerprint_count
         from protected_documents d
         left join lateral (
           select count(*)::int as fingerprint_count
             from document_fingerprints f
             join document_versions v on v.id = f.version_id
            where v.document_id = d.id and v.version_no = d.current_version
         ) fc on true
         ${where}
        order by d.created_at desc`,
      params
    );
    res.json(rows);
  } catch (err) {
    next(err);
  }
});

// GET /api/protected/documents/:id — detail including version history
router.get('/documents/:id', requirePermission('protect:read'), async (req, res, next) => {
  try {
    if (!isUuid(req.params.id)) return res.status(404).json({ error: 'document not found' });
    const doc = await pool.query(
      `select d.id, d.collection_id, c.name as collection_name,
              c.classification, d.title, d.status, d.failure_reason,
              d.current_version, d.created_at
         from protected_documents d
         join protected_collections c on c.id = d.collection_id
        where d.id = $1`,
      [req.params.id]
    );
    if (doc.rows.length === 0) return res.status(404).json({ error: 'document not found' });
    const versions = await pool.query(
      `select v.id, v.version_no, v.sha256, v.size_bytes, v.mime,
              v.original_filename, v.registered_at, v.retired_at,
              (select count(*)::int from document_fingerprints f
                where f.version_id = v.id) as fingerprint_count
         from document_versions v
        where v.document_id = $1
        order by v.version_no desc`,
      [req.params.id]
    );
    res.json({ ...doc.rows[0], versions: versions.rows });
  } catch (err) {
    next(err);
  }
});

// =====================================================================
// EDM sources — exact data match (fingerprinting doc §4). A source is a
// structured export (personnel, payroll…) whose CELL VALUES are the
// sensitive material: only salted hashes are ever stored long-term, and
// the salt is never returned by any API. Audit entries carry counts and
// sizes only — NEVER cell values.
// =====================================================================

// POST /api/protected/edm-sources  { name, schema: [{name, type, primary}] }
router.post('/edm-sources', requirePermission('protect:write'), async (req, res, next) => {
  try {
    const body = req.body || {};
    const name = typeof body.name === 'string' ? body.name.trim() : '';
    if (!name) return res.status(400).json({ error: 'name is required' });
    const schema = body.schema;
    if (!Array.isArray(schema) || schema.length === 0) {
      return res.status(400).json({ error: 'schema must be a non-empty array of fields' });
    }
    const seen = new Set();
    const fields = [];
    for (const f of schema) {
      const fieldName = f && typeof f.name === 'string' ? f.name.trim() : '';
      if (!fieldName) return res.status(400).json({ error: 'every field needs a name' });
      const key = fieldName.toLowerCase();
      if (seen.has(key)) {
        return res.status(400).json({ error: `duplicate field name: ${fieldName}` });
      }
      seen.add(key);
      if (!FIELD_TYPES.includes(f.type)) {
        return res.status(400).json({
          error: `field ${fieldName}: type must be one of ${FIELD_TYPES.join(', ')}`,
        });
      }
      fields.push({ name: fieldName, type: f.type, primary: f.primary === true });
    }
    if (!fields.some((f) => f.primary)) {
      return res.status(400).json({ error: 'at least one field must be primary' });
    }

    // Per-source hashing salt — generated here, stored, never returned.
    const saltHex = crypto.randomBytes(32).toString('hex');
    let row;
    try {
      const { rows } = await pool.query(
        `insert into edm_sources (name, schema_json, salt_hex, created_by)
         values ($1, $2, $3, $4)
         returning id, name, schema_json, row_count, status, created_at`,
        [name, JSON.stringify(fields), saltHex, req.user.id]
      );
      row = rows[0];
    } catch (err) {
      if (err.code === '23505') {
        return res.status(409).json({ error: 'an EDM source with that name already exists' });
      }
      throw err;
    }
    await audit(req.user.email, 'edm_source.create', row.id, {
      name: row.name,
      fieldCount: fields.length,
      primaryFields: fields.filter((f) => f.primary).length,
    });
    res.status(201).json({
      id: row.id,
      name: row.name,
      schema: row.schema_json,
      row_count: row.row_count,
      status: row.status,
      created_at: row.created_at,
    });
  } catch (err) {
    next(err);
  }
});

// PUT /api/protected/edm-sources/:id/data — raw CSV body (the dataset export).
// The upload is held encrypted in the blob store only until the worker has
// hashed it; ingestion then DELETES the blob (plaintext is not retained).
router.put(
  '/edm-sources/:id/data',
  requirePermission('protect:write'),
  rawBody,
  async (req, res, next) => {
    try {
      if (!isUuid(req.params.id)) {
        return res.status(404).json({ error: 'edm source not found' });
      }
      if (!Buffer.isBuffer(req.body) || req.body.length === 0) {
        return res.status(400).json({ error: 'request body must be the raw csv bytes' });
      }
      const source = await pool.query('select id, status from edm_sources where id = $1', [
        req.params.id,
      ]);
      if (source.rows.length === 0) {
        return res.status(404).json({ error: 'edm source not found' });
      }
      if (source.rows[0].status === 'ingesting') {
        return res.status(409).json({ error: 'an ingestion is already in progress for this source' });
      }

      // Encrypt-and-store first (same rationale as document registration);
      // a rollback below at worst orphans one blob, never leaks plaintext.
      const blob = await putBlob(req.body);

      const client = await pool.connect();
      try {
        await client.query('begin');
        await client.query(
          `update edm_sources
              set status = 'ingesting', failure_reason = null, temp_blob_ref = $2
            where id = $1`,
          [req.params.id, blob.ref]
        );
        await client.query(
          `insert into processing_jobs (kind, ref_id) values ('ingest_edm_source', $1)`,
          [req.params.id]
        );
        await client.query('commit');
      } catch (err) {
        await client.query('rollback').catch(() => {});
        throw err;
      } finally {
        client.release();
      }

      // Size only — never row contents.
      await audit(req.user.email, 'edm_source.ingest', req.params.id, {
        sizeBytes: blob.sizeBytes,
      });
      res.status(202).json({ id: req.params.id, status: 'ingesting' });
    } catch (err) {
      next(err);
    }
  }
);

// GET /api/protected/edm-sources — list (metadata only: never the salt,
// never temp blob refs, never hashes).
router.get('/edm-sources', requirePermission('protect:read'), async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `select id, name, schema_json, row_count, status, failure_reason, created_at
         from edm_sources
        order by name`
    );
    res.json(
      rows.map((r) => ({
        id: r.id,
        name: r.name,
        fields: r.schema_json.map((f) => ({ name: f.name, type: f.type, primary: f.primary })),
        row_count: r.row_count,
        status: r.status,
        failure_reason: r.failure_reason,
        created_at: r.created_at,
      }))
    );
  } catch (err) {
    next(err);
  }
});

// =====================================================================
// Index compilation — packages every 'ready' document/EDM source into a
// signed bundle (lib/indexBundle.js) that agents download over mTLS.
// The compile itself runs in the worker (it can take a while on large
// registries); this route only queues the job.
// =====================================================================

// GET /api/protected/index — last compiled bundle + how much ready content has
// been registered since, so the console can prompt for a recompile. "Pending"
// is ready content whose current version was registered after the last bundle
// was built (or all ready content, if nothing has ever been compiled). Note:
// registered_at is upload time, not fingerprint-completion time — a document
// that was still processing during a compile is a rare edge the operator will
// catch on the next registration anyway.
router.get('/index', requirePermission('protect:read'), async (req, res, next) => {
  try {
    const bundle = await pool.query(
      `select version, built_at, size_bytes from index_bundles order by version desc limit 1`
    );
    const last = bundle.rows[0] || null;
    const since = last ? last.built_at : null;

    const docs = await pool.query(
      `select
         count(*) filter (where d.status = 'ready')::int as ready,
         count(*) filter (
           where d.status = 'ready' and ($1::timestamptz is null or v.registered_at > $1)
         )::int as pending
       from protected_documents d
       join document_versions v
         on v.document_id = d.id and v.version_no = d.current_version`,
      [since]
    );

    let edm = { rows: [{ ready: 0, pending: 0 }] };
    try {
      edm = await pool.query(
        `select
           count(*) filter (where status = 'ready')::int as ready,
           count(*) filter (
             where status = 'ready' and ($1::timestamptz is null or created_at > $1)
           )::int as pending
         from edm_sources`,
        [since]
      );
    } catch (e) {
      // edm_sources may not exist on older schemas — ignore, report zeros.
    }

    const pending = docs.rows[0].pending + edm.rows[0].pending;
    res.json({
      lastCompiled: last
        ? { version: last.version, builtAt: last.built_at, sizeBytes: Number(last.size_bytes) }
        : null,
      readyDocuments: docs.rows[0].ready,
      pendingDocuments: docs.rows[0].pending,
      readyEdmSources: edm.rows[0].ready,
      pendingEdmSources: edm.rows[0].pending,
      needsCompile: pending > 0,
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/protected/index/compile — queue a compile_index job.
router.post('/index/compile', requirePermission('protect:write'), async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `insert into processing_jobs (kind) values ('compile_index') returning id`
    );
    await audit(req.user.email, 'index_bundle.compile', rows[0].id, {});
    res.status(202).json({ jobId: rows[0].id, status: 'queued' });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
