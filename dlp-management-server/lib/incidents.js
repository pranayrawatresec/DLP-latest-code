'use strict';
// =====================================================================
// Incident resolution (server half of Step 6). Agents report a compact
// verdict — bundle hash matches, never captured content. Resolution turns
// those raw hashes back into something a reviewer can act on: which
// protected documents, WHERE in each document (matched fingerprint seq
// ranges), and how much of the document was seen (containment).
//
// Resolution is lazy: it runs on the first console read of an incident and
// the result is stored in detection_incidents.resolved_json, so the
// agent-facing insert path stays a cheap single INSERT.
//
// Expected verdict_json shape (produced by the agent's matcher):
//   {
//     "bundleVersion": 3,
//     "idm": [ { "versionId": "<uuid>", "matchedHashes": ["123", "-456"] } ],
//     "edm": [ { "sourceId": "<uuid>", "rowId": 12, "fieldIds": [0, 2] } ]
//   }
// Only idm entries are resolved here (seq ranges live server-side); edm
// entries are already row/field references and pass through as reported.
// =====================================================================
const pool = require('../db/pool');
const { containment } = require('./fingerprint');
const { isUuid } = require('./enrollmentTokens');

// Collapse a version's matched fingerprints into ranges. `allRows` is the
// version's fingerprints ordered by seq; a range is a maximal run of
// CONSECUTIVE stored fingerprints (adjacent rows in seq order) whose hash
// is in `matchedSet` — i.e. a contiguous matched region of the document.
// Returns [[startSeq, endSeq], ...].
function collapseSeqRanges(allRows, matchedSet) {
  const ranges = [];
  let start = null;
  let last = null;
  for (const row of allRows) {
    if (matchedSet.has(String(row.hash))) {
      if (start === null) start = row.seq;
      last = row.seq;
    } else if (start !== null) {
      ranges.push([start, last]);
      start = null;
    }
  }
  if (start !== null) ranges.push([start, last]);
  return ranges;
}

// Resolve one idm verdict entry ({versionId, matchedHashes}) against the DB.
async function resolveIdmEntry(entry) {
  const versionId = entry && entry.versionId;
  const matched = Array.isArray(entry && entry.matchedHashes) ? entry.matchedHashes : [];
  if (!versionId || !isUuid(String(versionId))) {
    return { versionId: String(versionId || ''), error: 'invalid versionId' };
  }
  const version = await pool.query(
    `select v.id, v.document_id, d.title
       from document_versions v
       join protected_documents d on d.id = v.document_id
      where v.id = $1`,
    [versionId]
  );
  if (version.rows.length === 0) {
    return { versionId, error: 'version not found' };
  }
  const { document_id: documentId, title } = version.rows[0];

  const { rows: allRows } = await pool.query(
    `select seq, hash::text as hash
       from document_fingerprints where version_id = $1 order by seq`,
    [versionId]
  );

  // Everything is compared as decimal strings (the pg BIGINT wire form);
  // agent-reported hashes may arrive as strings or numbers.
  const matchedSet = new Set();
  for (const h of matched) {
    try {
      matchedSet.add(BigInt(h).toString());
    } catch {
      /* skip unparseable hash — never fail the whole resolution on junk */
    }
  }

  const docHashes = allRows.map((r) => r.hash);
  const seqRanges = collapseSeqRanges(allRows, matchedSet);
  const matchedCount = new Set(docHashes.filter((h) => matchedSet.has(h))).size;

  return {
    versionId,
    documentId,
    title,
    containment: containment(docHashes, [...matchedSet]),
    matchedCount,
    totalCount: new Set(docHashes).size,
    seqRanges,
  };
}

// Resolve an incident's verdict and persist resolved_json. Idempotent-ish:
// the caller only invokes this when resolved_json is still null; a
// concurrent double-resolve just writes the same result twice.
async function resolveIncident(incidentId) {
  const { rows } = await pool.query(
    'select id, verdict_json from detection_incidents where id = $1',
    [incidentId]
  );
  if (rows.length === 0) throw new Error('incident not found');
  const verdict = rows[0].verdict_json || {};

  const idm = [];
  if (Array.isArray(verdict.idm)) {
    for (const entry of verdict.idm) {
      idm.push(await resolveIdmEntry(entry));
    }
  }

  const resolved = {
    resolvedAt: new Date().toISOString(),
    idm,
    // edm verdicts already reference source/row/field — passed through.
    edm: Array.isArray(verdict.edm) ? verdict.edm : [],
  };
  await pool.query(
    'update detection_incidents set resolved_json = $2 where id = $1',
    [incidentId, JSON.stringify(resolved)]
  );
  return resolved;
}

module.exports = { resolveIncident, collapseSeqRanges };
