'use strict';
// =====================================================================
// Index bundle compiler (Step 4) — the signed, versioned artifact agents
// download over mTLS and match against locally. One bundle carries:
//
//   * every 'ready' protected document's CURRENT-version IDM fingerprints
//   * every 'ready' EDM source's salted cell hashes (plus the per-source
//     salts the agent needs to hash candidate cells — bundles are only
//     ever served to mTLS-authenticated agents)
//   * a bloom pre-filter over the union of all hashes, so the agent can
//     reject the overwhelmingly-common "no match" case in nanoseconds
//   * an RSA-SHA256 signature by the internal CA over everything above —
//     agents verify with the ca.pem they pinned at enrollment before
//     loading a single byte (a tampered bundle must fail closed).
//
// BYTE-EXACT FORMAT CONTRACT: docs/index-bundle-format.md is normative —
// the Rust loader is written from that file. Change nothing here without
// changing the format version and the doc together.
//
// All multi-byte integers are LITTLE-endian. Hashes are stored as SIGNED
// i64 (the BIGINT column convention) but compared/sorted as UNSIGNED u64
// (BigInt.asUintN) — same duality as lib/fingerprint.js.
// =====================================================================
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const pool = require('../db/pool');
const { signBuffer, verifyBufferSignature } = require('./ca');
const { DEFAULT_K, DEFAULT_W } = require('./fingerprint');

const MAGIC = Buffer.from('DLPX1', 'ascii');
const FORMAT_VERSION = 1;
const INDEX_DIR = path.join(__dirname, '..', 'data', 'index');

// Bloom tunables (builder-side; the loader always reads mBits/kHashes from
// the file). ~10 bits/entry with k=7 gives a ~1e-2..1e-3 false-positive
// rate; minimum 1024 bits so tiny bundles still get a real filter.
const BLOOM_BITS_PER_ENTRY = 10;
const BLOOM_K = 7;
const BLOOM_MIN_BITS = 1024;

const MASK_64 = 0xffffffffffffffffn;
const FNV_OFFSET_BASIS = 0xcbf29ce484222325n;
const FNV_PRIME = 0x100000001b3n;

// ---------------------------------------------------------------------
// u64 primitives (all wrapping — must mirror the Rust u64 math exactly)
// ---------------------------------------------------------------------

// Accepts a signed/unsigned BigInt or a decimal string (pg BIGINT form)
// and returns the unsigned-u64 view.
function toU64(hash) {
  return BigInt.asUintN(64, typeof hash === 'bigint' ? hash : BigInt(hash));
}

// The bloom membership KEY: the 8-byte little-endian encoding of the hash
// as unsigned u64.
function bloomKeyBytes(hash) {
  const b = Buffer.alloc(8);
  b.writeBigUInt64LE(toU64(hash), 0);
  return b;
}

// FNV-1a 64 over raw bytes (lib/fingerprint.js hashes strings; the bloom
// hashes the 8 key bytes — same constants).
function fnv1a64Bytes(buf) {
  let h = FNV_OFFSET_BASIS;
  for (let i = 0; i < buf.length; i++) {
    h ^= BigInt(buf[i]);
    h = (h * FNV_PRIME) & MASK_64;
  }
  return h; // unsigned u64
}

// splitmix64 finalizer (constants are part of the format contract).
function splitmix64(x) {
  let z = (BigInt.asUintN(64, x) + 0x9e3779b97f4a7c15n) & MASK_64;
  z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK_64;
  z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK_64;
  return z ^ (z >> 31n);
}

// Double hashing (Kirsch–Mitzenmacher): bit_i = (h1 + i*h2) mod mBits,
// with (h1 + i*h2) computed in wrapping u64 arithmetic first.
function bloomBitIndexes(hash, mBits, kHashes) {
  const key = bloomKeyBytes(hash);
  const h1 = fnv1a64Bytes(key);
  const h2 = splitmix64(h1);
  const m = BigInt(mBits);
  const out = [];
  for (let i = 0n; i < BigInt(kHashes); i++) {
    const t = (h1 + i * h2) & MASK_64;
    out.push(Number(t % m));
  }
  return out;
}

// Build the filter over a set of hashes. mBits = max(1024, 10*n) rounded
// UP to a multiple of 64 (builder convenience only — loaders trust the
// stored mBits). Bit i lives in byte i>>3 at mask 1<<(i&7) (LSB-first).
function buildBloom(hashes) {
  const distinct = new Set();
  for (const h of hashes) distinct.add(toU64(h));
  const n = distinct.size;
  let mBits = Math.max(BLOOM_MIN_BITS, n * BLOOM_BITS_PER_ENTRY);
  mBits = Math.ceil(mBits / 64) * 64;
  const bits = Buffer.alloc(Math.ceil(mBits / 8));
  for (const h of distinct) {
    for (const idx of bloomBitIndexes(h, mBits, BLOOM_K)) {
      bits[idx >> 3] |= 1 << (idx & 7);
    }
  }
  return { mBits, kHashes: BLOOM_K, bits };
}

function bloomHas(bloom, hash) {
  for (const idx of bloomBitIndexes(hash, bloom.mBits, bloom.kHashes)) {
    if ((bloom.bits[idx >> 3] & (1 << (idx & 7))) === 0) return false;
  }
  return true;
}

// ---------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------
function u16le(v) {
  const b = Buffer.alloc(2);
  b.writeUInt16LE(v, 0);
  return b;
}
function u32le(v) {
  const b = Buffer.alloc(4);
  b.writeUInt32LE(v, 0);
  return b;
}
function i64le(hash) {
  const b = Buffer.alloc(8);
  b.writeBigInt64LE(BigInt.asIntN(64, typeof hash === 'bigint' ? hash : BigInt(hash)), 0);
  return b;
}

// Compare two hashes as unsigned u64 (the sort order of both sections).
function cmpU64(a, b) {
  const ua = toU64(a);
  const ub = toU64(b);
  return ua < ub ? -1 : ua > ub ? 1 : 0;
}

// Build a bundle from in-memory data. `data`:
//   { bundleVersion, params: {k,w,hashBits}, scope: [collectionIds],
//     docs: [{versionId, documentId, collectionId, title, fpCount}],
//     edmSources: [{sourceId, name, fields:[{fieldId,name,type,primary}]}],
//     edmSalts: {sourceId: saltHex},
//     idmEntries: [{hash, docIndex}],
//     edmEntries: [{hash, sourceIndex, rowId, fieldId}] }
// Returns the full signed bundle Buffer; { sign: false } returns just the
// unsigned prefix (everything the signature covers) — used by tests.
function buildBundle(data, { sign = true } = {}) {
  const idm = [...data.idmEntries].sort(
    (a, b) => cmpU64(a.hash, b.hash) || a.docIndex - b.docIndex
  );
  const edm = [...data.edmEntries].sort(
    (a, b) =>
      cmpU64(a.hash, b.hash) ||
      a.sourceIndex - b.sourceIndex ||
      a.rowId - b.rowId ||
      a.fieldId - b.fieldId
  );

  const header = {
    bundleVersion: data.bundleVersion,
    params: data.params,
    edmSalts: data.edmSalts,
    scope: data.scope,
    counts: { idm: idm.length, edm: edm.length, docs: data.docs.length },
    docs: data.docs,
    edmSources: data.edmSources,
  };
  const headerJson = Buffer.from(JSON.stringify(header), 'utf8');

  const bloom = buildBloom([
    ...idm.map((e) => e.hash),
    ...edm.map((e) => e.hash),
  ]);

  const idmBuf = Buffer.alloc(12 * idm.length);
  for (let i = 0; i < idm.length; i++) {
    i64le(idm[i].hash).copy(idmBuf, i * 12);
    idmBuf.writeUInt32LE(idm[i].docIndex, i * 12 + 8);
  }
  const edmBuf = Buffer.alloc(16 * edm.length);
  for (let i = 0; i < edm.length; i++) {
    i64le(edm[i].hash).copy(edmBuf, i * 16);
    edmBuf.writeUInt16LE(edm[i].sourceIndex, i * 16 + 8);
    edmBuf.writeUInt32LE(edm[i].rowId, i * 16 + 10);
    edmBuf.writeUInt16LE(edm[i].fieldId, i * 16 + 14);
  }

  const unsigned = Buffer.concat([
    MAGIC,
    u16le(FORMAT_VERSION),
    u32le(headerJson.length),
    headerJson,
    u32le(bloom.mBits),
    u32le(bloom.kHashes),
    bloom.bits,
    u32le(idm.length),
    idmBuf,
    u32le(edm.length),
    edmBuf,
  ]);
  if (!sign) return unsigned;

  const sig = signBuffer(unsigned);
  return Buffer.concat([unsigned, u32le(sig.length), sig]);
}

// ---------------------------------------------------------------------
// Parsing + verification (fail closed: ANY inconsistency throws)
// ---------------------------------------------------------------------
function parseError(msg) {
  const err = new Error(`bundle parse error: ${msg}`);
  err.permanent = true;
  return err;
}

function verifyAndParseBundle(buffer, caCertPem) {
  if (!Buffer.isBuffer(buffer)) throw parseError('not a buffer');
  let off = 0;
  const need = (n, what) => {
    if (off + n > buffer.length) throw parseError(`truncated: ${what}`);
  };

  need(MAGIC.length, 'magic');
  if (!buffer.subarray(0, MAGIC.length).equals(MAGIC)) throw parseError('bad magic');
  off = MAGIC.length;
  need(2, 'format version');
  const formatVersion = buffer.readUInt16LE(off);
  off += 2;
  if (formatVersion !== FORMAT_VERSION) {
    throw parseError(`unsupported format version ${formatVersion}`);
  }
  need(4, 'header length');
  const headerLen = buffer.readUInt32LE(off);
  off += 4;
  need(headerLen, 'header');
  let header;
  try {
    header = JSON.parse(buffer.subarray(off, off + headerLen).toString('utf8'));
  } catch {
    throw parseError('header is not valid JSON');
  }
  off += headerLen;

  need(8, 'bloom header');
  const mBits = buffer.readUInt32LE(off);
  const kHashes = buffer.readUInt32LE(off + 4);
  off += 8;
  if (mBits < 8 || kHashes < 1 || kHashes > 64) throw parseError('bad bloom parameters');
  const bloomBytes = Math.ceil(mBits / 8);
  need(bloomBytes, 'bloom bits');
  const bloom = { mBits, kHashes, bits: buffer.subarray(off, off + bloomBytes) };
  off += bloomBytes;

  need(4, 'idm count');
  const idmCount = buffer.readUInt32LE(off);
  off += 4;
  need(idmCount * 12, 'idm entries');
  const idm = new Array(idmCount);
  let prev = null;
  for (let i = 0; i < idmCount; i++) {
    const hash = buffer.readBigInt64LE(off);
    const docIndex = buffer.readUInt32LE(off + 8);
    off += 12;
    if (prev !== null && toU64(hash) < toU64(prev)) throw parseError('idm section not sorted');
    prev = hash;
    if (!header.docs || docIndex >= header.docs.length) throw parseError('idm docIndex out of range');
    idm[i] = { hash, docIndex };
  }

  need(4, 'edm count');
  const edmCount = buffer.readUInt32LE(off);
  off += 4;
  need(edmCount * 16, 'edm entries');
  const edm = new Array(edmCount);
  prev = null;
  for (let i = 0; i < edmCount; i++) {
    const hash = buffer.readBigInt64LE(off);
    const sourceIndex = buffer.readUInt16LE(off + 8);
    const rowId = buffer.readUInt32LE(off + 10);
    const fieldId = buffer.readUInt16LE(off + 14);
    off += 16;
    if (prev !== null && toU64(hash) < toU64(prev)) throw parseError('edm section not sorted');
    prev = hash;
    if (!header.edmSources || sourceIndex >= header.edmSources.length) {
      throw parseError('edm sourceIndex out of range');
    }
    edm[i] = { hash, sourceIndex, rowId, fieldId };
  }

  need(4, 'signature length');
  const sigLen = buffer.readUInt32LE(off);
  const signedEnd = off; // signature covers [0, signedEnd)
  off += 4;
  need(sigLen, 'signature');
  const signature = buffer.subarray(off, off + sigLen);
  off += sigLen;
  if (off !== buffer.length) throw parseError('trailing bytes after signature');

  if (!verifyBufferSignature(buffer.subarray(0, signedEnd), Buffer.from(signature), caCertPem)) {
    throw parseError('signature verification failed');
  }

  if (header.counts && (header.counts.idm !== idmCount || header.counts.edm !== edmCount)) {
    throw parseError('header counts do not match sections');
  }

  // Lookup helpers (hash accepted as BigInt or decimal string).
  const idmByHash = new Map();
  for (const e of idm) {
    const k = e.hash.toString();
    if (!idmByHash.has(k)) idmByHash.set(k, []);
    idmByHash.get(k).push({ docIndex: e.docIndex, doc: header.docs[e.docIndex] });
  }
  const edmByHash = new Map();
  for (const e of edm) {
    const k = e.hash.toString();
    if (!edmByHash.has(k)) edmByHash.set(k, []);
    edmByHash.get(k).push({
      sourceIndex: e.sourceIndex,
      source: header.edmSources[e.sourceIndex],
      rowId: e.rowId,
      fieldId: e.fieldId,
    });
  }
  const keyOf = (hash) => BigInt.asIntN(64, typeof hash === 'bigint' ? hash : BigInt(hash)).toString();

  return {
    formatVersion,
    header,
    bloom,
    idm,
    edm,
    signature: Buffer.from(signature),
    bloomHas: (hash) => bloomHas(bloom, hash),
    lookupIdm: (hash) => idmByHash.get(keyOf(hash)) || [],
    lookupEdm: (hash) => edmByHash.get(keyOf(hash)) || [],
  };
}

// ---------------------------------------------------------------------
// Compilation from the database
// ---------------------------------------------------------------------
const BUNDLE_VERSION_LOCK = 43; // advisory lock: serialize version allocation

// Compile everything 'ready' into a new bundle file + index_bundles row.
// Returns { version, fileRef, sha256, sizeBytes, counts }.
async function compileBundle() {
  // Deterministic ordering everywhere (order by id) so identical DB content
  // always produces identical bundle bytes.
  const docRows = (
    await pool.query(
      `select v.id as version_id, d.id as document_id, d.collection_id, d.title
         from protected_documents d
         join document_versions v
           on v.document_id = d.id and v.version_no = d.current_version
        where d.status = 'ready'
        order by d.id`
    )
  ).rows;

  const docs = [];
  const idmEntries = [];
  for (const row of docRows) {
    const { rows } = await pool.query(
      `select distinct hash::text as hash
         from document_fingerprints where version_id = $1`,
      [row.version_id]
    );
    const docIndex = docs.length;
    docs.push({
      versionId: row.version_id,
      documentId: row.document_id,
      collectionId: row.collection_id,
      title: row.title,
      fpCount: rows.length,
    });
    for (const r of rows) idmEntries.push({ hash: r.hash, docIndex });
  }

  const srcRows = (
    await pool.query(
      `select id, name, schema_json, salt_hex
         from edm_sources where status = 'ready' order by id`
    )
  ).rows;
  const edmSources = [];
  const edmSalts = {};
  const edmEntries = [];
  for (const row of srcRows) {
    const sourceIndex = edmSources.length;
    edmSources.push({
      sourceId: row.id,
      name: row.name,
      fields: row.schema_json.map((f, i) => ({
        fieldId: i,
        name: f.name,
        type: f.type,
        primary: f.primary === true,
      })),
    });
    edmSalts[row.id] = row.salt_hex;
    const { rows } = await pool.query(
      `select row_id, field_id, hash::text as hash
         from edm_hashes where source_id = $1`,
      [row.id]
    );
    for (const r of rows) {
      edmEntries.push({ hash: r.hash, sourceIndex, rowId: r.row_id, fieldId: r.field_id });
    }
  }

  const scope = [...new Set(docs.map((d) => d.collectionId))].sort();
  const params = { k: DEFAULT_K, w: DEFAULT_W, hashBits: 64 };

  // Allocate the next version and insert under an advisory lock so two
  // concurrent compiles cannot race the UNIQUE(version) constraint.
  const client = await pool.connect();
  try {
    await client.query('begin');
    await client.query('select pg_advisory_xact_lock($1)', [BUNDLE_VERSION_LOCK]);
    const v = await client.query(
      'select coalesce(max(version), 0) + 1 as version from index_bundles'
    );
    const version = v.rows[0].version;

    const file = buildBundle({
      bundleVersion: version,
      params,
      scope,
      docs,
      edmSources,
      edmSalts,
      idmEntries,
      edmEntries,
    });
    const sha256 = crypto.createHash('sha256').update(file).digest('hex');
    const fileRef = `bundle-v${version}.dlpx`;

    fs.mkdirSync(INDEX_DIR, { recursive: true });
    fs.writeFileSync(path.join(INDEX_DIR, fileRef), file);

    await client.query(
      `insert into index_bundles (version, params_json, scope_json, sha256, size_bytes, file_ref)
       values ($1, $2, $3, $4, $5, $6)`,
      [version, JSON.stringify(params), JSON.stringify(scope), sha256, file.length, fileRef]
    );
    await client.query('commit');
    return {
      version,
      fileRef,
      sha256,
      sizeBytes: file.length,
      counts: { idm: idmEntries.length, edm: edmEntries.length, docs: docs.length },
    };
  } catch (err) {
    await client.query('rollback').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

// Latest bundle row (or null) / latest version (0 if none) — used by the
// agent surface (checkin advertisement + GET /agent/index).
async function latestBundle() {
  const { rows } = await pool.query(
    `select id, version, sha256, size_bytes, file_ref, built_at
       from index_bundles order by version desc limit 1`
  );
  return rows[0] || null;
}

async function latestBundleVersion() {
  const { rows } = await pool.query(
    'select coalesce(max(version), 0) as version from index_bundles'
  );
  return rows[0].version;
}

module.exports = {
  MAGIC,
  FORMAT_VERSION,
  INDEX_DIR,
  buildBundle,
  verifyAndParseBundle,
  compileBundle,
  latestBundle,
  latestBundleVersion,
  buildBloom,
  bloomHas,
  // exposed for tests / the format doc's worked examples
  _internal: { fnv1a64Bytes, splitmix64, bloomBitIndexes, bloomKeyBytes, toU64 },
};
