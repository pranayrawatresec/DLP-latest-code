'use strict';
// =====================================================================
// Encrypted blob store (guide Phase 4 groundwork)
//
// Protected-document content NEVER touches the database — plaintext is
// encrypted with AES-256-GCM and written under data/blobs/, and only an
// opaque ref (shard/uuid) is stored in document_versions.blob_ref.
//
// Envelope encryption:
//   * Each blob gets its own random 256-bit data key + 96-bit IV.
//   * The data key is wrapped (AES-256-GCM again, its own random IV)
//     with a master key from env DLP_BLOB_MASTER_KEY (64 hex chars).
//   * Rotating the master key therefore only means re-wrapping 48-byte
//     key blocks, never re-encrypting terabytes of evidence. Deleting a
//     blob's wrapped key crypto-shreds that blob.
//
// File layout (all lengths fixed except ciphertext):
//   magic 'DLPB1' (5) | wrap-iv (12) | wrapped-key (32+16 tag)
//   | data-iv (12) | data-tag (16) | ciphertext
//
// GCM authenticates both layers: any flipped byte in the wrapped key or
// the ciphertext makes decryption throw — we fail closed, never return
// partial or corrupted plaintext.
//
// Pure storage layer: RBAC and audit are owned by the routes that call
// this (every evidence/document access must be audited by the caller).
// Never log keys, refs alongside content, or the content itself.
// =====================================================================
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const BLOB_DIR = path.join(__dirname, '..', 'data', 'blobs');
const MAGIC = Buffer.from('DLPB1', 'ascii');
const KEY_BYTES = 32; // AES-256
const IV_BYTES = 12; // GCM standard nonce
const TAG_BYTES = 16;
const WRAPPED_KEY_BYTES = KEY_BYTES + TAG_BYTES;
const HEADER_BYTES = MAGIC.length + IV_BYTES + WRAPPED_KEY_BYTES + IV_BYTES + TAG_BYTES;

// A ref is exactly "<2-hex shard>/<uuid>" — anything else is rejected
// before it goes near the filesystem (path-traversal guard).
const REF_RE = /^([0-9a-f]{2})\/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$/;

// Read lazily (not at module load) so the server can boot for non-blob
// work, but any blob operation without a proper key fails loudly.
function masterKey() {
  const hex = process.env.DLP_BLOB_MASTER_KEY;
  if (!hex) {
    throw new Error(
      'DLP_BLOB_MASTER_KEY is not set — add a 64-hex-char (256-bit) key to .env, ' +
        'e.g. generated with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"'
    );
  }
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error('DLP_BLOB_MASTER_KEY is malformed — it must be exactly 64 hex characters (a 256-bit key)');
  }
  return Buffer.from(hex, 'hex');
}

// Encrypt and store a plaintext buffer. Returns { ref, sha256, sizeBytes }
// where sha256/sizeBytes describe the PLAINTEXT (for document_versions).
// The plaintext itself is never written to disk or logged.
async function putBlob(buffer) {
  if (!Buffer.isBuffer(buffer)) {
    throw new Error('putBlob expects a Buffer');
  }
  const mk = masterKey();
  const sha256 = crypto.createHash('sha256').update(buffer).digest('hex');

  // Per-blob data key + IV; encrypt the content.
  const dataKey = crypto.randomBytes(KEY_BYTES);
  const dataIv = crypto.randomBytes(IV_BYTES);
  const dataCipher = crypto.createCipheriv('aes-256-gcm', dataKey, dataIv);
  const ciphertext = Buffer.concat([dataCipher.update(buffer), dataCipher.final()]);
  const dataTag = dataCipher.getAuthTag();

  // Wrap the data key under the master key.
  const wrapIv = crypto.randomBytes(IV_BYTES);
  const wrapCipher = crypto.createCipheriv('aes-256-gcm', mk, wrapIv);
  const wrappedKey = Buffer.concat([wrapCipher.update(dataKey), wrapCipher.final(), wrapCipher.getAuthTag()]);
  dataKey.fill(0); // drop the plaintext key from memory as soon as possible

  const id = crypto.randomUUID();
  const shard = id.slice(0, 2);
  const ref = `${shard}/${id}`; // relative, forward-slash — what goes in blob_ref

  const dir = path.join(BLOB_DIR, shard);
  await fs.promises.mkdir(dir, { recursive: true });
  const file = Buffer.concat([MAGIC, wrapIv, wrappedKey, dataIv, dataTag, ciphertext]);
  await fs.promises.writeFile(path.join(dir, id), file);

  return { ref, sha256, sizeBytes: buffer.length };
}

// Fetch and decrypt a blob by its ref. Throws on unknown ref, malformed
// ref (traversal attempt), truncated file, or ANY authentication-tag
// failure (tampered key block or ciphertext) — fail closed.
async function getBlob(ref) {
  const m = typeof ref === 'string' ? REF_RE.exec(ref) : null;
  if (!m || !m[2].startsWith(m[1])) {
    throw new Error('invalid blob ref'); // never echo the ref — could be attacker-controlled
  }
  const mk = masterKey();

  let file;
  try {
    file = await fs.promises.readFile(path.join(BLOB_DIR, m[1], m[2]));
  } catch (err) {
    if (err.code === 'ENOENT') throw new Error('blob not found');
    throw err;
  }
  if (file.length < HEADER_BYTES || !file.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error('blob is corrupt: bad header');
  }

  let off = MAGIC.length;
  const wrapIv = file.subarray(off, (off += IV_BYTES));
  const wrappedKey = file.subarray(off, (off += WRAPPED_KEY_BYTES));
  const dataIv = file.subarray(off, (off += IV_BYTES));
  const dataTag = file.subarray(off, (off += TAG_BYTES));
  const ciphertext = file.subarray(off);

  // Unwrap the data key (GCM verifies the wrap tag).
  let dataKey;
  try {
    const unwrap = crypto.createDecipheriv('aes-256-gcm', mk, wrapIv);
    unwrap.setAuthTag(wrappedKey.subarray(KEY_BYTES));
    dataKey = Buffer.concat([unwrap.update(wrappedKey.subarray(0, KEY_BYTES)), unwrap.final()]);
  } catch (err) {
    throw new Error('blob decryption failed: key unwrap authentication error (tampered or wrong master key)');
  }

  // Decrypt the content (GCM verifies the data tag).
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', dataKey, dataIv);
    decipher.setAuthTag(dataTag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (err) {
    throw new Error('blob decryption failed: content authentication error (tampered ciphertext)');
  } finally {
    dataKey.fill(0);
  }
}

// Remove a blob from disk by its ref. Idempotent: a ref that no longer
// exists is success (the goal — the bytes being gone — is already met).
// Malformed refs are rejected exactly like getBlob (path-traversal guard).
// Used by the EDM ingest worker: temporary plaintext uploads must NOT be
// retained once their salted hashes are stored.
async function deleteBlob(ref) {
  const m = typeof ref === 'string' ? REF_RE.exec(ref) : null;
  if (!m || !m[2].startsWith(m[1])) {
    throw new Error('invalid blob ref'); // never echo the ref — could be attacker-controlled
  }
  try {
    await fs.promises.unlink(path.join(BLOB_DIR, m[1], m[2]));
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
}

module.exports = { putBlob, getBlob, deleteBlob };
