'use strict';
// Test + edge-case harness for the encrypted blob store (lib/blobStore.js).
//
// No database needed — this is a pure filesystem/crypto layer. The suite
// sets its own master key in-process, then verifies:
//   A. Round-trip — put/get restores the exact plaintext; ref/sha/size shape.
//   B. At rest — the on-disk file is header + ciphertext, plaintext absent.
//   C. Tamper — flipping any byte (ciphertext, tags, wrapped key) throws.
//   D. Refs — traversal / malformed refs are rejected before touching disk.
//   E. Keys — missing/malformed/wrong master key fails loudly and closed.
//
// Cleans up every blob it creates.
require('dotenv').config();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// A throwaway master key for this run — set BEFORE requiring nothing in
// particular (the store reads it lazily on each call, so order is free),
// but set explicitly so the suite never depends on the developer's .env.
const TEST_MASTER_KEY = crypto.randomBytes(32).toString('hex');
process.env.DLP_BLOB_MASTER_KEY = TEST_MASTER_KEY;

const { putBlob, getBlob } = require('../lib/blobStore');

const BLOB_DIR = path.join(__dirname, '..', 'data', 'blobs');
const results = [];
let passed = 0;
let failed = 0;
const createdRefs = []; // for cleanup

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
async function expectThrow(fn, msgPart) {
  try {
    await fn();
  } catch (err) {
    if (msgPart) {
      assert(err.message.includes(msgPart), `wrong error: "${err.message}" (wanted "${msgPart}")`);
    }
    return err.message;
  }
  throw new Error('expected a throw, got success');
}

function refToPath(ref) {
  const [shard, id] = ref.split('/');
  return path.join(BLOB_DIR, shard, id);
}

async function put(buffer) {
  const out = await putBlob(buffer);
  createdRefs.push(out.ref);
  return out;
}

// Write a copy of a stored blob with one byte XOR-flipped at `offset`,
// registered under a fresh valid ref so getBlob will read it.
async function tamperedCopy(ref, offset) {
  const raw = await fs.promises.readFile(refToPath(ref));
  raw[offset] ^= 0x01;
  const id = crypto.randomUUID();
  const shard = id.slice(0, 2);
  await fs.promises.mkdir(path.join(BLOB_DIR, shard), { recursive: true });
  await fs.promises.writeFile(path.join(BLOB_DIR, shard, id), raw);
  const newRef = `${shard}/${id}`;
  createdRefs.push(newRef);
  return newRef;
}

async function main() {
  console.log('\nEncrypted blob store — test & edge-case suite\n');

  const MARKER = 'TOP-SECRET-PLAINTEXT-MARKER-' + crypto.randomBytes(8).toString('hex');
  const plaintext = Buffer.concat([Buffer.from(MARKER), crypto.randomBytes(4096)]);

  // ============ A. Round-trip ============
  let stored;
  await check('B01', 'putBlob returns shard/uuid ref, plaintext sha256 and size', async () => {
    stored = await put(plaintext);
    assert(/^[0-9a-f]{2}\/[0-9a-f-]{36}$/.test(stored.ref), `bad ref shape: ${stored.ref}`);
    assert(stored.ref.split('/')[1].startsWith(stored.ref.split('/')[0]), 'shard != first 2 chars of uuid');
    assert(stored.sha256 === crypto.createHash('sha256').update(plaintext).digest('hex'),
      'sha256 is not of the plaintext');
    assert(stored.sizeBytes === plaintext.length, 'sizeBytes != plaintext length');
    return stored.ref;
  });

  await check('B02', 'getBlob round-trips the exact plaintext', async () => {
    const back = await getBlob(stored.ref);
    assert(Buffer.isBuffer(back), 'not a Buffer');
    assert(back.equals(plaintext), 'plaintext mismatch after round-trip');
    return `${back.length} bytes`;
  });

  await check('B03', 'empty buffer round-trips', async () => {
    const out = await put(Buffer.alloc(0));
    assert(out.sizeBytes === 0, 'sizeBytes should be 0');
    const back = await getBlob(out.ref);
    assert(back.length === 0, 'expected empty buffer back');
  });

  await check('B04', 'two puts of the same plaintext produce different refs and ciphertexts', async () => {
    const a = await put(plaintext);
    const b = await put(plaintext);
    assert(a.ref !== b.ref, 'refs collided');
    assert(a.sha256 === b.sha256, 'same plaintext must hash identically');
    const fa = await fs.promises.readFile(refToPath(a.ref));
    const fb = await fs.promises.readFile(refToPath(b.ref));
    assert(!fa.equals(fb), 'ciphertexts identical — per-blob key/IV not random?');
  });

  // ============ B. At rest ============
  await check('B05', 'on-disk file has the DLPB1 header and NO plaintext', async () => {
    const raw = await fs.promises.readFile(refToPath(stored.ref));
    assert(raw.subarray(0, 5).toString('ascii') === 'DLPB1', 'missing magic');
    assert(!raw.includes(Buffer.from(MARKER)), 'plaintext marker found in the stored file');
    // header = 5 magic + 12 wrapIv + 48 wrappedKey + 12 dataIv + 16 tag = 93
    assert(raw.length === 93 + plaintext.length, `unexpected file size ${raw.length}`);
  });

  await check('B06', 'putBlob rejects non-Buffer input', async () => {
    await expectThrow(() => putBlob('a string'), 'Buffer');
    await expectThrow(() => putBlob({}), 'Buffer');
  });

  // ============ C. Tamper detection ============
  await check('B07', 'flipping a ciphertext byte -> getBlob throws', async () => {
    const ref = await tamperedCopy(stored.ref, 93 + 100); // inside ciphertext
    return expectThrow(() => getBlob(ref), 'authentication');
  });

  await check('B08', 'flipping a byte in the wrapped key -> getBlob throws', async () => {
    const ref = await tamperedCopy(stored.ref, 5 + 12 + 3); // inside wrapped-key block
    return expectThrow(() => getBlob(ref), 'authentication');
  });

  await check('B09', 'flipping a byte in the data tag -> getBlob throws', async () => {
    const ref = await tamperedCopy(stored.ref, 5 + 12 + 48 + 12 + 2); // inside data-tag
    return expectThrow(() => getBlob(ref), 'authentication');
  });

  await check('B10', 'truncated / non-blob file -> clear corrupt error', async () => {
    const id = crypto.randomUUID();
    const shard = id.slice(0, 2);
    await fs.promises.mkdir(path.join(BLOB_DIR, shard), { recursive: true });
    await fs.promises.writeFile(path.join(BLOB_DIR, shard, id), Buffer.from('not a blob'));
    createdRefs.push(`${shard}/${id}`);
    return expectThrow(() => getBlob(`${shard}/${id}`), 'corrupt');
  });

  // ============ D. Ref validation / path traversal ============
  await check('B11', 'traversal and malformed refs are rejected', async () => {
    const bad = [
      '../../.env',
      '..\\..\\.env',
      'aa/../../.env',
      'aa/..',
      '/etc/passwd',
      'C:/Windows/win.ini',
      `aa/${'0'.repeat(36)}`, // not a uuid
      'zz/' + crypto.randomUUID(), // non-hex shard
      'ff/' + crypto.randomUUID().replace(/^../, 'ab'), // shard != uuid prefix... (see below)
      '',
      null,
      undefined,
      42,
      stored.ref + '/extra',
    ];
    for (const ref of bad) {
      // 'ff/…' case: uuid starts 'ab' but shard is 'ff' — mismatch must be rejected too.
      await expectThrow(() => getBlob(ref), 'invalid blob ref');
    }
    return `${bad.length} refs rejected`;
  });

  await check('B12', 'well-formed but unknown ref -> not found (no leak)', async () => {
    const id = crypto.randomUUID();
    return expectThrow(() => getBlob(`${id.slice(0, 2)}/${id}`), 'not found');
  });

  // ============ E. Master key handling ============
  await check('B13', 'missing DLP_BLOB_MASTER_KEY -> clear error, both ops', async () => {
    delete process.env.DLP_BLOB_MASTER_KEY;
    try {
      await expectThrow(() => putBlob(Buffer.from('x')), 'DLP_BLOB_MASTER_KEY is not set');
      await expectThrow(() => getBlob(stored.ref), 'DLP_BLOB_MASTER_KEY is not set');
    } finally {
      process.env.DLP_BLOB_MASTER_KEY = TEST_MASTER_KEY;
    }
  });

  await check('B14', 'malformed master key (wrong length / non-hex) -> clear error', async () => {
    try {
      process.env.DLP_BLOB_MASTER_KEY = 'abcd'; // too short
      await expectThrow(() => putBlob(Buffer.from('x')), '64 hex');
      process.env.DLP_BLOB_MASTER_KEY = 'g'.repeat(64); // right length, not hex
      await expectThrow(() => putBlob(Buffer.from('x')), '64 hex');
    } finally {
      process.env.DLP_BLOB_MASTER_KEY = TEST_MASTER_KEY;
    }
  });

  await check('B15', 'wrong (rotated-away) master key -> decrypt fails closed', async () => {
    try {
      process.env.DLP_BLOB_MASTER_KEY = crypto.randomBytes(32).toString('hex');
      return await expectThrow(() => getBlob(stored.ref), 'authentication');
    } finally {
      process.env.DLP_BLOB_MASTER_KEY = TEST_MASTER_KEY;
    }
  });

  // ============ Cleanup ============
  for (const ref of createdRefs) {
    await fs.promises.unlink(refToPath(ref)).catch(() => {});
  }

  console.log(`\n${passed} passed, ${failed} failed\n`);
  fs.writeFileSync(
    path.join(__dirname, '.blobstore-results.json'),
    JSON.stringify({ generatedAt: new Date().toISOString(), passed, failed, results }, null, 2)
  );
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
