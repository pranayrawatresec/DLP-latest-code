'use strict';
// =====================================================================
// Generates test/fixtures/bundle-sample/ — the golden fixture the Rust
// bundle loader is tested against (docs/index-bundle-format.md §7):
//
//   sample.bundle  — bundle built from 2 tiny in-memory documents and one
//                    EDM source with a FIXED salt (fully deterministic
//                    inputs; only the signature depends on the CA key)
//   ca-cert.pem    — the dev CA certificate that signed it
//   expected.json  — expected header fields, present hashes with their
//                    lookups, bloom-negative absent hashes, and (if found)
//                    bloom-POSITIVE absent hashes
//
// Usage: node scripts/gen-bundle-fixture.js   (requires npm run init-ca)
// The deterministic input builder is exported for test/bundle.test.js.
// =====================================================================
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const { fingerprint } = require('../lib/fingerprint');
const { ingestCsv } = require('../lib/edm');
const bundleLib = require('../lib/indexBundle');

const OUT_DIR = path.join(__dirname, '..', 'test', 'fixtures', 'bundle-sample');

// --- Fixed identities and salt: NEVER change these — the committed fixture
// and the Rust loader tests depend on them byte-for-byte. -------------------
const COLLECTION_ID = '11111111-1111-4111-8111-111111111111';
const DOC_A = { documentId: '22222222-2222-4222-8222-222222222222',
                versionId: '33333333-3333-4333-8333-333333333333', title: 'Fixture Plan Alpha' };
const DOC_B = { documentId: '44444444-4444-4444-8444-444444444444',
                versionId: '55555555-5555-4555-8555-555555555555', title: 'Fixture Plan Bravo' };
const EDM_SOURCE_ID = '66666666-6666-4666-8666-666666666666';
const EDM_SALT_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';

const DOC_A_TEXT =
  'Operation fixture alpha. ' +
  Array.from({ length: 12 }, (_, i) =>
    `Unit ${i + 1} advances to grid reference alpha ${i + 1} and holds the ` +
    `river crossing until the fuel convoy has cleared checkpoint delta ${i + 1}.`
  ).join(' ');

const DOC_B_TEXT =
  'Operation fixture bravo. ' +
  Array.from({ length: 12 }, (_, i) =>
    `Squadron ${i + 1} rotates through maintenance bay bravo ${i + 1} while ` +
    `the reserve flight covers the northern approach corridor sector ${i + 1}.`
  ).join(' ');

const EDM_SCHEMA = [
  { name: 'full_name', type: 'text', primary: true },
  { name: 'service_no', type: 'id', primary: true },
  { name: 'dob', type: 'date', primary: false },
];
const EDM_CSV =
  'full_name,service_no,dob\n' +
  '"Smith, John",AB-1234,14/03/1988\n' +
  'Jane Doe,CD-5678,1990-07-02\n' +
  '"O\'Brien, Pat",EF-9012,5 Mar 1979\n';

// Distinct fingerprint hashes of a text, as signed-decimal strings in
// first-seen (seq) order.
function distinctFingerprints(text) {
  const { fingerprints } = fingerprint(text);
  const seen = new Set();
  const out = [];
  for (const f of fingerprints) {
    const s = f.hash.toString();
    if (!seen.has(s)) {
      seen.add(s);
      out.push(s);
    }
  }
  return out;
}

// The deterministic buildBundle() input — shared with test/bundle.test.js.
function fixtureData() {
  const fpsA = distinctFingerprints(DOC_A_TEXT);
  const fpsB = distinctFingerprints(DOC_B_TEXT);
  const { entries } = ingestCsv(EDM_CSV, EDM_SCHEMA, Buffer.from(EDM_SALT_HEX, 'hex'));

  return {
    bundleVersion: 1,
    params: { k: 8, w: 8, hashBits: 64 },
    scope: [COLLECTION_ID],
    docs: [
      { versionId: DOC_A.versionId, documentId: DOC_A.documentId,
        collectionId: COLLECTION_ID, title: DOC_A.title, fpCount: fpsA.length },
      { versionId: DOC_B.versionId, documentId: DOC_B.documentId,
        collectionId: COLLECTION_ID, title: DOC_B.title, fpCount: fpsB.length },
    ],
    edmSources: [
      {
        sourceId: EDM_SOURCE_ID,
        name: 'fixture personnel',
        fields: EDM_SCHEMA.map((f, i) => ({
          fieldId: i, name: f.name, type: f.type, primary: f.primary,
        })),
      },
    ],
    edmSalts: { [EDM_SOURCE_ID]: EDM_SALT_HEX },
    idmEntries: [
      ...fpsA.map((hash) => ({ hash, docIndex: 0 })),
      ...fpsB.map((hash) => ({ hash, docIndex: 1 })),
    ],
    edmEntries: entries.map((e) => ({
      hash: e.hash.toString(), sourceIndex: 0, rowId: e.rowId, fieldId: e.fieldId,
    })),
  };
}

function main() {
  const data = fixtureData();
  const bundle = bundleLib.buildBundle(data); // signed with the dev CA
  const caPem = require('../lib/ca').loadCaCertificatePem();
  const parsed = bundleLib.verifyAndParseBundle(bundle, caPem); // self-check

  // --- Present hashes: 3 idm (first of A, last of A, first of B) + 3 edm
  // (row 1 name, row 2 id, row 3 dob) with their expected lookups. ---------
  const fpsA = distinctFingerprints(DOC_A_TEXT);
  const fpsB = distinctFingerprints(DOC_B_TEXT);
  const pickEdm = (rowId, fieldId) =>
    data.edmEntries.find((e) => e.rowId === rowId && e.fieldId === fieldId);
  const present = [
    ...[fpsA[0], fpsA[fpsA.length - 1], fpsB[0]].map((hash) => ({
      hash,
      section: 'idm',
      matches: parsed.lookupIdm(hash).map((m) => ({
        docIndex: m.docIndex, versionId: m.doc.versionId, title: m.doc.title,
      })),
    })),
    ...[pickEdm(1, 0), pickEdm(2, 1), pickEdm(3, 2)].map((e) => ({
      hash: e.hash,
      section: 'edm',
      matches: parsed.lookupEdm(e.hash).map((m) => ({
        sourceIndex: m.sourceIndex, sourceId: m.source.sourceId,
        rowId: m.rowId, fieldId: m.fieldId,
      })),
    })),
  ];
  for (const p of present) {
    if (p.matches.length === 0) throw new Error(`present hash ${p.hash} has no lookup`);
    if (!parsed.bloomHas(p.hash)) throw new Error(`present hash ${p.hash} bloom-negative`);
  }

  // --- Absent hashes. Deterministic candidate stream: splitmix64(1..n)
  // reinterpreted signed. Classify each as bloom-negative or bloom-positive
  // until we have 4 negatives and (ideally) 2 positives. --------------------
  const inBundle = new Set([
    ...data.idmEntries.map((e) => String(e.hash)),
    ...data.edmEntries.map((e) => String(e.hash)),
  ]);
  const { splitmix64 } = bundleLib._internal;
  const absentBloomNegative = [];
  const absentBloomPositive = [];
  let bloomPositiveNote = null;
  const CAP = 30_000_000;
  for (let i = 1n; absentBloomNegative.length < 4 || absentBloomPositive.length < 2; i++) {
    if (i > CAP) {
      bloomPositiveNote =
        `no bloom-positive absent hash found within ${CAP} deterministic candidates ` +
        '(false-positive rate too low for this bundle size)';
      break;
    }
    const hash = BigInt.asIntN(64, splitmix64(i)).toString();
    if (inBundle.has(hash)) continue;
    if (parsed.bloomHas(hash)) {
      if (absentBloomPositive.length < 2) absentBloomPositive.push(hash);
    } else if (absentBloomNegative.length < 4) {
      absentBloomNegative.push(hash);
    }
  }

  const expected = {
    note:
      'Golden fixture for the Rust bundle loader (docs/index-bundle-format.md). ' +
      'Hashes are signed-i64 decimal strings. absentBloomNegative hashes are not in ' +
      'the bundle AND the bloom filter answers false; absentBloomPositive hashes are ' +
      'not in the bundle but the bloom filter answers true (false positives — the ' +
      'loader must fall through to the sorted sections and find nothing).',
    header: parsed.header,
    bloom: { mBits: parsed.bloom.mBits, kHashes: parsed.bloom.kHashes },
    present,
    absentBloomNegative,
    absentBloomPositive,
    ...(bloomPositiveNote ? { bloomPositiveNote } : {}),
  };

  fs.mkdirSync(OUT_DIR, { recursive: true });
  fs.writeFileSync(path.join(OUT_DIR, 'sample.bundle'), bundle);
  fs.writeFileSync(path.join(OUT_DIR, 'ca-cert.pem'), caPem);
  fs.writeFileSync(path.join(OUT_DIR, 'expected.json'), JSON.stringify(expected, null, 2));
  console.log(
    `wrote ${OUT_DIR}: sample.bundle (${bundle.length} bytes, ` +
      `${parsed.idm.length} idm, ${parsed.edm.length} edm), ca-cert.pem, expected.json ` +
      `(${absentBloomPositive.length} bloom-positive absents)`
  );
}

module.exports = { fixtureData, OUT_DIR };

if (require.main === module) main();
