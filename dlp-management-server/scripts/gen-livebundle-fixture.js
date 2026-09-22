'use strict';
// =====================================================================
// Generates dlp-agent/tests/fixtures/livebundle/ — the fixture the agent's
// live-bundle reload tests (dlp-agent/tests/live_bundle.rs) run against.
//
//   v1.bundle   — bundleVersion 1, registers ONLY "Fixture Plan Alpha"
//   v2.bundle   — bundleVersion 2, registers Alpha AND "Fixture Plan Bravo"
//   v3.bundle   — bundleVersion 3, same content as v2
//   bravo.txt   — the text of document Bravo (matches v2/v3, NOT v1)
//   ca-cert.pem — the dev CA that signed all three
//
// The point of v1 vs v2: a reload test can prove that a newly downloaded
// index actually changes DETECTION (Bravo goes from no-match to match)
// without an agent restart, not merely that a version number moved.
//
// Built from the same deterministic inputs as gen-bundle-fixture.js, so
// only the signatures depend on the CA key.
//
// Usage: node scripts/gen-livebundle-fixture.js   (requires npm run init-ca)
// =====================================================================
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const bundleLib = require('../lib/indexBundle');
const { fixtureData } = require('./gen-bundle-fixture');

const OUT_DIR = path.join(__dirname, '..', '..', 'dlp-agent', 'tests', 'fixtures', 'livebundle');

// Must match DOC_B_TEXT in gen-bundle-fixture.js.
const BRAVO_TEXT =
  'Operation fixture bravo. ' +
  Array.from({ length: 12 }, (_, i) =>
    `Squadron ${i + 1} rotates through maintenance bay bravo ${i + 1} while ` +
    `the reserve flight covers the northern approach corridor sector ${i + 1}.`
  ).join(' ');

function alphaOnly(data, version) {
  return {
    ...data,
    bundleVersion: version,
    docs: [data.docs[0]],
    idmEntries: data.idmEntries.filter((e) => e.docIndex === 0),
  };
}

function withBoth(data, version) {
  return { ...data, bundleVersion: version };
}

function main() {
  const data = fixtureData();
  const caPem = require('../lib/ca').loadCaCertificatePem();
  const out = {
    'v1.bundle': bundleLib.buildBundle(alphaOnly(data, 1)),
    'v2.bundle': bundleLib.buildBundle(withBoth(data, 2)),
    'v3.bundle': bundleLib.buildBundle(withBoth(data, 3)),
  };
  // Self-check every artifact against the CA before writing anything.
  for (const [name, bytes] of Object.entries(out)) {
    const parsed = bundleLib.verifyAndParseBundle(bytes, caPem);
    console.log(`${name}: version ${parsed.header.bundleVersion}, ${parsed.header.docs.length} doc(s), ${bytes.length} bytes`);
  }
  fs.mkdirSync(OUT_DIR, { recursive: true });
  for (const [name, bytes] of Object.entries(out)) fs.writeFileSync(path.join(OUT_DIR, name), bytes);
  fs.writeFileSync(path.join(OUT_DIR, 'bravo.txt'), BRAVO_TEXT);
  fs.writeFileSync(path.join(OUT_DIR, 'ca-cert.pem'), caPem);
  console.log(`wrote ${OUT_DIR}`);
}

if (require.main === module) main();
