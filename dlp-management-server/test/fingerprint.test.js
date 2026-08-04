'use strict';
// Test + edge-case harness for the IDM fingerprinting library (lib/fingerprint.js).
//
// Three levels of verification:
//   A. Primitives — FNV-1a against independently hard-coded known values,
//      normalization (NFKC / case / punctuation), shingling, and the
//      winnowing rules (unsigned compare, rightmost tie, min-position change).
//   B. Golden vectors — test/fixtures/fingerprint-vectors.json must be
//      reproduced EXACTLY. The Rust agent is ported against that file, so a
//      failure here means a breaking protocol change, not a "flaky test".
//   C. Detection bands — containment behaviour across realistic mutations of
//      a ~40-sentence document (reformat, append, delete 25%, full rewrite).
//
// Pure computation — no database, no server, no network.
require('dotenv').config();
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const fpr = require('../lib/fingerprint');

const results = [];
let passed = 0;
let failed = 0;

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
function ok(cond, msg) {
  if (!cond) throw new Error(msg || 'assertion failed');
}

// ============ Base corpus for the detection-band tests (C) ============
// ~40 distinct sentences (a plausible protected document).
const BASE_SENTENCES = [
  'The perimeter fence on the north side was inspected at first light by the duty officer.',
  'Every visitor badge must be surrendered at the gatehouse before the holder leaves the site.',
  'Deliveries arriving after eighteen hundred are held in the outer compound until morning.',
  'The generator room is tested under load on the first Tuesday of every month.',
  'Access to the server hall requires two named custodians to be present at all times.',
  'Contractors working above the false ceiling must lodge a permit with the facilities desk.',
  'The evacuation assembly point for buildings three and four is the west car park.',
  'Radio checks between the control room and each patrol are logged every thirty minutes.',
  'Keys to the archive store are issued against signature and counted at shift change.',
  'Any damaged seal on a document container is reported immediately to the registry team.',
  'The camera covering loading bay two was realigned after the survey noted a blind spot.',
  'Fire doors along the central corridor are checked for obstructions during each round.',
  'Personal devices are deposited in the lockers outside the secure working area.',
  'The visitor log for the previous quarter is reconciled against the badge system weekly.',
  'Escorts must remain within sight of their visitors for the whole duration of the stay.',
  'The standby lighting in stairwell six failed its discharge test and awaits new batteries.',
  'Waste destined for destruction is double bagged and weighed before collection.',
  'The duty roster for the holiday period was approved by the site manager on Friday.',
  'Alarm activations outside working hours trigger a callout to the response contractor.',
  'The fuel level in the standby tank is dipped manually and recorded each Monday.',
  'Grounds maintenance staff are briefed not to store equipment against the inner fence.',
  'The pass office closes at sixteen thirty and late arrivals are handled by the gatehouse.',
  'Lift number two remains out of service pending a replacement door interlock.',
  'A trial of the new turnstile software is scheduled for the last week of the month.',
  'The mail screening room reported no suspicious items during the reporting period.',
  'Roof access requests are countersigned by both the safety adviser and the duty engineer.',
  'The tamper alarm on the east gate cabinet was traced to a loose junction box lid.',
  'Cleaning crews assigned to restricted rooms hold the appropriate level of clearance.',
  'The quarterly lock audit found two cabinets keyed outside the approved suite.',
  'Vehicle searches at the main gate are conducted at random intervals through the day.',
  'The intruder detection system completed its annual certification without defects.',
  'Spare radios are kept on charge in the control room and rotated every week.',
  'The car park barrier arm was replaced after being struck by a delivery vehicle.',
  'Induction briefings for new starters now include the updated spill response procedure.',
  'The plant room door closer was adjusted so the door latches under its own weight.',
  'Records of the monthly fence line walk are retained for a minimum of three years.',
  'A faulty motion sensor in corridor nine produced repeated false alarms overnight.',
  'The gatehouse first aid kit was restocked and the eyewash bottles were replaced.',
  'External floodlighting switches to half output after midnight to reduce consumption.',
  'The annual review of patrol routes begins with a survey of the southern boundary.',
];
const BASE_DOC = BASE_SENTENCES.join(' ');

// Cosmetic mutation: case, punctuation, extra whitespace — content identical.
const REFORMATTED_DOC = BASE_SENTENCES.map((s, i) =>
  (i % 2 === 0 ? s.toUpperCase() : s)
    .replace(/\./g, i % 3 === 0 ? '!!!' : ' ...')
    .replace(/ /g, i % 5 === 0 ? '\t\t' : '  ')
).join('\n\n --- \n\n');

// One genuinely new paragraph appended.
const ADDED_PARAGRAPH =
  'A separate initiative examined the catering compound, where the review team ' +
  'interviewed kitchen staff about out of hours deliveries, sampled the cold store ' +
  'temperature logs, and recommended that the rear service door be fitted with the ' +
  'same monitored contact used elsewhere on the site so that openings appear in the ' +
  'central event record alongside every other controlled entrance.';
const APPENDED_DOC = BASE_DOC + ' ' + ADDED_PARAGRAPH;

// ~25% of sentences removed (two blocks of five: indexes 14-18 and 34-38).
const DELETED_DOC = BASE_SENTENCES.filter((s, i) => !((i >= 14 && i <= 18) || (i >= 34 && i <= 38))).join(' ');

// Same topic (site security report), completely different wording.
const REWRITTEN_DOC = [
  'Guards walked the boundary as usual and nothing unusual turned up along the wire.',
  'People coming in for meetings hand back their temporary cards when they go home.',
  'Trucks that show up late in the evening wait outside until somebody signs them in.',
  'We run the backup power plant once a month to make sure it still takes the strain.',
  'Nobody gets into the computer room alone; a second keyholder always tags along.',
  'Workmen poking around in the ceiling spaces need a chit from the office first.',
  'If the bells ring, everyone from the far blocks gathers on the tarmac by the gym.',
  'The wardens call in on the handsets twice an hour so the desk knows where they are.',
  'Whoever draws the strongroom key signs a book, and the bunch is tallied at handover.',
  'Broken wrappers on filing boxes get flagged straight away to the records people.',
  'One of the yard cameras was twisted round because it could not see a corner before.',
  'On every walkabout the wardens make sure nothing is piled up against the exits.',
  'Phones and smart watches stay in the cubbyholes by the entrance to the quiet zone.',
  'Someone cross checks the sign in sheets against the card reader printout regularly.',
  'Hosts stick with their guests from the front door until they are back out again.',
].join(' ');

const fixturePath = path.join(__dirname, 'fixtures', 'fingerprint-vectors.json');

async function main() {
  console.log('\nIDM fingerprinting — test & edge-case suite\n');

  // ============ A. Primitives ============
  await check('F01', 'FNV-1a 64 matches independently known test values (signed form)', () => {
    // Reference values from the published FNV-1a test suite, hard-coded here —
    // NOT derived from the implementation. The Rust port must match these too.
    const known = [
      ['', 0xcbf29ce484222325n],
      ['a', 0xaf63dc4c8601ec8cn],
      ['foobar', 0x85944171f73967e8n],
    ];
    for (const [input, u64] of known) {
      const expected = BigInt.asIntN(64, u64);
      const got = fpr.fnv1a64(input);
      ok(got === expected, `fnv1a64(${JSON.stringify(input)}) = ${got}, want ${expected}`);
      ok(typeof got === 'bigint', 'hash must be a BigInt');
    }
    ok(fpr.fnv1a64('') < 0n, 'offset basis has the top bit set — signed form must be negative');
    return '3 known vectors, signed 64-bit';
  });

  await check('F02', 'normalize: NFKC + lowercase + punctuation runs collapse to one space', () => {
    const { canonical, tokens } = fpr.normalize('  Ｈｅｌｌｏ,,,   ﬁne---World!! №1 ');
    ok(canonical === 'hello fine world no1', `canonical was ${JSON.stringify(canonical)}`);
    assert.deepStrictEqual(tokens, ['hello', 'fine', 'world', 'no1']);
    // Case/punctuation/whitespace variants normalize identically.
    const a = fpr.normalize('The QUICK  brown-fox!').canonical;
    const b = fpr.normalize('the quick brown fox').canonical;
    ok(a === b, 'variants must share one canonical form');
    return canonical;
  });

  await check('F03', 'normalize: empty and punctuation-only inputs yield no tokens', () => {
    assert.deepStrictEqual(fpr.normalize(''), { canonical: '', tokens: [] });
    assert.deepStrictEqual(fpr.normalize(' ... !!! --- ').tokens, []);
    assert.deepStrictEqual(fpr.normalize(null).tokens, []);
    return 'empty → []';
  });

  await check('F04', 'shingles: k-window with overlap k-1; short docs give one whole-text shingle', () => {
    const tokens = 'a b c d e f g h i j'.split(' '); // 10 tokens
    const sh = fpr.shinglesOf(tokens, 8);
    ok(sh.length === 3, `expected 3 shingles, got ${sh.length}`);
    ok(sh[0] === 'a b c d e f g h', 'first shingle wrong');
    ok(sh[1] === 'b c d e f g h i', 'overlap must be k-1');
    ok(sh[2] === 'c d e f g h i j', 'last shingle wrong');
    assert.deepStrictEqual(fpr.shinglesOf(['x', 'y'], 8), ['x y']); // < k → whole string
    assert.deepStrictEqual(fpr.shinglesOf([], 8), []);
    return '10 tokens → 3 shingles; 2 tokens → 1 shingle';
  });

  await check('F05', 'winnowing: unsigned compare, rightmost tie, record on min-position change', () => {
    // Fewer than w hashes → single min; tie at values 3n → rightmost (index 2).
    assert.deepStrictEqual(fpr.winnow([5n, 3n, 3n, 9n], 8), [{ hash: 3n, seq: 2 }]);
    // Unsigned compare: -1n is 0xffff...ffff unsigned — the LARGEST value, never the min.
    assert.deepStrictEqual(fpr.winnow([-1n, 7n], 8), [{ hash: 7n, seq: 1 }]);
    // w=2 walk over [9,5,5,8,2]: windows pick seq 1 (5), then the TIE at seq 2
    // (rightmost 5), then seq 2 again (no record), then seq 4 (2).
    assert.deepStrictEqual(fpr.winnow([9n, 5n, 5n, 8n, 2n], 2), [
      { hash: 5n, seq: 1 },
      { hash: 5n, seq: 2 },
      { hash: 2n, seq: 4 },
    ]);
    assert.deepStrictEqual(fpr.winnow([], 8), []);
    return 'ties rightmost, unsigned order, dedupe by position';
  });

  // ============ B. Golden vectors ============
  await check('F06', 'golden vectors file reproduced EXACTLY (Rust porting contract)', () => {
    const fixture = JSON.parse(fs.readFileSync(fixturePath, 'utf8'));
    ok(fixture.k === 8 && fixture.w === 8, 'fixture must pin k=8 w=8');
    ok(fixture.vectors.length >= 10, 'expected at least 10 vectors');
    for (const v of fixture.vectors) {
      const { canonical, tokens } = fpr.normalize(v.input);
      ok(canonical === v.canonical, `${v.name}: canonical drifted`);
      assert.deepStrictEqual(tokens, v.tokens, `${v.name}: tokens drifted`);
      const shingles = fpr.shinglesOf(tokens, fixture.k);
      const hashes = shingles.map((s) => fpr.fnv1a64(s).toString());
      assert.deepStrictEqual(hashes, v.shingleHashes, `${v.name}: shingle hashes drifted`);
      const result = fpr.fingerprint(v.input, { k: fixture.k, w: fixture.w });
      ok(result.tokenCount === v.tokenCount, `${v.name}: tokenCount drifted`);
      ok(result.shingleCount === v.shingleCount, `${v.name}: shingleCount drifted`);
      assert.deepStrictEqual(
        fpr.serializeFingerprints(result.fingerprints),
        v.fingerprints,
        `${v.name}: winnowed fingerprints drifted`
      );
    }
    return `${fixture.vectors.length} vectors bit-exact`;
  });

  await check('F07', 'determinism: two runs over the same input are deeply equal', () => {
    const a = fpr.fingerprint(BASE_DOC);
    const b = fpr.fingerprint(BASE_DOC);
    assert.deepStrictEqual(a, b);
    ok(a.fingerprints.length > 0, 'expected non-empty fingerprints');
    return `${a.fingerprints.length} fingerprints, identical across runs`;
  });

  // ============ C. Detection bands ============
  const baseFp = fpr.fingerprint(BASE_DOC).fingerprints;

  await check('F08', 'containment(base, base) = 1', () => {
    const c = fpr.containment(baseFp, baseFp);
    ok(c === 1, `expected 1, got ${c}`);
    return `1.0 over ${baseFp.length} fingerprints`;
  });

  await check('F09', 'reformatted variant (case/punctuation/whitespace) > 0.95', () => {
    const c = fpr.containment(baseFp, fpr.fingerprint(REFORMATTED_DOC).fingerprints);
    ok(c > 0.95, `expected > 0.95, got ${c}`);
    return `containment = ${c.toFixed(4)}`;
  });

  await check('F10', 'one new paragraph appended keeps containment of base > 0.9', () => {
    const c = fpr.containment(baseFp, fpr.fingerprint(APPENDED_DOC).fingerprints);
    ok(c > 0.9, `expected > 0.9, got ${c}`);
    return `containment = ${c.toFixed(4)}`;
  });

  await check('F11', 'deleting ~25% of sentences lands in (0.6, 0.9)', () => {
    const c = fpr.containment(baseFp, fpr.fingerprint(DELETED_DOC).fingerprints);
    ok(c > 0.6 && c < 0.9, `expected 0.6 < c < 0.9, got ${c}`);
    return `containment = ${c.toFixed(4)}`;
  });

  await check('F12', 'fully rewritten text (same topic, new wording) < 0.2', () => {
    const c = fpr.containment(baseFp, fpr.fingerprint(REWRITTEN_DOC).fingerprints);
    ok(c < 0.2, `expected < 0.2, got ${c}`);
    return `containment = ${c.toFixed(4)}`;
  });

  await check('F13', 'similarity returns { containment, coverage }; empty sets fail secure to 0', () => {
    const partFp = fpr.fingerprint(DELETED_DOC).fingerprints;
    const s = fpr.similarity(baseFp, partFp);
    ok(s.containment === fpr.containment(baseFp, partFp), 'containment must agree');
    ok(s.coverage > 0 && s.coverage <= 1, `coverage out of range: ${s.coverage}`);
    // DELETED_DOC is a pure subset of base → nearly all its material is protected.
    ok(s.coverage > 0.9, `expected coverage > 0.9 for a subset doc, got ${s.coverage}`);
    ok(fpr.containment([], baseFp) === 0, 'empty protected set must give 0, not match-everything');
    assert.deepStrictEqual(fpr.similarity([], []), { containment: 0, coverage: 0 });
    return `containment=${s.containment.toFixed(4)} coverage=${s.coverage.toFixed(4)}`;
  });

  await check('F14', 'hashes are signed BigInts; serialized form is JSON-safe strings', () => {
    const r = fpr.fingerprint(BASE_DOC);
    for (const f of r.fingerprints) {
      ok(typeof f.hash === 'bigint', 'hash must be BigInt');
      ok(f.hash >= -(2n ** 63n) && f.hash < 2n ** 63n, 'hash must fit signed 64-bit (BIGINT)');
      ok(Number.isInteger(f.seq) && f.seq >= 0, 'seq must be a non-negative integer');
    }
    const ser = fpr.serializeFingerprints(r.fingerprints);
    const json = JSON.stringify(ser); // throws if any BigInt leaks through
    ok(ser.every((f) => typeof f.hash === 'string'), 'serialized hashes must be strings');
    ok(json.length > 0, 'must serialize');
    return `${ser.length} entries round-trip as strings`;
  });

  console.log(`\n${passed} passed, ${failed} failed\n`);
  fs.writeFileSync(
    path.join(__dirname, '.fingerprint-results.json'),
    JSON.stringify({ generatedAt: new Date().toISOString(), passed, failed, results }, null, 2)
  );
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
