'use strict';
// =====================================================================
// Tests for lib/extractText.js — bounded-format text extraction.
//
// No DB and no HTTP needed: the extractor is a pure library, so this
// harness just feeds it the generated fixtures and asserts on the text
// (positive cases) and on UnreadableError reasons (negative cases).
//
// Fixtures live in test/fixtures/extract/ and are (re)built by:
//   node test/fixtures/extract/gen-fixtures.js
// This test regenerates them up front so it never runs against stale
// samples.
//
// Run: node test/extract.test.js
// =====================================================================
const fs = require('fs');
const path = require('path');
const assert = require('assert');
const { execFileSync } = require('child_process');

const { extractText, UnreadableError } = require('../lib/extractText');

const FIXTURES = path.join(__dirname, 'fixtures', 'extract');

// Regenerate fixtures so the test is self-contained and reproducible.
execFileSync(process.execPath, [path.join(FIXTURES, 'gen-fixtures.js')], { stdio: 'ignore' });

function fixture(name) {
  return fs.readFileSync(path.join(FIXTURES, name));
}

async function extractFixture(name) {
  return extractText(fixture(name), name);
}

// Run fn and assert it throws UnreadableError with the given reason.
async function expectUnreadable(fn, reason) {
  try {
    await fn();
  } catch (err) {
    assert(err instanceof UnreadableError, `expected UnreadableError, got ${err.name}: ${err.message}`);
    assert.strictEqual(err.reason, reason, `expected reason '${reason}', got '${err.reason}'`);
    return err;
  }
  assert.fail(`expected UnreadableError('${reason}') but nothing was thrown`);
}

// ---------------------------------------------------------------------
// harness (same shape as test/enrollmentTokens.test.js)
// ---------------------------------------------------------------------
const results = [];
let passed = 0;
let failed = 0;

async function check(id, name, fn) {
  try {
    const detail = await fn();
    results.push({ id, name, status: 'PASS', detail: detail || '' });
    passed++;
    console.log(`PASS ${id} ${name}`);
  } catch (err) {
    results.push({ id, name, status: 'FAIL', detail: err.message });
    failed++;
    console.log(`FAIL ${id} ${name} — ${err.message}`);
  }
}

async function main() {
  // ---- plain text family -------------------------------------------

  await check('X01', 'plain .txt extracts as UTF-8, format "text"', async () => {
    const { text, format } = await extractFixture('sample.txt');
    assert.strictEqual(format, 'text');
    assert(text.includes('OPERATION LIONHEART'), 'missing expected substring');
    assert(text.includes('Second line.'), 'missing second line');
    return `${text.length} chars`;
  });

  await check('X02', 'UTF-8 BOM is stripped and accents survive', async () => {
    const { text } = await extractFixture('sample-bom.txt');
    assert(!text.startsWith('﻿'), 'BOM leaked into text');
    assert(text.includes('café résumé naïve'), 'accented text mangled');
    return 'BOM stripped';
  });

  await check('X03', 'UTF-16LE BOM decodes', async () => {
    const { text } = await extractFixture('sample-utf16le.txt');
    assert(text.includes('WIDECHAR SECRET'), 'utf16le not decoded');
    return 'ok';
  });

  await check('X04', 'UTF-16BE BOM decodes', async () => {
    const { text } = await extractFixture('sample-utf16be.txt');
    assert(text.includes('BIGENDIAN SECRET'), 'utf16be not decoded');
    return 'ok';
  });

  await check('X05', '.md and .csv extract as text', async () => {
    const md = await extractFixture('sample.md');
    assert(md.text.includes('KEYWORD_MD') && md.format === 'text');
    const csv = await extractFixture('sample.csv');
    assert(csv.text.includes('CSV_ROW_ALPHA') && csv.format === 'text');
    return 'ok';
  });

  await check('X06', '.txt with NUL bytes -> binary-content', async () => {
    await expectUnreadable(() => extractFixture('binary.txt'), 'binary-content');
    return 'refused';
  });

  await check('X07', '.txt with invalid UTF-8 -> binary-content', async () => {
    await expectUnreadable(() => extractFixture('badutf8.txt'), 'binary-content');
    return 'refused';
  });

  // ---- OOXML --------------------------------------------------------

  await check('X08', '.docx extracts body, header, footer; entities decoded', async () => {
    const { text, format } = await extractFixture('sample.docx');
    assert.strictEqual(format, 'docx');
    assert(text.includes('PROJECT AEGIS'), 'body missing');
    assert(text.includes('HEADER-MARKING-SECRET'), 'header part missing');
    assert(text.includes('FOOTER-PAGE-MARK'), 'footer part missing');
    assert(text.includes('fish & chips <classified> "q" \'a\''), 'XML entities not decoded');
    assert(!text.includes('&amp;'), 'entity left encoded');
    return `${text.length} chars`;
  });

  await check('X09', '.docx paragraphs are newline-separated', async () => {
    const { text } = await extractFixture('sample.docx');
    const lines = text.split('\n');
    assert(lines.some((l) => l.includes('PROJECT AEGIS')), 'para 1 not on own line');
    assert(lines.some((l) => l.includes('fish & chips')), 'para 2 not on own line');
    assert(!lines.some((l) => l.includes('PROJECT AEGIS') && l.includes('fish & chips')),
      'paragraphs ran together');
    return `${lines.length} lines`;
  });

  await check('X10', '.xlsx extracts shared strings and inline strings', async () => {
    const { text, format } = await extractFixture('sample.xlsx');
    assert.strictEqual(format, 'xlsx');
    assert(text.includes('SHARED-STRING-ONE'), 'shared string missing');
    assert(text.includes('Budget & forecast'), 'entity in shared string not decoded');
    assert(text.includes('INLINE-CELL-TEXT'), 'inline sheet string missing');
    return 'ok';
  });

  await check('X11', '.pptx extracts slides in order, newline-separated', async () => {
    const { text, format } = await extractFixture('sample.pptx');
    assert.strictEqual(format, 'pptx');
    const one = text.indexOf('SLIDE-ONE-TITLE');
    const two = text.indexOf('SLIDE-TWO-BODY');
    assert(one !== -1 && two !== -1, 'slide text missing');
    assert(one < two, 'slides out of order');
    assert(text.slice(one, two).includes('\n'), 'slides not newline-separated');
    return 'ok';
  });

  // ---- PDF ----------------------------------------------------------

  await check('X12', '.pdf text layer extracts', async () => {
    const { text, format } = await extractFixture('sample.pdf');
    assert.strictEqual(format, 'pdf');
    assert(text.includes('PDF-TEXT-LAYER-MARK'), 'pdf text missing');
    return 'ok';
  });

  await check('X13', 'scanned .pdf (no text layer) -> no-text-layer', async () => {
    await expectUnreadable(() => extractFixture('scanned.pdf'), 'no-text-layer');
    return 'refused';
  });

  // ---- zip recursion ------------------------------------------------

  await check('X14', '.zip recurses into supported members, skips others silently', async () => {
    const { text, format } = await extractFixture('nested.zip');
    assert.strictEqual(format, 'zip');
    assert(text.includes('TOP-LEVEL-TEXT'), 'top-level member missing');
    assert(text.includes('DEEP-NESTED-TEXT'), 'nested-zip member missing');
    assert(text.includes('ZIP-MD-MEMBER'), '.md member missing');
    assert(!text.includes('\u0000'), 'binary member leaked into text');
    return 'ok';
  });

  await check('X15', '.zip depth cap: level 3 reachable, level 4 skipped', async () => {
    const { text } = await extractFixture('deep.zip');
    assert(text.includes('LEVEL-THREE-TEXT'), 'depth-3 text should be reachable');
    assert(!text.includes('LEVEL-FOUR-TEXT'), 'depth-4 text should have been skipped');
    return 'ok';
  });

  // ---- encryption / corruption / bounds -----------------------------

  await check('X16', 'encrypted .zip (GP bit 0x1) -> encrypted-container', async () => {
    await expectUnreadable(() => extractFixture('encrypted.zip'), 'encrypted-container');
    return 'refused';
  });

  await check('X17', 'password-protected office file (CFB magic) -> encrypted-container', async () => {
    await expectUnreadable(() => extractFixture('protected.docx'), 'encrypted-container');
    return 'refused';
  });

  await check('X18', 'non-zip bytes under .docx name -> corrupt-container', async () => {
    await expectUnreadable(() => extractFixture('corrupt.docx'), 'corrupt-container');
    return 'refused';
  });

  await check('X19', 'unsupported extension -> unsupported-format', async () => {
    await expectUnreadable(
      () => extractText(Buffer.from('MZ fake executable'), 'tool.exe'),
      'unsupported-format'
    );
    await expectUnreadable(() => extractText(Buffer.from('no extension'), 'README'), 'unsupported-format');
    return 'refused';
  });

  await check('X20', 'buffer over 100MB -> too-large (checked before format dispatch)', async () => {
    const big = Buffer.alloc(100 * 1024 * 1024 + 1);
    await expectUnreadable(() => extractText(big, 'huge.txt'), 'too-large');
    return 'refused';
  });

  await check('X21', 'UnreadableError shape: Error subclass, reason === message', async () => {
    const err = await expectUnreadable(() => extractFixture('encrypted.zip'), 'encrypted-container');
    assert(err instanceof Error, 'not an Error subclass');
    assert.strictEqual(err.name, 'UnreadableError');
    assert.strictEqual(err.message, err.reason);
    return 'ok';
  });

  // ---- results ------------------------------------------------------

  console.log(`\n${passed} passed, ${failed} failed`);
  fs.writeFileSync(
    path.join(__dirname, '.extract-results.json'),
    JSON.stringify({ generatedAt: new Date().toISOString(), passed, failed, results }, null, 2)
  );
  process.exit(failed === 0 ? 0 : 1);
}

main().catch((err) => {
  console.error('test harness crashed:', err);
  process.exit(1);
});
