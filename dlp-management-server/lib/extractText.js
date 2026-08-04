'use strict';
// =====================================================================
// Bounded-format text extraction (content-inspection groundwork)
//
// Turns a file buffer into plain text so later policy layers (keyword /
// fingerprint matching) can inspect content without ever shelling out or
// touching the network — this must run air-gapped. v1 supports a BOUNDED
// set of formats; anything else is refused loudly:
//   plain text  — .txt .md .csv .log + common source extensions (UTF-8,
//                 with UTF-8 / UTF-16LE / UTF-16BE BOM handling)
//   .docx/.xlsx/.pptx — OOXML zips, read via yauzl, text pulled from the
//                 relevant XML parts with a narrow regex (v1 — no XML DOM)
//   .pdf        — text layer only, via pdf-parse (no OCR)
//   .zip        — recurse into supported members (depth/size bounded)
//
// Failure model: every refusal is an UnreadableError with a machine
// reason so callers can decide policy (e.g. treat 'encrypted-container'
// as a policy violation, 'unsupported-format' as pass-through):
//   unsupported-format | binary-content | encrypted-container |
//   no-text-layer | corrupt-container | too-large
//
// Bombs and abuse are bounded: 100MB input cap, zip recursion depth cap,
// per-member and total-extracted-text caps, streamed inflation with a
// hard byte ceiling (a lying zip header cannot balloon memory).
//
// NEVER log extracted text or buffers here or in callers — document
// content is exactly the sensitive data this product exists to protect.
// =====================================================================
const yauzl = require('yauzl');
const { PDFParse } = require('pdf-parse');

const MAX_BUFFER_BYTES = 100 * 1024 * 1024; // reject anything larger outright
const ZIP_MAX_DEPTH = 3; // zip-in-zip nesting cap (top-level zip = depth 1)
const ZIP_MEMBER_CAP_BYTES = 20 * 1024 * 1024; // per-member inflated cap
const ZIP_TOTAL_TEXT_CAP = 10 * 1024 * 1024; // total extracted text cap (chars)

// Plain-text family: decoded as UTF-8 (BOM-aware). Deliberately a closed
// list — "looks like text" sniffing is how binary junk sneaks in.
const TEXT_EXTENSIONS = new Set([
  'txt', 'md', 'markdown', 'csv', 'tsv', 'log',
  // common source / config extensions
  'js', 'mjs', 'cjs', 'jsx', 'ts', 'tsx', 'json', 'xml', 'html', 'htm', 'css',
  'py', 'java', 'c', 'h', 'cpp', 'hpp', 'cc', 'cs', 'go', 'rs', 'rb', 'php',
  'pl', 'sh', 'bash', 'ps1', 'psm1', 'bat', 'cmd', 'sql', 'yaml', 'yml',
  'ini', 'cfg', 'conf', 'toml', 'properties', 'env',
]);

class UnreadableError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'UnreadableError';
    this.reason = reason; // machine-readable; message === reason
    this.unreadable = true;
  }
}

// ---------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------

function extensionOf(filename) {
  const base = String(filename || '').replace(/\\/g, '/').split('/').pop() || '';
  const dot = base.lastIndexOf('.');
  if (dot <= 0) return ''; // no extension (dotfiles like ".env" are unsupported in v1)
  return base.slice(dot + 1).toLowerCase();
}

// Decode ONLY the five predefined XML entities (v1 scope — OOXML writers
// escape text content with exactly these).
const XML_ENTITIES = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
function decodeXmlEntities(s) {
  return s.replace(/&(amp|lt|gt|quot|apos);/g, (_, name) => XML_ENTITIES[name]);
}

// OLE/CFB magic — password-protected OOXML files are wrapped in a CFB
// container (plain OOXML is a zip). Seeing this under a .docx/.xlsx/.pptx
// name means "encrypted", not "legacy binary office".
function isCfb(buffer) {
  return (
    buffer.length >= 4 &&
    buffer[0] === 0xd0 && buffer[1] === 0xcf && buffer[2] === 0x11 && buffer[3] === 0xe0
  );
}

// UTF-8 (BOM-aware) decode with sanity checks. NUL bytes or invalid UTF-8
// mean "this is not text" — refuse rather than emit mojibake the policy
// engine would silently fail to match against.
const UTF8_STRICT = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false });
function decodePlainText(buffer) {
  // UTF-16 BOMs first (a UTF-16 file is FULL of NUL bytes — legitimate).
  if (buffer.length >= 2 && buffer[0] === 0xff && buffer[1] === 0xfe) {
    const body = buffer.subarray(2);
    if (body.length % 2 !== 0) throw new UnreadableError('binary-content');
    return body.toString('utf16le');
  }
  if (buffer.length >= 2 && buffer[0] === 0xfe && buffer[1] === 0xff) {
    const body = Buffer.from(buffer.subarray(2)); // copy — swap16 mutates
    if (body.length % 2 !== 0) throw new UnreadableError('binary-content');
    body.swap16();
    return body.toString('utf16le');
  }
  if (buffer.includes(0x00)) throw new UnreadableError('binary-content');
  try {
    return UTF8_STRICT.decode(buffer); // fatal:true throws on invalid UTF-8
  } catch (err) {
    throw new UnreadableError('binary-content');
  }
}

// ---------------------------------------------------------------------
// zip plumbing (yauzl, promisified, bounded)
// ---------------------------------------------------------------------

// Read selected members of a zip buffer into memory, in archive order.
// * ANY entry with the encryption bit (general-purpose flag 0x1) set makes
//   the whole container 'encrypted-container' — fail secure, no partials.
// * Members whose (claimed or actual) inflated size exceeds perFileCap are
//   skipped via `oversized: true` — the stream is hard-capped, so a lying
//   size field cannot balloon memory.
async function readZipEntries(buffer, shouldRead, perFileCap = ZIP_MEMBER_CAP_BYTES) {
  let zipfile;
  try {
    zipfile = await yauzl.fromBufferPromise(buffer, { lazyEntries: true });
  } catch (err) {
    throw new UnreadableError('corrupt-container');
  }
  const out = [];
  try {
    await new Promise((resolve, reject) => {
      zipfile.on('error', () => reject(new UnreadableError('corrupt-container')));
      zipfile.on('end', resolve);
      zipfile.on('entry', (entry) => {
        (async () => {
          if ((entry.generalPurposeBitFlag & 0x1) !== 0) {
            throw new UnreadableError('encrypted-container');
          }
          const name = entry.fileName;
          if (name.endsWith('/') || !shouldRead(name)) {
            return; // directory or not wanted — skip without inflating
          }
          if (entry.uncompressedSize > perFileCap) {
            out.push({ name, data: null, oversized: true });
            return;
          }
          const stream = await zipfile.openReadStreamPromise(entry);
          const data = await collectStream(stream, perFileCap);
          out.push(data === null ? { name, data: null, oversized: true } : { name, data });
        })()
          .then(() => zipfile.readEntry())
          .catch(reject);
      });
      zipfile.readEntry();
    });
  } finally {
    zipfile.close();
  }
  return out;
}

// Drain a stream into a Buffer with a hard byte cap. Returns null if the
// cap is exceeded (caller treats the member as oversized and skips it).
function collectStream(stream, maxBytes) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    stream.on('data', (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        stream.destroy();
        resolve(null);
        return;
      }
      chunks.push(chunk);
    });
    stream.on('end', () => resolve(Buffer.concat(chunks)));
    stream.on('error', () => reject(new UnreadableError('corrupt-container')));
  });
}

// ---------------------------------------------------------------------
// per-format extractors
// ---------------------------------------------------------------------

// Pull the text of every <tag> element from OOXML markup, in document
// order. Regex-based on purpose (v1): no XML parser dependency, and the
// OOXML text elements we target never nest themselves.
function xmlElementText(xml, tag) {
  const re = new RegExp(`<${tag}(?:\\s[^>]*)?>([\\s\\S]*?)</${tag}>`, 'g');
  const parts = [];
  let m;
  while ((m = re.exec(xml)) !== null) parts.push(decodeXmlEntities(m[1]));
  return parts;
}

// .docx — word/document.xml (+ headers/footers). <w:t> holds the runs;
// </w:p> ends a paragraph, which we render as a newline.
async function extractDocx(buffer) {
  const wanted = (name) =>
    name === 'word/document.xml' || /^word\/(?:header|footer)\d*\.xml$/.test(name);
  const entries = await readZipEntries(buffer, wanted);
  const byName = new Map(entries.filter((e) => e.data).map((e) => [e.name, e.data]));
  if (!byName.has('word/document.xml')) throw new UnreadableError('corrupt-container');

  const partNames = [
    'word/document.xml',
    ...[...byName.keys()].filter((n) => n !== 'word/document.xml').sort(),
  ];
  const paragraphs = [];
  for (const name of partNames) {
    const xml = byName.get(name).toString('utf8');
    for (const chunk of xml.split(/<\/w:p>/)) {
      const runs = xmlElementText(chunk, 'w:t').join('');
      if (runs.length) paragraphs.push(runs);
    }
  }
  return paragraphs.join('\n');
}

// .xlsx — the shared-string table plus inline strings in the sheets.
// (Numbers/formulas are not text content and are out of v1 scope.)
async function extractXlsx(buffer) {
  const wanted = (name) =>
    name === 'xl/sharedStrings.xml' || /^xl\/worksheets\/sheet[^/]*\.xml$/.test(name);
  const entries = await readZipEntries(buffer, wanted);
  const usable = entries.filter((e) => e.data);
  if (usable.length === 0) throw new UnreadableError('corrupt-container');

  const parts = [];
  for (const { name, data } of usable) {
    const xml = data.toString('utf8');
    if (name === 'xl/sharedStrings.xml') {
      parts.push(...xmlElementText(xml, 't'));
    } else {
      // inline strings live in <is><t>…</t></is> cells; only pull those
      for (const inline of xml.match(/<is>[\s\S]*?<\/is>/g) || []) {
        parts.push(...xmlElementText(inline, 't'));
      }
    }
  }
  return parts.join('\n');
}

// .pptx — every ppt/slides/slideN.xml in slide order; <a:t> holds the text.
async function extractPptx(buffer) {
  const slideRe = /^ppt\/slides\/slide(\d+)\.xml$/;
  const entries = await readZipEntries(buffer, (name) => slideRe.test(name));
  const usable = entries.filter((e) => e.data);
  if (usable.length === 0) throw new UnreadableError('corrupt-container');

  usable.sort((a, b) => Number(a.name.match(slideRe)[1]) - Number(b.name.match(slideRe)[1]));
  const slides = usable.map(({ data }) => xmlElementText(data.toString('utf8'), 'a:t').join('\n'));
  return slides.join('\n');
}

// .pdf — text layer only (no OCR in v1; scanned documents refuse loudly so
// policy can decide, instead of silently matching nothing).
async function extractPdf(buffer) {
  let parser;
  let text;
  try {
    parser = new PDFParse({ data: Uint8Array.from(buffer) });
    const result = await parser.getText();
    // Join per-page text ourselves — result.text decorates output with
    // "-- 1 of N --" page separators, which would defeat the empty-text
    // (scanned document) check and pollute policy matching.
    text = Array.isArray(result.pages)
      ? result.pages.map((p) => p.text).join('\n')
      : result.text;
  } catch (err) {
    if (err && err.name === 'PasswordException') {
      throw new UnreadableError('encrypted-container');
    }
    throw new UnreadableError('corrupt-container');
  } finally {
    if (parser) await parser.destroy().catch(() => {});
  }
  if (!text || !text.trim()) throw new UnreadableError('no-text-layer');
  return text;
}

// .zip — recurse into supported members, bounded (see caps at top).
// Unsupported/unreadable members are skipped SILENTLY (a zip full of .exes
// legitimately yields the text of just its one .txt) — but encryption
// anywhere inside still refuses the whole container, fail secure.
async function extractZip(buffer, depth, budget) {
  const entries = await readZipEntries(buffer, () => true);
  const pieces = [];
  for (const { name, data, oversized } of entries) {
    if (oversized || !data) continue;
    if (budget.remaining <= 0) break;
    const ext = extensionOf(name);
    if (ext === 'zip' && depth >= ZIP_MAX_DEPTH) continue; // depth cap: skip, don't recurse
    try {
      const text = await extractByExtension(data, name, ext, depth + (ext === 'zip' ? 1 : 0), budget);
      if (text.length) {
        const clipped = text.length > budget.remaining ? text.slice(0, budget.remaining) : text;
        budget.remaining -= clipped.length;
        pieces.push(clipped);
      }
    } catch (err) {
      if (err instanceof UnreadableError && err.reason !== 'encrypted-container') {
        continue; // unsupported/binary/corrupt member — skip silently
      }
      throw err; // encryption anywhere = refuse whole container
    }
  }
  return pieces.join('\n');
}

// ---------------------------------------------------------------------
// dispatch
// ---------------------------------------------------------------------

const OOXML_EXTS = new Set(['docx', 'xlsx', 'pptx']);

async function extractByExtension(buffer, filename, ext, depth, budget) {
  if (TEXT_EXTENSIONS.has(ext)) return decodePlainText(buffer);
  if (OOXML_EXTS.has(ext)) {
    if (isCfb(buffer)) throw new UnreadableError('encrypted-container');
    if (ext === 'docx') return extractDocx(buffer);
    if (ext === 'xlsx') return extractXlsx(buffer);
    return extractPptx(buffer);
  }
  if (ext === 'pdf') return extractPdf(buffer);
  if (ext === 'zip') return extractZip(buffer, depth, budget);
  throw new UnreadableError('unsupported-format');
}

function formatOf(ext) {
  if (TEXT_EXTENSIONS.has(ext)) return 'text';
  return ext; // docx | xlsx | pptx | pdf | zip
}

// Extract plain text from a file buffer. Resolves { text, format } where
// format is 'text' | 'docx' | 'xlsx' | 'pptx' | 'pdf' | 'zip'; throws
// UnreadableError (err.reason) for anything outside the bounded v1 scope.
async function extractText(buffer, filename) {
  if (!Buffer.isBuffer(buffer)) {
    throw new TypeError('extractText: buffer must be a Buffer');
  }
  if (buffer.length > MAX_BUFFER_BYTES) throw new UnreadableError('too-large');

  const ext = extensionOf(filename);
  const budget = { remaining: ZIP_TOTAL_TEXT_CAP };
  const text = await extractByExtension(buffer, filename, ext, 1, budget);
  return { text, format: formatOf(ext) };
}

module.exports = {
  extractText,
  UnreadableError,
  // bounds exported for callers/tests (documented limits, not tunables)
  MAX_BUFFER_BYTES,
  ZIP_MAX_DEPTH,
  ZIP_MEMBER_CAP_BYTES,
  ZIP_TOTAL_TEXT_CAP,
};
