'use strict';
// =====================================================================
// EDM (Exact Data Match) — typed cell normalization, salted hashing, and
// CSV ingestion (fingerprinting doc §4). Answers "does this text contain
// actual ROWS from an authoritative dataset (personnel, payroll, assets)?".
//
// Pipeline per cell:
//   normalizeField — canonical form per declared type (text|id|number|date)
//   hashField      — SHA-256(salt || uint16BE(fieldId) || utf8(value)),
//                    first 8 bytes big-endian → SIGNED 64-bit BigInt
//                    (BigInt.asIntN — same BIGINT-column convention as
//                    lib/fingerprint.js; serialize as strings, never JSON).
//
// The salt is per-source, 32 random bytes, and is what makes offline
// dictionary attacks on low-entropy cells (names, dates) expensive. It is
// a mitigation, not perfect secrecy — documented, not hidden.
//
// DETERMINISM IS A CONTRACT: the Rust agent ports normalizeField/hashField
// against the same rules — changing them invalidates every stored hash.
//
// Pure computation: no DB, no I/O, no state. The caller (worker) owns
// storage; the plaintext CSV must never be retained after ingestion.
// =====================================================================
const crypto = require('crypto');
const { normalize } = require('./fingerprint');

const FIELD_TYPES = ['text', 'id', 'number', 'date'];

// ---------------------------------------------------------------------
// 1. Typed normalization. Returns the canonical string, or null when the
//    cell is empty/unparseable — null cells are SKIPPED (never hashed),
//    so junk data cannot become an accidental match-everything hash.
// ---------------------------------------------------------------------
const MONTHS = {
  jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6,
  jul: 7, aug: 8, sep: 9, oct: 10, nov: 11, dec: 12,
};

function daysInMonth(year, month) {
  return new Date(Date.UTC(year, month, 0)).getUTCDate();
}

function toIsoDate(day, month, year) {
  if (month < 1 || month > 12) return null;
  if (day < 1 || day > daysInMonth(year, month)) return null;
  const mm = String(month).padStart(2, '0');
  const dd = String(day).padStart(2, '0');
  return `${year}-${mm}-${dd}`;
}

// dd/mm/yyyy, dd-mm-yyyy, yyyy-mm-dd, or "dd Mon yyyy" → 'yyyy-mm-dd';
// null if unparseable (bad shape, bad month, day out of range).
function normalizeDate(s) {
  let m = /^(\d{1,2})[/-](\d{1,2})[/-](\d{4})$/.exec(s);
  if (m) return toIsoDate(Number(m[1]), Number(m[2]), Number(m[3]));
  m = /^(\d{4})-(\d{1,2})-(\d{1,2})$/.exec(s);
  if (m) return toIsoDate(Number(m[3]), Number(m[2]), Number(m[1]));
  m = /^(\d{1,2})\s+([a-zA-Z]{3,})\s+(\d{4})$/.exec(s);
  if (m) {
    const month = MONTHS[m[2].slice(0, 3).toLowerCase()];
    if (!month || (m[2].length > 3 && !isFullMonthName(m[2], month))) return null;
    return toIsoDate(Number(m[1]), month, Number(m[3]));
  }
  return null;
}

const MONTH_NAMES = ['january', 'february', 'march', 'april', 'may', 'june',
  'july', 'august', 'september', 'october', 'november', 'december'];
function isFullMonthName(word, month) {
  return MONTH_NAMES[month - 1] === word.toLowerCase();
}

// Canonical digit string: grouping separators (commas, spaces, underscores)
// stripped, no leading zeros, fraction kept but trailing zeros dropped
// ("1,234.50" → "1234.5", "007" → "7", "-0" → "0"). Null if not a number.
function normalizeNumber(s) {
  const stripped = s.replace(/[,\s_]/g, '');
  const m = /^([+-]?)(\d+)(?:\.(\d+))?$/.exec(stripped);
  if (!m) return null;
  const sign = m[1] === '-' ? '-' : '';
  const int = m[2].replace(/^0+(?=\d)/, '');
  let frac = m[3] ? m[3].replace(/0+$/, '') : '';
  let out = frac ? `${int}.${frac}` : int;
  if (out === '0') return '0'; // never '-0'
  return sign + out;
}

function normalizeField(value, type) {
  if (!FIELD_TYPES.includes(type)) {
    throw new Error(`unknown field type: ${type}`);
  }
  if (value == null) return null;
  const s = String(value).trim();
  if (s === '') return null;
  switch (type) {
    case 'text': {
      // Exactly the IDM canonicalisation (NFKC → lowercase → punctuation
      // runs collapse to one space) — reused, never duplicated.
      const { canonical } = normalize(s);
      return canonical === '' ? null : canonical;
    }
    case 'id': {
      // Serial/ID numbers: formatting varies wildly — keep only the
      // alphanumerics, uppercased ("ab-12 34" → "AB1234").
      const out = s.normalize('NFKC').replace(/[^\p{L}\p{N}]+/gu, '').toUpperCase();
      return out === '' ? null : out;
    }
    case 'number':
      return normalizeNumber(s);
    case 'date':
      return normalizeDate(s);
    /* istanbul ignore next -- unreachable, types validated above */
    default:
      return null;
  }
}

// ---------------------------------------------------------------------
// 2. Salted hash: first 8 bytes (big-endian) of
//    SHA-256(salt || uint16BE(fieldId) || utf8(normalizedValue)),
//    exposed SIGNED for the BIGINT column. fieldId is bound into the hash
//    so 'smith' in a name column never collides with 'smith' elsewhere.
// ---------------------------------------------------------------------
function hashField(salt, fieldId, normalizedValue) {
  if (!Buffer.isBuffer(salt) || salt.length === 0) {
    throw new Error('hashField expects a salt Buffer');
  }
  if (!Number.isInteger(fieldId) || fieldId < 0 || fieldId > 0xffff) {
    throw new Error('fieldId must be an integer in [0, 65535]');
  }
  const fid = Buffer.alloc(2);
  fid.writeUInt16BE(fieldId, 0);
  const digest = crypto
    .createHash('sha256')
    .update(salt)
    .update(fid)
    .update(Buffer.from(String(normalizedValue), 'utf8'))
    .digest();
  return BigInt.asIntN(64, digest.readBigUInt64BE(0));
}

// ---------------------------------------------------------------------
// 3. CSV parsing — RFC-4180-enough: comma-separated, optional "quoted"
//    fields with "" escapes, embedded commas/quotes/newlines inside
//    quotes, CRLF or LF row endings. Returns array of rows (arrays of
//    strings). Malformed quoting throws (fail secure — a half-parsed
//    dataset must not silently produce a half-protected index).
// ---------------------------------------------------------------------
function parseCsv(text) {
  const s = String(text == null ? '' : text);
  const rows = [];
  let row = [];
  let field = '';
  let inQuotes = false;
  let i = 0;
  const pushField = () => { row.push(field); field = ''; };
  const pushRow = () => { pushField(); rows.push(row); row = []; };
  while (i < s.length) {
    const c = s[i];
    if (inQuotes) {
      if (c === '"') {
        if (s[i + 1] === '"') { field += '"'; i += 2; continue; } // escaped quote
        inQuotes = false; i++;
        continue;
      }
      field += c; i++;
      continue;
    }
    if (c === '"') {
      if (field !== '') throw new Error(`csv parse error: unexpected quote at offset ${i}`);
      inQuotes = true; i++;
      continue;
    }
    if (c === ',') { pushField(); i++; continue; }
    if (c === '\r' && s[i + 1] === '\n') { pushRow(); i += 2; continue; }
    if (c === '\n' || c === '\r') { pushRow(); i++; continue; }
    field += c; i++;
  }
  if (inQuotes) throw new Error('csv parse error: unterminated quoted field');
  // Final field/row unless the text ended exactly on a row terminator.
  if (field !== '' || row.length > 0) pushRow();
  return rows;
}

// ---------------------------------------------------------------------
// 4. Ingestion: CSV text + schema ([{name, type, primary}]) + per-source
//    salt Buffer → { entries: [{rowId, fieldId, hash}], rowCount }.
//    * header row must match the schema field names (order and spelling,
//    case-insensitive) — a mismatched export must fail loudly;
//    * rowId is 1-based over DATA rows; fieldId is the schema index;
//    * empty cells and null-normalized values are skipped;
//    * ragged rows (wrong column count) throw.
//    Errors carry err.reason (a code, never cell content) for the worker.
// ---------------------------------------------------------------------
function ingestError(reason, message) {
  const err = new Error(message);
  err.reason = reason;
  err.permanent = true; // bad data will not fix itself on retry
  return err;
}

function ingestCsv(csvText, schema, salt) {
  if (!Array.isArray(schema) || schema.length === 0) {
    throw ingestError('bad-schema', 'schema must be a non-empty array');
  }
  let rows;
  try {
    rows = parseCsv(csvText);
  } catch (err) {
    throw ingestError('csv-parse-error', err.message);
  }
  // Drop trailing fully-empty rows (a trailing newline is not a data row).
  while (rows.length > 0 && rows[rows.length - 1].every((c) => c.trim() === '')) {
    rows.pop();
  }
  if (rows.length === 0) throw ingestError('csv-empty', 'csv has no header row');

  const header = rows[0].map((h) => h.trim().toLowerCase());
  const expected = schema.map((f) => String(f.name).trim().toLowerCase());
  if (header.length !== expected.length || header.some((h, idx) => h !== expected[idx])) {
    throw ingestError('csv-header-mismatch', 'csv header does not match the source schema');
  }

  const entries = [];
  for (let r = 1; r < rows.length; r++) {
    const cells = rows[r];
    if (cells.length !== schema.length) {
      throw ingestError('csv-ragged-row', `row ${r} has ${cells.length} cells, expected ${schema.length}`);
    }
    for (let f = 0; f < schema.length; f++) {
      const value = normalizeField(cells[f], schema[f].type);
      if (value === null) continue; // empty or unparseable cell — skip
      entries.push({ rowId: r, fieldId: f, hash: hashField(salt, f, value) });
    }
  }
  return { entries, rowCount: rows.length - 1 };
}

module.exports = {
  normalizeField,
  hashField,
  parseCsv,
  ingestCsv,
  FIELD_TYPES,
};
