'use strict';
// =====================================================================
// Fixture generator for test/extract.test.js — run once (idempotent):
//   node test/fixtures/extract/gen-fixtures.js
//
// Builds every sample file from scratch so the repo carries no opaque
// binaries of unknown origin (this ships to defence customers — every
// byte in the tree must be explainable):
//   * OOXML (.docx/.xlsx/.pptx) and .zip fixtures via a minimal raw zip
//     writer (STORED entries only: local headers + central directory).
//   * A minimal hand-written PDF with one page and a Tj text operator
//     (offsets computed, valid xref) + a "scanned" PDF with no text layer.
//   * Plain-text variants with UTF-8 / UTF-16LE / UTF-16BE BOMs, a
//     binary .txt, a fake zip-encrypted archive (general-purpose bit 0x1),
//     and a fake CFB-wrapped "password-protected" docx.
// =====================================================================
const fs = require('fs');
const path = require('path');

const OUT = __dirname;

// ---------------------------------------------------------------------
// raw zip writer (STORED / method 0 only)
// ---------------------------------------------------------------------

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

function crc32(buf) {
  let c = 0xffffffff;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

// files: [{ name, data (Buffer|string), flags? }] — flags lets the
// encrypted-zip fixture set the encryption bit (0x1) without real crypto.
function buildZip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const f of files) {
    const name = Buffer.from(f.name, 'utf8');
    let data = Buffer.isBuffer(f.data) ? f.data : Buffer.from(f.data, 'utf8');
    const flags = f.flags || 0;
    const crc = crc32(data);
    const uncompressedSize = data.length;
    if (flags & 0x1) {
      // Encrypted STORED entries carry a 12-byte encryption header before
      // the (fake) ciphertext; compressed size includes it. Readers must
      // refuse on the flag alone, so the bytes themselves are arbitrary.
      data = Buffer.concat([Buffer.alloc(12, 0xaa), data]);
    }

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0); // local file header signature
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(flags, 6); // general-purpose bit flag
    local.writeUInt16LE(0, 8); // method 0 = STORED
    local.writeUInt16LE(0, 10); // mod time
    local.writeUInt16LE(0x21, 12); // mod date (1980-01-01)
    local.writeUInt32LE(crc, 14);
    local.writeUInt32LE(data.length, 18); // compressed size (raw + enc header)
    local.writeUInt32LE(uncompressedSize, 22); // uncompressed size
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28); // extra length
    locals.push(local, name, data);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0); // central directory signature
    central.writeUInt16LE(20, 4); // version made by
    central.writeUInt16LE(20, 6); // version needed
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(0, 10); // method
    central.writeUInt16LE(0, 12); // time
    central.writeUInt16LE(0x21, 14); // date
    central.writeUInt32LE(crc, 16);
    central.writeUInt32LE(data.length, 20); // compressed size
    central.writeUInt32LE(uncompressedSize, 24); // uncompressed size
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30); // extra length
    central.writeUInt16LE(0, 32); // comment length
    central.writeUInt16LE(0, 34); // disk number
    central.writeUInt16LE(0, 36); // internal attrs
    central.writeUInt32LE(0, 38); // external attrs
    central.writeUInt32LE(offset, 42); // local header offset
    centrals.push(central, name);

    offset += local.length + name.length + data.length;
  }

  const centralStart = offset;
  const centralBuf = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); // end-of-central-directory signature
  eocd.writeUInt16LE(0, 4); // disk number
  eocd.writeUInt16LE(0, 6); // central dir start disk
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(centralBuf.length, 12);
  eocd.writeUInt32LE(centralStart, 16);
  eocd.writeUInt16LE(0, 20); // comment length
  return Buffer.concat([...locals, centralBuf, eocd]);
}

// ---------------------------------------------------------------------
// minimal hand-written PDF (one page; text via a Tj operator)
// ---------------------------------------------------------------------

function buildPdf(textOrNull) {
  const stream =
    textOrNull === null ? '' : `BT /F1 12 Tf 72 720 Td (${textOrNull}) Tj ET`;
  const objects = [
    '<< /Type /Catalog /Pages 2 0 R >>',
    '<< /Type /Pages /Kids [3 0 R] /Count 1 >>',
    '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R ' +
      '/Resources << /Font << /F1 5 0 R >> >> >>',
    `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
    '<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>',
  ];

  let body = '%PDF-1.4\n';
  const offsets = [];
  objects.forEach((obj, i) => {
    offsets.push(body.length);
    body += `${i + 1} 0 obj\n${obj}\nendobj\n`;
  });

  const xrefStart = body.length;
  let xref = `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) xref += `${String(off).padStart(10, '0')} 00000 n \n`;
  const trailer =
    `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R >>\n` +
    `startxref\n${xrefStart}\n%%EOF\n`;
  return Buffer.from(body + xref + trailer, 'latin1');
}

// ---------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------

function write(name, data) {
  fs.writeFileSync(path.join(OUT, name), data);
  console.log('wrote', name, `(${data.length} bytes)`);
}

// -- plain text family
write('sample.txt', Buffer.from('Plain text fixture: OPERATION LIONHEART briefing.\nSecond line.\n', 'utf8'));
write('sample-bom.txt', Buffer.concat([
  Buffer.from([0xef, 0xbb, 0xbf]),
  Buffer.from('BOM text fixture: café résumé naïve.\n', 'utf8'),
]));
write('sample-utf16le.txt', Buffer.concat([
  Buffer.from([0xff, 0xfe]),
  Buffer.from('UTF-16LE fixture: WIDECHAR SECRET.\n', 'utf16le'),
]));
{
  const le = Buffer.from('UTF-16BE fixture: BIGENDIAN SECRET.\n', 'utf16le');
  le.swap16();
  write('sample-utf16be.txt', Buffer.concat([Buffer.from([0xfe, 0xff]), le]));
}
write('sample.md', Buffer.from('# Heading\n\nMarkdown fixture body with KEYWORD_MD.\n', 'utf8'));
write('sample.csv', Buffer.from('id,name\n1,CSV_ROW_ALPHA\n2,CSV_ROW_BETA\n', 'utf8'));
// .txt that is actually binary (NUL bytes) → binary-content
write('binary.txt', Buffer.from([0x50, 0x4b, 0x00, 0x01, 0x02, 0x00, 0xff, 0xfe, 0x00, 0x41]));
// .txt with invalid UTF-8 (lone continuation bytes), no NULs → binary-content
write('badutf8.txt', Buffer.from([0x68, 0x69, 0x20, 0xc3, 0x28, 0x80, 0x80, 0x21]));

// -- docx: body + header + footer, entities, two paragraphs
const docxDocument =
  '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
  '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>' +
  '<w:p><w:r><w:t>Docx body paragraph one: PROJECT AEGIS.</w:t></w:r></w:p>' +
  '<w:p><w:r><w:t xml:space="preserve">Entities: fish &amp; chips &lt;classified&gt; &quot;q&quot; &apos;a&apos;.</w:t></w:r></w:p>' +
  '</w:body></w:document>';
const docxHeader =
  '<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">' +
  '<w:p><w:r><w:t>HEADER-MARKING-SECRET</w:t></w:r></w:p></w:hdr>';
const docxFooter =
  '<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">' +
  '<w:p><w:r><w:t>FOOTER-PAGE-MARK</w:t></w:r></w:p></w:ftr>';
write('sample.docx', buildZip([
  { name: '[Content_Types].xml', data: '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>' },
  { name: 'word/document.xml', data: docxDocument },
  { name: 'word/header1.xml', data: docxHeader },
  { name: 'word/footer1.xml', data: docxFooter },
]));

// -- xlsx: shared strings + one sheet with an inline string
const sharedStrings =
  '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
  '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="2" uniqueCount="2">' +
  '<si><t>SHARED-STRING-ONE</t></si><si><t xml:space="preserve">Budget &amp; forecast</t></si></sst>';
const sheet1 =
  '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
  '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>' +
  '<row r="1"><c r="A1" t="s"><v>0</v></c>' +
  '<c r="B1" t="inlineStr"><is><t>INLINE-CELL-TEXT</t></is></c></row>' +
  '</sheetData></worksheet>';
write('sample.xlsx', buildZip([
  { name: 'xl/sharedStrings.xml', data: sharedStrings },
  { name: 'xl/worksheets/sheet1.xml', data: sheet1 },
]));

// -- pptx: two slides (order must come out 1 then 2)
function slideXml(text) {
  return (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
    '<p:sld xmlns:a="http://schemas.openxmlformats.org/drawingml/2006/main" ' +
    'xmlns:p="http://schemas.openxmlformats.org/presentationml/2006/main">' +
    `<p:cSld><p:spTree><p:sp><p:txBody><a:p><a:r><a:t>${text}</a:t></a:r></a:p>` +
    '</p:txBody></p:sp></p:spTree></p:cSld></p:sld>'
  );
}
write('sample.pptx', buildZip([
  { name: 'ppt/slides/slide1.xml', data: slideXml('SLIDE-ONE-TITLE') },
  { name: 'ppt/slides/slide2.xml', data: slideXml('SLIDE-TWO-BODY') },
]));

// -- pdf: real text layer / no text layer ("scanned")
write('sample.pdf', buildPdf('Hello PDF fixture PDF-TEXT-LAYER-MARK'));
write('scanned.pdf', buildPdf(null));

// -- zip recursion: txt + nested zip (with its own txt) + unsupported member
const innerZip = buildZip([{ name: 'deep.txt', data: 'DEEP-NESTED-TEXT level two.\n' }]);
write('nested.zip', buildZip([
  { name: 'top.txt', data: 'TOP-LEVEL-TEXT in zip.\n' },
  { name: 'inner.zip', data: innerZip },
  { name: 'blob.bin', data: Buffer.from([0x00, 0x01, 0x02, 0x03]) },
  { name: 'note.md', data: 'ZIP-MD-MEMBER note.\n' },
]));

// -- depth cap: level1.zip > level2.zip > level3.zip > level4.zip
// level3's own txt is reachable (depth 3); level4's txt must be skipped.
const level4 = buildZip([{ name: 'four.txt', data: 'LEVEL-FOUR-TEXT should be skipped.\n' }]);
const level3 = buildZip([
  { name: 'three.txt', data: 'LEVEL-THREE-TEXT reachable.\n' },
  { name: 'level4.zip', data: level4 },
]);
const level2 = buildZip([{ name: 'level3.zip', data: level3 }]);
write('deep.zip', buildZip([{ name: 'level2.zip', data: level2 }]));

// -- encrypted zip: general-purpose bit 0x1 set (no real crypto needed —
// the reader must refuse on the flag alone, before touching data)
write('encrypted.zip', buildZip([
  { name: 'secret.txt', data: 'pretend-ciphertext', flags: 0x1 },
]));

// -- password-protected office file: CFB magic under a .docx name
write('protected.docx', Buffer.concat([
  Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]),
  Buffer.alloc(504), // pad to a plausible CFB sector; content irrelevant
]));

// -- not-a-zip under a .docx name → corrupt-container
write('corrupt.docx', Buffer.from('this is not a zip archive at all', 'utf8'));

console.log('done.');
