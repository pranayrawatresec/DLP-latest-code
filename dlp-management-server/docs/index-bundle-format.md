# DLP index bundle — byte-exact format (`DLPX1`, format version 1)

This document is **normative**. The Rust agent's bundle loader is written from
this file alone; `lib/indexBundle.js` is the reference implementation and
`test/fixtures/bundle-sample/` is the golden fixture. Any change to this format
is a breaking protocol change and MUST bump the `u16` format version.

A bundle is the signed artifact agents download from `GET /agent/index` (mTLS).
It contains IDM document fingerprints, EDM salted cell hashes, a bloom
pre-filter over both, and an RSA signature by the internal CA. The file is
**unencrypted but signed** — the loader MUST verify the signature against the
pinned CA certificate (`ca.pem` from enrollment) **before trusting any parsed
value**, and MUST reject the whole file on any parse or verification failure
(fail closed).

## 0. Conventions

* **All multi-byte integers are little-endian.** `u16` / `u32` are unsigned;
  `i64` is a signed two's-complement 64-bit integer.
* **Hashes** (both IDM fingerprints and EDM cell hashes) are stored as `i64`.
  They are the signed reinterpretation of an unsigned 64-bit value
  (`BigInt.asIntN(64, u)` in JS, `u as i64` in Rust). Whenever hashes are
  *compared, sorted, or fed to the bloom filter*, use the **unsigned** `u64`
  reinterpretation (`hash as u64` in Rust).
* There is no padding or alignment anywhere; sections are back-to-back.

## 1. Overall layout

| offset | size | field |
|---|---|---|
| 0 | 5 | magic: ASCII `DLPX1` (bytes `44 4C 50 58 31`) |
| 5 | 2 | `u16` formatVer — MUST be `1` |
| 7 | 4 | `u32` headerLen — byte length of the header JSON |
| 11 | headerLen | header JSON, UTF-8, no BOM, no NUL terminator |
| … | 4 | `u32` mBits — bloom filter size in **bits** |
| … | 4 | `u32` kHashes — number of bloom hash functions |
| … | ceil(mBits/8) | bloom bit array |
| … | 4 | `u32` idmCount |
| … | idmCount × 12 | IDM entries (§4) |
| … | 4 | `u32` edmCount |
| … | edmCount × 16 | EDM entries (§5) |
| … | 4 | `u32` sigLen |
| … | sigLen | signature (§6) |

The signature is the **last** field; after it the file MUST end. A loader MUST
reject a file with trailing bytes, a truncated section, bad magic, or an
unknown format version.

## 2. Header JSON

UTF-8 JSON object. Key order in the file is not guaranteed — parse it as JSON,
do not pattern-match bytes. Shape:

```json
{
  "bundleVersion": 3,
  "params": { "k": 8, "w": 8, "hashBits": 64 },
  "edmSalts": { "<sourceId uuid>": "<64 hex chars>" },
  "scope": ["<collectionId uuid>", "..."],
  "counts": { "idm": 12345, "edm": 678, "docs": 4 },
  "docs": [
    { "versionId": "<uuid>", "documentId": "<uuid>", "collectionId": "<uuid>",
      "title": "Base Plan", "fpCount": 321 }
  ],
  "edmSources": [
    { "sourceId": "<uuid>", "name": "personnel",
      "fields": [ { "fieldId": 0, "name": "full_name", "type": "text", "primary": true } ] }
  ]
}
```

* `bundleVersion` — the server-assigned, strictly increasing integer version
  of this bundle (matches `index.latest` in the check-in response).
* `params` — the IDM fingerprinting parameters the hashes were built with
  (`k` tokens per shingle, `w` winnowing window, `hashBits` always 64).
  A loader whose matcher uses different parameters MUST reject the bundle.
* `edmSalts` — per-EDM-source hashing salt, hex. The agent needs these to
  hash candidate cell values (`SHA-256(salt || uint16BE(fieldId) || utf8(value))`,
  first 8 bytes big-endian, reinterpreted as `i64` — see `lib/edm.js`).
* `scope` — the protected-collection ids covered, sorted ascending as strings.
* `counts` — MUST equal the actual section counts; loaders SHOULD cross-check.
* `docs` — array indexed by the `docIndex` in IDM entries. `fpCount` is the
  number of **distinct** fingerprint hashes of that document version (= its
  IDM entry count in this bundle).
* `edmSources` — array indexed by the `sourceIndex` in EDM entries. `fieldId`
  equals the field's position in this array **and** in the source schema; it
  is the value bound into the EDM hash.

## 3. Bloom filter

A single filter over the **union** of every hash in the IDM and EDM sections.
Purpose: cheap agent-side pre-filter — `absent from filter ⇒ definitely not in
the bundle`. False positives are possible (then confirm via binary search in
§4/§5); false negatives are a bug (the builder inserts every stored hash).

### 3.1 Membership key

The key of a hash is its **8-byte little-endian encoding as unsigned u64**:

```
key = (hash as u64).to_le_bytes()      // exactly 8 bytes
```

### 3.2 Hash functions

Two 64-bit values are derived from the 8 key bytes; all arithmetic is
**wrapping (mod 2^64) unsigned 64-bit**:

* `h1` = FNV-1a 64 over the 8 key bytes:

```
h = 0xcbf29ce484222325            // FNV-1a 64 offset basis
for each byte b of key:
    h = h XOR b
    h = h * 0x100000001b3         // FNV-1a 64 prime, wrapping mul
h1 = h
```

* `h2` = `splitmix64(h1)` with these exact constants:

```
fn splitmix64(x: u64) -> u64 {
    let mut z = x.wrapping_add(0x9E3779B97F4A7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
    z ^ (z >> 31)
}
```

### 3.3 Bit positions and bit order

For `i` in `0 .. kHashes-1` (kHashes is read from the file):

```
t   = h1.wrapping_add((i as u64).wrapping_mul(h2))   // wrapping u64
bit = t % (mBits as u64)                             // 0 .. mBits-1
```

Bit `bit` of the filter lives in **byte `bit >> 3`**, at mask **`1 << (bit & 7)`**
(LSB-first within each byte). The hash is "possibly present" iff **all**
`kHashes` bits are set.

### 3.4 Sizing (builder-side, informative)

The server sizes the filter at ~10 bits per distinct hash with `kHashes = 7`:
`mBits = max(1024, 10 × distinctHashes)` rounded up to a multiple of 64.
Loaders MUST NOT assume this — always use the `mBits`/`kHashes` read from the
file.

## 4. IDM section

`u32 idmCount`, then `idmCount` fixed 12-byte records:

| offset in record | size | field |
|---|---|---|
| 0 | 8 | `i64` hash — document fingerprint (winnowed FNV-1a shingle hash) |
| 8 | 4 | `u32` docIndex — index into `header.docs` |

Records are sorted **ascending by hash compared as unsigned u64**; equal
hashes are sorted by `docIndex` ascending. The same hash MAY appear in
multiple records (one per document containing it); binary-search the first
occurrence, then scan forward while the hash matches. Within one document a
hash appears **at most once** (entries are per-document distinct).

## 5. EDM section

`u32 edmCount`, then `edmCount` fixed 16-byte records:

| offset in record | size | field |
|---|---|---|
| 0 | 8 | `i64` hash — salted cell hash (see `edmSalts`, §2) |
| 8 | 2 | `u16` sourceIndex — index into `header.edmSources` |
| 10 | 4 | `u32` rowId — 1-based data row within the source export |
| 14 | 2 | `u16` fieldId — schema field index (bound into the hash) |

Same sort rule: ascending by hash as unsigned u64; ties by
(`sourceIndex`, `rowId`, `fieldId`) ascending.

## 6. Signature

`u32 sigLen`, then `sigLen` signature bytes. The signature is
**RSASSA-PKCS1-v1_5 with SHA-256** (`sha256WithRSAEncryption` — the same
algorithm as every certificate the CA issues) computed by the internal CA's
RSA-4096 private key over **all preceding bytes**: from file offset 0 up to
but not including the `sigLen` field. Verify with the public key of the CA
certificate the agent pinned at enrollment (`ca.pem`). For an RSA-4096 CA,
`sigLen` is 512; loaders MUST use the stored length, not assume it.

Verification failure — or any structural inconsistency in §1–§5 — MUST cause
the loader to discard the entire bundle and keep using its previous verified
bundle (fail secure).

## 7. Golden fixture

`test/fixtures/bundle-sample/` contains:

* `sample.bundle` — a bundle built from 2 tiny documents and 1 EDM source
  with a fixed salt (deterministic inputs; regenerate with
  `node scripts/gen-bundle-fixture.js`, requires the dev CA),
* `ca-cert.pem` — the CA certificate that signed it,
* `expected.json` — header fields, present hashes with their expected
  doc/row lookups, and absent hashes with their expected bloom answers.

A conforming loader MUST reproduce every assertion in `expected.json`.
