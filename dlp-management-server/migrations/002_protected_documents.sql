-- 002_protected_documents.sql — protected document registry (Phase 4 groundwork).
-- Collections of classified documents, their versioned encrypted blobs,
-- rolling-hash fingerprints for agent-side matching, and the background
-- processing job queue that extracts/fingerprints uploaded documents.
-- Applied inside a transaction by db/migrate.js. No BEGIN/COMMIT here.

-- ============================================================
-- Collections: named groups of protected documents, each with a
-- classification level that policies will reference later.
-- ============================================================

create table protected_collections (
  id             uuid primary key default gen_random_uuid(),
  name           text not null unique,
  classification text not null,        -- e.g. 'official', 'secret' — policy vocabulary
  description    text not null default '',
  created_by     uuid references admin_users(id),
  created_at     timestamptz not null default now()
);

-- ============================================================
-- Documents: one logical protected document, moving through the
-- ingest pipeline (pending → extracting → fingerprinting → ready).
-- ============================================================

create table protected_documents (
  id              uuid primary key default gen_random_uuid(),
  collection_id   uuid not null references protected_collections(id),
  title           text not null,
  status          text not null default 'pending'
                  check (status in ('pending', 'extracting', 'fingerprinting', 'ready', 'failed')),
  failure_reason  text,                -- set only when status = 'failed'
  current_version integer,             -- version_no of the active version, null until first ingest
  created_by      uuid references admin_users(id),
  created_at      timestamptz not null default now()
);

-- ============================================================
-- Versions: each upload of a document is an immutable version.
-- blob_ref points into the encrypted blob store (lib/blobStore.js),
-- never a filesystem path chosen by the client. sha256 is of the
-- PLAINTEXT — used for dedupe and integrity checks after decrypt.
-- ============================================================

create table document_versions (
  id                uuid primary key default gen_random_uuid(),
  document_id       uuid not null references protected_documents(id),
  version_no        integer not null,
  blob_ref          text not null,     -- shard/uuid ref into the encrypted blob store
  sha256            text not null,     -- hex sha256 of the plaintext
  size_bytes        bigint,
  mime              text,
  original_filename text,
  registered_by     uuid references admin_users(id),
  registered_at     timestamptz not null default now(),
  retired_at        timestamptz,       -- null while this version is still enforced
  unique (document_id, version_no)
);

-- ============================================================
-- Fingerprints: ordered rolling-hash shingles per version. Stored as
-- signed 64-bit values (bigint) — the agent matches candidate hashes
-- against the (hash) index, then confirms ordering via seq.
-- ============================================================

create table document_fingerprints (
  version_id uuid not null references document_versions(id) on delete cascade,
  hash       bigint not null,          -- signed 64-bit fingerprint hash
  seq        integer not null,         -- position of the shingle within the version
  primary key (version_id, seq)
);

create index document_fingerprints_hash_idx on document_fingerprints (hash);

-- ============================================================
-- Processing jobs: minimal DB-backed queue for the ingest pipeline
-- (text extraction, fingerprinting). Workers poll for
-- state = 'queued' and run_after <= now().
-- ============================================================

create table processing_jobs (
  id          uuid primary key default gen_random_uuid(),
  kind        text not null,           -- e.g. 'extract', 'fingerprint'
  ref_id      uuid,                    -- id of the row the job operates on
  state       text not null default 'queued'
              check (state in ('queued', 'running', 'done', 'failed')),
  attempts    integer not null default 0,
  last_error  text,
  run_after   timestamptz not null default now(),
  created_at  timestamptz not null default now(),
  finished_at timestamptz
);

create index processing_jobs_state_idx on processing_jobs (state, run_after);
