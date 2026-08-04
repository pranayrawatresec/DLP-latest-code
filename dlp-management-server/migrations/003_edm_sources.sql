-- 003_edm_sources.sql — EDM (exact data match) source registry (fingerprinting doc §4).
-- An EDM source is a structured export (personnel, payroll, assets) whose CELL
-- VALUES must never leave the org. We keep only salted 64-bit hashes of the
-- typed-normalized cells, grouped by row — the plaintext CSV is NOT retained
-- (temp_blob_ref holds the encrypted upload only while ingestion is queued;
-- the worker deletes the blob and nulls the ref once hashes are stored).
-- Applied inside a transaction by db/migrate.js. No BEGIN/COMMIT here.

-- ============================================================
-- Sources: one registered structured dataset. schema_json is the ordered
-- field list [{name, type, primary}] (types: text|id|number|date);
-- field_id in edm_hashes is the index into this array. salt_hex is the
-- per-source 32-byte hashing salt — never returned by any API.
-- ============================================================

create table edm_sources (
  id             uuid primary key default gen_random_uuid(),
  name           text not null unique,
  schema_json    jsonb not null,
  salt_hex       text not null,
  temp_blob_ref  text,                 -- encrypted upload awaiting ingestion; null once ingested
  row_count      integer not null default 0,
  status         text not null default 'empty'
                 check (status in ('empty', 'ingesting', 'ready', 'failed')),
  failure_reason text,                 -- reason code only, set when status = 'failed'
  created_by     uuid references admin_users(id),
  created_at     timestamptz not null default now()
);

-- ============================================================
-- Hashes: salted SHA-256-derived signed 64-bit hash per non-empty cell.
-- row_id groups cells of one source row (the agent's same-row proximity
-- rule); the (hash) index serves candidate lookups, like IDM fingerprints.
-- ============================================================

create table edm_hashes (
  source_id uuid not null references edm_sources(id) on delete cascade,
  row_id    integer not null,          -- 1-based data row within the source export
  field_id  smallint not null,         -- index of the field in schema_json
  hash      bigint not null,           -- signed 64-bit salted cell hash
  primary key (source_id, row_id, field_id)
);

create index edm_hashes_hash_idx on edm_hashes (hash);
