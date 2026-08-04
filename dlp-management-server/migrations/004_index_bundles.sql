-- 004_index_bundles.sql — compiled detection index bundles + agent incidents (Step 4/6).
-- A bundle is the signed, versioned artifact the agents download over mTLS:
-- every ready document's IDM fingerprints and every ready EDM source's salted
-- hashes, plus a bloom pre-filter, in the byte-exact format documented in
-- docs/index-bundle-format.md. The file itself lives OUTSIDE the database
-- (data/index/, unencrypted but CA-signed); file_ref names it. Incidents are
-- what agents report back when a bundle match fires on an endpoint.
-- Applied inside a transaction by db/migrate.js. No BEGIN/COMMIT here.

-- ============================================================
-- Bundles: one row per compiled index version. version is a strictly
-- increasing integer — agents compare it against checkin's index.latest.
-- params_json records the fingerprinting parameters baked into the file
-- (k, w, hashBits); scope_json the collection ids covered.
-- ============================================================

create table index_bundles (
  id          uuid primary key default gen_random_uuid(),
  version     integer unique not null,
  params_json jsonb,
  scope_json  jsonb,
  sha256      text,                     -- hex sha256 of the whole bundle file
  size_bytes  bigint,
  file_ref    text not null,            -- filename inside data/index/ (server-chosen)
  built_at    timestamptz not null default now()
);

-- ============================================================
-- Incidents: a detection reported by an agent (mTLS-authenticated; the
-- agent identity comes from its client certificate, never the body).
-- verdict_json is the agent's raw match report (hashes/ids only — never
-- captured content). resolved_json is filled in lazily server-side on
-- first reviewer read: titles, matched seq ranges, containment.
-- ============================================================

create table detection_incidents (
  id            uuid primary key default gen_random_uuid(),
  agent_id      uuid not null references agents(id),
  channel       text not null,          -- e.g. 'usb', 'upload', 'clipboard'
  verdict_json  jsonb not null,
  file_name     text,
  file_sha256   text,
  reported_at   timestamptz not null default now(),
  resolved_json jsonb                   -- null until first reviewer read resolves it
);

create index detection_incidents_agent_idx on detection_incidents (agent_id, reported_at);
create index detection_incidents_reported_idx on detection_incidents (reported_at);
