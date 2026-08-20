-- 013_trusted_readers_group.sql — per-group scoping of the trusted-applications
-- list (per-machine/per-group targeting, slice 2).
--
-- Until now the sanctioned-reader allowlist was one flat GLOBAL list delivered to
-- every endpoint. This scopes each reader to a group:
--   * group_id NULL  = GLOBAL — applies to every group (today's behaviour for all
--     existing rows, so nothing changes until an admin adds a group-scoped rule).
--   * group_id set   = applies ONLY to that group.
-- Delivery returns GLOBAL rules + the agent's own group's rules.
--
-- Uniqueness must become per-scope while keeping the #15 case-insensitive
-- guarantee. The old GLOBAL uniques (008 exact + 011 case-insensitive) are replaced
-- by one functional index on (COALESCE(group_id,0), match_type, lower(value)):
--   * COALESCE(...,0) buckets every GLOBAL row together, so two global "winword.exe"
--     still collide (case-insensitively);
--   * a global rule and a per-group copy of the same app may coexist (different
--     buckets), which is the whole point of scoping.
-- Existing rows are all group_id NULL and were already unique under 011, so the new
-- index builds cleanly.
--
-- Applied inside a transaction by db/migrate.js — no BEGIN/COMMIT here.

ALTER TABLE trusted_readers
  ADD COLUMN group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE;

DROP INDEX IF EXISTS trusted_readers_ci_unique;                              -- 011
ALTER TABLE trusted_readers DROP CONSTRAINT IF EXISTS trusted_readers_match_type_value_key; -- 008

CREATE UNIQUE INDEX trusted_readers_scope_ci_unique
  ON trusted_readers (COALESCE(group_id, 0), match_type, lower(value));
