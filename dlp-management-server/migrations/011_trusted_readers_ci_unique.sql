-- 011_trusted_readers_ci_unique.sql — enforce CASE-INSENSITIVE uniqueness on the
-- sanctioned-reader list at the DATABASE level (audit finding #15 hardening).
--
-- The route already rejects case-insensitive duplicates before insert
-- (routes/trustedReaders.js: `lower(value) = lower($2)` under the chain lock), so
-- "winword.exe" and "WINWORD.EXE" can't both be added through the API. This makes
-- that a hard DB invariant too — independent of the application path — matching the
-- fact that the endpoint matches readers case-insensitively.
--
-- 1) Remove any PRE-EXISTING case-insensitive duplicates (only possible from before
--    the app-layer guard). Keep the EARLIEST row (lowest id) of each
--    (match_type, lower(value)) group; the survivors are unchanged. The exact
--    UNIQUE (match_type, value) constraint already barred identical-case dups, so
--    in practice this removes nothing on a current database.
-- 2) Add the functional unique index. `lower(text)` is IMMUTABLE, so it is index-able.
--
-- The original exact UNIQUE (match_type, value) constraint is left in place as a
-- (now-redundant) backstop. Applied inside a transaction by db/migrate.js.

DELETE FROM trusted_readers a
  USING trusted_readers b
 WHERE a.match_type = b.match_type
   AND lower(a.value) = lower(b.value)
   AND a.id > b.id;

CREATE UNIQUE INDEX IF NOT EXISTS trusted_readers_ci_unique
  ON trusted_readers (match_type, lower(value));
