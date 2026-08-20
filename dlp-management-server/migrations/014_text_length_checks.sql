-- 014_text_length_checks.sql — enforce user-text length caps at the DATABASE, not
-- only in the Express routes (defense-in-depth; the schema should own its own
-- invariants regardless of which write path inserts).
--
-- Until now these caps lived only in app code:
--   * trusted_readers.value  <= 512  (routes/trustedReaders.js validateReader)
--   * trusted_readers.note   <= 1000 (route truncates)
--   * groups.name            <= 64   (routes/groups.js validateName)
--   * groups.description     <= 256  (route truncates)
-- so a direct SQL insert / future route / bug could store an unbounded string. The
-- primary API path always enforced these, so existing rows already comply and the
-- CHECKs add cleanly. char_length() counts characters (not bytes), matching the JS
-- .length / validation semantics.
--
-- Applied inside a transaction by db/migrate.js — no BEGIN/COMMIT here.

ALTER TABLE trusted_readers
  ADD CONSTRAINT trusted_readers_value_len CHECK (char_length(value) <= 512),
  ADD CONSTRAINT trusted_readers_note_len  CHECK (note IS NULL OR char_length(note) <= 1000);

ALTER TABLE groups
  ADD CONSTRAINT groups_name_len        CHECK (char_length(name) <= 64),
  ADD CONSTRAINT groups_description_len CHECK (description IS NULL OR char_length(description) <= 256);
