-- 018_trusted_readers_deny.sql — deny-override ("Blocked applications") for the
-- read-deny sanctioned-reader list.
--
-- WHY: trust is granted by Authenticode PUBLISHER (e.g. 'Microsoft Corporation'),
-- which is coarse: one publisher rule trusts EVERY app that vendor signs — Office
-- and Explorer, but also the built-in exfiltration channels (Teams, OneDrive,
-- Edge). The allowlist had no way to carve an exception out of a broad publisher
-- trust, so a sensitive file could be read (and taken off the box) by a trusted-
-- by-publisher cloud/chat app. This adds a per-rule KIND:
--
--   kind = 'allow'  (default, every existing row) — the application MAY read
--                    sensitive content (today's trusted-reader behaviour).
--   kind = 'deny'   — a deny-OVERRIDE: this application is treated as an
--                    untrusted reader (subject to read-deny) EVEN IF an allow
--                    rule (e.g. a publisher) would otherwise trust it. Deny wins.
--
-- Effective trust on the endpoint becomes:
--   trusted  ==  (matches an ALLOW rule)  AND  (matches NO DENY rule).
-- So an admin keeps 'Microsoft Corporation' trusted for Office/Explorer/Defender
-- yet blocks the exfil channels by name — e.g. deny name 'ms-teams.exe',
-- 'Teams.exe', 'OneDrive.exe'.
--
-- SECURITY NOTE (documented, not hidden): deny-override closes the DEFAULT leak
-- (the exfil app installed and run normally can no longer read sensitive files),
-- but it cannot stop a determined insider who copies/renames a publisher-trusted
-- binary to escape a name/path deny while still matching the publisher allow.
-- That residual hole is inherent to publisher trust; fully closing it needs app-
-- control (WDAC/AppLocker) or not trusting the publisher at all. See
-- docs/trusted-readers-starter-list.md.
--
-- We deliberately SEED NO deny rows (an opinionated block could break a site that
-- legitimately shares via Teams internally); recommended entries are documented
-- in the curation guide, mirroring how the allow starter-list documents (but does
-- not seed) Adobe/Chrome/Firefox.
--
-- Applied inside a transaction by db/migrate.js — no BEGIN/COMMIT here.

-- 1) The kind discriminator. NOT NULL + DEFAULT 'allow' backfills every existing
--    row to 'allow', preserving today's behaviour exactly.
ALTER TABLE trusted_readers
  ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'allow'
    CHECK (kind IN ('allow', 'deny'));

-- 2) Fold kind into the case-insensitive uniqueness scope, so the same matcher
--    may exist once as an allow AND once as a deny (their intents differ; deny
--    wins at evaluation on the endpoint) while still barring true duplicates
--    within a (group, kind, match_type) bucket. Replaces the 013 index.
DROP INDEX IF EXISTS trusted_readers_scope_ci_unique;                        -- 013
CREATE UNIQUE INDEX trusted_readers_scope_ci_unique
  ON trusted_readers (COALESCE(group_id, 0), kind, match_type, lower(value));
