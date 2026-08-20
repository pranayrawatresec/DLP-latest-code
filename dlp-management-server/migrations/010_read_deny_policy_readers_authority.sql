-- 010_read_deny_policy_readers_authority.sql — server-authoritative reader
-- allowlist for read-deny (audit finding #9).
--
-- Until now the effective sanctioned-reader allowlist was the UNION of a
-- machine's LOCAL [[trusted_readers]] and the console-synced readers, so the
-- console could only ADD trust, never revoke a rule typed into an endpoint's
-- agent.toml. This adds a per-policy authority switch:
--
--   readers_authority
--     merge    (default, back-compat) — union of local + central, as before
--     central  — the console list is the WHOLE allowlist; local rules are
--                ignored, so HQ can revoke any trust. (The agent's own-exe /
--                sibling-sealer trust is separate and always applies, so the
--                agent never blocks itself.)
--
-- Default 'merge' keeps every existing deployment behaving exactly as before;
-- an admin opts into 'central' from the console.
--
-- Applied inside a transaction by db/migrate.js — no BEGIN/COMMIT here.

ALTER TABLE read_deny_policy
  ADD COLUMN readers_authority TEXT NOT NULL DEFAULT 'merge'
    CHECK (readers_authority IN ('central', 'merge'));
