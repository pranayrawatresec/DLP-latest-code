-- 017_read_deny_remote_sessions.sql — "deny sensitive access in remote (RDP)
-- sessions" toggle for the read-deny policy (both the global Default row and the
-- per-group override table).
--
-- WHY: an RDP session is a *separate* Windows logon session; a user connected over
-- RDP is not physically present. Mirroring how an EV code-signing token refuses to
-- be used over RDP (session isolation), this lets an admin declare "sensitive files
-- may not be read from a remote session at all". When on, the agent flags EVERY
-- process running in an RDP session as an untrusted reader (strict / token model —
-- overriding the app allowlist), so the existing read-deny/open-deny denies their
-- sensitive-file reads and any copy-out (redirected drive, clipboard) fails at the
-- source read. Classic RDP only (WTS protocol = RDP); AnyDesk/RustDesk hijack the
-- CONSOLE session and are covered by the process allowlist, not this flag.
--
-- Additive + backward-compatible: default false (feature off), so existing
-- deployments are unchanged. Same column added to read_deny_policy (009) and the
-- per-group override group_read_deny_policy (012) so a group can override it too.
--
-- Applied inside a transaction by db/migrate.js — no BEGIN/COMMIT here.

ALTER TABLE read_deny_policy
  ADD COLUMN IF NOT EXISTS deny_remote_sessions BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE group_read_deny_policy
  ADD COLUMN IF NOT EXISTS deny_remote_sessions BOOLEAN;
