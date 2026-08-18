-- 009_read_deny_policy.sql — the endpoint READ-DENY policy, managed in the console
-- and delivered to agents over mTLS at GET /agent/read-deny-policy. A single
-- global row (id = 1). The agent APPLIES it to the kernel driver programmatically
-- (mode knob, watch config, volume attach) so the operator never touches a command
-- line. Metadata only — no secrets.
--
--   mode        off | monitor | enforce
--                 off     = no read protection
--                 monitor = classify + report "would-block", but ALLOW (safe rollout)
--                 enforce = deny for real
--   posture     allowlist | blocklist  (which processes count as untrusted)
--   scan_fixed  also watch the fixed drive (C:) under watch_paths (else removable-only)
--   watch_paths folder prefixes on the fixed drive, e.g. ["\\Users"] (up to 16)
--   fail_block  block when a verdict cannot be produced (fail-secure) vs allow+audit
--
-- Applied inside a transaction by db/migrate.js — no BEGIN/COMMIT here.

CREATE TABLE read_deny_policy (
  id          INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),   -- singleton row
  mode        TEXT NOT NULL DEFAULT 'off'
                CHECK (mode IN ('off','monitor','enforce')),
  posture     TEXT NOT NULL DEFAULT 'blocklist'
                CHECK (posture IN ('allowlist','blocklist')),
  scan_fixed  BOOLEAN NOT NULL DEFAULT false,
  watch_paths JSONB   NOT NULL DEFAULT '[]'::jsonb,
  fail_block  BOOLEAN NOT NULL DEFAULT false,
  updated_by  TEXT,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed the singleton with safe defaults (off / removable-only / fail-open):
-- protection is inert until an admin turns it on from the console.
INSERT INTO read_deny_policy (id) VALUES (1);
