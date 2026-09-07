-- 019_clipboard_policy.sql — the endpoint CLIPBOARD policy, managed in the console
-- and delivered to agents over mTLS at GET /agent/clipboard-policy. A single global
-- row (id = 1), mirroring read_deny_policy. The DLPAgent service auto-spawns a
-- per-session clipboard helper (WTS) that applies this policy; the operator never
-- runs a command line. Metadata only — no secrets, and NEVER the clipboard content.
--
--   mode          off | monitor | enforce
--                   off     = clipboard protection inert (helper idle, no incidents)
--                   monitor = classify a sensitive copy + report an incident, but
--                             ALLOW the paste (audit-only, safe rollout)
--                   enforce = BLOCK — clear the clipboard on a sensitive copy so the
--                             paste yields nothing (with a redaction notice)
--   block_images  also block images (CF_DIB/BITMAP) wholesale — they cannot be
--                   content-inspected without OCR, so this is an all-or-nothing knob
--   fail_block    block when a verdict cannot be produced (no bundle / classify
--                   failure) — fail-secure. Default TRUE for a defence posture.
--
-- Ships 'off' (like read_deny_policy) so an upgrade never surprises a live estate;
-- an admin turns it on from the console. Model A (strict) only: a sensitive copy is
-- blocked regardless of the paste destination — there is no per-app exception here.
--
-- Applied inside a transaction by db/migrate.js — no BEGIN/COMMIT here.

CREATE TABLE clipboard_policy (
  id            INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),   -- singleton row
  mode          TEXT NOT NULL DEFAULT 'off'
                  CHECK (mode IN ('off','monitor','enforce')),
  block_images  BOOLEAN NOT NULL DEFAULT false,
  fail_block    BOOLEAN NOT NULL DEFAULT true,
  updated_by    TEXT,
  updated_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Seed the singleton with a safe default (off): clipboard protection is inert until
-- an admin turns it on from the console.
INSERT INTO clipboard_policy (id) VALUES (1);
