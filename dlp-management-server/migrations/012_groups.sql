-- 012_groups.sql — per-machine / per-group policy targeting (foundation + policy).
--
-- Until now the read-deny policy was a single global row (read_deny_policy id=1)
-- and every endpoint got it. This introduces GROUPS so an admin can give a pilot
-- group or a department different read-deny rules and roll enforcement out to a
-- subset from the console.
--
-- Backward compatibility is the design constraint:
--   * A single seeded "Default" group represents "every endpoint not assigned to
--     another group". The EXISTING read_deny_policy (id=1) is, unchanged, the
--     Default group's policy — so the current global behaviour is preserved
--     exactly and the existing route/agent endpoint keep working for it.
--   * agents.group_id is NULLABLE and NULL means Default, so no backfill is needed
--     and every already-enrolled agent keeps its current (global) policy.
--   * A non-default group with NO override row INHERITS the Default policy, so a
--     freshly-created group behaves like today until an admin customises it.
--
-- Trusted-readers remain global in this migration; per-group reader scoping is a
-- separate follow-up so it can touch the #15 uniqueness indexes carefully.
--
-- Applied inside a transaction by db/migrate.js — no BEGIN/COMMIT here.

CREATE TABLE groups (
  id          SERIAL PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  description TEXT,
  -- Exactly one row is the Default (enforced by the partial unique index below).
  is_default  BOOLEAN NOT NULL DEFAULT false,
  created_by  TEXT,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- At most one Default group. (Partial unique index: only rows with is_default=true
-- participate, so many non-default groups coexist.)
CREATE UNIQUE INDEX groups_single_default ON groups (is_default) WHERE is_default;

INSERT INTO groups (name, description, is_default, created_by)
VALUES ('Default', 'All endpoints not assigned to another group', true, 'system');

-- Agent membership. NULL = the Default group (no backfill; new enrolments default
-- to NULL). ON DELETE SET NULL: deleting a group returns its machines to Default.
ALTER TABLE agents
  ADD COLUMN group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL;

-- Per-group read-deny policy OVERRIDE. One row per non-default group that has
-- customised its policy; absent => the group inherits the Default (read_deny_policy
-- id=1). Same columns/semantics as read_deny_policy (009 + 010).
CREATE TABLE group_read_deny_policy (
  group_id          INTEGER PRIMARY KEY REFERENCES groups(id) ON DELETE CASCADE,
  mode              TEXT NOT NULL DEFAULT 'off'
                      CHECK (mode IN ('off','monitor','enforce')),
  posture           TEXT NOT NULL DEFAULT 'blocklist'
                      CHECK (posture IN ('allowlist','blocklist')),
  scan_fixed        BOOLEAN NOT NULL DEFAULT false,
  watch_paths       JSONB   NOT NULL DEFAULT '[]'::jsonb,
  fail_block        BOOLEAN NOT NULL DEFAULT false,
  readers_authority TEXT NOT NULL DEFAULT 'merge'
                      CHECK (readers_authority IN ('central','merge')),
  updated_by        TEXT,
  updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
