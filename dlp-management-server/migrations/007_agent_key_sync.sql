-- 007_agent_key_sync.sql — M6 agent-facing key + trusted-destination delivery.
-- Spec: ENCRYPT-ON-WRITE-IMPLEMENTATION.md §6, plus the pinned M6 contract.
-- All additive + nullable/defaulted so existing rows and the current insert
-- paths keep working unchanged. Applied inside a transaction by db/migrate.js —
-- no BEGIN/COMMIT here.

-- ============================================================
-- trusted_destinations.on_block_band — what the agent does with a file that
-- lands in the BLOCK band on an otherwise-trusted destination:
--   'block' — refuse the write (default; whitelisting never weakens blocking).
--   'seal'  — seal it into a .dlpenc envelope instead of blocking.
-- Delivered to agents as camelCase onBlockBand in GET /agent/trusted-config.
-- ============================================================
alter table trusted_destinations
  add column on_block_band text not null default 'block'
    check (on_block_band in ('block', 'seal'));

-- ============================================================
-- detection_incidents seal metadata — populated when an agent reports an
-- 'encrypted' action. IDs/hashes only, never key material or content.
--   key_id        — free-form KEK id that sealed the file (never parsed).
--   sealed_sha256 — hex sha256 of the sealed .dlpenc envelope.
-- Both nullable so the existing incident insert path is unaffected.
-- ============================================================
alter table detection_incidents
  add column key_id        text,
  add column sealed_sha256 text;
