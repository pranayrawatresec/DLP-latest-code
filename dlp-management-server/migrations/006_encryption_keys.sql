-- 006_encryption_keys.sql — encrypt-on-write (trusted destinations) server slice.
-- Spec: ENCRYPT-ON-WRITE-IMPLEMENTATION.md §6.1 — exactly these two tables.
--   encryption_keys       — per-classification KEKs, stored wrapped under the
--                           Org Root Key (never plaintext at rest). Key ids are
--                           FREE-FORM strings — never parsed anywhere.
--   trusted_destinations  — the whitelist: (channel, matcher, mode, key id).
-- Applied inside a transaction by db/migrate.js. No BEGIN/COMMIT here.

CREATE TABLE encryption_keys (
  id            TEXT PRIMARY KEY,          -- 'class-internal/v1'
  classification TEXT NOT NULL,            -- 'internal', 'secret', ...
  version       INTEGER NOT NULL,
  wrapped_kek   BYTEA NOT NULL,            -- AES-256-GCM under ORK (nonce||ct||tag)
  state         TEXT NOT NULL CHECK (state IN ('active','rotated','destroyed')),
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  destroyed_at  TIMESTAMPTZ,
  destroyed_by  TEXT,                      -- user id; destruction rule enforced in code
  UNIQUE (classification, version)
);

CREATE TABLE trusted_destinations (
  id          SERIAL PRIMARY KEY,
  channel     TEXT NOT NULL CHECK (channel IN ('usb','web_upload','email')),
  matcher     JSONB NOT NULL,   -- {"serial":"..."} | {"vid":"..","pid":".."} | {"origin":"https://.."}
  mode        TEXT NOT NULL CHECK (mode IN ('encrypt_sensitive','encrypt_all')),
  key_id      TEXT NOT NULL REFERENCES encryption_keys(id),
  note        TEXT,
  created_by  TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
