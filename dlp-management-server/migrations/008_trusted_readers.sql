-- 008_trusted_readers.sql — read-deny "allowlist posture" sanctioned-reader list.
-- The applications allowed to read sensitive content locally on endpoints; every
-- process NOT matching one of these is treated as an untrusted reader and denied
-- the read of sensitive files by the kernel minifilter (read-deny). Delivered to
-- agents over mTLS at GET /agent/trusted-readers, and managed in the console by a
-- policy_author. Metadata only — no secrets, no content.
--
-- match_type / value identify a sanctioned application:
--   'publisher' — Authenticode signer name, e.g. 'Microsoft Corporation'
--                 (spoof-resistant: malware cannot sign as Microsoft).
--   'path'      — image path prefix, e.g. 'C:\Program Files\Adobe'
--                 (matched at a path-component boundary on the agent).
--   'name'      — image base name, e.g. 'winword.exe' (weakest; pair with
--                 app-control such as WDAC/AppLocker).
--
-- Applied inside a transaction by db/migrate.js — no BEGIN/COMMIT here.

CREATE TABLE trusted_readers (
  id          SERIAL PRIMARY KEY,
  match_type  TEXT NOT NULL CHECK (match_type IN ('publisher','path','name')),
  value       TEXT NOT NULL,
  note        TEXT,
  created_by  TEXT NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  -- The same matcher twice is meaningless; keep the list a set.
  UNIQUE (match_type, value)
);
