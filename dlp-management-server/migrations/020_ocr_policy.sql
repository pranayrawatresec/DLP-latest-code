-- 020_ocr_policy.sql — the endpoint OCR / image-inspection policy. One global
-- switch, delivered to agents at GET /agent/ocr-policy and honored by EVERY channel
-- that inspects content (clipboard, USB, read-deny/RDP, browser upload). When on,
-- an image (screenshot, image file) or a text-less PDF is OCR'd to text and scored
-- by the same protected-content engine; on the synchronous kernel READ-DENY path
-- (too short a budget for OCR) an image read by an untrusted/RDP process is instead
-- FAIL-SECURE blocked. Metadata only — no secrets, never image content.
--
--   enabled     master switch (default false — inert until an admin turns it on;
--               OCR is CPU-heavy so it is opt-in).
--   max_pixels  skip images larger than this many pixels (w*h) to bound OCR cost.
--   fail_block  when an image can't be OCR'd / inspected, block (fail-secure) vs
--               allow+audit. Default TRUE for a defence posture.
--
-- Applied inside a transaction by db/migrate.js — no BEGIN/COMMIT here.

CREATE TABLE ocr_policy (
  id          INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),   -- singleton row
  enabled     BOOLEAN NOT NULL DEFAULT false,
  max_pixels  BIGINT  NOT NULL DEFAULT 8000000,               -- ~ up to a 3840x2160 screenshot
  fail_block  BOOLEAN NOT NULL DEFAULT true,
  updated_by  TEXT,
  updated_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO ocr_policy (id) VALUES (1);
