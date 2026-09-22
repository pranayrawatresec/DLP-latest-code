-- 021_ml_policy.sql — the ML document-classification policy. The agent carries an
-- ONNX classifier (model version V6.2.01) that predicts ONE of 29 BUSINESS FUNCTION
-- classes for a document. That is a SECOND, INDEPENDENT detection signal next to
-- IDM/EDM fingerprinting: fingerprinting cannot see a document nobody registered,
-- the model cannot name WHICH document leaked. The engine ORs them (never ANDs) —
-- ML can only ADD sensitivity, it never downgrades a fingerprint hit.
--
-- An admin marks some of the 29 classes sensitive here; a model hit on a marked
-- class at or above its confidence threshold makes the document sensitive.
--
--   ml_labels             the model's FROZEN label space (29 rows, indices 0..28)
--                         mirrored into the DB. Mirrored — not read from the model
--                         file — because the console must be able to list and
--                         explain the classes on an air-gapped server that has no
--                         model file and no internet. Authoritative source is
--                         Document_classification/taxonomy/v6_2_01/registry.lock.json.
--                         `domain` is a DISPLAY grouping only (13 general / 3
--                         education / 13 defence); it carries no enforcement meaning.
--   ml_policy             the singleton switch, delivered to agents at
--                         GET /agent/ml-policy.
--                           enabled        master switch (default false — inert).
--                           min_confidence global floor a prediction must reach; a
--                                          label may raise/lower it for itself.
--                           action         'audit' (record only) or 'block'.
--                           fail_block     model missing / load or inference error
--                                          while enabled => block on EGRESS paths
--                                          (fail-secure). Default TRUE for a defence
--                                          posture. The synchronous kernel read-deny
--                                          path NEVER fail-blocks on ML (no budget
--                                          to run it) — see src/ocrpolicy.rs.
--                           model_version  the label space + graph this policy was
--                                          authored against; an agent carrying a
--                                          different model must not silently reuse it.
--   ml_sensitive_labels   the classes an admin marked sensitive, with an optional
--                         per-label threshold (NULL = use ml_policy.min_confidence).
--                         EMPTY by default: with no label selected the ML signal is
--                         inert, so merely turning the feature on cannot start
--                         blocking anything until an admin chooses classes.
--
-- Applied inside a transaction by db/migrate.js — no BEGIN/COMMIT here.

CREATE TABLE ml_labels (
  id      TEXT    PRIMARY KEY,                 -- frozen 3-letter class id, e.g. 'FIN'
  idx     INTEGER NOT NULL UNIQUE,             -- frozen logits position 0..28
  name    TEXT    NOT NULL,
  domain  TEXT    NOT NULL CHECK (domain IN ('general', 'education', 'defence'))
);

-- The 29 classes of taxonomy v6_2_01 (registry.lock.json, lock_version 1, width 29).
-- Order of the logits vector — do NOT renumber; the model's head is trained to it.
INSERT INTO ml_labels (id, idx, name, domain) VALUES
  ('ADM',  0, 'Administration',                    'general'),
  ('STU',  1, 'Student Records',                   'education'),
  ('TCH',  2, 'Teacher Records',                   'education'),
  ('GOV',  3, 'Government Reporting',              'general'),
  ('INS',  4, 'Inspection',                        'general'),
  ('OPS',  5, 'Planning & Operations',             'general'),
  ('FIN',  6, 'Finance',                           'general'),
  ('EXM',  7, 'Examination',                       'education'),
  ('COM',  8, 'Communication',                     'general'),
  ('POL',  9, 'Policies',                          'general'),
  ('ANA', 10, 'Analytics',                         'general'),
  ('PUB', 11, 'Public Information',                'general'),
  ('OOD', 12, 'Other / Unknown',                   'general'),
  ('PER', 13, 'Personnel & Service Records',       'general'),
  ('INT', 14, 'Intelligence & Threat Assessment',  'defence'),
  ('WPN', 15, 'Weapons & Armament',                'defence'),
  ('AVI', 16, 'Aviation & Air Systems',            'defence'),
  ('NAV', 17, 'Naval & Maritime Systems',          'defence'),
  ('SIG', 18, 'Signals & Communications',          'defence'),
  ('CYB', 19, 'Cyber Defence',                     'defence'),
  ('SPC', 20, 'Space & Satellite Systems',         'defence'),
  ('LOG', 21, 'Defence Logistics & Supply',        'defence'),
  ('ACQ', 22, 'Defence Acquisition & Procurement', 'defence'),
  ('DIP', 23, 'Defence Diplomacy & Border Affairs','defence'),
  ('TRN', 24, 'Military Training & Doctrine',      'defence'),
  ('MNT', 25, 'Maintenance & Engineering',         'defence'),
  ('MED', 26, 'Medical',                           'general'),
  ('LEG', 27, 'Legal',                             'general'),
  ('NUC', 28, 'Nuclear & Strategic Systems',       'defence');

CREATE TABLE ml_policy (
  id              INTEGER      PRIMARY KEY DEFAULT 1 CHECK (id = 1),   -- singleton row
  enabled         BOOLEAN      NOT NULL DEFAULT false,
  min_confidence  NUMERIC(4,3) NOT NULL DEFAULT 0.700
                    CHECK (min_confidence > 0 AND min_confidence <= 1),
  action          TEXT         NOT NULL DEFAULT 'audit' CHECK (action IN ('audit', 'block')),
  fail_block      BOOLEAN      NOT NULL DEFAULT true,
  model_version   TEXT         NOT NULL DEFAULT 'V6.2.01',
  updated_by      TEXT,
  updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);

INSERT INTO ml_policy (id) VALUES (1);

CREATE TABLE ml_sensitive_labels (
  label_id        TEXT         PRIMARY KEY REFERENCES ml_labels(id),
  min_confidence  NUMERIC(4,3)                                   -- NULL = inherit the global floor
                    CHECK (min_confidence > 0 AND min_confidence <= 1),
  added_by        TEXT,
  added_at        TIMESTAMPTZ  NOT NULL DEFAULT now()
);
