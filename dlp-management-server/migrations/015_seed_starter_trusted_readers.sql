-- 015_seed_starter_trusted_readers.sql — ship a real starter allowlist so a
-- standard Windows endpoint is USABLE the moment read-deny turns on.
--
-- WHY: the trusted-reader allowlist starts empty. With read-deny enabled and an
-- empty (or central+empty) list, every process is an untrusted reader and the
-- kernel denies it the read of sensitive files — including the apps that own
-- those files (Office opening its own .docx, the OS indexer, the viewer). This
-- seed gives every deployment a safe, spoof-resistant baseline; the console
-- (policy_author) curates the rest per site. See
-- docs/trusted-readers-starter-list.md for the full curation guide.
--
-- WHAT WE SEED (least-privilege, Authenticode-publisher based — "malware cannot
-- sign as Microsoft", so these cannot be spoofed by a renamed binary):
--   * 'Microsoft Windows'           — the OS itself: Explorer, Notepad/WordPad,
--                                     Photos, the search indexer, inbox apps.
--   * 'Microsoft Corporation'       — Office, Edge (browser + built-in PDF
--                                     viewer), Teams, OneDrive, Microsoft
--                                     Defender (AV). On an MS-centric endpoint
--                                     this alone covers browser, PDF and AV.
--   * 'Microsoft Windows Publisher' — signer CN used by some inbox/Store
--                                     components and system tooling.
--   * path C:\Program Files\DLP Agent — the agent's own install tree (the agent
--                                     is self-skipped in the driver, but its
--                                     helpers/tooling live here; harmless and
--                                     explicit).
--
-- WHAT WE DELIBERATELY DO NOT SEED (enable per deployment from the guide — they
-- broaden the trust surface and are not present on every site):
--   Adobe ('Adobe Inc.'), Google Chrome ('Google LLC'), Firefox
--   ('Mozilla Corporation'), and third-party AV / backup vendors. The guide
--   lists their exact signer CNs and how to verify one (Get-AuthenticodeSignature).
--
-- All rows are GLOBAL (group_id NULL → applies to every group, incl. Default).
-- ON CONFLICT DO NOTHING makes this idempotent and non-destructive: if an admin
-- already added any of these (any case, any scope collision on the unique
-- indexes), the existing row is kept and the seed skips it. Existing curated
-- lists are never overwritten. created_by = 'system-seed' marks provenance.
--
-- Applied inside a transaction by db/migrate.js — no BEGIN/COMMIT here.

INSERT INTO trusted_readers (match_type, value, note, created_by)
VALUES
  ('publisher', 'Microsoft Windows',
     'Starter: the Windows OS (Explorer, inbox apps, search indexer).', 'system-seed'),
  ('publisher', 'Microsoft Corporation',
     'Starter: Office, Edge (browser + PDF), Teams, OneDrive, Defender.', 'system-seed'),
  ('publisher', 'Microsoft Windows Publisher',
     'Starter: inbox/Store components and system tooling.', 'system-seed'),
  ('path', 'C:\Program Files\DLP Agent',
     'Starter: the DLP agent''s own install tree.', 'system-seed')
ON CONFLICT DO NOTHING;
