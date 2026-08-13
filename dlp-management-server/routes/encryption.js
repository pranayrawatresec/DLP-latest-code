'use strict';
// Encrypt-on-write admin API (ENCRYPT-ON-WRITE-IMPLEMENTATION.md §6.2, minimal
// slice: whitelist CRUD + key list/create/destroy — no key delivery here, that
// is the mTLS agent surface, M6).
//
// Two gates on every route: requireAuth (authN 401) then requirePermission
// (authZ 403, denials audited). RBAC:
//   * trusted_destinations:read   — policy_author, sysadmin, auditor
//   * trusted_destinations:write  — policy_author
//   * encryption_keys:manage      — sysadmin
//
// Key handling rules (review-blockers):
//   * KEKs exist in plaintext only transiently in this process while being
//     wrapped; buffers are zeroed immediately after use. wrapped_kek bytes are
//     NEVER returned by any endpoint here and NEVER logged/audited.
//   * The Org Root Key comes from DLP_ORG_ROOT_KEY (64 hex chars). Absent or
//     malformed => 503 on key creation. Fail secure: no default key, ever.
//   * Key ids are FREE-FORM strings. We generate "class-<c>/v<n>" but nothing
//     anywhere may parse a key id back apart (owner decision).
//   * Key destruction is SINGLE-PERSON (sysadmin) in v1 by owner decision; the
//     request and the effect are audited separately so a pending-confirmation
//     step can be inserted between them later without reshaping the audit trail.
const crypto = require('crypto');
const express = require('express');
const pool = require('../db/pool');
const { audit } = require('../lib/audit');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../lib/rbac');

const router = express.Router();
router.use(requireAuth);

const MODES = new Set(['encrypt_sensitive', 'encrypt_all']);
const BLOCK_BANDS = new Set(['block', 'seal']);

// ---------------------------------------------------------------------------
// Org Root Key + KEK wrapping (Node built-in crypto only — no new deps).
// ---------------------------------------------------------------------------

// Returns the ORK as a 32-byte Buffer, or null if not (correctly) configured.
// Read at request time, not module load, so ops can fix .env + restart nodemon
// without a stale capture; never logged.
function orgRootKey() {
  const hex = process.env.DLP_ORG_ROOT_KEY || '';
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) return null;
  return Buffer.from(hex, 'hex');
}

// AES-256-GCM wrap: returns nonce(12) || ciphertext(32) || tag(16), the layout
// documented on encryption_keys.wrapped_kek in migration 006.
function wrapKek(kek, ork) {
  const nonce = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ork, nonce);
  const ct = Buffer.concat([cipher.update(kek), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([nonce, ct, tag]);
}

// ---------------------------------------------------------------------------
// Validation helpers (all pure).
// ---------------------------------------------------------------------------

// v1 whitelist UI is the USB channel; web_upload/email matchers arrive with M7.
// Matcher shapes (strict — unknown keys rejected):
//   { serial: "<device serial>" }         non-empty printable string, <= 256
//   { vid: "hhhh", pid: "hhhh" }          4 hex digits each (USB VID/PID)
// Returns { ok: true, matcher } with a normalized copy, or { ok: false, error }.
function validateUsbMatcher(m) {
  if (m === null || typeof m !== 'object' || Array.isArray(m)) {
    return { ok: false, error: 'matcher must be an object' };
  }
  const keys = Object.keys(m).sort();
  if (keys.join(',') === 'serial') {
    const serial = typeof m.serial === 'string' ? m.serial.trim() : '';
    if (!serial || serial.length > 256) {
      return { ok: false, error: 'matcher.serial must be a non-empty string (max 256 chars)' };
    }
    return { ok: true, matcher: { serial } };
  }
  if (keys.join(',') === 'pid,vid') {
    const vid = typeof m.vid === 'string' ? m.vid.trim().toLowerCase() : '';
    const pid = typeof m.pid === 'string' ? m.pid.trim().toLowerCase() : '';
    if (!/^[0-9a-f]{4}$/.test(vid) || !/^[0-9a-f]{4}$/.test(pid)) {
      return { ok: false, error: 'matcher.vid and matcher.pid must each be 4 hex digits' };
    }
    return { ok: true, matcher: { vid, pid } };
  }
  return { ok: false, error: 'matcher must be exactly {serial} or {vid,pid}' };
}

// Classification feeds the generated key id, so keep it tame. This validates
// the INPUT NAME only — key ids themselves stay free-form and are never parsed.
function validClassification(c) {
  return typeof c === 'string' && /^[a-z0-9][a-z0-9_-]{0,63}$/.test(c);
}

function destinationJson(row) {
  return {
    id: row.id,
    channel: row.channel,
    matcher: row.matcher,
    mode: row.mode,
    keyId: row.key_id,
    onBlockBand: row.on_block_band,
    note: row.note,
    createdBy: row.created_by,
    createdAt: row.created_at,
  };
}

function keyJson(row) {
  // NEVER include wrapped_kek (or any key material) here.
  return {
    id: row.id,
    classification: row.classification,
    version: row.version,
    state: row.state,
    createdAt: row.created_at,
  };
}

// ---------------------------------------------------------------------------
// Trusted destinations (the whitelist).
// ---------------------------------------------------------------------------

// GET /api/encryption/trusted-destinations — the whitelist, newest first.
router.get(
  '/trusted-destinations',
  requirePermission('trusted_destinations:read'),
  async (req, res, next) => {
    try {
      const { rows } = await pool.query(
        `select id, channel, matcher, mode, key_id, on_block_band, note, created_by, created_at
           from trusted_destinations
          order by created_at desc, id desc`
      );
      res.json({ destinations: rows.map(destinationJson) });
    } catch (err) {
      next(err);
    }
  }
);

// POST /api/encryption/trusted-destinations
// Body: { channel:'usb', matcher:{serial}|{vid,pid}, mode, keyId?, note? }.
// keyId defaults to the single ACTIVE key; 409 if none (or ambiguous — with
// per-classification keys "pick one for me" is only safe when there is exactly
// one candidate; fail secure rather than guess).
router.post(
  '/trusted-destinations',
  requirePermission('trusted_destinations:write'),
  async (req, res, next) => {
    try {
      const body = req.body || {};

      if (body.channel !== 'usb') {
        return res.status(400).json({ error: "channel must be 'usb' (web_upload/email arrive in a later milestone)" });
      }
      const mv = validateUsbMatcher(body.matcher);
      if (!mv.ok) return res.status(400).json({ error: mv.error });
      const mode = typeof body.mode === 'string' ? body.mode : '';
      if (!MODES.has(mode)) {
        return res.status(400).json({ error: 'mode must be encrypt_sensitive|encrypt_all' });
      }
      const note = typeof body.note === 'string' ? body.note.slice(0, 1000) : null;

      // Optional: what to do with a file in the BLOCK band on this trusted
      // destination. Defaults to 'block' (whitelisting never weakens blocking);
      // 'seal' opts into sealing instead. Any other value is a 400.
      let onBlockBand = 'block';
      if (body.onBlockBand !== undefined) {
        if (!BLOCK_BANDS.has(body.onBlockBand)) {
          return res.status(400).json({ error: 'onBlockBand must be block|seal' });
        }
        onBlockBand = body.onBlockBand;
      }

      let keyId;
      if (body.keyId !== undefined) {
        if (typeof body.keyId !== 'string' || !body.keyId) {
          return res.status(400).json({ error: 'keyId must be a non-empty string' });
        }
        const k = await pool.query(
          `select id from encryption_keys where id = $1 and state = 'active'`,
          [body.keyId]
        );
        if (k.rows.length === 0) {
          return res.status(400).json({ error: 'keyId does not reference an active encryption key' });
        }
        keyId = k.rows[0].id;
      } else {
        const active = await pool.query(
          `select id from encryption_keys where state = 'active' order by id`
        );
        if (active.rows.length === 0) {
          return res.status(409).json({ error: 'no active encryption key exists; create one first' });
        }
        if (active.rows.length > 1) {
          return res.status(409).json({ error: 'multiple active encryption keys; specify keyId' });
        }
        keyId = active.rows[0].id;
      }

      const { rows } = await pool.query(
        `insert into trusted_destinations (channel, matcher, mode, key_id, on_block_band, note, created_by)
         values ($1, $2, $3, $4, $5, $6, $7)
         returning id, channel, matcher, mode, key_id, on_block_band, note, created_by, created_at`,
        ['usb', JSON.stringify(mv.matcher), mode, keyId, onBlockBand, note, req.user.email]
      );
      const dest = destinationJson(rows[0]);
      await audit(req.user.email, 'trusted_destination.create', String(dest.id), {
        channel: dest.channel,
        matcher: dest.matcher,
        mode: dest.mode,
        keyId: dest.keyId,
        onBlockBand: dest.onBlockBand,
      });
      res.status(201).json({ destination: dest });
    } catch (err) {
      next(err);
    }
  }
);

// DELETE /api/encryption/trusted-destinations/:id — remove a whitelist entry.
router.delete(
  '/trusted-destinations/:id',
  requirePermission('trusted_destinations:write'),
  async (req, res, next) => {
    try {
      if (!/^\d{1,10}$/.test(req.params.id)) {
        return res.status(404).json({ error: 'destination not found' });
      }
      const { rows } = await pool.query(
        `delete from trusted_destinations where id = $1
         returning id, channel, matcher, mode, key_id`,
        [parseInt(req.params.id, 10)]
      );
      if (rows.length === 0) return res.status(404).json({ error: 'destination not found' });
      await audit(req.user.email, 'trusted_destination.delete', String(rows[0].id), {
        channel: rows[0].channel,
        matcher: rows[0].matcher,
        mode: rows[0].mode,
        keyId: rows[0].key_id,
      });
      res.status(204).end();
    } catch (err) {
      next(err);
    }
  }
);

// ---------------------------------------------------------------------------
// Keys.
// ---------------------------------------------------------------------------

// GET /api/encryption/keys — key METADATA only, never wrapped_kek bytes.
router.get('/keys', requirePermission('trusted_destinations:read'), async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `select id, classification, version, state, created_at
         from encryption_keys
        order by created_at desc, id desc`
    );
    res.json({ keys: rows.map(keyJson) });
  } catch (err) {
    next(err);
  }
});

// POST /api/encryption/keys — create (or rotate) the KEK for a classification.
// Body: { classification }. Generates 32 random bytes, wraps them AES-256-GCM
// under the ORK, stores only the wrapped form. Any previously active key of the
// same classification moves to 'rotated' (spec §6.2 "create/rotate").
router.post('/keys', requirePermission('encryption_keys:manage'), async (req, res, next) => {
  const client = await pool.connect();
  let kek = null;
  try {
    const classification = (req.body || {}).classification;
    if (!validClassification(classification)) {
      return res.status(400).json({
        error: 'classification must match ^[a-z0-9][a-z0-9_-]{0,63}$',
      });
    }
    const ork = orgRootKey();
    if (!ork) {
      // Fail secure: no ORK => no key creation, and absolutely no default key.
      return res.status(503).json({ error: 'encryption not configured' });
    }

    kek = crypto.randomBytes(32);
    const wrapped = wrapKek(kek, ork);
    kek.fill(0); // plaintext KEK gone; only the wrapped form persists
    kek = null;

    await client.query('begin');
    const next_ = await client.query(
      `select coalesce(max(version), 0) + 1 as v from encryption_keys where classification = $1`,
      [classification]
    );
    const version = next_.rows[0].v;
    const rotated = await client.query(
      `update encryption_keys set state = 'rotated'
        where classification = $1 and state = 'active'
        returning id`,
      [classification]
    );
    const id = `class-${classification}/v${version}`;
    const { rows } = await client.query(
      `insert into encryption_keys (id, classification, version, wrapped_kek, state)
       values ($1, $2, $3, $4, 'active')
       returning id, classification, version, state, created_at`,
      [id, classification, version, wrapped]
    );
    await client.query('commit');

    await audit(req.user.email, 'encryption_key.create', id, {
      classification,
      version,
      rotated: rotated.rows.map((r) => r.id),
    });
    res.status(201).json({ key: keyJson(rows[0]) });
  } catch (err) {
    try { await client.query('rollback'); } catch (_) { /* not in tx */ }
    if (err && err.code === '23505') {
      // UNIQUE (classification, version) lost a race — client should retry.
      return res.status(409).json({ error: 'concurrent key creation; retry' });
    }
    next(err);
  } finally {
    if (kek) kek.fill(0);
    client.release();
  }
});

// POST /api/encryption/keys/:id/destroy — crypto-shred a KEK.
// Key ids contain '/', so callers must URL-encode the id
// (POST /api/encryption/keys/class-internal%2Fv1/destroy).
//
// SINGLE-PERSON in v1 (owner decision). Deliberately split into "request" and
// "execute" steps — each with its own audit entry — so a two-person pending/
// confirm gate can later be inserted between them without changing this shape.
router.post(
  '/keys/:id/destroy',
  requirePermission('encryption_keys:manage'),
  async (req, res, next) => {
    try {
      const id = req.params.id;
      const cur = await pool.query(
        `select id, state, octet_length(wrapped_kek) as len from encryption_keys where id = $1`,
        [id]
      );
      if (cur.rows.length === 0) return res.status(404).json({ error: 'key not found' });
      if (cur.rows[0].state === 'destroyed') {
        return res.status(409).json({ error: 'key already destroyed' });
      }

      // Step 1: the request itself is audited BEFORE anything changes.
      await audit(req.user.email, 'encryption_key.destroy_requested', id, {
        state: cur.rows[0].state,
      });

      // Step 2: execute — overwrite the wrapped KEK with random bytes of the
      // same length (crypto-shred; nothing recoverable even with the ORK),
      // then mark destroyed. Guarded on state so a concurrent destroy loses.
      const noise = crypto.randomBytes(cur.rows[0].len);
      const { rows } = await pool.query(
        `update encryption_keys
            set wrapped_kek = $1, state = 'destroyed', destroyed_at = now(), destroyed_by = $2
          where id = $3 and state <> 'destroyed'
          returning id, classification, version, state, created_at, destroyed_at, destroyed_by`,
        [noise, req.user.email, id]
      );
      if (rows.length === 0) return res.status(409).json({ error: 'key already destroyed' });

      await audit(req.user.email, 'encryption_key.destroyed', id, {
        destroyedBy: req.user.email,
        singlePerson: true, // explicit in the trail until the confirm step lands
      });
      res.json({
        key: {
          ...keyJson(rows[0]),
          destroyedAt: rows[0].destroyed_at,
          destroyedBy: rows[0].destroyed_by,
        },
      });
    } catch (err) {
      next(err);
    }
  }
);

module.exports = router;
