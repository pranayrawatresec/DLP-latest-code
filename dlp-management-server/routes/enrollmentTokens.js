'use strict';
// Enrollment-token management API (console side). Two gates on every route:
// requireAuth (authN), then requirePermission('enrollment.manage') (authZ) —
// sysadmin only. Every state change is audited.
const express = require('express');
const et = require('../lib/enrollmentTokens');
const { audit } = require('../lib/audit');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../lib/rbac');

const router = express.Router();
router.use(requireAuth, requirePermission('enrollment.manage'));

// GET /api/enrollment-tokens — metadata only (never token or hash)
router.get('/', async (req, res, next) => {
  try {
    res.json(await et.listTokens());
  } catch (err) {
    next(err);
  }
});

// POST /api/enrollment-tokens  { description?, maxUses?, expiresInHours? }
router.post('/', async (req, res, next) => {
  try {
    const body = req.body || {};
    const result = await et.createToken({
      description: body.description,
      maxUses: body.maxUses == null ? 1 : body.maxUses,
      expiresInHours: body.expiresInHours == null ? et.DEFAULT_EXPIRY_HOURS : body.expiresInHours,
      createdBy: req.user.email,
    });
    // Audit records the token's ID and metadata — never the secret itself.
    await audit(req.user.email, 'enrollment_token.create', result.id, {
      description: result.description,
      maxUses: result.maxUses,
      expiresAt: result.expiresAt,
    });
    res.status(201).json({
      ...result,
      warning:
        'Shown once and unrecoverable. Put it in the installer config; never commit or log it.',
    });
  } catch (err) {
    if (err.validation) return res.status(400).json({ error: err.message });
    next(err);
  }
});

// POST /api/enrollment-tokens/:id/revoke
router.post('/:id/revoke', async (req, res, next) => {
  try {
    const result = await et.revokeToken(req.params.id);
    if (result.notFound) return res.status(404).json({ error: 'token not found' });
    await audit(req.user.email, 'enrollment_token.revoke', req.params.id, {
      alreadyRevoked: Boolean(result.alreadyRevoked),
    });
    res.json({ ok: true, alreadyRevoked: Boolean(result.alreadyRevoked) });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
