// Role → permission matrix (guide §2.3: RBAC with separation of duties).
// Deliberate: sysadmin has NO evidence/incident read permission, and nobody
// but the auditor can read the audit log.
const { audit } = require('./audit');

const ROLE_PERMISSIONS = {
  sysadmin: [
    'users.manage',
    'sessions.manage',
    'system.config',
    'enrollment.manage', // mint/revoke agent enrollment tokens (Plane 2 provisioning)
    'agents.read', // view the enrolled agent fleet
    'agents.manage', // retire (de-enroll) agents
    'license.manage',
    'license.read',
    'protect:read', // view protected-document registry (metadata, never content)
    'encryption_keys:manage', // create/rotate/destroy KEKs (metadata only — never plaintext key material)
    'trusted_destinations:read', // see which destinations reference which key
  ],
  policy_author: [
    'policies.read',
    'policies.write',
    'protect:write',
    'protect:read',
    'trusted_destinations:read', // encrypt-on-write whitelist is policy
    'trusted_destinations:write',
  ],
  incident_reviewer: [
    'incidents.read',
    'incidents.read_metadata', // a reviewer can obviously see the metadata list too
    'evidence.read',
    'evidence.export',
    'protect:read',
  ],
  auditor: [
    'audit.read',
    'agents.read',
    'incidents.read_metadata',
    'license.read',
    'protect:read',
    'trusted_destinations:read', // review the whitelist + key states (metadata only)
  ],
};

function permissionsFor(roleNames) {
  const perms = new Set();
  for (const role of roleNames) {
    for (const p of ROLE_PERMISSIONS[role] || []) perms.add(p);
  }
  return [...perms];
}

// Holding more than one of the four roles undermines separation of duties.
// We flag it (small sites may accept it) rather than block it.
function sodWarning(roleNames) {
  return roleNames.length > 1 ? roleNames : null;
}

// Authorization gate. Must run after authentication (req.user attached).
// Denials are audited — a pattern of 403s is itself a security signal.
function requirePermission(permission) {
  return async (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'authentication required' });
    }
    if (!req.user.permissions.includes(permission)) {
      try {
        await audit(req.user.email, 'authz.denied', `${req.method} ${req.originalUrl}`, {
          required: permission,
        });
      } catch (err) {
        return next(err);
      }
      return res.status(403).json({ error: 'forbidden' });
    }
    next();
  };
}

module.exports = { ROLE_PERMISSIONS, permissionsFor, sodWarning, requirePermission };
