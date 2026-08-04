'use strict';
// =====================================================================
// Agent-facing app (Plane 2, guide §2.2). Served ONLY on the mTLS listener
// (bin/agent-server.js) — a DIFFERENT trust surface from the admin console:
//   * the console port trusts session cookies from humans
//   * this port trusts client CERTIFICATES from machines
// They never mix. No sessions, no cookies here.
//
// Routes:
//   POST /agent/enroll    the ONLY route reachable without a client cert (a
//                         new PC has none yet). A one-time token is the proof
//                         the install was sanctioned. Token -> signed cert.
//   POST /agent/checkin   requires a valid client cert (mutual TLS). The
//                         heartbeat: prove identity, update last_seen,
//                         advertise the latest index bundle version. (Phase 3
//                         will issue the licensed entitlement token here.)
//   GET  /agent/index     mTLS. Streams the latest signed index bundle
//                         (docs/index-bundle-format.md).
//   POST /agent/incidents mTLS. An agent reports a detection verdict
//                         (hashes/ids only — never captured content).
// =====================================================================
const fs = require('fs');
const path = require('path');
const express = require('express');
const pool = require('../db/pool');
const { audit } = require('../lib/audit');
const { signCertificateRequest, loadCaCertificatePem, canonicalSerial } = require('../lib/ca');
const { redeemToken } = require('../lib/enrollmentTokens');
const { latestBundle, latestBundleVersion, INDEX_DIR } = require('../lib/indexBundle');

const CHECKIN_INTERVAL_SECONDS = Number(process.env.CHECKIN_INTERVAL_SECONDS || 300);

const app = express();
// CSRs are ~1-2 KB; cap the body to blunt large-payload abuse on an
// unauthenticated endpoint.
app.use(express.json({ limit: '64kb' }));

function str(v, max = 255) {
  return v == null ? null : String(v).slice(0, max);
}

// --- POST /agent/enroll ------------------------------------------------
// Reachable WITHOUT a client certificate (the agent has none yet).
// Everything happens in ONE transaction: consume the token, insert the
// agent, sign the CSR, bind the serial — so a failure never wastes a token
// use and never leaves a half-created agent.
app.post('/agent/enroll', async (req, res, next) => {
  const { token, csrPem, hostname } = req.body || {};
  const os = str(req.body?.os);
  const agentVersion = str(req.body?.agentVersion, 64);
  if (!token || !csrPem || !hostname) {
    return res.status(400).json({ error: 'token, csrPem and hostname are required' });
  }
  const host = str(hostname);

  const client = await pool.connect();
  try {
    await client.query('begin');

    // 1) Atomically consume one token use (row-locked within this txn).
    const redeem = await redeemToken(String(token), { db: client });
    if (!redeem.ok) {
      await client.query('rollback');
      // Recognized-but-unusable tokens are a security signal → audit them.
      // Unknown/missing tokens are the flood vector (random guessing) →
      // reject generically WITHOUT an audit row, so probing can't bloat the
      // append-only log.
      if (redeem.reason !== 'unknown_token' && redeem.reason !== 'missing_token') {
        await audit('agent-enroll', 'agent.enroll_rejected', host, { reason: redeem.reason });
      }
      return res.status(403).json({ error: 'enrollment rejected' });
    }

    // 2) Create the agent row to obtain the server-assigned identity.
    const ins = await client.query(
      `insert into agents (hostname, os, agent_version, status)
       values ($1, $2, $3, 'enrolled') returning id`,
      [host, os, agentVersion]
    );
    const agentId = ins.rows[0].id;

    // 3) Sign the CSR — identity is OURS to assign (never what the CSR asked).
    //    Throws on malformed / weak / unsupported keys; rollback releases the
    //    token use and the agent row.
    let signed;
    try {
      signed = signCertificateRequest(String(csrPem), { commonName: `dlp-agent-${agentId}` });
    } catch (csrErr) {
      await client.query('rollback');
      await audit('agent-enroll', 'agent.enroll_rejected', host, { reason: `csr:${csrErr.message}` });
      return res.status(400).json({ error: 'invalid certificate request' });
    }

    // 4) Bind the issued certificate's serial to the agent.
    await client.query('update agents set cert_serial = $2, cert_not_after = $3 where id = $1', [
      agentId,
      signed.serial,
      signed.notAfter,
    ]);
    await client.query('commit');

    await audit('agent-enroll', 'agent.enroll', agentId, {
      hostname: host,
      tokenId: redeem.tokenId,
      certSerial: signed.serial,
    });

    return res.status(201).json({
      agentId,
      certificate: signed.certPem,
      ca: loadCaCertificatePem(), // agent pins this to verify the server later
      checkinIntervalSeconds: CHECKIN_INTERVAL_SECONDS,
    });
  } catch (err) {
    await client.query('rollback').catch(() => {});
    next(err);
  } finally {
    client.release();
  }
});

// --- mTLS gate: everything below REQUIRES a valid client certificate ---
app.use((req, res, next) => {
  // rejectUnauthorized is false on the listener (so /agent/enroll works
  // without a cert), so we enforce it ourselves here.
  if (!req.socket.authorized) {
    return res.status(401).json({ error: 'client certificate required' });
  }
  next();
});

// --- POST /agent/checkin ----------------------------------------------
// The heartbeat. Identity comes from the mTLS client certificate, not the
// body. Routine check-ins are deliberately NOT audited (a thousand agents
// every few minutes would drown the log) — only status transitions and
// refusals are.
app.post('/agent/checkin', async (req, res, next) => {
  const client = await pool.connect();
  try {
    const peer = req.socket.getPeerCertificate();
    const serial = canonicalSerial(peer.serialNumber || '');

    const { rows } = await client.query(
      'select id, status from agents where cert_serial = $1',
      [serial]
    );
    const agent = rows[0];

    if (!agent) {
      // Cert chains to our CA but no agent owns this serial — an anomaly.
      await audit('agent-checkin', 'agent.checkin_unknown', serial);
      return res.status(403).json({ error: 'unknown agent' });
    }
    if (agent.status === 'retired') {
      // Server-side de-enrollment / revocation (fail secure): no renewal.
      await audit('agent-checkin', 'agent.checkin_refused', agent.id, { reason: 'retired' });
      return res.status(403).json({ error: 'agent retired' });
    }

    const wasFirst = agent.status === 'enrolled';
    await client.query(
      `update agents set last_seen = now(), status = 'active',
              agent_version = coalesce($2, agent_version)
        where id = $1`,
      [agent.id, str(req.body?.agentVersion, 64)]
    );
    if (wasFirst) {
      await audit('agent-checkin', 'agent.activated', agent.id);
    }

    return res.json({
      status: 'active',
      agentId: agent.id,
      checkinIntervalSeconds: CHECKIN_INTERVAL_SECONDS,
      policyBundle: null, // signed policy arrives with the policy phase
      // Latest compiled index bundle version (0 = none yet). The agent
      // compares against its cached bundle and fetches GET /agent/index
      // when behind.
      index: { latest: await latestBundleVersion() },
      // entitlement token is issued here in Phase 3 (licensing/seat metering)
    });
  } catch (err) {
    next(err);
  } finally {
    client.release();
  }
});

// Resolve the calling agent from its mTLS client certificate (the gate above
// already guaranteed the cert chains to our CA). Returns null after sending
// the refusal response itself — same semantics as check-in: unknown serials
// and retired agents are refused fail-secure and audited.
async function requireKnownAgent(req, res, actor) {
  const peer = req.socket.getPeerCertificate();
  const serial = canonicalSerial(peer.serialNumber || '');
  const { rows } = await pool.query('select id, status from agents where cert_serial = $1', [
    serial,
  ]);
  const agent = rows[0];
  if (!agent) {
    await audit(actor, 'agent.refused_unknown', serial);
    res.status(403).json({ error: 'unknown agent' });
    return null;
  }
  if (agent.status === 'retired') {
    await audit(actor, 'agent.refused', agent.id, { reason: 'retired' });
    res.status(403).json({ error: 'agent retired' });
    return null;
  }
  return agent;
}

// --- GET /agent/index ---------------------------------------------------
// Streams the latest signed index bundle. The bundle is signed by the CA
// (the agent verifies with its pinned ca.pem before loading), so transport
// integrity is belt-and-braces on top of mTLS. Routine downloads are, like
// routine check-ins, deliberately NOT audited.
app.get('/agent/index', async (req, res, next) => {
  try {
    const agent = await requireKnownAgent(req, res, 'agent-index');
    if (!agent) return;

    const bundle = await latestBundle();
    if (!bundle) return res.status(404).json({ error: 'no index bundle available' });

    // file_ref is server-generated; basename() is defense in depth only.
    const file = path.join(INDEX_DIR, path.basename(bundle.file_ref));
    let stat;
    try {
      stat = await fs.promises.stat(file);
    } catch {
      // Row exists but the file is gone — an operator problem, not a 404
      // the agent should treat as "no bundle exists".
      return res.status(500).json({ error: 'bundle file unavailable' });
    }
    res.status(200);
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', String(stat.size));
    res.setHeader('X-Bundle-Version', String(bundle.version));
    res.setHeader('X-Bundle-Sha256', String(bundle.sha256));
    const stream = fs.createReadStream(file);
    stream.on('error', () => res.destroy()); // headers already sent — abort, never half-succeed
    stream.pipe(res);
  } catch (err) {
    next(err);
  }
});

// --- POST /agent/incidents ---------------------------------------------
// An agent reports a detection. The verdict carries hashes and ids ONLY —
// never captured file content (evidence blobs are a later phase). Identity
// comes from the certificate; the body cannot claim another agent.
app.post('/agent/incidents', async (req, res, next) => {
  try {
    const agent = await requireKnownAgent(req, res, 'agent-incident');
    if (!agent) return;

    const body = req.body || {};
    const channel = typeof body.channel === 'string' ? body.channel.trim().slice(0, 64) : '';
    if (!channel) return res.status(400).json({ error: 'channel is required' });
    const verdict = body.verdict;
    if (verdict === null || typeof verdict !== 'object' || Array.isArray(verdict)) {
      return res.status(400).json({ error: 'verdict must be an object' });
    }
    const fileName = str(body.fileName);
    const fileSha256 = str(body.fileSha256, 64);

    const { rows } = await pool.query(
      `insert into detection_incidents (agent_id, channel, verdict_json, file_name, file_sha256)
       values ($1, $2, $3, $4, $5) returning id`,
      [agent.id, channel, JSON.stringify(verdict), fileName, fileSha256]
    );
    const incidentId = rows[0].id;
    // Audited (a detection is a security event) — channel + ids only,
    // never the verdict payload or file name.
    await audit('agent-incident', 'agent.incident_reported', incidentId, {
      agentId: agent.id,
      channel,
    });
    return res.status(201).json({ id: incidentId });
  } catch (err) {
    next(err);
  }
});

// JSON errors only on this surface — never an HTML page.
app.use((req, res) => res.status(404).json({ error: 'not found' }));
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'internal error' });
});

module.exports = app;
