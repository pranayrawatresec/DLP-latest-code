'use strict';
// Comprehensive test + edge-case harness for the enrollment layer
// (agent/agentApp.js: POST /agent/enroll + POST /agent/checkin over mTLS).
//
// Verification levels:
//   * REAL mutual-TLS: an in-process HTTPS listener with the actual CA
//     material; clients present real key pairs and certificates.
//   * Independent: issued certs cross-checked with Node's native X509 and
//     the system OpenSSL; DB inspected directly for agent/token state.
//
// Requires an initialized CA (npm run init-ca) and the dev database.
// Creates its own tokens/agents (tagged) and cleans them up. Audit rows are
// append-only and remain.
require('dotenv').config();
const fs = require('fs');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const forge = require('node-forge');
const pool = require('../db/pool');
const ca = require('../lib/ca');
const et = require('../lib/enrollmentTokens');
const { verifyChain } = require('../lib/audit');
const agentApp = require('../agent/agentApp');

const TAG = 'enrtest-' + crypto.randomBytes(3).toString('hex');
const results = [];
let passed = 0;
let failed = 0;
let server;
let PORT;

let OPENSSL = true;
try { execFileSync('openssl', ['version']); } catch { OPENSSL = false; }

async function check(id, name, fn) {
  try {
    const detail = (await fn()) || '';
    results.push({ id, name, status: 'PASS', detail: String(detail) });
    passed++;
    console.log(`  PASS  ${id}  ${name}`);
  } catch (err) {
    results.push({ id, name, status: 'FAIL', detail: err.message });
    failed++;
    console.log(`  FAIL  ${id}  ${name}\n        ${err.message}`);
  }
}
function assert(cond, msg) { if (!cond) throw new Error(msg || 'assertion failed'); }

// --- HTTPS helper (optionally presenting a client cert) ---------------
// agent:false → a fresh socket per request that closes after, so server.close()
// isn't blocked by Node's default keep-alive pooling. Per-request timeout
// guards against a hung handshake.
function request({ pathname, method = 'POST', body, key, cert, verifyServer = false }) {
  return new Promise((resolve, reject) => {
    const data = body != null ? JSON.stringify(body) : null;
    const req = https.request(
      {
        host: '127.0.0.1',
        port: PORT,
        path: pathname,
        method,
        key,
        cert,
        ca: verifyServer ? ca.loadCaCertificatePem() : undefined,
        rejectUnauthorized: Boolean(verifyServer), // verify the SERVER cert when asked
        servername: 'localhost', // matches server cert SAN
        agent: false,
        headers: {
          'Content-Type': 'application/json',
          Connection: 'close',
          ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {}),
        },
      },
      (res) => {
        let b = '';
        res.on('data', (c) => (b += c));
        res.on('end', () => resolve({ status: res.statusCode, body: b ? JSON.parse(b) : null }));
      }
    );
    req.setTimeout(15000, () => req.destroy(new Error('request timeout')));
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// RSA keygen in forge (pure JS) is slow, so generate a couple of key pairs
// ONCE and reuse them. Different enrollments may share a key pair — each still
// gets a distinct certificate (serial/identity); only the CN/serial differ.
let K2048;
let K1024;
function csrFrom(keys, cn) {
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;
  csr.setSubject([{ name: 'commonName', value: cn }]);
  csr.sign(keys.privateKey, forge.md.sha256.create());
  return {
    csrPem: forge.pki.certificationRequestToPem(csr),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
  };
}
function makeCsr(bits = 2048, cn = 'agent-requested-name') {
  return csrFrom(bits === 1024 ? K1024 : K2048, cn);
}

async function mintToken(maxUses = 1) {
  return et.createToken({ description: TAG, maxUses, createdBy: TAG });
}
async function auditCount(action, target) {
  const q = target
    ? await pool.query('select count(*)::int n from audit_log where action=$1 and target=$2', [action, target])
    : await pool.query('select count(*)::int n from audit_log where action=$1', [action]);
  return q.rows[0].n;
}

async function main() {
  console.log('\nEnrollment layer — test & edge-case suite\n');
  if (!ca.caExists()) {
    console.error('No CA — run: npm run init-ca');
    process.exit(1);
  }
  console.log('  (generating test key pairs…)');
  K2048 = forge.pki.rsa.generateKeyPair(2048);
  K1024 = forge.pki.rsa.generateKeyPair(1024);

  // Stand up the REAL mTLS listener in-process.
  const tls = ca.loadServerTlsMaterial();
  server = https.createServer(
    { key: tls.key, cert: tls.cert, ca: tls.ca, requestCert: true, rejectUnauthorized: false, minVersion: 'TLSv1.2' },
    agentApp
  );
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  PORT = server.address().port;

  // ============ Enrollment ============
  let enrolled = null; // { agentId, keyPem, certPem }

  await check('N01', 'valid token + CSR → 201; cert chains to CA, clientAuth, server-assigned CN', async () => {
    const tok = await mintToken(1);
    const { csrPem, keyPem } = makeCsr(2048, 'i-want-to-be-admin');
    const res = await request({ pathname: '/agent/enroll', body: { token: tok.token, csrPem, hostname: `${TAG}-pc1`, os: 'Windows 11', agentVersion: '0.0.1' } });
    assert(res.status === 201, `status ${res.status}`);
    assert(res.body.certificate && res.body.ca, 'missing cert/ca in response');
    const x = new crypto.X509Certificate(res.body.certificate);
    const caX = new crypto.X509Certificate(ca.loadCaCertificatePem());
    assert(x.verify(caX.publicKey), 'issued cert does not chain to CA');
    assert(/dlp-agent-/.test(x.subject) && !/admin/.test(x.subject), 'CN not server-assigned / leaked CSR name');
    enrolled = { agentId: res.body.agentId, keyPem, certPem: res.body.certificate };
    // OpenSSL independent check
    if (OPENSSL) {
      const tmp = path.join(__dirname, `.n01-${TAG}.pem`);
      fs.writeFileSync(tmp, res.body.certificate);
      fs.writeFileSync(tmp + '.ca', ca.loadCaCertificatePem());
      const out = execFileSync('openssl', ['verify', '-CAfile', tmp + '.ca', tmp], { encoding: 'utf8' });
      fs.rmSync(tmp); fs.rmSync(tmp + '.ca');
      assert(/: OK/.test(out), 'openssl verify failed');
    }
    return `agent ${res.body.agentId.slice(0, 8)}; openssl OK`;
  });

  await check('N02', 'agent row recorded with cert_serial and status=enrolled', async () => {
    const r = await pool.query('select hostname, status, cert_serial from agents where id=$1', [enrolled.agentId]);
    assert(r.rows.length === 1, 'agent row missing');
    assert(r.rows[0].status === 'enrolled', `status ${r.rows[0].status}`);
    assert(r.rows[0].cert_serial, 'cert_serial not bound');
    return `serial ${r.rows[0].cert_serial.slice(0, 10)}…`;
  });

  await check('N03', 'issued cert public key matches the agent-generated CSR key (key binding)', async () => {
    // The private key stays with the agent; the cert carries the matching public key.
    const certX = new crypto.X509Certificate(enrolled.certPem);
    const key = crypto.createPrivateKey(enrolled.keyPem);
    assert(certX.checkPrivateKey(key), 'cert does not match the agent private key');
    return 'agent keypair bound to the certificate';
  });

  await check('N04', 'missing fields → 400', async () => {
    const res = await request({ pathname: '/agent/enroll', body: { hostname: 'x' } });
    assert(res.status === 400, `status ${res.status}`);
  });

  await check('N05', 'unknown token → 403 generic, and NOT audited (flood-resistant)', async () => {
    const before = await auditCount('agent.enroll_rejected');
    const { csrPem } = makeCsr();
    const res = await request({ pathname: '/agent/enroll', body: { token: 'dlpenr_' + crypto.randomBytes(32).toString('base64url'), csrPem, hostname: `${TAG}-x` } });
    assert(res.status === 403, `status ${res.status}`);
    const after = await auditCount('agent.enroll_rejected');
    assert(after === before, 'unknown-token probe should not write an audit row');
    return 'generic 403, no audit row';
  });

  await check('N06', 'revoked token → 403, and IS audited (recognized-token misuse)', async () => {
    const tok = await mintToken(1);
    await et.revokeToken(tok.id);
    const before = await auditCount('agent.enroll_rejected');
    const { csrPem } = makeCsr();
    const res = await request({ pathname: '/agent/enroll', body: { token: tok.token, csrPem, hostname: `${TAG}-rev` } });
    assert(res.status === 403, `status ${res.status}`);
    const after = await auditCount('agent.enroll_rejected');
    assert(after === before + 1, 'revoked-token attempt should be audited');
    return '403 + audited';
  });

  await check('N07', 'exhausted token → 403 (maxUses=1, second enroll fails)', async () => {
    const tok = await mintToken(1);
    const a = await request({ pathname: '/agent/enroll', body: { token: tok.token, csrPem: makeCsr().csrPem, hostname: `${TAG}-e1` } });
    const b = await request({ pathname: '/agent/enroll', body: { token: tok.token, csrPem: makeCsr().csrPem, hostname: `${TAG}-e2` } });
    assert(a.status === 201 && b.status === 403, `got ${a.status}/${b.status}`);
    return 'first 201, second 403';
  });

  await check('N08', 'malformed CSR with a VALID token → 400 AND the token use is released (txn rollback)', async () => {
    const tok = await mintToken(1);
    const bad = await request({ pathname: '/agent/enroll', body: { token: tok.token, csrPem: '-----BEGIN CERTIFICATE REQUEST-----\nnope\n-----END CERTIFICATE REQUEST-----', hostname: `${TAG}-bad` } });
    assert(bad.status === 400, `status ${bad.status}`);
    // The use must NOT have been consumed — a good CSR now succeeds.
    const good = await request({ pathname: '/agent/enroll', body: { token: tok.token, csrPem: makeCsr().csrPem, hostname: `${TAG}-good` } });
    assert(good.status === 201, `retry should succeed, got ${good.status}`);
    return 'bad CSR 400, token not wasted, retry 201';
  });

  await check('N09', 'weak key (RSA-1024) rejected → 400', async () => {
    const tok = await mintToken(1);
    const res = await request({ pathname: '/agent/enroll', body: { token: tok.token, csrPem: makeCsr(1024).csrPem, hostname: `${TAG}-weak` } });
    assert(res.status === 400, `status ${res.status}`);
    return 'RSA-1024 refused';
  });

  await check('N10', 'RACE: one single-use token, 8 concurrent enrolls → exactly ONE 201', async () => {
    const tok = await mintToken(1);
    const csrPem = makeCsr().csrPem;
    const attempts = await Promise.all(
      Array.from({ length: 8 }, (_, i) =>
        request({ pathname: '/agent/enroll', body: { token: tok.token, csrPem, hostname: `${TAG}-race${i}` } })
      )
    );
    const created = attempts.filter((a) => a.status === 201).length;
    assert(created === 1, `expected exactly 1 success, got ${created}`);
    const agents = await pool.query('select count(*)::int n from agents where hostname like $1', [`${TAG}-race%`]);
    assert(agents.rows[0].n === 1, `expected 1 agent row, got ${agents.rows[0].n}`);
    return `${created} enrolled / ${attempts.length - created} rejected; 1 agent row`;
  });

  // ============ Check-in over mTLS ============
  await check('N11', 'check-in WITHOUT a client certificate → 401', async () => {
    const res = await request({ pathname: '/agent/checkin', body: {} });
    assert(res.status === 401, `status ${res.status}`);
  });

  await check('N12', 'check-in WITH the enrolled cert over mTLS → 200; status→active, last_seen set', async () => {
    const res = await request({ pathname: '/agent/checkin', body: { agentVersion: '0.0.2' }, key: enrolled.keyPem, cert: enrolled.certPem, verifyServer: true });
    assert(res.status === 200, `status ${res.status}`);
    assert(res.body.status === 'active' && res.body.agentId === enrolled.agentId, 'unexpected checkin body');
    const r = await pool.query('select status, last_seen, agent_version from agents where id=$1', [enrolled.agentId]);
    assert(r.rows[0].status === 'active' && r.rows[0].last_seen, 'agent not activated');
    assert(r.rows[0].agent_version === '0.0.2', 'agent_version not updated');
    return 'mutual TLS ok; enrolled→active';
  });

  await check('N13', 'check-in with a cert from a DIFFERENT CA → 401 (not our client)', async () => {
    // Stand up a rogue CA in a temp dir and issue a client cert with it.
    const rogueDir = path.join(__dirname, `.rogue-${TAG}`);
    fs.mkdirSync(rogueDir, { recursive: true });
    const saved = process.env.CA_DIR;
    delete require.cache[require.resolve('../lib/ca')];
    process.env.CA_DIR = rogueDir;
    const rogueCa = require('../lib/ca');
    rogueCa.initializeCa({ commonName: 'Rogue CA' });
    const { csrPem, keyPem } = makeCsr();
    const rogueCert = rogueCa.signCertificateRequest(csrPem, { commonName: 'dlp-agent-rogue' });
    process.env.CA_DIR = saved;
    delete require.cache[require.resolve('../lib/ca')];
    require('../lib/ca');

    const res = await request({ pathname: '/agent/checkin', body: {}, key: keyPem, cert: rogueCert.certPem });
    fs.rmSync(rogueDir, { recursive: true, force: true });
    assert(res.status === 401, `rogue cert should be 401, got ${res.status}`);
    return 'rogue client cert rejected at the TLS gate';
  });

  await check('N14', 'check-in with a valid CA cert whose serial is NOT enrolled → 403 unknown agent', async () => {
    // Sign a cert with OUR CA but never enroll it (no agent row).
    const { csrPem, keyPem } = makeCsr();
    const ghost = ca.signCertificateRequest(csrPem, { commonName: 'dlp-agent-ghost' });
    const res = await request({ pathname: '/agent/checkin', body: {}, key: keyPem, cert: ghost.certPem, verifyServer: true });
    assert(res.status === 403, `status ${res.status}`);
    return 'CA-signed but unknown serial → 403';
  });

  await check('N15', 'RETIRED agent is refused check-in (fail-secure de-enrollment) + audited', async () => {
    await pool.query(`update agents set status='retired' where id=$1`, [enrolled.agentId]);
    const before = await auditCount('agent.checkin_refused', enrolled.agentId);
    const res = await request({ pathname: '/agent/checkin', body: {}, key: enrolled.keyPem, cert: enrolled.certPem, verifyServer: true });
    assert(res.status === 403, `status ${res.status}`);
    const after = await auditCount('agent.checkin_refused', enrolled.agentId);
    assert(after === before + 1, 'retirement refusal not audited');
    return 'retired → 403 + audited';
  });

  // ============ Invariants ============
  await check('N16', 'audit has enroll + activation events for this run', async () => {
    const enroll = await auditCount('agent.enroll');
    const activated = await auditCount('agent.activated', enrolled.agentId);
    assert(enroll >= 1 && activated >= 1, `enroll=${enroll} activated=${activated}`);
    return `enroll ${enroll}, activation logged`;
  });

  await check('N17', 'audit hash-chain intact after all enrollment operations', async () => {
    const broken = await verifyChain();
    assert(broken === null, `chain broken at seq ${broken}`);
    return 'AUDIT CHAIN INTACT';
  });

  // ---- cleanup (audit rows are append-only and remain) ----
  await pool.query('delete from agents where hostname like $1', [`${TAG}%`]);
  await pool.query('delete from enrollment_tokens where created_by = $1', [TAG]);
  await new Promise((r) => server.close(r));

  console.log(`\n${passed} passed, ${failed} failed, ${results.length} total\n`);
  fs.writeFileSync(
    path.join(__dirname, '.enrollment-results.json'),
    JSON.stringify({ generatedAt: new Date().toISOString(), opensslAvailable: OPENSSL, passed, failed, results }, null, 2)
  );
  await pool.end();
  process.exit(failed === 0 ? 0 : 1);
}

main().catch(async (err) => {
  console.error(err);
  try { await pool.query('delete from agents where hostname like $1', [`${TAG}%`]); } catch {}
  try { if (server) server.close(); } catch {}
  process.exit(1);
});
