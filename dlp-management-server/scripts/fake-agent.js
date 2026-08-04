'use strict';
// =====================================================================
// Stand-in for the future Rust agent — proves the secure channel end to end,
// so you can SEE enrollment + mTLS working before any Rust exists.
//
//   1) start the listener:   npm run agent-server
//   2) mint a token as sysadmin (console), then:
//        node scripts/fake-agent.js <enrollment-token> [host] [port]
//   3) run again with no token to re-use the stored cert and just check in.
//
// It generates its key pair locally (the PRIVATE key never leaves), enrolls,
// then checks in over mutual TLS while PINNING the CA to verify the server.
// State is kept in scripts/.fake-agent/.
// =====================================================================
const fs = require('fs');
const path = require('path');
const https = require('https');
const os = require('os');
const forge = require('node-forge');

const STATE = path.join(__dirname, '.fake-agent');
const HOST = process.argv[3] || 'localhost';
const PORT = Number(process.argv[4] || process.env.AGENT_PORT || 8443);

const good = (s) => console.log('  \x1b[32m✓ ' + s + '\x1b[0m');
const say = (s) => console.log('  ' + s);

function request(opts, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = https.request(
      { host: HOST, port: PORT, agent: false, servername: 'localhost',
        headers: { 'Content-Type': 'application/json', Connection: 'close' }, ...opts },
      (res) => {
        let b = '';
        res.on('data', (c) => (b += c));
        res.on('end', () => resolve({ status: res.statusCode, body: b ? JSON.parse(b) : null }));
      }
    );
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function enroll(token) {
  say('[1/4] generating an RSA-2048 key pair + CSR (private key stays local)…');
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;
  csr.setSubject([{ name: 'commonName', value: os.hostname() }]);
  csr.sign(keys.privateKey, forge.md.sha256.create());

  say('[2/4] enrolling: presenting the one-time token + CSR…');
  const res = await request(
    // rejectUnauthorized:false ONLY here — enrollment is how we obtain the CA
    // to pin. A real installer ships with the CA pinned from the start.
    { path: '/agent/enroll', method: 'POST', rejectUnauthorized: false },
    { token, csrPem: forge.pki.certificationRequestToPem(csr), hostname: os.hostname(),
      os: `${os.platform()} ${os.release()}`, agentVersion: '0.0.1-fake' }
  );
  if (res.status !== 201) throw new Error(`enrollment failed [${res.status}]: ${JSON.stringify(res.body)}`);
  fs.mkdirSync(STATE, { recursive: true });
  fs.writeFileSync(path.join(STATE, 'agent-key.pem'), forge.pki.privateKeyToPem(keys.privateKey), { mode: 0o600 });
  fs.writeFileSync(path.join(STATE, 'agent-cert.pem'), res.body.certificate);
  fs.writeFileSync(path.join(STATE, 'ca.pem'), res.body.ca);
  good(`enrolled as agent ${res.body.agentId}`);
  say(`received: client certificate + CA (pinned for future connections)`);
}

async function checkin() {
  const key = fs.readFileSync(path.join(STATE, 'agent-key.pem'));
  const cert = fs.readFileSync(path.join(STATE, 'agent-cert.pem'));
  const caPem = fs.readFileSync(path.join(STATE, 'ca.pem'));

  say('[3/4] checking in over MUTUAL TLS (server verifies us, we verify server)…');
  const res = await request(
    { path: '/agent/checkin', method: 'POST', key, cert, ca: caPem, rejectUnauthorized: true },
    { agentVersion: '0.0.1-fake' }
  );
  if (res.status !== 200) throw new Error(`checkin failed [${res.status}]: ${JSON.stringify(res.body)}`);
  good(`check-in accepted — status=${res.body.status}, next in ${res.body.checkinIntervalSeconds}s`);
  say('[4/4] both identities proven: our cert to the server, the CA-signed server cert to us.');
  console.log('');
  good('SECURE CHANNEL VERIFIED: enroll → mTLS check-in');
}

async function main() {
  const token = process.argv[2];
  const already = fs.existsSync(path.join(STATE, 'agent-cert.pem'));
  console.log('');
  if (!already) {
    if (!token) {
      console.error('Usage: node scripts/fake-agent.js <enrollment-token> [host] [port]');
      process.exit(1);
    }
    await enroll(token);
  } else {
    say('[1-2/4] already enrolled — reusing stored certificate');
  }
  await checkin();
}

main().catch((e) => { console.error('  ' + e.message); process.exit(1); });
