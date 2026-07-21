'use strict';
// =====================================================================
// Manual, narrated walkthrough of the internal CA — for building confidence
// by SEEING what it does. Read-only against the real ca/ directory; writes
// demo artifacts to scripts/.demo/ so you can inspect them yourself.
//
//   node scripts/ca-demo.js                       full narrated demo
//   node scripts/ca-demo.js "laptop-wants-admin"  agent requests this identity
//   node scripts/ca-demo.js --tamper              feed a corrupted CSR (rejected)
//
// Every certificate is shown via Node's native parser AND independently
// re-verified by the system OpenSSL, so you are not taking node-forge's word.
// =====================================================================
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const forge = require('node-forge');
const ca = require('../lib/ca');

const DEMO = path.join(__dirname, '.demo');
fs.mkdirSync(DEMO, { recursive: true });

// --- pretty output helpers -------------------------------------------
const line = (c = '─') => console.log(c.repeat(70));
function step(n, title) {
  console.log('');
  line('═');
  console.log(`  STEP ${n}:  ${title}`);
  line('═');
}
function say(s) {
  console.log('  ' + s);
}
function good(s) {
  console.log('  \x1b[32m✓ ' + s + '\x1b[0m');
}
function bad(s) {
  console.log('  \x1b[31m✗ ' + s + '\x1b[0m');
}

let OPENSSL = true;
try {
  execFileSync('openssl', ['version']);
} catch {
  OPENSSL = false;
}
function opensslText(file) {
  return execFileSync('openssl', ['x509', '-in', file, '-text', '-noout'], { encoding: 'utf8' });
}
function opensslVerify(caFile, leaf) {
  try {
    const out = execFileSync('openssl', ['verify', '-CAfile', caFile, leaf], { encoding: 'utf8' });
    return /: OK/.test(out);
  } catch {
    return false;
  }
}

// Show the human-meaningful fields of a certificate.
function describeCert(label, pem, file) {
  const x = new crypto.X509Certificate(pem);
  console.log('');
  say(`── ${label} ──`);
  say(`subject : ${x.subject.replace(/\n/g, ', ')}`);
  say(`issuer  : ${x.issuer.replace(/\n/g, ', ')}`);
  say(`serial  : ${x.serialNumber}`);
  say(`valid   : ${x.validFrom}  →  ${x.validTo}`);
  say(`keytype : ${x.publicKey.asymmetricKeyType.toUpperCase()}-${x.publicKey.asymmetricKeyDetails.modulusLength}`);
  if (x.subjectAltName) say(`SAN     : ${x.subjectAltName}`);
  if (OPENSSL && file) {
    const t = opensslText(file);
    const eku = (t.match(/X509v3 Extended Key Usage:[\s\S]*?\n\s*(.+)/) || [])[1];
    const bc = (t.match(/X509v3 Basic Constraints:.*\n\s*(.+)/) || [])[1];
    if (bc) say(`basic   : ${bc.trim()}`);
    if (eku) say(`EKU     : ${eku.trim()}`);
  }
  return x;
}

// =====================================================================
async function main() {
  const arg = process.argv[2] || null;
  const tamper = arg === '--tamper';
  const requestedCn = tamper ? 'agent-normal' : arg || 'CN=laptop-042, OU=please-make-me-a-CA';

  console.log('');
  line('━');
  console.log('   INTERNAL CA — MANUAL WALKTHROUGH');
  console.log(`   OpenSSL cross-check: ${OPENSSL ? 'AVAILABLE' : 'not found (native-only)'}`);
  line('━');

  // ---- STEP 0 ----
  step(0, 'Is the CA initialized?');
  if (!ca.caExists()) {
    bad('No CA found. Run:  npm run init-ca');
    process.exit(1);
  }
  const meta = ca.readMeta();
  good(`CA present in  ${ca.CA_DIR}`);
  say(`created ${meta.createdAt}`);
  say(`algorithm ${meta.caKeyBits}-bit CA / ${meta.leafKeyBits}-bit leaves, ${meta.signatureAlgorithm}`);
  say(`CA key encrypted at rest: ${meta.keyEncrypted ? 'yes' : 'no (file-permission protected)'}`);

  // ---- STEP 1 ----
  step(1, 'Look at the ROOT CA certificate (the trust anchor)');
  say('This is public — it is shipped to every agent. Note subject == issuer');
  say('(self-signed) and Basic Constraints CA:TRUE.');
  const caX = describeCert('root CA', ca.loadCaCertificatePem(), path.join(ca.CA_DIR, 'ca-cert.pem'));
  if (caX.subject === caX.issuer) good('self-signed (subject == issuer) — this is the root');
  else bad('CA is not self-signed?!');

  // ---- STEP 2 ----
  step(2, 'Look at the SERVER certificate (mTLS listener identity)');
  say('The agent will verify THIS against the CA to know it is talking to the');
  say('real server, not a counterfeit console.');
  const srvFile = path.join(ca.CA_DIR, 'server-cert.pem');
  describeCert('server cert', fs.readFileSync(srvFile), srvFile);
  const srvNative = new crypto.X509Certificate(fs.readFileSync(srvFile)).verify(caX.publicKey);
  console.log('');
  say('Does the server cert chain to the CA?');
  srvNative ? good('Node native verify: YES') : bad('Node native verify: NO');
  if (OPENSSL) {
    opensslVerify(path.join(ca.CA_DIR, 'ca-cert.pem'), srvFile)
      ? good('OpenSSL verify   : OK   (independent second opinion)')
      : bad('OpenSSL verify   : FAILED');
  }

  // ---- STEP 3 ----
  step(3, 'Act as a brand-new AGENT: generate a key + CSR');
  say('The agent makes its own key pair. The PRIVATE key never leaves the PC —');
  say('only the CSR (which carries the PUBLIC key) is sent to the server.');
  const agentKeys = forge.pki.rsa.generateKeyPair(2048);
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = agentKeys.publicKey;
  csr.setSubject([{ name: 'commonName', value: requestedCn }]);
  csr.sign(agentKeys.privateKey, forge.md.sha256.create());
  let csrPem = forge.pki.certificationRequestToPem(csr);
  fs.writeFileSync(path.join(DEMO, 'agent-key.pem'), forge.pki.privateKeyToPem(agentKeys.privateKey));
  fs.writeFileSync(path.join(DEMO, 'agent.csr'), csrPem);
  good('agent key pair generated (private key stays local)');
  say(`the agent PUT THIS in its CSR:   "${requestedCn}"`);
  if (/CA|admin/i.test(requestedCn)) say('   ↑ note the agent is TRYING to claim a privileged identity');

  if (tamper) {
    // ---- STEP 4 (adversarial) ----
    step(4, 'ADVERSARIAL: corrupt the CSR, then try to get it signed');
    const lines = csrPem.trim().split('\n');
    const mid = Math.floor(lines.length / 2);
    lines[mid] = lines[mid].split('').reverse().join('');
    csrPem = lines.join('\n');
    say('flipped bytes in the CSR body → its self-signature is now invalid');
    try {
      ca.signCertificateRequest(csrPem, { commonName: 'dlp-agent-x' });
      bad('CA SIGNED A TAMPERED CSR — this would be a serious bug');
    } catch (e) {
      good(`CA rejected it: "${e.message}"`);
      say('proof-of-possession works: you cannot get a cert for a key you do not hold');
    }
    finish();
    return;
  }

  // ---- STEP 4 ----
  const assignedCn = 'dlp-agent-' + crypto.randomUUID().slice(0, 8);
  step(4, 'Server signs the CSR — but assigns the identity ITSELF');
  say(`the server IGNORES what the agent asked and stamps:  "${assignedCn}"`);
  const issued = ca.signCertificateRequest(csrPem, { commonName: assignedCn });
  fs.writeFileSync(path.join(DEMO, 'agent-cert.pem'), issued.certPem);
  const agentFile = path.join(DEMO, 'agent-cert.pem');
  const agentX = describeCert('issued agent cert', issued.certPem, agentFile);

  // ---- STEP 5 ----
  step(5, 'The anti-spoofing check');
  say(`agent REQUESTED : ${requestedCn}`);
  say(`cert CONTAINS   : ${agentX.subject.replace(/\n/g, ', ')}`);
  if (!/please-make-me|admin|CA:/i.test(agentX.subject) && agentX.subject.includes(assignedCn)) {
    good('the requested identity was DISCARDED — the CA assigned the name');
  } else {
    bad('the requested identity leaked into the certificate!');
  }

  // ---- STEP 6 ----
  step(6, 'Does the agent certificate chain to our CA?');
  new crypto.X509Certificate(issued.certPem).verify(caX.publicKey)
    ? good('Node native verify: YES')
    : bad('Node native verify: NO');
  if (OPENSSL) {
    opensslVerify(path.join(ca.CA_DIR, 'ca-cert.pem'), agentFile)
      ? good('OpenSSL verify   : OK   (independent second opinion)')
      : bad('OpenSSL verify   : FAILED');
  }
  say('EKU is clientAuth (agent) vs the server cert’s serverAuth — different roles.');

  finish(assignedCn);
}

function finish(assignedCn) {
  console.log('');
  line('━');
  console.log('   DONE. Artifacts written to scripts/.demo/ — inspect them yourself:');
  console.log('');
  console.log('     openssl x509 -in ca/ca-cert.pem            -text -noout   # the CA');
  console.log('     openssl x509 -in ca/server-cert.pem        -text -noout   # server cert');
  console.log('     openssl x509 -in scripts/.demo/agent-cert.pem -text -noout   # agent cert');
  console.log('     openssl verify -CAfile ca/ca-cert.pem scripts/.demo/agent-cert.pem');
  console.log('');
  console.log('   Try to break it:');
  console.log('     node scripts/ca-demo.js "CN=i-am-the-sysadmin"   # agent cannot self-name');
  console.log('     node scripts/ca-demo.js --tamper                 # forged CSR is rejected');
  line('━');
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
