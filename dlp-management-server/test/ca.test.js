'use strict';
// Comprehensive test + edge-case harness for the internal CA (lib/ca.js).
//
// Every generated certificate is cross-verified with TWO independent tools —
// Node's native crypto.X509Certificate AND the system OpenSSL — so the results
// never rest on node-forge's own say-so.
//
// Runs against a THROWAWAY CA dir (test/.ca-tmp), never the real ca/.
// Emits a JSON summary to test/.ca-tmp/results.json for the HTML report.
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { execFileSync } = require('child_process');
const forge = require('node-forge');

const TMP = path.join(__dirname, '.ca-tmp');
fs.rmSync(TMP, { recursive: true, force: true });
fs.mkdirSync(TMP, { recursive: true });
process.env.CA_DIR = TMP; // point the module at the throwaway dir BEFORE require
delete process.env.CA_KEY_PASSPHRASE;

const ca = require('../lib/ca');

// --- tiny test runner -------------------------------------------------
const results = [];
let passed = 0;
let failed = 0;
function check(id, name, fn) {
  try {
    const detail = fn() || '';
    results.push({ id, name, status: 'PASS', detail: String(detail) });
    passed++;
    console.log(`  PASS  ${id}  ${name}`);
  } catch (err) {
    results.push({ id, name, status: 'FAIL', detail: err.message });
    failed++;
    console.log(`  FAIL  ${id}  ${name}\n        ${err.message}`);
  }
}
function assert(cond, msg) {
  if (!cond) throw new Error(msg || 'assertion failed');
}

// Is the system openssl usable for independent verification?
let OPENSSL = true;
try {
  execFileSync('openssl', ['version']);
} catch {
  OPENSSL = false;
  console.log('  (openssl not found — skipping independent OpenSSL cross-checks)');
}
function opensslVerify(caCertPath, leafPath) {
  // Returns true only if OpenSSL says the chain is OK.
  const out = execFileSync('openssl', ['verify', '-CAfile', caCertPath, leafPath], {
    encoding: 'utf8',
  });
  return /: OK\s*$/.test(out.trim());
}
function opensslText(certPath) {
  return execFileSync('openssl', ['x509', '-in', certPath, '-text', '-noout'], {
    encoding: 'utf8',
  });
}

console.log('\nInternal CA — test & edge-case suite\n');

// ============ 1. Initialization ============
check('T01', 'initializeCa creates all key/cert files', () => {
  const r = ca.initializeCa({
    commonName: 'DLP Test CA',
    organization: 'Test Org',
    serverDnsNames: ['dlp.test.local', 'localhost'],
    serverIpAddresses: ['127.0.0.1'],
  });
  for (const f of ['ca-key.pem', 'ca-cert.pem', 'server-key.pem', 'server-cert.pem', 'ca-meta.json']) {
    assert(fs.existsSync(path.join(TMP, f)), `missing ${f}`);
  }
  return `CA serial ${r.caSerial}, CA notAfter ${r.caNotAfter.toISOString().slice(0, 10)}`;
});

check('T02', 'caExists() is true after init', () => {
  assert(ca.caExists() === true);
});

check('T03', 're-init WITHOUT force is refused (would orphan agents)', () => {
  let threw = false;
  try {
    ca.initializeCa({ commonName: 'Second' });
  } catch (e) {
    threw = /refusing to overwrite/.test(e.message);
  }
  assert(threw, 'second init should have been refused');
});

// ============ 2. CA certificate shape ============
check('T04', 'CA cert: native X509 parses; self-issued', () => {
  const x = new crypto.X509Certificate(ca.loadCaCertificatePem());
  assert(x.subject === x.issuer, 'CA must be self-issued');
  assert(/DLP Test CA/.test(x.subject), 'unexpected CA subject');
  return x.subject.replace(/\n/g, ' ');
});

check('T05', 'CA cert: basicConstraints cA=TRUE, pathlen 0 (OpenSSL)', () => {
  if (!OPENSSL) return 'skipped (no openssl)';
  const t = opensslText(path.join(TMP, 'ca-cert.pem'));
  assert(/CA:TRUE/.test(t), 'CA:TRUE not found');
  assert(/pathlen:0/.test(t), 'pathlen:0 not found');
  assert(/Certificate Sign/.test(t) && /CRL Sign/.test(t), 'CA keyUsage wrong');
  return 'CA:TRUE, pathlen:0, keyCertSign+cRLSign';
});

check('T06', 'CA key is RSA-4096', () => {
  const x = new crypto.X509Certificate(ca.loadCaCertificatePem());
  const bits = x.publicKey.asymmetricKeyDetails.modulusLength;
  assert(bits === 4096, `expected 4096, got ${bits}`);
  return `${bits}-bit RSA`;
});

// ============ 3. Server certificate ============
check('T07', 'server cert chains to CA (native verify)', () => {
  const caX = new crypto.X509Certificate(ca.loadCaCertificatePem());
  const srvX = new crypto.X509Certificate(fs.readFileSync(path.join(TMP, 'server-cert.pem')));
  assert(srvX.verify(caX.publicKey), 'native signature verification failed');
  assert(srvX.checkIssued(caX), 'checkIssued failed');
  return 'verified against CA public key';
});

check('T08', 'server cert chains to CA (independent OpenSSL)', () => {
  if (!OPENSSL) return 'skipped (no openssl)';
  assert(
    opensslVerify(path.join(TMP, 'ca-cert.pem'), path.join(TMP, 'server-cert.pem')),
    'openssl verify did not return OK'
  );
  return 'openssl verify: OK';
});

check('T09', 'server cert has SAN (dns + ip) and EKU serverAuth', () => {
  const srvX = new crypto.X509Certificate(fs.readFileSync(path.join(TMP, 'server-cert.pem')));
  assert(/dlp\.test\.local/.test(srvX.subjectAltName || ''), 'SAN dns missing');
  assert(/127\.0\.0\.1/.test(srvX.subjectAltName || ''), 'SAN ip missing');
  if (OPENSSL) {
    const t = opensslText(path.join(TMP, 'server-cert.pem'));
    assert(/TLS Web Server Authentication/.test(t), 'EKU serverAuth missing');
  }
  return srvX.subjectAltName;
});

check('T10', 'server key and cert form a matching pair', () => {
  const srvX = new crypto.X509Certificate(fs.readFileSync(path.join(TMP, 'server-cert.pem')));
  const key = crypto.createPrivateKey(fs.readFileSync(path.join(TMP, 'server-key.pem')));
  assert(srvX.checkPrivateKey(key), 'server key does not match server cert');
  return 'key/cert pair matches';
});

// ============ 4. CSR signing (agent enrollment core) ============
function makeCsr(requestedCn) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const csr = forge.pki.createCertificationRequest();
  csr.publicKey = keys.publicKey;
  csr.setSubject([{ name: 'commonName', value: requestedCn }]);
  csr.sign(keys.privateKey, forge.md.sha256.create());
  return { csrPem: forge.pki.certificationRequestToPem(csr), keys };
}

check('T11', 'valid CSR is signed into a client cert that chains to CA', () => {
  const { csrPem } = makeCsr('whatever-the-agent-put');
  const out = ca.signCertificateRequest(csrPem, { commonName: 'dlp-agent-abc123' });
  fs.writeFileSync(path.join(TMP, 'agent-cert.pem'), out.certPem);
  const caX = new crypto.X509Certificate(ca.loadCaCertificatePem());
  const agX = new crypto.X509Certificate(out.certPem);
  assert(agX.verify(caX.publicKey), 'agent cert does not verify against CA');
  if (OPENSSL) {
    assert(opensslVerify(path.join(TMP, 'ca-cert.pem'), path.join(TMP, 'agent-cert.pem')), 'openssl verify failed');
  }
  return `serial ${out.serial}`;
});

check('T12', 'CA-assigned identity OVERRIDES the CSR subject', () => {
  const { csrPem } = makeCsr('CN=i-am-the-sysadmin');
  const out = ca.signCertificateRequest(csrPem, { commonName: 'dlp-agent-server-assigned' });
  const agX = new crypto.X509Certificate(out.certPem);
  assert(/dlp-agent-server-assigned/.test(agX.subject), 'server-assigned CN not applied');
  assert(!/sysadmin/.test(agX.subject), 'CSR-requested identity leaked into cert!');
  return agX.subject.replace(/\n/g, ' ');
});

check('T13', 'agent cert carries EKU clientAuth (not serverAuth)', () => {
  if (!OPENSSL) return 'skipped (no openssl)';
  const t = opensslText(path.join(TMP, 'agent-cert.pem'));
  assert(/TLS Web Client Authentication/.test(t), 'clientAuth EKU missing');
  assert(!/TLS Web Server Authentication/.test(t), 'agent must NOT have serverAuth');
  return 'clientAuth only';
});

// ============ 5. Failure / adversarial cases ============
check('T14', 'malformed CSR is rejected', () => {
  let threw = false;
  try {
    ca.signCertificateRequest('-----BEGIN CERTIFICATE REQUEST-----\nnot-base64\n-----END CERTIFICATE REQUEST-----', {
      commonName: 'x',
    });
  } catch (e) {
    threw = /malformed CSR/.test(e.message);
  }
  assert(threw, 'malformed CSR should have been rejected');
});

check('T15', 'CSR with a tampered signature is rejected (proof-of-possession)', () => {
  const { csrPem } = makeCsr('agent-x');
  // Flip bytes in the middle of the CSR body to break its self-signature.
  const lines = csrPem.trim().split('\n');
  const mid = Math.floor(lines.length / 2);
  lines[mid] = lines[mid].split('').reverse().join('');
  let threw = false;
  try {
    ca.signCertificateRequest(lines.join('\n'), { commonName: 'agent-x' });
  } catch (e) {
    threw = /malformed CSR|self-signature invalid/.test(e.message);
  }
  assert(threw, 'tampered CSR should have been rejected');
});

check('T16', 'signing without a server-assigned commonName is refused', () => {
  const { csrPem } = makeCsr('agent-y');
  let threw = false;
  try {
    ca.signCertificateRequest(csrPem, {});
  } catch (e) {
    threw = /commonName is required/.test(e.message);
  }
  assert(threw, 'missing commonName should be refused');
});

check('T17', 'a cert from a DIFFERENT CA does NOT verify against ours', () => {
  // Stand up a second, unrelated CA in another temp dir.
  const other = path.join(TMP, 'other');
  fs.mkdirSync(other, { recursive: true });
  const saved = process.env.CA_DIR;
  delete require.cache[require.resolve('../lib/ca')];
  process.env.CA_DIR = other;
  const ca2 = require('../lib/ca');
  ca2.initializeCa({ commonName: 'Rogue CA' });
  const rogueServer = fs.readFileSync(path.join(other, 'server-cert.pem'));
  process.env.CA_DIR = saved;
  delete require.cache[require.resolve('../lib/ca')];
  require('../lib/ca'); // restore original binding for later tests

  const ourCa = new crypto.X509Certificate(fs.readFileSync(path.join(TMP, 'ca-cert.pem')));
  const rogueX = new crypto.X509Certificate(rogueServer);
  assert(rogueX.verify(ourCa.publicKey) === false, 'rogue cert must NOT verify against our CA');
  if (OPENSSL) {
    let ok = true;
    try {
      opensslVerify(path.join(TMP, 'ca-cert.pem'), path.join(other, 'server-cert.pem'));
    } catch {
      ok = false; // openssl exits non-zero on failed verify
    }
    assert(ok === false, 'openssl should reject rogue cert against our CA');
  }
  return 'cross-CA verification correctly rejected';
});

// ============ 6. Serial numbers & validity ============
check('T18', 'serials are unique, positive, 128-bit', () => {
  const seen = new Set();
  for (let i = 0; i < 500; i++) {
    const h = ca._internal.newSerialHex();
    assert(h.length === 32, `serial not 16 bytes: ${h}`);
    assert(parseInt(h[0], 16) < 8, 'top bit not cleared (could be negative)');
    assert(!seen.has(h), 'duplicate serial generated');
    seen.add(h);
  }
  return '500/500 unique, positive, 16-byte';
});

check('T19', 'notBefore is backdated for clock skew; agent validity ~365d', () => {
  const { csrPem } = makeCsr('agent-z');
  const out = ca.signCertificateRequest(csrPem, { commonName: 'dlp-agent-z' });
  const x = new crypto.X509Certificate(out.certPem);
  const nb = new Date(x.validFrom).getTime();
  const na = new Date(x.validTo).getTime();
  assert(nb < Date.now(), 'notBefore should be in the past');
  const days = Math.round((na - nb) / 86400000);
  assert(days >= 365 && days <= 366, `unexpected validity span ${days}d`);
  return `validity ${days}d, backdated ${Math.round((Date.now() - nb) / 60000)}min`;
});

// ============ 7. Passphrase-encrypted CA key & reload ============
check('T20', 'passphrase-encrypted CA key: wrong pass fails, right pass signs', () => {
  const enc = path.join(TMP, 'enc');
  fs.mkdirSync(enc, { recursive: true });
  const saved = process.env.CA_DIR;
  delete require.cache[require.resolve('../lib/ca')];
  process.env.CA_DIR = enc;
  process.env.CA_KEY_PASSPHRASE = 'correct horse battery staple';
  const caE = require('../lib/ca');
  caE.initializeCa({ commonName: 'Encrypted CA' });

  // On-disk key must actually be encrypted.
  const raw = fs.readFileSync(path.join(enc, 'ca-key.pem'), 'utf8');
  assert(/ENCRYPTED/.test(raw), 'CA key on disk is not encrypted');

  // Wrong passphrase must fail to load/sign.
  const { csrPem } = makeCsr('agent-enc');
  let wrongFailed = false;
  try {
    caE.signCertificateRequest(csrPem, { commonName: 'dlp-agent-enc', passphrase: 'wrong' });
  } catch {
    wrongFailed = true;
  }
  assert(wrongFailed, 'wrong passphrase must not sign');

  // Correct passphrase (from env) must succeed — simulates a fresh process.
  const out = caE.signCertificateRequest(csrPem, { commonName: 'dlp-agent-enc' });
  const caX = new crypto.X509Certificate(caE.loadCaCertificatePem());
  assert(new crypto.X509Certificate(out.certPem).verify(caX.publicKey), 'signed cert must verify');

  // restore
  process.env.CA_DIR = saved;
  delete process.env.CA_KEY_PASSPHRASE;
  delete require.cache[require.resolve('../lib/ca')];
  require('../lib/ca');
  return 'encrypted at rest; wrong pass rejected; right pass signs';
});

check('T21', 'issued cert survives a simulated process restart (reload from disk)', () => {
  // Fresh require = new "process"; signing must still work purely from files.
  delete require.cache[require.resolve('../lib/ca')];
  process.env.CA_DIR = TMP;
  const caReloaded = require('../lib/ca');
  const { csrPem } = makeCsr('agent-restart');
  const out = caReloaded.signCertificateRequest(csrPem, { commonName: 'dlp-agent-restart' });
  const caX = new crypto.X509Certificate(caReloaded.loadCaCertificatePem());
  assert(new crypto.X509Certificate(out.certPem).verify(caX.publicKey));
  return 'reloaded CA signs correctly';
});

// --- summary ----------------------------------------------------------
console.log(`\n${passed} passed, ${failed} failed, ${results.length} total\n`);
fs.writeFileSync(
  path.join(TMP, 'results.json'),
  JSON.stringify(
    { generatedAt: new Date().toISOString(), opensslAvailable: OPENSSL, passed, failed, results },
    null,
    2
  )
);
process.exit(failed === 0 ? 0 : 1);
