'use strict';
// =====================================================================
// Internal Certificate Authority (Plane 2, guide §2.2)
//
// The management server is its own private CA: it issues and verifies every
// certificate locally, so agent identity works with NO internet and NO
// external CA. This is what lets the product run in air-gapped sites.
//
// Design (see docs/internal-ca.html for the full rationale):
//   * Key generation uses Node's native crypto (OpenSSL-backed) — strong
//     entropy, fast. node-forge only assembles/signs the X.509 structure.
//   * Single-level CA (no intermediate) — pathLenConstraint = 0 forbids
//     sub-CAs. HSM + FIPS module are Phase 6.
//   * RSA-4096 CA / RSA-2048 leaves, SHA-256 — FIPS-accepted for defence.
//   * Every issued cert: random 128-bit serial, SKI/AKI, correct
//     basicConstraints / keyUsage / extKeyUsage, clock-skew backdating.
//
// This module is pure crypto + filesystem. It deliberately does NOT touch
// the database or the audit log — callers (bin/init-ca.js, the enrollment
// layer) own persistence and auditing. That keeps the CA unit-testable in
// isolation.
// =====================================================================
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const forge = require('node-forge');
const { pki } = forge;

const CA_DIR = process.env.CA_DIR || path.join(__dirname, '..', 'ca');

// --- Tunables (algorithm / lifetime policy) --------------------------
const CA_KEY_BITS = 4096;
const LEAF_KEY_BITS = 2048;
const CA_VALIDITY_YEARS = 10;
const SERVER_VALIDITY_DAYS = 730; // 2 years
const AGENT_VALIDITY_DAYS = 365; // 1 year
const CLOCK_SKEW_MS = 5 * 60 * 1000; // backdate notBefore to tolerate skew
const SERIAL_BYTES = 16; // 128-bit serial numbers

// File names inside CA_DIR.
const F = {
  caKey: 'ca-key.pem',
  caCert: 'ca-cert.pem',
  serverKey: 'server-key.pem',
  serverCert: 'server-cert.pem',
  meta: 'ca-meta.json',
};

function p(name) {
  return path.join(CA_DIR, name);
}

// ---------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------

// RFC 5280: serial must be a positive integer, <= 20 octets. We use 128 bits
// of CSPRNG entropy and clear the top bit so it is always positive (avoids the
// signed-encoding ambiguity) — well above the 64-bit-entropy best practice.
function newSerialHex() {
  const bytes = crypto.randomBytes(SERIAL_BYTES);
  bytes[0] &= 0x7f;
  if (bytes[0] === 0x00) bytes[0] = 0x01; // never all-zero leading byte
  return bytes.toString('hex');
}

// Node's TLS layer reports peer serials as hex without leading zeros; forge
// keeps them. Compare in one canonical form (lowercase, no leading zeros).
function canonicalSerial(serial) {
  const s = String(serial).toLowerCase().replace(/^0+/, '');
  return s.length ? s : '0';
}

function notBefore() {
  return new Date(Date.now() - CLOCK_SKEW_MS);
}
function daysFromNow(days) {
  return new Date(Date.now() + days * 24 * 60 * 60 * 1000);
}
function yearsFromNow(years) {
  const d = new Date();
  d.setFullYear(d.getFullYear() + years);
  return d;
}

// Native keygen -> forge objects. Keys come from Node's OpenSSL-backed CSPRNG;
// forge only ever handles the already-generated key material.
function generateKeyPair(bits) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: bits,
  });
  return {
    forgePrivate: pki.privateKeyFromPem(privateKey.export({ type: 'pkcs1', format: 'pem' })),
    forgePublic: pki.publicKeyFromPem(publicKey.export({ type: 'spki', format: 'pem' })),
    // PKCS#8 is what we persist (optionally encrypted).
    pkcs8Pem: privateKey.export({ type: 'pkcs8', format: 'pem' }),
  };
}

// Persist a private key as PKCS#8 PEM, AES-256 encrypted if a passphrase is
// configured. mode 0600 regardless (best-effort on Windows).
function writePrivateKey(file, pkcs8Pem, passphrase) {
  let out = pkcs8Pem;
  if (passphrase) {
    const keyObj = crypto.createPrivateKey(pkcs8Pem);
    out = keyObj.export({
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase,
    });
  }
  fs.writeFileSync(p(file), out, { mode: 0o600 });
}

function readForgePrivateKey(file, passphrase) {
  const pem = fs.readFileSync(p(file), 'utf8');
  // Normalize through Node crypto so both encrypted and plain PKCS#8 load,
  // then hand an unencrypted PKCS#8 to forge for signing.
  const keyObj = crypto.createPrivateKey(passphrase ? { key: pem, passphrase } : pem);
  return pki.privateKeyFromPem(keyObj.export({ type: 'pkcs8', format: 'pem' }));
}

// Standard extension sets --------------------------------------------
function caExtensions(publicKey) {
  return [
    { name: 'basicConstraints', cA: true, pathLenConstraint: 0, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
    { name: 'subjectKeyIdentifier' },
  ];
}
function serverLeafExtensions(dnsNames, ipAddresses) {
  const altNames = [];
  for (const d of dnsNames) altNames.push({ type: 2, value: d }); // dNSName
  for (const ip of ipAddresses) altNames.push({ type: 7, ip }); // iPAddress
  return [
    { name: 'basicConstraints', cA: false, critical: true },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true, critical: true },
    { name: 'extKeyUsage', serverAuth: true },
    { name: 'subjectAltName', altNames },
    { name: 'subjectKeyIdentifier' },
  ];
}
function clientLeafExtensions() {
  return [
    { name: 'basicConstraints', cA: false, critical: true },
    { name: 'keyUsage', digitalSignature: true, critical: true },
    { name: 'extKeyUsage', clientAuth: true },
    { name: 'subjectKeyIdentifier' },
  ];
}

// Attach an Authority Key Identifier that points at the CA's Subject Key
// Identifier (RFC 5280 chain-building aid).
function addAuthorityKeyId(cert, caCert) {
  const ski = caCert.getExtension('subjectKeyIdentifier');
  if (ski && ski.subjectKeyIdentifier) {
    cert.setExtensions([
      ...cert.extensions,
      {
        name: 'authorityKeyIdentifier',
        keyIdentifier: forge.util.hexToBytes(ski.subjectKeyIdentifier),
      },
    ]);
  }
}

// ---------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------

function caExists() {
  return fs.existsSync(p(F.caKey)) && fs.existsSync(p(F.caCert));
}

// One-time initialization: root CA + the agent-listener server certificate.
// Refuses to overwrite an existing CA — regenerating it would orphan every
// enrolled agent in the field.
function initializeCa(options = {}) {
  const {
    commonName = 'DLP Internal CA',
    organization = 'DLP Management Server',
    country = null,
    serverDnsNames = ['localhost'],
    serverIpAddresses = ['127.0.0.1'],
    passphrase = process.env.CA_KEY_PASSPHRASE || null,
    force = false,
  } = options;

  if (caExists() && !force) {
    throw new Error(`CA already initialized in ${CA_DIR} — refusing to overwrite`);
  }
  fs.mkdirSync(CA_DIR, { recursive: true });

  const caSubject = [{ name: 'commonName', value: commonName }, { name: 'organizationName', value: organization }];
  if (country) caSubject.push({ name: 'countryName', value: country });

  // --- Root CA (self-signed) ---
  const caKeys = generateKeyPair(CA_KEY_BITS);
  const caCert = pki.createCertificate();
  caCert.publicKey = caKeys.forgePublic;
  caCert.serialNumber = newSerialHex();
  caCert.validity.notBefore = notBefore();
  caCert.validity.notAfter = yearsFromNow(CA_VALIDITY_YEARS);
  caCert.setSubject(caSubject);
  caCert.setIssuer(caSubject); // self-signed
  caCert.setExtensions(caExtensions(caKeys.forgePublic));
  caCert.sign(caKeys.forgePrivate, forge.md.sha256.create());

  // --- Agent-listener server certificate (signed by the CA) ---
  const serverCn = serverDnsNames[0] || 'localhost';
  const serverKeys = generateKeyPair(LEAF_KEY_BITS);
  const serverCert = pki.createCertificate();
  serverCert.publicKey = serverKeys.forgePublic;
  serverCert.serialNumber = newSerialHex();
  serverCert.validity.notBefore = notBefore();
  serverCert.validity.notAfter = daysFromNow(SERVER_VALIDITY_DAYS);
  serverCert.setSubject([{ name: 'commonName', value: serverCn }]);
  serverCert.setIssuer(caSubject);
  serverCert.setExtensions(serverLeafExtensions(serverDnsNames, serverIpAddresses));
  addAuthorityKeyId(serverCert, caCert);
  serverCert.sign(caKeys.forgePrivate, forge.md.sha256.create());

  // Persist. CA key is the crown jewel — optionally passphrase-encrypted.
  // Server key stays unencrypted so the TLS listener starts unattended.
  writePrivateKey(F.caKey, caKeys.pkcs8Pem, passphrase);
  fs.writeFileSync(p(F.caCert), pki.certificateToPem(caCert));
  writePrivateKey(F.serverKey, serverKeys.pkcs8Pem, null);
  fs.writeFileSync(p(F.serverCert), pki.certificateToPem(serverCert));
  fs.writeFileSync(
    p(F.meta),
    JSON.stringify(
      {
        createdAt: new Date().toISOString(),
        caSubject: commonName,
        caKeyBits: CA_KEY_BITS,
        leafKeyBits: LEAF_KEY_BITS,
        signatureAlgorithm: 'sha256WithRSAEncryption',
        caSerial: canonicalSerial(caCert.serialNumber),
        caNotAfter: caCert.validity.notAfter.toISOString(),
        keyEncrypted: Boolean(passphrase),
      },
      null,
      2
    )
  );

  return {
    dir: CA_DIR,
    caSerial: canonicalSerial(caCert.serialNumber),
    caNotAfter: caCert.validity.notAfter,
    serverCn,
    serverNotAfter: serverCert.validity.notAfter,
    keyEncrypted: Boolean(passphrase),
  };
}

// Sign an agent's CSR into a client certificate. The CSR only proves the
// agent holds its private key; the identity (CN) we stamp is OUR choice —
// never what the CSR asked for. This is what stops an agent naming itself.
function signCertificateRequest(csrPem, opts = {}) {
  const { commonName, validityDays = AGENT_VALIDITY_DAYS, passphrase = process.env.CA_KEY_PASSPHRASE || null } = opts;
  if (!commonName) throw new Error('commonName is required (server-assigned identity)');

  let csr;
  try {
    csr = pki.certificationRequestFromPem(String(csrPem));
  } catch (err) {
    throw new Error('malformed CSR');
  }
  if (!csr.verify()) throw new Error('CSR self-signature invalid'); // proof-of-possession

  // Reject weak or unsupported keys. We issue and expect RSA leaves (>= 2048);
  // a rogue/legacy agent must not enroll with a breakable key.
  const pub = csr.publicKey;
  if (!pub || !pub.n || typeof pub.n.bitLength !== 'function') {
    throw new Error('unsupported key type (RSA required)');
  }
  const keyBits = pub.n.bitLength();
  if (keyBits < LEAF_KEY_BITS) {
    throw new Error(`weak key: ${keyBits}-bit (minimum ${LEAF_KEY_BITS})`);
  }

  const caKey = readForgePrivateKey(F.caKey, passphrase);
  const caCert = pki.certificateFromPem(fs.readFileSync(p(F.caCert), 'utf8'));

  const cert = pki.createCertificate();
  cert.publicKey = csr.publicKey;
  cert.serialNumber = newSerialHex();
  cert.validity.notBefore = notBefore();
  cert.validity.notAfter = daysFromNow(validityDays);
  cert.setSubject([{ name: 'commonName', value: String(commonName) }]);
  cert.setIssuer(caCert.subject.attributes);
  cert.setExtensions(clientLeafExtensions());
  addAuthorityKeyId(cert, caCert);
  cert.sign(caKey, forge.md.sha256.create());

  return {
    certPem: pki.certificateToPem(cert),
    serial: canonicalSerial(cert.serialNumber),
    notAfter: cert.validity.notAfter,
    subjectCommonName: String(commonName),
  };
}

function loadCaCertificatePem() {
  return fs.readFileSync(p(F.caCert), 'utf8');
}

// RSASSA-PKCS1-v1_5 / SHA-256 signature over an arbitrary buffer with the CA
// private key — used to sign index bundles so agents can verify them against
// the CA certificate they already pin from enrollment. Same algorithm as the
// X.509 signing above (sha256WithRSAEncryption), just over raw bytes.
function signBuffer(buffer, opts = {}) {
  const { passphrase = process.env.CA_KEY_PASSPHRASE || null } = opts;
  if (!Buffer.isBuffer(buffer)) throw new Error('signBuffer expects a Buffer');
  const pem = fs.readFileSync(p(F.caKey), 'utf8');
  // Normalize through Node crypto so both encrypted and plain PKCS#8 load.
  const keyObj = crypto.createPrivateKey(passphrase ? { key: pem, passphrase } : pem);
  return crypto.sign('sha256', buffer, keyObj);
}

// Verify a signBuffer() signature against a CA certificate PEM. Pure
// verification — needs no key material, so agents/tests can run it anywhere.
function verifyBufferSignature(buffer, signature, caCertPem) {
  if (!Buffer.isBuffer(buffer) || !Buffer.isBuffer(signature)) return false;
  const cert = new crypto.X509Certificate(String(caCertPem));
  return crypto.verify('sha256', buffer, cert.publicKey, signature);
}

// Material for the mTLS listener: its key/cert plus the CA as the trust
// anchor for verifying agent client certificates.
function loadServerTlsMaterial() {
  return {
    key: fs.readFileSync(p(F.serverKey), 'utf8'),
    cert: fs.readFileSync(p(F.serverCert), 'utf8'),
    ca: loadCaCertificatePem(),
  };
}

function readMeta() {
  return JSON.parse(fs.readFileSync(p(F.meta), 'utf8'));
}

module.exports = {
  CA_DIR,
  FILES: F,
  caExists,
  initializeCa,
  signCertificateRequest,
  signBuffer,
  verifyBufferSignature,
  loadCaCertificatePem,
  loadServerTlsMaterial,
  readMeta,
  canonicalSerial,
  // exposed for tests
  _internal: { newSerialHex, generateKeyPair },
};
