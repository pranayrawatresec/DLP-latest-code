#!/usr/bin/env node
'use strict';
// One-time CA initialization, run on the server box during setup:
//   npm run init-ca
//
// Generates the internal root CA and the agent-listener server certificate,
// then records the event in the tamper-evident audit log. Refuses to run if a
// CA already exists — regenerating it would orphan every enrolled agent.
require('dotenv').config();
const os = require('os');
const ca = require('../lib/ca');
const { audit } = require('../lib/audit');

async function main() {
  if (ca.caExists()) {
    console.error(`CA already initialized in ${ca.CA_DIR}. Refusing to overwrite.`);
    console.error('Deleting a live CA orphans every enrolled agent — this is intentional.');
    process.exit(1);
  }

  const dnsPrimary = (process.env.AGENT_SERVER_DNS || os.hostname()).toLowerCase();
  const dnsNames = [...new Set([dnsPrimary, 'localhost'])];
  const passphrase = process.env.CA_KEY_PASSPHRASE || null;

  console.log('Generating internal CA (RSA-4096) and server certificate — a few seconds...');
  const r = ca.initializeCa({
    commonName: process.env.CA_COMMON_NAME || 'DLP Internal CA',
    organization: process.env.CA_ORG || 'DLP Management Server',
    country: process.env.CA_COUNTRY || null,
    serverDnsNames: dnsNames,
    serverIpAddresses: ['127.0.0.1'],
    passphrase,
  });

  // Security event — write it to the append-only, hash-chained audit log.
  await audit('cli:init-ca', 'ca.init', r.serverCn, {
    caSerial: r.caSerial,
    caNotAfter: r.caNotAfter.toISOString(),
    serverNotAfter: r.serverNotAfter.toISOString(),
    keyEncrypted: r.keyEncrypted,
  });

  console.log(`\nCA created in ${r.dir}`);
  console.log(`  root CA serial   ${r.caSerial}`);
  console.log(`  root valid until ${r.caNotAfter.toISOString().slice(0, 10)}`);
  console.log(`  server cert CN   ${r.serverCn}  (SAN: ${dnsNames.join(', ')}, 127.0.0.1)`);
  console.log(`  CA key encrypted ${r.keyEncrypted ? 'yes (passphrase)' : 'NO — file-permission protected only'}`);
  console.log('\nFiles: ca-key.pem  ca-cert.pem  server-key.pem  server-cert.pem  ca-meta.json');
  console.log('IMPORTANT: back up ca-key.pem securely and OFFLINE. If it is lost, every');
  console.log('agent in the field must re-enroll. Never commit the ca/ directory.');
  process.exit(0);
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
