#!/usr/bin/env node
'use strict';
// The mTLS listener that agents talk to:  npm run agent-server   (default :8443)
//
// Presents the CA-signed server certificate (agents pin the CA and verify it),
// and REQUESTS a client certificate. rejectUnauthorized is false ONLY because
// /agent/enroll must be reachable by not-yet-enrolled agents that have no
// certificate; every route past enrollment enforces req.socket.authorized
// itself (see agent/agentApp.js).
require('dotenv').config();
const https = require('https');
const { caExists, loadServerTlsMaterial } = require('../lib/ca');
const app = require('../agent/agentApp');

if (!caExists()) {
  console.error('CA not initialized — run: npm run init-ca');
  process.exit(1);
}

const port = Number(process.env.AGENT_PORT || 8443);
const tls = loadServerTlsMaterial();

const server = https.createServer(
  {
    key: tls.key,
    cert: tls.cert,
    ca: tls.ca, // trust anchor for verifying agent client certificates
    requestCert: true,
    rejectUnauthorized: false,
    minVersion: 'TLSv1.2',
  },
  app
);

server.listen(port, () => {
  console.log(`agent mTLS listener on https://0.0.0.0:${port}`);
});
