require('dotenv').config();
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is not set — copy .env.example to .env');
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Docker Desktop's NAT proxy silently drops quiet TCP connections; keep-alive
  // stops idle pool clients from being culled between requests.
  keepAlive: true,
});

// An idle client losing its connection emits 'error' on the pool; without a
// handler that event is fatal to the whole process. Log it and let the pool
// replace the client on next checkout instead.
pool.on('error', (err) => {
  console.error('[db] idle client connection error (client will be replaced):', err.message);
});

// A CHECKED-OUT client (pool.connect() held across a transaction, as the worker
// does) emits 'error' on the client itself — also fatal without a listener. The
// in-flight query still rejects and is handled by the caller; this listener only
// absorbs the duplicate event so a dropped connection can't kill the process.
pool.on('connect', (client) => {
  client.on('error', (err) => {
    console.error('[db] client connection error (in-flight query will reject):', err.message);
  });
});

module.exports = pool;
