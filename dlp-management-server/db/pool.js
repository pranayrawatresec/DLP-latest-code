require('dotenv').config();
const { Pool } = require('pg');

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is not set — copy .env.example to .env');
}

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

module.exports = pool;
