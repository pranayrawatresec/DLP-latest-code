#!/usr/bin/env node
// Creates the FIRST sysadmin account. Runs only on the server box — there is
// no signup page, ever. Refuses to run if any admin already exists (after
// that, user management happens in the console by a sysadmin).
//
// Interactive:      npm run bootstrap-admin
// Non-interactive:  DLP_ADMIN_EMAIL=... DLP_ADMIN_PASSWORD=... npm run bootstrap-admin
const readline = require('readline');
const bcrypt = require('bcryptjs');
const pool = require('../db/pool');
const { audit } = require('../lib/audit');

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD_LENGTH = 12;

function ask(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) =>
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    })
  );
}

// Password prompt with no echo.
function askHidden(question) {
  return new Promise((resolve) => {
    process.stdout.write(question);
    const stdin = process.stdin;
    stdin.resume();
    stdin.setRawMode(true);
    let value = '';
    const NL = String.fromCharCode(10);
    const onData = (chunk) => {
      const ch = chunk.toString('utf8');
      const code = ch.charCodeAt(0);
      if (code === 13 || code === 10 || code === 4) {
        // Enter (CR/LF) or Ctrl-D
        stdin.setRawMode(false);
        stdin.pause();
        stdin.removeListener('data', onData);
        process.stdout.write(NL);
        resolve(value);
      } else if (code === 3) {
        // Ctrl-C
        process.stdout.write(NL);
        process.exit(1);
      } else if (code === 127 || code === 8) {
        // Backspace / Delete
        value = value.slice(0, -1);
      } else {
        value += ch;
      }
    };
    stdin.on('data', onData);
  });
}

async function main() {
  const existing = await pool.query('select count(*)::int as n from admin_users');
  if (existing.rows[0].n > 0) {
    console.error(
      'Refusing: admin account(s) already exist. Create further users in the console (sysadmin role).'
    );
    process.exit(1);
  }

  const email = (process.env.DLP_ADMIN_EMAIL || (await ask('Admin email: ')))
    .trim()
    .toLowerCase();
  if (!EMAIL_RE.test(email)) {
    console.error('Invalid email.');
    process.exit(1);
  }

  let password = process.env.DLP_ADMIN_PASSWORD;
  if (!password) {
    password = await askHidden('Password (min 12 chars, not echoed): ');
    const confirm = await askHidden('Confirm password: ');
    if (password !== confirm) {
      console.error('Passwords do not match.');
      process.exit(1);
    }
  }
  if (password.length < MIN_PASSWORD_LENGTH) {
    console.error(`Password must be at least ${MIN_PASSWORD_LENGTH} characters.`);
    process.exit(1);
  }

  const pwHash = await bcrypt.hash(password, 12);
  const client = await pool.connect();
  try {
    await client.query('begin');
    const { rows } = await client.query(
      `insert into admin_users (email, display_name, pw_hash)
       values ($1, 'Bootstrap Administrator', $2) returning id`,
      [email, pwHash]
    );
    await client.query(
      `insert into user_roles (user_id, role_id, granted_by)
       select $1, id, 'cli:bootstrap' from roles where name = 'sysadmin'`,
      [rows[0].id]
    );
    await client.query('commit');
  } catch (err) {
    await client.query('rollback').catch(() => {});
    throw err;
  } finally {
    client.release();
  }

  await audit('cli:bootstrap', 'user.create', email, { roles: ['sysadmin'] });
  console.log(`Created sysadmin ${email}. Log in through the console UI.`);
  await pool.end();
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
