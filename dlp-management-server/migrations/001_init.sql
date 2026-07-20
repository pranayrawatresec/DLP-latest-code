-- 001_init.sql — authentication, authorization, and agent licensing only.
-- (Policies, incidents, evidence, fingerprints come in later migrations.)
-- Applied inside a transaction by db/migrate.js. No BEGIN/COMMIT here.

-- ============================================================
-- AuthZ: roles and assignments
-- ============================================================

create table roles (
  id          serial primary key,
  name        text not null unique,
  description text not null default ''
);

insert into roles (name, description) values
  ('sysadmin',          'Manage users, roles, system config, licence import. Cannot read evidence.'),
  ('policy_author',     'Create and edit policies.'),
  ('incident_reviewer', 'Read incidents; read/export evidence (every access audited).'),
  ('auditor',           'Read audit log, incident metadata, licence state.');

-- ============================================================
-- AuthN: admin users (email + password login) and sessions
-- ============================================================

create table admin_users (
  id              uuid primary key default gen_random_uuid(),
  email           text not null unique,
  display_name    text not null default '',
   mfa_enrolled    boolean not null default false,
  disabled        boolean not null default false,
  failed_attempts integer not null default 0,   -- consecutive failed logins
  locked_until    timestamptz,                  -- lockout window after too many failures
  created_at      timestamptz not null default now()
);

create table user_roles (
  user_id    uuid not null references admin_users(id) on delete cascade,
  role_id    integer not null references roles(id),
  granted_by text,
  granted_at timestamptz not null default now(),
  primary key (user_id, role_id)
);

-- Console sessions. The cookie holds the raw random token; we store only its
-- SHA-256 so a database read alone cannot hijack a session.
create table sessions (
  token_hash text primary key,
  user_id    uuid not null references admin_users(id) on delete cascade,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  ip         text,
  user_agent text
);

create index sessions_user_idx on sessions (user_id);

-- ============================================================
-- Audit log: append-only, hash-chained.
-- Part of auth security: every login, failed login, lockout and
-- permission denial is recorded here (guide requirement).
-- ============================================================

create table audit_log (
  seq       bigserial primary key,
  ts        timestamptz not null,
  actor     text not null,          -- user email, 'cli:bootstrap', 'system'
  action    text not null,          -- e.g. 'auth.login', 'auth.login_failed', 'authz.denied'
  target    text,
  detail    jsonb not null default '{}'::jsonb,
  prev_hash text not null,          -- hash of previous row ('genesis' for the first)
  hash      text not null           -- sha256 over (prev_hash + canonical entry)
);

create function audit_log_append_only() returns trigger as $$
begin
  raise exception 'audit_log is append-only';
end
$$ language plpgsql;

create trigger audit_log_no_modify
  before update or delete on audit_log
  for each row execute function audit_log_append_only();

create trigger audit_log_no_truncate
  before truncate on audit_log
  for each statement execute function audit_log_append_only();

-- ============================================================
-- Agents (the installed endpoints) — needed for licensing
-- ============================================================

create table agents (
  id             uuid primary key default gen_random_uuid(),
  hostname       text not null,
  os             text,
  last_user      text,
  cert_serial    text unique,       -- Phase 2: client certificate serial
  cert_not_after timestamptz,
  agent_version  text,
  status         text not null default 'enrolled',  -- enrolled | active | offline | retired
  enrolled_at    timestamptz not null default now(),
  last_seen      timestamptz
);

-- One-time enrollment tokens. Only the hash is stored — the token itself is a
-- secret that must never be persisted or logged.
create table enrollment_tokens (
  id          uuid primary key default gen_random_uuid(),
  token_hash  text not null unique,
  description text not null default '',
  max_uses    integer not null default 1,
  use_count   integer not null default 0,
  created_by  text not null,
  created_at  timestamptz not null default now(),
  expires_at  timestamptz,
  revoked     boolean not null default false
);

-- ============================================================
-- Licensing
-- ============================================================

-- Single-row table: the active entitlement imported on this server.
create table license_state (
  id                integer primary key default 1 check (id = 1),
  seats             integer not null,
  modules           jsonb not null default '[]'::jsonb,
  expires_on        date,
  bound_fingerprint text,            -- node-lock fingerprint of this server
  license_ref       text,            -- reference to the imported licence file/dongle
  imported_at       timestamptz not null default now()
);

-- Per-agent short-lived entitlement tokens, drawn from the licence seat pool.
create table agent_entitlements (
  agent_id   uuid primary key references agents(id) on delete cascade,
  token_hash text not null,
  issued_at  timestamptz not null default now(),
  expires_at timestamptz not null
);
