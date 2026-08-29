const { Pool } = require('pg');

let pool;
function getPool() {
  if (!pool) {
    if (!process.env.DATABASE_URL) throw new Error('DATABASE_URL is required');
    pool = new Pool({
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false,
      max: 10,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 10000
    });
  }
  return pool;
}

async function query(text, values, client) {
  return (client || getPool()).query(text, values);
}

async function transaction(work) {
  const client = await getPool().connect();
  try {
    await client.query('BEGIN');
    const result = await work(client);
    await client.query('COMMIT');
    return result;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  } finally {
    client.release();
  }
}

async function migrate() {
  await query(`
    CREATE EXTENSION IF NOT EXISTS pgcrypto;
    CREATE TABLE IF NOT EXISTS organizations (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      name text NOT NULL,
      slug text NOT NULL UNIQUE,
      plan text NOT NULL DEFAULT 'trial',
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS users (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      email text NOT NULL,
      password_hash text NOT NULL,
      full_name text NOT NULL,
      role text NOT NULL DEFAULT 'admin' CHECK (role IN ('admin','analyst','auditor','viewer')),
      failed_attempts integer NOT NULL DEFAULT 0,
      locked_until timestamptz,
      last_login_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (organization_id, email)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS users_email_global_idx ON users (lower(email));
    CREATE TABLE IF NOT EXISTS cases (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      case_number text NOT NULL,
      title text NOT NULL,
      case_type text NOT NULL,
      priority text NOT NULL CHECK (priority IN ('Critical','High','Medium','Low')),
      status text NOT NULL DEFAULT 'Open',
      description text NOT NULL DEFAULT '',
      assigned_to uuid REFERENCES users(id) ON DELETE SET NULL,
      created_by uuid NOT NULL REFERENCES users(id),
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (organization_id, case_number)
    );
    CREATE TABLE IF NOT EXISTS audit_events (
      id bigserial PRIMARY KEY,
      organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      actor_id uuid REFERENCES users(id) ON DELETE SET NULL,
      action text NOT NULL,
      entity_type text NOT NULL,
      entity_id text,
      metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
      ip inet,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS cases_tenant_created_idx ON cases (organization_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS audit_tenant_created_idx ON audit_events (organization_id, created_at DESC);
  `);
}

module.exports = { getPool, query, transaction, migrate };
