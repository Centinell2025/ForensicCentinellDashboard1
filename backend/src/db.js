const fs = require('node:fs');
const path = require('node:path');
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

async function withTenant(organizationId, work) {
  if (!organizationId) throw new Error('Tenant context is required');
  return transaction(async client => {
    await client.query("SELECT set_config('app.current_organization_id', $1, true)", [organizationId]);
    return work(client);
  });
}

async function migrate() {
  await query(`
    CREATE EXTENSION IF NOT EXISTS pgcrypto;
    CREATE TABLE IF NOT EXISTS organizations (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      name text NOT NULL,
      slug text NOT NULL UNIQUE,
      plan text NOT NULL DEFAULT 'trial',
      timezone text NOT NULL DEFAULT 'UTC',
      evidence_retention_days integer NOT NULL DEFAULT 2555 CHECK (evidence_retention_days BETWEEN 1 AND 36500),
      notification_preferences jsonb NOT NULL DEFAULT '{}'::jsonb,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    ALTER TABLE organizations ADD COLUMN IF NOT EXISTS timezone text NOT NULL DEFAULT 'UTC';
    ALTER TABLE organizations ADD COLUMN IF NOT EXISTS evidence_retention_days integer NOT NULL DEFAULT 2555;
    ALTER TABLE organizations ADD COLUMN IF NOT EXISTS notification_preferences jsonb NOT NULL DEFAULT '{}'::jsonb;
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
      previous_hash text,
      event_hash text,
      ip inet,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS cases_tenant_created_idx ON cases (organization_id, created_at DESC);
    CREATE INDEX IF NOT EXISTS audit_tenant_created_idx ON audit_events (organization_id, created_at DESC);
    ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS previous_hash text;
    ALTER TABLE audit_events ADD COLUMN IF NOT EXISTS event_hash text;
    CREATE TABLE IF NOT EXISTS webauthn_credentials (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      credential_id bytea NOT NULL UNIQUE,
      public_key bytea NOT NULL,
      counter bigint NOT NULL DEFAULT 0,
      transports text[] NOT NULL DEFAULT '{}',
      device_label text,
      created_at timestamptz NOT NULL DEFAULT now(),
      last_used_at timestamptz
    );
    CREATE TABLE IF NOT EXISTS abac_policies (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      name text NOT NULL,
      effect text NOT NULL CHECK (effect IN ('allow','deny')),
      action_pattern text NOT NULL,
      conditions jsonb NOT NULL DEFAULT '{}'::jsonb,
      enabled boolean NOT NULL DEFAULT true,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS evidence_objects (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      case_id uuid NOT NULL REFERENCES cases(id) ON DELETE CASCADE,
      object_key text NOT NULL,
      plaintext_sha256 text NOT NULL,
      ciphertext_sha256 text NOT NULL,
      cipher text NOT NULL DEFAULT 'AES-256-GCM',
      iv bytea NOT NULL,
      auth_tag bytea NOT NULL,
      encrypted_data_key bytea NOT NULL,
      kms_key_id text NOT NULL,
      size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
      created_by uuid NOT NULL REFERENCES users(id),
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (organization_id, object_key)
    );
    CREATE TABLE IF NOT EXISTS audit_anchors (
      id bigserial PRIMARY KEY,
      organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      last_event_id bigint NOT NULL,
      chain_hash text NOT NULL,
      external_provider text NOT NULL,
      external_reference text NOT NULL,
      anchored_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS corporate_records (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      organization_id uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
      module text NOT NULL CHECK (module IN ('ai-operations','operator-support','crm','websites','social-intelligence','call-reviews')),
      fields jsonb NOT NULL CHECK (jsonb_typeof(fields)='array' AND jsonb_array_length(fields)=3),
      created_by uuid NOT NULL REFERENCES users(id),
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS corporate_records_tenant_module_idx ON corporate_records (organization_id,module,updated_at DESC);
    CREATE OR REPLACE FUNCTION centinell_audit_hash() RETURNS trigger LANGUAGE plpgsql AS $$
    DECLARE prior text;
    BEGIN
      PERFORM pg_advisory_xact_lock(hashtext(NEW.organization_id::text));
      SELECT event_hash INTO prior FROM audit_events WHERE organization_id=NEW.organization_id ORDER BY id DESC LIMIT 1;
      NEW.previous_hash := coalesce(prior, repeat('0',64));
      NEW.event_hash := encode(digest(
        NEW.previous_hash || '|' || NEW.organization_id::text || '|' || coalesce(NEW.actor_id::text,'') || '|' ||
        NEW.action || '|' || NEW.entity_type || '|' || coalesce(NEW.entity_id,'') || '|' || NEW.metadata::text || '|' || NEW.created_at::text,
        'sha256'), 'hex');
      RETURN NEW;
    END $$;
    DROP TRIGGER IF EXISTS audit_events_hash_chain ON audit_events;
    CREATE TRIGGER audit_events_hash_chain BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION centinell_audit_hash();
    CREATE OR REPLACE FUNCTION centinell_verify_audit_chain(target_org uuid) RETURNS boolean LANGUAGE plpgsql AS $$
    DECLARE item record; prior text := repeat('0',64); expected text;
    BEGIN
      FOR item IN SELECT * FROM audit_events WHERE organization_id=target_org ORDER BY id LOOP
        IF item.previous_hash IS DISTINCT FROM prior THEN RETURN false; END IF;
        expected := encode(digest(
          prior || '|' || item.organization_id::text || '|' || coalesce(item.actor_id::text,'') || '|' ||
          item.action || '|' || item.entity_type || '|' || coalesce(item.entity_id,'') || '|' || item.metadata::text || '|' || item.created_at::text,
          'sha256'), 'hex');
        IF item.event_hash IS DISTINCT FROM expected THEN RETURN false; END IF;
        prior := item.event_hash;
      END LOOP;
      RETURN true;
    END $$;
    ALTER TABLE cases ENABLE ROW LEVEL SECURITY;
    ALTER TABLE cases FORCE ROW LEVEL SECURITY;
    ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
    ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
    ALTER TABLE evidence_objects ENABLE ROW LEVEL SECURITY;
    ALTER TABLE evidence_objects FORCE ROW LEVEL SECURITY;
    ALTER TABLE webauthn_credentials ENABLE ROW LEVEL SECURITY;
    ALTER TABLE webauthn_credentials FORCE ROW LEVEL SECURITY;
    ALTER TABLE abac_policies ENABLE ROW LEVEL SECURITY;
    ALTER TABLE abac_policies FORCE ROW LEVEL SECURITY;
    ALTER TABLE audit_anchors ENABLE ROW LEVEL SECURITY;
    ALTER TABLE audit_anchors FORCE ROW LEVEL SECURITY;
    ALTER TABLE corporate_records ENABLE ROW LEVEL SECURITY;
    ALTER TABLE corporate_records FORCE ROW LEVEL SECURITY;
    DROP POLICY IF EXISTS cases_tenant_isolation ON cases;
    CREATE POLICY cases_tenant_isolation ON cases USING (organization_id = nullif(current_setting('app.current_organization_id',true),'')::uuid) WITH CHECK (organization_id = nullif(current_setting('app.current_organization_id',true),'')::uuid);
    DROP POLICY IF EXISTS audit_tenant_isolation ON audit_events;
    CREATE POLICY audit_tenant_isolation ON audit_events USING (organization_id = nullif(current_setting('app.current_organization_id',true),'')::uuid) WITH CHECK (organization_id = nullif(current_setting('app.current_organization_id',true),'')::uuid);
    DROP POLICY IF EXISTS evidence_tenant_isolation ON evidence_objects;
    CREATE POLICY evidence_tenant_isolation ON evidence_objects USING (organization_id = nullif(current_setting('app.current_organization_id',true),'')::uuid) WITH CHECK (organization_id = nullif(current_setting('app.current_organization_id',true),'')::uuid);
    DROP POLICY IF EXISTS webauthn_tenant_isolation ON webauthn_credentials;
    CREATE POLICY webauthn_tenant_isolation ON webauthn_credentials USING (organization_id = nullif(current_setting('app.current_organization_id',true),'')::uuid) WITH CHECK (organization_id = nullif(current_setting('app.current_organization_id',true),'')::uuid);
    DROP POLICY IF EXISTS abac_tenant_isolation ON abac_policies;
    CREATE POLICY abac_tenant_isolation ON abac_policies USING (organization_id = nullif(current_setting('app.current_organization_id',true),'')::uuid) WITH CHECK (organization_id = nullif(current_setting('app.current_organization_id',true),'')::uuid);
    DROP POLICY IF EXISTS anchors_tenant_isolation ON audit_anchors;
    CREATE POLICY anchors_tenant_isolation ON audit_anchors USING (organization_id = nullif(current_setting('app.current_organization_id',true),'')::uuid) WITH CHECK (organization_id = nullif(current_setting('app.current_organization_id',true),'')::uuid);
    DROP POLICY IF EXISTS corporate_records_tenant_isolation ON corporate_records;
    CREATE POLICY corporate_records_tenant_isolation ON corporate_records USING (organization_id = nullif(current_setting('app.current_organization_id',true),'')::uuid) WITH CHECK (organization_id = nullif(current_setting('app.current_organization_id',true),'')::uuid);
  `);
  const forensicCopilotMigration = fs.readFileSync(path.join(__dirname, '..', 'migrations', '20260830_forensic_copilot.sql'), 'utf8');
  await query(forensicCopilotMigration);
}

module.exports = { getPool, query, transaction, withTenant, migrate };
