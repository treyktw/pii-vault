BEGIN;

CREATE SCHEMA IF NOT EXISTS pii_vault;

DO $role$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'pii_vault_app') THEN
    CREATE ROLE pii_vault_app NOLOGIN NOINHERIT NOBYPASSRLS;
  END IF;
END
$role$;

CREATE TABLE IF NOT EXISTS pii_vault.records (
  vault_id uuid PRIMARY KEY,
  tenant_id text NOT NULL CHECK (length(tenant_id) > 0),
  owner_type text NOT NULL CHECK (
    owner_type IN ('user', 'client', 'deal', 'organization')
  ),
  owner_id text NOT NULL CHECK (length(owner_id) > 0),
  field_type text NOT NULL CHECK (
    field_type IN (
      'ssn',
      'drivers_license',
      'date_of_birth',
      'credit_score',
      'monthly_income',
      'housing_payment',
      'preapproval_max',
      'trade_payoff',
      'co_buyer_name',
      'co_buyer_score',
      'bank_account',
      'tax_id',
      'passport',
      'custom'
    )
  ),
  ciphertext text NOT NULL,
  iv text NOT NULL,
  auth_tag text NOT NULL,
  algorithm text NOT NULL CHECK (algorithm = 'aes-256-gcm'),
  key_version integer NOT NULL CHECK (key_version > 0),
  display_hint text NOT NULL,
  expires_at timestamptz NOT NULL,
  created_by text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  deleted_at timestamptz,
  CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX IF NOT EXISTS pii_vault_one_active_field_per_owner
  ON pii_vault.records (tenant_id, owner_type, owner_id, field_type)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS pii_vault_records_tenant_owner
  ON pii_vault.records (tenant_id, owner_type, owner_id)
  WHERE deleted_at IS NULL;

CREATE INDEX IF NOT EXISTS pii_vault_records_expiration
  ON pii_vault.records (tenant_id, expires_at)
  WHERE deleted_at IS NULL;

CREATE TABLE IF NOT EXISTS pii_vault.access_events (
  event_id uuid PRIMARY KEY,
  tenant_id text NOT NULL CHECK (length(tenant_id) > 0),
  vault_id uuid,
  action text NOT NULL CHECK (
    action IN ('create', 'update', 'read', 'delete', 'audit_read', 'migrate')
  ),
  actor_id text NOT NULL CHECK (length(actor_id) > 0),
  actor_role text NOT NULL CHECK (length(actor_role) > 0),
  reason text NOT NULL CHECK (length(reason) BETWEEN 10 AND 500),
  succeeded boolean NOT NULL,
  request_id uuid NOT NULL,
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  CHECK (jsonb_typeof(metadata) = 'object')
);

CREATE INDEX IF NOT EXISTS pii_vault_access_events_tenant_time
  ON pii_vault.access_events (tenant_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS pii_vault_access_events_vault_time
  ON pii_vault.access_events (tenant_id, vault_id, occurred_at DESC);

ALTER TABLE pii_vault.records ENABLE ROW LEVEL SECURITY;
ALTER TABLE pii_vault.records FORCE ROW LEVEL SECURITY;
ALTER TABLE pii_vault.access_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE pii_vault.access_events FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS pii_vault_records_tenant_policy ON pii_vault.records;
CREATE POLICY pii_vault_records_tenant_policy
  ON pii_vault.records
  FOR ALL
  TO pii_vault_app
  USING (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')
  )
  WITH CHECK (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')
  );

DROP POLICY IF EXISTS pii_vault_access_events_select_policy
  ON pii_vault.access_events;
CREATE POLICY pii_vault_access_events_select_policy
  ON pii_vault.access_events
  FOR SELECT
  TO pii_vault_app
  USING (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')
  );

DROP POLICY IF EXISTS pii_vault_access_events_insert_policy
  ON pii_vault.access_events;
CREATE POLICY pii_vault_access_events_insert_policy
  ON pii_vault.access_events
  FOR INSERT
  TO pii_vault_app
  WITH CHECK (
    tenant_id = NULLIF(current_setting('app.tenant_id', true), '')
    AND actor_id = NULLIF(current_setting('app.actor_id', true), '')
  );

REVOKE ALL ON SCHEMA pii_vault FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA pii_vault FROM PUBLIC;
GRANT USAGE ON SCHEMA pii_vault TO pii_vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON pii_vault.records TO pii_vault_app;
GRANT SELECT, INSERT ON pii_vault.access_events TO pii_vault_app;
REVOKE UPDATE, DELETE, TRUNCATE ON pii_vault.access_events FROM pii_vault_app;

COMMIT;

-- Create a separate LOGIN role with an owner session, then grant it
-- membership in pii_vault_app. Do not use the schema owner (or any superuser
-- or BYPASSRLS role) at runtime; both runtimes refuse to start if you do:
--
--   CREATE ROLE pii_vault_runtime LOGIN PASSWORD '<generated-secret>'
--     INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
--   GRANT pii_vault_app TO pii_vault_runtime WITH INHERIT TRUE, SET FALSE;
--
-- Set PII_VAULT_DATABASE_URL to the pii_vault_runtime connection string only.
-- docker/initdb/010_local_logins.sql does exactly this for local development.
