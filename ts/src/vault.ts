import pg from "pg";
import {
  decryptVaultValue,
  encryptVaultValue,
  loadKeyring,
  type EncryptionContext,
  type VaultKeyring,
  type VaultOwnerType,
  type VaultPiiType,
} from "./vaultCrypto.js";

/**
 * Who is acting, and for which tenant. The caller's own authorization layer
 * derives this from an authenticated session; the vault never accepts a
 * tenant id from the end user directly.
 */
export type VaultActor = {
  userId: string;
  role: string;
  tenantId: string;
};

export type StoreVaultRecordInput = {
  actor: VaultActor;
  vaultId: string;
  ownerType: VaultOwnerType;
  ownerId: string;
  type: VaultPiiType;
  plaintext: string;
  /** Defaults to the keyring's active version. */
  keyVersion?: number;
  expiresAt: number;
  reason: string;
  requestId: string;
  replacingExisting: boolean;
};

type VaultRecordRow = {
  vault_id: string;
  tenant_id: string;
  owner_type: VaultOwnerType;
  owner_id: string;
  field_type: VaultPiiType;
  ciphertext: string;
  iv: string;
  auth_tag: string;
  algorithm: "aes-256-gcm";
  key_version: number;
  display_hint: string;
  expires_at: Date;
};

type VaultEventRow = {
  event_id: string;
  vault_id: string | null;
  action: string;
  actor_id: string;
  actor_role: string;
  reason: string;
  succeeded: boolean;
  request_id: string;
  occurred_at: Date;
  metadata: Record<string, unknown>;
};

type RuntimeRoleRow = {
  role_name: string;
  is_superuser: boolean;
  bypasses_rls: boolean;
  owns_records: boolean;
  owns_access_events: boolean;
  owns_schema: boolean;
  records_rls_enabled: boolean;
  records_rls_forced: boolean;
  events_rls_enabled: boolean;
  events_rls_forced: boolean;
  has_schema_usage: boolean;
  has_record_permissions: boolean;
  has_event_permissions: boolean;
  event_log_is_append_only: boolean;
};

type IsolationLevel = "SERIALIZABLE" | "REPEATABLE READ";

export type PiiVaultOptions = {
  /** Connection string for the runtime login (never the schema owner). */
  databaseUrl: string;
  /** Defaults to loadKeyring(process.env). */
  keyring?: VaultKeyring;
  /**
   * Login names refused before connecting, case-insensitive. Put your
   * provider's owner role here (for example `neondb_owner` on Neon, or
   * `postgres`); the catalog check below catches the rest.
   */
  forbiddenLoginRoles?: string[];
  maxConnections?: number;
};

const runtimeRoleSQL = `
  SELECT
    current_user AS role_name,
    r.rolsuper AS is_superuser,
    r.rolbypassrls AS bypasses_rls,
    records.relowner = r.oid AS owns_records,
    events.relowner = r.oid AS owns_access_events,
    namespace.nspowner = r.oid AS owns_schema,
    records.relrowsecurity AS records_rls_enabled,
    records.relforcerowsecurity AS records_rls_forced,
    events.relrowsecurity AS events_rls_enabled,
    events.relforcerowsecurity AS events_rls_forced,
    has_schema_privilege(current_user, 'pii_vault', 'USAGE')
      AS has_schema_usage,
    has_table_privilege(current_user, 'pii_vault.records', 'SELECT')
      AND has_table_privilege(current_user, 'pii_vault.records', 'INSERT')
      AND has_table_privilege(current_user, 'pii_vault.records', 'UPDATE')
      AND has_table_privilege(current_user, 'pii_vault.records', 'DELETE')
      AS has_record_permissions,
    has_table_privilege(current_user, 'pii_vault.access_events', 'SELECT')
      AND has_table_privilege(current_user, 'pii_vault.access_events', 'INSERT')
      AS has_event_permissions,
    NOT (
      has_table_privilege(current_user, 'pii_vault.access_events', 'UPDATE')
      OR has_table_privilege(current_user, 'pii_vault.access_events', 'DELETE')
      OR has_table_privilege(current_user, 'pii_vault.access_events', 'TRUNCATE')
    ) AS event_log_is_append_only
  FROM pg_catalog.pg_roles r
  JOIN pg_catalog.pg_class records
    ON records.oid = 'pii_vault.records'::regclass
  JOIN pg_catalog.pg_class events
    ON events.oid = 'pii_vault.access_events'::regclass
  JOIN pg_catalog.pg_namespace namespace
    ON namespace.oid = records.relnamespace
  WHERE r.rolname = current_user
`;

const storeSQL = `
  WITH stored AS (
    INSERT INTO pii_vault.records (
      vault_id,
      tenant_id,
      owner_type,
      owner_id,
      field_type,
      ciphertext,
      iv,
      auth_tag,
      algorithm,
      key_version,
      display_hint,
      expires_at,
      created_by
    ) VALUES (
      $1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12::timestamptz, $13
    )
    ON CONFLICT (tenant_id, owner_type, owner_id, field_type)
      WHERE deleted_at IS NULL
    DO UPDATE SET
      ciphertext = EXCLUDED.ciphertext,
      iv = EXCLUDED.iv,
      auth_tag = EXCLUDED.auth_tag,
      algorithm = EXCLUDED.algorithm,
      key_version = EXCLUDED.key_version,
      display_hint = EXCLUDED.display_hint,
      expires_at = EXCLUDED.expires_at,
      updated_at = clock_timestamp()
    -- The ciphertext is bound to the vault id it was sealed under. Replacing
    -- an active record under a different id would keep the old id and store
    -- a ciphertext that can never open, so only same-id replacement applies.
    WHERE pii_vault.records.vault_id = EXCLUDED.vault_id
    RETURNING vault_id, display_hint, expires_at
  ), logged AS (
    INSERT INTO pii_vault.access_events (
      event_id,
      tenant_id,
      vault_id,
      action,
      actor_id,
      actor_role,
      reason,
      succeeded,
      request_id,
      metadata
    )
    SELECT
      gen_random_uuid(),
      $2,
      stored.vault_id,
      $14,
      $13,
      $15,
      $16,
      true,
      $17::uuid,
      $18::jsonb
    FROM stored
  )
  SELECT vault_id, display_hint, expires_at FROM stored
`;

// Selects the record and logs the read in one statement: if the access event
// cannot be written (bad reason, missing actor context, revoked grant), the
// whole statement fails and no ciphertext leaves the database.
const retrieveSQL = `
  WITH selected AS (
    SELECT
      vault_id,
      tenant_id,
      owner_type,
      owner_id,
      field_type,
      ciphertext,
      iv,
      auth_tag,
      algorithm,
      key_version,
      display_hint,
      expires_at
    FROM pii_vault.records
    WHERE vault_id = $1::uuid
      AND tenant_id = $2
      AND deleted_at IS NULL
      AND expires_at > clock_timestamp()
    FOR SHARE
  ), logged AS (
    INSERT INTO pii_vault.access_events (
      event_id,
      tenant_id,
      vault_id,
      action,
      actor_id,
      actor_role,
      reason,
      succeeded,
      request_id,
      metadata
    )
    SELECT
      gen_random_uuid(),
      $2,
      selected.vault_id,
      'read',
      $3,
      $4,
      $5,
      true,
      $6::uuid,
      jsonb_build_object('fieldType', selected.field_type)
    FROM selected
    RETURNING event_id
  )
  SELECT selected.* FROM selected, logged
`;

const deleteSQL = `
  WITH removed AS (
    DELETE FROM pii_vault.records
    WHERE vault_id = $1::uuid
      AND tenant_id = $2
    RETURNING vault_id, field_type
  ), logged AS (
    INSERT INTO pii_vault.access_events (
      event_id,
      tenant_id,
      vault_id,
      action,
      actor_id,
      actor_role,
      reason,
      succeeded,
      request_id,
      metadata
    )
    SELECT
      gen_random_uuid(),
      $2,
      removed.vault_id,
      'delete',
      $3,
      $4,
      $5,
      true,
      $6::uuid,
      jsonb_build_object('fieldType', removed.field_type)
    FROM removed
    RETURNING event_id
  )
  SELECT removed.vault_id FROM removed, logged
`;

const listEventsSQL = `
  WITH logged AS (
    INSERT INTO pii_vault.access_events (
      event_id,
      tenant_id,
      vault_id,
      action,
      actor_id,
      actor_role,
      reason,
      succeeded,
      request_id,
      metadata
    ) VALUES (
      gen_random_uuid(),
      $1,
      $2::uuid,
      'audit_read',
      $3,
      $4,
      $5,
      true,
      $6::uuid,
      '{}'::jsonb
    )
  )
  SELECT
    event_id,
    vault_id,
    action,
    actor_id,
    actor_role,
    reason,
    succeeded,
    request_id,
    occurred_at,
    metadata
  FROM pii_vault.access_events
  WHERE tenant_id = $1
    AND ($2::uuid IS NULL OR vault_id = $2::uuid)
  ORDER BY occurred_at DESC
  LIMIT $7
`;

export class PiiVault {
  private readonly pool: pg.Pool;
  private readonly keyring: VaultKeyring;
  private verifiedConnection: Promise<void> | undefined;

  constructor(options: PiiVaultOptions) {
    const { databaseUrl } = options;
    if (!databaseUrl) {
      throw new Error("PII_VAULT_DATABASE_URL is not configured");
    }

    let parsed: URL;
    try {
      parsed = new URL(databaseUrl);
    } catch {
      throw new Error("PII_VAULT_DATABASE_URL is invalid");
    }

    const loginName = decodeURIComponent(parsed.username).toLowerCase();
    const forbidden = (options.forbiddenLoginRoles ?? []).map((name) => name.toLowerCase());
    if (forbidden.includes(loginName)) {
      throw new Error("The database owner role must not be used by the PII vault runtime");
    }

    this.keyring = options.keyring ?? loadKeyring();
    this.pool = new pg.Pool({
      connectionString: databaseUrl,
      max: options.maxConnections ?? 4,
    });
  }

  async close(): Promise<void> {
    await this.pool.end();
  }

  /**
   * Refuses to run as a role that could see across tenants or rewrite the
   * access log: superusers, BYPASSRLS roles, table or schema owners, or any
   * role with UPDATE/DELETE/TRUNCATE on access_events. Checked once per
   * PiiVault and retried after a failure.
   */
  private async assertSafeRuntimeRole(): Promise<void> {
    if (!this.verifiedConnection) {
      this.verifiedConnection = (async () => {
        const { rows } = await this.pool.query<RuntimeRoleRow>(runtimeRoleSQL);
        const role = rows[0];
        if (
          !role ||
          role.is_superuser ||
          role.bypasses_rls ||
          role.owns_records ||
          role.owns_access_events ||
          role.owns_schema ||
          !role.records_rls_enabled ||
          !role.records_rls_forced ||
          !role.events_rls_enabled ||
          !role.events_rls_forced ||
          !role.has_schema_usage ||
          !role.has_record_permissions ||
          !role.has_event_permissions ||
          !role.event_log_is_append_only
        ) {
          throw new Error("The PII vault runtime role is not RLS-safe");
        }
      })().catch((error) => {
        this.verifiedConnection = undefined;
        throw error;
      });
    }
    await this.verifiedConnection;
  }

  async verifyVaultConnection(): Promise<void> {
    await this.assertSafeRuntimeRole();
  }

  /**
   * Runs one statement inside a transaction whose tenant and actor are bound
   * with transaction-local set_config, so RLS policies see them and they
   * cannot leak to the next borrower of the pooled connection.
   */
  private async inTenantTransaction<Row extends pg.QueryResultRow>(
    actor: VaultActor,
    isolationLevel: IsolationLevel,
    statement: string,
    params: unknown[],
  ): Promise<Row[]> {
    await this.assertSafeRuntimeRole();
    const client = await this.pool.connect();
    try {
      await client.query(`BEGIN ISOLATION LEVEL ${isolationLevel}`);
      await client.query(
        `SELECT
          set_config('app.tenant_id', $1, true),
          set_config('app.actor_id', $2, true)`,
        [actor.tenantId, actor.userId],
      );
      const { rows } = await client.query<Row>(statement, params);
      await client.query("COMMIT");
      return rows;
    } catch (error) {
      await client.query("ROLLBACK").catch(() => undefined);
      throw error;
    } finally {
      client.release();
    }
  }

  async storeVaultRecord(input: StoreVaultRecordInput) {
    const keyVersion = input.keyVersion ?? this.keyring.activeVersion;
    const context: EncryptionContext = {
      tenantId: input.actor.tenantId,
      vaultId: input.vaultId,
      ownerType: input.ownerType,
      ownerId: input.ownerId,
      type: input.type,
      keyVersion,
    };
    const encrypted = encryptVaultValue(input.plaintext, context, this.keyring);
    const action = input.replacingExisting ? "update" : "create";
    const metadata = JSON.stringify({
      ownerType: input.ownerType,
      fieldType: input.type,
      keyVersion,
    });

    const records = await this.inTenantTransaction<{
      vault_id: string;
      display_hint: string;
      expires_at: Date;
    }>(input.actor, "SERIALIZABLE", storeSQL, [
      input.vaultId,
      input.actor.tenantId,
      input.ownerType,
      input.ownerId,
      input.type,
      encrypted.ciphertext,
      encrypted.iv,
      encrypted.authTag,
      encrypted.algorithm,
      encrypted.keyVersion,
      encrypted.displayHint,
      new Date(input.expiresAt).toISOString(),
      input.actor.userId,
      action,
      input.actor.role,
      input.reason,
      input.requestId,
      metadata,
    ]);

    const stored = records[0];
    if (!stored) {
      // The guarded ON CONFLICT matched an active record with another id.
      throw new Error(
        "An active record for this owner and field already exists under a different vault id; " +
          "replace it by passing that vault id",
      );
    }
    return {
      vaultId: stored.vault_id,
      masked: stored.display_hint,
      expiresAt: new Date(stored.expires_at).getTime(),
    };
  }

  async retrieveVaultRecord(input: {
    actor: VaultActor;
    vaultId: string;
    reason: string;
    requestId: string;
  }) {
    const records = await this.inTenantTransaction<VaultRecordRow>(
      input.actor,
      "REPEATABLE READ",
      retrieveSQL,
      [
        input.vaultId,
        input.actor.tenantId,
        input.actor.userId,
        input.actor.role,
        input.reason,
        input.requestId,
      ],
    );

    const row = records[0];
    if (!row) {
      throw new Error("PII record not found");
    }

    const plaintext = decryptVaultValue(
      {
        ciphertext: row.ciphertext,
        iv: row.iv,
        authTag: row.auth_tag,
        algorithm: row.algorithm,
        keyVersion: row.key_version,
      },
      {
        tenantId: row.tenant_id,
        vaultId: row.vault_id,
        ownerType: row.owner_type,
        ownerId: row.owner_id,
        type: row.field_type,
        keyVersion: row.key_version,
      },
      this.keyring,
    );

    return {
      vaultId: row.vault_id,
      type: row.field_type,
      ownerType: row.owner_type,
      ownerId: row.owner_id,
      plaintext,
      masked: row.display_hint,
      expiresAt: new Date(row.expires_at).getTime(),
    };
  }

  async deleteVaultRecord(input: {
    actor: VaultActor;
    vaultId: string;
    reason: string;
    requestId: string;
  }) {
    const deleted = await this.inTenantTransaction<{ vault_id: string }>(
      input.actor,
      "SERIALIZABLE",
      deleteSQL,
      [
        input.vaultId,
        input.actor.tenantId,
        input.actor.userId,
        input.actor.role,
        input.reason,
        input.requestId,
      ],
    );

    if (!deleted[0]) {
      throw new Error("PII record not found");
    }
  }

  async listVaultEvents(input: {
    actor: VaultActor;
    vaultId?: string;
    reason: string;
    requestId: string;
    limit: number;
  }) {
    const filterVaultId = input.vaultId ?? null;
    const events = await this.inTenantTransaction<VaultEventRow>(
      input.actor,
      "REPEATABLE READ",
      listEventsSQL,
      [
        input.actor.tenantId,
        filterVaultId,
        input.actor.userId,
        input.actor.role,
        input.reason,
        input.requestId,
        input.limit,
      ],
    );

    return events.map((event) => ({
      eventId: event.event_id,
      vaultId: event.vault_id,
      action: event.action,
      actorId: event.actor_id,
      actorRole: event.actor_role,
      reason: event.reason,
      succeeded: event.succeeded,
      requestId: event.request_id,
      occurredAt: new Date(event.occurred_at).getTime(),
      metadata: event.metadata,
    }));
  }
}
