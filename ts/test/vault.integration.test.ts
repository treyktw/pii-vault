// Postgres integration tests. Need the docker compose database:
//
//   make db-up && make test-integration
//
// Skipped unless PII_VAULT_DATABASE_URL and PII_VAULT_OWNER_DATABASE_URL are
// set. Every test uses fresh random tenant ids, so the suite can run
// repeatedly against the same database.
import { execFileSync, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { PiiVault, type VaultActor } from "../src/vault.js";
import { loadKeyring, type VaultKeyring } from "../src/vaultCrypto.js";

const runtimeUrl = process.env.PII_VAULT_DATABASE_URL;
const ownerUrl = process.env.PII_VAULT_OWNER_DATABASE_URL;
const enabled = Boolean(runtimeUrl && ownerUrl);

// Test keys only.
const keyV1 = Buffer.alloc(32, 0x01).toString("base64");
const keyV2 = Buffer.alloc(32, 0x02).toString("base64");
const keyringV1Only = (): VaultKeyring =>
  loadKeyring({ PII_VAULT_KEYRING: JSON.stringify({ "1": keyV1 }), PII_VAULT_ACTIVE_KEY_VERSION: "1" });
const keyringV1V2 = (): VaultKeyring =>
  loadKeyring({
    PII_VAULT_KEYRING: JSON.stringify({ "1": keyV1, "2": keyV2 }),
    PII_VAULT_ACTIVE_KEY_VERSION: "2",
  });
const keyringV2Only = (): VaultKeyring =>
  loadKeyring({ PII_VAULT_KEYRING: JSON.stringify({ "2": keyV2 }), PII_VAULT_ACTIVE_KEY_VERSION: "2" });

const READ_REASON = "Integration test: verifying an audited read";
const goModuleDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "go");
const goAvailable = spawnSync("go", ["version"]).status === 0;
const oneDayFromNow = () => Date.now() + 24 * 60 * 60 * 1000;

function withLogin(url: string, user: string, password: string): string {
  const parsed = new URL(url);
  parsed.username = user;
  parsed.password = password;
  return parsed.toString();
}

function newActor(tenantId = `tenant_${randomUUID()}`): VaultActor {
  return { tenantId, userId: `user_${randomUUID().slice(0, 8)}`, role: "manager" };
}

describe.skipIf(!enabled)("PiiVault against Postgres", () => {
  let vault: PiiVault;
  let owner: pg.Pool;
  let runtime: pg.Pool;

  beforeAll(async () => {
    vault = new PiiVault({ databaseUrl: runtimeUrl!, keyring: keyringV1V2() });
    owner = new pg.Pool({ connectionString: ownerUrl! });
    runtime = new pg.Pool({ connectionString: runtimeUrl! });
    await vault.verifyVaultConnection();
  });

  afterAll(async () => {
    await vault?.close();
    await owner?.end();
    await runtime?.end();
  });

  async function store(actor: VaultActor, plaintext = "123-45-6789", target = vault) {
    const vaultId = randomUUID();
    const stored = await target.storeVaultRecord({
      actor,
      vaultId,
      ownerType: "client",
      ownerId: "client_0001",
      type: "ssn",
      plaintext,
      expiresAt: oneDayFromNow(),
      reason: "Integration test: storing a synthetic SSN",
      requestId: randomUUID(),
      replacingExisting: false,
    });
    return { vaultId, ...stored };
  }

  async function eventsFor(tenantId: string) {
    const { rows } = await owner.query<{ action: string; vault_id: string; actor_id: string; reason: string }>(
      `SELECT action, vault_id::text, actor_id, reason
         FROM pii_vault.access_events
        WHERE tenant_id = $1
        ORDER BY occurred_at`,
      [tenantId],
    );
    return rows;
  }

  /** Runs statements as the runtime login with a tenant bound, then rolls back. */
  async function asRuntime<T>(tenantId: string | null, actorId: string | null, work: (client: pg.PoolClient) => Promise<T>) {
    const client = await runtime.connect();
    try {
      await client.query("BEGIN");
      if (tenantId !== null) {
        await client.query("SELECT set_config('app.tenant_id', $1, true)", [tenantId]);
      }
      if (actorId !== null) {
        await client.query("SELECT set_config('app.actor_id', $1, true)", [actorId]);
      }
      return await work(client);
    } finally {
      await client.query("ROLLBACK").catch(() => undefined);
      client.release();
    }
  }

  describe("storage", () => {
    it("stores ciphertext and a masked hint, never plaintext", async () => {
      const actor = newActor();
      const { vaultId, masked } = await store(actor, "123-45-6789");
      expect(masked).toBe("***-**-6789");

      const { rows } = await owner.query(`SELECT * FROM pii_vault.records WHERE vault_id = $1`, [vaultId]);
      expect(rows).toHaveLength(1);
      const serializedRow = JSON.stringify(rows[0]);
      expect(serializedRow).not.toContain("123-45-6789");
      expect(serializedRow).not.toContain("123456789");
      expect(rows[0].algorithm).toBe("aes-256-gcm");
      expect(rows[0].key_version).toBe(2);

      expect((await eventsFor(actor.tenantId)).map((event) => event.action)).toEqual(["create"]);
    });
  });

  describe("reads log access atomically", () => {
    it("writes exactly one read event per successful read, in the same statement", async () => {
      const actor = newActor();
      const { vaultId } = await store(actor);

      const first = await vault.retrieveVaultRecord({ actor, vaultId, reason: READ_REASON, requestId: randomUUID() });
      expect(first.plaintext).toBe("123-45-6789");
      await vault.retrieveVaultRecord({ actor, vaultId, reason: READ_REASON, requestId: randomUUID() });

      const events = await eventsFor(actor.tenantId);
      expect(events.map((event) => event.action)).toEqual(["create", "read", "read"]);
      expect(events[1]).toMatchObject({ vault_id: vaultId, actor_id: actor.userId, reason: READ_REASON });
    });

    it("returns nothing when the access event cannot be written", async () => {
      const actor = newActor();
      const { vaultId } = await store(actor);

      // The access log requires a 10-500 character reason. A read with a
      // short reason fails as a whole: no ciphertext, no event.
      await expect(
        vault.retrieveVaultRecord({ actor, vaultId, reason: "because", requestId: randomUUID() }),
      ).rejects.toThrow(/access_events_reason_check|violates check constraint/);

      expect((await eventsFor(actor.tenantId)).map((event) => event.action)).toEqual(["create"]);
    });

    it("refuses an access event for an actor other than the bound one", async () => {
      const actor = newActor();
      const { vaultId } = await store(actor);
      // Simulates a caller that binds one actor and tries to log as another.
      await asRuntime(actor.tenantId, actor.userId, async (client) => {
        await expect(
          client.query(
            `INSERT INTO pii_vault.access_events
               (event_id, tenant_id, vault_id, action, actor_id, actor_role, reason, succeeded, request_id)
             VALUES (gen_random_uuid(), $1, $2, 'read', 'someone_else', 'manager', $3, true, gen_random_uuid())`,
            [actor.tenantId, vaultId, READ_REASON],
          ),
        ).rejects.toThrow(/row-level security/);
      });
    });

    it("audit reads are themselves audited", async () => {
      const actor = newActor();
      const { vaultId } = await store(actor);
      const events = await vault.listVaultEvents({
        actor,
        vaultId,
        reason: "Integration test: reviewing access history",
        requestId: randomUUID(),
        limit: 10,
      });
      expect(events.map((event) => event.action)).toContain("create");
      expect((await eventsFor(actor.tenantId)).map((event) => event.action)).toEqual(["create", "audit_read"]);
    });
  });

  describe("row-level security blocks cross-tenant access", () => {
    it("a tenant B actor cannot read a tenant A record through the API", async () => {
      const tenantA = newActor();
      const tenantB = newActor();
      const { vaultId } = await store(tenantA);

      await expect(
        vault.retrieveVaultRecord({ actor: tenantB, vaultId, reason: READ_REASON, requestId: randomUUID() }),
      ).rejects.toThrow("PII record not found");
      // Nothing was logged against either tenant for the blocked read.
      expect(await eventsFor(tenantB.tenantId)).toEqual([]);
      expect((await eventsFor(tenantA.tenantId)).map((event) => event.action)).toEqual(["create"]);
    });

    it("RLS, not the WHERE clause, is what hides the rows", async () => {
      const tenantA = newActor();
      const { vaultId } = await store(tenantA);
      const countVisible = (client: pg.PoolClient) =>
        client
          .query<{ visible: string }>(`SELECT count(*) AS visible FROM pii_vault.records WHERE vault_id = $1`, [vaultId])
          .then((result) => Number(result.rows[0]!.visible));

      expect(await asRuntime(tenantA.tenantId, null, countVisible)).toBe(1);
      expect(await asRuntime(`tenant_${randomUUID()}`, null, countVisible)).toBe(0);
      // No tenant bound at all: fails closed to zero rows.
      expect(await asRuntime(null, null, countVisible)).toBe(0);
      expect(await asRuntime("", null, countVisible)).toBe(0);
    });

    it("cannot update, delete or plant rows in another tenant", async () => {
      const tenantA = newActor();
      const tenantB = newActor();
      const { vaultId } = await store(tenantA);

      await asRuntime(tenantB.tenantId, tenantB.userId, async (client) => {
        const updated = await client.query(`UPDATE pii_vault.records SET display_hint = 'pwned' WHERE vault_id = $1`, [vaultId]);
        expect(updated.rowCount).toBe(0);
        const deleted = await client.query(`DELETE FROM pii_vault.records WHERE vault_id = $1`, [vaultId]);
        expect(deleted.rowCount).toBe(0);
        await expect(
          client.query(
            `INSERT INTO pii_vault.records
               (vault_id, tenant_id, owner_type, owner_id, field_type, ciphertext, iv, auth_tag,
                algorithm, key_version, display_hint, expires_at, created_by)
             VALUES (gen_random_uuid(), $1, 'client', 'c', 'ssn', 'x', 'x', 'x',
                     'aes-256-gcm', 1, '***', now() + interval '1 day', $2)`,
            [tenantA.tenantId, tenantB.userId],
          ),
        ).rejects.toThrow(/row-level security/);
      });

      const { rows } = await owner.query(`SELECT display_hint FROM pii_vault.records WHERE vault_id = $1`, [vaultId]);
      expect(rows[0].display_hint).toBe("***-**-6789");
    });

    it("cannot read another tenant's access log", async () => {
      const tenantA = newActor();
      await store(tenantA);
      const visible = await asRuntime(`tenant_${randomUUID()}`, null, (client) =>
        client.query(`SELECT count(*)::int AS n FROM pii_vault.access_events WHERE tenant_id = $1`, [tenantA.tenantId]),
      );
      expect(visible.rows[0].n).toBe(0);
    });
  });

  describe("the access log is append-only", () => {
    it.each([
      ["UPDATE", `UPDATE pii_vault.access_events SET reason = 'rewritten history here'`],
      ["DELETE", `DELETE FROM pii_vault.access_events`],
      ["TRUNCATE", `TRUNCATE pii_vault.access_events`],
    ])("rejects %s from the runtime role", async (_verb, statement) => {
      const actor = newActor();
      await store(actor);
      await asRuntime(actor.tenantId, actor.userId, async (client) => {
        await expect(client.query(statement)).rejects.toMatchObject({ code: "42501" });
      });
      expect(await eventsFor(actor.tenantId)).toHaveLength(1);
    });
  });

  describe("replacing a record", () => {
    it("replaces in place under the same vault id and stays readable", async () => {
      const actor = newActor();
      const { vaultId } = await store(actor, "111-22-3333");
      await vault.storeVaultRecord({
        actor,
        vaultId,
        ownerType: "client",
        ownerId: "client_0001",
        type: "ssn",
        plaintext: "444-55-6666",
        expiresAt: oneDayFromNow(),
        reason: "Integration test: correcting a synthetic SSN",
        requestId: randomUUID(),
        replacingExisting: true,
      });
      const read = await vault.retrieveVaultRecord({ actor, vaultId, reason: READ_REASON, requestId: randomUUID() });
      expect(read.plaintext).toBe("444-55-6666");
      expect((await eventsFor(actor.tenantId)).map((event) => event.action)).toEqual(["create", "update", "read"]);
    });

    it("refuses to overwrite an active record under a different vault id", async () => {
      const actor = newActor();
      const { vaultId } = await store(actor, "111-22-3333");
      await expect(store(actor, "444-55-6666")).rejects.toThrow("different vault id");
      // The original is untouched and still opens; nothing extra was logged.
      const read = await vault.retrieveVaultRecord({ actor, vaultId, reason: READ_REASON, requestId: randomUUID() });
      expect(read.plaintext).toBe("111-22-3333");
      expect((await eventsFor(actor.tenantId)).map((event) => event.action)).toEqual(["create", "read"]);
    });
  });

  describe("key rotation", () => {
    it("reads v1 and v2 records side by side, and only v1 breaks when v1 is retired", async () => {
      const actor = newActor();
      const beforeRotation = new PiiVault({ databaseUrl: runtimeUrl!, keyring: keyringV1Only() });
      const afterRotation = new PiiVault({ databaseUrl: runtimeUrl!, keyring: keyringV1V2() });
      const retiredV1 = new PiiVault({ databaseUrl: runtimeUrl!, keyring: keyringV2Only() });
      const storeFor = (target: PiiVault, ownerId: string, plaintext: string) =>
        target.storeVaultRecord({
          actor,
          vaultId: randomUUID(),
          ownerType: "client",
          ownerId,
          type: "ssn",
          plaintext,
          expiresAt: oneDayFromNow(),
          reason: "Integration test: storing across a key rotation",
          requestId: randomUUID(),
          replacingExisting: false,
        });
      const read = (target: PiiVault, vaultId: string) =>
        target.retrieveVaultRecord({ actor, vaultId, reason: READ_REASON, requestId: randomUUID() });

      try {
        const oldRecord = await storeFor(beforeRotation, "client_old", "111-22-3333");
        const newRecord = await storeFor(afterRotation, "client_new", "444-55-6666");

        expect((await read(afterRotation, oldRecord.vaultId)).plaintext).toBe("111-22-3333");
        expect((await read(afterRotation, newRecord.vaultId)).plaintext).toBe("444-55-6666");

        expect((await read(retiredV1, newRecord.vaultId)).plaintext).toBe("444-55-6666");
        await expect(read(retiredV1, oldRecord.vaultId)).rejects.toThrow("PII vault key version 1 is unavailable");
      } finally {
        await beforeRotation.close();
        await afterRotation.close();
        await retiredV1.close();
      }
    });
  });

  describe.skipIf(!goAvailable)("Node writes, Go reads (through Postgres)", () => {
    it("the Go reader opens and audits records the Node library stored", async () => {
      const actor = newActor();
      const ownerId = "client_interop";
      for (const [type, plaintext] of [
        ["ssn", "123-45-6789"],
        ["date_of_birth", "1990-01-31"],
      ] as const) {
        await vault.storeVaultRecord({
          actor,
          vaultId: randomUUID(),
          ownerType: "client",
          ownerId,
          type,
          plaintext,
          expiresAt: oneDayFromNow(),
          reason: "Integration test: storing for the Go reader",
          requestId: randomUUID(),
          replacingExisting: false,
        });
      }

      const output = execFileSync(
        "go",
        ["run", "./cmd/vault-read", "-tenant", actor.tenantId, "-owner", ownerId, "-types", "ssn,date_of_birth", "-actor", "go_reader"],
        {
          cwd: goModuleDir,
          env: {
            ...process.env,
            PII_VAULT_DATABASE_URL: runtimeUrl!,
            PII_VAULT_KEYRING: JSON.stringify({ "1": keyV1, "2": keyV2 }),
          },
          encoding: "utf8",
        },
      );
      expect(JSON.parse(output)).toEqual({ ssn: "123-45-6789", date_of_birth: "1990-01-31" });

      const goReads = (await eventsFor(actor.tenantId)).filter((event) => event.actor_id === "go_reader");
      expect(goReads.map((event) => event.action)).toEqual(["read", "read"]);
    }, 120_000);
  });

  describe("runtime role checks", () => {
    it("refuses a BYPASSRLS login even when it has every grant", async () => {
      const bypass = new PiiVault({
        databaseUrl: withLogin(runtimeUrl!, "pii_vault_bypass", "bypass-local-only"),
        keyring: keyringV1V2(),
      });
      try {
        await expect(bypass.verifyVaultConnection()).rejects.toThrow("not RLS-safe");
        await expect(
          bypass.retrieveVaultRecord({ actor: newActor(), vaultId: randomUUID(), reason: READ_REASON, requestId: randomUUID() }),
        ).rejects.toThrow("not RLS-safe");
      } finally {
        await bypass.close();
      }
    });

    it("refuses the schema owner / superuser", async () => {
      const superuser = new PiiVault({ databaseUrl: ownerUrl!, keyring: keyringV1V2() });
      try {
        await expect(superuser.verifyVaultConnection()).rejects.toThrow("not RLS-safe");
      } finally {
        await superuser.close();
      }
    });

    it("refuses a forbidden login name before connecting", () => {
      expect(
        () => new PiiVault({ databaseUrl: ownerUrl!, keyring: keyringV1V2(), forbiddenLoginRoles: ["postgres"] }),
      ).toThrow("must not be used");
    });
  });
});
