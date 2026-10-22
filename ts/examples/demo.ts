// `make demo`: stores synthetic PII for two tenants, reads one value, then
// shows what is actually in the database and what RLS does with a
// cross-tenant read. All data here is fake.
import { execFileSync, spawnSync } from "node:child_process";
import { randomUUID } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import pg from "pg";
import { PiiVault, type VaultActor } from "../src/vault.js";
import { loadKeyring } from "../src/vaultCrypto.js";

const runtimeUrl = process.env.PII_VAULT_DATABASE_URL;
const ownerUrl = process.env.PII_VAULT_OWNER_DATABASE_URL;
if (!runtimeUrl || !ownerUrl || !process.env.PII_VAULT_KEYRING) {
  console.error("Set PII_VAULT_DATABASE_URL, PII_VAULT_OWNER_DATABASE_URL and PII_VAULT_KEYRING (see .env.example).");
  process.exit(1);
}

const heading = (text: string) => console.log(`\n\x1b[1m== ${text}\x1b[0m`);
const runSuffix = randomUUID().slice(0, 8);
const acme: VaultActor = { tenantId: `tenant_acme_${runSuffix}`, userId: "user_alice", role: "manager" };
const globex: VaultActor = { tenantId: `tenant_globex_${runSuffix}`, userId: "user_bob", role: "manager" };
const oneYear = Date.now() + 365 * 24 * 60 * 60 * 1000;

const vault = new PiiVault({ databaseUrl: runtimeUrl, keyring: loadKeyring(), forbiddenLoginRoles: ["postgres"] });
const owner = new pg.Pool({ connectionString: ownerUrl });

try {
  heading("Runtime role check");
  await vault.verifyVaultConnection();
  console.log(`connected as ${new URL(runtimeUrl).username}: not superuser, no BYPASSRLS, owns nothing, cannot rewrite the access log`);

  heading("Store synthetic PII for two tenants");
  const seeded: Array<{ actor: VaultActor; ownerId: string; type: "ssn" | "date_of_birth" | "monthly_income"; value: string }> = [
    { actor: acme, ownerId: "client_0001", type: "ssn", value: "123-45-6789" },
    { actor: acme, ownerId: "client_0001", type: "date_of_birth", value: "1990-01-31" },
    { actor: acme, ownerId: "client_0001", type: "monthly_income", value: "8250.00" },
    { actor: globex, ownerId: "client_0001", type: "ssn", value: "987-65-4320" },
  ];
  const vaultIds = new Map<string, string>();
  for (const item of seeded) {
    const vaultId = randomUUID();
    const stored = await vault.storeVaultRecord({
      actor: item.actor,
      vaultId,
      ownerType: "client",
      ownerId: item.ownerId,
      type: item.type,
      plaintext: item.value,
      expiresAt: oneYear,
      reason: "Demo: onboarding a synthetic customer",
      requestId: randomUUID(),
      replacingExisting: false,
    });
    vaultIds.set(`${item.actor.tenantId}/${item.type}`, vaultId);
    console.log(`${item.actor.tenantId.padEnd(28)} ${item.type.padEnd(15)} -> ${stored.masked.padEnd(12)} vault_id=${vaultId}`);
  }

  const acmeSsnId = vaultIds.get(`${acme.tenantId}/ssn`)!;

  heading("Read one value (tenant acme, audited)");
  const read = await vault.retrieveVaultRecord({
    actor: acme,
    vaultId: acmeSsnId,
    reason: "Demo: verifying identity for a credit application",
    requestId: randomUUID(),
  });
  console.log(`plaintext returned to the caller: ${read.plaintext}  (masked: ${read.masked})`);

  heading("What the database actually holds (pii_vault.records)");
  const record = await owner.query(
    `SELECT vault_id, tenant_id, owner_type, owner_id, field_type, ciphertext, iv, auth_tag, key_version, display_hint
       FROM pii_vault.records WHERE vault_id = $1`,
    [acmeSsnId],
  );
  console.table(record.rows);

  heading("The access log row written in the same statement as the read");
  const events = await owner.query(
    `SELECT action, actor_id, actor_role, reason, metadata::text AS metadata, occurred_at
       FROM pii_vault.access_events WHERE vault_id = $1 ORDER BY occurred_at`,
    [acmeSsnId],
  );
  console.table(events.rows);

  heading("Cross-tenant read: globex asks for acme's vault id");
  try {
    await vault.retrieveVaultRecord({
      actor: globex,
      vaultId: acmeSsnId,
      reason: "Demo: attempting a cross-tenant read",
      requestId: randomUUID(),
    });
    console.log("UNEXPECTED: cross-tenant read succeeded");
    process.exitCode = 1;
  } catch (error) {
    console.log(`blocked: ${(error as Error).message}`);
  }
  const runtime = new pg.Pool({ connectionString: runtimeUrl });
  const client = await runtime.connect();
  try {
    await client.query("BEGIN");
    await client.query("SELECT set_config('app.tenant_id', $1, true)", [globex.tenantId]);
    const raw = await client.query(`SELECT count(*)::int AS visible FROM pii_vault.records WHERE vault_id = $1`, [acmeSsnId]);
    console.log(`raw SELECT as the runtime role with tenant=globex, no tenant filter in SQL: ${raw.rows[0].visible} rows visible`);
    try {
      await client.query("SAVEPOINT s");
      await client.query("DELETE FROM pii_vault.access_events");
    } catch (error) {
      await client.query("ROLLBACK TO SAVEPOINT s");
      console.log(`DELETE FROM pii_vault.access_events: ${(error as Error).message}`);
    }
  } finally {
    await client.query("ROLLBACK");
    client.release();
    await runtime.end();
  }
  const globexEvents = await owner.query(
    `SELECT count(*)::int AS n FROM pii_vault.access_events WHERE tenant_id = $1 AND action = 'read'`,
    [globex.tenantId],
  );
  console.log(`read events logged for the blocked attempt: ${globexEvents.rows[0].n}`);

  heading("A BYPASSRLS login is refused");
  const bypassUrl = new URL(runtimeUrl);
  bypassUrl.username = "pii_vault_bypass";
  bypassUrl.password = "bypass-local-only";
  const bypassVault = new PiiVault({ databaseUrl: bypassUrl.toString(), keyring: loadKeyring() });
  try {
    await bypassVault.verifyVaultConnection();
    console.log("UNEXPECTED: BYPASSRLS login accepted");
    process.exitCode = 1;
  } catch (error) {
    console.log(`pii_vault_bypass: ${(error as Error).message}`);
  } finally {
    await bypassVault.close();
  }

  const goDir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "go");
  if (spawnSync("go", ["version"]).status === 0) {
    heading("The Go reader opens what Node wrote");
    const output = execFileSync(
      "go",
      ["run", "./cmd/vault-read", "-tenant", acme.tenantId, "-owner", "client_0001", "-types", "ssn,date_of_birth,monthly_income"],
      { cwd: goDir, encoding: "utf8" },
    );
    console.log(`go run ./cmd/vault-read -> ${output.trim()}`);
  }
} finally {
  await vault.close();
  await owner.end();
}
