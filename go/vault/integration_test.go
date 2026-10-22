package vault

// Postgres integration tests for the Go reader. Need the docker compose
// database (make db-up); skipped unless PII_VAULT_DATABASE_URL and
// PII_VAULT_OWNER_DATABASE_URL are set.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

const testReason = "Go integration test: verifying an audited read"

type integrationEnv struct {
	runtimeURL string
	owner      *pgxpool.Pool
	runtime    *pgxpool.Pool
}

func newIntegrationEnv(t *testing.T) integrationEnv {
	t.Helper()
	runtimeURL, ownerURL := os.Getenv("PII_VAULT_DATABASE_URL"), os.Getenv("PII_VAULT_OWNER_DATABASE_URL")
	if runtimeURL == "" || ownerURL == "" {
		t.Skip("PII_VAULT_DATABASE_URL / PII_VAULT_OWNER_DATABASE_URL not set; run `make db-up` and `make test-integration`")
	}
	ctx := context.Background()
	owner, err := pgxpool.New(ctx, ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := pgxpool.New(ctx, runtimeURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { owner.Close(); runtime.Close() })
	return integrationEnv{runtimeURL: runtimeURL, owner: owner, runtime: runtime}
}

func randomID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + hex.EncodeToString(b)
}

func randomUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// insertSealed seals a value in Go and writes it the way the Node writer does:
// as the runtime login, inside a tenant-bound transaction.
func (e integrationEnv) insertSealed(t *testing.T, keys Keyring, c Context, plaintext string) {
	t.Helper()
	sealed, err := keys.Seal(plaintext, c)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	err = pgx.BeginFunc(ctx, e.runtime, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true), set_config('app.actor_id', 'seeder', true)`, c.TenantID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `
			INSERT INTO pii_vault.records
			  (vault_id, tenant_id, owner_type, owner_id, field_type, ciphertext, iv, auth_tag,
			   algorithm, key_version, display_hint, expires_at, created_by)
			VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, '***', now() + interval '1 day', 'seeder')`,
			c.VaultID, c.TenantID, c.OwnerType, c.OwnerID, c.Type,
			sealed.Ciphertext, sealed.IV, sealed.AuthTag, sealed.Algorithm, c.KeyVersion)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (e integrationEnv) readEvents(t *testing.T, tenantID string) []string {
	t.Helper()
	rows, err := e.owner.Query(context.Background(),
		`SELECT action || ':' || coalesce(metadata->>'fieldType', '') FROM pii_vault.access_events WHERE tenant_id = $1 ORDER BY occurred_at, action`, tenantID)
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func withLogin(t *testing.T, raw, user, password string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword(user, password)
	return u.String()
}

func TestIntegrationReadLogsEveryRecordAtomically(t *testing.T) {
	env := newIntegrationEnv(t)
	keys := testKeys(t)
	ctx := context.Background()
	tenant, owner := randomID("tenant_"), randomID("client_")
	for _, field := range []struct{ typ, value string }{{"ssn", "123-45-6789"}, {"date_of_birth", "1990-01-31"}} {
		env.insertSealed(t, keys, Context{TenantID: tenant, VaultID: randomUUID(), OwnerType: "client", OwnerID: owner, Type: field.typ, KeyVersion: 2}, field.value)
	}

	reader, err := Open(ctx, env.runtimeURL, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	got, err := reader.Read(ctx, Actor{UserID: "user_go", Role: "manager"}, tenant, "client", owner,
		[]string{"ssn", "date_of_birth", "tax_id"}, testReason)
	if err != nil {
		t.Fatal(err)
	}
	if got["ssn"] != "123-45-6789" || got["date_of_birth"] != "1990-01-31" || len(got) != 2 {
		t.Fatalf("Read = %v", got)
	}
	events := env.readEvents(t, tenant)
	if strings.Join(events, ",") != "read:date_of_birth,read:ssn" && strings.Join(events, ",") != "read:ssn,read:date_of_birth" {
		t.Fatalf("access events = %v, want one read per returned record", events)
	}

	// A reason the access log rejects fails the whole read: no values, no event.
	if _, err := reader.Read(ctx, Actor{UserID: "user_go", Role: "manager"}, tenant, "client", owner, []string{"ssn"}, "short"); err == nil {
		t.Fatal("read with an unloggable reason succeeded")
	}
	if n := len(env.readEvents(t, tenant)); n != 2 {
		t.Fatalf("failed read left %d events, want 2", n)
	}
}

func TestIntegrationCrossTenantReadIsEmpty(t *testing.T) {
	env := newIntegrationEnv(t)
	keys := testKeys(t)
	ctx := context.Background()
	tenantA, tenantB, owner := randomID("tenant_"), randomID("tenant_"), randomID("client_")
	env.insertSealed(t, keys, Context{TenantID: tenantA, VaultID: randomUUID(), OwnerType: "client", OwnerID: owner, Type: "ssn", KeyVersion: 2}, "123-45-6789")

	reader, err := Open(ctx, env.runtimeURL, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()

	got, err := reader.Read(ctx, Actor{UserID: "user_b", Role: "manager"}, tenantB, "client", owner, []string{"ssn"}, testReason)
	if err != nil || len(got) != 0 {
		t.Fatalf("tenant B read of tenant A owner = %v, %v", got, err)
	}
	if ev := env.readEvents(t, tenantB); len(ev) != 0 {
		t.Fatalf("blocked read logged %v", ev)
	}
}

func TestIntegrationAccessLogIsAppendOnly(t *testing.T) {
	env := newIntegrationEnv(t)
	ctx := context.Background()
	for _, stmt := range []string{
		`UPDATE pii_vault.access_events SET reason = 'rewritten history here'`,
		`DELETE FROM pii_vault.access_events`,
		`TRUNCATE pii_vault.access_events`,
	} {
		err := pgx.BeginFunc(ctx, env.runtime, func(tx pgx.Tx) error {
			_, err := tx.Exec(ctx, stmt)
			return err
		})
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "42501" {
			t.Errorf("%s: err = %v, want insufficient_privilege", stmt, err)
		}
	}
}

func TestIntegrationRotationKeepsOldRecordsReadable(t *testing.T) {
	env := newIntegrationEnv(t)
	keys := testKeys(t)
	ctx := context.Background()
	tenant := randomID("tenant_")
	env.insertSealed(t, keys, Context{TenantID: tenant, VaultID: randomUUID(), OwnerType: "client", OwnerID: "old", Type: "ssn", KeyVersion: 1}, "111-22-3333")
	env.insertSealed(t, keys, Context{TenantID: tenant, VaultID: randomUUID(), OwnerType: "client", OwnerID: "new", Type: "ssn", KeyVersion: 2}, "444-55-6666")

	reader, err := Open(ctx, env.runtimeURL, keys)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	actor := Actor{UserID: "user_go", Role: "manager"}
	for owner, want := range map[string]string{"old": "111-22-3333", "new": "444-55-6666"} {
		got, err := reader.Read(ctx, actor, tenant, "client", owner, []string{"ssn"}, testReason)
		if err != nil || got["ssn"] != want {
			t.Errorf("owner %s: %v, %v", owner, got, err)
		}
	}

	retired, err := Open(ctx, env.runtimeURL, Keyring{2: keys[2]})
	if err != nil {
		t.Fatal(err)
	}
	defer retired.Close()
	if _, err := retired.Read(ctx, actor, tenant, "client", "old", []string{"ssn"}, testReason); err == nil {
		t.Fatal("read a v1 record after retiring key version 1")
	}
}

func TestIntegrationRefusesUnsafeLogins(t *testing.T) {
	env := newIntegrationEnv(t)
	keys := testKeys(t)
	ctx := context.Background()

	if _, err := Open(ctx, withLogin(t, env.runtimeURL, "pii_vault_bypass", "bypass-local-only"), keys); err == nil {
		t.Error("opened with a BYPASSRLS login")
	}
	if _, err := Open(ctx, os.Getenv("PII_VAULT_OWNER_DATABASE_URL"), keys); err == nil {
		t.Error("opened as the superuser / schema owner")
	}
	if _, err := Open(ctx, os.Getenv("PII_VAULT_OWNER_DATABASE_URL"), keys, WithForbiddenLoginRoles("postgres")); err == nil ||
		!strings.Contains(err.Error(), "must not be used") {
		t.Errorf("forbidden login name: %v", err)
	}
	if r, err := Open(ctx, env.runtimeURL, keys, WithForbiddenLoginRoles("postgres", "neondb_owner")); err != nil {
		t.Errorf("refused the plain runtime login: %v", err)
	} else {
		r.Close()
	}
}

// Sealed values survive the text columns unchanged (no padding or encoding
// drift between what Seal returns and what comes back from Postgres).
func TestIntegrationSealedValueSurvivesPostgres(t *testing.T) {
	env := newIntegrationEnv(t)
	keys := testKeys(t)
	ctx := context.Background()
	c := Context{TenantID: randomID("tenant_"), VaultID: randomUUID(), OwnerType: "client", OwnerID: "client_0001", Type: "ssn", KeyVersion: 2}
	env.insertSealed(t, keys, c, "123-45-6789")
	var ciphertext, iv, tag string
	err := env.owner.QueryRow(ctx, `SELECT ciphertext, iv, auth_tag FROM pii_vault.records WHERE vault_id = $1::uuid`, c.VaultID).Scan(&ciphertext, &iv, &tag)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := keys.Open(Sealed{Ciphertext: ciphertext, IV: iv, AuthTag: tag, Algorithm: "aes-256-gcm"}, c); err != nil || got != "123-45-6789" {
		t.Fatalf("round trip through Postgres = %q, %v", got, err)
	}
}
