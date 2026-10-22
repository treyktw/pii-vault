// Package vault reads restricted customer values (SSN, licence number, date
// of birth, tax id...) from the PII vault: a dedicated Postgres database,
// schema pii_vault (see sql/001_pii_vault.sql).
//
// It is the read half of ts/src/vault.ts and vaultCrypto.ts and must decrypt
// exactly what they encrypted: AES-256-GCM under a per-record key derived
// with HKDF-SHA256 from the keyring's master key, with the record's identity
// as additional data. Every read is logged in pii_vault.access_events in the
// same statement that selects it, so a value is never returned without its
// access record.
//
// Records are keyed by whatever ids the writer used (tenant id, owner id are
// opaque strings), so the Node writer and this reader can live in different
// services.
//
// Plaintext never leaves this package except to the caller, and is never
// logged.
package vault

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrNotConfigured means no vault database or keyring is set.
var ErrNotConfigured = errors.New("PII vault is not configured")

// Service and HKDFLabel must match VAULT_SERVICE and VAULT_HKDF_LABEL in
// ts/src/vaultCrypto.ts: they are bound into every key and ciphertext.
const (
	Service   = "pii-vault"
	HKDFLabel = "pii-vault"
)

// Keyring holds the master keys by version.
type Keyring map[int][]byte

// ParseKeyring reads PII_VAULT_KEYRING: {"1": "<base64 32 bytes>", ...}.
func ParseKeyring(raw string) (Keyring, error) {
	var entries map[string]string
	if err := json.Unmarshal([]byte(raw), &entries); err != nil {
		return nil, errors.New("PII_VAULT_KEYRING must be a JSON object")
	}
	keys := Keyring{}
	for v, encoded := range entries {
		version, err := strconv.Atoi(v)
		if err != nil || version < 1 {
			return nil, errors.New("PII_VAULT_KEYRING contains an invalid entry")
		}
		key, err := decodeKey(encoded)
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("PII vault key version %d must decode to 32 bytes", version)
		}
		keys[version] = key
	}
	if len(keys) == 0 {
		return nil, errors.New("PII_VAULT_KEYRING is empty")
	}
	return keys, nil
}

// decodeKey reads base64 as Node's Buffer.from(value, "base64") does:
// padding optional, URL-safe letters accepted.
func decodeKey(encoded string) ([]byte, error) {
	s := strings.TrimRight(strings.TrimSpace(encoded), "=")
	s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	return base64.RawStdEncoding.DecodeString(s)
}

// Context is a record's identity, bound into its key and its ciphertext.
type Context struct {
	TenantID   string
	VaultID    string
	OwnerType  string
	OwnerID    string
	Type       string
	KeyVersion int
}

// aad is canonicalContext: JSON.stringify of these keys in this order.
//
// encoding/json and JSON.stringify agree on everything here except U+2028 and
// U+2029, which Go escapes even with SetEscapeHTML(false) and JavaScript
// writes literally. Those are put back so an id containing them still opens
// (testdata/vectors.json has a case for it).
func (c Context) aad() []byte {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(struct {
		Service    string `json:"service"`
		Purpose    string `json:"purpose"`
		TenantID   string `json:"tenantId"`
		VaultID    string `json:"vaultId"`
		OwnerType  string `json:"ownerType"`
		OwnerID    string `json:"ownerId"`
		Type       string `json:"type"`
		KeyVersion int    `json:"keyVersion"`
	}{Service, "pii-vault", c.TenantID, c.VaultID, c.OwnerType, c.OwnerID, c.Type, c.KeyVersion})
	out := bytes.TrimSuffix(b.Bytes(), []byte("\n"))
	out = bytes.ReplaceAll(out, []byte(`\u2028`), []byte("\u2028"))
	out = bytes.ReplaceAll(out, []byte(`\u2029`), []byte("\u2029"))
	return out
}

func (k Keyring) recordKey(c Context) ([]byte, error) {
	master, ok := k[c.KeyVersion]
	if !ok {
		return nil, fmt.Errorf("PII vault key version %d is unavailable", c.KeyVersion)
	}
	info := HKDFLabel + ":" + c.VaultID + ":" + c.OwnerType + ":" + c.OwnerID + ":" + c.Type
	return hkdf.Key(sha256.New, master, []byte("tenant:"+c.TenantID), info, 32)
}

// Sealed is an encrypted value as the records table stores it.
type Sealed struct {
	Ciphertext string // base64
	IV         string // base64, 12 bytes
	AuthTag    string // base64, 16 bytes
	Algorithm  string
}

// Open decrypts a sealed value.
func (k Keyring) Open(s Sealed, c Context) (string, error) {
	if s.Algorithm != "aes-256-gcm" {
		return "", errors.New("unsupported PII vault encryption algorithm")
	}
	key, err := k.recordKey(c)
	if err != nil {
		return "", err
	}
	ct, err1 := base64.StdEncoding.DecodeString(s.Ciphertext)
	iv, err2 := base64.StdEncoding.DecodeString(s.IV)
	tag, err3 := base64.StdEncoding.DecodeString(s.AuthTag)
	if err1 != nil || err2 != nil || err3 != nil || len(iv) != 12 || len(tag) != 16 {
		return "", errors.New("PII vault record is malformed")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, iv, append(ct, tag...), c.aad())
	if err != nil {
		return "", errors.New("PII vault record failed authentication")
	}
	return string(plain), nil
}

// Seal encrypts a value (tests, and the write path when it moves here).
//
// Unlike the Node writer, Seal does not validate or trim plaintext: callers
// pass the normalized value.
func (k Keyring) Seal(plaintext string, c Context) (Sealed, error) {
	iv := make([]byte, 12)
	if _, err := rand.Read(iv); err != nil {
		return Sealed{}, err
	}
	return k.sealWithIV(plaintext, c, iv)
}

// sealWithIV is Seal with a caller-chosen IV, for the shared test vectors
// only: reusing an IV under one record key breaks GCM.
func (k Keyring) sealWithIV(plaintext string, c Context, iv []byte) (Sealed, error) {
	if len(iv) != 12 {
		return Sealed{}, errors.New("PII vault IV must be 12 bytes")
	}
	key, err := k.recordKey(c)
	if err != nil {
		return Sealed{}, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return Sealed{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return Sealed{}, err
	}
	out := gcm.Seal(nil, iv, []byte(plaintext), c.aad())
	ct, tag := out[:len(out)-16], out[len(out)-16:]
	return Sealed{
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
		IV:         base64.StdEncoding.EncodeToString(iv),
		AuthTag:    base64.StdEncoding.EncodeToString(tag),
		Algorithm:  "aes-256-gcm",
	}, nil
}

// Actor is who a read is for: the user who asked for the document.
type Actor struct {
	UserID string
	Role   string
}

// Reader reads records from the vault database.
type Reader struct {
	pool *pgxpool.Pool
	keys Keyring
}

// Option configures Open.
type Option func(*options)

type options struct {
	forbiddenLogins []string
}

// WithForbiddenLoginRoles names login roles refused outright, before and
// after connecting (case-insensitive): your provider's owner role, for
// example "postgres" or "neondb_owner". Superusers, BYPASSRLS roles and table
// owners are refused regardless.
func WithForbiddenLoginRoles(names ...string) Option {
	return func(o *options) {
		for _, n := range names {
			o.forbiddenLogins = append(o.forbiddenLogins, strings.ToLower(n))
		}
	}
}

// Open connects to the vault. Every new connection is checked to be a plain
// runtime role under forced RLS that cannot rewrite the access log, as the
// Node runtime checks it.
func Open(ctx context.Context, databaseURL string, keys Keyring, opts ...Option) (*Reader, error) {
	if databaseURL == "" || len(keys) == 0 {
		return nil, ErrNotConfigured
	}
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	u, err := url.Parse(databaseURL)
	if err != nil || u.User == nil {
		return nil, errors.New("PII_VAULT_DATABASE_URL is invalid")
	}
	for _, forbidden := range o.forbiddenLogins {
		if strings.EqualFold(u.User.Username(), forbidden) {
			return nil, errors.New("the database owner role must not be used by the PII vault runtime")
		}
	}
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, errors.New("PII_VAULT_DATABASE_URL is invalid")
	}
	cfg.MaxConns = 4
	cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		return verifyRole(ctx, conn, o.forbiddenLogins)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("PII vault: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("PII vault: %w", err)
	}
	return &Reader{pool: pool, keys: keys}, nil
}

// Close closes the pool.
func (r *Reader) Close() { r.pool.Close() }

const verifyRoleSQL = `
SELECT NOT (lower(current_user) = ANY($1::text[]))
   AND NOT r.rolsuper AND NOT r.rolbypassrls
   AND records.relowner <> r.oid AND events.relowner <> r.oid AND ns.nspowner <> r.oid
   AND records.relrowsecurity AND records.relforcerowsecurity
   AND events.relrowsecurity AND events.relforcerowsecurity
   AND has_schema_privilege(current_user, 'pii_vault', 'USAGE')
   AND has_table_privilege(current_user, 'pii_vault.records', 'SELECT')
   AND has_table_privilege(current_user, 'pii_vault.access_events', 'INSERT')
   AND NOT (has_table_privilege(current_user, 'pii_vault.access_events', 'UPDATE')
            OR has_table_privilege(current_user, 'pii_vault.access_events', 'DELETE')
            OR has_table_privilege(current_user, 'pii_vault.access_events', 'TRUNCATE'))
FROM pg_catalog.pg_roles r
JOIN pg_catalog.pg_class records ON records.oid = 'pii_vault.records'::regclass
JOIN pg_catalog.pg_class events ON events.oid = 'pii_vault.access_events'::regclass
JOIN pg_catalog.pg_namespace ns ON ns.oid = records.relnamespace
WHERE r.rolname = current_user`

func verifyRole(ctx context.Context, conn *pgx.Conn, forbiddenLogins []string) error {
	if forbiddenLogins == nil {
		forbiddenLogins = []string{}
	}
	var ok bool
	if err := conn.QueryRow(ctx, verifyRoleSQL, forbiddenLogins).Scan(&ok); err != nil || !ok {
		return errors.New("the PII vault runtime role is not RLS-safe")
	}
	return nil
}

// readSQL selects the owner's live records of the requested types and logs
// one read per record, in one statement.
const readSQL = `
WITH selected AS (
  SELECT vault_id, tenant_id, owner_type, owner_id, field_type, ciphertext, iv, auth_tag, algorithm, key_version
  FROM pii_vault.records
  WHERE tenant_id = $1 AND owner_type = $2 AND owner_id = $3 AND field_type = ANY($4::text[])
    AND deleted_at IS NULL AND expires_at > clock_timestamp()
  FOR SHARE
), logged AS (
  INSERT INTO pii_vault.access_events
    (event_id, tenant_id, vault_id, action, actor_id, actor_role, reason, succeeded, request_id, metadata)
  SELECT gen_random_uuid(), $1, s.vault_id, 'read', $5, $6, $7, true, gen_random_uuid(),
         jsonb_build_object('fieldType', s.field_type)
  FROM selected s
  RETURNING vault_id
)
SELECT s.vault_id::text, s.tenant_id, s.owner_type, s.owner_id, s.field_type,
       s.ciphertext, s.iv, s.auth_tag, s.algorithm, s.key_version
FROM selected s JOIN logged l ON l.vault_id = s.vault_id`

// Read returns the owner's values of the requested types, by type. A type
// with no live record is absent.
func (r *Reader) Read(ctx context.Context, actor Actor, tenantID, ownerType, ownerID string, types []string, reason string) (map[string]string, error) {
	out := map[string]string{}
	if len(types) == 0 {
		return out, nil
	}
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true), set_config('app.actor_id', $2, true)`,
		tenantID, actor.UserID); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, readSQL, tenantID, ownerType, ownerID, types, actor.UserID, actor.Role, reason)
	if err != nil {
		return nil, err
	}
	type row struct {
		c Context
		s Sealed
	}
	var got []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.c.VaultID, &x.c.TenantID, &x.c.OwnerType, &x.c.OwnerID, &x.c.Type,
			&x.s.Ciphertext, &x.s.IV, &x.s.AuthTag, &x.s.Algorithm, &x.c.KeyVersion); err != nil {
			rows.Close()
			return nil, err
		}
		got = append(got, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, x := range got {
		if x.c.TenantID != tenantID || x.c.OwnerType != ownerType || x.c.OwnerID != ownerID {
			return nil, errors.New("PII reference integrity failure")
		}
		plain, err := r.keys.Open(x.s, x.c)
		if err != nil {
			return nil, err
		}
		out[x.c.Type] = plain
	}
	// The access log commits with the read.
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return out, nil
}
