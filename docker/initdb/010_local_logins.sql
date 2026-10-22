-- Local-development logins. Runs after sql/001_pii_vault.sql as the
-- bootstrap superuser (which therefore owns the schema and tables).
--
-- pii_vault_runtime is what the application uses: a plain login that inherits
-- pii_vault_app's grants and cannot SET ROLE to it, own anything, or bypass
-- RLS. The password is a local placeholder.
CREATE ROLE pii_vault_runtime LOGIN PASSWORD 'runtime-local-only'
  INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT pii_vault_app TO pii_vault_runtime WITH INHERIT TRUE, SET FALSE;

-- pii_vault_bypass exists only so the tests and demo can prove the runtimes
-- refuse a BYPASSRLS login even when it has every grant the runtime needs.
CREATE ROLE pii_vault_bypass LOGIN PASSWORD 'bypass-local-only'
  INHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION BYPASSRLS;
GRANT pii_vault_app TO pii_vault_bypass WITH INHERIT TRUE, SET FALSE;
