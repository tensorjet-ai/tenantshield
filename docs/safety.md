# Safety model

TenantShield defaults to localhost and refuses remote hosts. Guarded remote access needs three independent opt-ins. User-defined production markers are checked against hostname, database name, and Supabase project reference before dynamic cases, including on localhost.

Fixture setup commonly needs the local Supabase admin connection. TenantShield reports that privileged connection as `TS-RLS-006`; it does not use its privileges for authorization cases. Each case switches to a configured Data API role and fails closed unless the effective role is non-superuser and lacks `BYPASSRLS`.

Before every case TenantShield:

1. begins a transaction and applies statement/lock timeouts;
2. sets `anon` or `authenticated` with `SET LOCAL ROLE`;
3. sets Supabase-compatible request JWT claims;
4. verifies `current_user`, role attributes, `auth.uid()`, and `auth.jwt()`;
5. creates a savepoint, executes one case, rolls back to the savepoint, then rolls back the transaction.

Connection URLs, JWTs, common secret assignments, fixture row values, and raw identifiers used by dynamic findings are redacted. Reports use semantic `owner-identity-tenant` or `foreign-identity-tenant` labels; no tenant-derived hash is stored. JSON, HTML, and SARIF files are replaced atomically with private `0600` permissions.

Fixture paths are constrained to the discovered project after canonical symlink resolution, preventing configuration traversal from reading an unrelated local file.

Fixture transaction-control statements are rejected before execution. This prevents fixture SQL from committing partial setup changes outside TenantShield's rollback/error handling.

Saved reports include tested resources and passed, failed, errored, and skipped case counts. Connection loss aborts the suite. Any errored/skipped case or failed same-tenant positive control marks the dynamic run incomplete.

Rollback does not reclaim PostgreSQL sequence values and cannot undo trigger calls to external systems. Disable such triggers in disposable fixtures or point them to inert local services.
