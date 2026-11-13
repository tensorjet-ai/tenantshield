# Fixture guide

Dynamic tests can use either deterministic SQL fixtures (`fixtures.mode: sql`) or automatic transactional synthesis (`fixtures.mode: auto` or `tenantshield test --auto-seed`).

## Manual SQL fixtures (`fixtures.mode: sql`)

Fixture SQL must deterministically create at least one visible row for both owner and foreign identities on resources testing SELECT, UPDATE, or DELETE. INSERT-only resources do not need visible control rows. Tenant values can come from JWT `claims`, `identities.<name>.tenants`, or resource-level `ownerTenantValue` and `foreignTenantValue` (supporting junction-table authorization where the tenant ID is not stored in the JWT). `primaryKey` supports both single-column and composite primary keys. Keep primary keys stable across runs.

Recommended fixture pattern:

```sql
truncate table public.invoices;
insert into public.invoices (id, org_id) values
  ('aaaaaaaa-0000-4000-8000-000000000001', 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
  ('bbbbbbbb-0000-4000-8000-000000000001', 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb');
```

Setup executes once in a transaction through the disposable local database connection, which must have permission to create the fixture rows. TenantShield owns that transaction: fixture SQL containing `BEGIN`, `START TRANSACTION`, `COMMIT`, `END`, `ROLLBACK`, `ABORT`, `SAVEPOINT`, `RELEASE`, or prepared-transaction control is rejected before execution. `doctor` performs the same preflight. A setup error attempts rollback and returns a redacted diagnostic. Each authorization case runs in a separate transaction with statement/lock timeouts, a verified `anon` or `authenticated` role, a savepoint, and unconditional row rollback. Sequence values consumed by defaults or triggers are not reclaimed.

Fixture paths must remain inside the project root, including after symlink resolution.

## Automatic transactional synthesis (`--auto-seed`)

When `fixtures.mode: auto` or `--auto-seed` is enabled, TenantShield inspects foreign-key dependencies (including `auth.users` and configured or auto-detected `membership` junction tables), synthesizes deterministic rows for `ownerIdentity`, `foreignIdentity`, and optional `dualMemberIdentity` inside an outer transaction, runs all dynamic cases in nested savepoints, and rolls back the outer transaction on completion.

## Dynamic probe semantics

Dynamic `INSERT` testing automatically supplies the configured `tenantColumn` plus any required non-nullable, non-default, non-generated columns (reusing foreign-key values from seeded/control rows and deterministic scalar values for other required columns). Every operation runs same-tenant controls for both identities (and `dualMemberIdentity` when configured) before testing both cross-tenant directions. A failed positive control skips the dependent cross-tenant case, marks the report incomplete, and exits with code `3` rather than reporting the resource as secure.

UPDATE testing includes no-op access checks plus tenant-key reassignment/takeover in both identity directions. INSERT and reassignment statements intentionally omit `RETURNING`, preventing a SELECT policy from masking whether the write boundary itself allowed the operation.

Before rollback, each case forces deferred constraints to run. Writes that cannot commit because of deferred constraints are inconclusive errors, not cross-tenant successes.
