# Configuration reference

TenantShield reads `tenantshield.config.yaml`. Validation finishes before database access. Unknown keys fail validation; connection strings and secrets must come from environment variables.

Static scans include `public`, schemas listed in `database.exposedSchemas`, schemas listed in local `supabase/config.toml` `[api].schemas`, and schemas named by configured resources. Plain PostgreSQL repositories can pass `--config path/to/tenantshield.config.yaml`; they do not need a Supabase project.

```yaml
version: 1
database:
  connectionEnv: TENANTSHIELD_DATABASE_URL
  allowedHosts: [localhost, 127.0.0.1]
  exposedSchemas: [public, app]
  productionMarkers: [prod, live]
migrationsDir: db/migrations
fixtures:
  mode: sql
  setupSql: tenantshield/fixtures.sql
identities:
  alice:
    role: authenticated
    userId: 11111111-1111-1111-1111-111111111111
    claims: { org_id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa }
  bob:
    role: authenticated
    userId: 22222222-2222-2222-2222-222222222222
    claims: { org_id: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb }
resources:
  invoices:
    schema: public
    primaryKey: id
    tenantColumn: org_id
    ownerIdentity: alice
    foreignIdentity: bob
    dualMemberIdentity: contractor
    membership:
      schema: public
      table: organization_members
      tenantColumn: org_id
      userColumn: user_id
    testOperations: [select, insert, update, delete]
```

Identity claims must match values returned by `auth.jwt()`. `role` and `sub` are reserved and derived from identity configuration. UUID user IDs are normalized to lowercase PostgreSQL text form. Authorization claims should originate from trusted app metadata, never user-editable metadata. A resource marked `public: true` is excluded from tenant-isolation rules and dynamic cases.

For every non-public resource, owner and foreign identities need distinct string or safe-integer tenant values. Values can come from JWT `claims`, `identities.<name>.tenants`, or resource-level `ownerTenantValue` and `foreignTenantValue`. Explicit values support junction-table authorization that does not store a tenant claim in the JWT. `membership` configures (or disambiguates) the junction table binding `userColumn` to `tenantColumn` when `--auto-seed` synthesizes membership rows. `dualMemberIdentity` names a distinct authenticated identity used for multi-organization probes. `primaryKey` accepts one column or an ordered list of composite-key columns.

`fixtures.setupSql` must be a project-relative path without `..` traversal. TenantShield resolves symlinks and refuses fixture files outside the project. Set `fixtures.mode: auto` or pass `tenantshield test --auto-seed` to synthesize deterministic fixture rows inside a transaction that is always rolled back. Synthesis failures make the dynamic suite incomplete. `testOperations` must not contain duplicates.

Remote targets require all three controls: the hostname in `allowedHosts`, `--allow-remote`, and `TENANTSHIELD_ALLOW_REMOTE=1`. Connection query parameters may not override inspected `host` or `port`. MCP dynamic tools accept local database targets only.
