# tenantshield

> Provable PostgreSQL and Supabase Row-Level Security (RLS) tenant-isolation guard.

TenantShield inspects PostgreSQL catalogs, inherited role grants, table ownership bypasses, and client-editable metadata claims, then executes bidirectional dynamic attack cases inside transactional rollbacks to mathematically prove tenant boundaries.

[![npm version](https://img.shields.io/npm/v/tenantshield.svg)](https://www.npmjs.com/package/tenantshield)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

---

## Quick Start

Audit your local Supabase or PostgreSQL database instantly with `npx`:

```bash
# 1. Discover local migrations/config and generate starter tenantshield.config.yaml
npx tenantshield init

# 2. Verify local prerequisites (Node 22+, database connectivity, permissions)
npx tenantshield doctor

# 3. Run non-mutating static catalog inspection
npx tenantshield scan --fail-on high

# 4. Run bidirectional dynamic attack simulation with automatic fixture synthesis
npx tenantshield test --auto-seed --fail-on high --output tenantshield-report.json

# 5. Export comprehensive audit artifacts (HTML, SARIF 2.1.0, or Markdown PR diff)
npx tenantshield report tenantshield-report.json --format html --output audit-report.html
npx tenantshield report tenantshield-report.json --format sarif --output audit-report.sarif
```

---

## The Problem: Why Standard RLS Linters Fail

Most teams assume running `ALTER TABLE ... ENABLE ROW LEVEL SECURITY;` guarantees multi-tenant privacy. In reality, standard static linters only check if that binary flag is enabled, missing catastrophic isolation escapes:

1. **Table Ownership Bypass (`TS-RLS-007`)**: By default in PostgreSQL, table owner roles bypass all RLS policies. If your backend service or migration user connects under an owner role without `FORCE ROW LEVEL SECURITY`, tenant filters are silently bypassed.
2. **Forged Metadata Claims (`TS-RLS-008`)**: Many policies inspect `auth.jwt() -> 'user_metadata' ->> 'org_id'`. In Supabase, users can edit their own `user_metadata` directly through standard client SDKs, granting themselves arbitrary tenant access.
3. **UPDATE Row Takeover (`TS-DYN-UPDATE`)**: A policy may forbid Tenant B from reading Tenant A's row, but fail to enforce a `WITH CHECK` constraint on updates. Tenant B executes `UPDATE invoices SET tenant_id = 'tenant_b'` and steals the row without triggering a read alert.
4. **Exposed Foreign Tables & Views (`TS-FT-001`, `TS-VIEW-001`)**: PostgreSQL does not enforce RLS on foreign data wrappers (FDWs), and views default to `SECURITY DEFINER` behavior unless created with `WITH (security_invoker = true)`.

---

## Features

- **Deep Static Privilege Graph**: Inspects PostgreSQL internal catalogs (`pg_class`, `pg_policy`, `pg_roles`, `pg_proc`) to map effective grants across `anon` and `authenticated` roles, including group role inheritance and `PUBLIC` defaults.
- **Bidirectional Dynamic Probes**: Simulates cross-tenant `SELECT`, `INSERT`, `UPDATE`, and `DELETE` operations in both identity directions under simulated Supabase request JWT contexts.
- **Automatic Fixture Synthesis (`--auto-seed`)**: Traverses foreign key dependency trees, `auth.users`, and membership junction tables to synthesize deterministic test rows on the fly.
- **Transactional Rollback Architecture**: Every dynamic case runs inside an isolated savepoint and outer transaction that rolls back unconditionally. Zero persistent row residue.
- **CI/CD & Code Scanning Ready**: Emits versioned JSON, self-contained HTML audit matrices, GitHub-native Markdown access diffs (`--baseline`), and standardized SARIF 2.1.0 for GitHub Advanced Security.
- **Strict Safety Interlocks**: Defaults strictly to `localhost` / `127.0.0.1` and refuses remote hosts unless guarded by 3 independent opt-in controls (`allowedHosts`, `--allow-remote`, `TENANTSHIELD_ALLOW_REMOTE=1`).

---

## CLI Usage

### 1. `tenantshield init`

Discovers your database configuration (`supabase/config.toml` or custom migrations), detects tenant column conventions (`org_id`, `tenant_id`, `account_id`, `workspace_id`), and generates a starter `tenantshield.config.yaml`.

```bash
npx tenantshield init
```

_Note: `init` never overwrites existing configuration or fixture files._

### 2. `tenantshield doctor`

Preflights local runtime prerequisites:

- Node.js 22+ engine validation
- Supabase CLI & Docker availability (if using Supabase)
- Database connectivity and connection string sanity
- Config file syntax and schema validation
- Disposable database safety verification

```bash
npx tenantshield doctor
npx tenantshield doctor --config path/to/tenantshield.config.yaml
```

### 3. `tenantshield scan` (alias: `audit`)

Executes 17 non-mutating static catalog checks across all configured schemas.

```bash
# Basic scan with default failure threshold (high)
npx tenantshield scan

# Set custom failure threshold (critical, high, medium, low)
npx tenantshield scan --fail-on critical

# Write versioned JSON report for CI pipelines
npx tenantshield scan --output tenantshield-report.json

# Stream raw JSON to stdout (all logs and progress stream to stderr)
npx tenantshield scan --json > report.json

# Enable verbose diagnostic timings and connection metadata
npx tenantshield scan --verbose
```

### 4. `tenantshield test`

Executes static rules followed by bidirectional dynamic tenant-boundary attacks.

```bash
# Run with automatic fixture row synthesis
npx tenantshield test --auto-seed

# Run with deterministic SQL fixtures from tenantshield/fixtures.sql
npx tenantshield test

# Save report and exit with code 1 if high-severity leaks are found
npx tenantshield test --auto-seed --fail-on high --output tenantshield-report.json
```

### 5. `tenantshield report`

Converts saved JSON reports into terminal summaries, standalone HTML documents, SARIF 2.1.0 bundles, or Pull Request Markdown diffs:

```bash
# Render terminal summary
npx tenantshield report tenantshield-report.json --format terminal

# Generate standalone HTML audit report
npx tenantshield report tenantshield-report.json --format html --output audit.html

# Generate SARIF 2.1.0 for GitHub Code Scanning
npx tenantshield report tenantshield-report.json --format sarif --output scan.sarif

# Generate GitHub PR Markdown diff against a baseline report
npx tenantshield report tenantshield-report.json --format markdown --baseline baseline-report.json
```

---

## Configuration (`tenantshield.config.yaml`)

TenantShield is configured via `tenantshield.config.yaml` in your project root:

```yaml
version: 1
database:
  connectionEnv: TENANTSHIELD_DATABASE_URL
  allowedHosts: [localhost, 127.0.0.1]
  exposedSchemas: [public]
  productionMarkers: [prod, live, primary]

migrationsDir: supabase/migrations

fixtures:
  mode: auto # Use 'auto' for synthetic rows, or 'sql' for setupSql
  setupSql: tenantshield/fixtures.sql

identities:
  alice:
    role: authenticated
    userId: 11111111-1111-1111-1111-111111111111
    claims:
      org_id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
  bob:
    role: authenticated
    userId: 22222222-2222-2222-2222-222222222222
    claims:
      org_id: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
  contractor:
    role: authenticated
    userId: 33333333-3333-3333-3333-333333333333
    claims:
      org_id: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa

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

---

## Rule Catalog (22 Deterministic Checks)

| Rule ID           | Category | Default Severity | Description                                                                                   |
| :---------------- | :------- | :--------------- | :-------------------------------------------------------------------------------------------- |
| `TS-RLS-001`      | Static   | **Critical**     | Exposed table has Row-Level Security disabled.                                                |
| `TS-RLS-002`      | Static   | **High**         | Data API role has an operation grant without an applicable policy.                            |
| `TS-RLS-003`      | Static   | **High**         | Permissive policy has an omitted or unconditional boundary (`USING (true)`).                  |
| `TS-RLS-004`      | Static   | **High**         | Policy grants access to roles outside configured identities.                                  |
| `TS-RLS-005`      | Static   | **Medium**       | INSERT/UPDATE policy lacks an effective `WITH CHECK` boundary.                                |
| `TS-RLS-006`      | Static   | **Medium**       | Connection role is superuser or has `BYPASSRLS` privileges.                                   |
| `TS-RLS-007`      | Static   | **Critical**     | Data API role inherits table ownership without `FORCE ROW LEVEL SECURITY`.                    |
| `TS-RLS-008`      | Static   | **High**         | Active RLS policy trusts user-editable `user_metadata` for authorization.                     |
| `TS-RLS-009`      | Static   | **Low**          | Active RLS policy calls deprecated `auth.role()` or `auth.email()` helpers.                   |
| `TS-RLS-010`      | Static   | **Critical**     | Data API role has `TRUNCATE` grants, bypassing row policies completely.                       |
| `TS-FT-001`       | Static   | **Critical**     | Exposed foreign data wrapper (FDW) table lacks PostgreSQL RLS protection.                     |
| `TS-FN-001`       | Static   | **High**         | Exposed `SECURITY DEFINER` function is executable by Data API roles or `PUBLIC`.              |
| `TS-FN-002`       | Static   | **High**         | Exposed `SECURITY DEFINER` function lacks a pinned safe `search_path`.                        |
| `TS-STORAGE-001`  | Static   | **High**         | Supabase Storage bucket visibility and `storage.objects` policy boundaries mismatch.          |
| `TS-PERF-001`     | Static   | **Medium**       | Per-row `auth.uid()` / `auth.jwt()` calls lack scalar subquery caching `(SELECT auth.uid())`. |
| `TS-PERF-002`     | Static   | **Low**          | RLS tenant column has no valid leading index.                                                 |
| `TS-VIEW-001`     | Static   | **High**         | View exposed without `WITH (security_invoker = true)`.                                        |
| `TS-DYN-SELECT`   | Dynamic  | **Critical**     | Foreign identity successfully read owner tenant rows.                                         |
| `TS-DYN-INSERT`   | Dynamic  | **Critical**     | Foreign identity successfully inserted rows under another tenant identifier.                  |
| `TS-DYN-UPDATE`   | Dynamic  | **Critical**     | Foreign identity took over owner rows or reassigned records to another tenant.                |
| `TS-DYN-DELETE`   | Dynamic  | **Critical**     | Foreign identity successfully deleted owner tenant rows.                                      |
| `TS-DYN-SUBQUERY` | Dynamic  | **High**         | Multi-organization junction subquery raised SQLSTATE `21000` (cardinality violation).         |

---

## CI/CD Pipeline Integration

Gate pull requests on zero cross-tenant leaks using GitHub Actions:

```yaml
name: TenantShield Audit

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  rls-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 22

      - name: Start Local Supabase
        run: |
          npx --yes supabase@2.109.1 start
          npx --yes supabase@2.109.1 db reset --local

      - name: Run TenantShield Dynamic Audit
        env:
          TENANTSHIELD_DATABASE_URL: postgresql://postgres:postgres@127.0.0.1:54322/postgres
        run: |
          npx --yes tenantshield@0.2.0 test --auto-seed --fail-on high --output audit-report.json

      - name: Generate SARIF Security Report
        if: always()
        run: |
          npx --yes tenantshield@0.2.0 report audit-report.json --format sarif --output tenantshield.sarif

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: tenantshield.sarif
```

---

## Safety Model & Limitations

- **Local-First Mandate**: Dynamic mutation tests default strictly to local instances (`localhost`, `127.0.0.1`). Remote execution requires 3 independent opt-in guards: hostname allow-listing in YAML, the `--allow-remote` CLI flag, and `TENANTSHIELD_ALLOW_REMOTE=1` in the environment.
- **Production Marker Checks**: Hostnames, database names, and Supabase project references matching keywords like `prod` or `live` are blocked immediately before dynamic cases run.
- **Rollback Boundaries**: Every dynamic case executes inside an isolated savepoint and outer transaction that rolls back. However, PostgreSQL sequence numbers advance and external HTTP triggers cannot be undone by transaction rollback. Always run dynamic cases against ephemeral or disposable local databases.
- **Evidence, Not Guarantee**: TenantShield provides automated regression evidence. It is not a formal mathematical proof over all hypothetical inputs or arbitrary procedural SQL routines.

---

## Links & Ecosystem

- **Homepage & Workbench**: [tenantshield.tensorjetai.com](https://tenantshield.tensorjetai.com)
- **Organization**: [TensorJetAI](https://github.com/tensorjet-ai)
- **GitHub Repository**: [github.com/tensorjet-ai/TenantShield](https://github.com/tensorjet-ai/TenantShield)
- **Issues & Support**: [github.com/tensorjet-ai/TenantShield/issues](https://github.com/tensorjet-ai/TenantShield/issues)
- **MCP Companion Server**: [`tenantshield-mcp`](https://www.npmjs.com/package/tenantshield-mcp)

---

## License

[Apache-2.0](LICENSE) © 2026 TensorJetAI
