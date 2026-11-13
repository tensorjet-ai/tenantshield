# tenantshield-mcp

> Model Context Protocol (MCP) server for PostgreSQL and Supabase Row-Level Security verification.

TenantShield MCP connects AI coding agents—including Cursor, Claude Code, Windsurf, and Claude Desktop—directly to local PostgreSQL and Supabase security intelligence. It empowers AI agents to audit live catalog privilege graphs, scan migration files for RLS anti-patterns, and simulate cross-tenant access attacks inside rollback-only transactions before code is committed.

[![npm version](https://img.shields.io/npm/v/tenantshield-mcp.svg)](https://www.npmjs.com/package/tenantshield-mcp)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

---

## Quick Start

### 1. Claude Code CLI

Add TenantShield MCP to Claude Code with a single command:

```bash
claude mcp add tenantshield -- npx --yes tenantshield-mcp@0.2.0
```

### 2. Cursor (`.cursor/mcp.json` or `~/.cursor/mcp.json`)

Add the server to your project or global Cursor configuration:

```json
{
  "mcpServers": {
    "tenantshield": {
      "command": "npx",
      "args": ["--yes", "tenantshield-mcp@0.2.0"],
      "env": {
        "TENANTSHIELD_DATABASE_URL": "postgresql://postgres:postgres@127.0.0.1:54322/postgres"
      }
    }
  }
}
```

### 3. Claude Desktop (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "tenantshield": {
      "command": "npx",
      "args": ["--yes", "tenantshield-mcp@0.2.0"],
      "env": {
        "TENANTSHIELD_DATABASE_URL": "postgresql://postgres:postgres@127.0.0.1:54322/postgres"
      }
    }
  }
}
```

---

## Features

- **Shift-Left AI Security Guardrails**: Gives AI assistants the capability to verify database security and isolation boundaries before generating code or applying database migrations.
- **Pre-Migration Hazard Scanner (`verify_migration_safety`)**: Fast static analysis detects 6 critical RLS vulnerabilities in SQL migration scripts before execution on any database.
- **Live Catalog Matrix Inspection (`inspect_rls_matrix`)**: Inspects PostgreSQL catalog tables (`pg_class`, `pg_policy`, `pg_roles`) to expose effective role privileges, inherited grants, and policy rules.
- **Dynamic Cross-Tenant Attack Simulation (`simulate_tenant_access`)**: Executes real `SELECT`, `INSERT`, `UPDATE`, and `DELETE` access probes across tenant boundaries inside isolated transactional savepoints with unconditional rollbacks.
- **Automatic Fixture Synthesis (`autoSeed: true`)**: Synthesizes foreign key dependencies and test rows automatically without manual SQL fixture scripting.
- **Zero Cloud Ingress & Redacted Payloads**: Operates entirely over local stdio. Database connection strings, secrets, and raw row values are redacted before returning data to the AI model.
- **Strict Localhost Interlock**: Refuses remote hosts and production marker databases by default to protect live infrastructure.

---

## Exposed MCP Tools

`tenantshield-mcp` exposes 3 specialized tools:

### 1. `verify_migration_safety`

Performs non-executing static analysis of a SQL migration script to detect common RLS anti-patterns before applying changes.

- **Parameters**:
  - `sql` _(string, optional)_: Raw SQL migration string to inspect.
  - `path` _(string, optional)_: File path to a `.sql` migration file.

- **Detected Vulnerabilities**:
  - `table_without_rls`: `CREATE TABLE` without an accompanying `ENABLE ROW LEVEL SECURITY`.
  - `unconditional_policy`: `USING (true)` or `WITH CHECK (true)` granting unrestricted access.
  - `user_metadata`: Authorization expressions checking client-editable `user_metadata` in JWTs.
  - `view_without_security_invoker`: `CREATE VIEW` without `WITH (security_invoker = true)`.
  - `truncate_grant`: `GRANT TRUNCATE` on tables (TRUNCATE bypasses PostgreSQL RLS).
  - `unsafe_security_definer`: `SECURITY DEFINER` function missing a fixed `search_path` or public execution revocation.

- **Example Response**:
  ```json
  {
    "safe": false,
    "findings": ["table_without_rls", "user_metadata"]
  }
  ```

---

### 2. `inspect_rls_matrix`

Connects to the local database, inspects system catalogs (`pg_class`, `pg_policy`, `pg_roles`), and computes the effective privilege matrix for all configured schemas and roles.

- **Parameters**:
  - `config` _(object, required)_: Parsed TenantShield configuration object (matching `tenantshield.config.yaml`).
  - `connectionEnv` _(string, optional)_: Environment variable containing the PostgreSQL connection URL (defaults to `TENANTSHIELD_DATABASE_URL`).

- **Returns**:
  - `matrix`: Array of tables, effective role privileges, and active RLS policies.
  - `findings`: Static rule violations (`TS-RLS-001` through `TS-RLS-010`, `TS-FT-001`, `TS-FN-001`, etc.).

---

### 3. `simulate_tenant_access`

Runs bidirectional dynamic tenant access controls against a local target database. Tests whether Tenant B can read, insert, modify, or delete Tenant A's records.

- **Parameters**:
  - `config` _(object, required)_: TenantShield configuration object specifying identities and resources.
  - `autoSeed` _(boolean, optional)_: When `true`, automatically synthesizes foreign-key dependencies and fixture rows inside a transaction that is always rolled back.
  - `setupSql` _(string, optional)_: Custom SQL fixture setup string (required if `autoSeed` is false).
  - `connectionEnv` _(string, optional)_: Environment variable containing the PostgreSQL connection string.

- **Safety Architecture**:
  1. Begins an outer transaction and sets aggressive statement timeouts.
  2. Synthesizes fixture rows (if `autoSeed: true`).
  3. Switches to `anon` or `authenticated` role with `SET LOCAL ROLE` and sets mock JWT claims.
  4. Creates a savepoint, runs the cross-tenant probe, and rolls back to the savepoint.
  5. Rolls back the outer transaction. Database state remains unchanged.

---

## Client Setup Guides

### Cursor Integration

Create or update `.cursor/mcp.json` in your repository root:

```json
{
  "mcpServers": {
    "tenantshield": {
      "command": "npx",
      "args": ["--yes", "tenantshield-mcp@0.2.0"],
      "env": {
        "TENANTSHIELD_DATABASE_URL": "postgresql://postgres:postgres@127.0.0.1:54322/postgres"
      }
    }
  }
}
```

### Windsurf Integration

Add to `~/.codeium/windsurf/mcp_config.json`:

```json
{
  "mcpServers": {
    "tenantshield": {
      "command": "npx",
      "args": ["--yes", "tenantshield-mcp@0.2.0"],
      "env": {
        "TENANTSHIELD_DATABASE_URL": "postgresql://postgres:postgres@127.0.0.1:54322/postgres"
      }
    }
  }
}
```

---

## Example Agent Workflows & Prompts

Once configured, your AI coding agent can autonomously verify security boundaries:

- **Migration Safety**:

  > _"Inspect the migration I just wrote in `supabase/migrations/20260716000000_add_teams.sql` using TenantShield. Does it introduce any RLS bypasses or security definer hazards?"_

- **Catalog Audit**:

  > _"Use `inspect_rls_matrix` to audit the effective permissions on `public.workspaces`. Are table owner privileges unforced?"_

- **Dynamic Attack Simulation**:
  > _"Run `simulate_tenant_access` with `autoSeed: true` against my local Supabase instance. Confirm that Alice cannot read or update Bob's invoice records."_

---

## Safety Model & Non-Production Policy

- **Local Targets Only**: `tenantshield-mcp` connects only to local database targets (`127.0.0.1` / `localhost`). Remote hosts are refused.
- **Production Name Guard**: Connection strings containing production markers (`prod`, `live`, `primary`, etc.) fail closed immediately.
- **Zero Raw Data Exposure**: All connection strings, JWT tokens, and sensitive tenant column values are sanitized and redacted before being delivered via JSON-RPC.
- **Rollback Discipline**: Fixtures and dynamic attacks run within savepoint rollbacks; test rows are never permanently committed. Note that sequence values advance and external HTTP triggers are not undone by transaction rollbacks. Always use disposable or ephemeral local databases.

---

## Links & Ecosystem

- **Homepage**: [tenantshield.tensorjetai.com](https://tenantshield.tensorjetai.com)
- **Organization**: [TensorJetAI](https://github.com/tensorjet-ai)
- **GitHub Repository**: [github.com/tensorjet-ai/TenantShield](https://github.com/tensorjet-ai/TenantShield)
- **Issues & Support**: [github.com/tensorjet-ai/TenantShield/issues](https://github.com/tensorjet-ai/TenantShield/issues)
- **Core CLI**: [`tenantshield`](https://www.npmjs.com/package/tenantshield)

---

## License

[Apache-2.0](LICENSE) © 2026 TensorJetAI
