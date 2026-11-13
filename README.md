# TenantShield

TenantShield is a local-first TypeScript CLI that finds Supabase/PostgreSQL Row-Level Security tenant-isolation failures. It combines read-only catalog checks with rollback-only authorization cases for `anon` and `authenticated` roles.

TenantShield produces evidence, not a formal audit, security proof, compliance certification, or legal guarantee. Run dynamic cases only against disposable local databases; sequence advances and trigger side effects are not undone by transaction rollback.

## Five-minute quickstart

Requirements for the local Supabase quickstart: Node.js 22+, pnpm 10+, Docker, Supabase CLI, and PostgreSQL. Plain PostgreSQL repositories can use an explicit TenantShield config without Supabase CLI or Docker.

```bash
pnpm install --frozen-lockfile
pnpm build
cd examples/secure
npx --yes supabase@2.109.1 start
npx --yes supabase@2.109.1 db reset --local
export TENANTSHIELD_DATABASE_URL='postgresql://postgres:postgres@127.0.0.1:54322/postgres'
node ../../apps/cli/dist/index.js doctor
node ../../apps/cli/dist/index.js scan --fail-on high
node ../../apps/cli/dist/index.js test --fail-on high
```

Stop the example stack afterward with `npx --yes supabase@2.109.1 stop`.

Inside an existing local Supabase or PostgreSQL project (via npm):

```bash
npx tenantshield init
npx tenantshield scan --fail-on high --output tenantshield-report.json
npx tenantshield test --auto-seed --fail-on high --output tenantshield-report.json
npx tenantshield report tenantshield-report.json --format html --output tenantshield-report.html
npx tenantshield report tenantshield-report.json --format sarif --output tenantshield-report.sarif
npx tenantshield report tenantshield-report.json --format markdown
```

Start the Model Context Protocol (MCP) server for Cursor, Claude Code, or Windsurf:

```bash
npx tenantshield-mcp
```

`init` never overwrites existing configuration or fixture files. It creates a fixture SQL placeholder, detects exact tenant-column names (`org_id`, `organization_id`, `tenant_id`, `account_id`, `workspace_id`) in migrations, and labels suggestions as configuration candidates. Fixture paths are project-contained, including through symlinks.

The local admin connection lets TenantShield load deterministic fixtures. Every authorization case immediately switches to and verifies the configured `anon` or `authenticated` role before touching application data. Never use production credentials or a production database.

## Commands

- `tenantshield init`: discover `supabase/config.toml` and write starter YAML.
- `tenantshield doctor`: check Node, Supabase CLI, Docker, project/config, and database reachability.
- `tenantshield scan` (alias `audit`): run non-mutating table, foreign-table, view, function, storage, performance, grant, and policy rules across configured schemas.
- `tenantshield test`: load deterministic fixtures, run static checks, then isolated dynamic controls.
- `tenantshield test --auto-seed`: synthesize deterministic fixture rows in a rollback-only transaction.
- `tenantshield report`: convert saved JSON to terminal, HTML, JSON, SARIF, or Markdown; `--baseline` adds a fingerprint-based new/resolved diff.
- `tenantshield-mcp`: start the local stdio MCP server with RLS inspection, migration checks, and tenant-access simulation tools.

`scan` and `test` accept two output flags:

- `--json`: print the full versioned report JSON to stdout instead of the terminal render. `--output` still writes the report file, and exit codes are unchanged. In `--json` mode every other message (including the `Report:` path line and progress) goes to stderr, so stdout stays parseable.
- `--verbose`: print diagnostic lines to stderr — the redacted connection target, config summary, and per-step timings.
- `--config <path>`: load TenantShield YAML from a plain PostgreSQL repository.
- `--format markdown --baseline <path>`: render a GitHub-ready access diff against a saved report.

Progress feedback always goes to stderr so stdout stays parseable: `scan` reports before and after catalog capture, and `test` prints a `k/N resources tested` line as each resource's dynamic cases complete.

Exit codes: `0` complete and clean at threshold; `1` complete scan with a finding at threshold; `2` invalid configuration/dependency/safety target; `3` database/fixture failure or incomplete dynamic suite; `4` internal error.

## Documentation

- [Configuration](docs/configuration.md)
- [Fixture guide](docs/fixtures.md)
- [Rule catalog](docs/rules.md)
- [Safety model](docs/safety.md)
- [Limitations](docs/limitations.md)
- [GitHub Actions example](examples/github-actions/tenantshield.yml)

## License

Apache License 2.0 (`Apache-2.0`) starting with `v0.2.0` (`v0.1.0` on npm was published under MIT). See [LICENSE](LICENSE) and [NOTICE](NOTICE).

Reference projects live in `examples/secure` and `examples/vulnerable`.
