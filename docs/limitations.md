# Current limitations

- Automatic fixture synthesis covers deterministic values for common PostgreSQL scalar types. Custom constraints, generated columns, triggers, and foreign-key cycles can make synthesis fail; those failures leave the dynamic suite incomplete.
- Dynamic row changes roll back, but PostgreSQL sequences advance and external trigger effects may not.
- Migration source locations use a lightweight SQL definition indexer. Complex or split-across-lines DDL may not receive an exact location.
- Supabase Storage checks compare bucket visibility with detectable `storage.objects` policy expressions; they do not model signed URLs, CDN caches, or application-level download flows.
- Foreign tables are reported when exposed because PostgreSQL does not apply RLS to them; TenantShield does not analyze remote-server filtering.
- The migration MCP tool uses conservative text checks. It does not execute migrations or prove arbitrary SQL safe.
- Dynamic tests sample deterministic control rows and configured identities. They provide regression evidence, not proof over every row, claim, or application path.
- Dynamic test targets remain subject to strict local/remote safety checks. Never run mutation tests against production data.

The open-source CLI (`tenantshield`) and MCP server (`tenantshield-mcp`) are licensed under the Apache License 2.0 (`Apache-2.0`) starting with `v0.2.0` (`v0.1.0` was published under MIT). See [LICENSE](../LICENSE) and [NOTICE](../NOTICE).
