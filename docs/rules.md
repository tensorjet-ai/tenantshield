# Rule catalog

| Rule              | Meaning                                                                                        | Default severity |
| ----------------- | ---------------------------------------------------------------------------------------------- | ---------------- |
| `TS-RLS-001`      | Exposed table has RLS disabled                                                                 | Critical         |
| `TS-RLS-002`      | Data API role has an operation grant without applicable policy                                 | High             |
| `TS-RLS-003`      | Permissive policy has an omitted or unconditional effective boundary                           | High             |
| `TS-RLS-004`      | Policy targets a role outside configured identities                                            | High             |
| `TS-RLS-005`      | INSERT/UPDATE policy lacks an effective `WITH CHECK` boundary                                  | Medium           |
| `TS-RLS-006`      | Connection role is superuser or has `BYPASSRLS`; effective dynamic role is separately verified | Medium           |
| `TS-RLS-007`      | Data API role inherits table ownership and bypasses RLS unless RLS is forced                   | Critical         |
| `TS-RLS-008`      | Active RLS policy trusts user-editable `user_metadata` for authorization                       | High             |
| `TS-RLS-009`      | Active RLS policy calls deprecated `auth.role()` or `auth.email()` helpers                     | Low              |
| `TS-RLS-010`      | Data API role has `TRUNCATE`, which bypasses row-level security                                | Critical/High    |
| `TS-FT-001`       | Foreign table is exposed through the Data API without PostgreSQL RLS protection                | Critical         |
| `TS-FN-001`       | Exposed `SECURITY DEFINER` function is executable by Data API roles/PUBLIC                     | High             |
| `TS-FN-002`       | Exposed `SECURITY DEFINER` function lacks a pinned safe `search_path`                          | High             |
| `TS-STORAGE-001`  | Supabase Storage bucket visibility and `storage.objects` policy boundaries disagree            | High             |
| `TS-PERF-001`     | Active RLS policy calls `auth.uid()` or `auth.jwt()` without scalar-SELECT wrapping            | Medium           |
| `TS-PERF-002`     | RLS tenant column has no valid index with that column first                                    | Low              |
| `TS-VIEW-001`     | Data API role can select a view that does not use invoker security                             | High             |
| `TS-DYN-SELECT`   | Foreign identity selected owner rows                                                           | Critical         |
| `TS-DYN-INSERT`   | Foreign identity inserted another tenant identifier                                            | Critical         |
| `TS-DYN-UPDATE`   | Foreign identity updated/took over owner rows, or owner reassigned a row to another tenant     | Critical         |
| `TS-DYN-DELETE`   | Foreign identity deleted owner rows                                                            | Critical         |
| `TS-DYN-SUBQUERY` | Dual-organization membership control raised SQLSTATE `21000`                                   | High             |

Only objects with effective `anon` or `authenticated` privileges and schema `USAGE` are treated as exposed. Effective table privileges include table-level and column-level grants inherited through group roles and `PUBLIC`. Policy findings require matching effective table privileges; inactive policy roles do not create Data API access. Function exposure checks likewise use effective `EXECUTE` privileges.

Table ownership is also effective through inherited roles. Owners bypass ordinary RLS, so TenantShield emits `TS-RLS-007` unless `FORCE ROW LEVEL SECURITY` is enabled.

Restrictive policies combine with permissive results using AND. TenantShield suppresses unconditional-policy findings only when every active role and operation has a restrictive expression with a recognizable tenant-column binding to `auth.uid()`, `auth.jwt()`, or the request JWT setting. Broad checks such as `auth.uid() IS NOT NULL` do not count as tenant boundaries.

`TS-RLS-010` reports `TRUNCATE` grants because PostgreSQL does not apply row-level security to that command. `TS-FN-001` excludes trigger functions; `TS-FN-002` checks exposed definer functions for a pinned `search_path`. `TS-STORAGE-001` compares bucket visibility with policies on `storage.objects`. The performance rules identify per-row auth-helper calls and tenant columns without a leading index; `(select auth.uid())` and `(select auth.jwt())` remain recognized tenant-boundary expressions.

Membership predicates using `IN` and `EXISTS` are recognized when they bind access to a request identity. Dynamic controls can also probe a configured dual-member identity for scalar-subquery cardinality failures.

Supabase users can edit `user_metadata`, so `TS-RLS-008` rejects active policy expressions that read it through `auth.jwt()` or the underlying request-claims setting. Store authorization claims in `app_metadata` or trusted database tables instead.

Supabase deprecates `auth.role()` in favor of native policy `TO` roles and `auth.email()` in favor of the email claim from `auth.jwt()`. `TS-RLS-009` reports active uses so policies can migrate without changing their intended access boundary.

PostgreSQL foreign tables do not provide RLS. `TS-FT-001` reports an active foreign table with effective Data API privileges. Keep foreign tables in a private schema and expose only a secured, filtered function when API access is required.

For UPDATE policies, PostgreSQL reuses `USING` as `WITH CHECK` when `WITH CHECK` is omitted. TenantShield reports `TS-RLS-005` only when neither boundary exists. Fingerprints derive from stable rule/resource/role/operation/identity fields, not prose. Static expression analysis intentionally recognizes only narrow high-confidence patterns; TenantShield does not attempt general SQL-policy proof.
