import { describe, expect, it, vi } from 'vitest';
import {
  captureCatalogSnapshot,
  catalogSnapshotSchema,
  parsePostgresArray,
  type SqlClient,
} from './index.js';

const BEGIN = 'BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY';
const ROLLBACK = 'ROLLBACK';

function createCatalogQueryMock(): ReturnType<typeof vi.fn<SqlClient['query']>> {
  return vi.fn<SqlClient['query']>().mockImplementation((sql) => {
    if (sql === BEGIN || sql === ROLLBACK) return Promise.resolve({ rows: [] });
    if (sql.includes("to_regclass('storage.buckets')"))
      return Promise.resolve({ rows: [{ has_storage: false }] });
    if (sql.includes('current_database()')) {
      return Promise.resolve({
        rows: [
          {
            database_name: 'postgres',
            server_version: '16.4',
            current_role: 'scanner',
            is_superuser: false,
            can_bypass_rls: false,
          },
        ],
      });
    }
    if (sql.includes('effective_owner_roles')) {
      return Promise.resolve({
        rows: [
          {
            schema_name: 'public',
            table_name: 'invoices',
            relation_kind: 'r',
            rls_enabled: true,
            rls_forced: false,
            effective_owner_roles: '{authenticated}',
          },
          {
            schema_name: 'public',
            table_name: 'external_accounts',
            relation_kind: 'f',
            rls_enabled: false,
            rls_forced: false,
            effective_owner_roles: '{}',
          },
        ],
      });
    }
    if (sql.includes("c.relkind IN ('v', 'm')")) {
      return Promise.resolve({
        rows: [
          {
            schema_name: 'public',
            view_name: 'invoice_export',
            security_invoker: false,
          },
          {
            schema_name: 'public',
            view_name: 'invoice_rollup',
            security_invoker: false,
          },
        ],
      });
    }
    if (sql.includes('information_schema.columns')) {
      return Promise.resolve({
        rows: [
          {
            schema_name: 'public',
            table_name: 'invoices',
            column_name: 'id',
            data_type: 'uuid',
            ordinal_position: 1,
          },
          {
            schema_name: 'public',
            table_name: 'invoices',
            column_name: 'org_id',
            data_type: 'uuid',
            ordinal_position: 2,
          },
        ],
      });
    }
    if (sql.includes("contype = 'p'")) {
      return Promise.resolve({
        rows: [{ schema_name: 'public', table_name: 'invoices', columns: '{id}' }],
      });
    }
    if (sql.includes('FROM pg_index'))
      return Promise.resolve({
        rows: [
          {
            schema_name: 'public',
            table_name: 'invoices',
            index_name: 'invoices_org_id_idx',
            columns: '{org_id}',
          },
        ],
      });
    if (sql.includes("contype = 'f'")) return Promise.resolve({ rows: [] });
    if (sql.includes('has_table_privilege')) {
      return Promise.resolve({
        rows: [
          {
            schema_name: 'public',
            table_name: 'invoices',
            grantee: 'authenticated',
            privilege_type: 'SELECT',
          },
          {
            schema_name: 'public',
            table_name: 'invoice_export',
            grantee: 'authenticated',
            privilege_type: 'SELECT',
          },
        ],
      });
    }
    if (sql.includes('FROM pg_policies')) {
      return Promise.resolve({
        rows: [
          {
            schema_name: 'public',
            table_name: 'invoices',
            policy_name: 'tenant select',
            permissive: 'PERMISSIVE',
            roles: '{authenticated}',
            effective_roles: '{authenticated}',
            command: 'SELECT',
            using_expression: "(org_id = auth.jwt() ->> 'org_id')",
            check_expression: null,
          },
        ],
      });
    }
    if (sql.includes('FROM pg_policy policy')) {
      return Promise.resolve({
        rows: [
          {
            schema_name: 'public',
            table_name: 'invoices',
            policy_name: 'tenant select',
            referenced_schema: 'public',
            referenced_table: 'organization_members',
          },
        ],
      });
    }
    if (sql.includes('FROM pg_proc')) {
      return Promise.resolve({
        rows: [
          {
            schema_name: 'public',
            function_name: 'danger',
            identity_arguments: '',
            security_definer: true,
            execute_roles: '{authenticated,anon}',
          },
        ],
      });
    }
    throw new Error(`Unexpected query: ${sql}`);
  });
}

describe('catalog snapshot', () => {
  it('captures and normalizes PostgreSQL catalog state with read-only queries', async () => {
    const query = createCatalogQueryMock();
    const client: SqlClient = { query };

    const snapshot = await captureCatalogSnapshot(client, ['public']);

    expect(catalogSnapshotSchema.parse(snapshot)).toEqual(snapshot);
    expect(snapshot.tables[0]).toMatchObject({
      schema: 'public',
      name: 'invoices',
      primaryKey: ['id'],
      ownerRoles: ['authenticated'],
      grants: [{ role: 'authenticated', privileges: ['select'] }],
      policies: [{ name: 'tenant select', command: 'select', roles: ['authenticated'] }],
    });
    expect(snapshot.tables[0]?.policies[0]).toMatchObject({
      effectiveRoles: ['authenticated'],
      referencedRelations: [{ schema: 'public', table: 'organization_members' }],
    });
    expect(snapshot.tables).toContainEqual(
      expect.objectContaining({ name: 'external_accounts', isForeign: true }),
    );
    expect(snapshot.functions[0]?.executeRoles).toEqual(['anon', 'authenticated']);
    expect((snapshot as unknown as { views: unknown[] }).views).toContainEqual({
      schema: 'public',
      name: 'invoice_export',
      securityInvoker: false,
      grants: [{ role: 'authenticated', privileges: ['select'] }],
    });
    expect((snapshot as unknown as { views: unknown[] }).views).toContainEqual(
      expect.objectContaining({ name: 'invoice_rollup', securityInvoker: false }),
    );
    expect(query.mock.calls.some(([sql]) => sql.includes('has_function_privilege'))).toBe(true);
    expect(
      query.mock.calls
        .filter(([sql]) => /has_(?:table|function)_privilege/.test(sql))
        .every(([sql]) => sql.includes('has_schema_privilege')),
    ).toBe(true);
    expect(query.mock.calls.some(([sql]) => sql.includes('has_any_column_privilege'))).toBe(true);
    expect(query.mock.calls.some(([sql]) => sql.includes("c.relkind IN ('r', 'p', 'f')"))).toBe(
      true,
    );
    const grantsQuery = query.mock.calls.find(([sql]) => sql.includes('has_table_privilege'))?.[0];
    expect(grantsQuery).toContain("c.relkind IN ('r', 'p', 'f', 'v', 'm')");
    expect(
      query.mock.calls
        .filter(([sql]) => sql !== BEGIN && sql !== ROLLBACK)
        .every(([sql]) => /^\s*SELECT/i.test(sql)),
    ).toBe(true);
  });

  it('runs every catalog query inside one repeatable-read read-only transaction', async () => {
    const query = createCatalogQueryMock();
    const client: SqlClient = { query };

    await captureCatalogSnapshot(client, ['public']);

    const statements = query.mock.calls.map(([sql]) => sql);
    expect(statements[0]).toBe(BEGIN);
    expect(statements[statements.length - 1]).toBe(ROLLBACK);
    const catalogIndexes = statements
      .map((sql, index) => (/^\s*SELECT/i.test(sql) ? index : -1))
      .filter((index) => index >= 0);
    expect(catalogIndexes).toHaveLength(12);
    expect(catalogIndexes.every((index) => index > 0 && index < statements.length - 1)).toBe(true);
    expect(statements.filter((sql) => sql === BEGIN)).toHaveLength(1);
    expect(statements.filter((sql) => sql === ROLLBACK)).toHaveLength(1);
  });

  it('rolls back the snapshot transaction when a catalog query fails', async () => {
    const statements: string[] = [];
    const client: SqlClient = {
      query: (sql) => {
        statements.push(sql);
        if (sql === BEGIN || sql === ROLLBACK) return Promise.resolve({ rows: [] });
        return Promise.reject(new Error('connection lost'));
      },
    };

    await expect(captureCatalogSnapshot(client, ['public'])).rejects.toThrow('connection lost');
    expect(statements[0]).toBe(BEGIN);
    expect(statements[statements.length - 1]).toBe(ROLLBACK);
  });

  it('sequences catalog queries for clients that reject concurrent execution', async () => {
    let active = 0;
    let maximumActive = 0;
    const client: SqlClient = {
      query: async (sql) => {
        active += 1;
        maximumActive = Math.max(maximumActive, active);
        await Promise.resolve();
        active -= 1;
        if (sql === BEGIN || sql === ROLLBACK) return { rows: [] };
        if (sql.includes("to_regclass('storage.buckets')"))
          return { rows: [{ has_storage: false }] };
        if (sql.includes('current_database()')) {
          return {
            rows: [
              {
                database_name: 'postgres',
                server_version: '16.4',
                current_role: 'scanner',
                is_superuser: false,
                can_bypass_rls: false,
              },
            ],
          };
        }
        return { rows: [] };
      },
    };
    await captureCatalogSnapshot(client, ['public']);
    expect(maximumActive).toBe(1);
  });
});

describe('parsePostgresArray', () => {
  it('parses plain and single-element arrays', () => {
    expect(parsePostgresArray('{a,b,c}')).toEqual(['a', 'b', 'c']);
    expect(parsePostgresArray('{single}')).toEqual(['single']);
  });

  it('parses the empty array', () => {
    expect(parsePostgresArray('{}')).toEqual([]);
  });

  it('parses quoted elements, including commas inside quotes', () => {
    expect(parsePostgresArray('{"quoted","with space"}')).toEqual(['quoted', 'with space']);
    expect(parsePostgresArray('{"a,b",c}')).toEqual(['a,b', 'c']);
  });

  it('unescapes escaped quotes and backslashes inside quoted elements', () => {
    expect(parsePostgresArray('{"a\\"b"}')).toEqual(['a"b']);
    expect(parsePostgresArray('{"a\\\\b"}')).toEqual(['a\\b']);
  });

  it('treats a backslash as escaping the next character anywhere', () => {
    // The escaped 'b' loses its backslash; this is the current behavior.
    expect(parsePostgresArray('{a\\bc}')).toEqual(['abc']);
  });

  it('drops unquoted NULL elements but keeps quoted "NULL"', () => {
    expect(parsePostgresArray('{NULL,x,NULL}')).toEqual(['x']);
    expect(parsePostgresArray('{"NULL"}')).toEqual(['NULL']);
    expect(parsePostgresArray('{NULL}')).toEqual([]);
  });

  it('keeps empty-string elements, quoted or not', () => {
    expect(parsePostgresArray('{a,,b}')).toEqual(['a', '', 'b']);
    expect(parsePostgresArray('{,,}')).toEqual(['', '', '']);
    expect(parsePostgresArray('{"",x}')).toEqual(['', 'x']);
  });

  it('preserves spacing after separators verbatim', () => {
    expect(parsePostgresArray('{a, b}')).toEqual(['a', ' b']);
  });

  it('returns no elements for input without matching braces', () => {
    expect(parsePostgresArray('no-braces')).toEqual([]);
    expect(parsePostgresArray('{unclosed')).toEqual([]);
    expect(parsePostgresArray('}extra{')).toEqual([]);
    expect(parsePostgresArray('')).toEqual([]);
  });

  it('rejects unterminated quotes and dangling escapes as invalid', () => {
    expect(() => parsePostgresArray('{a,"b}')).toThrow('Invalid PostgreSQL array value');
    expect(() => parsePostgresArray('{a"b}')).toThrow('Invalid PostgreSQL array value');
    expect(() => parsePostgresArray('{"a\\}')).toThrow('Invalid PostgreSQL array value');
  });

  it('keeps braces inside quoted elements without confusing them with the terminator', () => {
    expect(parsePostgresArray('{"a}b"}')).toEqual(['a}b']);
    expect(parsePostgresArray('{"a{b",c}')).toEqual(['a{b', 'c']);
  });
});
