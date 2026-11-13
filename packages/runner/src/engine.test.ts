import { describe, expect, it } from 'vitest';
import type { CatalogSnapshot } from '@tenantshield/catalog';
import type { TenantShieldConfig } from '@tenantshield/config';
import {
  FixtureSetupError,
  IdentityVerificationError,
  runDynamicTests,
  synthesizeFixturesInTransaction,
  type DynamicSqlClient,
  type DynamicSqlResult,
} from './index.js';

const aliceId = '11111111-1111-1111-1111-111111111111';
const bobId = '22222222-2222-2222-2222-222222222222';
const aliceTenant = 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa';
const bobTenant = 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb';

const config: TenantShieldConfig = {
  version: 1,
  database: { connectionEnv: 'DATABASE_URL', allowedHosts: ['localhost'] },
  fixtures: { setupSql: 'fixtures.sql' },
  identities: {
    alice: { role: 'authenticated', userId: aliceId, claims: { org_id: aliceTenant } },
    bob: { role: 'authenticated', userId: bobId, claims: { org_id: bobTenant } },
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

const snapshot: CatalogSnapshot = {
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

class FakeRlsClient implements DynamicSqlClient {
  private identity = 'alice';
  private claims: Record<string, unknown> = {};
  private activeBegins = 0;
  readonly statements: string[] = [];
  maxConcurrentBegins = 0;

  query(sql: string, values: readonly unknown[] = []): Promise<DynamicSqlResult> {
    this.statements.push(sql);
    if (sql === 'BEGIN') {
      this.activeBegins += 1;
      this.maxConcurrentBegins = Math.max(this.maxConcurrentBegins, this.activeBegins);
    }
    if (sql === 'ROLLBACK') this.activeBegins -= 1;
    if (sql.startsWith('SET LOCAL ROLE')) return Promise.resolve({ rows: [], rowCount: 0 });
    if (sql.includes("set_config('request.jwt.claims'")) {
      this.claims = JSON.parse(String(values[0])) as Record<string, unknown>;
      this.identity = this.claims['sub'] === aliceId ? 'alice' : 'bob';
      return Promise.resolve({ rows: [], rowCount: 0 });
    }
    if (sql.includes('FROM pg_roles'))
      return Promise.resolve({
        rows: [{ current_role: 'authenticated', is_superuser: false, can_bypass_rls: false }],
        rowCount: 1,
      });
    if (sql.includes('auth.uid()')) {
      return Promise.resolve({
        rows: [{ user_id: this.claims['sub'], jwt: this.claims }],
        rowCount: 1,
      });
    }
    if (sql.includes('tenantshield_fixture')) {
      const own =
        this.identity === 'alice'
          ? {
              primary_key: 'invoice-a',
              primary_key_0: 'invoice-a',
              primary_key_1: '1',
              tenant_key: aliceTenant,
            }
          : {
              primary_key: 'invoice-b',
              primary_key_0: 'invoice-b',
              primary_key_1: '2',
              tenant_key: bobTenant,
            };
      return Promise.resolve({ rows: [own], rowCount: 1 });
    }
    if (sql.includes('tenantshield_select')) {
      const ownerTarget = values[0] === 'invoice-a';
      const visible = this.identity === 'alice' ? ownerTarget : !ownerTarget;
      return Promise.resolve({
        rows: visible ? [{ primary_key: String(values[0]) }] : [],
        rowCount: visible ? 1 : 0,
      });
    }
    if (sql.includes('tenantshield_update_tenant')) {
      return Promise.reject(
        Object.assign(new Error('row-level security violation'), { code: '42501' }),
      );
    }
    if (sql.includes('tenantshield_update') || sql.includes('tenantshield_delete')) {
      const ownerTarget = values[0] === 'invoice-a';
      const allowed = this.identity === 'alice' ? ownerTarget : !ownerTarget;
      return Promise.resolve({
        rows: allowed ? [{ primary_key: String(values[0]) }] : [],
        rowCount: allowed ? 1 : 0,
      });
    }
    if (sql.startsWith('INSERT INTO')) {
      return Promise.resolve({ rows: [{ org_id: values[0], id: values[1] }], rowCount: 1 });
    }
    return Promise.resolve({ rows: [], rowCount: 0 });
  }
}

describe('dynamic CRUD engine', () => {
  it('synthesizes fixture rows inside one outer transaction and always rolls it back', async () => {
    const client = new FakeRlsClient();
    const result = await synthesizeFixturesInTransaction(client, config, snapshot);
    expect(result.complete).toBe(true);
    expect(client.statements[0]).toBe('BEGIN');
    expect(client.statements.at(-1)).toBe('ROLLBACK');
    expect(client.statements.filter((sql) => sql.startsWith('INSERT INTO'))).toHaveLength(2);
    expect(client.statements.filter((sql) => sql === 'BEGIN')).toHaveLength(1);
    expect(result.warnings.some((warning) => warning.includes('sequence values'))).toBe(true);
  });
  it('passes secure cross-tenant select/update/delete cases', async () => {
    const client = new FakeRlsClient();
    const result = await runDynamicTests(client, config, snapshot);
    expect(result.findings).toEqual([]);
    expect(result.cases.every((testCase) => testCase.resource === 'public.invoices')).toBe(true);
    expect(
      result.cases
        .filter((testCase) => testCase.control === 'foreign')
        .every((testCase) => testCase.status === 'passed'),
    ).toBe(true);
    expect(
      result.cases
        .filter((testCase) => testCase.control === 'same')
        .every((testCase) => testCase.status === 'passed'),
    ).toBe(true);
    expect(result.cases).toHaveLength(16);
    expect(client.statements.find((sql) => sql.includes('tenantshield_fixture'))).toContain(
      '"org_id" = $1',
    );
  });

  it('emits critical findings when foreign access succeeds', async () => {
    const vulnerable = new FakeRlsClient();
    const original = vulnerable.query.bind(vulnerable);
    vulnerable.query = (sql, values = []) => {
      if (sql.includes('tenantshield_select') && values[0] === 'invoice-a')
        return Promise.resolve({ rows: [{ primary_key: 'invoice-a' }], rowCount: 1 });
      return original(sql, values);
    };
    const result = await runDynamicTests(vulnerable, config, snapshot);
    expect(result.findings).toContainEqual(
      expect.objectContaining({
        ruleId: 'TS-DYN-SELECT',
        severity: 'critical',
        identity: 'bob',
        testedTenant: 'owner-identity-tenant',
      }),
    );
    expect(JSON.stringify(result.findings)).not.toContain('invoice-a');
    expect(JSON.stringify(result.findings)).not.toContain(aliceTenant);
  });

  it('detects asymmetric owner-to-foreign access', async () => {
    const vulnerable = new FakeRlsClient();
    const original = vulnerable.query.bind(vulnerable);
    let activeUser = aliceId;
    vulnerable.query = (sql, values = []) => {
      if (sql.includes("set_config('request.jwt.claims'")) {
        activeUser = (JSON.parse(String(values[0])) as { sub: string }).sub;
      }
      if (
        sql.includes('tenantshield_select') &&
        activeUser === aliceId &&
        values[0] === 'invoice-b'
      ) {
        return Promise.resolve({ rows: [{ primary_key: 'invoice-b' }], rowCount: 1 });
      }
      return original(sql, values);
    };
    const selectConfig: TenantShieldConfig = {
      ...config,
      resources: {
        invoices: { ...config.resources['invoices']!, testOperations: ['select'] },
      },
    };

    const result = await runDynamicTests(vulnerable, selectConfig, snapshot);

    expect(result.findings).toContainEqual(
      expect.objectContaining({
        ruleId: 'TS-DYN-SELECT',
        identity: 'alice',
        testedTenant: 'foreign-identity-tenant',
      }),
    );
  });

  it('emits a critical finding when an owner can reassign a row to another tenant', async () => {
    const vulnerable = new FakeRlsClient();
    const original = vulnerable.query.bind(vulnerable);
    let reassignmentSql = '';
    vulnerable.query = (sql, values = []) => {
      if (sql.includes('tenantshield_update_tenant')) {
        reassignmentSql = sql;
        return Promise.resolve({ rows: [{ primary_key: 'invoice-a' }], rowCount: 1 });
      }
      return original(sql, values);
    };
    const result = await runDynamicTests(vulnerable, config, snapshot);
    expect(result.findings).toContainEqual(
      expect.objectContaining({
        ruleId: 'TS-DYN-UPDATE',
        severity: 'critical',
        identity: 'alice',
        testedTenant: 'owner-row-to-foreign-identity-tenant',
      }),
    );
    expect(reassignmentSql).not.toMatch(/returning/i);
  });

  it('emits a critical finding when a foreign identity can take over an owner row', async () => {
    const vulnerable = new FakeRlsClient();
    const original = vulnerable.query.bind(vulnerable);
    let activeUser = aliceId;
    vulnerable.query = (sql, values = []) => {
      if (sql.includes("set_config('request.jwt.claims'")) {
        activeUser = (JSON.parse(String(values[0])) as { sub: string }).sub;
      }
      if (sql.includes('tenantshield_update_tenant') && activeUser === bobId) {
        return Promise.resolve({ rows: [], rowCount: 1 });
      }
      return original(sql, values);
    };
    const result = await runDynamicTests(vulnerable, config, snapshot);
    expect(result.findings).toContainEqual(
      expect.objectContaining({
        ruleId: 'TS-DYN-UPDATE',
        severity: 'critical',
        identity: 'bob',
        testedTenant: 'owner-row-to-foreign-identity-tenant',
      }),
    );
  });

  it('emits a critical finding when an owner identity can take over a foreign row', async () => {
    const vulnerable = new FakeRlsClient();
    const original = vulnerable.query.bind(vulnerable);
    let activeUser = aliceId;
    vulnerable.query = (sql, values = []) => {
      if (sql.includes("set_config('request.jwt.claims'")) {
        activeUser = (JSON.parse(String(values[0])) as { sub: string }).sub;
      }
      if (
        sql.includes('tenantshield_update_tenant') &&
        activeUser === aliceId &&
        values[0] === 'invoice-b'
      ) {
        return Promise.resolve({ rows: [], rowCount: 1 });
      }
      return original(sql, values);
    };
    const updateConfig: TenantShieldConfig = {
      ...config,
      resources: {
        invoices: { ...config.resources['invoices']!, testOperations: ['update'] },
      },
    };

    const result = await runDynamicTests(vulnerable, updateConfig, snapshot);

    expect(result.findings).toContainEqual(
      expect.objectContaining({
        ruleId: 'TS-DYN-UPDATE',
        identity: 'alice',
        testedTenant: 'foreign-row-to-owner-identity-tenant',
      }),
    );
  });

  it('tests INSERT authorization without a RETURNING-induced SELECT policy check', async () => {
    const vulnerable = new FakeRlsClient();
    const insertConfig: TenantShieldConfig = {
      ...config,
      resources: {
        invoices: { ...config.resources['invoices']!, testOperations: ['insert'] },
      },
    };
    const original = vulnerable.query.bind(vulnerable);
    let insertSql = '';
    vulnerable.query = (sql, values = []) => {
      if (sql.includes('tenantshield_insert')) {
        insertSql = sql;
        return Promise.resolve({ rows: [], rowCount: 1 });
      }
      return original(sql, values);
    };
    const result = await runDynamicTests(vulnerable, insertConfig, snapshot);
    expect(result.findings).toContainEqual(
      expect.objectContaining({ ruleId: 'TS-DYN-INSERT', severity: 'critical' }),
    );
    expect(insertSql).not.toMatch(/returning/i);
  });

  it('populates required INSERT columns with identity foreign keys and fresh scalar values', async () => {
    const insertConfig: TenantShieldConfig = {
      ...config,
      resources: { invoices: { ...config.resources['invoices']!, testOperations: ['insert'] } },
    };
    const insertSnapshot: CatalogSnapshot = {
      ...snapshot,
      tables: [
        {
          ...snapshot.tables[0]!,
          columns: [
            { name: 'id', dataType: 'uuid', ordinal: 1, isNullable: false },
            { name: 'org_id', dataType: 'uuid', ordinal: 2, isNullable: false },
            { name: 'user_id', dataType: 'uuid', ordinal: 3, isNullable: false },
            { name: 'label', dataType: 'text', ordinal: 4, isNullable: false },
          ],
          foreignKeys: [
            {
              columns: ['org_id'],
              referencedSchema: 'public',
              referencedTable: 'organizations',
              referencedColumns: ['id'],
            },
            {
              columns: ['user_id'],
              referencedSchema: 'auth',
              referencedTable: 'users',
              referencedColumns: ['id'],
            },
          ],
        },
      ],
    };
    const client = new FakeRlsClient();
    const original = client.query.bind(client);
    const insertValues: unknown[][] = [];
    let activeClaims: Record<string, unknown> = {};
    client.query = (sql, values = []) => {
      if (sql.includes("set_config('request.jwt.claims'")) {
        activeClaims = JSON.parse(String(values[0])) as Record<string, unknown>;
      }
      if (sql.includes('tenantshield_insert')) {
        insertValues.push([...values]);
        expect(sql).toContain('"user_id"');
        expect(sql).toContain('"label"');
        const allowed = values[2] === activeClaims['sub'] && values[1] === activeClaims['org_id'];
        return Promise.resolve({ rows: [], rowCount: allowed ? 1 : 0 });
      }
      return original(sql, values);
    };

    const result = await runDynamicTests(client, insertConfig, insertSnapshot, {
      seededFixtures: {
        invoices: {
          owner: { org_id: aliceTenant, user_id: aliceId, label: 'existing-owner-label' },
          foreign: { org_id: bobTenant, user_id: bobId, label: 'existing-foreign-label' },
        },
      },
    });
    expect(result.cases).toHaveLength(4);
    expect(result.complete).toBe(true);
    expect(result.findings).toEqual([]);
    expect(insertValues).toHaveLength(4);
    expect(insertValues.map((values) => values[2])).toEqual([aliceId, bobId, bobId, aliceId]);
    expect(new Set(insertValues.map((values) => values[3])).size).toBe(4);
    expect(insertValues.map((values) => values[3])).not.toContain('existing-owner-label');
    expect(insertValues.map((values) => values[3])).not.toContain('existing-foreign-label');
    expect(new Set(insertValues.map((values) => values[0])).size).toBe(4);
  });

  it('aborts the suite when the database connection is lost', async () => {
    const disconnected = new FakeRlsClient();
    const original = disconnected.query.bind(disconnected);
    let selectCalls = 0;
    disconnected.query = (sql, values = []) => {
      if (sql.includes('tenantshield_select') && ++selectCalls === 2) {
        return Promise.reject(Object.assign(new Error('connection terminated'), { code: '08006' }));
      }
      return original(sql, values);
    };
    await expect(runDynamicTests(disconnected, config, snapshot)).rejects.toMatchObject({
      code: '08006',
    });
  });

  it('aborts when a verified identity becomes ineffective during a case', async () => {
    const unsafe = new FakeRlsClient();
    const original = unsafe.query.bind(unsafe);
    let roleChecks = 0;
    unsafe.query = (sql, values = []) => {
      if (sql.includes('FROM pg_roles') && ++roleChecks === 3) {
        return Promise.resolve({
          rows: [{ current_role: 'anon', is_superuser: false, can_bypass_rls: false }],
          rowCount: 1,
        });
      }
      return original(sql, values);
    };
    await expect(runDynamicTests(unsafe, config, snapshot)).rejects.toBeInstanceOf(
      IdentityVerificationError,
    );
  });

  it('marks the suite incomplete when a positive control fails', async () => {
    const broken = new FakeRlsClient();
    const original = broken.query.bind(broken);
    let selectCalls = 0;
    broken.query = (sql, values = []) => {
      if (sql.includes('tenantshield_select') && ++selectCalls === 1) {
        return Promise.resolve({ rows: [], rowCount: 0 });
      }
      return original(sql, values);
    };
    const result = await runDynamicTests(broken, config, snapshot);
    expect(result.complete).toBe(false);
    expect(result.cases).toContainEqual(
      expect.objectContaining({ operation: 'select', control: 'foreign', status: 'passed' }),
    );
    expect(result.warnings).toContainEqual(expect.stringMatching(/positive control.*SELECT/i));
  });

  it('requires the cross-tenant identity to pass the same operation first', async () => {
    const bobDenied = new FakeRlsClient();
    const updateConfig: TenantShieldConfig = {
      ...config,
      resources: {
        invoices: { ...config.resources['invoices']!, testOperations: ['update'] },
      },
    };
    const original = bobDenied.query.bind(bobDenied);
    let currentUser = aliceId;
    bobDenied.query = (sql, values = []) => {
      if (sql.includes("set_config('request.jwt.claims'")) {
        currentUser = (JSON.parse(String(values[0])) as { sub: string }).sub;
      }
      if (sql.includes('tenantshield_update') && currentUser === bobId) {
        return Promise.resolve({ rows: [], rowCount: 0 });
      }
      return original(sql, values);
    };
    const result = await runDynamicTests(bobDenied, updateConfig, snapshot);
    expect(result.complete).toBe(false);
    expect(result.cases).toContainEqual(
      expect.objectContaining({
        operation: 'update',
        control: 'same',
        identity: 'bob',
        status: 'failed',
      }),
    );
    expect(result.cases).toContainEqual(
      expect.objectContaining({
        operation: 'update',
        control: 'foreign',
        identity: 'bob',
        status: 'skipped',
      }),
    );
  });

  it('tests INSERT-only resources without requiring SELECT-visible fixture rows', async () => {
    const insertOnly = new FakeRlsClient();
    const insertConfig: TenantShieldConfig = {
      ...config,
      resources: {
        invoices: { ...config.resources['invoices']!, testOperations: ['insert'] },
      },
    };
    const original = insertOnly.query.bind(insertOnly);
    insertOnly.query = (sql, values = []) => {
      if (sql.includes('tenantshield_fixture')) {
        return Promise.reject(Object.assign(new Error('SELECT denied'), { code: '42501' }));
      }
      if (sql.includes('tenantshield_insert')) {
        return Promise.resolve({ rows: [], rowCount: 1 });
      }
      return original(sql, values);
    };
    const result = await runDynamicTests(insertOnly, insertConfig, snapshot);
    expect(result.complete).toBe(true);
    expect(result.findings).toContainEqual(
      expect.objectContaining({ ruleId: 'TS-DYN-INSERT', identity: 'bob' }),
    );
    expect(result.cases.filter((testCase) => testCase.operation === 'insert')).toHaveLength(4);
  });

  it('normalizes UUID tenant claims for PostgreSQL text lookup', async () => {
    const uppercase = new FakeRlsClient();
    const uppercaseConfig: TenantShieldConfig = {
      ...config,
      identities: {
        alice: {
          ...config.identities['alice']!,
          claims: { org_id: aliceTenant.toUpperCase() },
        },
        bob: {
          ...config.identities['bob']!,
          claims: { org_id: bobTenant.toUpperCase() },
        },
      },
      resources: {
        invoices: { ...config.resources['invoices']!, testOperations: ['select'] },
      },
    };
    const original = uppercase.query.bind(uppercase);
    let currentClaims = { sub: aliceId, role: 'authenticated', org_id: aliceTenant.toUpperCase() };
    uppercase.query = (sql, values = []) => {
      if (sql.includes("set_config('request.jwt.claims'")) {
        currentClaims = JSON.parse(String(values[0])) as typeof currentClaims;
      }
      if (sql.includes('auth.uid()')) {
        return Promise.resolve({
          rows: [{ user_id: currentClaims.sub, jwt: currentClaims }],
          rowCount: 1,
        });
      }
      if (sql.includes('tenantshield_fixture')) {
        const expected = currentClaims.sub === aliceId ? aliceTenant : bobTenant;
        if (values[0] !== expected) return Promise.resolve({ rows: [], rowCount: 0 });
      }
      return original(sql, values);
    };
    await expect(runDynamicTests(uppercase, uppercaseConfig, snapshot)).resolves.toMatchObject({
      complete: true,
      findings: [],
    });
  });

  it('rejects controls that resolve to the same canonical database tenant', async () => {
    const equivalentClaims: TenantShieldConfig = {
      ...config,
      identities: {
        alice: { ...config.identities['alice']!, claims: { org_id: '01' } },
        bob: { ...config.identities['bob']!, claims: { org_id: '1' } },
      },
      resources: {
        invoices: { ...config.resources['invoices']!, testOperations: ['select'] },
      },
    };
    const client = new FakeRlsClient();
    const original = client.query.bind(client);
    let fixtureCalls = 0;
    let activeClaims: Record<string, unknown> = {};
    client.query = (sql, values = []) => {
      if (sql.includes("set_config('request.jwt.claims'")) {
        activeClaims = JSON.parse(String(values[0])) as Record<string, unknown>;
      }
      if (sql.includes('auth.uid()')) {
        return Promise.resolve({
          rows: [{ user_id: activeClaims['sub'], jwt: activeClaims }],
          rowCount: 1,
        });
      }
      if (sql.includes('tenantshield_fixture')) {
        fixtureCalls += 1;
        return Promise.resolve({
          rows: [{ primary_key: `invoice-${fixtureCalls}`, tenant_key: '1' }],
          rowCount: 1,
        });
      }
      return original(sql, values);
    };
    await expect(runDynamicTests(client, equivalentClaims, snapshot)).rejects.toThrow(
      /same database tenant/i,
    );
  });

  it('rejects equivalent integer tenants before INSERT-only cases', async () => {
    const equivalentClaims: TenantShieldConfig = {
      ...config,
      identities: {
        alice: { ...config.identities['alice']!, claims: { org_id: '01' } },
        bob: { ...config.identities['bob']!, claims: { org_id: '1' } },
      },
      resources: {
        invoices: { ...config.resources['invoices']!, testOperations: ['insert'] },
      },
    };
    const integerSnapshot: CatalogSnapshot = {
      ...snapshot,
      tables: snapshot.tables.map((table) => ({
        ...table,
        columns: table.columns.map((column) =>
          column.name === 'org_id' ? { ...column, dataType: 'integer' } : column,
        ),
      })),
    };
    await expect(
      runDynamicTests(new FakeRlsClient(), equivalentClaims, integerSnapshot),
    ).rejects.toThrow(/same database tenant/i);
  });

  it('supports configured composite primary keys', async () => {
    const compositeKeySnapshot: CatalogSnapshot = {
      ...snapshot,
      tables: [{ ...snapshot.tables[0]!, primaryKey: ['org_id', 'id'] }],
    };
    await expect(
      runDynamicTests(
        new FakeRlsClient(),
        {
          ...config,
          resources: {
            invoices: { ...config.resources['invoices']!, primaryKey: ['org_id', 'id'] },
          },
        },
        compositeKeySnapshot,
      ),
    ).resolves.toMatchObject({ complete: true, findings: [] });
  });

  it('reports SQLSTATE 21000 from a dual-organization control as an incomplete subquery finding', async () => {
    const memberId = '33333333-3333-3333-3333-333333333333';
    class CardinalityClient extends FakeRlsClient {
      private currentSubject = '';
      override query(sql: string, values: readonly unknown[] = []): Promise<DynamicSqlResult> {
        if (sql.includes("set_config('request.jwt.claims'")) {
          this.currentSubject = String(
            (JSON.parse(String(values[0])) as Record<string, unknown>)['sub'],
          );
        }
        if (sql.includes('tenantshield_select') && this.currentSubject === memberId) {
          return Promise.reject(
            Object.assign(new Error('multiple rows from scalar subquery'), { code: '21000' }),
          );
        }
        return super.query(sql, values);
      }
    }
    const memberConfig: TenantShieldConfig = {
      ...config,
      identities: {
        ...config.identities,
        member: { role: 'authenticated', userId: memberId, claims: {} },
      },
      resources: {
        invoices: {
          ...config.resources['invoices']!,
          dualMemberIdentity: 'member',
          testOperations: ['select'],
        },
      },
    };
    const result = await runDynamicTests(new CardinalityClient(), memberConfig, snapshot);
    expect(result.complete).toBe(false);
    expect(result.findings).toEqual([
      expect.objectContaining({ ruleId: 'TS-DYN-SUBQUERY', severity: 'high' }),
    ]);
    expect(result.cases).toContainEqual(
      expect.objectContaining({ scenario: 'dual-membership-cardinality', status: 'error' }),
    );
  });

  it('redacts database details when control-row lookup fails', async () => {
    const broken = new FakeRlsClient();
    const original = broken.query.bind(broken);
    broken.query = (sql, values = []) => {
      if (sql.includes('tenantshield_fixture')) {
        return Promise.reject(
          Object.assign(new Error(`invalid input syntax: ${aliceTenant}`), { code: '22P02' }),
        );
      }
      return original(sql, values);
    };

    let thrown: unknown;
    try {
      await runDynamicTests(broken, config, snapshot);
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(FixtureSetupError);
    expect(String(thrown)).not.toContain(aliceTenant);
  });

  it('keeps resources sequential by default and overlaps them with maxConcurrentResources', async () => {
    const multiConfig: TenantShieldConfig = {
      ...config,
      resources: {
        invoices: config.resources['invoices']!,
        projects: {
          primaryKey: 'id',
          tenantColumn: 'org_id',
          ownerIdentity: 'alice',
          foreignIdentity: 'bob',
          testOperations: ['select'],
        },
      },
    };
    const multiSnapshot: CatalogSnapshot = {
      ...snapshot,
      tables: [
        ...snapshot.tables,
        {
          schema: 'public',
          name: 'projects',
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
    };

    const sequential = new FakeRlsClient();
    const sequentialResult = await runDynamicTests(sequential, multiConfig, multiSnapshot);
    expect(sequential.maxConcurrentBegins).toBe(1);
    expect(sequentialResult.complete).toBe(true);

    const concurrent = new FakeRlsClient();
    const concurrentResult = await runDynamicTests(concurrent, multiConfig, multiSnapshot, {
      maxConcurrentResources: 2,
    });
    expect(concurrent.maxConcurrentBegins).toBe(2);
    expect(concurrentResult.complete).toBe(true);
    expect(concurrentResult.findings).toEqual([]);
    expect(concurrentResult.cases).toHaveLength(sequentialResult.cases.length);
    expect(concurrentResult.cases.filter((c) => c.resource === 'public.invoices')).toHaveLength(16);
    expect(concurrentResult.cases.filter((c) => c.resource === 'public.projects')).toHaveLength(4);

    await expect(
      runDynamicTests(new FakeRlsClient(), multiConfig, multiSnapshot, {
        maxConcurrentResources: 99,
      }),
    ).resolves.toMatchObject({ complete: true });
  });
});
