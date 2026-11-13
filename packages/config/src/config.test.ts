import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { ConfigValidationError, parseConfig, parseConfigYaml } from './index.js';

const validConfig = {
  version: 1,
  database: { connectionEnv: 'TENANTSHIELD_DATABASE_URL', allowedHosts: ['localhost'] },
  fixtures: { setupSql: 'tenantshield/fixtures.sql' },
  identities: {
    alice: {
      role: 'authenticated',
      userId: '11111111-1111-1111-1111-111111111111',
      claims: { org_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' },
    },
    bob: {
      role: 'authenticated',
      userId: '22222222-2222-2222-2222-222222222222',
      claims: { org_id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' },
    },
  },
  resources: {
    invoices: {
      primaryKey: 'id',
      tenantColumn: 'org_id',
      ownerIdentity: 'alice',
      foreignIdentity: 'bob',
      testOperations: ['select', 'insert', 'update', 'delete'],
    },
  },
} as const;

describe('configuration contract', () => {
  it('parses a valid configuration', () => {
    expect(parseConfig(validConfig)).toEqual(validConfig);
  });

  it('accepts composite keys and explicit junction-table tenant controls', () => {
    const input = {
      ...validConfig,
      fixtures: { mode: 'auto' },
      identities: {
        alice: { role: 'authenticated', userId: validConfig.identities.alice.userId, claims: {} },
        bob: { role: 'authenticated', userId: validConfig.identities.bob.userId, claims: {} },
        member: {
          role: 'authenticated',
          userId: '33333333-3333-3333-3333-333333333333',
          claims: {},
        },
      },
      resources: {
        invoices: {
          ...validConfig.resources.invoices,
          primaryKey: ['org_id', 'id'],
          ownerTenantValue: 'org-a',
          foreignTenantValue: 'org-b',
          dualMemberIdentity: 'member',
        },
      },
    };
    expect(parseConfig(input).resources['invoices']?.primaryKey).toEqual(['org_id', 'id']);
  });

  it('accepts an explicit membership-table mapping', () => {
    const input = {
      ...validConfig,
      resources: {
        invoices: {
          ...validConfig.resources.invoices,
          membership: {
            schema: 'public',
            table: 'organization_members',
            tenantColumn: 'org_id',
            userColumn: 'user_id',
          },
        },
      },
    };
    expect(parseConfig(input).resources['invoices']?.membership).toEqual({
      schema: 'public',
      table: 'organization_members',
      tenantColumn: 'org_id',
      userColumn: 'user_id',
    });
  });

  it('normalizes UUID user IDs to PostgreSQL lowercase text form', () => {
    const input = {
      ...validConfig,
      identities: {
        ...validConfig.identities,
        alice: {
          ...validConfig.identities.alice,
          userId: 'AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA',
        },
      },
    };
    expect(parseConfig(input).identities['alice']?.userId).toBe(
      'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
    );
  });

  it('rejects prototype-inherited identity names for public resources', () => {
    const input = {
      ...validConfig,
      resources: {
        invoices: {
          ...validConfig.resources.invoices,
          ownerIdentity: 'toString',
          public: true,
        },
      },
    };
    expect(() => parseConfig(input)).toThrow(/resources\.invoices\.ownerIdentity/);
  });

  it('rejects unsafe numeric tenant claims that cannot round-trip exactly', () => {
    const input = {
      ...validConfig,
      identities: {
        ...validConfig.identities,
        alice: { ...validConfig.identities.alice, claims: { org_id: Number.MAX_SAFE_INTEGER + 1 } },
        bob: { ...validConfig.identities.bob, claims: { org_id: Number.MAX_SAFE_INTEGER } },
      },
    };
    expect(() => parseConfig(input)).toThrow(/identities\.alice\.claims\.org_id/);
  });

  it('rejects user IDs on unauthenticated Data API identities', () => {
    const input = {
      ...validConfig,
      identities: {
        ...validConfig.identities,
        alice: { ...validConfig.identities.alice, role: 'anon' },
      },
    };
    expect(() => parseConfig(input)).toThrow(/identities\.alice\.userId/);
  });

  it.each([
    ['version', { ...validConfig, version: 2 }, 'version'],
    ['database', { ...validConfig, database: undefined }, 'database'],
    [
      'connectionEnv',
      { ...validConfig, database: { ...validConfig.database, connectionEnv: '' } },
      'database.connectionEnv',
    ],
    [
      'allowedHosts',
      { ...validConfig, database: { ...validConfig.database, allowedHosts: [] } },
      'database.allowedHosts',
    ],
    ['fixtures', { ...validConfig, fixtures: { setupSql: '' } }, 'fixtures.setupSql'],
    [
      'fixture parent traversal',
      { ...validConfig, fixtures: { setupSql: '../secrets.sql' } },
      'fixtures.setupSql',
    ],
    ['identities', { ...validConfig, identities: {} }, 'identities'],
    [
      'identity role',
      {
        ...validConfig,
        identities: {
          ...validConfig.identities,
          alice: { ...validConfig.identities.alice, role: 'admin' },
        },
      },
      'identities.alice.role',
    ],
    [
      'identity userId',
      {
        ...validConfig,
        identities: {
          ...validConfig.identities,
          alice: { ...validConfig.identities.alice, userId: 'x' },
        },
      },
      'identities.alice.userId',
    ],
    [
      'reserved identity claim',
      {
        ...validConfig,
        identities: {
          ...validConfig.identities,
          alice: {
            ...validConfig.identities.alice,
            claims: { ...validConfig.identities.alice.claims, role: 'anon' },
          },
        },
      },
      'identities.alice.claims.role',
    ],
    ['resources', { ...validConfig, resources: {} }, 'resources'],
    [
      'operations',
      {
        ...validConfig,
        resources: { invoices: { ...validConfig.resources.invoices, testOperations: [] } },
      },
      'resources.invoices.testOperations',
    ],
    [
      'duplicate operations',
      {
        ...validConfig,
        resources: {
          invoices: { ...validConfig.resources.invoices, testOperations: ['select', 'select'] },
        },
      },
      'resources.invoices.testOperations',
    ],
    [
      'unknown owner',
      {
        ...validConfig,
        resources: { invoices: { ...validConfig.resources.invoices, ownerIdentity: 'nobody' } },
      },
      'resources.invoices.ownerIdentity',
    ],
    [
      'same identity',
      {
        ...validConfig,
        resources: { invoices: { ...validConfig.resources.invoices, foreignIdentity: 'alice' } },
      },
      'resources.invoices.foreignIdentity',
    ],
    [
      'same authenticated user',
      {
        ...validConfig,
        identities: {
          ...validConfig.identities,
          bob: {
            ...validConfig.identities.bob,
            userId: validConfig.identities.alice.userId,
          },
        },
      },
      'resources.invoices.foreignIdentity',
    ],
    [
      'missing tenant claim',
      {
        ...validConfig,
        identities: {
          ...validConfig.identities,
          alice: { ...validConfig.identities.alice, claims: {} },
        },
      },
      'identities.alice.claims.org_id',
    ],
    [
      'same tenant claim',
      {
        ...validConfig,
        identities: {
          ...validConfig.identities,
          bob: { ...validConfig.identities.bob, claims: validConfig.identities.alice.claims },
        },
      },
      'resources.invoices.foreignIdentity',
    ],
    [
      'same UUID tenant claim with different case',
      {
        ...validConfig,
        identities: {
          ...validConfig.identities,
          bob: {
            ...validConfig.identities.bob,
            claims: { org_id: validConfig.identities.alice.claims.org_id.toUpperCase() },
          },
        },
      },
      'resources.invoices.foreignIdentity',
    ],
  ])('rejects invalid %s with an exact path', (_name, input, path) => {
    expect(() => parseConfig(input)).toThrow(ConfigValidationError);
    try {
      parseConfig(input);
    } catch (error) {
      expect(error).toBeInstanceOf(ConfigValidationError);
      expect((error as ConfigValidationError).issues.some((issue) => issue.path === path)).toBe(
        true,
      );
    }
  });

  it('rejects secret-bearing and unknown configuration fields', () => {
    const input = {
      ...validConfig,
      database: { ...validConfig.database, connectionUrl: 'postgres://secret' },
    };
    expect(() => parseConfig(input)).toThrow(/database.connectionUrl/);
  });

  it('reports YAML syntax errors without exposing source text', () => {
    expect(() => parseConfigYaml('database: [')).toThrow(/Invalid YAML/);
  });

  it.each([
    'tenantshield.config.example.yaml',
    'examples/secure/tenantshield.config.yaml',
    'examples/vulnerable/tenantshield.config.yaml',
  ])('keeps shipped configuration %s valid', async (path) => {
    expect(parseConfigYaml(await readFile(resolve(path), 'utf8'))).toBeDefined();
  });
});
