import { mkdtemp, mkdir, readFile, symlink, unlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import {
  discoverSupabaseProject,
  initializeProject,
  loadProjectConfig,
  ProjectDiscoveryError,
  readFixtureSql,
  runDoctor,
  scanWithClient,
} from './project.js';
import type { SqlClient } from '@tenantshield/catalog';
import { parseConfigYaml, type TenantShieldConfig } from '@tenantshield/config';

describe('project commands', () => {
  it('discovers Supabase config and exact tenant-column candidates', async () => {
    const root = await mkdtemp(join(tmpdir(), 'tenantshield-'));
    await mkdir(join(root, 'supabase', 'migrations'), { recursive: true });
    await writeFile(
      join(root, 'supabase', 'config.toml'),
      `project_id = "fixture"
[api]
schemas = [
  "public",
  "tenant_api", # application API
]
`,
    );
    await writeFile(
      join(root, 'supabase', 'migrations', '001.sql'),
      'create table public.invoices (id uuid primary key, org_id uuid not null, organization text);',
    );
    const result = await discoverSupabaseProject(join(root, 'nested'));
    expect(result.root).toBe(root);
    expect(result.projectRef).toBe('fixture');
    expect(result.exposedSchemas).toEqual(['public', 'tenant_api']);
    expect(result.candidates).toContainEqual({
      schema: 'public',
      table: 'invoices',
      tenantColumn: 'org_id',
    });
  });

  it('rejects malformed Supabase TOML instead of silently scanning the wrong schemas', async () => {
    const root = await mkdtemp(join(tmpdir(), 'tenantshield-'));
    await mkdir(join(root, 'supabase'), { recursive: true });
    await writeFile(join(root, 'supabase', 'config.toml'), '[api\nschemas = ["public"]');

    await expect(discoverSupabaseProject(root)).rejects.toEqual(
      new ProjectDiscoveryError('Invalid supabase/config.toml'),
    );
  });

  it('rejects invalid Data API schema configuration', async () => {
    const root = await mkdtemp(join(tmpdir(), 'tenantshield-'));
    await mkdir(join(root, 'supabase'), { recursive: true });
    await writeFile(join(root, 'supabase', 'config.toml'), '[api]\nschemas = ["public", ""]');

    await expect(discoverSupabaseProject(root)).rejects.toEqual(
      new ProjectDiscoveryError('Invalid api.schemas in supabase/config.toml'),
    );
  });

  it('folds unquoted SQL identifiers to PostgreSQL lowercase', async () => {
    const root = await mkdtemp(join(tmpdir(), 'tenantshield-'));
    await mkdir(join(root, 'supabase', 'migrations'), { recursive: true });
    await writeFile(join(root, 'supabase', 'config.toml'), 'project_id = "fixture"');
    await writeFile(
      join(root, 'supabase', 'migrations', '001.sql'),
      'create table Analytics.Invoices (ID uuid primary key, ORG_ID uuid not null);',
    );
    expect((await discoverSupabaseProject(root)).candidates).toContainEqual({
      schema: 'analytics',
      table: 'invoices',
      tenantColumn: 'org_id',
    });
  });

  it('does not misidentify a case-sensitive quoted tenant column', async () => {
    const root = await mkdtemp(join(tmpdir(), 'tenantshield-'));
    await mkdir(join(root, 'supabase', 'migrations'), { recursive: true });
    await writeFile(join(root, 'supabase', 'config.toml'), 'project_id = "fixture"');
    await writeFile(
      join(root, 'supabase', 'migrations', '001.sql'),
      'create table public.secrets (id uuid primary key, "ORG_ID" uuid not null);',
    );
    expect((await discoverSupabaseProject(root)).candidates).toEqual([]);
  });

  it('initializes without overwriting an existing config', async () => {
    const root = await mkdtemp(join(tmpdir(), 'tenantshield-'));
    await mkdir(join(root, 'supabase'), { recursive: true });
    await writeFile(join(root, 'supabase', 'config.toml'), 'project_id = "fixture"');
    const created = await initializeProject(root);
    expect(created.created).toBe(true);
    expect(await readFile(created.path, 'utf8')).toMatch(
      /connectionEnv: TENANTSHIELD_DATABASE_URL/,
    );
    expect(parseConfigYaml(await readFile(created.path, 'utf8'))).toBeDefined();
    const fixturePath = join(root, 'tenantshield', 'fixtures.sql');
    expect(await readFile(fixturePath, 'utf8')).toMatch(/deterministic fixture/i);
    await writeFile(created.path, 'sentinel');
    await writeFile(fixturePath, 'fixture sentinel');
    expect((await initializeProject(root)).created).toBe(false);
    expect(await readFile(created.path, 'utf8')).toBe('sentinel');
    expect(await readFile(fixturePath, 'utf8')).toBe('fixture sentinel');
  });

  it('reports doctor dependency failures without throwing', async () => {
    const execute = vi.fn((command: string) => {
      if (command === 'docker') return Promise.resolve({ ok: true, output: 'Docker 29' });
      return Promise.resolve({ ok: false, output: 'not found' });
    });
    const checks = await runDoctor({ cwd: '/missing', nodeVersion: 'v20.0.0', execute });
    expect(checks).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'Node.js 22+', ok: false }),
        expect.objectContaining({ name: 'Supabase CLI', ok: false }),
        expect.objectContaining({ name: 'Docker', ok: true }),
      ]),
    );
  });

  it('keeps project discovery successful when only TenantShield config is invalid', async () => {
    const root = await mkdtemp(join(tmpdir(), 'tenantshield-'));
    await mkdir(join(root, 'supabase'), { recursive: true });
    await writeFile(join(root, 'supabase', 'config.toml'), 'project_id = "fixture"');
    await writeFile(join(root, 'tenantshield.config.yaml'), 'version: 99');
    const execute = () => Promise.resolve({ ok: true, output: 'ok' });
    const checks = await runDoctor({ cwd: root, nodeVersion: 'v22.0.0', execute });
    expect(checks).toContainEqual(expect.objectContaining({ name: 'Supabase project', ok: true }));
    expect(checks).toContainEqual(expect.objectContaining({ name: 'Migrations', ok: false }));
    expect(checks).toContainEqual(
      expect.objectContaining({ name: 'TenantShield config', ok: false }),
    );
  });

  it('checks Docker daemon readiness and rejects comment-only fixture SQL', async () => {
    const root = await mkdtemp(join(tmpdir(), 'tenantshield-'));
    await mkdir(join(root, 'supabase', 'migrations'), { recursive: true });
    await writeFile(join(root, 'supabase', 'config.toml'), 'project_id = "fixture"');
    await writeFile(
      join(root, 'supabase', 'migrations', '001.sql'),
      'create table public.invoices (id uuid primary key, org_id uuid not null);',
    );
    await initializeProject(root);
    const execute = vi.fn(() => Promise.resolve({ ok: true, output: 'ok' }));
    const checks = await runDoctor({ cwd: root, nodeVersion: 'v22.0.0', execute });
    expect(execute).toHaveBeenCalledWith('docker', ['info', '--format', '{{.ServerVersion}}']);
    expect(checks).toContainEqual(expect.objectContaining({ name: 'Fixture SQL', ok: false }));
  });

  it('rejects transaction-control fixture SQL during doctor preflight', async () => {
    const root = await mkdtemp(join(tmpdir(), 'tenantshield-'));
    await mkdir(join(root, 'supabase', 'migrations'), { recursive: true });
    await writeFile(join(root, 'supabase', 'config.toml'), 'project_id = "fixture"');
    await writeFile(
      join(root, 'supabase', 'migrations', '001.sql'),
      'create table public.invoices (id uuid primary key, org_id uuid not null);',
    );
    await initializeProject(root);
    await writeFile(join(root, 'tenantshield', 'fixtures.sql'), 'COMMIT; SELECT 1;');
    const execute = vi.fn(() => Promise.resolve({ ok: true, output: 'ok' }));

    const checks = await runDoctor({ cwd: root, nodeVersion: 'v22.0.0', execute });

    const fixtureCheck = checks.find((check) => check.name === 'Fixture SQL');
    expect(fixtureCheck).toMatchObject({ name: 'Fixture SQL', ok: false });
    expect(fixtureCheck?.detail).toMatch(/transaction-control/i);
  });

  it('rejects fixture symlinks that escape the project', async () => {
    const root = await mkdtemp(join(tmpdir(), 'tenantshield-'));
    const externalRoot = await mkdtemp(join(tmpdir(), 'tenantshield-external-'));
    await mkdir(join(root, 'supabase', 'migrations'), { recursive: true });
    await writeFile(join(root, 'supabase', 'config.toml'), 'project_id = "fixture"');
    await writeFile(join(root, 'supabase', 'migrations', '001.sql'), 'select 1;');
    await initializeProject(root);
    const fixturePath = join(root, 'tenantshield', 'fixtures.sql');
    const externalPath = join(externalRoot, 'secrets.sql');
    await writeFile(externalPath, 'select 1;');
    await unlink(fixturePath);
    await symlink(externalPath, fixturePath);

    await expect(readFixtureSql(root, 'tenantshield/fixtures.sql')).rejects.toBeInstanceOf(
      ProjectDiscoveryError,
    );
    const execute = vi.fn(() => Promise.resolve({ ok: true, output: 'ok' }));
    const checks = await runDoctor({ cwd: root, nodeVersion: 'v22.0.0', execute });
    expect(checks).toContainEqual(expect.objectContaining({ name: 'Fixture SQL', ok: false }));
  });

  it('classifies a missing TenantShield config as project discovery failure', async () => {
    const root = await mkdtemp(join(tmpdir(), 'tenantshield-'));
    await mkdir(join(root, 'supabase'), { recursive: true });
    await writeFile(join(root, 'supabase', 'config.toml'), 'project_id = "fixture"');
    await expect(loadProjectConfig(root)).rejects.toBeInstanceOf(ProjectDiscoveryError);
  });

  it('loads and diagnoses a plain PostgreSQL project without Supabase files', async () => {
    const root = await mkdtemp(join(tmpdir(), 'tenantshield-plain-'));
    await mkdir(join(root, 'db', 'migrations'), { recursive: true });
    await writeFile(
      join(root, 'db', 'migrations', '001.sql'),
      'CREATE TABLE public.items (id uuid);',
    );
    await writeFile(
      join(root, 'tenantshield.config.yaml'),
      `version: 1\ndatabase:\n  connectionEnv: DATABASE_URL\n  allowedHosts: [localhost]\n  exposedSchemas: [public, app]\nmigrationsDir: db/migrations\nfixtures:\n  mode: auto\nidentities:\n  alice:\n    role: authenticated\n    userId: 11111111-1111-1111-1111-111111111111\n    claims: {}\n  bob:\n    role: authenticated\n    userId: 22222222-2222-2222-2222-222222222222\n    claims: {}\nresources:\n  items:\n    primaryKey: id\n    tenantColumn: org_id\n    ownerIdentity: alice\n    foreignIdentity: bob\n    ownerTenantValue: org-a\n    foreignTenantValue: org-b\n    testOperations: [select]\n`,
    );
    const loaded = await loadProjectConfig(root, 'tenantshield.config.yaml');
    expect(loaded.exposedSchemas).toEqual(['public', 'app']);
    const checks = await runDoctor({ cwd: root, nodeVersion: 'v22.0.0' });
    expect(checks).toContainEqual(
      expect.objectContaining({ name: 'TenantShield config', ok: true }),
    );
    expect(checks).toContainEqual(expect.objectContaining({ name: 'Fixture SQL', ok: true }));
  });

  it('runs a static scan through an injected read-only catalog client', async () => {
    const config: TenantShieldConfig = {
      version: 1,
      database: { connectionEnv: 'DATABASE_URL', allowedHosts: ['localhost'] },
      fixtures: { setupSql: 'fixtures.sql' },
      identities: {
        alice: {
          role: 'authenticated',
          userId: '11111111-1111-1111-1111-111111111111',
          claims: {},
        },
        bob: { role: 'authenticated', userId: '22222222-2222-2222-2222-222222222222', claims: {} },
      },
      resources: {
        invoices: {
          schema: 'tenant_data',
          primaryKey: 'id',
          tenantColumn: 'org_id',
          ownerIdentity: 'alice',
          foreignIdentity: 'bob',
          membership: {
            schema: 'tenant_membership',
            table: 'organization_members',
            tenantColumn: 'org_id',
            userColumn: 'user_id',
          },
          testOperations: ['select'],
        },
      },
    };
    const client: SqlClient = {
      query: vi.fn((sql: string) => {
        if (sql.includes('current_database()'))
          return Promise.resolve({
            rows: [
              {
                database_name: 'postgres',
                server_version: '16',
                current_role: 'scanner',
                is_superuser: false,
                can_bypass_rls: false,
              },
            ],
          });
        if (sql.includes("c.relkind IN ('r', 'p', 'f')"))
          return Promise.resolve({
            rows: [
              {
                schema_name: 'tenant_data',
                table_name: 'invoices',
                rls_enabled: false,
                rls_forced: false,
              },
            ],
          });
        if (sql.includes('has_table_privilege'))
          return Promise.resolve({
            rows: [
              {
                schema_name: 'tenant_data',
                table_name: 'invoices',
                grantee: 'authenticated',
                privilege_type: 'SELECT',
              },
            ],
          });
        return Promise.resolve({ rows: [] });
      }),
    };
    const result = await scanWithClient(client, config, ['public', 'tenant_api'], true);
    expect(result.snapshot.schemas).toEqual([
      'public',
      'tenant_api',
      'tenant_data',
      'tenant_membership',
    ]);
    expect(result.findings.map((finding) => finding.ruleId)).toEqual(['TS-RLS-001']);
    expect(result.summary).toMatch(/1 finding/);
  });
});
