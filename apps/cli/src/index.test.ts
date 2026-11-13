import { readFileSync } from 'node:fs';
import { mkdtemp, readFile, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { CatalogSnapshot } from '@tenantshield/catalog';
import { ConfigValidationError, type TenantShieldConfig } from '@tenantshield/config';
import { createFindingFingerprint, reportSchema, type Finding } from '@tenantshield/findings';
import {
  CliPrerequisiteError,
  createProgram,
  createResourceProgressTracker,
  databasePoolOptions,
  determineTestExitCode,
  dynamicTestResources,
  exitCodeForError,
  formatCliError,
  formatDoctorCheck,
  formatResourceProgress,
  formatVerboseConnection,
  hasMutationCases,
  installPipeErrorHandlers,
  isMainModule,
  normalizeCliError,
  parseSeverity,
  runScanCommand,
  runTestCommand,
  summarizeStaticResources,
  TOOL_VERSION,
  type CliIo,
} from './index.js';
import {
  loadProjectConfig,
  ProjectDiscoveryError,
  readFixtureSql,
  scanWithClient,
} from './commands/project.js';
import { IdentityVerificationError, runDynamicTests, runFixtureSetup } from '@tenantshield/runner';

import type * as projectCommands from './commands/project.js';
import type * as runnerModule from '@tenantshield/runner';

vi.mock('pg', () => {
  class Pool {
    connect() {
      return Promise.resolve({
        query: () => Promise.resolve({ rows: [], rowCount: 0 }),
        release: () => {},
      });
    }
    query() {
      return Promise.resolve({ rows: [], rowCount: 0 });
    }
    end() {
      return Promise.resolve();
    }
  }
  return { Pool };
});

vi.mock('./commands/project.js', async (importOriginal) => ({
  ...(await importOriginal<typeof projectCommands>()),
  loadProjectConfig: vi.fn(),
  scanWithClient: vi.fn(),
  readFixtureSql: vi.fn(),
}));

vi.mock('@tenantshield/runner', async (importOriginal) => ({
  ...(await importOriginal<typeof runnerModule>()),
  runFixtureSetup: vi.fn(),
  runDynamicTests: vi.fn(),
}));

describe('CLI foundation', () => {
  it('exposes a version command', () => {
    const manifest = JSON.parse(
      readFileSync(new URL('../package.json', import.meta.url), 'utf8'),
    ) as { version: string };
    expect(TOOL_VERSION).toBe(manifest.version);
    expect(createProgram().version()).toBe(manifest.version);
  });

  it('formats expected errors consistently', () => {
    expect(
      formatCliError({
        code: 2,
        message: 'Invalid configuration',
        details: ['database.connectionEnv: Required'],
      }),
    ).toBe('error TS002: Invalid configuration\n  database.connectionEnv: Required');
  });

  it('ignores closed output pipes but preserves unexpected stream failures', () => {
    let listener: ((error: NodeJS.ErrnoException) => void) | undefined;
    const stream = {
      on: (_event: string, callback: (error: NodeJS.ErrnoException) => void) => {
        listener = callback;
        return stream;
      },
    } as unknown as NodeJS.WritableStream;
    installPipeErrorHandlers([stream]);
    expect(() => listener?.(Object.assign(new Error('closed'), { code: 'EPIPE' }))).not.toThrow();
    expect(() => listener?.(Object.assign(new Error('disk failed'), { code: 'EIO' }))).toThrow(
      'disk failed',
    );
  });

  it('preserves structured configuration issue paths in CLI diagnostics', () => {
    expect(
      normalizeCliError(
        new ConfigValidationError([
          { path: 'resources.invoices.ownerIdentity', message: 'Unknown identity' },
        ]),
      ),
    ).toEqual({
      code: 2,
      message: 'Invalid configuration',
      details: ['resources.invoices.ownerIdentity: Unknown identity'],
    });
  });

  it('registers the complete MVP command surface', () => {
    expect(createProgram().commands.map((command) => command.name())).toEqual([
      'init',
      'doctor',
      'scan',
      'test',
      'report',
    ]);
  });

  it('includes views in static scan resource summaries', () => {
    expect(
      summarizeStaticResources({
        tables: [{ schema: 'public', name: 'invoices' }],
        views: [{ schema: 'public', name: 'invoice_export' }],
        functions: [{ schema: 'public', name: 'danger', identityArguments: 'invoice_id uuid' }],
      }),
    ).toEqual(['public.danger(invoice_id uuid)', 'public.invoice_export', 'public.invoices']);
  });

  it('warns about external side effects only when mutation cases are configured', () => {
    const resource: TenantShieldConfig['resources'][string] = {
      primaryKey: 'id',
      tenantColumn: 'org_id',
      ownerIdentity: 'alice',
      foreignIdentity: 'bob',
      testOperations: ['select'],
    };
    expect(hasMutationCases({ invoices: resource })).toBe(false);
    expect(
      hasMutationCases({ invoices: { ...resource, testOperations: ['select', 'update'] } }),
    ).toBe(true);
    expect(hasMutationCases({ invoices: { ...resource, public: true } })).toBe(false);
  });

  it('recognizes npm bin symlinks as the main module', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'tenantshield-bin-'));
    const target = join(directory, 'index.js');
    const bin = join(directory, 'tenantshield');
    await writeFile(target, '');
    await symlink(target, bin);
    expect(isMainModule(pathToFileURL(target).href, bin)).toBe(true);
  });

  it('validates severity before command work begins', () => {
    expect(parseSeverity('medium')).toBe('medium');
    expect(() => parseSeverity('urgent')).toThrow(CliPrerequisiteError);
  });

  it('bounds database connection establishment for scan and test commands', () => {
    expect(databasePoolOptions('postgresql://localhost/postgres')).toMatchObject({
      connectionString: 'postgresql://localhost/postgres',
      max: 1,
      connectionTimeoutMillis: 5_000,
    });
  });

  it('uses setup-failure exit code for incomplete dynamic results', () => {
    expect(determineTestExitCode([], 'high', false)).toBe(3);
    expect(determineTestExitCode([], 'high', true)).toBe(0);
  });

  it('maps missing prerequisites to exit code 2', () => {
    expect(exitCodeForError(new CliPrerequisiteError('missing env'))).toBe(2);
    expect(exitCodeForError(new ProjectDiscoveryError('missing project'))).toBe(2);
  });

  it('maps PostgreSQL setup errors to exit code 3', () => {
    expect(exitCodeForError(Object.assign(new Error('permission denied'), { code: '42501' }))).toBe(
      3,
    );
    expect(exitCodeForError(new IdentityVerificationError('role mismatch'))).toBe(3);
  });

  it('maps DNS and network connection errors to exit code 3', () => {
    expect(
      exitCodeForError(Object.assign(new Error('getaddrinfo failed'), { code: 'ENOTFOUND' })),
    ).toBe(3);
  });

  it.each([
    'EACCES',
    'EPERM',
    'ENOENT',
    'ENOTDIR',
    'EISDIR',
    'EROFS',
    'ENOSPC',
    'EEXIST',
    'ELOOP',
    'EMFILE',
    'ENFILE',
    'ENAMETOOLONG',
    'EDQUOT',
    'EFBIG',
  ])('maps filesystem prerequisite error %s to exit code 2', (code) => {
    expect(exitCodeForError(Object.assign(new Error('filesystem failure'), { code }))).toBe(2);
  });

  it.each(['ECONNABORTED', 'EADDRNOTAVAIL', 'ERR_SOCKET_CLOSED'])(
    'maps database transport error %s to exit code 3',
    (code) => {
      expect(exitCodeForError(Object.assign(new Error('transport failure'), { code }))).toBe(3);
    },
  );

  it('maps an invalid saved report to exit code 2', () => {
    let validationError: unknown;
    try {
      reportSchema.parse({});
    } catch (error) {
      validationError = error;
    }
    expect(exitCodeForError(validationError)).toBe(2);
  });

  it('redacts and sanitizes doctor diagnostics', () => {
    const output = formatDoctorCheck({
      name: 'Database\u001b[31m',
      ok: false,
      detail: 'postgres://alice:secret@localhost/db\nforged',
    });
    expect(output).not.toContain('secret');
    expect(output).not.toContain('\u001b');
    expect(output).not.toContain('\nforged');
    expect(output).toContain('[REDACTED]');
  });
});

describe('scan and test output flags', () => {
  const CONNECTION_ENV = 'TENANTSHIELD_FIXTURE_DATABASE_URL';
  const CONNECTION_URL = 'postgresql://postgres:secret@127.0.0.1:54322/postgres';

  const fixtureConfig = {
    version: 1,
    database: { connectionEnv: CONNECTION_ENV, allowedHosts: ['localhost'] },
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
        testOperations: ['select'],
      },
      orders: {
        primaryKey: 'id',
        tenantColumn: 'org_id',
        ownerIdentity: 'alice',
        foreignIdentity: 'bob',
        testOperations: ['select'],
      },
    },
  } as unknown as TenantShieldConfig;

  const fixtureSnapshot = {
    version: 1,
    database: { serverVersion: '15.1' },
    tables: [{ schema: 'public', name: 'invoices', columns: [], primaryKey: [] }],
    views: [],
    functions: [],
  } as unknown as CatalogSnapshot;

  function createFakeIo() {
    const stdout: string[] = [];
    const stderr: string[] = [];
    const record =
      (sink: string[]) =>
      (chunk: string | Uint8Array): boolean => {
        sink.push(String(chunk));
        return true;
      };
    const io: CliIo = {
      stdout: { write: record(stdout) } as unknown as NodeJS.WritableStream,
      stderr: { write: record(stderr) } as unknown as NodeJS.WritableStream,
    };
    return { io, stdout: () => stdout.join(''), stderr: () => stderr.join('') };
  }

  function fingerprinted(input: Omit<Finding, 'fingerprint'>): Finding {
    return { ...input, fingerprint: createFindingFingerprint(input) };
  }

  beforeEach(() => {
    vi.clearAllMocks();
    process.env[CONNECTION_ENV] = CONNECTION_URL;
    process.exitCode = 0;
    vi.mocked(loadProjectConfig).mockResolvedValue({
      config: fixtureConfig,
      path: '/fixtures/tenantshield.config.yaml',
      exposedSchemas: ['public'],
      migrationsDirectory: '/fixtures/migrations',
      projectRef: 'fixture',
    });
    vi.mocked(scanWithClient).mockResolvedValue({
      snapshot: fixtureSnapshot,
      findings: [],
      summary: '0 findings across 2 resources',
    });
    vi.mocked(readFixtureSql).mockResolvedValue('select 1;');
    vi.mocked(runFixtureSetup).mockResolvedValue();
    vi.mocked(runDynamicTests).mockResolvedValue({
      cases: [],
      findings: [],
      warnings: [],
      complete: true,
    });
  });

  afterEach(() => {
    delete process.env[CONNECTION_ENV];
    process.exitCode = 0;
  });

  it('registers --json and --verbose on scan and test', () => {
    for (const name of ['scan', 'test']) {
      const command = createProgram().commands.find((entry) => entry.name() === name);
      const flags = command?.options.map((option) => option.long);
      expect(flags).toContain('--json');
      expect(flags).toContain('--verbose');
    }
  });

  it('prints parseable report JSON for scan --json and keeps --output behavior', async () => {
    const output = join(await mkdtemp(join(tmpdir(), 'tenantshield-json-')), 'report.json');
    const fake = createFakeIo();
    await runScanCommand({ failOn: 'high', json: true, output }, fake.io);
    const stdout = fake.stdout();
    const report = reportSchema.parse(JSON.parse(stdout));
    expect(report.version).toBe(1);
    expect(report.execution.mode).toBe('scan');
    expect(report.metadata.target.database).toBe('postgres');
    expect(stdout).not.toContain('secret');
    expect(JSON.parse(await readFile(output, 'utf8'))).toHaveProperty('execution.mode', 'scan');
  });

  it('prints parseable report JSON for test --json and moves the report path line to stderr', async () => {
    const output = join(await mkdtemp(join(tmpdir(), 'tenantshield-json-')), 'report.json');
    const fake = createFakeIo();
    await runTestCommand({ failOn: 'high', json: true, format: 'markdown', output }, fake.io);
    const stdout = fake.stdout();
    const report = reportSchema.parse(JSON.parse(stdout));
    expect(report.execution.mode).toBe('test');
    expect(stdout).not.toContain('Report:');
    expect(fake.stderr()).toContain(`Report: ${resolve(output)}`);
    expect(JSON.parse(await readFile(output, 'utf8'))).toHaveProperty('execution.mode', 'test');
  });

  it('rejects an invalid baseline before running fixtures or overwriting the report', async () => {
    const output = join(await mkdtemp(join(tmpdir(), 'tenantshield-baseline-')), 'report.json');
    await writeFile(output, '{}');
    const fake = createFakeIo();
    await expect(
      runTestCommand({ failOn: 'high', format: 'markdown', output, baseline: output }, fake.io),
    ).rejects.toThrow('Baseline report is not a valid TenantShield JSON report');
    expect(await readFile(output, 'utf8')).toBe('{}');
    expect(fake.stdout()).toBe('');
    expect(runFixtureSetup).not.toHaveBeenCalled();
  });

  it('writes verbose scan diagnostics to stderr with credentials redacted', async () => {
    const fake = createFakeIo();
    await runScanCommand({ failOn: 'high', verbose: true }, fake.io);
    const stderr = fake.stderr();
    expect(stderr).toContain(formatVerboseConnection(CONNECTION_URL));
    expect(stderr).toContain('postgres://[REDACTED]');
    expect(stderr).not.toContain('secret');
    expect(stderr).toContain('Target: 127.0.0.1:54322/postgres (local)');
    expect(stderr).toContain(
      'Config: /fixtures/tenantshield.config.yaml (version 1, 2 identities, 2 resources)',
    );
    expect(stderr).toMatch(/Timing: load config \d+ms/);
    expect(stderr).toMatch(/Timing: target inspection \d+ms/);
    expect(stderr).toMatch(/Timing: catalog capture \d+ms/);
  });

  it('writes per-step timing diagnostics for test --verbose', async () => {
    const output = join(await mkdtemp(join(tmpdir(), 'tenantshield-verbose-')), 'report.json');
    const fake = createFakeIo();
    await runTestCommand({ failOn: 'high', output, verbose: true }, fake.io);
    const stderr = fake.stderr();
    expect(stderr).toMatch(/Timing: static scan \d+ms/);
    expect(stderr).toMatch(/Timing: fixture setup \d+ms/);
    expect(stderr).toMatch(/Timing: dynamic tests \d+ms/);
  });

  it('emits per-resource progress lines to stderr without polluting stdout', async () => {
    vi.mocked(runDynamicTests).mockImplementation(async (client) => {
      await client.query('/* tenantshield_select */ SELECT 1 FROM "public"."invoices"');
      await client.query('/* tenantshield_select */ SELECT 1 FROM "public"."orders"');
      return { cases: [], findings: [], warnings: [], complete: true };
    });
    const output = join(await mkdtemp(join(tmpdir(), 'tenantshield-progress-')), 'report.json');
    const fake = createFakeIo();
    await runTestCommand({ failOn: 'high', output }, fake.io);
    expect(fake.stderr()).toContain('1/2 resources tested');
    expect(fake.stderr()).toContain('2/2 resources tested');
    expect(fake.stdout()).not.toContain('resources tested');
  });

  it('tracks resource completion from qualified dynamic SQL table names', async () => {
    const completions: string[] = [];
    const tracker = createResourceProgressTracker(
      {
        query: () => Promise.resolve({ rows: [], rowCount: 0 }),
      },
      dynamicTestResources(fixtureConfig),
      (completed, total) => completions.push(formatResourceProgress(completed, total)),
    );
    await tracker.client.query('SELECT 1 FROM "public"."invoices"');
    await tracker.client.query('SELECT 1 FROM "public"."orders"');
    tracker.finish();
    expect(completions).toEqual(['1/2 resources tested', '2/2 resources tested']);
  });

  it('keeps default scan terminal output with progress only on stderr', async () => {
    const fake = createFakeIo();
    await runScanCommand({ failOn: 'high' }, fake.io);
    expect(fake.stdout().startsWith('{')).toBe(false);
    expect(fake.stdout()).not.toContain('"version": 1');
    expect(fake.stderr()).toContain('Capturing catalog snapshot...');
    expect(fake.stderr()).toContain('Catalog snapshot complete (1 resource)');
    expect(process.exitCode).toBe(0);
  });

  it('keeps default test terminal output, report file, and header lines', async () => {
    const output = join(await mkdtemp(join(tmpdir(), 'tenantshield-default-')), 'report.json');
    const fake = createFakeIo();
    await runTestCommand({ failOn: 'high', output }, fake.io);
    const stdout = fake.stdout();
    expect(stdout).toContain('Target: 127.0.0.1:54322/postgres');
    expect(stdout).toContain('Supabase project: fixture');
    expect(stdout).toContain(`Report: ${resolve(output)}`);
    expect(stdout).not.toContain('resources tested');
    expect(JSON.parse(await readFile(output, 'utf8'))).toHaveProperty('execution.mode', 'test');
    expect(process.exitCode).toBe(0);
  });

  it('preserves the finding threshold exit code in --json mode', async () => {
    const finding = fingerprinted({
      ruleId: 'TS-RLS-001',
      title: 'Exposed table without RLS',
      severity: 'critical',
      confidence: 'high',
      source: 'static',
      schema: 'public',
      table: 'invoices',
      expected: 'RLS enabled',
      observed: 'RLS disabled',
      reproduction: { command: 'tenantshield scan', details: 'public.invoices' },
      remediation: 'Enable RLS.',
      documentationUrl: 'https://example.invalid/rules/TS-RLS-001',
    });
    vi.mocked(scanWithClient).mockResolvedValue({
      snapshot: fixtureSnapshot,
      findings: [finding],
      summary: '1 finding across 1 resource',
    });
    const fake = createFakeIo();
    await runScanCommand({ failOn: 'high', json: true }, fake.io);
    expect(process.exitCode).toBe(1);
    const report = reportSchema.parse(JSON.parse(fake.stdout()));
    expect(report.findings).toHaveLength(1);
  });
});
