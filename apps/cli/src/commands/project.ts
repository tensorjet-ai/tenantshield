import { execFile } from 'node:child_process';
import { access, mkdir, readFile, readdir, realpath, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path';
import { promisify } from 'node:util';
import { parse as parseToml } from 'smol-toml';
import { captureCatalogSnapshot, type SqlClient } from '@tenantshield/catalog';
import { parseConfigYaml, type TenantShieldConfig } from '@tenantshield/config';
import { runStaticRules } from '@tenantshield/rules';
import { validateFixtureSetupSql } from '@tenantshield/runner';
import type { Finding } from '@tenantshield/findings';

const execFileAsync = promisify(execFile);
const TENANT_COLUMN_NAMES = new Set([
  'org_id',
  'organization_id',
  'tenant_id',
  'account_id',
  'workspace_id',
]);

export interface TenantColumnCandidate {
  schema: string;
  table: string;
  tenantColumn: string;
}

export interface DiscoveredProject {
  root: string;
  configToml: string;
  projectRef?: string;
  exposedSchemas: string[];
  migrationsDirectory: string;
  candidates: TenantColumnCandidate[];
}

export class ProjectDiscoveryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProjectDiscoveryError';
  }
}

export async function readFixtureSql(projectRoot: string, setupSql: string): Promise<string> {
  const canonicalRoot = await realpath(projectRoot);
  const fixturePath = resolve(canonicalRoot, setupSql);
  const canonicalFixture = await realpath(fixturePath);
  const relativePath = relative(canonicalRoot, canonicalFixture);
  if (relativePath === '..' || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) {
    throw new ProjectDiscoveryError('Fixture SQL must remain inside the Supabase project');
  }
  return readFile(canonicalFixture, 'utf8');
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function migrationFiles(directory: string): Promise<string[]> {
  if (!(await exists(directory))) return [];
  const entries = await readdir(directory, { withFileTypes: true });
  return entries
    .filter((entry) => entry.isFile() && entry.name.endsWith('.sql'))
    .map((entry) => join(directory, entry.name))
    .sort();
}

export async function mapFindingsToMigrationLocations(
  root: string,
  migrationsDirectory: string,
  findings: readonly Finding[],
): Promise<Finding[]> {
  const files = await migrationFiles(resolve(root, migrationsDirectory));
  const locations = new Map<string, { file: string; startLine: number }>();
  for (const file of files) {
    const source = await readFile(file, 'utf8');
    const lines = source.split(/\r?\n/);
    lines.forEach((line, index) => {
      const match = line.match(
        /\bcreate\s+(?:or\s+replace\s+)?(?:(materialized)\s+)?(table|view|function|policy)\s+(?:if\s+not\s+exists\s+)?(?:(?:"?([A-Za-z_][\w$]*)"?)\s*\.\s*)?"?([A-Za-z_][\w$]*)"?/i,
      );
      if (!match) return;
      const kind = match[2]!.toLowerCase();
      const schema = match[3] ?? 'public';
      const name = match[4]!;
      const location = { file: relative(root, file).split(sep).join('/'), startLine: index + 1 };
      locations.set(`${kind}:${schema}.${name}`, location);
      locations.set(`${kind}:*.${name}`, location);
    });
  }
  return findings.map((finding) => {
    const kind = finding.function ? 'function' : finding.policy ? 'policy' : 'table';
    const objectName = finding.function?.split('(')[0] ?? finding.policy ?? finding.table;
    if (!objectName) return finding;
    const location =
      locations.get(`${kind}:${finding.schema ?? 'public'}.${objectName}`) ??
      locations.get(`${kind}:*.${objectName}`);
    return location ? { ...finding, location } : finding;
  });
}

function candidatesFromSql(sql: string): TenantColumnCandidate[] {
  const candidates: TenantColumnCandidate[] = [];
  const tablePattern =
    /create\s+table\s+(?:if\s+not\s+exists\s+)?(?:(?:"([A-Za-z_][\w$]*)"|([A-Za-z_][\w$]*))\.)?(?:"([A-Za-z_][\w$]*)"|([A-Za-z_][\w$]*))\s*\(([\s\S]*?)\)\s*;/gi;
  for (const match of sql.matchAll(tablePattern)) {
    const schema = match[1] ?? match[2]?.toLowerCase() ?? 'public';
    const table = match[3] ?? match[4]?.toLowerCase();
    const body = match[5];
    if (!table || !body) continue;
    for (const column of TENANT_COLUMN_NAMES) {
      const quoted = new RegExp(`(?:^|,)\\s*"${column}"\\s+`, 'm').test(body);
      const unquoted = new RegExp(`(?:^|,)\\s*${column}\\s+`, 'im').test(body);
      if (quoted || unquoted) {
        candidates.push({ schema, table, tenantColumn: column });
      }
    }
  }
  return candidates;
}

function objectRecord(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function projectSettingsFromToml(source: string): {
  projectRef?: string;
  exposedSchemas: string[];
} {
  let parsed: unknown;
  try {
    parsed = parseToml(source);
  } catch {
    throw new ProjectDiscoveryError('Invalid supabase/config.toml');
  }
  const root = objectRecord(parsed);
  if (!root) throw new ProjectDiscoveryError('Invalid supabase/config.toml');
  const projectRef =
    typeof root['project_id'] === 'string' && root['project_id'].trim()
      ? root['project_id'].trim()
      : undefined;
  const api = objectRecord(root['api']);
  const configuredSchemas = api?.['schemas'];
  if (
    configuredSchemas !== undefined &&
    (!Array.isArray(configuredSchemas) ||
      configuredSchemas.some((schema) => typeof schema !== 'string' || !schema.trim()))
  ) {
    throw new ProjectDiscoveryError('Invalid api.schemas in supabase/config.toml');
  }
  const additional = (configuredSchemas ?? []) as string[];
  const exposedSchemas = [
    'public',
    ...new Set(additional.map((schema) => schema.trim()).filter((schema) => schema !== 'public')),
  ];
  return { ...(projectRef ? { projectRef } : {}), exposedSchemas };
}

export async function discoverSupabaseProject(cwd: string): Promise<DiscoveredProject> {
  const configToml = await findSupabaseConfig(cwd);
  if (!configToml)
    throw new ProjectDiscoveryError(
      'No supabase/config.toml found in this directory or its parents',
    );
  const root = dirname(dirname(configToml));
  const migrationsDirectory = join(root, 'supabase', 'migrations');
  const settings = projectSettingsFromToml(await readFile(configToml, 'utf8'));
  const candidates: TenantColumnCandidate[] = [];
  for (const file of await migrationFiles(migrationsDirectory)) {
    candidates.push(...candidatesFromSql(await readFile(file, 'utf8')));
  }
  return { root, configToml, ...settings, migrationsDirectory, candidates };
}

async function findSupabaseConfig(cwd: string): Promise<string | undefined> {
  let current = resolve(cwd);
  const filesystemRoot = parse(current).root;
  while (true) {
    const configToml = join(current, 'supabase', 'config.toml');
    if (await exists(configToml)) return configToml;
    if (current === filesystemRoot) return undefined;
    current = dirname(current);
  }
}

function starterConfig(candidate?: TenantColumnCandidate): string {
  const schemaLine =
    candidate && candidate.schema !== 'public' ? `    schema: ${candidate.schema}\n` : '';
  const resource = candidate?.table ?? 'invoices';
  const tenantColumn = candidate?.tenantColumn ?? 'org_id';
  return `version: 1
database:
  connectionEnv: TENANTSHIELD_DATABASE_URL
  allowedHosts: [localhost, 127.0.0.1]
fixtures:
  setupSql: tenantshield/fixtures.sql
identities:
  alice:
    role: authenticated
    userId: 11111111-1111-1111-1111-111111111111
    claims:
      ${tenantColumn}: aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa
  bob:
    role: authenticated
    userId: 22222222-2222-2222-2222-222222222222
    claims:
      ${tenantColumn}: bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb
resources:
  ${resource}:
${schemaLine}    primaryKey: id
    tenantColumn: ${tenantColumn}
    ownerIdentity: alice
    foreignIdentity: bob
    testOperations: [select, insert, update, delete]
`;
}

export async function initializeProject(
  cwd: string,
): Promise<{ path: string; created: boolean; candidates: TenantColumnCandidate[] }> {
  const project = await discoverSupabaseProject(cwd);
  const path = join(project.root, 'tenantshield.config.yaml');
  if (await exists(path)) return { path, created: false, candidates: project.candidates };
  const fixtureDirectory = join(project.root, 'tenantshield');
  await mkdir(fixtureDirectory, { recursive: true });
  await writeFile(
    join(fixtureDirectory, 'fixtures.sql'),
    '-- Add deterministic fixture setup SQL here. TenantShield runs this only against a disposable local database.\n',
    { encoding: 'utf8', flag: 'wx' },
  ).catch((error: unknown) => {
    if (!(error instanceof Error && 'code' in error && error.code === 'EEXIST')) throw error;
  });
  await writeFile(path, starterConfig(project.candidates[0]), { encoding: 'utf8', flag: 'wx' });
  return { path, created: true, candidates: project.candidates };
}

export interface DoctorCheck {
  name: string;
  ok: boolean;
  detail: string;
}

export interface DoctorOptions {
  cwd: string;
  configPath?: string;
  nodeVersion?: string;
  execute?: (command: string, args: readonly string[]) => Promise<{ ok: boolean; output: string }>;
  connectionProbe?: (config: TenantShieldConfig) => Promise<void>;
}

async function defaultExecute(
  command: string,
  args: readonly string[],
): Promise<{ ok: boolean; output: string }> {
  try {
    const result = await execFileAsync(command, [...args], { timeout: 5_000 });
    return { ok: true, output: result.stdout.trim() || result.stderr.trim() };
  } catch {
    return { ok: false, output: 'not found or unavailable' };
  }
}

export async function runDoctor(options: DoctorOptions): Promise<DoctorCheck[]> {
  const execute = options.execute ?? defaultExecute;
  const nodeVersion = options.nodeVersion ?? process.version;
  const nodeMajor = Number(nodeVersion.replace(/^v/, '').split('.')[0]);
  const checks: DoctorCheck[] = [{ name: 'Node.js 22+', ok: nodeMajor >= 22, detail: nodeVersion }];
  const explicitPath = options.configPath ? resolve(options.cwd, options.configPath) : undefined;
  const configToml =
    (explicitPath && (await findSupabaseConfig(dirname(explicitPath)))) ||
    (await findSupabaseConfig(options.cwd));
  const localConfigPath = resolve(options.cwd, 'tenantshield.config.yaml');
  if (configToml || (!explicitPath && !(await exists(localConfigPath)))) {
    for (const [name, command, args] of [
      ['Supabase CLI', 'supabase', ['--version']],
      ['Docker', 'docker', ['info', '--format', '{{.ServerVersion}}']],
    ] as const) {
      const result = await execute(command, args);
      checks.push({ name, ok: result.ok, detail: result.output });
    }
    try {
      if (!configToml) throw new ProjectDiscoveryError('No supabase/config.toml found');
      const { projectRef } = projectSettingsFromToml(await readFile(configToml, 'utf8'));
      checks.push({
        name: 'Supabase project',
        ok: true,
        detail: projectRef ? `${projectRef} (${configToml})` : configToml,
      });
    } catch (error) {
      checks.push({
        name: 'Supabase project',
        ok: false,
        detail: error instanceof Error ? error.message : 'not found',
      });
      return checks;
    }
  }

  const checkMigrations = async (directory: string) => {
    const migrations = await migrationFiles(directory);
    checks.push({
      name: 'Migrations',
      ok: migrations.length > 0,
      detail: migrations.length
        ? `${migrations.length} SQL migration${migrations.length === 1 ? '' : 's'}`
        : `none found in ${directory}`,
    });
  };

  let loaded: Awaited<ReturnType<typeof loadProjectConfig>>;
  try {
    loaded = await loadProjectConfig(options.cwd, options.configPath);
  } catch (error) {
    if (configToml) await checkMigrations(join(dirname(configToml), 'migrations'));
    checks.push({
      name: 'TenantShield config',
      ok: false,
      detail: error instanceof Error ? error.message : 'invalid',
    });
    return checks;
  }

  const { config, path: configPath, migrationsDirectory } = loaded;
  const projectRoot = dirname(configPath);
  await checkMigrations(migrationsDirectory);
  checks.push({ name: 'TenantShield config', ok: true, detail: configPath });

  const fixtureName = config.fixtures?.mode === 'auto' ? undefined : config.fixtures?.setupSql;
  const fixturePath = fixtureName ? resolve(projectRoot, fixtureName) : undefined;
  let fixtureSql: string | undefined;
  if (fixtureName) {
    try {
      fixtureSql = await readFixtureSql(projectRoot, fixtureName);
    } catch {
      // Missing or unreadable fixture is reported below without exposing OS details.
    }
  }
  const executableFixture =
    fixtureSql
      ?.replaceAll(/\/\*[\s\S]*?\*\//g, '')
      .replaceAll(/--[^\r\n]*/g, '')
      .trim() ?? '';
  let fixtureValidationError: string | undefined;
  if (executableFixture.length > 0 && fixtureSql) {
    try {
      validateFixtureSetupSql(fixtureSql);
    } catch (error) {
      fixtureValidationError =
        error instanceof Error ? error.message : 'Fixture SQL validation failed';
    }
  }
  checks.push({
    name: 'Fixture SQL',
    ok:
      (config.fixtures?.mode === 'auto' && !fixtureName) ||
      (executableFixture.length > 0 && !fixtureValidationError),
    detail:
      fixtureValidationError ??
      (config.fixtures?.mode === 'auto' && !fixtureName
        ? 'automatic fixture synthesis enabled'
        : executableFixture.length > 0
          ? (fixturePath ?? 'fixture configured')
          : `${fixturePath ?? 'fixtures.sql'} (missing or comment-only)`),
  });
  if (options.connectionProbe) {
    try {
      await options.connectionProbe(config);
      checks.push({ name: 'Database connection', ok: true, detail: 'reachable' });
    } catch (error) {
      checks.push({
        name: 'Database connection',
        ok: false,
        detail: error instanceof Error ? error.message : 'failed',
      });
    }
  }
  return checks;
}

export async function loadProjectConfig(
  cwd: string,
  explicitConfigPath?: string,
): Promise<{
  config: TenantShieldConfig;
  path: string;
  projectRef?: string;
  exposedSchemas: string[];
  migrationsDirectory: string;
}> {
  const explicitPath = explicitConfigPath ? resolve(cwd, explicitConfigPath) : undefined;
  const configToml =
    (explicitPath && (await findSupabaseConfig(dirname(explicitPath)))) ||
    (await findSupabaseConfig(cwd));
  const settings = configToml
    ? projectSettingsFromToml(await readFile(configToml, 'utf8'))
    : undefined;
  const localPath = resolve(cwd, 'tenantshield.config.yaml');
  const path =
    explicitPath ??
    ((await exists(localPath)) || !configToml
      ? localPath
      : resolve(dirname(configToml), '..', 'tenantshield.config.yaml'));
  let source: string;
  try {
    source = await readFile(path, 'utf8');
  } catch {
    throw new ProjectDiscoveryError(`No readable tenantshield.config.yaml found at ${path}`);
  }
  const config = parseConfigYaml(source);
  return {
    config,
    path,
    exposedSchemas: config.database.exposedSchemas ?? settings?.exposedSchemas ?? ['public'],
    migrationsDirectory: config.migrationsDir
      ? resolve(dirname(path), config.migrationsDir)
      : configToml
        ? join(dirname(configToml), 'migrations')
        : resolve(dirname(path), 'migrations'),
    ...(settings?.projectRef ? { projectRef: settings.projectRef } : {}),
  };
}

export async function scanWithClient(
  client: SqlClient,
  config: TenantShieldConfig,
  exposedSchemas: readonly string[] = ['public'],
  includeForeignKeyDependencies = false,
) {
  const configuredSchemas = [
    'public',
    ...new Set(
      [
        ...exposedSchemas,
        ...Object.values(config.resources).flatMap((resource) => [
          resource.schema,
          ...(includeForeignKeyDependencies ? [resource.membership?.schema] : []),
        ]),
      ]
        .filter((schema): schema is string => Boolean(schema))
        .filter((schema) => schema !== 'public')
        .sort(),
    ),
  ];
  const snapshot = await captureCatalogSnapshot(client, configuredSchemas, {
    includeForeignKeyDependencies,
  });
  const findings = runStaticRules(snapshot, config);
  return {
    snapshot,
    findings,
    summary: `${findings.length} finding${findings.length === 1 ? '' : 's'} across ${snapshot.tables.length + snapshot.views.length + snapshot.functions.length} resource${snapshot.tables.length + snapshot.views.length + snapshot.functions.length === 1 ? '' : 's'}`,
  };
}
