import { realpathSync } from 'node:fs';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Command, CommanderError } from 'commander';
import { Pool, type PoolClient, type PoolConfig } from 'pg';
import { ZodError } from 'zod';
import packageManifest from '../package.json' with { type: 'json' };
import { ConfigValidationError, type TenantShieldConfig } from '@tenantshield/config';
import {
  failureThresholdMet,
  reportSchema,
  type ExecutionSummary,
  type Severity,
  type TenantShieldReport,
} from '@tenantshield/findings';
import {
  redactText,
  renderHtml,
  renderJson,
  renderMarkdown,
  renderSarif,
  renderTerminal,
  sanitizeTerminalText,
  writeJsonReport,
  writeTextReport,
} from '@tenantshield/reporters';
import {
  DatabaseSafetyError,
  FixtureSetupError,
  IdentityVerificationError,
  assertNotProductionTarget,
  inspectDatabaseTarget,
  isDatabaseOperationError,
  runDynamicTests,
  runFixtureSetup,
  synthesizeFixturesInTransaction,
  type DatabaseTarget,
  type DynamicSqlClient,
} from '@tenantshield/runner';
import {
  initializeProject,
  loadProjectConfig,
  mapFindingsToMigrationLocations,
  readFixtureSql,
  runDoctor,
  scanWithClient,
  ProjectDiscoveryError,
  type DoctorCheck,
} from './commands/project.js';

export interface CliError {
  code: 1 | 2 | 3 | 4;
  message: string;
  details?: readonly string[];
}

export class CliPrerequisiteError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CliPrerequisiteError';
  }
}

export const TOOL_VERSION = packageManifest.version;

export function databasePoolOptions(connectionString: string): PoolConfig {
  return { connectionString, max: 1, connectionTimeoutMillis: 5_000 };
}

export interface CliIo {
  stdout: NodeJS.WritableStream;
  stderr: NodeJS.WritableStream;
}

export const defaultCliIo: CliIo = { stdout: process.stdout, stderr: process.stderr };

function createStderrNote(io: CliIo): (line: string) => void {
  return (line) => {
    io.stderr.write(`${safeCliText(line)}\n`);
  };
}

export function formatVerboseConnection(connectionUrl: string): string {
  return `Connection: ${redactText(connectionUrl)}`;
}

export function formatVerboseTarget(target: DatabaseTarget): string {
  return `Target: ${target.host}:${target.port}/${target.database} (${target.isRemote ? 'remote' : 'local'})`;
}

export function formatConfigSummary(config: TenantShieldConfig, path: string): string {
  return `Config: ${path} (version ${config.version}, ${Object.keys(config.identities).length} identities, ${Object.keys(config.resources).length} resources)`;
}

export function formatStepTiming(step: string, milliseconds: number): string {
  return `Timing: ${step} ${milliseconds}ms`;
}

export function formatResourceProgress(completed: number, total: number): string {
  return `${completed}/${total} resources tested`;
}

export interface TrackedResource {
  qualified: string;
}

export interface ResourceProgressTracker {
  client: DynamicSqlClient;
  finish: () => void;
}

function quoteSqlIdentifier(identifier: string): string {
  return `"${identifier.replaceAll('"', '""')}"`;
}

export function dynamicTestResources(config: TenantShieldConfig): TrackedResource[] {
  return Object.entries(config.resources)
    .filter(([, resource]) => !resource.public)
    .map(([name, resource]) => ({
      qualified: `${quoteSqlIdentifier(resource.schema ?? 'public')}.${quoteSqlIdentifier(name)}`,
    }));
}

export function createResourceProgressTracker(
  client: DynamicSqlClient,
  resources: readonly TrackedResource[],
  onResourceComplete: (completed: number, total: number) => void,
): ResourceProgressTracker {
  let current: string | undefined;
  let completed = 0;
  const complete = (): void => onResourceComplete(++completed, resources.length);
  return {
    client: {
      query: async (sql, values) => {
        const resource = resources.find((entry) => sql.includes(entry.qualified));
        if (resource && resource.qualified !== current) {
          if (current !== undefined) complete();
          current = resource.qualified;
        }
        return client.query(sql, values);
      },
    },
    finish: () => {
      if (current !== undefined) complete();
    },
  };
}

export function formatCliError(error: CliError): string {
  const heading = safeCliText(`error TS${String(error.code).padStart(3, '0')}: ${error.message}`);
  return error.details?.length
    ? `${heading}\n${error.details.map((detail) => `  ${safeCliText(detail)}`).join('\n')}`
    : heading;
}

function safeCliText(input: string): string {
  return sanitizeTerminalText(redactText(input));
}

export function formatDoctorCheck(check: DoctorCheck): string {
  return safeCliText(`${check.ok ? 'ok' : 'fail'} ${check.name}: ${check.detail}`);
}

export function createProgram(): Command {
  const command = new Command()
    .name('tenantshield')
    .description('Find PostgreSQL RLS tenant-isolation failures')
    .version(TOOL_VERSION)
    .exitOverride();

  command
    .command('init')
    .description('Create starter tenantshield.config.yaml')
    .action(async () => {
      const result = await initializeProject(process.cwd());
      process.stdout.write(
        `${safeCliText(`${result.created ? 'created' : 'exists'} ${result.path}`)}\n`,
      );
    });

  command
    .command('doctor')
    .description('Validate local prerequisites')
    .option('--config <path>', 'TenantShield YAML config path')
    .action(async (options: { config?: string }) => {
      const checks = await runDoctor({
        cwd: process.cwd(),
        ...(options.config ? { configPath: options.config } : {}),
        connectionProbe: async (config) => {
          const connectionUrl = process.env[config.database.connectionEnv];
          if (!connectionUrl) throw new Error(`missing ${config.database.connectionEnv}`);
          inspectDatabaseTarget(connectionUrl, { allowedHosts: config.database.allowedHosts });
          const pool = new Pool({
            connectionString: connectionUrl,
            max: 1,
            connectionTimeoutMillis: 3_000,
          });
          try {
            await pool.query('SELECT 1');
          } finally {
            await pool.end();
          }
        },
      });
      for (const check of checks) process.stdout.write(`${formatDoctorCheck(check)}\n`);
      if (checks.some((check) => !check.ok)) process.exitCode = 2;
    });

  command
    .command('scan')
    .alias('audit')
    .description('Run non-mutating static RLS checks')
    .option('--allow-remote', 'allow guarded remote database connection')
    .option('--config <path>', 'TenantShield YAML config path')
    .option('--fail-on <severity>', 'failure threshold', 'high')
    .option('--output <path>', 'write versioned JSON report')
    .option('--json', 'print the JSON report to stdout instead of the terminal render')
    .option('--format <format>', 'terminal, json, html, sarif, or markdown')
    .option('--baseline <path>', 'compare against a saved JSON report')
    .option('--verbose', 'print diagnostic details to stderr')
    .action(async (options: ScanCommandOptions) => {
      await runScanCommand(options);
    });

  command
    .command('test')
    .description('Run static checks and dynamic tenant-boundary cases')
    .option('--allow-remote', 'allow guarded remote database connection')
    .option('--config <path>', 'TenantShield YAML config path')
    .option('--auto-seed', 'synthesize disposable tenant fixture rows')
    .option('--filter <pattern>', 'filter evaluated resources by name or pattern')
    .option('--fail-on <severity>', 'failure threshold', 'high')
    .option('--output <path>', 'write versioned JSON report', 'tenantshield-report.json')
    .option('--json', 'print the JSON report to stdout instead of the terminal render')
    .option('--format <format>', 'terminal, json, html, sarif, or markdown')
    .option('--baseline <path>', 'compare against a saved JSON report')
    .option('--verbose', 'print diagnostic details to stderr')
    .action(async (options: TestCommandOptions) => {
      await runTestCommand(options);
    });

  command
    .command('report')
    .description('Convert a saved JSON report')
    .argument('<input>', 'saved TenantShield JSON report')
    .option('--format <format>', 'terminal, json, html, sarif, or markdown', 'terminal')
    .option('--output <path>', 'write output instead of stdout')
    .option('--baseline <path>', 'compare findings with a baseline JSON report')
    .action(
      async (input: string, options: { format: string; output?: string; baseline?: string }) => {
        const format = parseReportFormat(options.format);
        const inputPath = resolve(input);
        const outputPath = options.output ? resolve(options.output) : undefined;
        if (outputPath === inputPath && format !== 'json') {
          throw new CliPrerequisiteError(
            'Report output must differ from the source JSON when converting formats',
          );
        }
        let source: string;
        try {
          source = await readFile(inputPath, 'utf8');
        } catch {
          throw new CliPrerequisiteError(`Saved report could not be read: ${inputPath}`);
        }
        const report = reportSchema.parse(JSON.parse(source));
        let output: string;
        const baseline = options.baseline ? await readBaseline(options.baseline) : undefined;
        if (format === 'terminal') output = `${renderTerminal(report)}\n`;
        else if (format === 'json') output = renderJson(report);
        else if (format === 'html') output = renderHtml(report);
        else if (format === 'sarif') output = renderSarif(report);
        else output = renderMarkdown(report, baseline);
        if (outputPath && format === 'json') {
          await writeJsonReport(outputPath, report);
        } else if (outputPath) {
          await writeTextReport(outputPath, output);
        } else process.stdout.write(output);
      },
    );

  return command;
}

export interface ScanCommandOptions {
  config?: string;
  allowRemote?: boolean;
  failOn: Severity;
  output?: string;
  json?: boolean;
  verbose?: boolean;
  format?: string;
  baseline?: string;
}

export interface TestCommandOptions {
  config?: string;
  autoSeed?: boolean;
  allowRemote?: boolean;
  filter?: string;
  failOn: Severity;
  output: string;
  json?: boolean;
  verbose?: boolean;
  format?: string;
  baseline?: string;
}

export async function runScanCommand(
  options: ScanCommandOptions,
  io: CliIo = defaultCliIo,
): Promise<void> {
  const failOn = parseSeverity(options.failOn);
  const format = parseReportFormat(options.json ? 'json' : (options.format ?? 'terminal'));
  const baseline = options.baseline ? await readBaseline(options.baseline) : undefined;
  const note = createStderrNote(io);
  let stepStartedAt = Date.now();
  const {
    config,
    path: configPath,
    exposedSchemas,
    migrationsDirectory,
  } = await loadProjectConfig(process.cwd(), options.config);
  if (options.verbose) {
    note(formatStepTiming('load config', Date.now() - stepStartedAt));
    note(formatConfigSummary(config, configPath));
  }
  stepStartedAt = Date.now();
  const connectionUrl = requiredEnvironment(config.database.connectionEnv);
  const target = inspectDatabaseTarget(connectionUrl, {
    allowRemoteFlag: options.allowRemote ?? false,
    allowRemoteEnv: process.env['TENANTSHIELD_ALLOW_REMOTE'] === '1',
    allowedHosts: config.database.allowedHosts,
  });
  if (options.verbose) {
    note(formatStepTiming('target inspection', Date.now() - stepStartedAt));
    note(formatVerboseConnection(connectionUrl));
    note(formatVerboseTarget(target));
  }
  const startedAt = new Date().toISOString();
  const pool = new Pool(databasePoolOptions(connectionUrl));
  let databaseClient: PoolClient | undefined;
  try {
    databaseClient = await pool.connect();
    note('Capturing catalog snapshot...');
    stepStartedAt = Date.now();
    const result = await scanWithClient(
      {
        query: async (sql, values) => {
          const queryResult = await databaseClient!.query(sql, values ? [...values] : undefined);
          return { rows: queryResult.rows as Record<string, unknown>[] };
        },
      },
      config,
      exposedSchemas,
    );
    if (options.verbose) note(formatStepTiming('catalog capture', Date.now() - stepStartedAt));
    const resourceCount =
      result.snapshot.tables.length +
      result.snapshot.views.length +
      result.snapshot.functions.length;
    note(`Catalog snapshot complete (${resourceCount} resource${resourceCount === 1 ? '' : 's'})`);
    const locatedFindings = await mapFindingsToMigrationLocations(
      dirname(configPath),
      migrationsDirectory,
      result.findings,
    );
    const report = makeReport(
      startedAt,
      target,
      result.snapshot.database.serverVersion,
      locatedFindings,
      [],
      {
        mode: 'scan',
        testedResources: summarizeStaticResources(result.snapshot),
        totalCases: 0,
        passedCases: 0,
        failedCases: 0,
        errorCases: 0,
        skippedCases: 0,
        complete: true,
      },
      result.snapshot.tables.map((table) => `${table.schema}.${table.name}`),
    );
    if (options.output) await writeJsonReport(resolve(options.output), report);
    io.stdout.write(renderCliReport(report, format, baseline, failOn));
    if (failureThresholdMet(locatedFindings, failOn)) process.exitCode = 1;
  } finally {
    databaseClient?.release();
    await pool.end();
  }
}

export async function runTestCommand(
  options: TestCommandOptions,
  io: CliIo = defaultCliIo,
): Promise<void> {
  const failOn = parseSeverity(options.failOn);
  const format = parseReportFormat(options.json ? 'json' : (options.format ?? 'terminal'));
  const baseline = options.baseline ? await readBaseline(options.baseline) : undefined;
  const note = createStderrNote(io);
  const emitHeader =
    format !== 'terminal' ? note : (line: string) => io.stdout.write(`${safeCliText(line)}\n`);
  let stepStartedAt = Date.now();
  const {
    config,
    path: configPath,
    projectRef,
    exposedSchemas,
    migrationsDirectory,
  } = await loadProjectConfig(process.cwd(), options.config);
  if (options.filter) {
    const filterTerm = options.filter.toLowerCase();
    const filtered: Record<string, (typeof config.resources)[string]> = {};
    for (const [name, resource] of Object.entries(config.resources)) {
      if (name.toLowerCase().includes(filterTerm) || filterTerm.includes(name.toLowerCase())) {
        filtered[name] = resource;
      }
    }
    if (Object.keys(filtered).length === 0) {
      throw new Error(`Filter "${options.filter}" did not match any configured resources.`);
    }
    if (!Object.values(filtered).some((resource) => !resource.public)) {
      throw new Error(`Filter "${options.filter}" matched no tenant-protected resources to test.`);
    }
    config.resources = filtered;
  }
  if (options.verbose) {
    note(formatStepTiming('load config', Date.now() - stepStartedAt));
    note(formatConfigSummary(config, configPath));
  }
  stepStartedAt = Date.now();
  const connectionUrl = requiredEnvironment(config.database.connectionEnv);
  const target = inspectDatabaseTarget(connectionUrl, {
    allowRemoteFlag: options.allowRemote ?? false,
    allowRemoteEnv: process.env['TENANTSHIELD_ALLOW_REMOTE'] === '1',
    allowedHosts: config.database.allowedHosts,
  });
  if (options.verbose) {
    note(formatStepTiming('target inspection', Date.now() - stepStartedAt));
    note(formatVerboseConnection(connectionUrl));
    note(formatVerboseTarget(target));
  }
  assertNotProductionTarget(
    target,
    config.database.productionMarkers ?? [],
    projectRef ? [projectRef] : [],
  );
  emitHeader(`Target: ${target.host}:${target.port}/${target.database}`);
  emitHeader(`Supabase project: ${projectRef ?? 'unknown'}`);
  if (hasMutationCases(config.resources)) {
    emitHeader('Warning: dynamic mutation cases can activate external trigger side effects.');
  }
  const startedAt = new Date().toISOString();
  const autoSeed = options.autoSeed === true || config.fixtures?.mode === 'auto';
  let setupSql: string | undefined;
  if (!autoSeed) {
    try {
      if (!config.fixtures?.setupSql)
        throw new ProjectDiscoveryError(
          'fixtures.setupSql is required unless --auto-seed is enabled',
        );
      setupSql = await readFixtureSql(dirname(configPath), config.fixtures.setupSql);
    } catch (error) {
      if (error instanceof ProjectDiscoveryError) throw error;
      throw new FixtureSetupError(
        'Fixture SQL could not be read; verify fixtures.setupSql and file permissions',
      );
    }
  }
  const pool = new Pool(databasePoolOptions(connectionUrl));
  let databaseClient: PoolClient | undefined;
  try {
    databaseClient = await pool.connect();
    const client: DynamicSqlClient = {
      query: async (sql, values) => {
        const result = await databaseClient!.query(sql, values ? [...values] : undefined);
        return { rows: result.rows as Record<string, unknown>[], rowCount: result.rowCount };
      },
    };
    stepStartedAt = Date.now();
    const staticResult = await scanWithClient(client, config, exposedSchemas, autoSeed);
    if (options.verbose) note(formatStepTiming('static scan', Date.now() - stepStartedAt));
    stepStartedAt = Date.now();
    if (!autoSeed) await runFixtureSetup(client, setupSql!);
    if (options.verbose)
      note(
        formatStepTiming(
          autoSeed ? 'automatic fixture synthesis' : 'fixture setup',
          Date.now() - stepStartedAt,
        ),
      );
    const tracker = createResourceProgressTracker(
      client,
      dynamicTestResources(config),
      (completed, total) => note(formatResourceProgress(completed, total)),
    );
    stepStartedAt = Date.now();
    const dynamicResult = autoSeed
      ? await synthesizeFixturesInTransaction(tracker.client, config, staticResult.snapshot)
      : await runDynamicTests(tracker.client, config, staticResult.snapshot);
    tracker.finish();
    if (options.verbose) note(formatStepTiming('dynamic tests', Date.now() - stepStartedAt));
    let allFindings = [...staticResult.findings, ...dynamicResult.findings];
    if (options.filter) {
      const filterTerm = options.filter.toLowerCase();
      allFindings = allFindings.filter((f) => {
        const table = f.table?.toLowerCase() ?? '';
        const fn = f.function?.toLowerCase() ?? '';
        const ruleId = f.ruleId.toLowerCase();
        return (
          (table && table.includes(filterTerm)) ||
          (fn && fn.includes(filterTerm)) ||
          ruleId.includes(filterTerm) ||
          (table && filterTerm.includes(table))
        );
      });
    }
    const findings = await mapFindingsToMigrationLocations(
      dirname(configPath),
      migrationsDirectory,
      allFindings,
    );
    const report = makeReport(
      startedAt,
      target,
      staticResult.snapshot.database.serverVersion,
      findings,
      dynamicResult.warnings,
      summarizeDynamicExecution(dynamicResult.cases, dynamicResult.complete, config),
      staticResult.snapshot.tables.map((table) => `${table.schema}.${table.name}`),
    );
    await writeJsonReport(resolve(options.output), report);
    const output = renderCliReport(report, format, baseline, failOn);
    if (format !== 'terminal') {
      io.stdout.write(output);
      note(`Report: ${resolve(options.output)}`);
    } else {
      io.stdout.write(`${output}${safeCliText(`Report: ${resolve(options.output)}`)}\n`);
    }
    process.exitCode = determineTestExitCode(findings, failOn, dynamicResult.complete);
  } finally {
    databaseClient?.release();
    await pool.end();
  }
}

export function parseSeverity(input: string): Severity {
  if (
    input === 'info' ||
    input === 'low' ||
    input === 'medium' ||
    input === 'high' ||
    input === 'critical'
  )
    return input;
  throw new CliPrerequisiteError(`Invalid severity ${input}`);
}

type ReportFormat = 'terminal' | 'json' | 'html' | 'sarif' | 'markdown';

export function parseReportFormat(input: string): ReportFormat {
  const format = input.toLowerCase();
  if (
    format === 'terminal' ||
    format === 'json' ||
    format === 'html' ||
    format === 'sarif' ||
    format === 'markdown'
  ) {
    return format;
  }
  throw new CliPrerequisiteError(`Unknown report format ${format}`);
}

async function readBaseline(path: string): Promise<TenantShieldReport> {
  let source: string;
  try {
    source = await readFile(resolve(path), 'utf8');
  } catch {
    throw new CliPrerequisiteError(`Baseline report could not be read: ${resolve(path)}`);
  }
  try {
    return reportSchema.parse(JSON.parse(source));
  } catch {
    throw new CliPrerequisiteError('Baseline report is not a valid TenantShield JSON report');
  }
}

function renderCliReport(
  report: TenantShieldReport,
  format: ReportFormat,
  baseline?: TenantShieldReport,
  failOn?: Severity,
): string {
  if (format === 'json') return renderJson(report);
  if (format === 'html') return renderHtml(report);
  if (format === 'sarif') return renderSarif(report);
  if (format === 'markdown') return renderMarkdown(report, baseline, failOn);
  return `${renderTerminal(report)}\n`;
}

function requiredEnvironment(name: string): string {
  const value = process.env[name];
  if (!value) throw new CliPrerequisiteError(`Missing environment variable ${name}`);
  return value;
}

export function determineTestExitCode(
  findings: TenantShieldReport['findings'],
  failOn: Severity,
  complete: boolean,
): 0 | 1 | 3 {
  if (!complete) return 3;
  return failureThresholdMet(findings, failOn) ? 1 : 0;
}

export function summarizeStaticResources(snapshot: {
  tables: readonly { schema: string; name: string }[];
  views: readonly { schema: string; name: string }[];
  functions: readonly { schema: string; name: string; identityArguments: string }[];
}): string[] {
  return [
    ...[...snapshot.tables, ...snapshot.views].map(
      (resource) => `${resource.schema}.${resource.name}`,
    ),
    ...snapshot.functions.map((fn) => `${fn.schema}.${fn.name}(${fn.identityArguments})`),
  ].sort();
}

export function hasMutationCases(resources: TenantShieldConfig['resources']): boolean {
  return Object.values(resources).some(
    (resource) =>
      !resource.public && resource.testOperations.some((operation) => operation !== 'select'),
  );
}

function summarizeDynamicExecution(
  cases: Awaited<ReturnType<typeof runDynamicTests>>['cases'],
  complete: boolean,
  config: TenantShieldConfig,
): ExecutionSummary {
  const count = (status: (typeof cases)[number]['status']) =>
    cases.filter((testCase) => testCase.status === status).length;
  return {
    mode: 'test',
    testedResources: [...new Set(cases.map((testCase) => testCase.resource))].sort(),
    testedMatrix: [
      ...new Map(
        cases.map((testCase) => {
          const key = `${testCase.resource}\0${testCase.identity}`;
          const related = cases.filter(
            (candidate) =>
              candidate.resource === testCase.resource && candidate.identity === testCase.identity,
          );
          const statuses = related.map((candidate) => candidate.status);
          const status: (typeof cases)[number]['status'] = statuses.includes('error')
            ? 'error'
            : statuses.includes('failed')
              ? 'failed'
              : statuses.includes('skipped')
                ? 'skipped'
                : 'passed';
          return [
            key,
            {
              resource: testCase.resource,
              role: config.identities[testCase.identity]?.role ?? 'unknown',
              operations: [...new Set(related.map((candidate) => candidate.operation))].sort(),
              status,
            },
          ];
        }),
      ).values(),
    ],
    totalCases: cases.length,
    passedCases: count('passed'),
    failedCases: count('failed'),
    errorCases: count('error'),
    skippedCases: count('skipped'),
    complete,
    cases: cases.map((c, index) => {
      const separator = c.resource.lastIndexOf('.');
      return {
        id: `${c.resource}:${c.identity}:${c.operation}:${c.control}:${c.scenario ?? 'default'}:${index}`,
        resource: c.resource,
        schema: separator > 0 ? c.resource.slice(0, separator) : 'public',
        table: separator > 0 ? c.resource.slice(separator + 1) : c.resource,
        operation: c.operation,
        identity: c.identity,
        control: c.control,
        status: c.status,
        observed: c.observed,
        ...(c.scenario ? { scenario: c.scenario } : {}),
      };
    }),
  };
}

function makeReport(
  startedAt: string,
  target: { host: string; port: number; database: string },
  serverVersion: string,
  findings: TenantShieldReport['findings'],
  warnings: string[],
  execution: ExecutionSummary,
  catalogTables: string[],
): TenantShieldReport {
  return {
    version: 1,
    metadata: {
      toolVersion: TOOL_VERSION,
      startedAt,
      completedAt: new Date().toISOString(),
      ...(process.env['GITHUB_SHA'] ? { gitCommit: process.env['GITHUB_SHA'] } : {}),
      target: { host: target.host, port: target.port, database: target.database, serverVersion },
    },
    staticAuditExecuted: true,
    catalogTables,
    catalogComplete: true,
    findings,
    warnings: warnings.map(redactText),
    execution,
  };
}

export const program = createProgram();

export function isMainModule(moduleUrl: string, argvPath: string): boolean {
  try {
    return realpathSync(fileURLToPath(moduleUrl)) === realpathSync(argvPath);
  } catch {
    return false;
  }
}

export function exitCodeForError(error: unknown): 2 | 3 | 4 {
  const errorCode =
    error && typeof error === 'object' && 'code' in error && typeof error.code === 'string'
      ? error.code
      : null;
  if (
    errorCode &&
    [
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
    ].includes(errorCode)
  ) {
    return 2;
  }
  if (
    error instanceof FixtureSetupError ||
    error instanceof IdentityVerificationError ||
    isDatabaseOperationError(error)
  )
    return 3;
  if (
    error instanceof DatabaseSafetyError ||
    error instanceof ConfigValidationError ||
    error instanceof CliPrerequisiteError ||
    error instanceof ProjectDiscoveryError ||
    error instanceof CommanderError ||
    error instanceof ZodError ||
    error instanceof SyntaxError
  )
    return 2;
  return 4;
}

export function normalizeCliError(error: unknown): CliError {
  const code = exitCodeForError(error);
  if (error instanceof ConfigValidationError) {
    return {
      code,
      message: 'Invalid configuration',
      details: error.issues.map((issue) => `${issue.path}: ${issue.message}`),
    };
  }
  if (error instanceof ZodError) {
    return {
      code,
      message: 'Data validation failed',
      details: error.issues.map(
        (issue) => `${issue.path.map(String).join('.') || '<root>'}: ${issue.message}`,
      ),
    };
  }
  if (error instanceof SyntaxError) return { code, message: 'Saved report contains invalid JSON' };
  return {
    code,
    message: error instanceof Error ? error.message : 'Unknown internal error',
  };
}

export function installPipeErrorHandlers(
  streams: readonly NodeJS.WritableStream[] = [process.stdout, process.stderr],
): void {
  for (const stream of streams) {
    stream.on('error', (error: NodeJS.ErrnoException) => {
      if (error.code === 'EPIPE') return;
      throw error;
    });
  }
}

if (process.argv[1] && isMainModule(import.meta.url, process.argv[1])) {
  installPipeErrorHandlers();
  program.parseAsync().catch((error: unknown) => {
    if (error instanceof CommanderError && error.exitCode === 0) {
      process.exitCode = 0;
      return;
    }
    const cliError = normalizeCliError(error);
    process.stderr.write(`${formatCliError(cliError)}\n`);
    process.exitCode = cliError.code;
  });
}
