import { execFile } from 'node:child_process';
import { access, mkdtemp, readdir, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { promisify } from 'node:util';
import { Pool, type PoolClient } from 'pg';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { reportSchema, type TenantShieldReport } from '../../packages/findings/src/index.js';

const execFileAsync = promisify(execFile);

const ROOT = resolve(import.meta.dirname, '../..');
const CLI_PATH = resolve(ROOT, 'apps/cli/dist/index.js');
const EXAMPLES = {
  vulnerable: {
    dir: resolve(ROOT, 'examples/vulnerable'),
    database: 'tenantshield_e2e_vulnerable',
  },
  secure: { dir: resolve(ROOT, 'examples/secure'), database: 'tenantshield_e2e_secure' },
} as const;

const ADMIN_CONNECTION_URL = process.env['TENANTSHIELD_E2E_DATABASE_URL'];
const suite = ADMIN_CONNECTION_URL ? describe : describe.skip;

const RUNNER_ROLE = 'tenantshield_e2e_runner';
const RUNNER_PASSWORD = 'tenantshield_e2e_runner_local_password';
const DATA_API_ROLES = ['anon', 'authenticated'] as const;

interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
}

interface ExampleEnvironment {
  runnerUrl: string;
  workDir: string;
}

async function runCli(
  args: readonly string[],
  options: { cwd: string; env: Record<string, string> },
): Promise<CliResult> {
  try {
    const result = await execFileAsync(process.execPath, [CLI_PATH, ...args], {
      cwd: options.cwd,
      env: { ...process.env, ...options.env },
    });
    return { code: 0, stdout: result.stdout, stderr: result.stderr };
  } catch (error) {
    if (
      error instanceof Error &&
      'code' in error &&
      typeof error.code === 'number' &&
      'stdout' in error &&
      typeof error.stdout === 'string' &&
      'stderr' in error &&
      typeof error.stderr === 'string'
    ) {
      return { code: error.code, stdout: error.stdout, stderr: error.stderr };
    }
    throw error;
  }
}

function parseReport(stdout: string, label: string): TenantShieldReport {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new Error(`${label}: --json stdout was not parseable JSON`);
  }
  return reportSchema.parse(parsed);
}

function secretsFor(adminUrl: string): string[] {
  const secrets = new Set<string>([RUNNER_PASSWORD]);
  try {
    const password = new URL(adminUrl).password;
    if (password) secrets.add(password);
  } catch {
    // The suite already validated the admin URL by connecting.
  }
  return [...secrets];
}

function expectNoSecrets(stdout: string, adminUrl: string, label: string): void {
  for (const secret of secretsFor(adminUrl)) {
    expect(stdout, `${label}: stdout leaked a connection credential`).not.toContain(secret);
  }
}

async function migrationSql(dir: string): Promise<string> {
  const migrationsDirectory = resolve(dir, 'supabase/migrations');
  const entries = await readdir(migrationsDirectory);
  const files = entries.filter((entry) => entry.endsWith('.sql')).sort();
  const contents = await Promise.all(
    files.map((file) => readFile(resolve(migrationsDirectory, file), 'utf8')),
  );
  return contents.join('\n');
}

async function roleExists(admin: PoolClient, role: string): Promise<boolean> {
  const result = await admin.query('SELECT 1 FROM pg_roles WHERE rolname = $1', [role]);
  return (result.rowCount ?? 0) > 0;
}

async function dropDatabase(admin: PoolClient, database: string): Promise<void> {
  await admin.query(`DROP DATABASE IF EXISTS "${database}" WITH (FORCE)`);
}

const AUTH_HELPERS_SQL = `CREATE SCHEMA IF NOT EXISTS auth;
CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$
  SELECT NULLIF(current_setting('request.jwt.claim.sub', true), '')::uuid
$$;
CREATE FUNCTION auth.jwt() RETURNS jsonb LANGUAGE sql STABLE AS $$
  SELECT COALESCE(NULLIF(current_setting('request.jwt.claims', true), '')::jsonb, '{}'::jsonb)
$$;
GRANT USAGE ON SCHEMA auth TO anon, authenticated;
GRANT EXECUTE ON FUNCTION auth.uid(), auth.jwt() TO anon, authenticated;`;

// Fixture setup runs as the runner connection role, which must be able to write
// into RLS-protected tables without being a superuser or BYPASSRLS role (either
// attribute would trip the TS-RLS-006 static finding and the dynamic safety
// checks). Transferring table ownership to the runner role achieves that: RLS
// does not apply to the owner unless FORCE ROW LEVEL SECURITY is set, and the
// Data API roles do not inherit the runner role, so no ownership-bypass finding
// is raised.
const RUNNER_BOOTSTRAP_SQL = `DO $$
DECLARE
  table_name text;
BEGIN
  FOR table_name IN SELECT tablename FROM pg_tables WHERE schemaname = 'public' LOOP
    EXECUTE format('ALTER TABLE public.%I OWNER TO ${RUNNER_ROLE}', table_name);
  END LOOP;
END
$$;
GRANT USAGE ON SCHEMA public TO ${RUNNER_ROLE};
GRANT ALL ON ALL TABLES IN SCHEMA public TO ${RUNNER_ROLE};
GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO ${RUNNER_ROLE};
GRANT anon, authenticated TO ${RUNNER_ROLE};`;

suite('examples end-to-end', () => {
  const adminUrl = ADMIN_CONNECTION_URL as string;
  const adminPool = new Pool({ connectionString: adminUrl, max: 1 });
  const environments: Partial<Record<keyof typeof EXAMPLES, ExampleEnvironment>> = {};
  const createdRoles: string[] = [];
  let workDir: string | undefined;

  beforeAll(async () => {
    await access(CLI_PATH); // Fails with a clear ENOENT stack when `pnpm build` has not run.
    workDir = await mkdtemp(resolve(tmpdir(), 'tenantshield-examples-e2e-'));
    const admin = await adminPool.connect();
    try {
      for (const role of [...DATA_API_ROLES, RUNNER_ROLE]) {
        if (!(await roleExists(admin, role))) {
          const login = role === RUNNER_ROLE ? ` LOGIN PASSWORD '${RUNNER_PASSWORD}'` : ' NOLOGIN';
          await admin.query(`CREATE ROLE "${role}"${login}`);
          createdRoles.push(role);
        }
      }
      for (const [key, example] of Object.entries(EXAMPLES)) {
        await dropDatabase(admin, example.database);
        await admin.query(`CREATE DATABASE "${example.database}"`);
        const databaseUrl = new URL(adminUrl);
        databaseUrl.pathname = `/${example.database}`;
        const bootstrap = new Pool({ connectionString: databaseUrl.toString(), max: 1 });
        try {
          const client = await bootstrap.connect();
          try {
            await client.query(AUTH_HELPERS_SQL);
            await client.query(await migrationSql(example.dir));
            await client.query(
              `GRANT EXECUTE ON FUNCTION auth.uid(), auth.jwt() TO ${RUNNER_ROLE}`,
            );
            await client.query(RUNNER_BOOTSTRAP_SQL);
          } finally {
            client.release();
          }
        } finally {
          await bootstrap.end();
        }
        const runnerUrl = new URL(adminUrl);
        runnerUrl.username = RUNNER_ROLE;
        runnerUrl.password = RUNNER_PASSWORD;
        runnerUrl.pathname = `/${example.database}`;
        environments[key as keyof typeof EXAMPLES] = { runnerUrl: runnerUrl.toString(), workDir };
      }
    } finally {
      admin.release();
    }
  });

  afterAll(async () => {
    const admin = await adminPool.connect();
    try {
      for (const example of Object.values(EXAMPLES)) {
        await dropDatabase(admin, example.database);
      }
      if (createdRoles.includes(RUNNER_ROLE)) {
        await admin.query(`REVOKE anon, authenticated FROM "${RUNNER_ROLE}"`);
      }
      for (const role of [...createdRoles].reverse()) {
        await admin.query(`DROP ROLE "${role}"`);
      }
    } finally {
      admin.release();
      await adminPool.end();
      if (workDir) await rm(workDir, { recursive: true, force: true });
    }
  });

  describe('examples/vulnerable', () => {
    it('reports high-severity static findings and exits 1 for scan --json', async () => {
      const env = environments.vulnerable!;
      const result = await runCli(['scan', '--json'], {
        cwd: EXAMPLES.vulnerable.dir,
        env: { TENANTSHIELD_DATABASE_URL: env.runnerUrl },
      });
      expect(result.code).toBe(1);
      expectNoSecrets(result.stdout, adminUrl, 'vulnerable scan');
      const report = parseReport(result.stdout, 'vulnerable scan');
      expect(report.execution.mode).toBe('scan');
      const ruleIds = report.findings.map((finding) => finding.ruleId);
      // The seeded migration ships a single `FOR ALL ... USING (true) WITH CHECK (true)`
      // policy, which the static rules flag as an unconditional policy boundary.
      expect(ruleIds).toContain('TS-RLS-003');
    });

    it('reports TS-DYN cross-tenant findings and exits 1 for test --json', async () => {
      const env = environments.vulnerable!;
      const outputPath = resolve(env.workDir, 'vulnerable-report.json');
      const result = await runCli(['test', '--json', '--output', outputPath], {
        cwd: EXAMPLES.vulnerable.dir,
        env: { TENANTSHIELD_DATABASE_URL: env.runnerUrl },
      });
      expect(result.code).toBe(1);
      expectNoSecrets(result.stdout, adminUrl, 'vulnerable test');
      const report = parseReport(result.stdout, 'vulnerable test');
      expect(report.execution.mode).toBe('test');
      expect(report.execution.complete).toBe(true);
      expect(report.execution.errorCases).toBe(0);
      expect(report.execution.skippedCases).toBe(0);
      const ruleIds = report.findings.map((finding) => finding.ruleId);
      // The unconditional FOR ALL policy lets both identities read, write, reassign,
      // and delete across tenants; every dynamic operation must surface findings.
      expect(ruleIds).toContain('TS-RLS-003');
      for (const operation of ['SELECT', 'INSERT', 'UPDATE', 'DELETE'] as const) {
        expect(ruleIds).toContain(`TS-DYN-${operation}`);
      }
      expect(report.findings.filter((finding) => finding.source === 'dynamic')).toHaveLength(12);
    });
  });

  describe('examples/secure', () => {
    it('reports zero findings and exits 0 for scan --json', async () => {
      const env = environments.secure!;
      const result = await runCli(['scan', '--json'], {
        cwd: EXAMPLES.secure.dir,
        env: { TENANTSHIELD_DATABASE_URL: env.runnerUrl },
      });
      expect(result.code).toBe(0);
      expectNoSecrets(result.stdout, adminUrl, 'secure scan');
      const report = parseReport(result.stdout, 'secure scan');
      expect(report.execution.mode).toBe('scan');
      expect(report.findings).toEqual([]);
    });

    it('passes the complete dynamic suite with zero findings and exits 0', async () => {
      const env = environments.secure!;
      const outputPath = resolve(env.workDir, 'secure-report.json');
      const result = await runCli(['test', '--json', '--output', outputPath], {
        cwd: EXAMPLES.secure.dir,
        env: { TENANTSHIELD_DATABASE_URL: env.runnerUrl },
      });
      expect(result.code).toBe(0);
      expectNoSecrets(result.stdout, adminUrl, 'secure test');
      const report = parseReport(result.stdout, 'secure test');
      expect(report.execution.mode).toBe('test');
      // 4 operations x (owner-same, foreign-same, cross, reverse-cross) plus 4 extra
      // UPDATE tenant-reassignment scenarios: every case must have run and passed.
      expect(report.execution.totalCases).toBe(20);
      expect(report.execution.passedCases).toBe(20);
      expect(report.execution.failedCases).toBe(0);
      expect(report.execution.errorCases).toBe(0);
      expect(report.execution.skippedCases).toBe(0);
      expect(report.execution.complete).toBe(true);
      expect(report.findings).toEqual([]);
    });
  });
});
