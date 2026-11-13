import { execFile } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { promisify } from 'node:util';
import { describe, expect, it } from 'vitest';

const execFileAsync = promisify(execFile);

interface ExecFailure extends Error {
  code: number;
  stderr: string;
}

async function commandFailure(command: ReturnType<typeof execFileAsync>): Promise<ExecFailure> {
  try {
    await command;
  } catch (error) {
    if (
      error instanceof Error &&
      'code' in error &&
      typeof error.code === 'number' &&
      'stderr' in error &&
      typeof error.stderr === 'string'
    ) {
      return error as ExecFailure;
    }
    throw error;
  }
  throw new Error('Expected command to fail');
}

describe('packaged CLI', () => {
  it('executes the built version command', async () => {
    const result = await execFileAsync(process.execPath, [
      resolve('apps/cli/dist/index.js'),
      '--version',
    ]);
    expect(result.stdout.trim()).toBe('0.2.1');
  });

  it('supports the audit alias for scan', async () => {
    const failure = await commandFailure(
      execFileAsync(process.execPath, [
        resolve('apps/cli/dist/index.js'),
        'audit',
        '--fail-on',
        'urgent',
      ]),
    );
    expect(failure.code).toBe(2);
    expect(failure.stderr).toContain('Invalid severity urgent');
  });

  it('exits cleanly when a downstream pipe closes early', async () => {
    await expect(
      execFileAsync('bash', [
        '-o',
        'pipefail',
        '-c',
        '"$1" "$2" --help | dd of=/dev/null bs=1 count=0 2>/dev/null',
        'tenantshield-pipe-test',
        process.execPath,
        resolve('apps/cli/dist/index.js'),
      ]),
    ).resolves.toBeDefined();
  });

  it('rejects invalid severity before project or database work', async () => {
    const failure = await commandFailure(
      execFileAsync(process.execPath, [
        resolve('apps/cli/dist/index.js'),
        'scan',
        '--fail-on',
        'urgent',
      ]),
    );
    expect(failure.code).toBe(2);
    expect(failure.stderr).toContain('Invalid severity urgent');
  });

  it.each([
    ['unknown command', ['unknown-command']],
    ['unknown option', ['scan', '--unknown-option']],
  ])('maps %s usage errors to exit code 2', async (_label, args) => {
    const failure = await commandFailure(
      execFileAsync(process.execPath, [resolve('apps/cli/dist/index.js'), ...args]),
    );
    expect(failure.code).toBe(2);
  });

  it('maps missing TenantShield config to exit code 2', async () => {
    const empty = await mkdtemp(resolve(tmpdir(), 'tenantshield-e2e-'));
    try {
      const failure = await commandFailure(
        execFileAsync(process.execPath, [resolve('apps/cli/dist/index.js'), 'scan'], {
          cwd: empty,
        }),
      );
      expect(failure.code).toBe(2);
      expect(failure.stderr).toContain('No readable tenantshield.config.yaml found');
    } finally {
      await rm(empty, { recursive: true, force: true });
    }
  });

  it('maps a missing saved report to exit code 2', async () => {
    const missing = resolve(tmpdir(), 'tenantshield-report-does-not-exist.json');
    const failure = await commandFailure(
      execFileAsync(process.execPath, [
        resolve('apps/cli/dist/index.js'),
        'report',
        missing,
        '--format',
        'json',
      ]),
    );
    expect(failure.code).toBe(2);
  });

  it('validates report format before reading the input file', async () => {
    const failure = await commandFailure(
      execFileAsync(process.execPath, [
        resolve('apps/cli/dist/index.js'),
        'report',
        resolve(tmpdir(), 'tenantshield-report-does-not-exist.json'),
        '--format',
        'xml',
      ]),
    );
    expect(failure.code).toBe(2);
    expect(failure.stderr).toContain('Unknown report format xml');
  });

  it('refuses to overwrite a JSON source report with another format', async () => {
    const directory = await mkdtemp(resolve(tmpdir(), 'tenantshield-report-e2e-'));
    const reportPath = resolve(directory, 'report.json');
    const source = `${JSON.stringify({
      version: 1,
      metadata: {
        toolVersion: '0.1.0-dev',
        startedAt: '2026-07-19T00:00:00.000Z',
        completedAt: '2026-07-19T00:00:01.000Z',
        target: { host: 'localhost', port: 5432, database: 'postgres' },
      },
      execution: {
        mode: 'scan',
        testedResources: [],
        totalCases: 0,
        passedCases: 0,
        failedCases: 0,
        errorCases: 0,
        skippedCases: 0,
        complete: true,
      },
      findings: [],
      warnings: [],
    })}\n`;
    await writeFile(reportPath, source);
    try {
      const failure = await commandFailure(
        execFileAsync(process.execPath, [
          resolve('apps/cli/dist/index.js'),
          'report',
          reportPath,
          '--format',
          'html',
          '--output',
          reportPath,
        ]),
      );
      expect(failure.code).toBe(2);
      expect(await readFile(reportPath, 'utf8')).toBe(source);
    } finally {
      await rm(directory, { recursive: true, force: true });
    }
  });
});
