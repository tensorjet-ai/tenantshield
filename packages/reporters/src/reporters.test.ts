import { mkdtemp, mkdir, readdir, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import {
  createFindingFingerprint,
  reportSchema,
  type Finding,
  type TenantShieldReport,
} from '@tenantshield/findings';
import {
  redactText,
  renderHtml,
  renderJson,
  renderMarkdown,
  renderSarif,
  renderTerminal,
  writeJsonReport,
  writeTextReport,
} from './index.js';

function fingerprinted(input: Finding): Finding {
  return { ...input, fingerprint: createFindingFingerprint(input) };
}

const report: TenantShieldReport = {
  version: 1,
  metadata: {
    toolVersion: '0.1.0-dev',
    startedAt: '2026-07-16T00:00:00.000Z',
    completedAt: '2026-07-16T00:00:01.000Z',
    target: { host: 'localhost', port: 54322, database: 'postgres', serverVersion: '16.4' },
  },
  findings: [
    fingerprinted({
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
      fingerprint: 'a'.repeat(64),
    }),
  ],
  warnings: ['Triggers may have external side effects.'],
  execution: {
    mode: 'test',
    testedResources: ['public.invoices'],
    testedMatrix: [
      {
        resource: 'public.invoices',
        role: 'authenticated',
        operations: ['select', 'update'],
        status: 'passed',
      },
    ],
    totalCases: 4,
    passedCases: 3,
    failedCases: 0,
    errorCases: 0,
    skippedCases: 1,
    complete: false,
  },
};

describe('reporters', () => {
  it('renders a fingerprint-based Markdown PR diff and matrix', () => {
    const baseline = { ...report, findings: [] };
    const output = renderMarkdown(report, baseline);
    expect(output).toContain('### New findings');
    expect(output).toContain('TS-RLS-001');
    expect(output).toContain('| public.invoices |');
    expect(output).toContain('### Resolved findings');
  });

  it('maps optional migration locations into SARIF without changing fingerprints', () => {
    const located = {
      ...report,
      findings: [
        { ...report.findings[0]!, location: { file: 'db/migrations/001.sql', startLine: 12 } },
      ],
    };
    const sarif = JSON.parse(renderSarif(located)) as {
      runs: {
        results: {
          locations: {
            physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } };
          }[];
        }[];
      }[];
    };
    expect(sarif.runs[0]?.results[0]?.locations[0]?.physicalLocation).toEqual({
      artifactLocation: { uri: 'db/migrations/001.sql' },
      region: { startLine: 12 },
    });
    expect(located.findings[0]?.fingerprint).toBe(report.findings[0]?.fingerprint);
  });
  it('renders stable compact terminal output', () => {
    expect(renderTerminal(report)).toMatchInlineSnapshot(`
      "TenantShield 0.1.0-dev — localhost:54322/postgres
      Findings: 1 critical, 0 high, 0 medium, 0 low, 0 info
      Resources: public.invoices
      Cases: 3 passed, 0 failed, 0 errors, 1 skipped — INCOMPLETE

      public.invoices
        CRITICAL TS-RLS-001 Exposed table without RLS
          Enable RLS.

      Warning: Triggers may have external side effects."
    `);
  });

  it('writes valid JSON atomically', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'tenantshield-report-'));
    const path = join(directory, 'report.json');
    await writeJsonReport(path, report);
    expect(reportSchema.parse(JSON.parse(await readFile(path, 'utf8')))).toEqual(report);
  });

  it('replaces existing text reports with private file permissions', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'tenantshield-report-'));
    const path = join(directory, 'report.html');
    await writeFile(path, 'old', { mode: 0o644 });
    await writeTextReport(path, '<html>safe</html>');
    expect(await readFile(path, 'utf8')).toBe('<html>safe</html>');
    expect((await stat(path)).mode & 0o777).toBe(0o600);
  });

  it('redacts sensitive finding text before saving JSON', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'tenantshield-report-'));
    const path = join(directory, 'report.json');
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature';
    const sensitive: TenantShieldReport = {
      ...report,
      findings: [
        fingerprinted({
          ...report.findings[0]!,
          table: jwt,
          observed: 'postgres://alice:password@localhost/postgres',
        }),
      ],
    };
    await writeJsonReport(path, sensitive);
    const saved = await readFile(path, 'utf8');
    expect(saved).not.toContain('password');
    expect(saved).not.toContain(jwt);
    expect(saved).toContain('[REDACTED]');
  });

  it('redacts sensitive finding text when rendering JSON to stdout', () => {
    const sensitive: TenantShieldReport = {
      ...report,
      findings: [
        fingerprinted({
          ...report.findings[0]!,
          observed: 'postgres://alice:password@localhost/postgres',
        }),
      ],
    };
    const output = renderJson(sensitive);
    expect(output).not.toContain('password');
    expect(output).toContain('[REDACTED]');
    expect(reportSchema.parse(JSON.parse(output))).toBeDefined();
  });

  it('renders standalone escaped HTML', () => {
    const html = renderHtml({ ...report, warnings: ['<script>alert(1)</script>'] });
    expect(html).toContain('<!doctype html>');
    expect(html).not.toContain('<script>alert(1)</script>');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
    expect(html).not.toMatch(/<link|<img/i);
  });

  it('renders SARIF 2.1.0 with stable fingerprints', () => {
    const sarif = JSON.parse(renderSarif(report)) as Record<string, unknown>;
    expect(sarif).toMatchObject({
      version: '2.1.0',
      runs: [{ tool: { driver: { name: 'TenantShield' } } }],
    });
    expect(JSON.stringify(sarif)).toContain('TS-RLS-001');
    expect(JSON.stringify(sarif)).toContain('tenantshieldFingerprint');
  });

  it('deep-redacts sensitive identity fields in HTML and SARIF', () => {
    const sensitive: TenantShieldReport = {
      ...report,
      findings: [
        fingerprinted({
          ...report.findings[0]!,
          table: 'postgres://alice:password@localhost/postgres',
        }),
      ],
    };
    for (const output of [renderHtml(sensitive), renderSarif(sensitive)]) {
      expect(output).not.toContain('password');
      expect(output).toContain('[REDACTED]');
    }
  });

  it('redacts connection credentials, JWTs, and common secret assignments', () => {
    const jwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature';
    const input = `postgres://alice:password@localhost/db token=${jwt} password=hunter2 "api_key": "json-secret"`;
    const output = redactText(input);
    expect(output).not.toContain('password');
    expect(output).not.toContain(jwt);
    expect(output).not.toContain('json-secret');
    expect(output).toContain('[REDACTED]');
  });

  it('redacts five-segment JWE tokens completely', () => {
    const jwe =
      'eyJhbGciOiJSU0EtTjVDIiwiZW5jIjoiQTEyOEdDTSIsImtpZCI6IjEifQ.encrypted-key.iv.ciphertext.tag';
    expect(redactText(`authorization=${jwe}`)).not.toContain(jwe);
    expect(redactText(`authorization=${jwe}`)).toBe('authorization=[REDACTED]');
    expect(redactText(`prefix ${jwe} suffix`)).toBe('prefix [REDACTED] suffix');
  });

  it('redacts signature-less JWTs without a signature segment', () => {
    const unsigned = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0';
    expect(redactText(`Bearer ${unsigned}`)).toBe('Bearer [REDACTED]');
    expect(redactText('Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.')).toBe('Bearer [REDACTED].');
  });

  it('redacts PASETO tokens including their footer segment', () => {
    const paseto = 'v4.local.8V3LkM8sMAS8slQ7gG9RxjXPsWbXOMUB8xFfUaRIudBOcHahzCFtSNzsASa8x1gC';
    const footered = `${paseto}.c3RhdGljLWZvb3Rlcg`;
    expect(redactText(`paseto=${footered}`)).toBe('paseto=[REDACTED]');
    expect(redactText(`paseto=${paseto}`)).toBe('paseto=[REDACTED]');
    expect(redactText('token v3.public.payload-only here')).toBe('token [REDACTED] here');
  });

  it('neutralizes control characters in terminal output', () => {
    const malicious = {
      ...report,
      findings: [
        fingerprinted({
          ...report.findings[0]!,
          table: 'invoices\u001b[31m\nforged',
          title: 'unsafe\u0007title\u202ereversed\u009bcontrol',
        }),
      ],
    };
    const output = renderTerminal(malicious);
    expect(output).not.toContain('\u001b');
    expect(output).not.toContain('\u0007');
    expect(output).not.toContain('\u202e');
    expect(output).not.toContain('\u009b');
    expect(output).not.toContain('\nforged');
    expect(output).toContain('invoices�[31m�forged');
  });

  it('neutralizes control characters in tested resource names', () => {
    const output = renderTerminal({
      ...report,
      execution: { ...report.execution, testedResources: ['public.invoices\u001b[31m\nforged'] },
    });
    expect(output).not.toContain('\u001b');
    expect(output).not.toContain('\nforged');
    expect(output).toContain('Resources: public.invoices\uFFFD[31m\uFFFDforged');
  });

  it('maps medium findings to SARIF warnings and low findings to notes', () => {
    const severityReport: TenantShieldReport = {
      ...report,
      findings: ['medium', 'low'].map((severity) =>
        fingerprinted({
          ...report.findings[0]!,
          ruleId: `TS-TEST-${severity}`,
          severity: severity as Finding['severity'],
        }),
      ),
    };
    const sarif = JSON.parse(renderSarif(severityReport)) as {
      runs: { results: { level: string; ruleId: string }[] }[];
    };
    const levels = Object.fromEntries(
      sarif.runs[0]!.results.map((result) => [result.ruleId, result.level]),
    );
    expect(levels['TS-TEST-medium']).toBe('warning');
    expect(levels['TS-TEST-low']).toBe('note');
  });

  it('labels findings without a table or schema with fallback resource names', () => {
    const sparseReport: TenantShieldReport = {
      ...report,
      findings: [
        fingerprinted({ ...report.findings[0]!, table: undefined }),
        fingerprinted({
          ...report.findings[0]!,
          ruleId: 'TS-TEST-DB',
          schema: undefined,
          table: undefined,
        }),
      ],
    };
    const sarif = JSON.parse(renderSarif(sparseReport)) as {
      runs: { results: { properties: { resource: string }; ruleId: string }[] }[];
    };
    const resources = Object.fromEntries(
      sarif.runs[0]!.results.map((result) => [result.ruleId, result.properties.resource]),
    );
    expect(resources['TS-RLS-001']).toBe('public');
    expect(resources['TS-TEST-DB']).toBe('Database');
  });

  it('cleans up the temporary file and rethrows when the report cannot be moved', async () => {
    const directory = await mkdtemp(join(tmpdir(), 'tenantshield-report-'));
    const path = join(directory, 'report.json');
    await mkdir(path); // A directory at the destination makes rename fail.
    await expect(writeTextReport(path, '<html>safe</html>')).rejects.toThrow();
    const leftovers = await readdir(directory);
    expect(leftovers).toEqual(['report.json']);
  });
});
