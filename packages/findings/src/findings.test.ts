import { describe, expect, it } from 'vitest';
import {
  createFindingFingerprint,
  failureThresholdMet,
  reportSchema,
  type Finding,
} from './index.js';

const finding: Finding = {
  ruleId: 'TS-RLS-001',
  title: 'Exposed table without RLS',
  severity: 'high',
  confidence: 'high',
  source: 'static',
  schema: 'public',
  table: 'invoices',
  operation: 'select',
  expected: 'RLS enabled',
  observed: 'RLS disabled',
  reproduction: { command: 'tenantshield scan', details: 'public.invoices' },
  remediation: 'Enable and force RLS, then add scoped policies.',
  documentationUrl: 'https://example.invalid/rules/TS-RLS-001',
  fingerprint: '',
};

function validReport() {
  return {
    version: 1 as const,
    metadata: {
      toolVersion: '0.1.0-dev',
      startedAt: '2026-07-16T00:00:00.000Z',
      completedAt: '2026-07-16T00:00:01.000Z',
      target: { host: 'localhost', database: 'postgres' },
    },
    findings: [{ ...finding, fingerprint: createFindingFingerprint(finding) }],
    warnings: [],
    execution: {
      mode: 'test' as const,
      testedResources: ['public.invoices'],
      totalCases: 4,
      passedCases: 3,
      failedCases: 0,
      errorCases: 0,
      skippedCases: 1,
      complete: false,
    },
  };
}

describe('finding contract', () => {
  it('creates stable fingerprints independent of prose and object order', () => {
    const a = createFindingFingerprint(finding);
    const b = createFindingFingerprint({
      ...finding,
      title: 'Changed prose',
      remediation: 'Changed',
    });
    expect(a).toBe(b);
    expect(a).toMatch(/^[a-f0-9]{64}$/);
  });

  it('preserves version 1 fingerprints for non-function findings', () => {
    expect(createFindingFingerprint(finding)).toBe(
      '5888bafee2be59bc1a3126982a4bc54734f87eddce1bf637bf6b8a25f3878fee',
    );
  });

  it('applies inclusive severity thresholds', () => {
    expect(failureThresholdMet([finding], 'high')).toBe(true);
    expect(failureThresholdMet([finding], 'critical')).toBe(false);
    expect(failureThresholdMet([], 'low')).toBe(false);
  });

  it('round-trips a versioned report', () => {
    const report = validReport();
    expect(reportSchema.parse(JSON.parse(JSON.stringify(report)))).toEqual(report);
  });

  it.each(['severity', 'confidence', 'source', 'ruleId', 'expected', 'observed'])(
    'rejects invalid %s',
    (field) => {
      const invalid = { ...finding, fingerprint: 'a'.repeat(64), [field]: '' };
      expect(() => reportSchema.shape.findings.element.parse(invalid)).toThrow();
    },
  );

  it('rejects inconsistent execution totals', () => {
    const execution = {
      mode: 'test',
      testedResources: ['public.invoices'],
      totalCases: 4,
      passedCases: 4,
      failedCases: 0,
      errorCases: 0,
      skippedCases: 1,
      complete: false,
    };
    expect(() => reportSchema.shape.execution.parse(execution)).toThrow(/add up/i);
  });

  it('rejects a complete execution containing errored or skipped cases', () => {
    const report = validReport();
    report.execution.complete = true;
    expect(() => reportSchema.parse(report)).toThrow(/complete/i);
  });

  it('rejects scan execution summaries containing dynamic cases', () => {
    const report = validReport();
    const invalid = {
      ...report,
      execution: { ...report.execution, mode: 'scan' as const, complete: true },
    };
    expect(() => reportSchema.parse(invalid)).toThrow(/scan/i);
  });

  it('rejects a fingerprint that does not match finding identity', () => {
    const report = validReport();
    report.findings[0]!.fingerprint = 'a'.repeat(64);
    expect(() => reportSchema.parse(report)).toThrow(/fingerprint/i);
  });

  it('rejects completion timestamps before start timestamps', () => {
    const report = validReport();
    report.metadata.completedAt = '2026-07-15T23:59:59.000Z';
    expect(() => reportSchema.parse(report)).toThrow(/completedAt/i);
  });

  it('rejects impossible database ports', () => {
    const report = validReport();
    expect(() =>
      reportSchema.parse({
        ...report,
        metadata: {
          ...report.metadata,
          target: { ...report.metadata.target, port: 70_000 },
        },
      }),
    ).toThrow();
  });
});
