import { createHash } from 'node:crypto';
import { z } from 'zod';

export const severitySchema = z.enum(['info', 'low', 'medium', 'high', 'critical']);
export const confidenceSchema = z.enum(['low', 'medium', 'high']);
export const findingSourceSchema = z.enum(['static', 'dynamic']);
export const operationSchema = z.enum(['select', 'insert', 'update', 'delete', 'execute']);

export const findingSchema = z
  .object({
    ruleId: z.string().trim().min(1),
    title: z.string().trim().min(1),
    severity: severitySchema,
    confidence: confidenceSchema,
    source: findingSourceSchema,
    schema: z.string().trim().min(1).optional(),
    table: z.string().trim().min(1).optional(),
    function: z.string().trim().min(1).optional(),
    policy: z.string().trim().min(1).optional(),
    role: z.string().trim().min(1).optional(),
    operation: operationSchema.optional(),
    identity: z.string().trim().min(1).optional(),
    testedTenant: z.string().trim().min(1).optional(),
    expected: z.string().trim().min(1),
    observed: z.string().trim().min(1),
    reproduction: z
      .object({
        command: z.string().trim().min(1),
        details: z.string().trim().min(1),
      })
      .strict(),
    remediation: z.string().trim().min(1),
    documentationUrl: z.url(),
    location: z
      .object({ file: z.string().trim().min(1), startLine: z.number().int().positive() })
      .optional(),
    fingerprint: z.string().regex(/^[a-f0-9]{64}$/),
  })
  .strict();

export type Finding = z.infer<typeof findingSchema>;
export type Severity = z.infer<typeof severitySchema>;

export const scanMetadataSchema = z
  .object({
    toolVersion: z.string().trim().min(1),
    startedAt: z.iso.datetime(),
    completedAt: z.iso.datetime(),
    gitCommit: z.string().min(1).optional(),
    target: z
      .object({
        host: z.string().trim().min(1),
        port: z.number().int().min(1).max(65_535).optional(),
        database: z.string().trim().min(1),
        serverVersion: z.string().trim().min(1).optional(),
      })
      .strict(),
  })
  .strict()
  .superRefine((metadata, context) => {
    if (Date.parse(metadata.completedAt) < Date.parse(metadata.startedAt)) {
      context.addIssue({
        code: 'custom',
        path: ['completedAt'],
        message: 'completedAt must not precede startedAt',
      });
    }
  });

export const executionSummarySchema = z
  .object({
    mode: z.enum(['scan', 'test']),
    testedResources: z.array(z.string().trim().min(1)),
    testedMatrix: z
      .array(
        z.object({
          resource: z.string().trim().min(1),
          role: z.string().trim().min(1),
          operations: z.array(z.enum(['select', 'insert', 'update', 'delete'])),
          status: z.enum(['passed', 'failed', 'error', 'skipped']),
        }),
      )
      .optional(),
    cases: z
      .array(
        z.object({
          id: z.string().trim().min(1),
          resource: z.string().trim().min(1),
          schema: z.string().trim().min(1),
          table: z.string().trim().min(1),
          operation: z.enum(['select', 'insert', 'update', 'delete']),
          identity: z.string().trim().min(1),
          control: z.enum(['same', 'foreign']),
          status: z.enum(['passed', 'failed', 'error', 'skipped']),
          observed: z.string().trim().min(1),
          scenario: z.string().optional(),
        }),
      )
      .optional(),
    totalCases: z.number().int().nonnegative(),
    passedCases: z.number().int().nonnegative(),
    failedCases: z.number().int().nonnegative(),
    errorCases: z.number().int().nonnegative(),
    skippedCases: z.number().int().nonnegative(),
    complete: z.boolean(),
  })
  .strict()
  .superRefine((summary, context) => {
    const counted =
      summary.passedCases + summary.failedCases + summary.errorCases + summary.skippedCases;
    if (counted !== summary.totalCases) {
      context.addIssue({
        code: 'custom',
        path: ['totalCases'],
        message: 'Case counts must add up to totalCases',
      });
    }
    if (summary.complete && (summary.errorCases > 0 || summary.skippedCases > 0)) {
      context.addIssue({
        code: 'custom',
        path: ['complete'],
        message: 'Complete execution cannot contain errored or skipped cases',
      });
    }
    if (summary.mode === 'scan' && (summary.totalCases !== 0 || !summary.complete)) {
      context.addIssue({
        code: 'custom',
        path: ['mode'],
        message: 'Scan execution must be complete and contain no dynamic cases',
      });
    }
    if (summary.cases) {
      if (summary.cases.length !== summary.totalCases) {
        context.addIssue({
          code: 'custom',
          path: ['cases'],
          message: 'Serialized case count must equal totalCases',
        });
      }
      if (new Set(summary.cases.map((testCase) => testCase.id)).size !== summary.cases.length) {
        context.addIssue({
          code: 'custom',
          path: ['cases'],
          message: 'Serialized case IDs must be unique',
        });
      }
      const serializedCounts = {
        passed: summary.cases.filter((testCase) => testCase.status === 'passed').length,
        failed: summary.cases.filter((testCase) => testCase.status === 'failed').length,
        error: summary.cases.filter((testCase) => testCase.status === 'error').length,
        skipped: summary.cases.filter((testCase) => testCase.status === 'skipped').length,
      };
      const summaryCountByStatus = {
        passed: 'passedCases',
        failed: 'failedCases',
        error: 'errorCases',
        skipped: 'skippedCases',
      } as const;
      for (const status of Object.keys(serializedCounts) as Array<keyof typeof serializedCounts>) {
        const summaryCount = summaryCountByStatus[status];
        if (serializedCounts[status] !== summary[summaryCount]) {
          context.addIssue({
            code: 'custom',
            path: ['cases'],
            message: `Serialized ${status} case count does not match execution summary`,
          });
        }
      }
    }
  });

export type ExecutionSummary = z.infer<typeof executionSummarySchema>;

export const reportSchema = z
  .object({
    version: z.literal(1),
    metadata: scanMetadataSchema,
    staticAuditExecuted: z.boolean().optional(),
    catalogTables: z.array(z.string().trim().min(1)).optional(),
    catalogComplete: z.boolean().optional(),
    execution: executionSummarySchema,
    findings: z.array(findingSchema),
    warnings: z.array(z.string()),
  })
  .strict()
  .superRefine((report, context) => {
    report.findings.forEach((finding, index) => {
      if (finding.fingerprint !== createFindingFingerprint(finding)) {
        context.addIssue({
          code: 'custom',
          path: ['findings', index, 'fingerprint'],
          message: 'Fingerprint does not match finding identity',
        });
      }
    });
  });

export type TenantShieldReport = z.infer<typeof reportSchema>;

const severityRank: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

type FingerprintInput = Omit<Finding, 'fingerprint'> | Finding;

export function createFindingFingerprint(finding: FingerprintInput): string {
  const identity = {
    ruleId: finding.ruleId,
    source: finding.source,
    schema: finding.schema ?? null,
    table: finding.table ?? null,
    ...(finding.function ? { function: finding.function } : {}),
    policy: finding.policy ?? null,
    role: finding.role ?? null,
    operation: finding.operation ?? null,
    identity: finding.identity ?? null,
    testedTenant: finding.testedTenant ?? null,
  };
  return createHash('sha256').update(JSON.stringify(identity)).digest('hex');
}

export function failureThresholdMet(findings: readonly Finding[], threshold: Severity): boolean {
  return findings.some((finding) => severityRank[finding.severity] >= severityRank[threshold]);
}
