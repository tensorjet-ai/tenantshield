import { randomUUID } from 'node:crypto';
import { rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import {
  createFindingFingerprint,
  failureThresholdMet,
  reportSchema,
  type Finding,
  type Severity,
  type TenantShieldReport,
} from '@tenantshield/findings';

const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function redactText(input: string): string {
  return (
    input
      .replace(/postgres(?:ql)?:\/\/[^\s]+/gi, 'postgres://[REDACTED]')
      // JWT/JWE: header.payload plus any further segments, so 3-segment JWS,
      // 5-segment JWE, and signature-less header.payload tokens all match.
      .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\b/g, '[REDACTED]')
      // PASETO: vN.local or vN.public payload with an optional footer segment.
      .replace(/\bv[0-9]\.(?:local|public)\.[A-Za-z0-9_-]+\.?[A-Za-z0-9_-]*/g, '[REDACTED]')
      .replace(
        /["']?(?:password|passwd|token|secret|api[_-]?key)["']?\s*[:=]\s*(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,}\]]+)/gi,
        '[REDACTED]',
      )
  );
}

export function sanitizeTerminalText(input: string): string {
  return [...input]
    .map((character) => {
      const code = character.codePointAt(0) ?? 0;
      const unsafeControl =
        code < 0x20 ||
        (code >= 0x7f && code <= 0x9f) ||
        code === 0x061c ||
        (code >= 0x200b && code <= 0x200f) ||
        (code >= 0x202a && code <= 0x202e) ||
        (code >= 0x2060 && code <= 0x206f) ||
        (code >= 0xfff9 && code <= 0xfffb) ||
        code === 0xfeff;
      return unsafeControl ? '�' : character;
    })
    .join('');
}

function terminalText(input: string): string {
  return sanitizeTerminalText(redactText(input));
}

function resourceName(finding: Finding): string {
  if (finding.schema && finding.function) return `${finding.schema}.${finding.function}`;
  if (finding.schema && finding.table) return `${finding.schema}.${finding.table}`;
  if (finding.schema) return finding.schema;
  return 'Database';
}

export function renderTerminal(input: TenantShieldReport): string {
  const report = redactedReport(input);
  const target = report.metadata.target;
  const host = `${target.host}${target.port ? `:${target.port}` : ''}/${target.database}`;
  const counts = new Map(SEVERITIES.map((severity) => [severity, 0]));
  for (const finding of report.findings)
    counts.set(finding.severity, (counts.get(finding.severity) ?? 0) + 1);
  const lines = [
    terminalText(`TenantShield ${report.metadata.toolVersion} — ${host}`),
    `Findings: ${SEVERITIES.map((severity) => `${counts.get(severity)} ${severity}`).join(', ')}`,
    terminalText(`Resources: ${report.execution.testedResources.join(', ') || 'none'}`),
    `Cases: ${report.execution.passedCases} passed, ${report.execution.failedCases} failed, ${report.execution.errorCases} errors, ${report.execution.skippedCases} skipped — ${report.execution.complete ? 'COMPLETE' : 'INCOMPLETE'}`,
  ];
  const groups = new Map<string, Finding[]>();
  for (const finding of report.findings) {
    const name = resourceName(finding);
    groups.set(name, [...(groups.get(name) ?? []), finding]);
  }
  for (const [name, findings] of groups) {
    lines.push('', terminalText(name));
    for (const finding of findings) {
      lines.push(
        terminalText(`  ${finding.severity.toUpperCase()} ${finding.ruleId} ${finding.title}`),
      );
      lines.push(`    ${terminalText(finding.remediation)}`);
    }
  }
  for (const warning of report.warnings) lines.push('', `Warning: ${terminalText(warning)}`);
  return lines.join('\n');
}

export function redactValue(value: unknown): unknown {
  if (typeof value === 'string') return redactText(value);
  if (Array.isArray(value)) return value.map(redactValue);
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, child]) => [key, redactValue(child)]),
    );
  }
  return value;
}

function redactedReport(input: TenantShieldReport): TenantShieldReport {
  const redacted = redactValue(reportSchema.parse(input)) as TenantShieldReport;
  return reportSchema.parse({
    ...redacted,
    findings: redacted.findings.map((finding) => ({
      ...finding,
      fingerprint: createFindingFingerprint(finding),
    })),
  });
}

export function renderJson(input: TenantShieldReport): string {
  return `${JSON.stringify(redactedReport(input), null, 2)}\n`;
}

export function renderMarkdown(
  input: TenantShieldReport,
  baselineInput?: TenantShieldReport,
  failOn: Severity = 'high',
): string {
  const report = redactedReport(input);
  const baseline = baselineInput ? redactedReport(baselineInput) : undefined;
  const current = new Map(report.findings.map((finding) => [finding.fingerprint, finding]));
  const previous = new Map(
    (baseline?.findings ?? []).map((finding) => [finding.fingerprint, finding]),
  );
  const added = report.findings.filter((finding) => !previous.has(finding.fingerprint));
  const resolved = (baseline?.findings ?? []).filter(
    (finding) => !current.has(finding.fingerprint),
  );
  const status =
    report.execution.complete && !failureThresholdMet(report.findings, failOn) ? 'PASS' : 'FAIL';
  const lines = [
    `## TenantShield: ${status}`,
    '',
    `**${report.findings.length} findings** · ${report.execution.passedCases} passed · ${report.execution.failedCases} failed · ${report.execution.errorCases} errors${baseline ? ` · ${added.length} new · ${resolved.length} resolved` : ''}`,
    '',
    '### New findings',
    ...(added.length
      ? added.map(
          (finding) =>
            `- **${finding.severity.toUpperCase()} ${finding.ruleId}** ${finding.title} — ${resourceName(finding)}`,
        )
      : ['- None']),
    ...(baseline
      ? [
          '',
          '### Resolved findings',
          ...(resolved.length
            ? resolved.map(
                (finding) => `- **${finding.ruleId}** ${finding.title} — ${resourceName(finding)}`,
              )
            : ['- None']),
        ]
      : []),
    '',
    '### Role × Resource × Tested CRUD',
    '',
    '| Resource | Role | CRUD status |',
    '|---|---|---|',
    ...(report.execution.testedMatrix?.length
      ? report.execution.testedMatrix.map(
          (row) =>
            `| ${row.resource} | ${row.role} | ${row.operations.join(', ').toUpperCase()} — ${row.status} |`,
        )
      : ['| — | — | No dynamic cases recorded |']),
    '',
  ];
  return `${redactText(lines.join('\n'))}\n`;
}

export async function writeJsonReport(path: string, input: TenantShieldReport): Promise<void> {
  const report = redactedReport(input);
  await writeTextReport(path, `${JSON.stringify(report, null, 2)}\n`);
}

export async function writeTextReport(path: string, output: string): Promise<void> {
  const temporary = join(dirname(path), `.${randomUUID()}.tenantshield.tmp`);
  try {
    await writeFile(temporary, output, {
      encoding: 'utf8',
      mode: 0o600,
    });
    await rename(temporary, path);
  } catch (error) {
    try {
      await rm(temporary, { force: true });
    } catch {
      // Preserve the original write/rename failure; cleanup is best effort.
    }
    throw error;
  }
}

function escapeHtml(input: string): string {
  return input
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

export function renderHtml(input: TenantShieldReport): string {
  const report = redactedReport(input);
  const counts = SEVERITIES.map((severity) => {
    const count = report.findings.filter((finding) => finding.severity === severity).length;
    return `<li><strong>${count}</strong> ${severity}</li>`;
  }).join('');
  const findings = report.findings
    .map(
      (finding) => `<article class="finding ${finding.severity}">
  <header><span>${escapeHtml(finding.severity.toUpperCase())}</span> <code>${escapeHtml(finding.ruleId)}</code></header>
  <h2>${escapeHtml(finding.title)}</h2>
  <p><strong>Resource:</strong> ${escapeHtml(resourceName(finding))}</p>
  <dl><dt>Expected</dt><dd>${escapeHtml(redactText(finding.expected))}</dd><dt>Observed</dt><dd>${escapeHtml(redactText(finding.observed))}</dd></dl>
  <p><strong>Remediation:</strong> ${escapeHtml(redactText(finding.remediation))}</p>
  <p><strong>Reproduce:</strong> <code>${escapeHtml(redactText(finding.reproduction.command))}</code> — ${escapeHtml(redactText(finding.reproduction.details))}</p>
</article>`,
    )
    .join('\n');
  const warnings = report.warnings
    .map((warning) => `<li>${escapeHtml(redactText(warning))}</li>`)
    .join('');
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TenantShield report</title><style>
:root{color-scheme:light dark;font-family:ui-sans-serif,system-ui,sans-serif}body{max-width:960px;margin:0 auto;padding:2rem;line-height:1.5}ul.summary{display:flex;gap:1.25rem;list-style:none;padding:0}.finding{border:1px solid #7776;border-left-width:.4rem;border-radius:.4rem;padding:1rem;margin:1rem 0}.critical{border-left-color:#d20}.high{border-left-color:#e70}.medium{border-left-color:#db0}.low{border-left-color:#29c}.info{border-left-color:#777}code{overflow-wrap:anywhere}dt{font-weight:700}dd{margin:0 0 .5rem}
</style></head><body>
<h1>TenantShield report</h1><p>${escapeHtml(report.metadata.target.host)}/${escapeHtml(report.metadata.target.database)} · ${escapeHtml(report.metadata.completedAt)}</p>
<ul class="summary">${counts}</ul>
<p><strong>Resources:</strong> ${escapeHtml(report.execution.testedResources.join(', ') || 'none')}</p>
<p><strong>Cases:</strong> ${report.execution.passedCases} passed, ${report.execution.failedCases} failed, ${report.execution.errorCases} errors, ${report.execution.skippedCases} skipped — ${report.execution.complete ? 'complete' : 'incomplete'}</p>
${findings || '<p>No findings met the scan criteria.</p>'}
${warnings ? `<section><h2>Safety warnings</h2><ul>${warnings}</ul></section>` : ''}
<footer><p>TenantShield findings are evidence, not a formal security audit or proof.</p></footer>
</body></html>\n`;
}

function sarifLevel(severity: Severity): 'error' | 'warning' | 'note' {
  if (severity === 'critical' || severity === 'high') return 'error';
  if (severity === 'medium') return 'warning';
  return 'note';
}

export function renderSarif(input: TenantShieldReport): string {
  const report = redactedReport(input);
  const rules = [
    ...new Map(report.findings.map((finding) => [finding.ruleId, finding])).values(),
  ].map((finding) => ({
    id: finding.ruleId,
    name: finding.title.replaceAll(/[^A-Za-z0-9]+/g, '-').replaceAll(/^-|-$/g, ''),
    shortDescription: { text: finding.title },
    helpUri: finding.documentationUrl,
    defaultConfiguration: { level: sarifLevel(finding.severity) },
  }));
  const sarif = {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: { driver: { name: 'TenantShield', version: report.metadata.toolVersion, rules } },
        results: report.findings.map((finding) => ({
          ruleId: finding.ruleId,
          level: sarifLevel(finding.severity),
          message: {
            text: `${finding.title}: ${redactText(finding.observed)}. ${redactText(finding.remediation)}`,
          },
          ...(finding.location
            ? {
                locations: [
                  {
                    physicalLocation: {
                      artifactLocation: { uri: finding.location.file.replaceAll('\\', '/') },
                      region: { startLine: finding.location.startLine },
                    },
                  },
                ],
              }
            : {}),
          partialFingerprints: { tenantshieldFingerprint: finding.fingerprint },
          properties: {
            confidence: finding.confidence,
            source: finding.source,
            resource: resourceName(finding),
            operation: finding.operation,
          },
        })),
      },
    ],
  };
  return `${JSON.stringify(sarif, null, 2)}\n`;
}
