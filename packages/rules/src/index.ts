import type {
  CatalogFunction,
  CatalogSnapshot,
  CatalogTable,
  CatalogView,
} from '@tenantshield/catalog';
import type { TenantShieldConfig } from '@tenantshield/config';
import { createFindingFingerprint, type Finding } from '@tenantshield/findings';

type FindingWithoutFingerprint = Omit<Finding, 'fingerprint'>;

const DOCS_BASE = 'https://github.com/tenantshield/tenantshield#';

function finding(input: FindingWithoutFingerprint): Finding {
  return { ...input, fingerprint: createFindingFingerprint(input) };
}

function reproduction(table: CatalogTable, details: string): Finding['reproduction'] {
  return { command: 'tenantshield scan', details: `${table.schema}.${table.name}: ${details}` };
}

function configuredResource(
  config: TenantShieldConfig,
  resourceObject: { schema: string; name: string },
) {
  return Object.entries(config.resources).find(([name, resource]) => {
    return name === resourceObject.name && (resource.schema ?? 'public') === resourceObject.schema;
  })?.[1];
}

function hasDataApiTableAccess(table: CatalogTable): boolean {
  return table.grants.some(
    (grant) =>
      ['public', 'anon', 'authenticated'].includes(grant.role) &&
      grant.privileges.some((privilege) =>
        ['select', 'insert', 'update', 'delete'].includes(privilege),
      ),
  );
}

type TopLevelOccurrence = { index: number; text: string };

const REQUEST_IDENTITY_PATTERN =
  /auth\s*\.\s*(?:uid|jwt)\s*\(|current_setting\s*\(\s*['"]request\.jwt\./i;

const BOOLEAN_CONNECTIVE_PATTERN = /\b(?:and|or|not)\b/;

function topLevelOccurrences(expression: string, pattern: RegExp): TopLevelOccurrence[] {
  const occurrences: TopLevelOccurrence[] = [];
  const matcher = new RegExp(
    pattern.source,
    pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`,
  );
  let depth = 0;
  let quote: string | null = null;
  for (let i = 0; i < expression.length; i += 1) {
    const char = expression[i]!;
    if (quote) {
      if (char === quote) {
        if (expression[i + 1] === quote) i += 1;
        else quote = null;
      }
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (char === '(') {
      depth += 1;
      continue;
    }
    if (char === ')') {
      depth = Math.max(0, depth - 1);
      continue;
    }
    if (depth !== 0) continue;
    matcher.lastIndex = i;
    const match = matcher.exec(expression);
    if (!match || match.index !== i) continue;
    occurrences.push({ index: i, text: match[0] });
    for (const matched of match[0]) {
      if (matched === '(') depth += 1;
      if (matched === ')') depth -= 1;
    }
    i += match[0].length - 1;
  }
  return occurrences;
}

function splitTopLevel(expression: string, pattern: RegExp): string[] {
  const parts: string[] = [];
  let cursor = 0;
  for (const { index, text } of topLevelOccurrences(expression, pattern)) {
    parts.push(expression.slice(cursor, index));
    cursor = index + text.length;
  }
  parts.push(expression.slice(cursor));
  return parts;
}

function balancedGroupEnd(expression: string, openIndex: number): number {
  let depth = 0;
  let quote: string | null = null;
  for (let i = openIndex; i < expression.length; i += 1) {
    const char = expression[i]!;
    if (quote) {
      if (char === quote) {
        if (expression[i + 1] === quote) i += 1;
        else quote = null;
      }
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (char === '(') depth += 1;
    if (char === ')') {
      depth -= 1;
      if (depth === 0) return i;
    }
  }
  return -1;
}

function stripOuterParens(expression: string): string {
  let current = expression.trim();
  while (current.startsWith('(') && balancedGroupEnd(current, 0) === current.length - 1) {
    current = current.slice(1, -1).trim();
  }
  return current;
}

function stripTrailingCasts(operand: string): string {
  let current = operand.trim();
  for (;;) {
    const match = current.match(
      /::\s*(?:"(?:[^"]|"")+"|[a-z_][\w$]*)(?:\s*\(\s*[^\s()]+\s*\))?(?:\s*\[\s*\])*$/i,
    );
    if (!match || match.index === undefined || match.index === 0) break;
    current = current.slice(0, match.index).trim();
  }
  return current;
}

function stripOperandWrappers(operand: string): string {
  let current = operand.trim();
  for (;;) {
    const stripped = stripOuterParens(stripTrailingCasts(current));
    if (stripped === current) return stripped;
    current = stripped;
  }
}

function hasTopLevelWord(expression: string, word: RegExp): boolean {
  return topLevelOccurrences(expression, word).length > 0;
}

function isTenantOperand(operand: string, tenantColumn: string): boolean {
  const stripped = stripOperandWrappers(operand);
  if (!stripped || hasTopLevelWord(stripped, BOOLEAN_CONNECTIVE_PATTERN)) return false;
  if (
    !/^(?:"(?:[^"]|"")+"|[a-z_][\w$]*)(?:\s*\.\s*(?:"(?:[^"]|"")+"|[a-z_][\w$]*))*$/i.test(stripped)
  ) {
    return false;
  }
  const segments = stripped.split('.').map((segment) => segment.trim().replaceAll('"', ''));
  const column = segments[segments.length - 1]!.toLowerCase();
  return column === tenantColumn.toLowerCase();
}

function isRequestIdentityOperand(operand: string): boolean {
  const stripped = stripOperandWrappers(operand);
  if (!stripped || hasTopLevelWord(stripped, BOOLEAN_CONNECTIVE_PATTERN)) return false;
  return REQUEST_IDENTITY_PATTERN.test(stripped);
}

function isNumericLiteral(operand: string): boolean {
  return /^\d+(?:\.\d+)?$/.test(operand);
}

function isExplicitlyUnconditional(expression: string | null): boolean {
  if (expression === null) return false;
  const normalized = expression.trim().toLowerCase().replaceAll(/\s+/g, ' ');
  const unwrapped = stripOuterParens(normalized);
  if (unwrapped === 'true') return true;
  const comparisonPatterns = [/\bis\s+not\s+distinct\s+from\b/, /=/];
  for (const pattern of comparisonPatterns) {
    for (const { index, text } of topLevelOccurrences(unwrapped, pattern)) {
      const leftText = unwrapped.slice(0, index).trim();
      if (pattern.source === '=' && /[<>!]$/.test(leftText)) continue;
      const left = stripOperandWrappers(leftText);
      const right = stripOperandWrappers(unwrapped.slice(index + text.length));
      if (left && left === right) return true;
      if (isNumericLiteral(left) && isNumericLiteral(right) && Number(left) === Number(right)) {
        return true;
      }
    }
  }
  return false;
}

function effectivePolicyRoles(policy: CatalogTable['policies'][number]): readonly string[] {
  return policy.effectiveRoles ?? policy.roles;
}

type CrudOperation = 'select' | 'insert' | 'update' | 'delete';

function policyAppliesToRole(policy: CatalogTable['policies'][number], role: string): boolean {
  const roles = effectivePolicyRoles(policy);
  return roles.includes('public') || roles.includes(role);
}

function policyAppliesToOperation(
  policy: CatalogTable['policies'][number],
  operation: CrudOperation,
): boolean {
  return policy.command === 'all' || policy.command === operation;
}

function activePolicyPairs(
  table: CatalogTable,
  policy: CatalogTable['policies'][number],
): { role: string; operation: CrudOperation }[] {
  const pairs: { role: string; operation: CrudOperation }[] = [];
  for (const grant of table.grants) {
    if (!['anon', 'authenticated'].includes(grant.role)) continue;
    for (const operation of grant.privileges) {
      if (!['select', 'insert', 'update', 'delete'].includes(operation)) continue;
      const crudOperation = operation as CrudOperation;
      if (
        policyAppliesToRole(policy, grant.role) &&
        policyAppliesToOperation(policy, crudOperation)
      ) {
        pairs.push({ role: grant.role, operation: crudOperation });
      }
    }
  }
  return pairs;
}

function fullyGuardedByRestrictivePolicies(
  table: CatalogTable,
  policy: CatalogTable['policies'][number],
  tenantColumn: string | undefined,
): boolean {
  if (!tenantColumn) return false;
  const pairs = activePolicyPairs(table, policy);
  return (
    pairs.length > 0 &&
    pairs.every(({ role, operation }) =>
      table.policies.some(
        (candidate) =>
          !candidate.permissive &&
          policyAppliesToRole(candidate, role) &&
          policyAppliesToOperation(candidate, operation) &&
          restrictivePolicyGuardsTenant(candidate, operation, tenantColumn),
      ),
    )
  );
}

function termBindsTenantToRequest(term: string, tenantColumn: string): boolean {
  const expression = stripOuterParens(term);
  if (!expression || /^not\b/.test(expression)) return false;

  for (const { index, text } of topLevelOccurrences(expression, /\bexists\s*\(/i)) {
    const openIndex = index + text.lastIndexOf('(');
    const closeIndex = balancedGroupEnd(expression, openIndex);
    if (closeIndex < 0) return false;
    const subquery = expression.slice(openIndex + 1, closeIndex);
    const escapedTenantColumn = tenantColumn.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const innerAliases = new Set<string>();
    const relationPattern =
      /\b(?:from|join)\s+(?:"([^"]+)"|([a-z_][\w$]*))(?:\s*\.\s*(?:"([^"]+)"|([a-z_][\w$]*)))?(?:\s+(?:as\s+)?(?:"([^"]+)"|([a-z_][\w$]*)))?/gi;
    const reservedAliases = new Set([
      'where',
      'join',
      'left',
      'right',
      'full',
      'inner',
      'cross',
      'on',
      'group',
      'order',
      'limit',
    ]);
    for (const relation of subquery.matchAll(relationPattern)) {
      const relationName = (
        relation[3] ??
        relation[4] ??
        relation[1] ??
        relation[2] ??
        ''
      ).toLowerCase();
      const alias = (relation[5] ?? relation[6] ?? '').toLowerCase();
      if (relationName) innerAliases.add(relationName);
      if (alias && !reservedAliases.has(alias)) innerAliases.add(alias);
    }
    const correlatedTenant = new RegExp(
      `(?:"([^"]+)"|([a-z_][\\w$]*))\\s*\\.\\s*(?:"${escapedTenantColumn}"|${escapedTenantColumn})\\b`,
      'i',
    );
    const tenantReference = subquery.match(correlatedTenant);
    const qualifier = (tenantReference?.[1] ?? tenantReference?.[2] ?? '').toLowerCase();
    if (qualifier && !innerAliases.has(qualifier) && REQUEST_IDENTITY_PATTERN.test(subquery))
      return true;
  }

  for (const { index, text } of topLevelOccurrences(expression, /\bis\s+not\s+distinct\s+from\b/)) {
    if (
      (isTenantOperand(expression.slice(0, index), tenantColumn) &&
        isRequestIdentityOperand(expression.slice(index + text.length))) ||
      (isRequestIdentityOperand(expression.slice(0, index)) &&
        isTenantOperand(expression.slice(index + text.length), tenantColumn))
    ) {
      return true;
    }
  }

  for (const { index, text } of topLevelOccurrences(expression, /\bin\s*\(/)) {
    if (/\bnot\s*$/.test(expression.slice(0, index))) continue;
    const openIndex = index + text.length - 1;
    const closeIndex = balancedGroupEnd(expression, openIndex);
    if (closeIndex === -1) return false;
    if (expression.slice(closeIndex + 1).trim()) return false;
    return (
      isTenantOperand(expression.slice(0, index), tenantColumn) &&
      isRequestIdentityOperand(expression.slice(openIndex + 1, closeIndex))
    );
  }

  for (const { index } of topLevelOccurrences(expression, /=/)) {
    if (/[<>!]$/.test(expression.slice(0, index).trimEnd())) continue;
    if (
      (isTenantOperand(expression.slice(0, index), tenantColumn) &&
        isRequestIdentityOperand(expression.slice(index + 1))) ||
      (isRequestIdentityOperand(expression.slice(0, index)) &&
        isTenantOperand(expression.slice(index + 1), tenantColumn))
    ) {
      return true;
    }
  }
  return false;
}

function expressionBindsTenantToRequest(expression: string | null, tenantColumn: string): boolean {
  if (!expression) return false;
  const normalized = expression.trim().toLowerCase().replaceAll(/\s+/g, ' ');
  if (/\bor\b/.test(normalized)) return false;
  return splitTopLevel(normalized, /\band\b/).some((term) =>
    termBindsTenantToRequest(term, tenantColumn),
  );
}

function restrictivePolicyGuardsTenant(
  policy: CatalogTable['policies'][number],
  operation: CrudOperation,
  tenantColumn: string,
): boolean {
  if (operation === 'insert') {
    return expressionBindsTenantToRequest(
      policy.checkExpression ?? policy.usingExpression,
      tenantColumn,
    );
  }
  if (operation === 'select' || operation === 'delete') {
    return expressionBindsTenantToRequest(policy.usingExpression, tenantColumn);
  }
  return (
    expressionBindsTenantToRequest(policy.usingExpression, tenantColumn) &&
    expressionBindsTenantToRequest(policy.checkExpression ?? policy.usingExpression, tenantColumn)
  );
}

function hasUnconditionalPolicyBoundary(policy: CatalogTable['policies'][number]): boolean {
  if (policy.command === 'insert') {
    return policy.checkExpression === null || isExplicitlyUnconditional(policy.checkExpression);
  }

  const usingIsUnconditional =
    policy.usingExpression === null || isExplicitlyUnconditional(policy.usingExpression);
  if (policy.command === 'select' || policy.command === 'delete') return usingIsUnconditional;

  const effectiveCheck = policy.checkExpression ?? policy.usingExpression;
  return (
    usingIsUnconditional || effectiveCheck === null || isExplicitlyUnconditional(effectiveCheck)
  );
}

function lacksEffectiveWriteCheck(policy: CatalogTable['policies'][number]): boolean {
  if (!policy.permissive) return false;
  if (policy.command === 'insert') return policy.checkExpression === null;
  if (policy.command !== 'update' && policy.command !== 'all') return false;
  return (policy.checkExpression ?? policy.usingExpression) === null;
}

function usesUserEditableMetadata(policy: CatalogTable['policies'][number]): boolean {
  return [policy.usingExpression, policy.checkExpression].some((expression) => {
    if (!expression) return false;
    const readsRequestClaims =
      /\bauth\s*\.\s*jwt\s*\(/i.test(expression) ||
      /\bcurrent_setting\s*\(\s*['"]request\.jwt\.claims\b/i.test(expression);
    return (
      /\braw_user_meta_data\b/i.test(expression) ||
      (/\buser_metadata\b/i.test(expression) && readsRequestClaims)
    );
  });
}

function usesDeprecatedAuthHelper(policy: CatalogTable['policies'][number]): boolean {
  return [policy.usingExpression, policy.checkExpression].some(
    (expression) => expression !== null && /\bauth\s*\.\s*(?:role|email)\s*\(/i.test(expression),
  );
}

function rlsDisabledFinding(table: CatalogTable): Finding {
  return finding({
    ruleId: 'TS-RLS-001',
    title: 'Exposed table without RLS',
    severity: 'critical',
    confidence: 'high',
    source: 'static',
    schema: table.schema,
    table: table.name,
    expected: 'RLS enabled on exposed table',
    observed: 'RLS is disabled',
    reproduction: reproduction(table, 'inspect relrowsecurity'),
    remediation: 'Enable RLS and add tenant-scoped policies before granting Data API roles.',
    documentationUrl: `${DOCS_BASE}ts-rls-001`,
  });
}

function exposedForeignTableFinding(table: CatalogTable): Finding {
  const roles = table.grants
    .filter((grant) => ['anon', 'authenticated'].includes(grant.role))
    .map((grant) => grant.role)
    .sort();
  return finding({
    ruleId: 'TS-FT-001',
    title: 'Foreign table is exposed through the Data API',
    severity: 'critical',
    confidence: 'high',
    source: 'static',
    schema: table.schema,
    table: table.name,
    role: roles.join(', '),
    expected: 'Foreign table kept in a private, unexposed schema',
    observed: 'Data API role has access, but foreign tables do not provide RLS',
    reproduction: reproduction(table, 'inspect foreign-table grants and exposed schemas'),
    remediation:
      'Move the foreign table to a private schema and revoke Data API access; expose only filtered data through a secured function when required.',
    documentationUrl: `${DOCS_BASE}ts-ft-001`,
  });
}

function ownerBypassFinding(table: CatalogTable, roles: readonly string[]): Finding {
  return finding({
    ruleId: 'TS-RLS-007',
    title: 'Data API role inherits table ownership and bypasses RLS',
    severity: 'critical',
    confidence: 'high',
    source: 'static',
    schema: table.schema,
    table: table.name,
    role: roles.join(', '),
    expected: 'Forced RLS or no effective Data API ownership',
    observed: 'Table ownership bypasses unforced row-level security',
    reproduction: reproduction(table, 'inspect relowner and relforcerowsecurity'),
    remediation:
      'Transfer table ownership to a non-API migration role or enable FORCE ROW LEVEL SECURITY.',
    documentationUrl: `${DOCS_BASE}ts-rls-007`,
  });
}

function missingPolicyFindings(table: CatalogTable): Finding[] {
  const findings: Finding[] = [];
  for (const grant of table.grants) {
    if (!['public', 'anon', 'authenticated'].includes(grant.role)) continue;
    for (const operation of grant.privileges) {
      if (
        operation !== 'select' &&
        operation !== 'insert' &&
        operation !== 'update' &&
        operation !== 'delete'
      )
        continue;
      const covered = table.policies.some(
        (policy) =>
          policy.permissive &&
          (policy.command === 'all' || policy.command === operation) &&
          (effectivePolicyRoles(policy).includes('public') ||
            effectivePolicyRoles(policy).includes(grant.role)),
      );
      if (covered) continue;
      findings.push(
        finding({
          ruleId: 'TS-RLS-002',
          title: 'Granted operation has no applicable RLS policy',
          severity: 'high',
          confidence: 'high',
          source: 'static',
          schema: table.schema,
          table: table.name,
          role: grant.role,
          operation,
          expected: `Applicable ${operation.toUpperCase()} policy for ${grant.role}`,
          observed: 'No matching policy',
          reproduction: reproduction(table, `${grant.role} has ${operation.toUpperCase()} grant`),
          remediation: `Add a tenant-scoped ${operation.toUpperCase()} policy or revoke the ${operation.toUpperCase()} grant.`,
          documentationUrl: `${DOCS_BASE}ts-rls-002`,
        }),
      );
    }
  }
  return findings;
}

function unconditionalPolicyFindings(table: CatalogTable, tenantColumn?: string): Finding[] {
  const findings: Finding[] = [];
  for (const policy of table.policies) {
    if (effectivePolicyRoles(policy).length === 0) continue;
    if (
      !policy.permissive ||
      activePolicyPairs(table, policy).length === 0 ||
      !hasUnconditionalPolicyBoundary(policy) ||
      fullyGuardedByRestrictivePolicies(table, policy, tenantColumn)
    ) {
      continue;
    }
    findings.push(
      finding({
        ruleId: 'TS-RLS-003',
        title: 'Unconditional effective RLS policy expression',
        severity: 'high',
        confidence: 'high',
        source: 'static',
        schema: table.schema,
        table: table.name,
        policy: policy.name,
        expected: 'Tenant-scoped policy expression',
        observed: 'An effective USING or WITH CHECK boundary is omitted or unconditional true',
        reproduction: reproduction(table, `policy ${policy.name}`),
        remediation:
          'Replace the unconditional expression with an explicit ownership or tenant predicate.',
        documentationUrl: `${DOCS_BASE}ts-rls-003`,
      }),
    );
  }
  return findings;
}

function unintendedRoleFindings(
  table: CatalogTable,
  expectedRoles: ReadonlySet<string>,
): Finding[] {
  const findings: Finding[] = [];
  for (const policy of table.policies) {
    if (!policy.permissive || effectivePolicyRoles(policy).length === 0) continue;
    for (const role of new Set(activePolicyPairs(table, policy).map((pair) => pair.role))) {
      if (expectedRoles.has(role)) continue;
      findings.push(
        finding({
          ruleId: 'TS-RLS-004',
          title: 'Policy grants access to an unintended role',
          severity: 'high',
          confidence: 'medium',
          source: 'static',
          schema: table.schema,
          table: table.name,
          policy: policy.name,
          role,
          expected: `Permissive policy roles limited to ${[...expectedRoles].join(', ')}`,
          observed: `Permissive policy grants access to ${role}`,
          reproduction: reproduction(table, `policy ${policy.name} role ${role}`),
          remediation: 'Restrict the permissive policy TO clause to intended Data API roles.',
          documentationUrl: `${DOCS_BASE}ts-rls-004`,
        }),
      );
    }
  }
  return findings;
}

function userEditableMetadataFindings(table: CatalogTable): Finding[] {
  const findings: Finding[] = [];
  for (const policy of table.policies) {
    if (
      effectivePolicyRoles(policy).length === 0 ||
      activePolicyPairs(table, policy).length === 0 ||
      !usesUserEditableMetadata(policy)
    ) {
      continue;
    }
    findings.push(
      finding({
        ruleId: 'TS-RLS-008',
        title: 'RLS policy trusts user-editable authorization metadata',
        severity: 'high',
        confidence: 'high',
        source: 'static',
        schema: table.schema,
        table: table.name,
        policy: policy.name,
        expected: 'Authorization data sourced from trusted app_metadata or database state',
        observed: 'Policy expression references user-editable user_metadata',
        reproduction: reproduction(table, `policy ${policy.name}`),
        remediation:
          'Move authorization data to app_metadata or trusted database tables and update the policy predicate.',
        documentationUrl: `${DOCS_BASE}ts-rls-008`,
      }),
    );
  }
  return findings;
}

function deprecatedAuthHelperFindings(table: CatalogTable): Finding[] {
  const findings: Finding[] = [];
  for (const policy of table.policies) {
    if (
      effectivePolicyRoles(policy).length === 0 ||
      activePolicyPairs(table, policy).length === 0 ||
      !usesDeprecatedAuthHelper(policy)
    ) {
      continue;
    }
    findings.push(
      finding({
        ruleId: 'TS-RLS-009',
        title: 'RLS policy uses a deprecated Supabase auth helper',
        severity: 'low',
        confidence: 'high',
        source: 'static',
        schema: table.schema,
        table: table.name,
        policy: policy.name,
        expected: 'Native policy TO roles and supported auth.jwt() claims',
        observed: 'Policy expression calls deprecated auth.role() or auth.email()',
        reproduction: reproduction(table, `policy ${policy.name}`),
        remediation:
          'Replace auth.role() with a policy TO clause and auth.email() with the email claim from auth.jwt().',
        documentationUrl: `${DOCS_BASE}ts-rls-009`,
      }),
    );
  }
  return findings;
}

function missingWriteCheckFindings(table: CatalogTable): Finding[] {
  const findings: Finding[] = [];
  for (const policy of table.policies) {
    if (effectivePolicyRoles(policy).length === 0) continue;
    if (
      !lacksEffectiveWriteCheck(policy) ||
      !activePolicyPairs(table, policy).some(
        ({ operation }) => operation === 'insert' || operation === 'update',
      )
    ) {
      continue;
    }
    findings.push(
      finding({
        ruleId: 'TS-RLS-005',
        title: 'Write policy lacks an effective WITH CHECK boundary',
        severity: 'medium',
        confidence: 'high',
        source: 'static',
        schema: table.schema,
        table: table.name,
        policy: policy.name,
        operation: policy.command === 'insert' ? 'insert' : 'update',
        expected: 'Tenant-scoped effective WITH CHECK expression',
        observed: 'No WITH CHECK or inheritable USING expression is defined',
        reproduction: reproduction(table, `policy ${policy.name}`),
        remediation: 'Add a tenant-scoped WITH CHECK expression for inserted or updated rows.',
        documentationUrl: `${DOCS_BASE}ts-rls-005`,
      }),
    );
  }
  return findings;
}

function bypassFinding(snapshot: CatalogSnapshot): Finding | null {
  if (!snapshot.database.isSuperuser && !snapshot.database.canBypassRls) return null;
  return finding({
    ruleId: 'TS-RLS-006',
    title: 'Privileged database connection requires verified role switching',
    severity: 'medium',
    confidence: 'medium',
    source: 'static',
    role: snapshot.database.currentRole,
    expected: 'Verified non-superuser effective role for each dynamic case',
    observed: snapshot.database.isSuperuser
      ? 'Current role is superuser'
      : 'Current role has BYPASSRLS',
    reproduction: {
      command: 'tenantshield doctor',
      details: 'inspect current database role attributes',
    },
    remediation:
      'Use only a disposable local database. Dynamic cases verify the effective role after SET LOCAL ROLE and fail closed.',
    documentationUrl: `${DOCS_BASE}ts-rls-006`,
  });
}

function securityDefinerFinding(fn: CatalogFunction): Finding {
  const signature = `${fn.name}(${fn.identityArguments})`;
  return finding({
    ruleId: 'TS-FN-001',
    title: 'Exposed SECURITY DEFINER function',
    severity: 'high',
    confidence: 'medium',
    source: 'static',
    schema: fn.schema,
    function: signature,
    role: fn.executeRoles.join(', '),
    expected: 'Invoker-security function or no Data API role execution grant',
    observed: `${fn.schema}.${signature} is SECURITY DEFINER`,
    reproduction: {
      command: 'tenantshield scan',
      details: `${fn.schema}.${signature}`,
    },
    remediation:
      'Prefer SECURITY INVOKER, move privileged functions to an unexposed schema, and revoke PUBLIC execution.',
    documentationUrl: `${DOCS_BASE}ts-fn-001`,
  });
}

function truncatePrivilegeRule(ctx: StaticRuleContext): Finding[] {
  const findings: Finding[] = [];
  for (const table of ctx.snapshot.tables) {
    if (table.isForeign || !ctx.snapshot.schemas.includes(table.schema)) continue;
    for (const grant of table.grants) {
      if (
        !['public', 'anon', 'authenticated'].includes(grant.role) ||
        !grant.privileges.includes('truncate')
      )
        continue;
      findings.push(
        finding({
          ruleId: 'TS-RLS-010',
          title: 'TRUNCATE privilege bypasses row-level security',
          severity: grant.role === 'authenticated' ? 'high' : 'critical',
          confidence: 'high',
          source: 'static',
          schema: table.schema,
          table: table.name,
          role: grant.role,
          expected: 'TRUNCATE withheld from Data API roles',
          observed: `${grant.role} can TRUNCATE ${table.schema}.${table.name}; PostgreSQL RLS does not filter TRUNCATE`,
          reproduction: reproduction(table, `${grant.role} has TRUNCATE privilege`),
          remediation: `REVOKE TRUNCATE ON TABLE ${table.schema}.${table.name} FROM anon, authenticated, PUBLIC;`,
          documentationUrl: `${DOCS_BASE}ts-rls-010`,
        }),
      );
    }
  }
  return findings;
}

function securityDefinerSearchPathRule(ctx: StaticRuleContext): Finding[] {
  return ctx.snapshot.functions
    .filter((fn) => {
      if (
        fn.isTrigger ||
        !fn.securityDefiner ||
        !fn.executeRoles.some((role) => ['public', 'anon', 'authenticated'].includes(role))
      )
        return false;
      const setting = fn.proconfig?.find((entry) => /^search_path\s*=/i.test(entry));
      if (!setting) return true;
      const value = setting
        .slice(setting.indexOf('=') + 1)
        .trim()
        .replaceAll('"', '')
        .toLowerCase();
      const schemas = value
        .split(',')
        .map((schema) => schema.trim())
        .filter(Boolean);
      return (
        schemas.length > 0 &&
        !(
          schemas[0] === 'pg_catalog' &&
          schemas.every((schema) => ['pg_catalog', 'pg_temp'].includes(schema))
        )
      );
    })
    .map((fn) =>
      finding({
        ruleId: 'TS-FN-002',
        title: 'SECURITY DEFINER function has an unsafe search_path',
        severity: 'high',
        confidence: 'high',
        source: 'static',
        schema: fn.schema,
        function: `${fn.name}(${fn.identityArguments})`,
        role: fn.executeRoles.join(', '),
        expected: 'Pinned search_path with pg_catalog first and no mutable schemas',
        observed:
          fn.proconfig?.find((entry) => /^search_path\s*=/i.test(entry)) ??
          'search_path is not pinned',
        reproduction: {
          command: 'tenantshield scan',
          details: `${fn.schema}.${fn.name}: inspect proconfig`,
        },
        remediation:
          'Set a safe function search_path such as pg_catalog, pg_temp and schema-qualify application objects.',
        documentationUrl: `${DOCS_BASE}ts-fn-002`,
      }),
    );
}

function storagePolicyRule(ctx: StaticRuleContext): Finding[] {
  const storageTable = ctx.snapshot.tables.find(
    (table) => table.schema === 'storage' && table.name === 'objects',
  );
  if (!storageTable || !ctx.snapshot.storageBuckets) return [];
  const findings: Finding[] = [];
  for (const bucket of ctx.snapshot.storageBuckets) {
    const associated = storageTable.policies.filter((policy) => {
      const expression = `${policy.usingExpression ?? ''} ${policy.checkExpression ?? ''}`;
      const escapeRegex = (value: string) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const bucketId = escapeRegex(bucket.id);
      const bucketName = escapeRegex(bucket.name);
      return new RegExp(
        `(?:bucket_id\\s*=\\s*['"]${bucketId}['"]|bucket_id\\s*=\\s*['"]${bucketName}['"])`,
        'i',
      ).test(expression);
    });
    const scoped = associated.some((policy) =>
      /auth\s*\.\s*(?:uid|jwt)\s*\(|storage\.foldername\s*\(/i.test(
        `${policy.usingExpression ?? ''} ${policy.checkExpression ?? ''}`,
      ),
    );
    const unconditional = associated.some(
      (policy) =>
        policy.permissive &&
        /\btrue\b/i.test(`${policy.usingExpression ?? ''} ${policy.checkExpression ?? ''}`),
    );
    if ((bucket.isPublic && scoped) || (!bucket.isPublic && (unconditional || !scoped))) {
      findings.push(
        finding({
          ruleId: 'TS-STORAGE-001',
          title: 'Storage bucket visibility and object policies are out of sync',
          severity: 'high',
          confidence: associated.length ? 'high' : 'medium',
          source: 'static',
          schema: 'storage',
          table: 'objects',
          policy: associated.map((policy) => policy.name).join(', ') || undefined,
          expected: bucket.isPublic
            ? 'Public bucket treated as publicly downloadable'
            : 'Private bucket protected by owner or tenant policy',
          observed: bucket.isPublic
            ? `Public bucket ${bucket.name} has row-scoped policies that do not restrict public URL downloads`
            : `Private bucket ${bucket.name} lacks an effective owner or tenant boundary`,
          reproduction: reproduction(storageTable, `bucket ${bucket.name} (${bucket.id})`),
          remediation: bucket.isPublic
            ? 'Do not rely on storage.objects RLS to protect downloads from a public bucket; make it private or remove sensitive content.'
            : 'Add a bucket_id-scoped policy that checks auth.uid(), auth.jwt(), or storage.foldername().',
          documentationUrl: `${DOCS_BASE}ts-storage-001`,
        }),
      );
    }
  }
  return findings;
}

function performanceRules(ctx: StaticRuleContext): Finding[] {
  const findings: Finding[] = [];
  for (const table of ctx.snapshot.tables.filter(
    (candidate) => candidate.rlsEnabled && !candidate.isForeign,
  )) {
    const resource = ctx.resourceFor(table);
    const tenantColumn = resource?.tenantColumn;
    for (const policy of table.policies) {
      if (
        effectivePolicyRoles(policy).length === 0 ||
        activePolicyPairs(table, policy).length === 0
      )
        continue;
      const expressions = [policy.usingExpression, policy.checkExpression].filter(
        (value): value is string => Boolean(value),
      );
      const slowAuth = expressions.some((expression) =>
        [...expression.matchAll(/auth\s*\.\s*(?:uid|jwt)\s*\(/gi)].some((match) => {
          return !/\(\s*select\s+(?:\(\s*)*$/i.test(expression.slice(0, match.index));
        }),
      );
      if (slowAuth)
        findings.push(
          finding({
            ruleId: 'TS-PERF-001',
            title: 'RLS auth helper is not wrapped for initPlan reuse',
            severity: 'medium',
            confidence: 'high',
            source: 'static',
            schema: table.schema,
            table: table.name,
            policy: policy.name,
            expected: '(select auth.uid()) or (select auth.jwt()) in policy expressions',
            observed: 'Policy calls auth.uid() or auth.jwt() per row',
            reproduction: reproduction(table, `policy ${policy.name}`),
            remediation:
              'Wrap auth.uid() and auth.jwt() calls in scalar SELECT expressions so PostgreSQL can evaluate them once per statement.',
            documentationUrl: `${DOCS_BASE}ts-perf-001`,
          }),
        );
    }
    const inferredTenant =
      tenantColumn ??
      table.policies
        .flatMap((policy) => [policy.usingExpression, policy.checkExpression])
        .filter((value): value is string => Boolean(value))
        .map(
          (expression) =>
            expression.match(
              /\b([a-z_][\w$]*(?:tenant|org(?:anization)?_id))\s*=\s*(?:\(\s*select\s+)?auth\s*\./i,
            )?.[1],
        )
        .find(Boolean);
    if (
      inferredTenant &&
      !(table.indexes ?? []).some(
        (index) => index.columns[0]?.toLowerCase() === inferredTenant.toLowerCase(),
      )
    ) {
      findings.push(
        finding({
          ruleId: 'TS-PERF-002',
          title: 'Tenant policy column has no leading index',
          severity: 'low',
          confidence: tenantColumn ? 'high' : 'medium',
          source: 'static',
          schema: table.schema,
          table: table.name,
          expected: `Index beginning with ${inferredTenant}`,
          observed: 'No valid index has the tenant column as its leading key',
          reproduction: reproduction(table, `inspect indexes for ${inferredTenant}`),
          remediation: `Create an index on ${table.schema}.${table.name} (${inferredTenant}) or a composite index with this column first.`,
          documentationUrl: `${DOCS_BASE}ts-perf-002`,
        }),
      );
    }
  }
  return findings;
}

function definerViewFinding(view: CatalogView, roles: readonly string[]): Finding {
  return finding({
    ruleId: 'TS-VIEW-001',
    title: 'Exposed view runs with definer privileges',
    severity: 'high',
    confidence: 'high',
    source: 'static',
    schema: view.schema,
    table: view.name,
    role: roles.join(', '),
    operation: 'select',
    expected: 'security_invoker=true or no Data API SELECT grant',
    observed: 'Granted view uses its owner privileges and can bypass underlying RLS',
    reproduction: {
      command: 'tenantshield scan',
      details: `${view.schema}.${view.name}: inspect security_invoker and SELECT grants`,
    },
    remediation:
      'Set security_invoker=true on PostgreSQL 15+ or revoke Data API access and move the view to an unexposed schema.',
    documentationUrl: `${DOCS_BASE}ts-view-001`,
  });
}

type StaticRuleContext = {
  snapshot: CatalogSnapshot;
  config: TenantShieldConfig;
  resourceFor: (resource: {
    schema: string;
    name: string;
  }) => ReturnType<typeof configuredResource>;
  hasDataApiAccess: (table: CatalogTable) => boolean;
};

type StaticRule = { id: string; check: (ctx: StaticRuleContext) => Finding[] };

function scannableTables(ctx: StaticRuleContext): CatalogTable[] {
  return ctx.snapshot.tables.filter(
    (table) => !ctx.resourceFor(table)?.public && ctx.hasDataApiAccess(table),
  );
}

function policyScanTables(ctx: StaticRuleContext): CatalogTable[] {
  return scannableTables(ctx).filter((table) => !table.isForeign && table.rlsEnabled);
}

function expectedRolesFor(ctx: StaticRuleContext, table: CatalogTable): ReadonlySet<string> {
  const expectedRoles = new Set<string>();
  const resource = ctx.resourceFor(table);
  if (resource) {
    expectedRoles.add(ctx.config.identities[resource.ownerIdentity]!.role);
    expectedRoles.add(ctx.config.identities[resource.foreignIdentity]!.role);
  } else {
    expectedRoles.add('authenticated');
  }
  return expectedRoles;
}

function bypassRule(ctx: StaticRuleContext): Finding[] {
  const bypass = bypassFinding(ctx.snapshot);
  return bypass ? [bypass] : [];
}

function exposedForeignTableRule(ctx: StaticRuleContext): Finding[] {
  return scannableTables(ctx)
    .filter((table) => table.isForeign)
    .map((table) => exposedForeignTableFinding(table));
}

function rlsDisabledRule(ctx: StaticRuleContext): Finding[] {
  return scannableTables(ctx)
    .filter((table) => !table.isForeign && !table.rlsEnabled)
    .map((table) => rlsDisabledFinding(table));
}

function ownerBypassRule(ctx: StaticRuleContext): Finding[] {
  return policyScanTables(ctx)
    .filter((table) => !table.rlsForced && (table.ownerRoles ?? []).length > 0)
    .map((table) => ownerBypassFinding(table, table.ownerRoles ?? []));
}

function missingPolicyRule(ctx: StaticRuleContext): Finding[] {
  return policyScanTables(ctx).flatMap((table) => missingPolicyFindings(table));
}

function unconditionalPolicyRule(ctx: StaticRuleContext): Finding[] {
  return policyScanTables(ctx).flatMap((table) =>
    unconditionalPolicyFindings(table, ctx.resourceFor(table)?.tenantColumn),
  );
}

function unintendedRoleRule(ctx: StaticRuleContext): Finding[] {
  return policyScanTables(ctx).flatMap((table) =>
    unintendedRoleFindings(table, expectedRolesFor(ctx, table)),
  );
}

function userEditableMetadataRule(ctx: StaticRuleContext): Finding[] {
  return policyScanTables(ctx).flatMap((table) => userEditableMetadataFindings(table));
}

function deprecatedAuthHelperRule(ctx: StaticRuleContext): Finding[] {
  return policyScanTables(ctx).flatMap((table) => deprecatedAuthHelperFindings(table));
}

function missingWriteCheckRule(ctx: StaticRuleContext): Finding[] {
  return policyScanTables(ctx).flatMap((table) => missingWriteCheckFindings(table));
}

function definerViewRule(ctx: StaticRuleContext): Finding[] {
  const findings: Finding[] = [];
  for (const view of ctx.snapshot.views) {
    if (view.securityInvoker || ctx.resourceFor(view)?.public) continue;
    const roles = view.grants
      .filter(
        (grant) =>
          ['public', 'anon', 'authenticated'].includes(grant.role) &&
          grant.privileges.includes('select'),
      )
      .map((grant) => grant.role)
      .sort();
    if (roles.length > 0) findings.push(definerViewFinding(view, roles));
  }
  return findings;
}

function securityDefinerRule(ctx: StaticRuleContext): Finding[] {
  return ctx.snapshot.functions
    .filter(
      (fn) =>
        fn.securityDefiner &&
        !fn.isTrigger &&
        fn.executeRoles.some((role) => ['public', 'anon', 'authenticated'].includes(role)),
    )
    .map((fn) => securityDefinerFinding(fn));
}

const STATIC_RULES: ReadonlyArray<StaticRule> = [
  { id: 'TS-RLS-010', check: truncatePrivilegeRule },
  { id: 'TS-FN-002', check: securityDefinerSearchPathRule },
  { id: 'TS-STORAGE-001', check: storagePolicyRule },
  { id: 'TS-PERF-001/002', check: performanceRules },
  { id: 'TS-RLS-006', check: bypassRule },
  { id: 'TS-FT-001', check: exposedForeignTableRule },
  { id: 'TS-RLS-001', check: rlsDisabledRule },
  { id: 'TS-RLS-007', check: ownerBypassRule },
  { id: 'TS-RLS-002', check: missingPolicyRule },
  { id: 'TS-RLS-003', check: unconditionalPolicyRule },
  { id: 'TS-RLS-004', check: unintendedRoleRule },
  { id: 'TS-RLS-008', check: userEditableMetadataRule },
  { id: 'TS-RLS-009', check: deprecatedAuthHelperRule },
  { id: 'TS-RLS-005', check: missingWriteCheckRule },
  { id: 'TS-VIEW-001', check: definerViewRule },
  { id: 'TS-FN-001', check: securityDefinerRule },
];

export function runStaticRules(snapshot: CatalogSnapshot, config: TenantShieldConfig): Finding[] {
  const context: StaticRuleContext = {
    snapshot,
    config,
    resourceFor: (resource) => configuredResource(config, resource),
    hasDataApiAccess: hasDataApiTableAccess,
  };
  return STATIC_RULES.flatMap((rule) => rule.check(context)).sort((a, b) =>
    a.fingerprint.localeCompare(b.fingerprint),
  );
}

export type {
  CatalogFunction,
  CatalogSnapshot,
  CatalogTable,
  CatalogView,
} from '@tenantshield/catalog';
