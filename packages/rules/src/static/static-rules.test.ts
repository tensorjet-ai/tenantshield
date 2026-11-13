import { describe, expect, it } from 'vitest';
import type { CatalogSnapshot, CatalogTable } from '@tenantshield/catalog';
import type { TenantShieldConfig } from '@tenantshield/config';
import { runStaticRules } from '../index.js';

const config: TenantShieldConfig = {
  version: 1,
  database: { connectionEnv: 'DATABASE_URL', allowedHosts: ['localhost'] },
  fixtures: { setupSql: 'fixtures.sql' },
  identities: {
    alice: { role: 'authenticated', userId: '11111111-1111-1111-1111-111111111111', claims: {} },
    bob: { role: 'authenticated', userId: '22222222-2222-2222-2222-222222222222', claims: {} },
  },
  resources: {
    invoices: {
      primaryKey: 'id',
      tenantColumn: 'org_id',
      ownerIdentity: 'alice',
      foreignIdentity: 'bob',
      testOperations: ['select', 'insert', 'update', 'delete'],
    },
  },
};

const secureTable: CatalogTable = {
  schema: 'public',
  name: 'invoices',
  rlsEnabled: true,
  rlsForced: false,
  columns: [
    { name: 'id', dataType: 'uuid', ordinal: 1 },
    { name: 'org_id', dataType: 'uuid', ordinal: 2 },
  ],
  primaryKey: ['id'],
  foreignKeys: [],
  grants: [{ role: 'authenticated', privileges: ['select', 'insert', 'update', 'delete'] }],
  indexes: [{ name: 'invoices_org_id_idx', columns: ['org_id'] }],
  policies: [
    {
      name: 'tenant select',
      command: 'select',
      permissive: true,
      roles: ['authenticated'],
      usingExpression: "org_id = (select auth.jwt()->>'org_id')",
      checkExpression: null,
    },
    {
      name: 'tenant insert',
      command: 'insert',
      permissive: true,
      roles: ['authenticated'],
      usingExpression: null,
      checkExpression: "org_id = (select auth.jwt()->>'org_id')",
    },
    {
      name: 'tenant update',
      command: 'update',
      permissive: true,
      roles: ['authenticated'],
      usingExpression: "org_id = (select auth.jwt()->>'org_id')",
      checkExpression: "org_id = (select auth.jwt()->>'org_id')",
    },
    {
      name: 'tenant delete',
      command: 'delete',
      permissive: true,
      roles: ['authenticated'],
      usingExpression: "org_id = (select auth.jwt()->>'org_id')",
      checkExpression: null,
    },
  ],
};

const anonSelectGrant: CatalogTable['grants'][number] = {
  role: 'anon',
  privileges: ['select'],
};

const snapshot = (table: CatalogTable = secureTable): CatalogSnapshot => ({
  version: 1,
  database: {
    name: 'postgres',
    serverVersion: '16.4',
    currentRole: 'scanner',
    isSuperuser: false,
    canBypassRls: false,
  },
  schemas: ['public'],
  tables: [table],
  views: [],
  functions: [],
});

describe('static rule pack', () => {
  it('has no findings for a secure configured table', () => {
    expect(runStaticRules(snapshot(), config)).toEqual([]);
  });

  it('flags TRUNCATE grants, trigger functions, unpinned definers, and missing tenant indexes', () => {
    const findings = runStaticRules(
      {
        ...snapshot(),
        tables: [
          {
            ...secureTable,
            indexes: [],
            grants: [...secureTable.grants, { role: 'anon', privileges: ['truncate'] }],
          },
        ],
        functions: [
          {
            schema: 'public',
            name: 'trigger_fn',
            identityArguments: '',
            securityDefiner: true,
            isTrigger: true,
            executeRoles: ['authenticated'],
          },
          {
            schema: 'public',
            name: 'unsafe_fn',
            identityArguments: '',
            securityDefiner: true,
            isTrigger: false,
            executeRoles: ['authenticated'],
            proconfig: [],
          },
        ],
      },
      config,
    );
    expect(findings.map((item) => item.ruleId)).toContain('TS-RLS-010');
    expect(findings.map((item) => item.ruleId)).toContain('TS-FN-002');
    expect(findings.map((item) => item.ruleId)).toContain('TS-PERF-002');
    expect(findings).not.toContainEqual(
      expect.objectContaining({ ruleId: 'TS-FN-001', function: 'trigger_fn()' }),
    );
  });

  it('flags unwrapped auth calls and preserves initPlan-wrapped identity boundaries', () => {
    const table = {
      ...secureTable,
      policies: secureTable.policies.map((policy) =>
        policy.command === 'select'
          ? { ...policy, usingExpression: 'org_id = auth.uid()' }
          : policy,
      ),
    };
    const findings = runStaticRules(snapshot(table), config);
    expect(findings).toContainEqual(
      expect.objectContaining({ ruleId: 'TS-PERF-001', policy: 'tenant select' }),
    );
    expect(findings).not.toContainEqual(
      expect.objectContaining({ ruleId: 'TS-RLS-003', policy: 'tenant insert' }),
    );
  });

  it('flags public buckets with row-scoped policies and private buckets without an owner boundary', () => {
    const storageObjects: CatalogTable = {
      ...secureTable,
      schema: 'storage',
      name: 'objects',
      policies: [
        {
          name: 'public bucket owner check',
          command: 'select',
          permissive: true,
          roles: ['authenticated'],
          usingExpression: "bucket_id = 'public-id' AND auth.uid() = owner_id",
          checkExpression: null,
        },
        {
          name: 'private allow all',
          command: 'select',
          permissive: true,
          roles: ['authenticated'],
          usingExpression: "bucket_id = 'private-id' AND true",
          checkExpression: null,
        },
      ],
    };
    const findings = runStaticRules(
      {
        ...snapshot(storageObjects),
        schemas: ['public', 'storage'],
        storageBuckets: [
          { id: 'public-id', name: 'public-files', isPublic: true },
          { id: 'private-id', name: 'private-files', isPublic: false },
        ],
      },
      config,
    );
    expect(findings.filter((item) => item.ruleId === 'TS-STORAGE-001')).toHaveLength(2);
  });

  it('does not call an ungranted table exposed when RLS is disabled', () => {
    expect(
      runStaticRules(
        snapshot({ ...secureTable, rlsEnabled: false, grants: [], policies: [] }),
        config,
      ),
    ).toEqual([]);
  });

  it('flags exposed foreign tables that cannot provide RLS', () => {
    const foreignTable: CatalogTable = {
      ...secureTable,
      name: 'external_accounts',
      isForeign: true,
      rlsEnabled: false,
      policies: [],
      grants: [{ role: 'authenticated', privileges: ['select'] }],
    };
    const findings = runStaticRules(snapshot(foreignTable), config);
    expect(findings).toContainEqual(
      expect.objectContaining({
        ruleId: 'TS-FT-001',
        severity: 'critical',
        table: 'external_accounts',
      }),
    );
    expect(findings).not.toContainEqual(expect.objectContaining({ ruleId: 'TS-RLS-001' }));
  });

  it('flags effective Data API ownership that bypasses unforced RLS', () => {
    const ownerBypass = {
      ...secureTable,
      ownerRoles: ['authenticated'],
    };
    expect(runStaticRules(snapshot(ownerBypass), config)).toContainEqual(
      expect.objectContaining({
        ruleId: 'TS-RLS-007',
        severity: 'critical',
        role: 'authenticated',
      }),
    );
    expect(
      runStaticRules(snapshot({ ...ownerBypass, rlsForced: true }), config),
    ).not.toContainEqual(expect.objectContaining({ ruleId: 'TS-RLS-007' }));
  });

  it.each([
    ['TS-RLS-001', { ...secureTable, rlsEnabled: false }],
    [
      'TS-RLS-002',
      {
        ...secureTable,
        policies: secureTable.policies.filter((policy) => policy.command !== 'delete'),
      },
    ],
    [
      'TS-RLS-003',
      {
        ...secureTable,
        policies: [
          { ...secureTable.policies[0]!, usingExpression: '(true)' },
          ...secureTable.policies.slice(1),
        ],
      },
    ],
    [
      'TS-RLS-004',
      {
        ...secureTable,
        grants: [...secureTable.grants, anonSelectGrant],
        policies: [
          { ...secureTable.policies[0]!, roles: ['public'] },
          ...secureTable.policies.slice(1),
        ],
      },
    ],
    [
      'TS-RLS-005',
      {
        ...secureTable,
        policies: secureTable.policies.map((policy) =>
          policy.command === 'insert' ? { ...policy, checkExpression: null } : policy,
        ),
      },
    ],
  ])('emits %s', (ruleId, table) => {
    expect(runStaticRules(snapshot(table), config).map((finding) => finding.ruleId)).toContain(
      ruleId,
    );
  });

  it('treats omitted UPDATE WITH CHECK as the scoped USING expression', () => {
    const implicitCheck = {
      ...secureTable,
      policies: secureTable.policies.map((policy) =>
        policy.command === 'update' ? { ...policy, checkExpression: null } : policy,
      ),
    };
    expect(runStaticRules(snapshot(implicitCheck), config)).toEqual([]);
  });

  it('does not treat a restrictive-only policy as operation coverage', () => {
    const restrictiveOnly = {
      ...secureTable,
      policies: secureTable.policies.map((policy) =>
        policy.command === 'select' ? { ...policy, permissive: false } : policy,
      ),
    };
    expect(runStaticRules(snapshot(restrictiveOnly), config)).toContainEqual(
      expect.objectContaining({
        ruleId: 'TS-RLS-002',
        operation: 'select',
        role: 'authenticated',
      }),
    );
  });

  it('recognizes policies inherited through a Data API group role', () => {
    const inherited = {
      ...secureTable,
      policies: secureTable.policies.map((policy) =>
        policy.command === 'select'
          ? {
              ...policy,
              roles: ['tenant_reader'],
              effectiveRoles: ['authenticated'],
            }
          : policy,
      ),
    };
    const findings = runStaticRules(snapshot(inherited), config);
    expect(findings).not.toContainEqual(
      expect.objectContaining({ ruleId: 'TS-RLS-002', operation: 'select' }),
    );
    expect(findings).not.toContainEqual(
      expect.objectContaining({ ruleId: 'TS-RLS-004', policy: 'tenant select' }),
    );
  });

  it('does not label a no-op restrictive TRUE policy as an access grant', () => {
    const withRestrictiveNoop = {
      ...secureTable,
      policies: [
        ...secureTable.policies,
        {
          ...secureTable.policies[0]!,
          name: 'restrictive audit marker',
          permissive: false,
          usingExpression: 'true',
        },
      ],
    };
    expect(runStaticRules(snapshot(withRestrictiveNoop), config)).not.toContainEqual(
      expect.objectContaining({ ruleId: 'TS-RLS-003', policy: 'restrictive audit marker' }),
    );
  });

  it('does not treat a restrictive PUBLIC policy as unintended access', () => {
    const withPublicRestriction = {
      ...secureTable,
      policies: [
        ...secureTable.policies,
        {
          ...secureTable.policies[0]!,
          name: 'restrict all callers',
          permissive: false,
          roles: ['public'],
        },
      ],
    };
    expect(runStaticRules(snapshot(withPublicRestriction), config)).not.toContainEqual(
      expect.objectContaining({ ruleId: 'TS-RLS-004', policy: 'restrict all callers' }),
    );
  });

  it('does not flag an unconditional permissive policy guarded by a scoped restrictive policy', () => {
    const selectPolicy = secureTable.policies.find((policy) => policy.command === 'select')!;
    const guarded = {
      ...secureTable,
      policies: [
        ...secureTable.policies.map((policy) =>
          policy.command === 'select' ? { ...policy, usingExpression: 'true' } : policy,
        ),
        {
          ...selectPolicy,
          name: 'restrictive tenant boundary',
          permissive: false,
        },
      ],
    };
    expect(runStaticRules(snapshot(guarded), config)).not.toContainEqual(
      expect.objectContaining({ ruleId: 'TS-RLS-003', policy: 'tenant select' }),
    );
  });

  it.each(['auth.uid() IS NOT NULL', 'org_id IS NOT NULL AND auth.uid() IS NOT NULL'])(
    'does not mistake a broad restrictive predicate for a tenant boundary: %s',
    (usingExpression) => {
      const selectPolicy = secureTable.policies.find((policy) => policy.command === 'select')!;
      const weakRestriction = {
        ...secureTable,
        policies: [
          ...secureTable.policies.map((policy) =>
            policy.command === 'select' ? { ...policy, usingExpression: 'true' } : policy,
          ),
          {
            ...selectPolicy,
            name: 'broad restrictive check',
            permissive: false,
            usingExpression,
          },
        ],
      };
      expect(runStaticRules(snapshot(weakRestriction), config)).toContainEqual(
        expect.objectContaining({ ruleId: 'TS-RLS-003', policy: 'tenant select' }),
      );
    },
  );

  it('does not flag an unconditional policy for a role without matching table privileges', () => {
    const withInactiveAnonPolicy = {
      ...secureTable,
      policies: [
        ...secureTable.policies,
        {
          ...secureTable.policies[0]!,
          name: 'inactive anon policy',
          roles: ['anon'],
          usingExpression: 'true',
        },
      ],
    };
    expect(runStaticRules(snapshot(withInactiveAnonPolicy), config)).not.toContainEqual(
      expect.objectContaining({ ruleId: 'TS-RLS-003', policy: 'inactive anon policy' }),
    );
  });

  it('flags authorization policies that trust user-editable JWT metadata', () => {
    const unsafeMetadata = {
      ...secureTable,
      policies: secureTable.policies.map((policy) =>
        policy.command === 'select'
          ? {
              ...policy,
              usingExpression: "org_id = (auth.jwt() -> 'user_metadata' ->> 'org_id')::uuid",
            }
          : policy,
      ),
    };
    expect(runStaticRules(snapshot(unsafeMetadata), config)).toContainEqual(
      expect.objectContaining({
        ruleId: 'TS-RLS-008',
        severity: 'high',
        policy: 'tenant select',
      }),
    );
    const safeMetadata = {
      ...unsafeMetadata,
      policies: unsafeMetadata.policies.map((policy) => ({
        ...policy,
        usingExpression: policy.usingExpression?.replace('user_metadata', 'app_metadata') ?? null,
      })),
    };
    expect(runStaticRules(snapshot(safeMetadata), config)).not.toContainEqual(
      expect.objectContaining({ ruleId: 'TS-RLS-008' }),
    );
  });

  it('flags user metadata read directly from the PostgreSQL request claims setting', () => {
    const unsafeMetadata = {
      ...secureTable,
      policies: secureTable.policies.map((policy) =>
        policy.command === 'select'
          ? {
              ...policy,
              usingExpression:
                "org_id = ((current_setting('request.jwt.claims', true)::jsonb -> 'user_metadata') ->> 'org_id')::uuid",
            }
          : policy,
      ),
    };
    expect(runStaticRules(snapshot(unsafeMetadata), config)).toContainEqual(
      expect.objectContaining({ ruleId: 'TS-RLS-008', policy: 'tenant select' }),
    );
  });

  it.each(['auth.role()', 'AUTH . EMAIL ( )'])(
    'flags active policies that use deprecated Supabase helper %s',
    (helper) => {
      const deprecatedHelper = {
        ...secureTable,
        policies: secureTable.policies.map((policy) =>
          policy.command === 'select'
            ? { ...policy, usingExpression: `${helper} IS NOT NULL` }
            : policy,
        ),
      };
      expect(runStaticRules(snapshot(deprecatedHelper), config)).toContainEqual(
        expect.objectContaining({
          ruleId: 'TS-RLS-009',
          severity: 'low',
          policy: 'tenant select',
        }),
      );
    },
  );

  it('does not flag deprecated helper text in inactive policies', () => {
    const inactive = {
      ...secureTable,
      policies: [
        ...secureTable.policies,
        {
          ...secureTable.policies[0]!,
          name: 'inactive deprecated helper',
          roles: ['anon'],
          usingExpression: "auth.role() = 'anon'",
        },
      ],
    };
    expect(runStaticRules(snapshot(inactive), config)).not.toContainEqual(
      expect.objectContaining({ ruleId: 'TS-RLS-009', policy: 'inactive deprecated helper' }),
    );
  });

  it('labels a missing INSERT boundary with the INSERT operation', () => {
    const missingCheck = {
      ...secureTable,
      policies: secureTable.policies.map((policy) =>
        policy.command === 'insert' ? { ...policy, checkExpression: null } : policy,
      ),
    };
    expect(runStaticRules(snapshot(missingCheck), config)).toContainEqual(
      expect.objectContaining({ ruleId: 'TS-RLS-005', operation: 'insert' }),
    );
  });

  it.each(['select', 'insert'] as const)(
    'detects an omitted %s policy expression as unconditional access',
    (command) => {
      const unsafe = {
        ...secureTable,
        policies: secureTable.policies.map((policy) =>
          policy.command === command
            ? { ...policy, usingExpression: null, checkExpression: null }
            : policy,
        ),
      };
      expect(runStaticRules(snapshot(unsafe), config)).toContainEqual(
        expect.objectContaining({ ruleId: 'TS-RLS-003', policy: `tenant ${command}` }),
      );
    },
  );

  it('emits bypass context and exposed security-definer findings', () => {
    const input = snapshot();
    input.database.canBypassRls = true;
    input.functions.push({
      schema: 'public',
      name: 'danger',
      identityArguments: '',
      securityDefiner: true,
      executeRoles: ['public'],
    });
    expect(runStaticRules(input, config).map((finding) => finding.ruleId)).toEqual(
      expect.arrayContaining(['TS-RLS-006', 'TS-FN-001']),
    );
  });

  it('gives distinct fingerprints to distinct security-definer functions', () => {
    const input = snapshot();
    input.functions.push(
      {
        schema: 'public',
        name: 'export_invoice',
        identityArguments: 'invoice_id uuid',
        securityDefiner: true,
        executeRoles: ['authenticated'],
      },
      {
        schema: 'public',
        name: 'delete_invoice',
        identityArguments: 'invoice_id uuid',
        securityDefiner: true,
        executeRoles: ['authenticated'],
      },
    );
    const findings = runStaticRules(input, config).filter(
      (finding) => finding.ruleId === 'TS-FN-001',
    );
    expect(findings).toHaveLength(2);
    expect(new Set(findings.map((finding) => finding.fingerprint)).size).toBe(2);
  });

  it('flags a Data API view that runs with definer privileges', () => {
    const input = {
      ...snapshot(),
      views: [
        {
          schema: 'public',
          name: 'invoice_export',
          securityInvoker: false,
          grants: [{ role: 'authenticated', privileges: ['select'] }],
        },
      ],
    } as CatalogSnapshot & { views: unknown[] };
    expect(runStaticRules(input, config)).toContainEqual(
      expect.objectContaining({
        ruleId: 'TS-VIEW-001',
        schema: 'public',
        severity: 'high',
      }),
    );
  });

  it('keeps security-impact severities aligned with the rule contract', () => {
    const withoutRls = runStaticRules(snapshot({ ...secureTable, rlsEnabled: false }), config);
    expect(withoutRls).toContainEqual(
      expect.objectContaining({ ruleId: 'TS-RLS-001', severity: 'critical', confidence: 'high' }),
    );
    const privileged = snapshot();
    privileged.database.canBypassRls = true;
    expect(runStaticRules(privileged, config)).toContainEqual(
      expect.objectContaining({ ruleId: 'TS-RLS-006', severity: 'medium', confidence: 'medium' }),
    );
  });

  it('does not flag configured public resources', () => {
    const publicConfig = structuredClone(config);
    publicConfig.resources['invoices']!.public = true;
    expect(
      runStaticRules(snapshot({ ...secureTable, rlsEnabled: false, policies: [] }), publicConfig),
    ).toEqual([]);
  });

  it('produces stable fingerprints', () => {
    const findings = runStaticRules(snapshot({ ...secureTable, rlsEnabled: false }), config);
    expect(
      runStaticRules(snapshot({ ...secureTable, rlsEnabled: false }), config)[0]!.fingerprint,
    ).toBe(findings[0]!.fingerprint);
  });

  const guardedUnconditionalSelect = (restrictiveUsing: string) => {
    const selectPolicy = secureTable.policies.find((policy) => policy.command === 'select')!;
    return {
      ...secureTable,
      policies: [
        ...secureTable.policies.map((policy) =>
          policy.command === 'select' ? { ...policy, usingExpression: 'true' } : policy,
        ),
        {
          ...selectPolicy,
          name: 'restrictive boundary',
          permissive: false,
          usingExpression: restrictiveUsing,
        },
      ],
    };
  };

  it.each([
    'creator_id = auth.uid() AND org_id = org_id',
    'NOT (org_id = auth.uid())',
    'NOT org_id = auth.uid()',
    'org_id <> auth.uid()',
    'org_id != auth.uid()',
    'org_id IS DISTINCT FROM auth.uid()',
  ])('does not accept a fail-open tenant boundary: %s', (restrictiveUsing) => {
    expect(
      runStaticRules(snapshot(guardedUnconditionalSelect(restrictiveUsing)), config),
    ).toContainEqual(expect.objectContaining({ ruleId: 'TS-RLS-003', policy: 'tenant select' }));
  });

  it.each([
    'org_id = auth.uid()',
    'auth.uid() = org_id',
    '(org_id) = (auth.uid())',
    "org_id = (auth.jwt() ->> 'org_id')::text",
    "org_id::text IN (SELECT jsonb_array_elements_text(auth.jwt() -> 'tenants'))",
    "org_id = (select auth.jwt()->>'org_id')",
    "status = 'active' AND org_id = auth.uid()",
  ])('accepts a direct tenant-to-request comparison: %s', (restrictiveUsing) => {
    expect(
      runStaticRules(snapshot(guardedUnconditionalSelect(restrictiveUsing)), config),
    ).not.toContainEqual(
      expect.objectContaining({ ruleId: 'TS-RLS-003', policy: 'tenant select' }),
    );
  });

  it('recognizes correlated membership EXISTS predicates without trusting uncorrelated subqueries', () => {
    const correlated = guardedUnconditionalSelect(
      'EXISTS (SELECT 1 FROM memberships m WHERE m.organization_id = invoices.org_id AND m.user_id = auth.uid())',
    );
    expect(runStaticRules(snapshot(correlated), config)).not.toContainEqual(
      expect.objectContaining({ ruleId: 'TS-RLS-003', policy: 'tenant select' }),
    );

    const uncorrelated = guardedUnconditionalSelect(
      'EXISTS (SELECT 1 FROM memberships m WHERE m.org_id = auth.uid())',
    );
    expect(runStaticRules(snapshot(uncorrelated), config)).toContainEqual(
      expect.objectContaining({ ruleId: 'TS-RLS-003', policy: 'tenant select' }),
    );
  });

  it.each(['org_id = org_id', '1 = 1', "'tenant' = 'tenant'", '(1 = 1)'])(
    'flags a normalized tautology as an unconditional policy expression: %s',
    (usingExpression) => {
      const tautology = {
        ...secureTable,
        policies: secureTable.policies.map((policy) =>
          policy.command === 'select' ? { ...policy, usingExpression } : policy,
        ),
      };
      expect(runStaticRules(snapshot(tautology), config)).toContainEqual(
        expect.objectContaining({ ruleId: 'TS-RLS-003', policy: 'tenant select' }),
      );
    },
  );

  it('does not treat a comparison between distinct columns as unconditional', () => {
    const distinctColumns = {
      ...secureTable,
      policies: secureTable.policies.map((policy) =>
        policy.command === 'select'
          ? { ...policy, usingExpression: 'org_id = parent_org_id' }
          : policy,
      ),
    };
    expect(runStaticRules(snapshot(distinctColumns), config)).not.toContainEqual(
      expect.objectContaining({ ruleId: 'TS-RLS-003', policy: 'tenant select' }),
    );
  });

  it('does not let an OR-split restrictive policy guard an unconditional one', () => {
    expect(
      runStaticRules(snapshot(guardedUnconditionalSelect('org_id = auth.uid() OR true')), config),
    ).toContainEqual(expect.objectContaining({ ruleId: 'TS-RLS-003', policy: 'tenant select' }));
  });

  it('keeps current handling of a permissive OR-split policy expression', () => {
    const orSplit = {
      ...secureTable,
      policies: secureTable.policies.map((policy) =>
        policy.command === 'select'
          ? { ...policy, usingExpression: 'org_id = auth.uid() OR true' }
          : policy,
      ),
    };
    expect(runStaticRules(snapshot(orSplit), config)).not.toContainEqual(
      expect.objectContaining({ ruleId: 'TS-RLS-003', policy: 'tenant select' }),
    );
  });
});
