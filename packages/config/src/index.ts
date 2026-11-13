import { parse as parseYaml } from 'yaml';
import { z } from 'zod';

const nonEmpty = z.string().trim().min(1);
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const projectRelativePath = nonEmpty.refine((value) => {
  const normalized = value.replaceAll('\\', '/');
  return (
    !normalized.startsWith('/') &&
    !/^[A-Za-z]:\//.test(normalized) &&
    !normalized.split('/').includes('..')
  );
}, 'Must be a project-relative path without parent traversal');
const identifier = z
  .string()
  .trim()
  .regex(/^[A-Za-z_][A-Za-z0-9_$]*$/, 'Must be a SQL identifier');
const uuid = z
  .string()
  .regex(UUID_PATTERN, 'Invalid UUID')
  .transform((value) => value.toLowerCase());
const tenantScalar = z.union([z.string(), z.number().refine(Number.isSafeInteger)]);

export const identitySchema = z
  .object({
    role: z.enum(['anon', 'authenticated']),
    userId: uuid.optional(),
    membershipRole: z.string().trim().min(1).optional(),
    claims: z.record(z.string(), z.json()).default({}),
    tenants: z.record(identifier, tenantScalar).optional(),
  })
  .strict()
  .superRefine((identity, context) => {
    if (identity.role === 'authenticated' && !identity.userId) {
      context.addIssue({
        code: 'custom',
        path: ['userId'],
        message: 'Required for authenticated identities',
      });
    }
    if (identity.role === 'anon' && identity.userId) {
      context.addIssue({
        code: 'custom',
        path: ['userId'],
        message: 'Must be omitted for the unauthenticated anon role',
      });
    }
    for (const claim of ['role', 'sub'] as const) {
      if (Object.hasOwn(identity.claims, claim)) {
        context.addIssue({
          code: 'custom',
          path: ['claims', claim],
          message: 'Reserved claim is derived from identity configuration',
        });
      }
    }
  });

export const resourceSchema = z
  .object({
    schema: identifier.optional(),
    primaryKey: z.union([
      identifier,
      z
        .array(identifier)
        .min(1)
        .refine((keys) => new Set(keys).size === keys.length, {
          message: 'Primary key columns must be unique',
        }),
    ]),
    tenantColumn: identifier,
    ownerIdentity: nonEmpty,
    foreignIdentity: nonEmpty,
    dualMemberIdentity: nonEmpty.optional(),
    membership: z
      .object({
        schema: identifier.optional(),
        table: identifier,
        tenantColumn: identifier,
        userColumn: identifier,
        roleColumn: identifier.optional(),
      })
      .strict()
      .optional(),
    ownerTenantValue: tenantScalar.optional(),
    foreignTenantValue: tenantScalar.optional(),
    testOperations: z
      .array(z.enum(['select', 'insert', 'update', 'delete']))
      .min(1)
      .refine((operations) => new Set(operations).size === operations.length, {
        message: 'Operations must be unique',
      }),
    public: z.boolean().optional(),
  })
  .strict();

export const configSchema = z
  .object({
    version: z.literal(1),
    database: z
      .object({
        connectionEnv: nonEmpty,
        allowedHosts: z.array(nonEmpty).min(1),
        productionMarkers: z.array(nonEmpty).optional(),
        exposedSchemas: z.array(identifier).min(1).optional(),
      })
      .strict(),
    fixtures: z
      .object({
        mode: z.enum(['sql', 'auto']).optional(),
        setupSql: projectRelativePath.optional(),
      })
      .strict()
      .optional(),
    migrationsDir: projectRelativePath.optional(),
    identities: z
      .record(nonEmpty, identitySchema)
      .refine((value) => Object.keys(value).length > 0, {
        message: 'At least one identity is required',
      }),
    resources: z.record(nonEmpty, resourceSchema).refine((value) => Object.keys(value).length > 0, {
      message: 'At least one resource is required',
    }),
  })
  .strict()
  .superRefine((config, context) => {
    for (const [name, resource] of Object.entries(config.resources)) {
      if (!Object.hasOwn(config.identities, resource.ownerIdentity)) {
        context.addIssue({
          code: 'custom',
          path: ['resources', name, 'ownerIdentity'],
          message: `Unknown identity: ${resource.ownerIdentity}`,
        });
      }
      if (!Object.hasOwn(config.identities, resource.foreignIdentity)) {
        context.addIssue({
          code: 'custom',
          path: ['resources', name, 'foreignIdentity'],
          message: `Unknown identity: ${resource.foreignIdentity}`,
        });
      }
      if (resource.dualMemberIdentity) {
        const dual = config.identities[resource.dualMemberIdentity];
        if (
          !dual ||
          dual.role !== 'authenticated' ||
          [resource.ownerIdentity, resource.foreignIdentity].some(
            (name) =>
              name === resource.dualMemberIdentity ||
              config.identities[name]?.userId === dual.userId,
          )
        ) {
          context.addIssue({
            code: 'custom',
            path: ['resources', name, 'dualMemberIdentity'],
            message: 'Must reference a distinct configured authenticated identity',
          });
        }
      }
      if (resource.ownerIdentity === resource.foreignIdentity) {
        context.addIssue({
          code: 'custom',
          path: ['resources', name, 'foreignIdentity'],
          message: 'Foreign identity must differ from owner identity',
        });
      }
      if (resource.public) continue;

      const owner = config.identities[resource.ownerIdentity];
      const foreign = config.identities[resource.foreignIdentity];
      if (owner?.userId && foreign?.userId && owner.userId === foreign.userId) {
        context.addIssue({
          code: 'custom',
          path: ['resources', name, 'foreignIdentity'],
          message: 'Foreign identity must use a different authenticated user ID',
        });
      }
      const ownerTenant =
        resource.ownerTenantValue ??
        owner?.tenants?.[resource.tenantColumn] ??
        owner?.claims[resource.tenantColumn];
      const foreignTenant =
        resource.foreignTenantValue ??
        foreign?.tenants?.[resource.tenantColumn] ??
        foreign?.claims[resource.tenantColumn];
      const ownerTenantPath =
        resource.ownerTenantValue !== undefined
          ? ['resources', name, 'ownerTenantValue']
          : owner?.tenants?.[resource.tenantColumn] !== undefined
            ? ['identities', resource.ownerIdentity, 'tenants', resource.tenantColumn]
            : ['identities', resource.ownerIdentity, 'claims', resource.tenantColumn];
      const foreignTenantPath =
        resource.foreignTenantValue !== undefined
          ? ['resources', name, 'foreignTenantValue']
          : foreign?.tenants?.[resource.tenantColumn] !== undefined
            ? ['identities', resource.foreignIdentity, 'tenants', resource.tenantColumn]
            : ['identities', resource.foreignIdentity, 'claims', resource.tenantColumn];
      const isScalarTenant = (value: unknown): value is string | number =>
        typeof value === 'string' || (typeof value === 'number' && Number.isSafeInteger(value));
      if (!isScalarTenant(ownerTenant)) {
        context.addIssue({
          code: 'custom',
          path: ownerTenantPath,
          message: 'Required string or safe-integer tenant claim for configured resource',
        });
      }
      if (!isScalarTenant(foreignTenant)) {
        context.addIssue({
          code: 'custom',
          path: foreignTenantPath,
          message: 'Required string or safe-integer tenant claim for configured resource',
        });
      }
      if (
        isScalarTenant(ownerTenant) &&
        isScalarTenant(foreignTenant) &&
        canonicalTenantClaim(ownerTenant) === canonicalTenantClaim(foreignTenant)
      ) {
        context.addIssue({
          code: 'custom',
          path: ['resources', name, 'foreignIdentity'],
          message: 'Foreign identity must have a different tenant claim from owner identity',
        });
      }
    }
  });

function canonicalTenantClaim(value: string | number): string {
  const text = String(value);
  return UUID_PATTERN.test(text) ? text.toLowerCase() : text;
}

export type TenantShieldConfig = z.infer<typeof configSchema>;

export interface ValidationIssue {
  path: string;
  message: string;
}

export class ConfigValidationError extends Error {
  readonly issues: ValidationIssue[];

  constructor(issues: ValidationIssue[]) {
    super(
      `Invalid configuration:\n${issues.map((issue) => `- ${issue.path}: ${issue.message}`).join('\n')}`,
    );
    this.name = 'ConfigValidationError';
    this.issues = issues;
  }
}

function formatPath(path: PropertyKey[]): string {
  return path.map(String).join('.') || '<root>';
}

export function parseConfig(input: unknown): TenantShieldConfig {
  const result = configSchema.safeParse(input);
  if (!result.success) {
    const issues = result.error.issues.flatMap((issue) => {
      if (issue.code === 'unrecognized_keys') {
        return issue.keys.map((key) => ({
          path: formatPath([...issue.path, key]),
          message: 'Unknown configuration field',
        }));
      }
      return [{ path: formatPath(issue.path), message: issue.message }];
    });
    throw new ConfigValidationError(issues);
  }
  return result.data;
}

export function parseConfigYaml(source: string): TenantShieldConfig {
  let parsed: unknown;
  try {
    parsed = parseYaml(source);
  } catch {
    throw new ConfigValidationError([{ path: '<yaml>', message: 'Invalid YAML syntax' }]);
  }
  return parseConfig(parsed);
}
