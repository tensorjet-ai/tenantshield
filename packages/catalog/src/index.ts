import { z } from 'zod';

const operationSchema = z.enum([
  'select',
  'insert',
  'update',
  'delete',
  'truncate',
  'references',
  'trigger',
]);

export const catalogPolicySchema = z.object({
  name: z.string(),
  command: z.enum(['all', 'select', 'insert', 'update', 'delete']),
  permissive: z.boolean(),
  roles: z.array(z.string()),
  effectiveRoles: z.array(z.string()).optional(),
  referencedRelations: z.array(z.object({ schema: z.string(), table: z.string() })).optional(),
  usingExpression: z.string().nullable(),
  checkExpression: z.string().nullable(),
});

const catalogGrantSchema = z.object({
  role: z.string(),
  privileges: z.array(operationSchema),
});

export const catalogTableSchema = z.object({
  schema: z.string(),
  name: z.string(),
  isForeign: z.boolean().optional(),
  rlsEnabled: z.boolean(),
  rlsForced: z.boolean(),
  ownerRoles: z.array(z.string()).optional(),
  columns: z.array(
    z.object({
      name: z.string(),
      dataType: z.string(),
      ordinal: z.number().int(),
      isNullable: z.boolean().optional(),
      hasDefault: z.boolean().optional(),
      isGenerated: z.boolean().optional(),
    }),
  ),
  primaryKey: z.array(z.string()),
  foreignKeys: z.array(
    z.object({
      columns: z.array(z.string()),
      referencedSchema: z.string(),
      referencedTable: z.string(),
      referencedColumns: z.array(z.string()),
    }),
  ),
  grants: z.array(catalogGrantSchema),
  policies: z.array(catalogPolicySchema),
  indexes: z.array(z.object({ name: z.string(), columns: z.array(z.string()) })).optional(),
});

export type CatalogTable = z.infer<typeof catalogTableSchema>;

export const catalogViewSchema = z.object({
  schema: z.string(),
  name: z.string(),
  securityInvoker: z.boolean(),
  grants: z.array(catalogGrantSchema),
});

export type CatalogView = z.infer<typeof catalogViewSchema>;

export const catalogFunctionSchema = z.object({
  schema: z.string(),
  name: z.string(),
  identityArguments: z.string(),
  securityDefiner: z.boolean(),
  isTrigger: z.boolean().optional(),
  proconfig: z.array(z.string()).optional(),
  executeRoles: z.array(z.string()),
});

export type CatalogFunction = z.infer<typeof catalogFunctionSchema>;

export const catalogSnapshotSchema = z.object({
  version: z.literal(1),
  database: z.object({
    name: z.string(),
    serverVersion: z.string(),
    currentRole: z.string(),
    isSuperuser: z.boolean(),
    canBypassRls: z.boolean(),
  }),
  schemas: z.array(z.string()),
  tables: z.array(catalogTableSchema),
  fixtureTables: z.array(catalogTableSchema).optional(),
  views: z.array(catalogViewSchema),
  functions: z.array(catalogFunctionSchema),
  storageBuckets: z
    .array(z.object({ id: z.string(), name: z.string(), isPublic: z.boolean() }))
    .optional(),
});

export type CatalogSnapshot = z.infer<typeof catalogSnapshotSchema>;

export interface SqlClient {
  query(sql: string, values?: readonly unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

const DATABASE_QUERY = `
SELECT current_database() AS database_name,
       current_setting('server_version') AS server_version,
       current_user AS current_role,
       r.rolsuper AS is_superuser,
       r.rolbypassrls AS can_bypass_rls
FROM pg_roles r
WHERE r.rolname = current_user`;

const TABLES_QUERY = `
SELECT n.nspname AS schema_name, c.relname AS table_name,
       c.relkind AS relation_kind,
       c.relrowsecurity AS rls_enabled, c.relforcerowsecurity AS rls_forced,
       ARRAY(
         SELECT data_role.rolname::text
         FROM pg_roles data_role
         WHERE data_role.rolname IN ('anon', 'authenticated')
           AND pg_has_role(data_role.oid, c.relowner, 'USAGE')
         ORDER BY data_role.rolname
       )::text[] AS effective_owner_roles
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p', 'f') AND n.nspname = ANY($1::text[])
ORDER BY n.nspname, c.relname`;

const VIEWS_QUERY = `
SELECT n.nspname AS schema_name, c.relname AS view_name,
       COALESCE(c.relkind = 'v' AND 'security_invoker=true' = ANY(c.reloptions), false) AS security_invoker
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('v', 'm') AND n.nspname = ANY($1::text[])
ORDER BY n.nspname, c.relname`;

const COLUMNS_QUERY = `
SELECT table_schema AS schema_name, table_name, column_name, data_type, ordinal_position,
       is_nullable = 'YES' AS is_nullable,
       (column_default IS NOT NULL OR is_identity = 'YES') AS has_default,
       is_generated <> 'NEVER' AS is_generated
FROM information_schema.columns
WHERE table_schema = ANY($1::text[])
ORDER BY table_schema, table_name, ordinal_position`;

const PRIMARY_KEYS_QUERY = `
SELECT n.nspname AS schema_name, c.relname AS table_name,
       array_agg(a.attname ORDER BY key.ordinality)::text[] AS columns
FROM pg_constraint con
JOIN pg_class c ON c.oid = con.conrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN unnest(con.conkey) WITH ORDINALITY AS key(attnum, ordinality) ON true
JOIN pg_attribute a ON a.attrelid = c.oid AND a.attnum = key.attnum
WHERE con.contype = 'p' AND n.nspname = ANY($1::text[])
GROUP BY n.nspname, c.relname`;

const INDEXES_QUERY = `
SELECT n.nspname AS schema_name, t.relname AS table_name, i.relname AS index_name,
       array_agg(COALESCE(a.attname, '<expression>') ORDER BY keys.ordinality)::text[] AS columns
FROM pg_index ix
JOIN pg_class t ON t.oid = ix.indrelid
JOIN pg_namespace n ON n.oid = t.relnamespace
JOIN pg_class i ON i.oid = ix.indexrelid
JOIN unnest(ix.indkey) WITH ORDINALITY AS keys(attnum, ordinality)
  ON keys.ordinality <= ix.indnkeyatts
LEFT JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = keys.attnum
WHERE ix.indisvalid AND n.nspname = ANY($1::text[])
GROUP BY n.nspname, t.relname, i.relname
ORDER BY n.nspname, t.relname, i.relname`;

const FOREIGN_KEYS_QUERY = `
SELECT src_ns.nspname AS schema_name, src.relname AS table_name,
       array_agg(src_att.attname ORDER BY keys.ordinality)::text[] AS columns,
       dst_ns.nspname AS referenced_schema, dst.relname AS referenced_table,
       array_agg(dst_att.attname ORDER BY keys.ordinality)::text[] AS referenced_columns
FROM pg_constraint con
JOIN pg_class src ON src.oid = con.conrelid
JOIN pg_namespace src_ns ON src_ns.oid = src.relnamespace
JOIN pg_class dst ON dst.oid = con.confrelid
JOIN pg_namespace dst_ns ON dst_ns.oid = dst.relnamespace
JOIN unnest(con.conkey, con.confkey) WITH ORDINALITY AS keys(src_num, dst_num, ordinality) ON true
JOIN pg_attribute src_att ON src_att.attrelid = src.oid AND src_att.attnum = keys.src_num
JOIN pg_attribute dst_att ON dst_att.attrelid = dst.oid AND dst_att.attnum = keys.dst_num
WHERE con.contype = 'f' AND src_ns.nspname = ANY($1::text[])
GROUP BY con.oid, src_ns.nspname, src.relname, dst_ns.nspname, dst.relname
ORDER BY src_ns.nspname, src.relname, con.conname`;

const FOREIGN_KEY_TARGETS_QUERY = `
WITH RECURSIVE dependencies(oid) AS (
  SELECT c.oid
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
  WHERE c.relkind IN ('r', 'p') AND n.nspname = ANY($1::text[])
  UNION
  SELECT dependency.refobjid
  FROM pg_depend dependency
  JOIN pg_policy policy ON policy.oid = dependency.objid
  JOIN pg_class source ON source.oid = policy.polrelid
  JOIN pg_namespace source_ns ON source_ns.oid = source.relnamespace
  WHERE dependency.classid = 'pg_policy'::regclass
    AND dependency.refclassid = 'pg_class'::regclass
    AND dependency.refobjid <> source.oid
    AND source_ns.nspname = ANY($1::text[])
  UNION
  SELECT con.confrelid
  FROM dependencies d
  JOIN pg_constraint con ON con.conrelid = d.oid AND con.contype = 'f'
)
SELECT n.nspname AS schema_name, c.relname AS table_name
FROM dependencies d
JOIN pg_class c ON c.oid = d.oid
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE NOT (n.nspname = ANY($1::text[]))`;

const GRANTS_QUERY = `
SELECT n.nspname AS schema_name, c.relname AS table_name,
       role.grantee, privilege.privilege_type
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN LATERAL (
  SELECT rolname AS grantee, oid AS role_oid FROM pg_roles WHERE rolname IN ('anon', 'authenticated')
  UNION ALL SELECT 'public', 0::oid
) role ON true
CROSS JOIN (VALUES
  ('SELECT'), ('INSERT'), ('UPDATE'), ('DELETE'), ('TRUNCATE'), ('REFERENCES'), ('TRIGGER')
) AS privilege(privilege_type)
WHERE c.relkind IN ('r', 'p', 'f', 'v', 'm')
  AND n.nspname = ANY($1::text[])
  AND (
    (role.role_oid <> 0 AND has_schema_privilege(role.role_oid, n.oid, 'USAGE'))
    OR (role.role_oid = 0 AND EXISTS (
      SELECT 1 FROM aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) schema_acl
      WHERE schema_acl.grantee = 0 AND schema_acl.privilege_type = 'USAGE'
    ))
  )
  AND (
    (role.role_oid = 0 AND EXISTS (
      SELECT 1 FROM aclexplode(COALESCE(c.relacl, acldefault('r', c.relowner))) acl
      WHERE acl.grantee = 0 AND acl.privilege_type = privilege.privilege_type
    ))
    OR (role.role_oid <> 0 AND has_table_privilege(role.role_oid, c.oid, privilege.privilege_type))
    OR (
      role.role_oid <> 0 AND
      privilege.privilege_type IN ('SELECT', 'INSERT', 'UPDATE', 'REFERENCES')
      AND has_any_column_privilege(role.role_oid, c.oid, privilege.privilege_type)
    )
  )
ORDER BY n.nspname, c.relname, role.grantee, privilege.privilege_type`;

const POLICIES_QUERY = `
SELECT policy.schemaname AS schema_name, policy.tablename AS table_name,
       policy.policyname AS policy_name, policy.permissive, policy.roles::text[] AS roles,
       ARRAY(
         SELECT data_role.rolname::text
         FROM pg_roles data_role
         WHERE data_role.rolname IN ('anon', 'authenticated')
           AND (
             'public'::name = ANY(policy.roles)
             OR EXISTS (
               SELECT 1
               FROM unnest(policy.roles) AS policy_role(role_name)
               JOIN pg_roles target_role ON target_role.rolname = policy_role.role_name
               WHERE pg_has_role(data_role.oid, target_role.oid, 'USAGE')
             )
           )
         ORDER BY data_role.rolname
       )::text[] AS effective_roles,
       policy.cmd AS command, policy.qual AS using_expression,
       policy.with_check AS check_expression
FROM pg_policies policy
WHERE policy.schemaname = ANY($1::text[])
ORDER BY policy.schemaname, policy.tablename, policy.policyname`;

const POLICY_REFERENCES_QUERY = `
SELECT DISTINCT source_ns.nspname AS schema_name, source.relname AS table_name,
       policy.polname AS policy_name,
       referenced_ns.nspname AS referenced_schema, referenced.relname AS referenced_table
FROM pg_policy policy
JOIN pg_class source ON source.oid = policy.polrelid
JOIN pg_namespace source_ns ON source_ns.oid = source.relnamespace
JOIN pg_depend dependency
  ON dependency.classid = 'pg_policy'::regclass
 AND dependency.objid = policy.oid
 AND dependency.refclassid = 'pg_class'::regclass
 AND dependency.refobjid <> source.oid
JOIN pg_class referenced ON referenced.oid = dependency.refobjid
JOIN pg_namespace referenced_ns ON referenced_ns.oid = referenced.relnamespace
WHERE source_ns.nspname = ANY($1::text[])
  AND referenced.relkind IN ('r', 'p', 'v', 'm', 'f')
ORDER BY source_ns.nspname, source.relname, policy.polname,
         referenced_ns.nspname, referenced.relname`;

const FUNCTIONS_QUERY = `
SELECT n.nspname AS schema_name, p.proname AS function_name,
       pg_get_function_identity_arguments(p.oid) AS identity_arguments,
       p.prosecdef AS security_definer,
       p.prorettype IN ('trigger'::regtype, 'event_trigger'::regtype) AS is_trigger,
       p.proconfig::text[] AS proconfig,
       array_remove(
         array_agg(DISTINCT CASE
           WHEN role.role_oid = 0
            AND EXISTS (SELECT 1 FROM aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) acl WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE')
            AND EXISTS (SELECT 1 FROM aclexplode(COALESCE(n.nspacl, acldefault('n', n.nspowner))) acl WHERE acl.grantee = 0 AND acl.privilege_type = 'USAGE') THEN role.grantee
           WHEN role.role_oid <> 0
            AND has_schema_privilege(role.role_oid, n.oid, 'USAGE')
            AND has_function_privilege(role.role_oid, p.oid, 'EXECUTE') THEN role.grantee
         END),
         NULL
       )::text[] AS execute_roles
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
LEFT JOIN LATERAL (
  SELECT rolname AS grantee, oid AS role_oid FROM pg_roles WHERE rolname IN ('anon', 'authenticated')
  UNION ALL SELECT 'public', 0::oid
) role ON true
WHERE p.prokind = 'f' AND n.nspname = ANY($1::text[])
 GROUP BY n.nspname, p.proname, p.oid, p.prosecdef
ORDER BY n.nspname, p.proname, identity_arguments`;

export function parsePostgresArray(value: string): string[] {
  if (!value.startsWith('{') || !value.endsWith('}')) return [];
  const body = value.slice(1, -1);
  if (body === '') return [];

  const values: string[] = [];
  let current = '';
  let quoted = false;
  let escaped = false;
  let wasQuoted = false;

  const push = (): void => {
    if (wasQuoted || current !== 'NULL') values.push(current);
    current = '';
    wasQuoted = false;
  };

  for (const character of body) {
    if (escaped) {
      current += character;
      escaped = false;
    } else if (character === '\\') {
      escaped = true;
    } else if (character === '"') {
      quoted = !quoted;
      wasQuoted = true;
    } else if (character === ',' && !quoted) {
      push();
    } else {
      current += character;
    }
  }
  if (escaped || quoted) throw new Error('Invalid PostgreSQL array value');
  push();
  return values;
}

function strings(value: unknown): string[] {
  if (Array.isArray(value)) return value.map(String);
  if (typeof value === 'string') return parsePostgresArray(value);
  return [];
}

function nullableString(value: unknown, field: string): string | null {
  if (value == null) return null;
  if (typeof value !== 'string') throw new Error(`Invalid catalog ${field}`);
  return value;
}

function key(schema: string, name: string): string {
  return `${schema}\u0000${name}`;
}

export async function captureCatalogSnapshot(
  client: SqlClient,
  exposedSchemas: readonly string[] = ['public'],
  options: { includeForeignKeyDependencies?: boolean } = {},
): Promise<CatalogSnapshot> {
  // Every catalog query must share one MVCC snapshot: if a migration committed
  // mid-capture, a granted table could look ungranted and be silently skipped by
  // static rules, reporting "secure" for an insecure database. READ ONLY keeps
  // the transaction legal for any role, including read-only scanners.
  await client.query('BEGIN TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY');
  try {
    return await readCatalogSnapshot(client, exposedSchemas, options.includeForeignKeyDependencies);
  } finally {
    await client.query('ROLLBACK');
  }
}

async function readCatalogSnapshot(
  client: SqlClient,
  exposedSchemas: readonly string[],
  includeForeignKeyDependencies = false,
): Promise<CatalogSnapshot> {
  const storageProbe = await client.query(
    "SELECT to_regclass('storage.buckets') IS NOT NULL AS has_storage",
  );
  const hasStorage = Boolean(storageProbe.rows[0]?.['has_storage']);
  const capturedSchemas =
    hasStorage && !exposedSchemas.includes('storage')
      ? [...exposedSchemas, 'storage']
      : [...exposedSchemas];
  const schemaValues = [capturedSchemas];
  const dependencyTargets = new Set<string>();
  const tableSchemas = new Set(capturedSchemas);
  if (includeForeignKeyDependencies) {
    const result = await client.query(FOREIGN_KEY_TARGETS_QUERY, schemaValues);
    for (const row of result.rows) {
      const schema = String(row['schema_name']);
      dependencyTargets.add(key(schema, String(row['table_name'])));
      tableSchemas.add(schema);
    }
  }
  const tableSchemaValues = [[...tableSchemas]];
  const databaseResult = await client.query(DATABASE_QUERY);
  const tablesResult = await client.query(TABLES_QUERY, tableSchemaValues);
  const viewsResult = await client.query(VIEWS_QUERY, schemaValues);
  const columnsResult = await client.query(COLUMNS_QUERY, tableSchemaValues);
  const primaryKeysResult = await client.query(PRIMARY_KEYS_QUERY, tableSchemaValues);
  const indexesResult = await client.query(INDEXES_QUERY, schemaValues);
  const foreignKeysResult = await client.query(FOREIGN_KEYS_QUERY, tableSchemaValues);
  const grantsResult = await client.query(GRANTS_QUERY, schemaValues);
  const policiesResult = await client.query(POLICIES_QUERY, schemaValues);
  const policyReferencesResult = await client.query(POLICY_REFERENCES_QUERY, schemaValues);
  const functionsResult = await client.query(FUNCTIONS_QUERY, schemaValues);
  const storageBucketsResult = hasStorage
    ? await client.query(
        'SELECT id::text AS id, name, COALESCE(public, false) AS is_public FROM storage.buckets ORDER BY name',
      )
    : { rows: [] };

  const database = databaseResult.rows[0];
  if (!database) throw new Error('Unable to read database metadata');

  const tables = new Map<string, CatalogTable>();
  for (const row of tablesResult.rows) {
    const schema = String(row['schema_name']);
    const name = String(row['table_name']);
    if (!capturedSchemas.includes(schema) && !dependencyTargets.has(key(schema, name))) continue;
    tables.set(key(schema, name), {
      schema,
      name,
      isForeign: row['relation_kind'] === 'f',
      rlsEnabled: Boolean(row['rls_enabled']),
      rlsForced: Boolean(row['rls_forced']),
      ownerRoles: strings(row['effective_owner_roles']).map((role) => role.toLowerCase()),
      columns: [],
      primaryKey: [],
      foreignKeys: [],
      grants: [],
      policies: [],
    });
  }

  const views = new Map<string, CatalogView>();
  for (const row of viewsResult.rows) {
    const schema = String(row['schema_name']);
    const name = String(row['view_name']);
    views.set(key(schema, name), {
      schema,
      name,
      securityInvoker: Boolean(row['security_invoker']),
      grants: [],
    });
  }

  for (const row of columnsResult.rows) {
    tables.get(key(String(row['schema_name']), String(row['table_name'])))?.columns.push({
      name: String(row['column_name']),
      dataType: String(row['data_type']),
      ordinal: Number(row['ordinal_position']),
      isNullable: Boolean(row['is_nullable']),
      hasDefault: Boolean(row['has_default']),
      isGenerated: Boolean(row['is_generated']),
    });
  }
  for (const row of primaryKeysResult.rows) {
    const table = tables.get(key(String(row['schema_name']), String(row['table_name'])));
    if (table) table.primaryKey = strings(row['columns']);
  }
  for (const row of indexesResult.rows) {
    const table = tables.get(key(String(row['schema_name']), String(row['table_name'])));
    if (!table) continue;
    (table.indexes ??= []).push({
      name: String(row['index_name']),
      columns: strings(row['columns']),
    });
  }
  for (const row of foreignKeysResult.rows) {
    tables.get(key(String(row['schema_name']), String(row['table_name'])))?.foreignKeys.push({
      columns: strings(row['columns']),
      referencedSchema: String(row['referenced_schema']),
      referencedTable: String(row['referenced_table']),
      referencedColumns: strings(row['referenced_columns']),
    });
  }
  for (const row of grantsResult.rows) {
    const targetKey = key(String(row['schema_name']), String(row['table_name']));
    const target = tables.get(targetKey) ?? views.get(targetKey);
    if (!target) continue;
    const role = String(row['grantee']).toLowerCase();
    let grant = target.grants.find((entry) => entry.role === role);
    if (!grant) {
      grant = { role, privileges: [] };
      target.grants.push(grant);
    }
    const privilege = operationSchema.parse(String(row['privilege_type']).toLowerCase());
    if (!grant.privileges.includes(privilege)) grant.privileges.push(privilege);
  }
  for (const row of policiesResult.rows) {
    const schema = String(row['schema_name']);
    const tableName = String(row['table_name']);
    const policyName = String(row['policy_name']);
    const referencedRelations = policyReferencesResult.rows
      .filter(
        (reference) =>
          reference['schema_name'] === schema &&
          reference['table_name'] === tableName &&
          reference['policy_name'] === policyName,
      )
      .map((reference) => ({
        schema: String(reference['referenced_schema']),
        table: String(reference['referenced_table']),
      }));
    tables.get(key(schema, tableName))?.policies.push({
      name: policyName,
      command: z
        .enum(['all', 'select', 'insert', 'update', 'delete'])
        .parse(String(row['command']).toLowerCase()),
      permissive: String(row['permissive']).toUpperCase() === 'PERMISSIVE',
      roles: strings(row['roles']).map((role) => role.toLowerCase()),
      effectiveRoles: strings(row['effective_roles']).map((role) => role.toLowerCase()),
      ...(referencedRelations.length ? { referencedRelations } : {}),
      usingExpression: nullableString(row['using_expression'], 'policy using expression'),
      checkExpression: nullableString(row['check_expression'], 'policy check expression'),
    });
  }

  const snapshot: CatalogSnapshot = {
    version: 1,
    database: {
      name: String(database['database_name']),
      serverVersion: String(database['server_version']),
      currentRole: String(database['current_role']),
      isSuperuser: Boolean(database['is_superuser']),
      canBypassRls: Boolean(database['can_bypass_rls']),
    },
    schemas: [...exposedSchemas],
    tables: [...tables.values()].filter((table) => capturedSchemas.includes(table.schema)),
    ...(dependencyTargets.size
      ? {
          fixtureTables: [...tables.values()].filter((table) =>
            dependencyTargets.has(key(table.schema, table.name)),
          ),
        }
      : {}),
    views: [...views.values()],
    functions: functionsResult.rows.map((row) => ({
      schema: String(row['schema_name']),
      name: String(row['function_name']),
      identityArguments:
        nullableString(row['identity_arguments'], 'function identity arguments') ?? '',
      securityDefiner: Boolean(row['security_definer']),
      isTrigger: Boolean(row['is_trigger']),
      proconfig: row['proconfig'] == null ? undefined : strings(row['proconfig']),
      executeRoles: strings(row['execute_roles'])
        .map((role) => role.toLowerCase())
        .sort(),
    })),
    ...(hasStorage
      ? {
          storageBuckets: storageBucketsResult.rows.map((row) => ({
            id: String(row['id']),
            name: String(row['name']),
            isPublic: Boolean(row['is_public']),
          })),
        }
      : {}),
  };
  return catalogSnapshotSchema.parse(snapshot);
}
