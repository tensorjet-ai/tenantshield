import type { CatalogSnapshot, CatalogTable } from '@tenantshield/catalog';
import { createHash } from 'node:crypto';
import type { TenantShieldConfig } from '@tenantshield/config';
import { createFindingFingerprint, type Finding } from '@tenantshield/findings';

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '::1']);
const outerTransactionClients = new WeakSet<object>();

export const MUTATION_TRIGGER_WARNING =
  'Database sequence values are not rolled back; triggers may also cause external, non-transactional side effects when TenantShield rolls back the test transaction.';

export class DatabaseSafetyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'DatabaseSafetyError';
  }
}

export interface RemoteAccessOptions {
  allowRemoteFlag?: boolean;
  allowRemoteEnv?: boolean;
  allowedHosts?: readonly string[];
}

export interface DatabaseTarget {
  host: string;
  port: number;
  database: string;
  isRemote: boolean;
}

export function assertNotProductionTarget(
  target: DatabaseTarget,
  markers: readonly string[] = [],
  contextValues: readonly string[] = [],
): void {
  const fields = [target.host, target.database, ...contextValues];
  const marker = markers.find((entry) => {
    const normalized = entry.toLowerCase();
    if (!normalized) return false;
    return fields.some((field) => {
      const normalizedField = field.toLowerCase();
      return (
        normalizedField === normalized || normalizedField.split(/[^a-z0-9]+/).includes(normalized)
      );
    });
  });
  if (marker) {
    throw new DatabaseSafetyError(
      `Dynamic tests refused because target matches configured production-like marker ${marker}`,
    );
  }
}

function normalizedHostname(url: URL): string {
  return url.hostname.replace(/^\[|\]$/g, '').toLowerCase();
}

export function inspectDatabaseTarget(
  connectionUrl: string,
  options: RemoteAccessOptions = {},
): DatabaseTarget {
  let parsed: URL;
  try {
    parsed = new URL(connectionUrl);
  } catch {
    throw new DatabaseSafetyError('Invalid PostgreSQL connection URL');
  }
  if (parsed.protocol !== 'postgres:' && parsed.protocol !== 'postgresql:') {
    throw new DatabaseSafetyError('Connection URL must use postgres:// or postgresql://');
  }
  if (parsed.searchParams.has('host') || parsed.searchParams.has('port')) {
    throw new DatabaseSafetyError(
      'Connection URL query parameters cannot override the inspected host or port',
    );
  }

  const host = normalizedHostname(parsed);
  const isRemote = !LOCAL_HOSTS.has(host);
  if (isRemote) {
    const allowlisted =
      options.allowedHosts?.some((allowed) => allowed.toLowerCase() === host) ?? false;
    if (!options.allowRemoteFlag || !options.allowRemoteEnv || !allowlisted) {
      throw new DatabaseSafetyError(
        `Remote database host ${host} refused; require --allow-remote, TENANTSHIELD_ALLOW_REMOTE=1, and allowedHosts entry`,
      );
    }
  }

  let database: string;
  try {
    database = decodeURIComponent(parsed.pathname.replace(/^\//, ''));
  } catch {
    throw new DatabaseSafetyError('Connection URL contains an invalid encoded database name');
  }
  if (!host || !database) {
    throw new DatabaseSafetyError('Connection URL must include host and database name');
  }

  const port = parsed.port ? Number(parsed.port) : 5432;
  if (!Number.isInteger(port) || port < 1 || port > 65_535) {
    throw new DatabaseSafetyError('Connection URL contains an invalid PostgreSQL port');
  }

  return {
    host,
    port,
    database,
    isRemote,
  };
}

export interface DatabaseRoleAttributes {
  isSuperuser: boolean;
  canBypassRls: boolean;
}

export function assertDynamicRoleSafe(attributes: DatabaseRoleAttributes): void {
  if (attributes.isSuperuser) {
    throw new DatabaseSafetyError('Dynamic tests cannot run through a superuser connection');
  }
  if (attributes.canBypassRls) {
    throw new DatabaseSafetyError('Dynamic tests cannot run through a role with BYPASSRLS');
  }
}

export interface DynamicSqlResult {
  rows: Record<string, unknown>[];
  rowCount?: number | null;
}

export interface DynamicSqlClient {
  query(sql: string, values?: readonly unknown[]): Promise<DynamicSqlResult>;
}

export interface DynamicIdentity {
  role: 'anon' | 'authenticated';
  userId?: string | undefined;
  claims: Record<string, unknown>;
}

export class IdentityVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'IdentityVerificationError';
  }
}

export class FixtureSetupError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'FixtureSetupError';
  }
}

function quoteIdentifier(identifier: string): string {
  return `"${identifier.replaceAll('"', '""')}"`;
}

function jsonObject(value: unknown): Record<string, unknown> | null {
  if (typeof value === 'string') {
    try {
      const parsed: unknown = JSON.parse(value);
      return parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)
        ? (parsed as Record<string, unknown>)
        : null;
    } catch {
      return null;
    }
  }
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

export async function establishIdentity(
  client: DynamicSqlClient,
  identity: DynamicIdentity,
): Promise<void> {
  await client.query(`SET LOCAL ROLE ${quoteIdentifier(identity.role)}`);
  const claims = { ...identity.claims, sub: identity.userId ?? '', role: identity.role };
  await client.query(
    `SELECT set_config('request.jwt.claims', $1, true),
            set_config('request.jwt.claim.sub', $2, true),
            set_config('request.jwt.claim.role', $3, true)`,
    [JSON.stringify(claims), identity.userId ?? '', identity.role],
  );

  const roleResult = await client.query(`SELECT current_user AS current_role,
       r.rolsuper AS is_superuser, r.rolbypassrls AS can_bypass_rls
FROM pg_roles r WHERE r.rolname = current_user`);
  const role = roleResult.rows[0];
  if (!role || role['current_role'] !== identity.role) {
    throw new IdentityVerificationError(
      'SET LOCAL ROLE did not establish the requested Data API role',
    );
  }
  assertDynamicRoleSafe({
    isSuperuser: Boolean(role['is_superuser']),
    canBypassRls: Boolean(role['can_bypass_rls']),
  });

  const verification = await client.query('SELECT auth.uid()::text AS user_id, auth.jwt() AS jwt');
  const row = verification.rows[0];
  const expectedUserId = identity.userId ?? null;
  if (!row || (row['user_id'] ?? null) !== expectedUserId) {
    throw new IdentityVerificationError('auth.uid() did not match configured identity');
  }
  const jwt = jsonObject(row['jwt']);
  if (!jwt || jwt['role'] !== identity.role || jwt['sub'] !== (identity.userId ?? '')) {
    throw new IdentityVerificationError(
      'auth.jwt() did not contain the configured role and subject',
    );
  }
  for (const [key, value] of Object.entries(identity.claims)) {
    if (JSON.stringify(jwt[key]) !== JSON.stringify(value)) {
      throw new IdentityVerificationError(`auth.jwt() did not contain configured claim ${key}`);
    }
  }
}

export async function runIsolatedCase<T>(
  client: DynamicSqlClient,
  identity: DynamicIdentity,
  action: () => Promise<T>,
): Promise<T> {
  if (outerTransactionClients.has(client)) {
    await client.query('SAVEPOINT tenantshield_outer_case');
    try {
      await client.query("SET LOCAL statement_timeout = '5s'");
      await client.query("SET LOCAL lock_timeout = '1s'");
      await establishIdentity(client, identity);
      const result = await action();
      await client.query('SET CONSTRAINTS ALL IMMEDIATE');
      return result;
    } finally {
      await client.query('ROLLBACK TO SAVEPOINT tenantshield_outer_case');
      await client.query('RELEASE SAVEPOINT tenantshield_outer_case');
    }
  }
  await client.query('BEGIN');
  try {
    await client.query("SET LOCAL statement_timeout = '5s'");
    await client.query("SET LOCAL lock_timeout = '1s'");
    await establishIdentity(client, identity);
    await client.query('SAVEPOINT tenantshield_case');
    try {
      const result = await action();
      await client.query('SET CONSTRAINTS ALL IMMEDIATE');
      return result;
    } finally {
      await client.query('ROLLBACK TO SAVEPOINT tenantshield_case');
    }
  } finally {
    await client.query('ROLLBACK');
  }
}

function fixtureStatementTokens(sql: string): string[][] {
  const statements: string[][] = [];
  let tokens: string[] = [];
  let index = 0;

  const finishStatement = () => {
    if (tokens.length > 0) statements.push(tokens);
    tokens = [];
  };

  while (index < sql.length) {
    const character = sql[index]!;
    const next = sql[index + 1];

    if (character === '-' && next === '-') {
      index += 2;
      while (index < sql.length && sql[index] !== '\n' && sql[index] !== '\r') index += 1;
      continue;
    }
    if (character === '/' && next === '*') {
      let depth = 1;
      index += 2;
      while (index < sql.length && depth > 0) {
        if (sql[index] === '/' && sql[index + 1] === '*') {
          depth += 1;
          index += 2;
        } else if (sql[index] === '*' && sql[index + 1] === '/') {
          depth -= 1;
          index += 2;
        } else index += 1;
      }
      continue;
    }
    if (character === '$') {
      const tag = sql.slice(index).match(/^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/)?.[0];
      if (tag) {
        const closing = sql.indexOf(tag, index + tag.length);
        index = closing === -1 ? sql.length : closing + tag.length;
        continue;
      }
    }
    if (character === '"') {
      index += 1;
      while (index < sql.length) {
        if (sql[index] !== '"') index += 1;
        else if (sql[index + 1] === '"') index += 2;
        else {
          index += 1;
          break;
        }
      }
      continue;
    }
    const escapeString =
      (character === 'e' || character === 'E') &&
      next === "'" &&
      (index === 0 || !/[A-Za-z0-9_$]/.test(sql[index - 1]!));
    if (character === "'" || escapeString) {
      index += escapeString ? 2 : 1;
      while (index < sql.length) {
        if (escapeString && sql[index] === '\\') index += 2;
        else if (sql[index] !== "'") index += 1;
        else if (sql[index + 1] === "'") index += 2;
        else {
          index += 1;
          break;
        }
      }
      continue;
    }
    if (character === ';') {
      finishStatement();
      index += 1;
      continue;
    }
    if (/[A-Za-z_]/.test(character)) {
      let end = index + 1;
      while (end < sql.length && /[A-Za-z0-9_$]/.test(sql[end]!)) end += 1;
      tokens.push(sql.slice(index, end).toLowerCase());
      index = end;
      continue;
    }
    index += 1;
  }
  finishStatement();
  return statements;
}

function containsFixtureTransactionControl(sql: string): boolean {
  return fixtureStatementTokens(sql).some((tokens) => {
    const first = tokens[0];
    if (
      first === 'begin' ||
      first === 'commit' ||
      first === 'end' ||
      first === 'rollback' ||
      first === 'abort' ||
      first === 'savepoint' ||
      first === 'release'
    ) {
      return true;
    }
    return (
      (first === 'start' && tokens[1] === 'transaction') ||
      (first === 'prepare' && tokens[1] === 'transaction')
    );
  });
}

const FORBIDDEN_FIXTURE_FUNCTIONS = new Set([
  'dblink',
  'dblink_exec',
  'pg_notify',
  'pg_read_file',
  'pg_read_binary_file',
  'pg_ls_dir',
  'lo_import',
  'lo_export',
  'lo_create',
  'lo_get',
  'lo_put',
  'lo_unlink',
  'lo_from_bytea',
]);

function containsFixtureServerSideEffect(sql: string): boolean {
  return fixtureStatementTokens(sql).some((tokens) => {
    if (tokens[0] === 'copy' && tokens.includes('program')) return true;
    return tokens.some((token) => FORBIDDEN_FIXTURE_FUNCTIONS.has(token));
  });
}

export function validateFixtureSetupSql(setupSql: string): void {
  if (containsFixtureTransactionControl(setupSql)) {
    throw new FixtureSetupError(
      'Fixture SQL must not contain transaction-control statements; TenantShield owns the setup transaction',
    );
  }
  if (containsFixtureServerSideEffect(setupSql)) {
    throw new FixtureSetupError(
      'Fixture SQL must only perform deterministic data setup; side-effecting statements such as COPY TO PROGRAM, dblink, pg_notify, or large-object functions are refused',
    );
  }
}

export async function runFixtureSetup(client: DynamicSqlClient, setupSql: string): Promise<void> {
  validateFixtureSetupSql(setupSql);
  await client.query('BEGIN');
  try {
    await client.query("SET LOCAL statement_timeout = '30s'");
    await client.query("SET LOCAL lock_timeout = '5s'");
    await client.query(setupSql);
    await client.query('COMMIT');
  } catch {
    try {
      await client.query('ROLLBACK');
    } catch {
      // Preserve the redacted fixture error when the connection is already lost.
    }
    throw new FixtureSetupError(
      'Fixture setup failed; rollback was attempted and sensitive row details were redacted',
    );
  }
}

function deterministicValue(dataType: string, key: string): string {
  const digest = createHash('sha256').update(key).digest();
  switch (dataType.toLowerCase()) {
    case 'uuid': {
      const hex = digest.subarray(0, 16).toString('hex');
      return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-a${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
    }
    case 'smallint':
      return String((digest.readUInt32BE(0) % 32_767) + 1);
    case 'integer':
    case 'bigint':
      return String((digest.readUInt32BE(0) % 1_000_000) + 1);
    case 'numeric':
    case 'decimal':
    case 'real':
    case 'double precision':
      return String((digest.readUInt32BE(0) % 1_000_000) + 1);
    case 'boolean':
      return 'true';
    case 'date':
      return '2000-01-01';
    case 'timestamp with time zone':
    case 'timestamp without time zone':
      return '2000-01-01T00:00:00Z';
    case 'jsonb':
    case 'json':
      return JSON.stringify({ tenantshield: key });
    default:
      return `tenantshield-${digest.subarray(0, 8).toString('hex')}`;
  }
}

interface MembershipMapping {
  schema: string;
  table: string;
  tenantColumn: string;
  userColumn: string;
  roleColumn?: string | undefined;
}

function resolveMembershipMapping(
  resource: TenantShieldConfig['resources'][string],
  target: CatalogTable,
  candidateTables: readonly CatalogTable[],
): MembershipMapping | undefined {
  if (resource.membership) {
    return {
      schema: resource.membership.schema ?? resource.schema ?? 'public',
      table: resource.membership.table,
      tenantColumn: resource.membership.tenantColumn,
      userColumn: resource.membership.userColumn,
      roleColumn: resource.membership.roleColumn,
    };
  }

  const tenantParent = target.foreignKeys.flatMap((foreignKey) => {
    const index = foreignKey.columns.indexOf(resource.tenantColumn);
    return index < 0
      ? []
      : [
          {
            schema: foreignKey.referencedSchema,
            table: foreignKey.referencedTable,
            column: foreignKey.referencedColumns[index]!,
          },
        ];
  })[0];
  const matches: MembershipMapping[] = [];
  for (const candidate of candidateTables) {
    if (candidate.schema === target.schema && candidate.name === target.name) continue;
    const referencedByPolicy = target.policies.some((policy) =>
      policy.referencedRelations?.some(
        (relation) => relation.schema === candidate.schema && relation.table === candidate.name,
      ),
    );
    if (!referencedByPolicy) continue;
    const tenantForeignKey = tenantParent
      ? candidate.foreignKeys.flatMap((foreignKey) => {
          if (
            foreignKey.referencedSchema !== tenantParent.schema ||
            foreignKey.referencedTable !== tenantParent.table
          )
            return [];
          const index = foreignKey.referencedColumns.indexOf(tenantParent.column);
          return index < 0 ? [] : [{ column: foreignKey.columns[index]! }];
        })[0]
      : undefined;
    const userForeignKey = candidate.foreignKeys.flatMap((foreignKey) => {
      if (foreignKey.referencedSchema !== 'auth' || foreignKey.referencedTable !== 'users')
        return [];
      const index = foreignKey.referencedColumns.indexOf('id');
      return index < 0 ? [] : [{ column: foreignKey.columns[index]! }];
    })[0];
    const hasColumnPair =
      candidate.columns.some((column) => column.name === resource.tenantColumn) &&
      candidate.columns.some((column) => column.name === 'user_id');
    if (tenantForeignKey && userForeignKey) {
      matches.push({
        schema: candidate.schema,
        table: candidate.name,
        tenantColumn: tenantForeignKey.column,
        userColumn: userForeignKey.column,
      });
    } else if (hasColumnPair) {
      matches.push({
        schema: candidate.schema,
        table: candidate.name,
        tenantColumn: resource.tenantColumn,
        userColumn: 'user_id',
      });
    }
  }
  if (matches.length > 1)
    throw new FixtureSetupError(
      'Automatic membership-table detection is ambiguous; configure resources.<name>.membership',
    );
  return matches[0];
}

export async function synthesizeFixturesInTransaction(
  client: DynamicSqlClient,
  config: TenantShieldConfig,
  snapshot: CatalogSnapshot,
): Promise<DynamicRunResult> {
  const resources = Object.entries(config.resources).filter(([, resource]) => !resource.public);
  if (!resources.length) return runDynamicTests(client, config, snapshot);
  const tableKey = (schema: string, name: string) => `${schema}\0${name}`;
  const tables = new Map(
    [...snapshot.tables, ...(snapshot.fixtureTables ?? [])].map((table) => [
      tableKey(table.schema, table.name),
      table,
    ]),
  );
  const seeded = new Map<string, Record<string, unknown>>();
  const seededResourceValues = new Map<
    string,
    { owner: Record<string, unknown>; foreign: Record<string, unknown> }
  >();
  let activeTable = '';
  let inserted = false;

  const seedTable = async (
    table: CatalogTable,
    identityName: string,
    pinned: Map<string, string>,
    ancestors: ReadonlySet<string>,
  ): Promise<Record<string, unknown>> => {
    const key = tableKey(table.schema, table.name);
    const qualified = `${quoteIdentifier(table.schema)}.${quoteIdentifier(table.name)}`;
    activeTable = `${table.schema}.${table.name}`;
    if (table.isForeign)
      throw new FixtureSetupError('Automatic fixture synthesis cannot write to a foreign table');
    if (ancestors.has(key))
      throw new FixtureSetupError(
        'Automatic fixture synthesis found a non-nullable foreign-key cycle',
      );

    const identity = identityFromConfig(config, identityName);
    if (table.schema === 'auth' && table.name === 'users' && identity.userId) {
      if (pinned.has('id') && pinned.get('id') !== identity.userId)
        throw new FixtureSetupError('Foreign key conflicts with the configured auth user');
      pinned.set('id', identity.userId);
    }
    const fixtureKey = JSON.stringify([
      key,
      pinned.size > 0 ? null : identityName,
      [...pinned].sort(),
    ]);
    const existing = seeded.get(fixtureKey);
    if (existing) return existing;
    const parents = new Set([...ancestors, key]);
    const values = new Map<string, string | null>(pinned);
    for (const fk of table.foreignKeys) {
      if (
        fk.columns.every(
          (column) =>
            !values.has(column) &&
            table.columns.some((candidate) => candidate.name === column && candidate.isNullable),
        )
      ) {
        for (const column of fk.columns) values.set(column, null);
        continue;
      }
      const referenced = tables.get(tableKey(fk.referencedSchema, fk.referencedTable));
      if (!referenced)
        throw new FixtureSetupError('Foreign-key target is missing from the fixture catalog');
      const targetPins = new Map<string, string>();
      fk.columns.forEach((column, index) => {
        const value = values.get(column);
        if (typeof value === 'string') targetPins.set(fk.referencedColumns[index]!, value);
      });
      const parent = await seedTable(referenced, identityName, targetPins, parents);
      fk.columns.forEach((column, index) => {
        const value = parent[fk.referencedColumns[index]!];
        if (typeof value !== 'string')
          throw new FixtureSetupError('Foreign-key target did not return a fixture key');
        values.set(column, value);
      });
    }

    activeTable = `${table.schema}.${table.name}`;
    for (const column of table.columns) {
      if (
        !values.has(column.name) &&
        !column.hasDefault &&
        !column.isGenerated &&
        (column.isNullable === false || table.primaryKey.includes(column.name))
      ) {
        values.set(
          column.name,
          deterministicValue(column.dataType, `${fixtureKey}:${column.name}`),
        );
      }
    }
    for (const column of values.keys()) {
      if (!table.columns.some((candidate) => candidate.name === column && !candidate.isGenerated))
        throw new FixtureSetupError('Fixture requires writing a missing or generated column');
    }
    const columns = [...values.keys()];
    const insert = columns.length
      ? `(${columns.map(quoteIdentifier).join(', ')}) VALUES (${columns.map((_, index) => `$${index + 1}`).join(', ')})`
      : 'DEFAULT VALUES';
    const returning = table.columns
      .map(({ name }) => `${quoteIdentifier(name)}::text AS ${quoteIdentifier(name)}`)
      .join(', ');
    inserted = true;
    const result = await client.query(
      `INSERT INTO ${qualified} ${insert}${returning ? ` RETURNING ${returning}` : ''}`,
      [...values.values()],
    );
    const row = result.rows[0];
    if (!row) throw new FixtureSetupError('Fixture insert did not return a row');
    seeded.set(fixtureKey, row);
    return row;
  };

  const membershipFixtureValues = (
    mapping: MembershipMapping,
    identityName: string,
    tenant: string,
  ): Map<string, string> => {
    const identity = identityFromConfig(config, identityName);
    if (!identity.userId) {
      throw new FixtureSetupError(`Membership fixture requires authenticated user ${identityName}`);
    }
    const pinned = new Map<string, string>([
      [mapping.tenantColumn, tenant],
      [mapping.userColumn, identity.userId],
    ]);
    if (mapping.roleColumn) {
      if (!identity.membershipRole) {
        throw new FixtureSetupError(
          `Membership fixture requires membershipRole for ${identityName}`,
        );
      }
      pinned.set(mapping.roleColumn, identity.membershipRole);
    }
    return pinned;
  };

  await client.query('BEGIN');
  outerTransactionClients.add(client);
  try {
    await client.query("SET LOCAL statement_timeout = '30s'");
    await client.query("SET LOCAL lock_timeout = '5s'");
    for (const [name, resource] of resources) {
      const schema = resource.schema ?? 'public';
      activeTable = `${schema}.${name}`;
      const table = tables.get(tableKey(schema, name));
      const tenantColumn = table?.columns.find((column) => column.name === resource.tenantColumn);
      if (!table || !tenantColumn)
        throw new FixtureSetupError('Resource or tenant column is missing');
      const sideValues: { identityName: string; tenant: string; row: Record<string, unknown> }[] =
        [];
      for (const [side, identityName, explicitTenant] of [
        ['owner', resource.ownerIdentity, resource.ownerTenantValue],
        ['foreign', resource.foreignIdentity, resource.foreignTenantValue],
      ] as const) {
        const identity = identityFromConfig(config, identityName);
        const value = tenantClaim(
          identity,
          tenantColumn.name,
          tenantColumn.dataType,
          explicitTenant,
        );
        const row = await seedTable(
          table,
          identityName,
          new Map([[tenantColumn.name, value]]),
          new Set(),
        );
        sideValues.push({ identityName, tenant: value, row });
        const current = seededResourceValues.get(name) ?? { owner: {}, foreign: {} };
        current[side] = row;
        seededResourceValues.set(name, current);
      }

      const membership = resolveMembershipMapping(resource, table, [...tables.values()]);
      if (membership) {
        const membershipTable = tables.get(tableKey(membership.schema, membership.table));
        if (!membershipTable)
          throw new FixtureSetupError(
            `Membership table ${membership.schema}.${membership.table} is missing from the catalog`,
          );
        for (const { identityName, tenant } of sideValues) {
          await seedTable(
            membershipTable,
            identityName,
            membershipFixtureValues(membership, identityName, tenant),
            new Set(),
          );
        }
        if (resource.dualMemberIdentity) {
          for (const { tenant } of sideValues) {
            await seedTable(
              membershipTable,
              resource.dualMemberIdentity,
              membershipFixtureValues(membership, resource.dualMemberIdentity, tenant),
              new Set(),
            );
          }
        }
      }
    }
    const result = await runDynamicTests(client, config, snapshot, {
      seededFixtures: Object.fromEntries(seededResourceValues),
    });
    return {
      ...result,
      warnings: [...new Set([...result.warnings, ...(inserted ? [MUTATION_TRIGGER_WARNING] : [])])],
    };
  } catch (error) {
    if (isDatabaseConnectionError(error) || error instanceof DatabaseSafetyError) throw error;
    const code = postgresErrorCode(error);
    const reason = code && /^[0-9A-Z]{5}$/.test(code) ? ` (SQLSTATE ${code})` : '';
    const warnings = [
      `Automatic fixture synthesis or control setup failed for ${activeTable}${reason}; the dynamic suite is UNRELIABLE and row details were redacted.`,
    ];
    if (inserted) warnings.push(MUTATION_TRIGGER_WARNING);
    return {
      complete: false,
      cases: resources.flatMap(([name, resource]) =>
        resource.testOperations.map((operation): DynamicCaseResult => ({
          resource: `${resource.schema ?? 'public'}.${name}`,
          operation,
          control: 'same',
          identity: resource.ownerIdentity,
          status: 'error',
          observed: 'not-run',
        })),
      ),
      findings: [],
      warnings,
    };
  } finally {
    outerTransactionClients.delete(client);
    await client.query('ROLLBACK');
  }
}

export interface DynamicCaseResult {
  resource: string;
  operation: 'select' | 'insert' | 'update' | 'delete';
  control: 'same' | 'foreign';
  identity: string;
  status: 'passed' | 'failed' | 'error' | 'skipped';
  observed: 'allowed' | 'blocked' | 'sql-error' | 'not-run';
  scenario?:
    | 'reverse-cross'
    | 'tenant-reassignment'
    | 'tenant-takeover'
    | 'reverse-tenant-reassignment'
    | 'reverse-tenant-takeover'
    | 'dual-membership'
    | 'dual-membership-cardinality';
}

export interface DynamicRunResult {
  cases: DynamicCaseResult[];
  findings: Finding[];
  warnings: string[];
  complete: boolean;
}

interface FixtureReference {
  primaryKeys: string[];
  tenantKey: string;
  columns: Record<string, string>;
}

function requiredInsertColumns(table: CatalogTable, tenantColumn: string) {
  return table.columns.filter(
    (column) =>
      column.name === tenantColumn ||
      (!column.isGenerated &&
        !column.hasDefault &&
        (column.isNullable === false || table.primaryKey.includes(column.name))),
  );
}

function identityFromConfig(
  config: TenantShieldConfig,
  name: string,
): TenantShieldConfig['identities'][string] {
  const identity = config.identities[name];
  if (!identity) throw new FixtureSetupError(`Configured identity ${name} does not exist`);
  return identity;
}

function tenantClaim(
  identity: TenantShieldConfig['identities'][string],
  column: string,
  dataType: string,
  explicitValue?: unknown,
): string {
  const value = explicitValue ?? identity.tenants?.[column] ?? identity.claims[column];
  if (typeof value !== 'string' && typeof value !== 'number') {
    throw new FixtureSetupError(
      `Identity is missing a scalar claim matching tenant column ${column}`,
    );
  }
  const text = String(value);
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(text)) {
    return text.toLowerCase();
  }
  if (['smallint', 'integer', 'bigint'].includes(dataType) && /^[+-]?\d+$/.test(text)) {
    return BigInt(text).toString();
  }
  return text;
}

async function fixtureReference(
  client: DynamicSqlClient,
  identity: DynamicIdentity,
  schema: string,
  table: string,
  primaryKeys: string[],
  tenantColumn: string,
  tenant: string,
  fixtureColumns: readonly string[],
): Promise<FixtureReference> {
  let result: DynamicSqlResult;
  try {
    result = await runIsolatedCase(client, identity, () =>
      client.query(
        `/* tenantshield_fixture */ SELECT ${primaryKeys.map((column, index) => `${quoteIdentifier(column)}::text AS primary_key_${index}`).join(', ')},
              ${fixtureColumns.map((column, index) => `${quoteIdentifier(column)}::text AS fixture_column_${index}`).join(', ')}${fixtureColumns.length ? ',' : ''}
              ${quoteIdentifier(tenantColumn)}::text AS tenant_key
       FROM ${quoteIdentifier(schema)}.${quoteIdentifier(table)}
       WHERE ${quoteIdentifier(tenantColumn)} = $1
       ORDER BY ${primaryKeys.map((column) => `${quoteIdentifier(column)}::text`).join(', ')} LIMIT 1`,
        [tenant],
      ),
    );
  } catch (error) {
    if (
      isDatabaseConnectionError(error) ||
      error instanceof IdentityVerificationError ||
      error instanceof DatabaseSafetyError
    ) {
      throw error;
    }
    throw new FixtureSetupError(
      `Control-row lookup failed for ${schema}.${table}; database details were redacted`,
    );
  }
  const row = result.rows[0];
  const values = primaryKeys.map(
    (_, index) =>
      row?.[`primary_key_${index}`] ??
      (primaryKeys.length === 1 ? row?.['primary_key'] : undefined),
  );
  if (
    !row ||
    values.some((value) => typeof value !== 'string') ||
    typeof row['tenant_key'] !== 'string'
  ) {
    throw new FixtureSetupError(
      `No visible control row for ${schema}.${table}; row values redacted`,
    );
  }
  const columns: Record<string, string> = {};
  fixtureColumns.forEach((column, index) => {
    const value = row[`fixture_column_${index}`];
    if (typeof value === 'string') columns[column] = value;
  });
  return { primaryKeys: values as string[], tenantKey: row['tenant_key'], columns };
}

function primaryKeyPredicate(columns: readonly string[], firstParameter = 1): string {
  return columns
    .map((column, index) => `${quoteIdentifier(column)}::text = $${firstParameter + index}`)
    .join(' AND ');
}

function postgresErrorCode(error: unknown): string | null {
  if (error && typeof error === 'object' && 'code' in error && typeof error.code === 'string')
    return error.code;
  return null;
}

export function isDatabaseConnectionError(error: unknown): boolean {
  const code = postgresErrorCode(error);
  if (
    code?.startsWith('08') ||
    [
      '57P01',
      '57P02',
      '57P03',
      'ECONNRESET',
      'ECONNREFUSED',
      'ECONNABORTED',
      'EADDRNOTAVAIL',
      'EPIPE',
      'ETIMEDOUT',
      'ENOTFOUND',
      'EAI_AGAIN',
      'ENETUNREACH',
      'EHOSTUNREACH',
      'ERR_TLS_CERT_ALTNAME_INVALID',
      'ERR_SOCKET_CLOSED',
      'CERT_HAS_EXPIRED',
      'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
    ].includes(code ?? '')
  ) {
    return true;
  }
  return (
    error instanceof Error &&
    /connection (?:terminated|closed|lost)|socket hang up/i.test(error.message)
  );
}

export function isDatabaseOperationError(error: unknown): boolean {
  if (isDatabaseConnectionError(error)) return true;
  const code = postgresErrorCode(error);
  return code !== null && /^[0-9A-Z]{5}$/.test(code);
}

function isAuthorizationError(error: unknown): boolean {
  return ['42501', '44000'].includes(postgresErrorCode(error) ?? '');
}

async function executeCase(
  client: DynamicSqlClient,
  identity: DynamicIdentity,
  identityName: string,
  resourceName: string,
  operation: DynamicCaseResult['operation'],
  control: DynamicCaseResult['control'],
  action: (actingIdentityName?: string) => Promise<DynamicSqlResult>,
  scenario?: DynamicCaseResult['scenario'],
): Promise<DynamicCaseResult> {
  try {
    const result = await runIsolatedCase(client, identity, () => action(identityName));
    const allowed = (result.rowCount ?? result.rows.length) > 0;
    const passed = control === 'same' ? allowed : !allowed;
    return {
      resource: resourceName,
      operation,
      control,
      identity: identityName,
      status: passed ? 'passed' : 'failed',
      observed: allowed ? 'allowed' : 'blocked',
      ...(scenario ? { scenario } : {}),
    };
  } catch (error) {
    if (isDatabaseConnectionError(error)) throw error;
    if (error instanceof IdentityVerificationError || error instanceof DatabaseSafetyError) {
      throw error;
    }
    if (scenario === 'dual-membership' && postgresErrorCode(error) === '21000') {
      return {
        resource: resourceName,
        operation,
        control,
        identity: identityName,
        status: 'error',
        observed: 'sql-error',
        scenario: 'dual-membership-cardinality',
      };
    }
    if (control === 'foreign' && isAuthorizationError(error)) {
      return {
        resource: resourceName,
        operation,
        control,
        identity: identityName,
        status: 'passed',
        observed: 'blocked',
        ...(scenario ? { scenario } : {}),
      };
    }
    return {
      resource: resourceName,
      operation,
      control,
      identity: identityName,
      status: 'error',
      observed: 'sql-error',
      ...(scenario ? { scenario } : {}),
    };
  }
}

function dynamicFinding(testCase: DynamicCaseResult, schema: string, table: string): Finding {
  if (testCase.scenario === 'dual-membership-cardinality') {
    const base: Omit<Finding, 'fingerprint'> = {
      ruleId: 'TS-DYN-SUBQUERY',
      title: 'Tenant membership policy raises a cardinality error',
      severity: 'high',
      confidence: 'high',
      source: 'dynamic',
      schema,
      table,
      operation: testCase.operation,
      identity: testCase.identity,
      expected:
        'Membership predicates return a set and support users belonging to multiple organizations',
      observed: 'A positive dual-organization control raised SQLSTATE 21000',
      reproduction: {
        command: 'tenantshield test',
        details: `${schema}.${table} as ${testCase.identity}; SQLSTATE 21000 details redacted`,
      },
      remediation: 'Use IN or EXISTS for multi-membership checks instead of a scalar subquery.',
      documentationUrl: 'https://github.com/tenantshield/tenantshield#ts-dyn-subquery',
    };
    return { ...base, fingerprint: createFindingFingerprint(base) };
  }
  const ruleId = `TS-DYN-${testCase.operation.toUpperCase()}`;
  const reassignment = testCase.scenario === 'tenant-reassignment';
  const takeover = testCase.scenario === 'tenant-takeover';
  const reverseCross = testCase.scenario === 'reverse-cross';
  const reverseReassignment = testCase.scenario === 'reverse-tenant-reassignment';
  const reverseTakeover = testCase.scenario === 'reverse-tenant-takeover';
  const scenarioLabel =
    reassignment || reverseReassignment
      ? 'tenant reassignment'
      : takeover || reverseTakeover
        ? 'tenant takeover'
        : testCase.operation;
  const base: Omit<Finding, 'fingerprint'> = {
    ruleId,
    title: `Cross-tenant ${testCase.operation.toUpperCase()} succeeded`,
    severity: 'critical',
    confidence: 'high',
    source: 'dynamic',
    schema,
    table,
    operation: testCase.operation,
    identity: testCase.identity,
    testedTenant: reassignment
      ? 'owner-row-to-foreign-identity-tenant'
      : takeover
        ? 'owner-row-to-foreign-identity-tenant'
        : reverseReassignment
          ? 'foreign-row-to-owner-identity-tenant'
          : reverseTakeover
            ? 'foreign-row-to-owner-identity-tenant'
            : reverseCross
              ? 'foreign-identity-tenant'
              : 'owner-identity-tenant',
    expected: reassignment
      ? 'Tenant-column reassignment to a foreign tenant blocked'
      : takeover
        ? 'Foreign identity blocked from taking over an owner row'
        : reverseReassignment
          ? 'Tenant-column reassignment to the owner tenant blocked'
          : reverseTakeover
            ? 'Owner identity blocked from taking over a foreign row'
            : reverseCross
              ? 'Owner identity blocked from operating on the foreign tenant'
              : 'Foreign identity blocked from operating on the owner tenant',
    observed: reassignment
      ? 'Owner reassigned a row to a foreign tenant'
      : takeover
        ? 'Foreign identity reassigned an owner row to its own tenant'
        : reverseReassignment
          ? 'Foreign identity reassigned its row to the owner tenant'
          : reverseTakeover
            ? 'Owner identity reassigned a foreign row to its own tenant'
            : reverseCross
              ? 'Owner identity operated on the foreign tenant'
              : 'Foreign identity operated on the owner tenant',
    reproduction: {
      command: 'tenantshield test',
      details: `${schema}.${table} ${scenarioLabel} as ${testCase.identity}; identifiers and row values redacted`,
    },
    remediation: `Add a tenant-scoped ${testCase.operation.toUpperCase()} policy and verify its role target.`,
    documentationUrl: `https://github.com/tenantshield/tenantshield#${ruleId.toLowerCase()}`,
  };
  return { ...base, fingerprint: createFindingFingerprint(base) };
}

export interface DynamicTestOptions {
  maxConcurrentResources?: number;
  seededFixtures?: Record<
    string,
    { owner: Record<string, unknown>; foreign: Record<string, unknown> }
  >;
}

interface ResourceOutcome {
  cases: DynamicCaseResult[];
  findings: Finding[];
  warnings: string[];
}

export async function runDynamicTests(
  client: DynamicSqlClient,
  config: TenantShieldConfig,
  snapshot: CatalogSnapshot,
  options: DynamicTestOptions = {},
): Promise<DynamicRunResult> {
  const runResource = async (
    resourceName: string,
    resource: (typeof config.resources)[string],
  ): Promise<ResourceOutcome> => {
    const cases: DynamicCaseResult[] = [];
    const findings: Finding[] = [];
    const warnings: string[] = [];

    const schema = resource.schema ?? 'public';
    const caseResource = `${schema}.${resourceName}`;
    const table = snapshot.tables.find(
      (entry) => entry.schema === schema && entry.name === resourceName,
    );
    if (!table)
      throw new FixtureSetupError(`Configured resource ${schema}.${resourceName} does not exist`);
    const columnNames = new Set(table.columns.map((column) => column.name));
    const tenantColumn = table.columns.find((column) => column.name === resource.tenantColumn);
    const primaryKeys =
      typeof resource.primaryKey === 'string' ? [resource.primaryKey] : resource.primaryKey;
    if (primaryKeys.some((column) => !columnNames.has(column)) || !tenantColumn) {
      throw new FixtureSetupError(
        `Configured key columns do not exist on ${schema}.${resourceName}`,
      );
    }
    if (
      table.primaryKey.length !== primaryKeys.length ||
      table.primaryKey.some((column, index) => column !== primaryKeys[index])
    ) {
      throw new FixtureSetupError(
        `Configured primaryKey must match the primary key columns on ${schema}.${resourceName}`,
      );
    }
    const owner = identityFromConfig(config, resource.ownerIdentity);
    const foreign = identityFromConfig(config, resource.foreignIdentity);
    const insertColumns = requiredInsertColumns(table, resource.tenantColumn);
    const requiredForeignKeyColumns = new Set(
      table.foreignKeys.flatMap((foreignKey) => foreignKey.columns),
    );
    const fixtureColumns = resource.testOperations.includes('insert')
      ? insertColumns
          .filter(
            (column) =>
              column.name !== resource.tenantColumn && requiredForeignKeyColumns.has(column.name),
          )
          .map((column) => column.name)
      : [];
    const seededValues = options.seededFixtures?.[resourceName];
    const ownerTenant = tenantClaim(
      owner,
      resource.tenantColumn,
      tenantColumn.dataType,
      resource.ownerTenantValue,
    );
    const foreignTenant = tenantClaim(
      foreign,
      resource.tenantColumn,
      tenantColumn.dataType,
      resource.foreignTenantValue,
    );
    if (ownerTenant === foreignTenant) {
      throw new FixtureSetupError(
        `Owner and foreign controls resolve to the same database tenant for ${schema}.${resourceName}`,
      );
    }
    let ownerRow: FixtureReference | undefined;
    let foreignRow: FixtureReference | undefined;
    if (resource.testOperations.some((operation) => operation !== 'insert')) {
      ownerRow = await fixtureReference(
        client,
        owner,
        schema,
        resourceName,
        primaryKeys,
        resource.tenantColumn,
        ownerTenant,
        fixtureColumns,
      );
      foreignRow = await fixtureReference(
        client,
        foreign,
        schema,
        resourceName,
        primaryKeys,
        resource.tenantColumn,
        foreignTenant,
        fixtureColumns,
      );
      if (ownerRow.tenantKey === foreignRow.tenantKey) {
        throw new FixtureSetupError(
          `Owner and foreign controls resolve to the same database tenant for ${schema}.${resourceName}`,
        );
      }
    }

    for (const operation of resource.testOperations) {
      const qualified = `${quoteIdentifier(schema)}.${quoteIdentifier(resourceName)}`;
      if (operation !== 'insert' && (!ownerRow || !foreignRow)) {
        throw new FixtureSetupError(
          `No control rows available for ${schema}.${resourceName}; row values redacted`,
        );
      }
      let ownerSameAction: () => Promise<DynamicSqlResult>;
      let foreignSameAction: () => Promise<DynamicSqlResult>;
      let crossAction: () => Promise<DynamicSqlResult>;
      let reverseCrossAction: () => Promise<DynamicSqlResult>;
      let tenantReassignmentAction: (() => Promise<DynamicSqlResult>) | undefined;
      let reverseTenantAction: (() => Promise<DynamicSqlResult>) | undefined;
      const tenantPredicate = (param: number) =>
        `${quoteIdentifier(resource.tenantColumn)}::text = $${param}`;
      if (operation === 'select') {
        const sql = `/* tenantshield_select */ SELECT 1 FROM ${qualified}
        WHERE ${primaryKeyPredicate(primaryKeys)} AND ${tenantPredicate(primaryKeys.length + 1)}
        LIMIT 1`;
        ownerSameAction = () => client.query(sql, [...ownerRow!.primaryKeys, ownerRow!.tenantKey]);
        foreignSameAction = () =>
          client.query(sql, [...foreignRow!.primaryKeys, foreignRow!.tenantKey]);
        crossAction = () => client.query(sql, [...ownerRow!.primaryKeys, ownerRow!.tenantKey]);
        reverseCrossAction = () =>
          client.query(sql, [...foreignRow!.primaryKeys, foreignRow!.tenantKey]);
      } else if (operation === 'insert') {
        let probeOrdinal = 0;
        const tenantParent = table.foreignKeys.flatMap((foreignKey) => {
          const index = foreignKey.columns.indexOf(resource.tenantColumn);
          return index < 0
            ? []
            : [
                {
                  schema: foreignKey.referencedSchema,
                  table: foreignKey.referencedTable,
                  column: foreignKey.referencedColumns[index]!,
                },
              ];
        })[0];
        const makeInsertAction =
          (
            tenant: string,
            identityName: string,
            fixtureValues: Record<string, unknown> | undefined,
          ) =>
          async (actingIdentityName = identityName): Promise<DynamicSqlResult> => {
            const probeKey = `${schema}.${resourceName}:${operation}:${identityName}:${actingIdentityName}:${probeOrdinal++}`;
            const values = insertColumns.map((column) => {
              if (column.name === resource.tenantColumn) return tenant;
              const foreignKey = table.foreignKeys.find((candidate) =>
                candidate.columns.includes(column.name),
              );
              if (foreignKey) {
                const index = foreignKey.columns.indexOf(column.name);
                const referencedColumn = foreignKey.referencedColumns[index]!;
                if (
                  foreignKey.referencedSchema === 'auth' &&
                  foreignKey.referencedTable === 'users' &&
                  referencedColumn === 'id'
                ) {
                  const userId = config.identities[actingIdentityName]?.userId;
                  if (userId) return userId;
                }
                const fixtureValue = fixtureValues?.[column.name];
                if (typeof fixtureValue === 'string') return fixtureValue;
                if (
                  tenantParent &&
                  foreignKey.referencedSchema === tenantParent.schema &&
                  foreignKey.referencedTable === tenantParent.table &&
                  referencedColumn === tenantParent.column
                )
                  return tenant;
                throw new FixtureSetupError(
                  `Required foreign-key value for ${column.name} is missing from tenant fixtures`,
                );
              }
              return deterministicValue(column.dataType, `${probeKey}:${column.name}`);
            });
            const columns = insertColumns.map((column) => quoteIdentifier(column.name));
            const placeholders = values.map((_, index) => `$${index + 1}`);
            const sql = `/* tenantshield_insert */ INSERT INTO ${qualified} (${columns.join(', ')}) VALUES (${placeholders.join(', ')})`;
            return client.query(sql, values);
          };
        const ownerValues = ownerRow?.columns ?? seededValues?.owner;
        const foreignValues = foreignRow?.columns ?? seededValues?.foreign;
        ownerSameAction = makeInsertAction(ownerTenant, resource.ownerIdentity, ownerValues);
        foreignSameAction = makeInsertAction(
          foreignTenant,
          resource.foreignIdentity,
          foreignValues,
        );
        crossAction = makeInsertAction(ownerTenant, resource.ownerIdentity, ownerValues);
        reverseCrossAction = makeInsertAction(
          foreignTenant,
          resource.foreignIdentity,
          foreignValues,
        );
        warnings.push(MUTATION_TRIGGER_WARNING);
      } else if (operation === 'update') {
        const sql = `/* tenantshield_update */ UPDATE ${qualified}
        SET ${quoteIdentifier(resource.tenantColumn)} = ${quoteIdentifier(resource.tenantColumn)}
        WHERE ${primaryKeyPredicate(primaryKeys)} AND ${tenantPredicate(primaryKeys.length + 1)}`;
        ownerSameAction = () => client.query(sql, [...ownerRow!.primaryKeys, ownerRow!.tenantKey]);
        foreignSameAction = () =>
          client.query(sql, [...foreignRow!.primaryKeys, foreignRow!.tenantKey]);
        crossAction = () => client.query(sql, [...ownerRow!.primaryKeys, ownerRow!.tenantKey]);
        reverseCrossAction = () =>
          client.query(sql, [...foreignRow!.primaryKeys, foreignRow!.tenantKey]);
        const tenantSql = `/* tenantshield_update_tenant */ UPDATE ${qualified}
        SET ${quoteIdentifier(resource.tenantColumn)} = $${primaryKeys.length + 1}
        WHERE ${primaryKeyPredicate(primaryKeys)} AND ${tenantPredicate(primaryKeys.length + 2)}`;
        tenantReassignmentAction = () =>
          client.query(tenantSql, [...ownerRow!.primaryKeys, foreignTenant, ownerRow!.tenantKey]);
        reverseTenantAction = () =>
          client.query(tenantSql, [...foreignRow!.primaryKeys, ownerTenant, foreignRow!.tenantKey]);
        warnings.push(MUTATION_TRIGGER_WARNING);
      } else {
        const sql = `/* tenantshield_delete */ DELETE FROM ${qualified}
        WHERE ${primaryKeyPredicate(primaryKeys)} AND ${tenantPredicate(primaryKeys.length + 1)}`;
        ownerSameAction = () => client.query(sql, [...ownerRow!.primaryKeys, ownerRow!.tenantKey]);
        foreignSameAction = () =>
          client.query(sql, [...foreignRow!.primaryKeys, foreignRow!.tenantKey]);
        crossAction = () => client.query(sql, [...ownerRow!.primaryKeys, ownerRow!.tenantKey]);
        reverseCrossAction = () =>
          client.query(sql, [...foreignRow!.primaryKeys, foreignRow!.tenantKey]);
        warnings.push(MUTATION_TRIGGER_WARNING);
      }

      const ownerSame = await executeCase(
        client,
        owner,
        resource.ownerIdentity,
        caseResource,
        operation,
        'same',
        ownerSameAction,
      );
      cases.push(ownerSame);
      if (ownerSame.status !== 'passed') {
        warnings.push(
          `Positive control failed for ${schema}.${resourceName} ${operation.toUpperCase()} as ${resource.ownerIdentity}.`,
        );
      }

      const foreignSame = await executeCase(
        client,
        foreign,
        resource.foreignIdentity,
        caseResource,
        operation,
        'same',
        foreignSameAction,
      );
      cases.push(foreignSame);

      if (resource.dualMemberIdentity) {
        const dual = identityFromConfig(config, resource.dualMemberIdentity);
        const dualControls = [
          await executeCase(
            client,
            dual,
            resource.dualMemberIdentity,
            caseResource,
            operation,
            'same',
            ownerSameAction,
            'dual-membership',
          ),
          await executeCase(
            client,
            dual,
            resource.dualMemberIdentity,
            caseResource,
            operation,
            'same',
            foreignSameAction,
            'dual-membership',
          ),
        ];
        cases.push(...dualControls);
        for (const dualControl of dualControls) {
          if (
            dualControl.status === 'error' &&
            dualControl.scenario === 'dual-membership-cardinality'
          ) {
            const issue = dynamicFinding(dualControl, schema, resourceName);
            if (!findings.some((finding) => finding.fingerprint === issue.fingerprint)) {
              findings.push(issue);
            }
          }
          if (dualControl.status !== 'passed')
            warnings.push(
              `Dual-membership positive control failed for ${schema}.${resourceName} ${operation.toUpperCase()}; suite is incomplete.`,
            );
        }
      }

      let cross: DynamicCaseResult;
      if (foreignSame.status !== 'passed') {
        warnings.push(
          `Positive control failed for ${schema}.${resourceName} ${operation.toUpperCase()} as ${resource.foreignIdentity}; cross-tenant case skipped.`,
        );
        cross = {
          resource: caseResource,
          operation,
          control: 'foreign',
          identity: resource.foreignIdentity,
          status: 'skipped',
          observed: 'not-run',
        };
      } else {
        cross = await executeCase(
          client,
          foreign,
          resource.foreignIdentity,
          caseResource,
          operation,
          'foreign',
          crossAction,
        );
      }
      cases.push(cross);
      if (cross.status === 'error') {
        warnings.push(
          `Authorization case errored for ${schema}.${resourceName} ${operation.toUpperCase()}; result is inconclusive.`,
        );
      }
      if (cross.status === 'failed' && cross.observed === 'allowed') {
        findings.push(dynamicFinding(cross, schema, resourceName));
      }

      let reverseCross: DynamicCaseResult;
      if (ownerSame.status !== 'passed') {
        reverseCross = {
          resource: caseResource,
          operation,
          control: 'foreign',
          identity: resource.ownerIdentity,
          status: 'skipped',
          observed: 'not-run',
          scenario: 'reverse-cross',
        };
      } else {
        reverseCross = await executeCase(
          client,
          owner,
          resource.ownerIdentity,
          caseResource,
          operation,
          'foreign',
          reverseCrossAction,
          'reverse-cross',
        );
      }
      cases.push(reverseCross);
      if (reverseCross.status === 'error') {
        warnings.push(
          `Reverse authorization case errored for ${schema}.${resourceName} ${operation.toUpperCase()}; result is inconclusive.`,
        );
      }
      if (reverseCross.status === 'failed' && reverseCross.observed === 'allowed') {
        findings.push(dynamicFinding(reverseCross, schema, resourceName));
      }

      if (operation === 'update' && tenantReassignmentAction && reverseTenantAction) {
        if (foreignSame.status !== 'passed') {
          cases.push({
            resource: caseResource,
            operation,
            control: 'foreign',
            identity: resource.foreignIdentity,
            status: 'skipped',
            observed: 'not-run',
            scenario: 'tenant-takeover',
          });
        } else {
          const takeover = await executeCase(
            client,
            foreign,
            resource.foreignIdentity,
            caseResource,
            operation,
            'foreign',
            tenantReassignmentAction,
            'tenant-takeover',
          );
          cases.push(takeover);
          if (takeover.status === 'error') {
            warnings.push(
              `Tenant-takeover case errored for ${schema}.${resourceName} UPDATE; result is inconclusive.`,
            );
          }
          if (takeover.status === 'failed' && takeover.observed === 'allowed') {
            findings.push(dynamicFinding(takeover, schema, resourceName));
          }
        }

        if (foreignSame.status !== 'passed') {
          cases.push({
            resource: caseResource,
            operation,
            control: 'foreign',
            identity: resource.foreignIdentity,
            status: 'skipped',
            observed: 'not-run',
            scenario: 'reverse-tenant-reassignment',
          });
        } else {
          const reverseReassignment = await executeCase(
            client,
            foreign,
            resource.foreignIdentity,
            caseResource,
            operation,
            'foreign',
            reverseTenantAction,
            'reverse-tenant-reassignment',
          );
          cases.push(reverseReassignment);
          if (reverseReassignment.status === 'error') {
            warnings.push(
              `Reverse tenant-reassignment case errored for ${schema}.${resourceName} UPDATE; result is inconclusive.`,
            );
          }
          if (
            reverseReassignment.status === 'failed' &&
            reverseReassignment.observed === 'allowed'
          ) {
            findings.push(dynamicFinding(reverseReassignment, schema, resourceName));
          }
        }

        if (ownerSame.status !== 'passed') {
          cases.push({
            resource: caseResource,
            operation,
            control: 'foreign',
            identity: resource.ownerIdentity,
            status: 'skipped',
            observed: 'not-run',
            scenario: 'reverse-tenant-takeover',
          });
        } else {
          const reverseTakeover = await executeCase(
            client,
            owner,
            resource.ownerIdentity,
            caseResource,
            operation,
            'foreign',
            reverseTenantAction,
            'reverse-tenant-takeover',
          );
          cases.push(reverseTakeover);
          if (reverseTakeover.status === 'error') {
            warnings.push(
              `Reverse tenant-takeover case errored for ${schema}.${resourceName} UPDATE; result is inconclusive.`,
            );
          }
          if (reverseTakeover.status === 'failed' && reverseTakeover.observed === 'allowed') {
            findings.push(dynamicFinding(reverseTakeover, schema, resourceName));
          }
        }

        if (ownerSame.status !== 'passed') {
          cases.push({
            resource: caseResource,
            operation,
            control: 'foreign',
            identity: resource.ownerIdentity,
            status: 'skipped',
            observed: 'not-run',
            scenario: 'tenant-reassignment',
          });
        } else {
          const reassignment = await executeCase(
            client,
            owner,
            resource.ownerIdentity,
            caseResource,
            operation,
            'foreign',
            tenantReassignmentAction,
            'tenant-reassignment',
          );
          cases.push(reassignment);
          if (reassignment.status === 'error') {
            warnings.push(
              `Tenant-reassignment case errored for ${schema}.${resourceName} UPDATE; result is inconclusive.`,
            );
          }
          if (reassignment.status === 'failed' && reassignment.observed === 'allowed') {
            findings.push(dynamicFinding(reassignment, schema, resourceName));
          }
        }
      }
    }
    return { cases, findings, warnings };
  };

  const entries = Object.entries(config.resources).filter(([, resource]) => !resource.public);
  const requested = options.maxConcurrentResources ?? 1;
  const limit = Math.min(8, Math.max(1, Number.isFinite(requested) ? Math.floor(requested) : 1));
  const results: ResourceOutcome[] = new Array<ResourceOutcome>(entries.length);
  let cursor = 0;
  await Promise.all(
    Array.from({ length: Math.min(limit, entries.length) }, async () => {
      while (cursor < entries.length) {
        const index = cursor++;
        results[index] = await runResource(entries[index]![0], entries[index]![1]);
      }
    }),
  );

  const cases = results.flatMap((entry) => entry.cases);
  const findings = results.flatMap((entry) => entry.findings);
  const warnings = results.flatMap((entry) => entry.warnings);
  const complete =
    cases.length > 0 &&
    !cases.some(
      (testCase) =>
        testCase.status === 'error' ||
        testCase.status === 'skipped' ||
        (testCase.control === 'same' && testCase.status === 'failed'),
    );
  return {
    cases,
    findings: findings.sort((a, b) => a.fingerprint.localeCompare(b.fingerprint)),
    warnings: [...new Set(warnings)],
    complete,
  };
}
