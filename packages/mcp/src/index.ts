#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { Pool, type PoolClient } from 'pg';
import { captureCatalogSnapshot } from '@tenantshield/catalog';
import { parseConfig } from '@tenantshield/config';
import { redactText, redactValue } from '@tenantshield/reporters';
import { runStaticRules } from '@tenantshield/rules';
import {
  assertNotProductionTarget,
  inspectDatabaseTarget,
  runDynamicTests,
  runFixtureSetup,
  synthesizeFixturesInTransaction,
} from '@tenantshield/runner';

type JsonRpcRequest = {
  jsonrpc: '2.0';
  id?: string | number;
  method: string;
  params?: Record<string, unknown>;
};
type ToolArguments = Record<string, unknown>;

const tools = [
  {
    name: 'inspect_rls_matrix',
    description: 'Inspect local PostgreSQL grants, policies, and static findings.',
    inputSchema: {
      type: 'object',
      properties: { connectionEnv: { type: 'string' }, config: { type: 'object' } },
      required: ['config'],
    },
  },
  {
    name: 'verify_migration_safety',
    description: 'Check a SQL migration for common RLS and privilege hazards.',
    inputSchema: {
      type: 'object',
      properties: { sql: { type: 'string' }, path: { type: 'string' } },
    },
  },
  {
    name: 'simulate_tenant_access',
    description: 'Run dynamic tenant access controls against a local PostgreSQL target.',
    inputSchema: {
      type: 'object',
      properties: {
        connectionEnv: { type: 'string' },
        config: { type: 'object' },
        setupSql: { type: 'string' },
        autoSeed: { type: 'boolean' },
      },
      required: ['config'],
    },
  },
];

function result(value: unknown) {
  return { content: [{ type: 'text', text: JSON.stringify(redactValue(value), null, 2) }] };
}

function localPool(connectionEnv: unknown, productionMarkers: readonly string[] = []): Pool {
  const envName = typeof connectionEnv === 'string' ? connectionEnv : 'TENANTSHIELD_DATABASE_URL';
  const connectionString = process.env[envName];
  if (!connectionString) throw new Error(`Missing environment variable ${envName}`);
  const target = inspectDatabaseTarget(connectionString);
  assertNotProductionTarget(target, productionMarkers);
  return new Pool({ connectionString, max: 1, connectionTimeoutMillis: 5_000 });
}

async function callTool(name: string, args: ToolArguments): Promise<unknown> {
  if (name === 'verify_migration_safety') {
    let sql = typeof args['sql'] === 'string' ? args['sql'] : '';
    if (!sql && typeof args['path'] === 'string') sql = await readFile(args['path'], 'utf8');
    if (!sql) throw new Error('Provide sql or path');
    const checks = [
      [
        'table_without_rls',
        /create\s+table\b/i.test(sql) && !/enable\s+row\s+level\s+security/i.test(sql),
      ],
      [
        'unconditional_policy',
        /create\s+policy[\s\S]*?using\s*\(\s*true\s*\)/i.test(sql) ||
          /create\s+policy[\s\S]*?with\s+check\s*\(\s*true\s*\)/i.test(sql),
      ],
      ['user_metadata', /user_metadata|raw_user_meta_data/i.test(sql)],
      [
        'view_without_security_invoker',
        /create\s+(?:or\s+replace\s+)?view\b/i.test(sql) &&
          !/security_invoker\s*=\s*true/i.test(sql),
      ],
      ['truncate_grant', /grant\s+truncate\b/i.test(sql)],
      [
        'unsafe_security_definer',
        /security\s+definer/i.test(sql) &&
          (!/set\s+search_path/i.test(sql) || !/revoke\s+execute[\s\S]*?from\s+public/i.test(sql)),
      ],
    ]
      .filter(([, failed]) => failed)
      .map(([rule]) => rule);
    return result({ safe: checks.length === 0, findings: checks });
  }
  if (name !== 'inspect_rls_matrix' && name !== 'simulate_tenant_access') {
    throw new Error(`Unknown tool ${name}`);
  }
  const config = parseConfig(args['config']);
  const autoSeed =
    name === 'simulate_tenant_access' &&
    (args['autoSeed'] === true || config.fixtures?.mode === 'auto');
  const pool = localPool(
    args['connectionEnv'] ?? config.database.connectionEnv,
    config.database.productionMarkers ?? [],
  );
  let poolClient: PoolClient | undefined;
  try {
    const client = (poolClient = await pool.connect());
    const db = {
      query: async (sql: string, values?: readonly unknown[]) => {
        const response = await client.query(sql, values ? [...values] : undefined);
        return { rows: response.rows as Record<string, unknown>[], rowCount: response.rowCount };
      },
    };
    const schemas = [
      ...new Set([
        ...(config.database.exposedSchemas ?? ['public']),
        ...Object.values(config.resources).flatMap((resource) => [
          resource.schema ?? 'public',
          ...(autoSeed && resource.membership?.schema ? [resource.membership.schema] : []),
        ]),
      ]),
    ];
    const snapshot = await captureCatalogSnapshot(db, schemas, {
      includeForeignKeyDependencies: autoSeed,
    });
    if (name === 'inspect_rls_matrix') {
      const findings = runStaticRules(snapshot, config);
      const matrix = snapshot.tables.map((table) => ({
        resource: `${table.schema}.${table.name}`,
        roles: table.grants.map((grant) => ({ role: grant.role, privileges: grant.privileges })),
        policies: table.policies.map((policy) => ({
          name: policy.name,
          command: policy.command,
          roles: policy.effectiveRoles ?? policy.roles,
        })),
      }));
      return result({ matrix, findings });
    }
    if (autoSeed) return result(await synthesizeFixturesInTransaction(db, config, snapshot));
    const setupSql = args['setupSql'];
    if (typeof setupSql !== 'string')
      throw new Error('setupSql is required unless autoSeed is true');
    await runFixtureSetup(db, setupSql);
    return result(await runDynamicTests(db, config, snapshot));
  } finally {
    poolClient?.release();
    await pool.end();
  }
}

function respond(message: unknown): void {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

async function handle(request: JsonRpcRequest): Promise<void> {
  const id = request.id;
  if (id === undefined) return;
  if (request.method === 'initialize') {
    respond({
      jsonrpc: '2.0',
      id,
      result: {
        protocolVersion: '2024-11-05',
        capabilities: { tools: {} },
        serverInfo: { name: 'tenantshield-mcp', version: '0.2.1' },
      },
    });
  } else if (request.method === 'ping') {
    respond({ jsonrpc: '2.0', id, result: {} });
  } else if (request.method === 'tools/list') {
    respond({ jsonrpc: '2.0', id, result: { tools } });
  } else if (request.method === 'tools/call') {
    const params = request.params ?? {};
    const name = typeof params['name'] === 'string' ? params['name'] : '';
    try {
      const output = await callTool(name, (params['arguments'] ?? {}) as ToolArguments);
      respond({ jsonrpc: '2.0', id, result: output });
    } catch (error) {
      respond({
        jsonrpc: '2.0',
        id,
        error: {
          code: -32000,
          message: redactText(error instanceof Error ? error.message : 'Tool failed'),
        },
      });
    }
  } else if (id !== undefined) {
    respond({ jsonrpc: '2.0', id, error: { code: -32601, message: 'Method not found' } });
  }
}

let buffer = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (chunk: string) => {
  buffer += chunk;
  for (;;) {
    const newline = buffer.indexOf('\n');
    if (newline < 0) break;
    const line = buffer.slice(0, newline).trim();
    buffer = buffer.slice(newline + 1);
    if (!line) continue;
    void (async () => {
      try {
        await handle(JSON.parse(line) as JsonRpcRequest);
      } catch {
        respond({
          jsonrpc: '2.0',
          id: null,
          error: { code: -32700, message: 'Invalid JSON-RPC message' },
        });
      }
    })();
  }
});
