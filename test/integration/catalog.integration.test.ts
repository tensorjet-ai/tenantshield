import { randomUUID } from 'node:crypto';
import { afterAll, describe, expect, it } from 'vitest';
import { Pool, type PoolClient } from 'pg';
import { captureCatalogSnapshot } from '../../packages/catalog/src/index.js';
import type { TenantShieldConfig } from '../../packages/config/src/index.js';
import {
  runDynamicTests,
  synthesizeFixturesInTransaction,
} from '../../packages/runner/src/index.js';

const connectionString = process.env['TENANTSHIELD_INTEGRATION_DATABASE_URL'];
const suite = connectionString ? describe : describe.skip;
const pool = connectionString ? new Pool({ connectionString, max: 1 }) : null;
const runnerTest =
  connectionString && process.env['TENANTSHIELD_RUNNER_INTEGRATION'] === '1' ? it : it.skip;

suite('PostgreSQL catalog integration', () => {
  afterAll(async () => pool?.end());

  it('captures a PostgreSQL 15+ server using read-only catalog queries', async () => {
    if (!pool) throw new Error('integration pool unavailable');
    const snapshot = await captureCatalogSnapshot(
      {
        query: async (sql, values) => {
          const result = await pool.query(sql, values ? [...values] : undefined);
          return { rows: result.rows as Record<string, unknown>[] };
        },
      },
      ['public'],
    );
    expect(Number(snapshot.database.serverVersion.split('.')[0])).toBeGreaterThanOrEqual(15);
  });

  it('normalizes primary-key and policy-role arrays from PostgreSQL', async () => {
    if (!pool) throw new Error('integration pool unavailable');
    const client = await pool.connect();
    let createdFileFdw = false;
    // Best-effort removal of leftovers from previously interrupted runs.
    const cleanupStatements = [
      'DROP SERVER IF EXISTS tenantshield_file_server CASCADE',
      'DROP VIEW IF EXISTS public.tenantshield_secure_view',
      'DROP MATERIALIZED VIEW IF EXISTS public.tenantshield_materialized_view',
      'DROP FUNCTION IF EXISTS public.tenantshield_catalog_definer()',
      'DROP FUNCTION IF EXISTS tenantshield_hidden.private_definer()',
      'DROP TABLE IF EXISTS public.tenantshield_column_fixture',
      'DROP SCHEMA IF EXISTS tenantshield_hidden CASCADE',
      'DROP OWNED BY tenantshield_catalog_reader CASCADE',
      'REVOKE tenantshield_catalog_reader FROM authenticated',
      'DROP ROLE IF EXISTS tenantshield_catalog_reader',
    ];
    for (const statement of cleanupStatements) {
      await client.query(statement).catch(() => undefined);
    }
    try {
      await client.query('BEGIN');
      const fileFdw = await client.query(`SELECT 1 FROM pg_extension WHERE extname = 'file_fdw'`);
      createdFileFdw = fileFdw.rowCount === 0;
      await client.query(`CREATE TABLE public.tenantshield_catalog_fixture (
        id uuid PRIMARY KEY,
        org_id uuid NOT NULL
      )`);
      await client.query('CREATE ROLE tenantshield_catalog_reader NOLOGIN');
      await client.query(`DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
          CREATE ROLE authenticated NOLOGIN;
        END IF;
      END $$`);
      await client.query('GRANT tenantshield_catalog_reader TO authenticated');
      await client.query(
        'ALTER TABLE public.tenantshield_catalog_fixture OWNER TO tenantshield_catalog_reader',
      );
      await client.query(
        'GRANT SELECT ON public.tenantshield_catalog_fixture TO tenantshield_catalog_reader',
      );
      await client.query(`CREATE TABLE public.tenantshield_column_fixture (
        id integer PRIMARY KEY,
        secret text NOT NULL
      )`);
      await client.query(
        'GRANT SELECT (id) ON public.tenantshield_column_fixture TO tenantshield_catalog_reader',
      );
      await client.query(
        'ALTER TABLE public.tenantshield_catalog_fixture ENABLE ROW LEVEL SECURITY',
      );
      await client.query(`CREATE POLICY "fixture policy"
        ON public.tenantshield_catalog_fixture FOR SELECT TO tenantshield_catalog_reader USING (true)`);
      await client.query(`CREATE VIEW public.tenantshield_secure_view
        WITH (security_invoker = true)
        AS SELECT id, org_id FROM public.tenantshield_catalog_fixture`);
      await client.query('GRANT SELECT ON public.tenantshield_secure_view TO authenticated');
      await client.query(`CREATE MATERIALIZED VIEW public.tenantshield_materialized_view
        AS SELECT id, org_id FROM public.tenantshield_catalog_fixture WITH NO DATA`);
      await client.query('GRANT SELECT ON public.tenantshield_materialized_view TO authenticated');
      await client.query(`CREATE FUNCTION public.tenantshield_catalog_definer()
        RETURNS integer LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$`);
      await client.query(
        'REVOKE ALL ON FUNCTION public.tenantshield_catalog_definer() FROM PUBLIC',
      );
      await client.query(
        'GRANT EXECUTE ON FUNCTION public.tenantshield_catalog_definer() TO tenantshield_catalog_reader',
      );
      await client.query('CREATE EXTENSION IF NOT EXISTS file_fdw');
      await client.query('CREATE SERVER tenantshield_file_server FOREIGN DATA WRAPPER file_fdw');
      await client.query(`CREATE FOREIGN TABLE public.tenantshield_foreign_fixture (
        id integer
      ) SERVER tenantshield_file_server OPTIONS (
        filename '/tmp/tenantshield-catalog-fixture.csv', format 'csv'
      )`);
      await client.query(
        'GRANT SELECT ON public.tenantshield_foreign_fixture TO tenantshield_catalog_reader',
      );
      await client.query(`CREATE SCHEMA tenantshield_hidden;
        CREATE TABLE tenantshield_hidden.private_fixture (id integer PRIMARY KEY);
        GRANT SELECT ON tenantshield_hidden.private_fixture TO tenantshield_catalog_reader;
        CREATE FUNCTION tenantshield_hidden.private_definer()
          RETURNS integer LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;
        REVOKE ALL ON FUNCTION tenantshield_hidden.private_definer() FROM PUBLIC;
        GRANT EXECUTE ON FUNCTION tenantshield_hidden.private_definer()
          TO tenantshield_catalog_reader`);
      // captureCatalogSnapshot opens its own REPEATABLE READ READ ONLY transaction,
      // so the fixture DDL must be committed before capturing.
      await client.query('COMMIT');
      const snapshot = await captureCatalogSnapshot(
        {
          query: async (sql, values) => {
            const result = await client.query(sql, values ? [...values] : undefined);
            return { rows: result.rows as Record<string, unknown>[] };
          },
        },
        ['public', 'tenantshield_hidden'],
      );
      const table = snapshot.tables.find((entry) => entry.name === 'tenantshield_catalog_fixture');
      expect(table?.primaryKey).toEqual(['id']);
      expect(table?.ownerRoles).toEqual(['authenticated']);
      expect(table?.policies).toContainEqual(
        expect.objectContaining({
          roles: ['tenantshield_catalog_reader'],
          effectiveRoles: ['authenticated'],
        }),
      );
      const authenticatedGrant = table?.grants.find((grant) => grant.role === 'authenticated');
      expect(authenticatedGrant?.privileges).toContain('select');
      expect(
        snapshot.tables.find((entry) => entry.name === 'tenantshield_column_fixture')?.grants,
      ).toContainEqual({ role: 'authenticated', privileges: ['select'] });
      expect(
        snapshot.tables.find((entry) => entry.name === 'tenantshield_foreign_fixture'),
      ).toMatchObject({
        isForeign: true,
        grants: [{ role: 'authenticated', privileges: ['select'] }],
      });
      expect(snapshot.views).toContainEqual(
        expect.objectContaining({ name: 'tenantshield_secure_view', securityInvoker: true }),
      );
      expect(snapshot.functions).toContainEqual(
        expect.objectContaining({
          name: 'tenantshield_catalog_definer',
          securityDefiner: true,
          executeRoles: ['authenticated'],
        }),
      );
      expect(
        snapshot.tables.find(
          (entry) => entry.schema === 'tenantshield_hidden' && entry.name === 'private_fixture',
        )?.grants,
      ).toEqual([]);
      expect(snapshot.functions).toContainEqual(
        expect.objectContaining({
          schema: 'tenantshield_hidden',
          name: 'private_definer',
          executeRoles: [],
        }),
      );
      expect(snapshot.views).toContainEqual(
        expect.objectContaining({
          name: 'tenantshield_materialized_view',
          securityInvoker: false,
        }),
      );
    } finally {
      // A failed statement can leave the transaction aborted; close it before cleanup.
      await client.query('ROLLBACK').catch(() => undefined);
      for (const statement of cleanupStatements) {
        await client.query(statement).catch(() => undefined);
      }
      if (createdFileFdw) {
        await client.query('DROP EXTENSION IF EXISTS file_fdw').catch(() => undefined);
      }
      client.release();
    }
  });

  runnerTest('proves secure and vulnerable CRUD boundaries with rollback', async () => {
    if (!pool || !connectionString) throw new Error('integration pool unavailable');
    const database = `tenantshield_${randomUUID().replaceAll('-', '')}`;
    let createdRole = false;
    let createdDatabase = false;
    let isolatedPool: Pool | undefined;
    let isolatedClient: PoolClient | undefined;
    try {
      const role = await pool.query(`SELECT 1 FROM pg_roles WHERE rolname = 'authenticated'`);
      if (role.rowCount === 0) {
        await pool.query('CREATE ROLE authenticated NOLOGIN');
        createdRole = true;
      }
      await pool.query(`CREATE DATABASE "${database}"`);
      createdDatabase = true;
      const url = new URL(connectionString);
      url.pathname = `/${database}`;
      isolatedPool = new Pool({ connectionString: url.toString(), max: 1 });
      await isolatedPool.query(`CREATE SCHEMA auth;
        CREATE FUNCTION auth.uid() RETURNS uuid LANGUAGE sql STABLE AS $$
          SELECT NULLIF(current_setting('request.jwt.claim.sub', true), '')::uuid
        $$;
        CREATE FUNCTION auth.jwt() RETURNS jsonb LANGUAGE sql STABLE AS $$
          SELECT COALESCE(NULLIF(current_setting('request.jwt.claims', true), '')::jsonb, '{}'::jsonb)
        $$;
        CREATE SCHEMA tenantshield_runner;
        GRANT USAGE ON SCHEMA auth, tenantshield_runner TO authenticated;
        GRANT EXECUTE ON FUNCTION auth.uid(), auth.jwt() TO authenticated;

        CREATE TABLE tenantshield_runner.secure_invoices (
          id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          org_id uuid NOT NULL
        );
        ALTER TABLE tenantshield_runner.secure_invoices ENABLE ROW LEVEL SECURITY;
        GRANT SELECT, INSERT, UPDATE, DELETE ON tenantshield_runner.secure_invoices TO authenticated;
        GRANT USAGE, SELECT ON SEQUENCE tenantshield_runner.secure_invoices_id_seq TO authenticated;
        CREATE POLICY secure_select ON tenantshield_runner.secure_invoices FOR SELECT TO authenticated
          USING (org_id = ((auth.jwt() ->> 'org_id')::uuid));
        CREATE POLICY secure_insert ON tenantshield_runner.secure_invoices FOR INSERT TO authenticated
          WITH CHECK (org_id = ((auth.jwt() ->> 'org_id')::uuid));
        CREATE POLICY secure_update ON tenantshield_runner.secure_invoices FOR UPDATE TO authenticated
          USING (org_id = ((auth.jwt() ->> 'org_id')::uuid))
          WITH CHECK (org_id = ((auth.jwt() ->> 'org_id')::uuid));
        CREATE POLICY secure_delete ON tenantshield_runner.secure_invoices FOR DELETE TO authenticated
          USING (org_id = ((auth.jwt() ->> 'org_id')::uuid));

        CREATE TABLE tenantshield_runner.vulnerable_invoices (
          id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          org_id uuid NOT NULL
        );
        ALTER TABLE tenantshield_runner.vulnerable_invoices ENABLE ROW LEVEL SECURITY;
        GRANT SELECT, INSERT, UPDATE, DELETE ON tenantshield_runner.vulnerable_invoices TO authenticated;
        GRANT USAGE, SELECT ON SEQUENCE tenantshield_runner.vulnerable_invoices_id_seq TO authenticated;
        CREATE POLICY vulnerable_all ON tenantshield_runner.vulnerable_invoices FOR ALL TO authenticated
          USING (true) WITH CHECK (true);

        INSERT INTO tenantshield_runner.secure_invoices (org_id) VALUES
          ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa');`);
      await isolatedPool.query(`INSERT INTO tenantshield_runner.secure_invoices (org_id) VALUES
          ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb');
        INSERT INTO tenantshield_runner.vulnerable_invoices (org_id) VALUES
          ('aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa'),
          ('bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb');`);
      isolatedClient = await isolatedPool.connect();

      const config: TenantShieldConfig = {
        version: 1,
        database: { connectionEnv: 'DATABASE_URL', allowedHosts: ['localhost'] },
        fixtures: { setupSql: 'fixtures.sql' },
        identities: {
          alice: {
            role: 'authenticated',
            userId: '11111111-1111-1111-1111-111111111111',
            claims: { org_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa' },
          },
          bob: {
            role: 'authenticated',
            userId: '22222222-2222-2222-2222-222222222222',
            claims: { org_id: 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb' },
          },
        },
        resources: {
          secure_invoices: {
            schema: 'tenantshield_runner',
            primaryKey: 'id',
            tenantColumn: 'org_id',
            ownerIdentity: 'alice',
            foreignIdentity: 'bob',
            testOperations: ['select', 'insert', 'update', 'delete'],
          },
          vulnerable_invoices: {
            schema: 'tenantshield_runner',
            primaryKey: 'id',
            tenantColumn: 'org_id',
            ownerIdentity: 'alice',
            foreignIdentity: 'bob',
            testOperations: ['select', 'insert', 'update', 'delete'],
          },
        },
      };
      const authorizationErrors: { marker: string; code: unknown }[] = [];
      const client = {
        query: async (sql: string, values?: readonly unknown[]) => {
          try {
            const result = await isolatedClient!.query(sql, values ? [...values] : undefined);
            return {
              rows: result.rows as Record<string, unknown>[],
              rowCount: result.rowCount,
            };
          } catch (error) {
            if (sql.includes('tenantshield_')) {
              authorizationErrors.push({
                marker: /tenantshield_[a-z_]+/.exec(sql)?.[0] ?? 'unknown',
                code: error && typeof error === 'object' && 'code' in error ? error.code : null,
              });
            }
            throw error;
          }
        },
      };
      const snapshot = await captureCatalogSnapshot(client, ['tenantshield_runner']);
      const first = await runDynamicTests(client, config, snapshot);
      const second = await runDynamicTests(client, config, snapshot);
      expect(
        first.complete,
        JSON.stringify(
          { cases: first.cases, warnings: first.warnings, authorizationErrors },
          null,
          2,
        ),
      ).toBe(true);
      expect(first.cases).toHaveLength(40);
      expect(
        first.cases
          .filter((testCase) => testCase.resource.endsWith('.secure_invoices'))
          .every((testCase) => testCase.status === 'passed'),
      ).toBe(true);
      expect(first.findings.map((finding) => finding.ruleId).sort()).toEqual([
        'TS-DYN-DELETE',
        'TS-DYN-DELETE',
        'TS-DYN-INSERT',
        'TS-DYN-INSERT',
        'TS-DYN-SELECT',
        'TS-DYN-SELECT',
        'TS-DYN-UPDATE',
        'TS-DYN-UPDATE',
        'TS-DYN-UPDATE',
        'TS-DYN-UPDATE',
        'TS-DYN-UPDATE',
        'TS-DYN-UPDATE',
      ]);
      expect(new Set(first.findings.map((finding) => finding.fingerprint)).size).toBe(
        first.findings.length,
      );
      expect(second.findings.map((finding) => finding.fingerprint)).toEqual(
        first.findings.map((finding) => finding.fingerprint),
      );
      const counts = await isolatedClient.query(`SELECT
        (SELECT count(*)::int FROM tenantshield_runner.secure_invoices) AS secure_count,
        (SELECT count(*)::int FROM tenantshield_runner.vulnerable_invoices) AS vulnerable_count`);
      expect(counts.rows[0]).toEqual({ secure_count: 2, vulnerable_count: 2 });

      await isolatedClient.query(`
        CREATE TABLE auth.users (id uuid PRIMARY KEY);
        CREATE SCHEMA tenantshield_private;
        CREATE TABLE tenantshield_private.orgs (id uuid PRIMARY KEY, quota smallint NOT NULL);
        CREATE TABLE tenantshield_runner.auto_items (
          org_id uuid REFERENCES tenantshield_private.orgs (id),
          id bigint GENERATED ALWAYS AS IDENTITY,
          alternate_org_id uuid NOT NULL REFERENCES tenantshield_private.orgs (id),
          user_id uuid NOT NULL REFERENCES auth.users (id),
          PRIMARY KEY (org_id, id)
        );
        ALTER TABLE tenantshield_runner.auto_items ENABLE ROW LEVEL SECURITY;
        GRANT SELECT ON tenantshield_runner.auto_items TO authenticated;
        CREATE POLICY scoped ON tenantshield_runner.auto_items TO authenticated
          USING (user_id = (SELECT auth.uid()));
      `);
      const autoConfig: TenantShieldConfig = {
        ...config,
        fixtures: { mode: 'auto' },
        identities: Object.fromEntries(
          Object.entries(config.identities).map(([name, identity]) => {
            const org = identity.claims['org_id'];
            if (typeof org !== 'string') throw new Error('Fixture organization claim is missing');
            return [name, { ...identity, claims: {}, tenants: { org_id: org } }];
          }),
        ),
        resources: {
          auto_items: {
            ...config.resources['secure_invoices']!,
            primaryKey: ['org_id', 'id'],
            testOperations: ['select'],
          },
        },
      };
      const autoSnapshot = await captureCatalogSnapshot(client, ['tenantshield_runner'], {
        includeForeignKeyDependencies: true,
      });
      expect(autoSnapshot.fixtureTables).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ schema: 'auth', name: 'users' }),
          expect.objectContaining({ schema: 'tenantshield_private', name: 'orgs' }),
        ]),
      );
      expect(
        autoSnapshot.tables.find((table) => table.name === 'auto_items')?.foreignKeys,
      ).toHaveLength(3);
      const automatic = await synthesizeFixturesInTransaction(client, autoConfig, autoSnapshot);
      expect(automatic, JSON.stringify(automatic)).toMatchObject({ complete: true, findings: [] });
      expect(automatic.cases).toHaveLength(4);
      await isolatedClient.query('ALTER TABLE tenantshield_runner.auto_items ADD CHECK (false)');
      const rejected = await synthesizeFixturesInTransaction(client, autoConfig, autoSnapshot);
      expect(rejected.complete).toBe(false);
      expect(rejected.warnings.join(' ')).toContain('SQLSTATE 23514');
      expect(
        (
          await isolatedClient.query(`SELECT
            (SELECT count(*)::int FROM auth.users) AS users,
            (SELECT count(*)::int FROM tenantshield_private.orgs) AS orgs,
            (SELECT count(*)::int FROM tenantshield_runner.auto_items) AS items`)
        ).rows[0],
      ).toEqual({ users: 0, orgs: 0, items: 0 });

      await isolatedClient.query(`DROP TABLE tenantshield_runner.auto_items;
        GRANT USAGE ON SCHEMA tenantshield_private TO authenticated;
        CREATE TABLE tenantshield_private.organization_members (
          org_id uuid NOT NULL REFERENCES tenantshield_private.orgs (id),
          user_id uuid NOT NULL REFERENCES auth.users (id),
          member_role text NOT NULL,
          PRIMARY KEY (org_id, user_id)
        );
        GRANT SELECT ON tenantshield_private.organization_members TO authenticated;
        CREATE TABLE tenantshield_runner.organization_events (
          org_id uuid NOT NULL REFERENCES tenantshield_private.orgs (id),
          user_id uuid NOT NULL REFERENCES auth.users (id),
          event_name text NOT NULL
        );
        CREATE FUNCTION tenantshield_runner.reject_unrelated_event_seed()
          RETURNS trigger LANGUAGE plpgsql AS $$
          BEGIN RAISE EXCEPTION 'unrelated event table must not be auto-seeded'; END
        $$;
        CREATE TRIGGER reject_unrelated_event_seed
          BEFORE INSERT ON tenantshield_runner.organization_events
          FOR EACH ROW EXECUTE FUNCTION tenantshield_runner.reject_unrelated_event_seed();
        CREATE TABLE tenantshield_runner.member_items (
          id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
          org_id uuid NOT NULL REFERENCES tenantshield_private.orgs (id),
          owner_id uuid NOT NULL REFERENCES auth.users (id),
          label text NOT NULL UNIQUE,
          "note from tenantshield_runner.organization_events marker" text NOT NULL DEFAULT ''
        );
        ALTER TABLE tenantshield_runner.member_items ENABLE ROW LEVEL SECURITY;
        GRANT SELECT, INSERT, UPDATE, DELETE ON tenantshield_runner.member_items TO authenticated;
        CREATE POLICY member_items_access ON tenantshield_runner.member_items FOR ALL TO authenticated
          USING (EXISTS (
            SELECT 1 FROM tenantshield_private.organization_members member
            WHERE member.org_id = tenantshield_runner.member_items.org_id
              AND member.user_id = auth.uid()
          ) AND 'from tenantshield_runner.organization_events' <> ''
            AND "note from tenantshield_runner.organization_events marker" = '')
          WITH CHECK (EXISTS (
            SELECT 1 FROM tenantshield_private.organization_members member
            WHERE member.org_id = tenantshield_runner.member_items.org_id
              AND member.user_id = auth.uid()
          ) AND 'from tenantshield_runner.organization_events' <> ''
            AND "note from tenantshield_runner.organization_events marker" = '');`);
      await isolatedClient.query(
        'GRANT USAGE, SELECT ON SEQUENCE tenantshield_runner.member_items_id_seq TO authenticated',
      );
      const memberConfig: TenantShieldConfig = {
        ...autoConfig,
        identities: {
          ...autoConfig.identities,
          member: {
            role: 'authenticated',
            userId: '33333333-3333-3333-3333-333333333333',
            claims: {},
          },
        },
        resources: {
          member_items: {
            ...autoConfig.resources['auto_items']!,
            primaryKey: 'id',
            dualMemberIdentity: 'member',
            testOperations: ['select', 'insert', 'update', 'delete'],
          },
        },
      };
      const memberSnapshot = await captureCatalogSnapshot(client, ['auth', 'tenantshield_runner'], {
        includeForeignKeyDependencies: true,
      });
      expect(memberSnapshot.fixtureTables).toEqual(
        expect.arrayContaining([
          expect.objectContaining({ schema: 'tenantshield_private', name: 'organization_members' }),
        ]),
      );
      expect(memberSnapshot.tables).toContainEqual(
        expect.objectContaining({ schema: 'auth', name: 'users' }),
      );
      const memberResult = await synthesizeFixturesInTransaction(
        client,
        memberConfig,
        memberSnapshot,
      );
      expect(memberResult, JSON.stringify(memberResult)).toMatchObject({
        complete: true,
        findings: [],
      });
      expect(memberResult.warnings.some((warning) => warning.includes('sequence values'))).toBe(
        true,
      );
      expect(
        (
          await isolatedClient.query(`SELECT
            (SELECT count(*)::int FROM tenantshield_private.organization_members) AS memberships,
            (SELECT count(*)::int FROM tenantshield_runner.member_items) AS items,
            (SELECT count(*)::int FROM auth.users) AS users,
            (SELECT count(*)::int FROM tenantshield_private.orgs) AS orgs`)
        ).rows[0],
      ).toEqual({ memberships: 0, items: 0, users: 0, orgs: 0 });
    } finally {
      isolatedClient?.release();
      await isolatedPool?.end();
      if (createdDatabase) await pool.query(`DROP DATABASE "${database}" WITH (FORCE)`);
      if (createdRole) await pool.query('DROP ROLE authenticated');
    }
  });
});
