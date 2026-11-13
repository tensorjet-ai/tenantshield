import { describe, expect, it } from 'vitest';
import {
  DatabaseSafetyError,
  MUTATION_TRIGGER_WARNING,
  assertDynamicRoleSafe,
  inspectDatabaseTarget,
  assertNotProductionTarget,
} from './index.js';

describe('database safety boundary', () => {
  it('returns a credential-free local target', () => {
    const target = inspectDatabaseTarget('postgresql://alice:secret@localhost:54322/postgres');
    expect(target).toEqual({
      host: 'localhost',
      port: 54322,
      database: 'postgres',
      isRemote: false,
    });
    expect(JSON.stringify(target)).not.toContain('secret');
  });

  it.each(['127.0.0.1', '::1'])('recognizes %s as local', (host) => {
    const encodedHost = host === '::1' ? '[::1]' : host;
    expect(inspectDatabaseTarget(`postgresql://${encodedHost}/postgres`).isRemote).toBe(false);
  });

  it('rejects remote targets by default without exposing credentials', () => {
    expect(() => inspectDatabaseTarget('postgres://alice:verysecret@db.example.com/prod')).toThrow(
      DatabaseSafetyError,
    );
    try {
      inspectDatabaseTarget('postgres://alice:verysecret@db.example.com/prod');
    } catch (error) {
      expect(String(error)).not.toContain('verysecret');
    }
  });

  it('normalizes malformed encoded database names into a safety error', () => {
    expect(() => inspectDatabaseTarget('postgres://localhost/%')).toThrow(DatabaseSafetyError);
  });

  it('requires flag, environment opt-in, and allowlist for remote targets', () => {
    const url = 'postgres://db.example.com/postgres';
    expect(() =>
      inspectDatabaseTarget(url, {
        allowRemoteFlag: true,
        allowRemoteEnv: false,
        allowedHosts: ['db.example.com'],
      }),
    ).toThrow();
    expect(() =>
      inspectDatabaseTarget(url, {
        allowRemoteFlag: false,
        allowRemoteEnv: true,
        allowedHosts: ['db.example.com'],
      }),
    ).toThrow();
    expect(() =>
      inspectDatabaseTarget(url, {
        allowRemoteFlag: true,
        allowRemoteEnv: true,
        allowedHosts: ['other.example.com'],
      }),
    ).toThrow();
    expect(
      inspectDatabaseTarget(url, {
        allowRemoteFlag: true,
        allowRemoteEnv: true,
        allowedHosts: ['db.example.com'],
      }).isRemote,
    ).toBe(true);
  });

  it.each([
    [{ isSuperuser: true, canBypassRls: false }, 'superuser'],
    [{ isSuperuser: false, canBypassRls: true }, 'BYPASSRLS'],
  ])('rejects misleading dynamic role context', (attributes, expected) => {
    expect(() => assertDynamicRoleSafe(attributes)).toThrow(expected);
  });

  it('allows ordinary roles and defines a trigger side-effect warning', () => {
    expect(() => assertDynamicRoleSafe({ isSuperuser: false, canBypassRls: false })).not.toThrow();
    expect(MUTATION_TRIGGER_WARNING).toMatch(/trigger/i);
    expect(MUTATION_TRIGGER_WARNING).toMatch(/sequence/i);
    expect(MUTATION_TRIGGER_WARNING).toMatch(/external/i);
  });

  it('rejects user-configured production-like target markers', () => {
    const target = {
      host: 'localhost',
      port: 5432,
      database: 'tenantshield_prod',
      isRemote: false,
    };
    expect(() => assertNotProductionTarget(target, ['prod', 'live'])).toThrow(
      /production-like marker/i,
    );
    expect(() => assertNotProductionTarget(target, ['staging'])).not.toThrow();
  });

  it('checks Supabase project identity against production markers', () => {
    const target = { host: 'localhost', port: 5432, database: 'postgres', isRemote: false };
    expect(() =>
      assertNotProductionTarget(target, ['prod', 'live'], ['tenantshield-prod']),
    ).toThrow(/production-like marker/i);
  });

  it('does not match markers inside unsegmented field substrings', () => {
    const target = { host: 'localhost', port: 5432, database: 'reproduce', isRemote: false };
    expect(() => assertNotProductionTarget(target, ['prod'])).not.toThrow();
    expect(() => assertNotProductionTarget(target, ['oduce'])).not.toThrow();
  });

  it('matches markers against whole fields or separator-delimited segments', () => {
    expect(() =>
      assertNotProductionTarget(
        { host: 'db.prod.example.com', port: 5432, database: 'postgres', isRemote: true },
        ['prod'],
      ),
    ).toThrow(/production-like marker/i);
    expect(() =>
      assertNotProductionTarget(
        { host: 'localhost', port: 5432, database: 'prod', isRemote: false },
        ['prod'],
      ),
    ).toThrow(/production-like marker/i);
    expect(() =>
      assertNotProductionTarget(
        { host: 'localhost', port: 5432, database: 'postgres', isRemote: false },
        ['prod'],
        ['aws-0/us-east-1-prod'],
      ),
    ).toThrow(/production-like marker/i);
  });

  it('rejects invalid port zero before database work', () => {
    expect(() => inspectDatabaseTarget('postgresql://localhost:0/postgres')).toThrow(
      DatabaseSafetyError,
    );
  });

  it.each([
    'postgresql://localhost/postgres?host=remote.example.com',
    'postgresql://localhost:5432/postgres?port=6543',
  ])('rejects connection parameters that override the inspected target', (url) => {
    expect(() => inspectDatabaseTarget(url)).toThrow(/override/i);
  });
});
