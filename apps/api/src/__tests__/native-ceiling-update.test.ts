import { afterAll, beforeAll, describe, expect, test } from 'bun:test';
import { PGlite } from '@electric-sql/pglite';
import { PrismaPGlite } from 'pglite-prisma-adapter';
import { PrismaClient, type OauthClient } from '@openkey/db';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { readdir, readFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  NativeCeilingRefusedError,
  diffNativeCeilings,
  sortedJson,
  updateNativeCeiling,
} from '../services/native-delegation/ceiling-update';
import { nativeDelegationJson, validateNativeDelegationConfig } from '../services/native-delegation/policy';

// TC-1990: an existing client's native delegation ceiling can be replaced from
// scripts/ci-register-oauth-client.ts. Runs on the tracked migration chain in
// PGlite; an AFTER UPDATE trigger counts every UPDATE the database sees.

// Every path this file writes lives under one temp dir, and HOME points at it.
const realHome = homedir();
const workDir = mkdtempSync('/var/tmp/tc1990.');
const originalHome = process.env.HOME;
process.env.HOME = workDir;
if (process.env.HOME !== workDir || process.env.HOME === realHome || !workDir.startsWith('/var/tmp/tc1990.')) {
  throw new Error('TC-1990 test sandbox is not active');
}

const databases: Array<{ close: () => Promise<void> }> = [];

// Registered first so it runs after every test and cleans up whatever they made.
afterAll(async () => {
  for (const database of databases.splice(0)) await database.close().catch(() => undefined);
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  rmSync(workDir, { recursive: true, force: true });
});

const root = resolve(import.meta.dir, '../../../..');
const APP = 'xyz.tinycloud.tinychat';
const HOST = 'https://tee.node.tinycloud.xyz';
const NATIVE_REDIRECT = 'xyz.tinycloud.exo://openkey/callback';
const DELEGATION_SCOPE = 'tinycloud:delegation';
const BASE_SCOPES = ['openid', 'email', 'keys', 'offline_access', DELEGATION_SCOPE];

// The example ceiling in docs/native-tinycloud-delegation.md.
const DOC_CEILING = {
  version: 1,
  appId: APP,
  tinycloudHost: HOST,
  kv: {
    paths: [`${APP}/threads/`, `${APP}/connectors/`],
    actions: ['get', 'put', 'list', 'del', 'metadata'],
  },
  sql: {
    databases: [`${APP}/threads`, `${APP}/canvas`, `${APP}/connectors`],
    actions: ['read', 'write', 'schema'],
  },
  maxDelegationTtlSeconds: 3600,
  grantLifetimeSeconds: 2592000,
  siweDomain: 'openkey.so',
};
const EXO_KV = ['migrations/', 'exo/v1/requests/', 'exo/v1/jobs/'].map((path) => `${APP}/${path}`);
const EXO_SQL = ['details', 'summaries', 'transcripts'].map((name) => `${APP}/${name}`);
const EXO_CEILING = {
  ...DOC_CEILING,
  kv: { ...DOC_CEILING.kv, paths: [...DOC_CEILING.kv.paths, ...EXO_KV] },
  sql: { ...DOC_CEILING.sql, databases: [...DOC_CEILING.sql.databases, ...EXO_SQL] },
};

/**
 * The supplied form of a ceiling for an existing client: appId and siweDomain
 * are kept from the stored ceiling, so they are not part of the supplied value.
 */
function suppliedCeiling(ceiling: unknown): unknown {
  if (!ceiling || typeof ceiling !== 'object' || Array.isArray(ceiling)) return ceiling;
  const { appId: _appId, siweDomain: _siweDomain, ...rest } = ceiling as Record<string, unknown>;
  return rest;
}

// Records the client id of every UPDATE the database sees on oauth_client.
const UPDATE_AUDIT_SQL = `
  CREATE TABLE tc1990_update_audit (client_id text NOT NULL);
  CREATE FUNCTION tc1990_record_update() RETURNS trigger AS $$
  BEGIN INSERT INTO tc1990_update_audit (client_id) VALUES (OLD."clientId"); RETURN NEW; END
  $$ LANGUAGE plpgsql;
  CREATE TRIGGER tc1990_record_update AFTER UPDATE ON "oauth_client"
    FOR EACH ROW EXECUTE FUNCTION tc1990_record_update();
`;

async function migratedDatabase(database: PGlite) {
  const directory = join(root, 'packages/db/prisma/migrations');
  const migrations = (await readdir(directory, { withFileTypes: true }))
    .filter((entry) => entry.isDirectory()).map((entry) => entry.name).sort();
  for (const migration of migrations) {
    await database.exec(await readFile(join(directory, migration, 'migration.sql'), 'utf8'));
  }
}

type SeedOptions = {
  type?: string | null;
  disabled?: boolean;
  ceiling?: unknown;
  extra?: Record<string, unknown>;
};

let sequence = 0;
function seedClient(prisma: PrismaClient, options: SeedOptions = {}) {
  sequence += 1;
  const clientId = `ok_tc1990_${String(sequence).padStart(4, '0')}`;
  const ceiling = 'ceiling' in options ? options.ceiling : DOC_CEILING;
  return prisma.oauthClient.create({
    data: {
      id: `tc1990-${sequence}`,
      clientId,
      name: `TC-1990 client ${sequence}`,
      redirectUris: [NATIVE_REDIRECT],
      scopes: ceiling == null ? BASE_SCOPES.slice(0, 4) : BASE_SCOPES,
      tinycloudNativeDelegation: ceiling == null ? undefined : ceiling as never,
      disabled: options.disabled ?? false,
      tokenEndpointAuthMethod: 'none',
      type: options.type === undefined ? 'native' : options.type,
      public: true,
      contacts: [],
      ...options.extra,
    },
  });
}

describe('native ceiling update (PGlite, tracked migrations)', () => {
  let database: PGlite;
  let prisma: PrismaClient;

  async function updateCount() {
    const { rows } = await database.query<{ count: number }>('SELECT count(*)::int AS count FROM tc1990_update_audit');
    return rows[0]!.count;
  }

  /** Seeds, then forgets the seeding writes so the audit counts only what the run does. */
  async function seed(options: SeedOptions = {}) {
    const client = await seedClient(prisma, options);
    await database.exec('DELETE FROM tc1990_update_audit');
    return client;
  }

  /** Runs the update; appId and siweDomain are left out of the supplied value unless `identity` is set. */
  async function run(clientId: string, ceiling: unknown, options: { dryRun?: boolean; allowNarrow?: boolean; identity?: boolean } = {}) {
    const lines: string[] = [];
    const supplied = options.identity ? ceiling : suppliedCeiling(ceiling);
    const result = await updateNativeCeiling(prisma, {
      clientId,
      rawCeiling: typeof supplied === 'string' ? supplied : JSON.stringify(supplied),
      dryRun: options.dryRun ?? false,
      allowNarrow: options.allowNarrow ?? false,
      log: (line) => lines.push(line),
    });
    return { result, output: lines.join('\n') };
  }

  async function row(clientId: string) {
    return prisma.oauthClient.findUniqueOrThrow({ where: { clientId } });
  }

  async function expectUntouched(clientId: string, snapshot: OauthClient) {
    expect(await row(clientId)).toEqual(snapshot);
    expect(await updateCount()).toBe(0);
  }

  beforeAll(async () => {
    expect(process.env.HOME).toBe(workDir);
    expect(process.env.HOME).not.toBe(realHome);
    database = new PGlite();
    databases.push(database);
    await migratedDatabase(database);
    await database.exec(UPDATE_AUDIT_SQL);
    prisma = new PrismaClient({ adapter: new PrismaPGlite(database) });
    databases.push({ close: () => prisma.$disconnect() });
  }, 120_000);

  describe('adding entries', () => {
    test('adds the six Exo entries to the documented ceiling and stores exactly the validated value', async () => {
      const client = await seed();
      const { result, output } = await run(client.clientId, EXO_CEILING);

      expect(result.outcome).toBe('written');
      expect(result.diff.removed).toEqual([]);
      expect(result.diff.added).toEqual([
        ...EXO_KV.map((path) => `kv.paths: ${path}`),
        ...EXO_SQL.map((name) => `sql.databases: ${name}`),
      ].sort());
      const stored = await row(client.clientId);
      expect(stored.tinycloudNativeDelegation).toEqual(
        nativeDelegationJson(validateNativeDelegationConfig(EXO_CEILING, stored)) as never,
      );
      expect(stored.scopes).toContain(DELEGATION_SCOPE);
      expect(stored.redirectUris).toEqual([NATIVE_REDIRECT]);
      expect(await updateCount()).toBe(1);
      expect(output).toContain(`BEFORE: ${sortedJson(DOC_CEILING)}`);
      expect(output).toContain(`AFTER: ${sortedJson(EXO_CEILING)}`);
    });

    test('a larger limit is a change, not a removal', async () => {
      const client = await seed();
      const { result } = await run(client.clientId, { ...DOC_CEILING, maxDelegationTtlSeconds: 7200 });
      expect(result.outcome).toBe('written');
      expect(result.diff).toEqual({ added: [], removed: [], changed: ['maxDelegationTtlSeconds: 3600 -> 7200'], fixed: [] });
    });

    test('a client without a ceiling receives one and the delegation scope', async () => {
      const client = await seed({ ceiling: null });
      expect(client.scopes).not.toContain(DELEGATION_SCOPE);
      const { result, output } = await run(client.clientId, EXO_CEILING, { identity: true });
      expect(result.outcome).toBe('written');
      expect(output).toContain('BEFORE: none');
      expect((await row(client.clientId)).scopes).toContain(DELEGATION_SCOPE);
    });

    test('the same ceiling, or the same entries in another order, writes nothing', async () => {
      const client = await seed();
      const reordered = { ...DOC_CEILING, kv: { ...DOC_CEILING.kv, paths: [...DOC_CEILING.kv.paths].reverse() } };
      const snapshot = await row(client.clientId);
      for (const ceiling of [DOC_CEILING, reordered]) {
        const { result, output } = await run(client.clientId, ceiling);
        expect(result.outcome).toBe('unchanged');
        expect(output).toContain('No change');
      }
      await expectUntouched(client.clientId, snapshot);
    });

    test('a stored value that fails validation is replaced, and its raw content is not printed', async () => {
      const client = await seed({ ceiling: { version: 9, marker: 'tc1990-raw-marker' } });
      const { result, output } = await run(client.clientId, EXO_CEILING, { identity: true });
      expect(result.outcome).toBe('written');
      expect(output).toContain('BEFORE: not valid under the current policy');
      expect(output).not.toContain('tc1990-raw-marker');
    });
  });

  describe('narrowing', () => {
    const cases: Array<[string, unknown, string[]]> = [
      ['a kv path', { ...DOC_CEILING, kv: { ...DOC_CEILING.kv, paths: [`${APP}/threads/`] } }, [`kv.paths: ${APP}/connectors/`]],
      ['a kv action', { ...DOC_CEILING, kv: { ...DOC_CEILING.kv, actions: ['get', 'put', 'list', 'del'] } }, ['kv.actions: metadata']],
      ['a sql database', { ...DOC_CEILING, sql: { ...DOC_CEILING.sql, databases: [`${APP}/threads`, `${APP}/connectors`] } }, [`sql.databases: ${APP}/canvas`]],
      ['a sql action', { ...DOC_CEILING, sql: { ...DOC_CEILING.sql, actions: ['read', 'write'] } }, ['sql.actions: schema']],
      ['the whole sql section', { ...DOC_CEILING, sql: null }, [
        `sql.databases: ${APP}/threads`, `sql.databases: ${APP}/canvas`, `sql.databases: ${APP}/connectors`,
        'sql.actions: read', 'sql.actions: write', 'sql.actions: schema',
      ]],
      ['maxDelegationTtlSeconds', { ...DOC_CEILING, maxDelegationTtlSeconds: 1800 }, ['maxDelegationTtlSeconds: 3600 -> 1800']],
      ['grantLifetimeSeconds', { ...DOC_CEILING, grantLifetimeSeconds: 86400 }, ['grantLifetimeSeconds: 2592000 -> 86400']],
    ];

    test.each(cases)('removing %s is refused with the removed entries named, and nothing is written', async (_label, ceiling, removed) => {
      const client = await seed();
      const snapshot = await row(client.clientId);
      const failure = await run(client.clientId, ceiling).catch((error: unknown) => error);
      expect(failure).toBeInstanceOf(NativeCeilingRefusedError);
      for (const line of removed) expect((failure as Error).message).toContain(`  - ${line}`);
      expect((failure as Error).message).toContain('--allow-narrow');
      await expectUntouched(client.clientId, snapshot);
    });

    test.each(cases)('removing %s is applied with allowNarrow', async (_label, ceiling, removed) => {
      const client = await seed();
      const { result } = await run(client.clientId, ceiling, { allowNarrow: true });
      expect(result.outcome).toBe('written');
      for (const line of removed) expect(result.diff.removed).toContain(line);
      const stored = await row(client.clientId);
      expect(sortedJson(stored.tinycloudNativeDelegation)).toBe(sortedJson(validateNativeDelegationConfig(ceiling, stored)));
      expect(await updateCount()).toBe(1);
    });

    test('a mixed value that adds and removes is refused as a whole', async () => {
      const client = await seed();
      const snapshot = await row(client.clientId);
      const mixed = { ...EXO_CEILING, kv: { ...EXO_CEILING.kv, paths: EXO_CEILING.kv.paths.filter((path) => !path.endsWith('/threads/')) } };
      await expect(run(client.clientId, mixed)).rejects.toBeInstanceOf(NativeCeilingRefusedError);
      await expectUntouched(client.clientId, snapshot);
    });
  });

  describe('malformed values', () => {
    const { version: _version, ...withoutVersion } = DOC_CEILING;
    const { tinycloudHost: _host, ...withoutHost } = DOC_CEILING;
    const { kv: _kv, ...withoutKv } = DOC_CEILING;
    const malformed: Array<[string, unknown]> = [
      ['text that is not JSON', 'not json {'],
      ['an array', []],
      ['null', null],
      ['a string', 'text'],
      ['version 2', { ...DOC_CEILING, version: 2 }],
      ['no version', withoutVersion],
      ['no tinycloudHost', withoutHost],
      ['no kv', withoutKv],
      ['only the new entries', { kv: { paths: EXO_KV, actions: ['get'] } }],
      ['an unknown field', { ...DOC_CEILING, extra: true }],
      ['a kv path outside the appId', { ...DOC_CEILING, kv: { ...DOC_CEILING.kv, paths: ['other.app/threads/'] } }],
      ['an empty kv path list', { ...DOC_CEILING, kv: { ...DOC_CEILING.kv, paths: [] } }],
      ['an unsupported action', { ...DOC_CEILING, kv: { ...DOC_CEILING.kv, actions: ['get', 'admin'] } }],
      ['an untrusted host', { ...DOC_CEILING, tinycloudHost: 'https://untrusted.example' }],
      ['a loopback host', { ...DOC_CEILING, tinycloudHost: 'http://localhost:8000' }],
    ];

    test.each(malformed)('refuses %s and writes nothing', async (_label, ceiling) => {
      const client = await seed();
      const snapshot = await row(client.clientId);
      await expect(run(client.clientId, ceiling, { allowNarrow: true })).rejects.toBeInstanceOf(Error);
      await expectUntouched(client.clientId, snapshot);
    });
  });

  describe('a ceiling update changes the ceiling only', () => {
    test('a successful update leaves appId, siweDomain and every other column untouched', async () => {
      const client = await seed();
      await run(client.clientId, EXO_CEILING);
      const stored = await row(client.clientId);
      const config = validateNativeDelegationConfig(stored.tinycloudNativeDelegation, stored);
      expect(config.appId).toBe(APP);
      expect(config.siweDomain).toBe('openkey.so');
      const { tinycloudNativeDelegation: _storedCeiling, updatedAt: _storedAt, ...storedColumns } = stored;
      const { tinycloudNativeDelegation: _seededCeiling, updatedAt: _seededAt, ...seededColumns } = client;
      expect(storedColumns).toEqual(seededColumns);
    });

    test('a stored ceiling without a siweDomain stays without one', async () => {
      const { siweDomain: _siweDomain, ...bare } = DOC_CEILING;
      const client = await seed({ ceiling: bare });
      const { result, output } = await run(client.clientId, EXO_CEILING);
      expect(result.outcome).toBe('written');
      expect(output).toContain('siweDomain = openkey.so (default)');
      const stored = await row(client.clientId);
      expect(Object.hasOwn(validateNativeDelegationConfig(stored.tinycloudNativeDelegation, stored), 'siweDomain')).toBe(false);
    });

    const equal: Array<[string, Record<string, string>]> = [
      ['the stored appId', { appId: APP }],
      ['the stored siweDomain', { siweDomain: 'openkey.so' }],
      ['both stored values', { appId: APP, siweDomain: 'openkey.so' }],
    ];

    test.each(equal)('supplying %s is accepted as a no-op: the stored values are unchanged and are the written ones', async (_label, fields) => {
      const client = await seed();
      const { result, output } = await run(client.clientId, { ...suppliedCeiling(EXO_CEILING) as object, ...fields }, { identity: true });
      expect(result.outcome).toBe('written');
      expect(output).toContain(`KEPT (not changed by this run): appId = ${APP}; siweDomain = openkey.so`);
      expect(output).toContain('EQUAL (no change): the supplied');
      const stored = await row(client.clientId);
      const config = validateNativeDelegationConfig(stored.tinycloudNativeDelegation, stored);
      expect([config.appId, config.siweDomain]).toEqual([APP, 'openkey.so']);
      expect(sortedJson(config)).toBe(sortedJson(EXO_CEILING));
      const { tinycloudNativeDelegation: _storedCeiling, updatedAt: _storedAt, ...storedColumns } = stored;
      const { tinycloudNativeDelegation: _seededCeiling, updatedAt: _seededAt, ...seededColumns } = client;
      expect(storedColumns).toEqual(seededColumns);
    });

    test('a ceiling copied whole from the stored value, with the six Exo entries added, is applied as is', async () => {
      const client = await seed();
      const { result } = await run(client.clientId, EXO_CEILING, { identity: true });
      expect(result.outcome).toBe('written');
      const stored = await row(client.clientId);
      expect(sortedJson(stored.tinycloudNativeDelegation)).toBe(sortedJson(EXO_CEILING));
    });

    test('a dry run with equal values prints the note and issues no UPDATE', async () => {
      const client = await seed();
      const snapshot = await row(client.clientId);
      const { result, output } = await run(client.clientId, EXO_CEILING, { identity: true, dryRun: true });
      expect(result.outcome).toBe('dry-run');
      expect(output).toContain('EQUAL (no change): the supplied appId and siweDomain equal the stored value');
      await expectUntouched(client.clientId, snapshot);
    });

    test('a custom stored siweDomain is kept when the same one is supplied', async () => {
      const custom = { ...DOC_CEILING, siweDomain: 'custom.example' };
      const client = await seed({ ceiling: custom });
      await run(client.clientId, { ...EXO_CEILING, siweDomain: 'custom.example' }, { identity: true });
      const stored = await row(client.clientId);
      expect(validateNativeDelegationConfig(stored.tinycloudNativeDelegation, stored).siweDomain).toBe('custom.example');
    });

    test('the default siweDomain equals an absent stored one, and the stored value stays absent', async () => {
      const { siweDomain: _siweDomain, ...bare } = DOC_CEILING;
      const client = await seed({ ceiling: bare });
      const { result } = await run(client.clientId, EXO_CEILING, { identity: true });
      expect(result.outcome).toBe('written');
      const stored = await row(client.clientId);
      expect(Object.hasOwn(validateNativeDelegationConfig(stored.tinycloudNativeDelegation, stored), 'siweDomain')).toBe(false);
    });

    const different: Array<[string, Record<string, unknown>, string]> = [
      ['another appId', { appId: 'xyz.tinycloud.other' }, `appId (stored: ${APP}; supplied: "xyz.tinycloud.other")`],
      ['another siweDomain', { siweDomain: 'example.test' }, 'siweDomain (stored: openkey.so; supplied: "example.test")'],
      ['both another appId and siweDomain', { appId: 'xyz.tinycloud.other', siweDomain: 'example.test' }, 'appId (stored'],
      ['an appId that is not a string', { appId: 7 }, 'appId (stored'],
    ];

    test.each(different)('supplying %s is refused, with or without allowNarrow, and nothing is written', async (_label, fields, expected) => {
      const client = await seed();
      const snapshot = await row(client.clientId);
      for (const allowNarrow of [false, true]) {
        const failure = await run(client.clientId, { ...suppliedCeiling(EXO_CEILING) as object, ...fields }, { allowNarrow, identity: true })
          .catch((error: unknown) => error);
        expect(failure).toBeInstanceOf(NativeCeilingRefusedError);
        expect((failure as Error).message).toContain(expected);
        expect((failure as Error).message).toContain('cannot be changed');
      }
      await expectUntouched(client.clientId, snapshot);
    });

    test('a siweDomain that differs from a custom stored one, or from an absent one, is refused', async () => {
      const { siweDomain: _siweDomain, ...bare } = DOC_CEILING;
      const cases: Array<[unknown, string]> = [
        [{ ...DOC_CEILING, siweDomain: 'custom.example' }, 'openkey.so'],
        [bare, 'example.test'],
      ];
      for (const [ceiling, supplied] of cases) {
        const client = await seed({ ceiling });
        const snapshot = await row(client.clientId);
        await expect(run(client.clientId, { ...EXO_CEILING, siweDomain: supplied }, { identity: true, allowNarrow: true }))
          .rejects.toBeInstanceOf(NativeCeilingRefusedError);
        await expectUntouched(client.clientId, snapshot);
      }
    });

    test('a different tinycloudHost is refused even with allowNarrow', async () => {
      const client = await seed();
      const snapshot = await row(client.clientId);
      const moved = { ...DOC_CEILING, tinycloudHost: 'https://node.tinycloud.xyz' };
      for (const allowNarrow of [false, true]) {
        const failure = await run(client.clientId, moved, { allowNarrow }).catch((error: unknown) => error);
        expect(failure).toBeInstanceOf(NativeCeilingRefusedError);
        expect((failure as Error).message).toContain(`  ! tinycloudHost: ${HOST} -> https://node.tinycloud.xyz`);
      }
      await expectUntouched(client.clientId, snapshot);
    });

    test('a stored value that fails validation still keeps its appId', async () => {
      const client = await seed({ ceiling: { version: 9, appId: APP } });
      const snapshot = await row(client.clientId);
      await expect(run(client.clientId, { ...EXO_CEILING, appId: 'xyz.tinycloud.other' }, { identity: true }))
        .rejects.toBeInstanceOf(NativeCeilingRefusedError);
      await expectUntouched(client.clientId, snapshot);
      const { result } = await run(client.clientId, EXO_CEILING, { identity: true });
      expect(result.outcome).toBe('written');
      expect(result.after.appId).toBe(APP);
    });

    test('a client without a ceiling has to supply its appId', async () => {
      const client = await seed({ ceiling: null });
      const snapshot = await row(client.clientId);
      await expect(run(client.clientId, EXO_CEILING)).rejects.toThrow('appId is invalid');
      await expectUntouched(client.clientId, snapshot);
    });
  });

  describe('dry run', () => {
    test('prints BEFORE, AFTER and the diff, and issues no UPDATE', async () => {
      const client = await seed();
      const snapshot = await row(client.clientId);
      const { result, output } = await run(client.clientId, EXO_CEILING, { dryRun: true });
      expect(result.outcome).toBe('dry-run');
      expect(output).toContain(`BEFORE: ${sortedJson(DOC_CEILING)}`);
      expect(output).toContain(`AFTER: ${sortedJson(EXO_CEILING)}`);
      expect(output).toContain(`KEPT (not changed by this run): appId = ${APP}; siweDomain = openkey.so`);
      for (const path of EXO_KV) expect(output).toContain(`  + kv.paths: ${path}`);
      for (const name of EXO_SQL) expect(output).toContain(`  + sql.databases: ${name}`);
      expect(output).toContain('DRY RUN: nothing written');
      await expectUntouched(client.clientId, snapshot);
      expect((await row(client.clientId)).updatedAt.getTime()).toBe(snapshot.updatedAt.getTime());
    });

    test('still refuses a removal without allowNarrow, and with it still writes nothing', async () => {
      const client = await seed();
      const snapshot = await row(client.clientId);
      const narrower = { ...DOC_CEILING, sql: null };
      await expect(run(client.clientId, narrower, { dryRun: true })).rejects.toBeInstanceOf(NativeCeilingRefusedError);
      const { result, output } = await run(client.clientId, narrower, { dryRun: true, allowNarrow: true });
      expect(result.outcome).toBe('dry-run');
      expect(output).toContain(`  - sql.databases: ${APP}/canvas`);
      await expectUntouched(client.clientId, snapshot);
    });
  });

  describe('the client row', () => {
    test('an unknown client_id is refused and no client is created', async () => {
      await seed();
      const before = await prisma.oauthClient.count();
      await expect(run('ok_tc1990_missing', EXO_CEILING)).rejects.toThrow('Enabled OAuth client not found: ok_tc1990_missing');
      expect(await prisma.oauthClient.count()).toBe(before);
      expect(await updateCount()).toBe(0);
    });

    test('a disabled client is refused', async () => {
      const client = await seed({ disabled: true });
      const snapshot = await row(client.clientId);
      await expect(run(client.clientId, EXO_CEILING)).rejects.toThrow('Enabled OAuth client not found');
      await expectUntouched(client.clientId, snapshot);
    });

    test.each(['spa', 'web', null])('a client of type %p is refused', async (type) => {
      const client = await seed({ type, ceiling: null });
      const snapshot = await row(client.clientId);
      await expect(run(client.clientId, EXO_CEILING)).rejects.toThrow('requires a native public client');
      await expectUntouched(client.clientId, snapshot);
    });
  });

  describe('output', () => {
    test('BEFORE and AFTER carry only ceiling fields, never client credentials or metadata', async () => {
      const client = await seed({
        extra: {
          clientSecret: 'tc1990-secret-hash-value',
          softwareStatement: 'tc1990.statement.jwt',
          metadata: { apiKey: 'tc1990-api-key-value' },
          contacts: ['owner-tc1990@example.test'],
          uri: 'https://tc1990.example.test',
        },
      });
      const { output } = await run(client.clientId, EXO_CEILING);
      for (const secret of ['tc1990-secret-hash-value', 'tc1990.statement.jwt', 'tc1990-api-key-value', 'owner-tc1990', 'tc1990.example.test']) {
        expect(output).not.toContain(secret);
      }
      const allowed = new Set([
        'version', 'appId', 'tinycloudHost', 'kv', 'paths', 'actions', 'sql', 'databases',
        'maxDelegationTtlSeconds', 'grantLifetimeSeconds', 'siweDomain',
      ]);
      const keys = [...output.matchAll(/"([^"]+)":/g)].map((match) => match[1]!);
      expect(keys.length).toBeGreaterThan(0);
      expect(keys.filter((key) => !allowed.has(key))).toEqual([]);
    });

    test('printed ceilings are key-sorted regardless of the key order supplied', () => {
      const shuffled = { siweDomain: 'openkey.so', kv: { actions: ['get'], paths: ['a/b/'] }, appId: 'a', version: 1 };
      expect(Object.keys(JSON.parse(sortedJson(shuffled)))).toEqual(['appId', 'kv', 'siweDomain', 'version']);
      expect(sortedJson(shuffled)).toBe(sortedJson({ version: 1, appId: 'a', kv: { paths: ['a/b/'], actions: ['get'] }, siweDomain: 'openkey.so' }));
    });
  });

  describe('diffNativeCeilings', () => {
    const client = { type: 'native', public: true, tokenEndpointAuthMethod: 'none' };
    test('treats an absent siweDomain as the default domain', () => {
      const withDefault = validateNativeDelegationConfig(DOC_CEILING, client);
      const { siweDomain: _siwe, ...bare } = DOC_CEILING;
      expect(diffNativeCeilings(withDefault, validateNativeDelegationConfig(bare, client))).toEqual({ added: [], removed: [], changed: [], fixed: [] });
    });
  });
});

describe('ci-register-oauth-client.ts', () => {
  let directory: string;
  const created: string[] = [];

  async function openDatabase() {
    const database = new PGlite(directory);
    const prisma = new PrismaClient({ adapter: new PrismaPGlite(database) });
    return {
      prisma,
      close: async () => {
        await prisma.$disconnect();
        await database.close();
      },
    };
  }

  /** Runs `fn` against the database, then releases it so the script can open it. */
  async function withDatabase<T>(fn: (prisma: PrismaClient) => Promise<T>): Promise<T> {
    const open = await openDatabase();
    try {
      return await fn(open.prisma);
    } finally {
      await open.close();
    }
  }

  async function script(args: string[], env: Record<string, string>) {
    const child = Bun.spawn([process.execPath, 'scripts/ci-register-oauth-client.ts', ...args], {
      cwd: root,
      // Only what the script needs; the caller's DATABASE_URL and other env never reach it.
      env: { PATH: process.env.PATH ?? '', HOME: workDir, NODE_ENV: 'test', DATABASE_URL: `pglite:${directory}`, ...env },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    // A hung child must fail the test, not stall the suite; no deterministic clock applies to a subprocess.
    const timer = setTimeout(() => child.kill(), 90_000);
    try {
      const [stdout, stderr, exitCode] = await Promise.all([
        new Response(child.stdout).text(),
        new Response(child.stderr).text(),
        child.exited,
      ]);
      return { stdout, stderr, exitCode };
    } finally {
      clearTimeout(timer);
    }
  }

  beforeAll(async () => {
    expect(process.env.HOME).toBe(workDir);
    expect(process.env.HOME).not.toBe(realHome);
    directory = join(workDir, 'cli-db');
    const database = new PGlite(directory);
    try {
      await migratedDatabase(database);
      await database.exec(UPDATE_AUDIT_SQL);
    } finally {
      await database.close();
    }
    created.push(directory);
  }, 120_000);

  const ceilingEnv = (clientId: string, ceiling: unknown) => ({
    CLIENT_ID: clientId,
    CLIENT_TINYCLOUD_NATIVE_DELEGATION: JSON.stringify(suppliedCeiling(ceiling)),
  });

  /** How many UPDATE statements the database has seen for this client. */
  async function updatesOf(clientId: string) {
    const rows = await withDatabase((prisma) => prisma.$queryRawUnsafe<Array<{ count: number }>>(
      'SELECT count(*)::int AS count FROM tc1990_update_audit WHERE client_id = $1', clientId,
    ));
    return rows[0]!.count;
  }

  async function storedOf(clientId: string) {
    return withDatabase((prisma) => prisma.oauthClient.findUniqueOrThrow({ where: { clientId } }));
  }

  test.each([[[]], [['--dry-run']]])('arguments %p print BEFORE/AFTER and the diff and issue no UPDATE', async (args) => {
    const client = await withDatabase((prisma) => seedClient(prisma));
    const result = await script(args, ceilingEnv(client.clientId, EXO_CEILING));
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.stdout).toContain('BEFORE:');
    expect(result.stdout).toContain('AFTER:');
    expect(result.stdout).toContain(`  + kv.paths: ${EXO_KV[0]}`);
    expect(result.stdout).toContain('DRY RUN: nothing written');
    expect(result.stdout).not.toContain('Written.');
    expect(result.stdout + result.stderr).not.toContain(directory);
    expect(await storedOf(client.clientId)).toEqual(client);
    expect(await updatesOf(client.clientId)).toBe(0);
  }, 120_000);

  test('--apply replaces the ceiling and reads it back', async () => {
    const client = await withDatabase((prisma) => seedClient(prisma));
    const result = await script(['--apply'], ceilingEnv(client.clientId, EXO_CEILING));
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.stdout).toContain('Written. The stored ceiling matches AFTER.');
    expect(result.stdout).toContain(`CLIENT_ID=${client.clientId}`);
    const stored = await storedOf(client.clientId);
    expect(sortedJson(stored.tinycloudNativeDelegation)).toBe(sortedJson(EXO_CEILING));
    expect(await updatesOf(client.clientId)).toBe(1);
  }, 120_000);

  test('--apply and --dry-run together are refused and write nothing', async () => {
    const client = await withDatabase((prisma) => seedClient(prisma));
    const result = await script(['--apply', '--dry-run'], ceilingEnv(client.clientId, EXO_CEILING));
    expect(result.exitCode).toBe(1);
    expect(result.stderr).toContain('--apply and --dry-run cannot be combined');
    expect(await storedOf(client.clientId)).toEqual(client);
    expect(await updatesOf(client.clientId)).toBe(0);
  }, 120_000);

  test('a removal exits non-zero without --allow-narrow, and --apply with it writes', async () => {
    const client = await withDatabase((prisma) => seedClient(prisma));
    const narrower = { ...DOC_CEILING, sql: null };
    for (const args of [[], ['--apply']]) {
      const refused = await script(args, ceilingEnv(client.clientId, narrower));
      expect(refused.exitCode).toBe(1);
      expect(refused.stderr).toContain(`  - sql.databases: ${APP}/canvas`);
      expect(refused.stderr).toContain('--allow-narrow');
      expect(await storedOf(client.clientId)).toEqual(client);
    }

    const allowedDry = await script(['--allow-narrow'], ceilingEnv(client.clientId, narrower));
    expect(allowedDry.exitCode, allowedDry.stderr).toBe(0);
    expect(allowedDry.stdout).toContain('DRY RUN: nothing written');
    expect(await updatesOf(client.clientId)).toBe(0);

    const applied = await script(['--allow-narrow', '--apply'], ceilingEnv(client.clientId, narrower));
    expect(applied.exitCode, applied.stderr).toBe(0);
    const stored = await storedOf(client.clientId);
    expect(validateNativeDelegationConfig(stored.tinycloudNativeDelegation, stored).sql).toBeNull();
    expect(await updatesOf(client.clientId)).toBe(1);
  }, 240_000);

  test('a different appId or siweDomain is refused, equal ones are accepted as they are, and the stored values are kept', async () => {
    const client = await withDatabase((prisma) => seedClient(prisma));
    for (const extra of [{ appId: 'xyz.tinycloud.other' }, { siweDomain: 'example.test' }]) {
      const refused = await script(['--apply', '--allow-narrow'], {
        CLIENT_ID: client.clientId,
        CLIENT_TINYCLOUD_NATIVE_DELEGATION: JSON.stringify({ ...suppliedCeiling(EXO_CEILING) as object, ...extra }),
      });
      expect(refused.exitCode).toBe(1);
      expect(refused.stderr).toContain('cannot be changed');
    }
    expect(await storedOf(client.clientId)).toEqual(client);
    expect(await updatesOf(client.clientId)).toBe(0);

    // The full value, as copied from the stored ceiling with the new entries added.
    const applied = await script(['--apply'], { CLIENT_ID: client.clientId, CLIENT_TINYCLOUD_NATIVE_DELEGATION: JSON.stringify(EXO_CEILING) });
    expect(applied.exitCode, applied.stderr).toBe(0);
    expect(applied.stdout).toContain(`KEPT (not changed by this run): appId = ${APP}; siweDomain = openkey.so`);
    expect(applied.stdout).toContain('EQUAL (no change): the supplied appId and siweDomain equal the stored value');
    const stored = await storedOf(client.clientId);
    const config = validateNativeDelegationConfig(stored.tinycloudNativeDelegation, stored);
    expect([config.appId, config.siweDomain]).toEqual([APP, 'openkey.so']);
    expect(await updatesOf(client.clientId)).toBe(1);
  }, 240_000);

  test('a ceiling cannot be combined with branding fields, and the flags need a ceiling', async () => {
    const client = await withDatabase((prisma) => seedClient(prisma));
    const combined = await script([], { ...ceilingEnv(client.clientId, EXO_CEILING), CLIENT_ICON: 'https://example.test/icon.png' });
    expect(combined.exitCode).toBe(1);
    expect(combined.stderr).toContain('remove CLIENT_ICON');
    for (const flag of ['--apply', '--dry-run']) {
      const flagOnly = await script([flag], { CLIENT_ID: client.clientId, CLIENT_ICON: 'https://example.test/icon.png' });
      expect(flagOnly.exitCode).toBe(1);
      expect(flagOnly.stderr).toContain('apply to ceiling updates only');
    }
    const unknown = await script(['--force'], ceilingEnv(client.clientId, EXO_CEILING));
    expect(unknown.exitCode).toBe(1);
    expect(unknown.stderr).toContain('Unknown argument: --force');
    const stored = await withDatabase((prisma) => prisma.oauthClient.findUniqueOrThrow({ where: { clientId: client.clientId } }));
    expect(stored).toEqual(client);
  }, 180_000);

  test('the branding update and create paths behave as before', async () => {
    const client = await withDatabase((prisma) => seedClient(prisma));
    const branding = await script([], { CLIENT_ID: client.clientId, CLIENT_ICON: 'https://example.test/icon.png' });
    expect(branding.exitCode, branding.stderr).toBe(0);
    expect(branding.stdout).toContain('Branding updated for enabled OAuth client');
    const updated = await withDatabase((prisma) => prisma.oauthClient.findUniqueOrThrow({ where: { clientId: client.clientId } }));
    expect(updated.icon).toBe('https://example.test/icon.png');
    expect(updated.tinycloudNativeDelegation).toEqual(client.tinycloudNativeDelegation as never);

    const name = `TC-1990 created ${Date.now()}`;
    const create = await script([], { CLIENT_NAME: name, CLIENT_REDIRECT_URIS: 'xyz.tinycloud.created://cb' });
    expect(create.exitCode, create.stderr).toBe(0);
    expect(create.stdout).toContain(`OAuth client registered: ${name}`);
    const createdRow = await withDatabase((prisma) => prisma.oauthClient.findFirst({ where: { name } }));
    expect(createdRow?.tinycloudNativeDelegation).toBeNull();
  }, 180_000);
});

// TC-1990: the workflow's own "Register client" shell step, run with `bun` stubbed
// to record its arguments, decides whether the script is told to write.
describe('register-oauth-client.yml dry_run mapping', () => {
  const workflow = readFileSync(join(root, '.github/workflows/register-oauth-client.yml'), 'utf8');
  const stubDirectory = join(workDir, 'stub-bin');

  function registerStepScript() {
    const lines = workflow.split('\n');
    const start = lines.findIndex((line) => line.trim() === '- name: Register client');
    const run = lines.findIndex((line, index) => index > start && line.trim() === 'run: |');
    expect(start).toBeGreaterThan(-1);
    expect(run).toBeGreaterThan(start);
    const indent = lines[run]!.indexOf('run:') + 2;
    const body: string[] = [];
    for (const line of lines.slice(run + 1)) {
      if (line.trim() !== '' && line.search(/\S/) < indent) break;
      body.push(line.slice(indent));
    }
    return body.join('\n');
  }

  /** The arguments the step passes to scripts/ci-register-oauth-client.ts. */
  async function scriptArguments(env: Record<string, string>) {
    const log = join(workDir, `stub-${sequence += 1}.log`);
    const child = Bun.spawn([Bun.which('bash') ?? '/bin/bash', '-e', '-c', registerStepScript()], {
      cwd: workDir,
      env: { PATH: `${stubDirectory}:/usr/bin:/bin`, HOME: workDir, DATABASE_URL: 'stub-not-a-real-url', STUB_LOG: log, ...env },
      stdout: 'pipe',
      stderr: 'pipe',
    });
    const [stderr, exitCode] = await Promise.all([new Response(child.stderr).text(), child.exited]);
    expect(exitCode, stderr).toBe(0);
    const invocation = readFileSync(log, 'utf8').split('\n').filter((line) => line.includes('ci-register-oauth-client.ts'));
    expect(invocation).toHaveLength(1);
    return invocation[0]!.split('ci-register-oauth-client.ts')[1]!.trim().split(' ').filter(Boolean);
  }

  beforeAll(() => {
    expect(process.env.HOME).toBe(workDir);
    expect(process.env.HOME).not.toBe(realHome);
    mkdirSync(stubDirectory);
    writeFileSync(join(stubDirectory, 'bun'), '#!/bin/sh\nprintf \'%s\\n\' "$*" >> "$STUB_LOG"\n');
    chmodSync(join(stubDirectory, 'bun'), 0o755);
  });

  const ceiling = { CLIENT_ID: 'ok_tc1990_mapping', CLIENT_TINYCLOUD_NATIVE_DELEGATION: '{"version":1}' };

  test.each([
    ['false', ['--apply']],
    ['true', []],
    ['', []],
    ['False', []],
    ['FALSE', []],
    [' false', []],
    ['0', []],
    ['no', []],
    ['maybe', []],
  ])('a ceiling update with dry_run %p passes %p', async (dryRun, expected) => {
    expect(await scriptArguments({ ...ceiling, DRY_RUN: dryRun })).toEqual(expected);
  });

  test('a ceiling update without a dry_run value passes no write flag', async () => {
    expect(await scriptArguments({ ...ceiling })).toEqual([]);
  });

  test.each([
    ['false', 'true', ['--apply', '--allow-narrow']],
    ['true', 'true', ['--allow-narrow']],
    ['false', 'false', ['--apply']],
    ['false', '', ['--apply']],
    ['false', 'yes', ['--apply']],
  ])('dry_run %p with allow_narrow %p passes %p', async (dryRun, allowNarrow, expected) => {
    expect(await scriptArguments({ ...ceiling, DRY_RUN: dryRun, ALLOW_NARROW: allowNarrow })).toEqual(expected);
  });

  test('create and branding runs never receive a flag, whatever dry_run says', async () => {
    const flags = { DRY_RUN: 'false', ALLOW_NARROW: 'true' };
    expect(await scriptArguments({ ...flags, CLIENT_NAME: 'App' })).toEqual([]);
    expect(await scriptArguments({ ...flags, CLIENT_TINYCLOUD_NATIVE_DELEGATION: '{"version":1}' })).toEqual([]);
    expect(await scriptArguments({ ...flags, CLIENT_ID: 'ok_tc1990_mapping', CLIENT_ICON: 'https://example.test/i.png' })).toEqual([]);
  });
});
