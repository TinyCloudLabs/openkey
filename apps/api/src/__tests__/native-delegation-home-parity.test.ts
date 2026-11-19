import { describe, expect, test } from 'bun:test';

import {
  NativeDelegationPolicyError,
  validateNativeDelegationConfig,
  type NativeDelegationClient,
  type NativeDelegationConfig,
} from '../services/native-delegation/policy';
import { ParError, validatePermissions } from '../services/native-delegation/par';

// TC-2720: the TinyCloud Home native client's ceiling matches what Home's web
// sign-in grants in the applications space (feed databases, hook
// subscriptions, the whole-space KV and the two catalog databases).
const app = 'xyz.tinycloud.tinychat';
const nativeClient: NativeDelegationClient = { type: 'native', public: true, tokenEndpointAuthMethod: 'none' };
const policyOptions = { allowLocalHosts: false };
const homeCeiling = {
  version: 1,
  appId: app,
  tinycloudHost: 'https://tee.node.tinycloud.xyz',
  kv: {
    paths: [`${app}/threads/`, `${app}/connectors/`, `${app}/exo/v1/requests/`, `${app}/exo/v1/jobs/`],
    actions: ['get', 'put', 'list', 'del', 'metadata'],
    root: true,
  },
  sql: {
    databases: [`${app}/threads`, `${app}/canvas`, `${app}/connectors`, `${app}/home_feed`, `${app}/details`, `${app}/summaries`, `${app}/transcripts`],
    actions: ['read', 'write', 'schema'],
    prefixes: [`${app}/feed/`],
    foreignDatabases: ['xyz.tinycloud.sample.healthlog/healthlog', 'xyz.tinycloud.sample.recipes/recipes'],
  },
  hooks: { paths: [`sql/${app}/feed/`, `sql/${app}/home_feed`, `sql/${app}/threads`], actions: ['subscribe'] },
  maxDelegationTtlSeconds: 3600,
  grantLifetimeSeconds: 2_592_000,
  siweDomain: 'openkey.so',
};

/** Home's applications-space manifest entries as the native app sends them (no `tinycloud.space`, no secrets). */
const homeRequest = [
  { service: 'tinycloud.capabilities', space: 'applications', path: '', actions: ['tinycloud.capabilities/read'] },
  { service: 'tinycloud.kv', space: 'applications', path: `${app}/threads/`, actions: ['tinycloud.kv/get', 'tinycloud.kv/put', 'tinycloud.kv/del', 'tinycloud.kv/list'] },
  { service: 'tinycloud.sql', space: 'applications', path: `${app}/threads`, actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  { service: 'tinycloud.sql', space: 'applications', path: `${app}/home_feed`, actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  { service: 'tinycloud.sql', space: 'applications', path: `${app}/feed/`, actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  { service: 'tinycloud.hooks', space: 'applications', path: `sql/${app}/feed/`, actions: ['tinycloud.hooks/subscribe'] },
  { service: 'tinycloud.hooks', space: 'applications', path: `sql/${app}/home_feed`, actions: ['tinycloud.hooks/subscribe'] },
  { service: 'tinycloud.hooks', space: 'applications', path: `sql/${app}/threads`, actions: ['tinycloud.hooks/subscribe'] },
  { service: 'tinycloud.sql', space: 'applications', path: `${app}/canvas`, actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  { service: 'tinycloud.sql', space: 'applications', path: `${app}/connectors`, actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  { service: 'tinycloud.kv', space: 'applications', path: `${app}/connectors/`, actions: ['tinycloud.kv/get', 'tinycloud.kv/put', 'tinycloud.kv/del', 'tinycloud.kv/list'] },
  { service: 'tinycloud.sql', space: 'applications', path: `${app}/details`, actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  { service: 'tinycloud.sql', space: 'applications', path: `${app}/summaries`, actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  { service: 'tinycloud.sql', space: 'applications', path: `${app}/transcripts`, actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  { service: 'tinycloud.kv', space: 'applications', path: '', actions: ['tinycloud.kv/get', 'tinycloud.kv/put', 'tinycloud.kv/del', 'tinycloud.kv/list', 'tinycloud.kv/metadata'] },
  { service: 'tinycloud.kv', space: 'applications', path: `${app}/exo/v1/requests/`, actions: ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/del'] },
  { service: 'tinycloud.kv', space: 'applications', path: `${app}/exo/v1/jobs/`, actions: ['tinycloud.kv/get', 'tinycloud.kv/put', 'tinycloud.kv/del'] },
  { service: 'tinycloud.sql', space: 'applications', path: 'xyz.tinycloud.sample.healthlog/healthlog', actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
  { service: 'tinycloud.sql', space: 'applications', path: 'xyz.tinycloud.sample.recipes/recipes', actions: ['tinycloud.sql/read', 'tinycloud.sql/write', 'tinycloud.sql/schema'] },
];

function accepted(input: unknown): NativeDelegationConfig {
  return validateNativeDelegationConfig(input, nativeClient, policyOptions);
}

function refused(input: unknown) {
  expect(() => validateNativeDelegationConfig(input, nativeClient, policyOptions)).toThrow(NativeDelegationPolicyError);
}

function exceeds(permissions: unknown[], ceiling: NativeDelegationConfig = accepted(homeCeiling)): string {
  try {
    validatePermissions([homeRequest[0], ...permissions], ceiling);
  } catch (error) {
    if (error instanceof ParError) return error.message;
    throw error;
  }
  return 'accepted';
}

describe('Home native ceiling parity (TC-2720)', () => {
  test('the Home ceiling validates and keeps its new fields in canonical form', () => {
    const parsed = accepted(homeCeiling);
    expect(parsed.kv.root).toBe(true);
    expect(parsed.sql?.prefixes).toEqual([`${app}/feed/`]);
    expect(parsed.sql?.foreignDatabases).toEqual(['xyz.tinycloud.sample.healthlog/healthlog', 'xyz.tinycloud.sample.recipes/recipes']);
    expect(parsed.hooks).toEqual(homeCeiling.hooks);
    expect(accepted(parsed)).toEqual(parsed);
  });

  test('PAR accepts the exact native request Home sends', () => {
    expect(validatePermissions(homeRequest, accepted(homeCeiling))).toHaveLength(homeRequest.length);
  });

  test('a ceiling without the new fields refuses the feed, hooks, root KV and catalog entries', () => {
    const legacy = accepted({ ...homeCeiling, kv: { ...homeCeiling.kv, root: undefined }, sql: { databases: homeCeiling.sql.databases, actions: homeCeiling.sql.actions }, hooks: undefined });
    expect(exceeds([homeRequest[4]], legacy)).toBe('SQL permission exceeds ceiling');
    expect(exceeds([homeRequest[17]], legacy)).toBe('SQL permission exceeds ceiling');
    expect(exceeds([homeRequest[14]], legacy)).toBe('KV permission exceeds ceiling');
    expect(exceeds([homeRequest[5]], legacy)).toBe('hooks permission exceeds ceiling');
  });
});

describe('Home ceiling validators fail closed', () => {
  test('kv.root is only the literal true', () => {
    for (const root of [false, 'true', 1, null]) refused({ ...homeCeiling, kv: { ...homeCeiling.kv, root } });
  });

  test('SQL prefixes stay under the appId as <appId>/<name>/', () => {
    for (const prefixes of [
      ['other.app/feed/'],
      [`${app}/feed`],
      [`${app}/`],
      [`${app}/feed/inner/`],
      [`${app}/../feed/`],
      ['feed/'],
      [],
    ]) {
      refused({ ...homeCeiling, sql: { ...homeCeiling.sql, prefixes } });
    }
  });

  test('other-app databases are explicit exact names outside this app and outside secret roots', () => {
    for (const foreignDatabases of [
      ['xyz.tinycloud.sample.healthlog/'],
      ['xyz.tinycloud.sample.healthlog/healthlog/'],
      ['xyz.tinycloud.sample.healthlog/a/b'],
      ['xyz.tinycloud.sample.healthlog'],
      [`${app}/threads`],
      ['secrets/healthlog'],
      ['vault/x'],
      ['-bad/x'],
      ['xyz.tinycloud.sample.healthlog/*'],
      [],
    ]) {
      refused({ ...homeCeiling, sql: { ...homeCeiling.sql, foreignDatabases } });
    }
  });

  test('hooks paths must be SQL paths the ceiling already holds, with subscribe only', () => {
    for (const paths of [
      [`sql/${app}/other`],
      [`kv/${app}/threads/`],
      [`${app}/threads`],
      [`sql/${app}/feed/agent`],
      ['sql/other.app/feed/'],
      [],
    ]) {
      refused({ ...homeCeiling, hooks: { ...homeCeiling.hooks, paths } });
    }
    refused({ ...homeCeiling, hooks: { ...homeCeiling.hooks, actions: ['register'] } });
    refused({ ...homeCeiling, hooks: { ...homeCeiling.hooks, extra: true } });
    refused({ ...homeCeiling, sql: null });
  });
});

describe('PAR stays inside the Home ceiling', () => {
  test('SQL outside the prefix, the exact list or the named catalog databases is refused', () => {
    expect(exceeds([{ ...homeRequest[4], path: `${app}/feed/agent-one` }])).toBe('accepted');
    expect(exceeds([{ ...homeRequest[4], path: `${app}/feedback` }])).toBe('SQL permission exceeds ceiling');
    expect(exceeds([{ ...homeRequest[17], path: 'xyz.tinycloud.sample.healthlog/other' }])).toBe('SQL permission exceeds ceiling');
    expect(exceeds([{ ...homeRequest[17], path: 'xyz.tinycloud.sample.other/healthlog' }])).toBe('SQL permission exceeds ceiling');
  });

  test('hooks need an exact ceiling path and only subscribe', () => {
    expect(exceeds([{ ...homeRequest[5], path: `sql/${app}/feed/agent-one` }])).toBe('hooks permission exceeds ceiling');
    expect(exceeds([{ ...homeRequest[5], path: `sql/${app}/canvas` }])).toBe('hooks permission exceeds ceiling');
    expect(exceeds([{ ...homeRequest[5], actions: ['tinycloud.hooks/register'] }])).toBe('invalid hooks permission');
    expect(exceeds([{ ...homeRequest[5], path: `sql/${app}/../secrets` }])).toBe('invalid hooks permission');
  });

  test('root KV is limited to the ceiling actions, and other services stay unsupported', () => {
    expect(exceeds([{ ...homeRequest[14], actions: ['tinycloud.kv/admin'] }])).toBe('invalid KV permission');
    const narrow = accepted({ ...homeCeiling, kv: { ...homeCeiling.kv, actions: ['get', 'list'] } });
    expect(exceeds([homeRequest[14]], narrow)).toBe('KV permission exceeds ceiling');
    expect(exceeds([{ service: 'tinycloud.space', space: 'applications', path: '', actions: ['tinycloud.space/info'] }])).toBe('unsupported service');
  });
});
