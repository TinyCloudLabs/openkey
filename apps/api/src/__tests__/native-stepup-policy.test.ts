import { describe, expect, test } from 'bun:test';

import {
  NativeDelegationPolicyError,
  validateNativeDelegationConfig,
  type NativeDelegationClient,
} from '../services/native-delegation/policy';

// TC-3569: the step-up section of the Home client's ceiling. It is admin-set,
// read-only by construction, and nothing reads it until the endpoint ships.
const nativeClient: NativeDelegationClient = { type: 'native', public: true, tokenEndpointAuthMethod: 'none' };
const options = { allowLocalHosts: false };
const base = {
  version: 1,
  appId: 'xyz.tinycloud.tinychat',
  tinycloudHost: 'https://tee.node.tinycloud.xyz',
  kv: { paths: ['xyz.tinycloud.tinychat/threads/'], actions: ['get', 'put'] },
  sql: null,
};

// Phase 1, exactly as ruled: all read-only.
const phase1 = {
  'xyz.tinycloud.explorer': {
    public: { kv: { paths: [''], actions: ['get', 'list', 'metadata'] } },
    applications: { sql: { databases: ['default'], actions: ['read', 'schema'] } },
  },
  'xyz.tinycloud.account': { account: { kv: { paths: ['applications/', 'spaces/'], actions: ['get', 'list'] } } },
  'xyz.tinycloud.courier': { agents: { kv: { paths: ['xyz.tinycloud.courier/'], actions: ['get', 'list'] } } },
};

const withStepUps = (stepUps: unknown) => ({ ...base, stepUps });
const accepted = (stepUps: unknown) => validateNativeDelegationConfig(withStepUps(stepUps), nativeClient, options);
function refused(stepUps: unknown) {
  expect(() => accepted(stepUps)).toThrow(NativeDelegationPolicyError);
}

describe('step-up ceilings', () => {
  test('the phase 1 ceilings validate and round-trip unchanged', () => {
    expect(accepted(phase1).stepUps).toEqual(phase1);
  });

  test('a ceiling without step-ups is unchanged', () => {
    expect(validateNativeDelegationConfig(base, nativeClient, options).stepUps).toBeUndefined();
  });

  test('every write or non-read action is refused', () => {
    for (const action of ['put', 'del', 'write', 'subscribe', 'tinycloud.kv/get', '*']) {
      refused({ explorer: { public: { kv: { paths: [''], actions: ['get', action] } } } });
      refused({ explorer: { applications: { sql: { databases: ['default'], actions: ['read', action] } } } });
    }
    refused({ explorer: { applications: { sql: { databases: ['default'], actions: ['write'] } } } });
    refused({ explorer: { public: { kv: { paths: [''], actions: ['get', 'list', 'metadata', 'put'] } } } });
  });

  test('the secrets space, encryption and unknown spaces or services are refused', () => {
    for (const space of ['secrets', 'tinycloud.space', 'tinycloud.encryption', 'encryption', 'Public', '']) {
      refused({ explorer: { [space]: { kv: { paths: ['a/'], actions: ['list'] } } } });
    }
    for (const service of ['encryption', 'secrets', 'hooks', 'vault']) {
      refused({ explorer: { public: { [service]: { paths: ['a/'], actions: ['get'] } } } });
    }
  });

  test('the secrets roots are never addressed, with any case or nesting', () => {
    for (const path of ['secrets/', 'vault/secrets/', 'vault/secrets/scoped/app/KEY', 'variables/', 'Variables/x', 'VAULT/']) {
      refused({ explorer: { public: { kv: { paths: [path], actions: ['list'] } } } });
      refused({ explorer: { account: { kv: { paths: [path], actions: ['get'] } } } });
      refused({ explorer: { applications: { sql: { databases: [path.replace(/\/$/, '')], actions: ['read'] } } } });
    }
  });

  test('"" is the whole space and is admitted only in the public space', () => {
    for (const space of ['account', 'agents', 'applications']) {
      refused({ explorer: { [space]: { kv: { paths: [''], actions: ['get'] } } } });
    }
    expect(accepted({ explorer: { public: { kv: { paths: [''], actions: ['get'] } } } }).stepUps).toBeDefined();
  });

  test('paths stay relative, dot-free and well formed', () => {
    for (const path of ['/abs/', '../up/', 'a/../b/', './a/', 'a//b/', 'a/*', 'a b/', `${'x'.repeat(257)}/`]) {
      refused({ explorer: { account: { kv: { paths: [path], actions: ['get'] } } } });
    }
  });

  test('SQL ceilings name exact databases, with no prefix, pattern or extra depth', () => {
    for (const database of ['default/', 'a/b/c', 'a/', '/a', '*', 'de*', '..', 'a/..']) {
      refused({ explorer: { applications: { sql: { databases: [database], actions: ['read'] } } } });
    }
    expect(accepted({ explorer: { applications: { sql: { databases: ['default', 'xyz.app/main'], actions: ['read'] } } } }).stepUps).toBeDefined();
  });

  test('shape errors are refused: unknown members, empty sections, bad app ids, too many apps', () => {
    refused(null);
    refused([]);
    refused('explorer');
    refused({});
    refused({ explorer: {} });
    refused({ explorer: { public: {} } });
    refused({ explorer: { public: { kv: { paths: [''], actions: ['get'] }, extra: true } } });
    refused({ explorer: { public: { kv: { paths: [''], actions: ['get'], root: true } } } });
    refused({ explorer: { public: { kv: { paths: [], actions: ['get'] } } } });
    refused({ explorer: { public: { kv: { paths: ['a/', 'a/'], actions: ['get'] } } } });
    refused({ explorer: { public: { kv: { paths: [''], actions: [] } } } });
    for (const appId of ['', '-x', 'x-', 'a b', 'secrets', 'vault', '__proto__', 'x'.repeat(129)]) {
      refused({ [appId]: { public: { kv: { paths: [''], actions: ['get'] } } } });
    }
    const many = Object.fromEntries(Array.from({ length: 17 }, (_, index) => [`app${index}`, phase1['xyz.tinycloud.account']]));
    refused(many);
  });

  test('a step-up section does not loosen the existing ceiling rules', () => {
    expect(() => validateNativeDelegationConfig(
      { ...base, stepUps: phase1, kv: { paths: ['secrets/'], actions: ['get'] } }, nativeClient, options,
    )).toThrow(NativeDelegationPolicyError);
    expect(() => validateNativeDelegationConfig(withStepUps(phase1), { ...nativeClient, public: false }, options))
      .toThrow(NativeDelegationPolicyError);
  });
});
