import { afterEach, describe, expect, test } from 'bun:test';
import { StepUpEntryError, validateStepUpPermissions } from '../services/native-delegation/step-up';
import { nativeDelegationMetadata, nativeStepUpEnabled, isPublicProtocolPath } from '../services/native-delegation/public-protocol';

const ceilings = {
  'xyz.tinycloud.explorer': {
    public: { kv: { paths: [''], actions: ['get', 'list', 'metadata'] } },
    applications: { sql: { databases: ['default'], actions: ['read', 'schema'] } },
  },
  'xyz.tinycloud.account': { account: { kv: { paths: ['applications/', 'spaces/'], actions: ['get', 'list'] } } },
} as Parameters<typeof validateStepUpPermissions>[2];

const kv = (space: string, path: string, actions = ['tinycloud.kv/get']) => ({ service: 'tinycloud.kv', space, path, actions });
function kind(appId: string, value: unknown) {
  try { validateStepUpPermissions(appId, value, ceilings); } catch (error) { if (error instanceof StepUpEntryError) return error.kind; throw error; }
  return 'ok';
}

describe('step-up entry validation', () => {
  test('a /-terminated ceiling path covers its subtree; an exact ceiling path covers only itself', () => {
    expect(kind('xyz.tinycloud.account', [kv('account', 'spaces/abc/def')])).toBe('ok');
    expect(kind('xyz.tinycloud.account', [kv('account', 'spaces/')])).toBe('ok');
    expect(kind('xyz.tinycloud.account', [kv('account', 'spaces')])).toBe('ceiling');
    expect(kind('xyz.tinycloud.account', [kv('account', 'spacesx/a')])).toBe('ceiling');
    expect(kind('xyz.tinycloud.explorer', [kv('public', '')])).toBe('ok');
    expect(kind('xyz.tinycloud.explorer', [kv('public', 'a')])).toBe('ceiling');
  });

  test('the empty path is only valid where the ceiling names it, and never for SQL', () => {
    expect(kind('xyz.tinycloud.account', [kv('account', '')])).toBe('ceiling');
    expect(kind('xyz.tinycloud.explorer', [{ service: 'tinycloud.sql', space: 'applications', path: '', actions: ['tinycloud.sql/read'] }])).toBe('malformed');
    expect(kind('xyz.tinycloud.explorer', [{ service: 'tinycloud.sql', space: 'applications', path: 'default/', actions: ['tinycloud.sql/read'] }])).toBe('malformed');
  });

  test('app ids are exact; inherited object keys are not apps', () => {
    for (const appId of ['xyz.tinycloud.EXPLORER', 'xyz.tinycloud.explorer.', 'constructor', 'toString', 'hasOwnProperty', '__proto__']) {
      expect(['malformed', 'ceiling']).toContain(kind(appId, [kv('public', '')]));
      expect(kind(appId, [kv('public', '')])).not.toBe('ok');
    }
    expect(() => validateStepUpPermissions('constructor', [kv('public', '')], ceilings)).toThrow(StepUpEntryError);
  });

  test('overlap in one space and service is refused, across spaces and services it is not', () => {
    expect(kind('xyz.tinycloud.account', [kv('account', 'spaces/'), kv('account', 'spaces/a')])).toBe('malformed');
    expect(kind('xyz.tinycloud.account', [kv('account', 'spaces/a'), kv('account', 'spaces/')])).toBe('malformed');
    expect(kind('xyz.tinycloud.account', [kv('account', 'applications/'), kv('account', 'spaces/')])).toBe('ok');
    expect(kind('xyz.tinycloud.explorer', [kv('public', ''), { service: 'tinycloud.sql', space: 'applications', path: 'default', actions: ['tinycloud.sql/read'] }])).toBe('ok');
    // The empty path is the root: it overlaps every other path in its space.
    const rootAndPrefix = { 'xyz.tinycloud.explorer': { public: { kv: { paths: ['', 'a/'], actions: ['get'] } } } } as Parameters<typeof validateStepUpPermissions>[2];
    for (const entries of [[kv('public', ''), kv('public', 'a/')], [kv('public', 'a/'), kv('public', '')]]) {
      expect(() => validateStepUpPermissions('xyz.tinycloud.explorer', entries, rootAndPrefix)).toThrow(expect.objectContaining({ kind: 'malformed' }));
    }
  });

  test('no ceilings at all refuses as policy, not as a malformed request', () => {
    expect(() => validateStepUpPermissions('xyz.tinycloud.explorer', [kv('public', '')], undefined)).toThrow(expect.objectContaining({ kind: 'ceiling' }));
  });
});

describe('step-up flag', () => {
  const original = process.env.OPENKEY_NATIVE_STEPUP_ENABLED;
  afterEach(() => {
    if (original === undefined) delete process.env.OPENKEY_NATIVE_STEPUP_ENABLED; else process.env.OPENKEY_NATIVE_STEPUP_ENABLED = original;
  });

  test('is on only for 1 or true; discovery advertises the endpoint only then', () => {
    for (const value of [undefined, '', '0', 'false', 'yes', 'on']) {
      if (value === undefined) delete process.env.OPENKEY_NATIVE_STEPUP_ENABLED; else process.env.OPENKEY_NATIVE_STEPUP_ENABLED = value;
      expect(nativeStepUpEnabled()).toBe(false);
      expect(nativeDelegationMetadata('https://api.openkey.so/api/auth')).not.toHaveProperty('tinycloud_delegation_stepup_endpoint');
    }
    for (const value of ['1', 'true', ' TRUE ']) {
      process.env.OPENKEY_NATIVE_STEPUP_ENABLED = value;
      expect(nativeStepUpEnabled()).toBe(true);
      expect(nativeDelegationMetadata('https://api.openkey.so/api/auth')).toMatchObject({
        tinycloud_delegation_stepup_endpoint: 'https://api.openkey.so/api/auth/oauth2/tinycloud/stepup',
      });
    }
  });

  test('the endpoint is a public protocol path (no cookie) whatever the flag', () => {
    expect(isPublicProtocolPath('https://api.openkey.so/api/auth/oauth2/tinycloud/stepup')).toBe(true);
  });
});
