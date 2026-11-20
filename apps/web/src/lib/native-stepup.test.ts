// @ts-expect-error bun:test is a runtime-only module; svelte-check doesn't ship types
import { describe, expect, test } from 'bun:test';
import { stepUpAccess, stepUpAppName } from './native-stepup';

const address = '0xd559ccd9eb87c530a9a349262669386de93cf412';
const spaceId = (name: string) => `tinycloud:pkh:eip155:1:${address}:${name}`;
const option = (service: string, space: string, path: string, abilities: string[]) => ({
  key: `${service}\0${spaceId(space)}\0${path}`,
  actions: abilities.map((ability) => ({ key: `${service}\0${spaceId(space)}\0${path}\0${ability}`, ability, required: true })),
});

describe('stepUpAppName', () => {
  test('names the three framed apps and shows any other id raw', () => {
    expect(stepUpAppName('xyz.tinycloud.explorer')).toBe('Explorer');
    expect(stepUpAppName('xyz.tinycloud.account')).toBe('Account');
    expect(stepUpAppName('xyz.tinycloud.courier')).toBe('Courier');
    expect(stepUpAppName('com.example.other')).toBe('com.example.other');
    expect(stepUpAppName('constructor')).toBe('constructor');
  });
});

describe('stepUpAccess', () => {
  const spaces = [{ space: 'account', spaceId: spaceId('account') }, { space: 'agents', spaceId: spaceId('agents') }];

  test('groups reads by space and leaves out the capabilities read', () => {
    const access = stepUpAccess(spaces, [
      option('tinycloud.capabilities', 'account', '', ['tinycloud.capabilities/read']),
      option('tinycloud.kv', 'account', 'applications/', ['tinycloud.kv/get', 'tinycloud.kv/list', 'tinycloud.kv/metadata']),
      option('tinycloud.sql', 'agents', '', ['tinycloud.sql/read']),
    ]);
    expect(access.readOnly).toBe(true);
    expect(access.spaces).toEqual([
      { space: 'account', spaceId: spaceId('account'), items: [{ resource: 'kv/applications/', actions: ['read', 'list', 'see details'], readOnly: true }] },
      { space: 'agents', spaceId: spaceId('agents'), items: [{ resource: 'sql', actions: ['read'], readOnly: true }] },
    ]);
  });

  test('a write is named as it is and the whole step-up is not read-only', () => {
    const access = stepUpAccess(spaces, [option('tinycloud.kv', 'account', 'x/', ['tinycloud.kv/get', 'tinycloud.kv/put'])]);
    expect(access.readOnly).toBe(false);
    expect(access.spaces[0].items[0]).toMatchObject({ actions: ['read', 'put'], readOnly: false });
  });

  test('an option in a space the list omits still shows under that space', () => {
    const access = stepUpAccess([], [option('tinycloud.kv', 'public', 'a/', ['tinycloud.kv/get'])]);
    expect(access.spaces.map((group) => group.space)).toEqual(['public']);
  });
});
