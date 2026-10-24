// What the preview and sign steps do with the resources admitted at prepare:
// the message may carry them byte for byte, naming no ability beyond the
// admitted ones, and nothing else under `apps/`.

import './tc1777-test-env';
import { describe, expect, test } from 'bun:test';
import { prepareSession } from '@tinycloud/node-sdk-wasm';
import {
  admittedAppKeyActionIds,
  appKeyGroupPartial,
  appKeyRefusalForSiwe,
  appKeyResourcesOf,
  type AdmittedAppKey,
} from '../services/app-key-refusal';

const ADDRESS = '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed';
const OWNER = `did:pkh:eip155:1:${ADDRESS}`;
const SPACE = `tinycloud:pkh:eip155:1:${ADDRESS}:default`;
const urn = (rest: string) => `urn:tinycloud:encryption:${OWNER}:default${rest}`;
const E = 'tinycloud.encryption/';
const PREFIX = urn('/apps/xyz.tinycloud.listen/');

function siwe(raw: Record<string, string[]>): string {
  const now = new Date();
  return prepareSession({
    address: ADDRESS,
    chainId: 1,
    domain: 'listen.tinycloud.xyz',
    issuedAt: now.toISOString(),
    expirationTime: new Date(now.getTime() + 3_600_000).toISOString(),
    spaceId: SPACE,
    jwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA' },
    abilities: { kv: { [SPACE]: ['tinycloud.kv/get'] } } as never,
    rawAbilities: raw,
  }).siwe;
}

const admitted: AdmittedAppKey[] = [{ resource: PREFIX, abilities: [`${E}key.create`, `${E}decrypt`] }];

describe('the admitted resources are passed byte for byte', () => {
  test('the same resource with the same abilities', () => {
    expect(appKeyRefusalForSiwe(siwe({ [PREFIX]: [`${E}key.create`, `${E}decrypt`] }), undefined, admitted)).toBeNull();
  });

  test('fewer abilities than were admitted', () => {
    expect(appKeyRefusalForSiwe(siwe({ [PREFIX]: [`${E}decrypt`] }), undefined, admitted)).toBeNull();
  });

  test('the wasm entries of the same message agree', () => {
    const entries = [{ service: 'encryption', space: 'encryption', path: PREFIX, actions: [`${E}decrypt`] }];
    expect(appKeyRefusalForSiwe(siwe({ [PREFIX]: [`${E}decrypt`] }), entries, admitted)).toBeNull();
  });

  test.each([
    ['an ability that was not admitted', { [PREFIX]: [`${E}key.create`, `${E}key.block`] }],
    ['a key under the admitted prefix in place of the prefix', { [urn('/apps/xyz.tinycloud.listen/k')]: [`${E}decrypt`] }],
    ['the prefix with its trailing slash gone', { [PREFIX.slice(0, -1)]: [`${E}decrypt`] }],
    ['a prefix under another app id', { [urn('/apps/xyz.tinycloud.notes/')]: [`${E}decrypt`] }],
    ['a deeper prefix', { [urn('/apps/xyz.tinycloud.listen/sub/')]: [`${E}decrypt`] }],
    ['the owner in lower case', { [PREFIX.replace(ADDRESS, ADDRESS.toLowerCase())]: [`${E}decrypt`] }],
    ['the resource in upper case', { [PREFIX.replace('apps', 'Apps')]: [`${E}decrypt`] }],
  ])('refuses %s', (_name, raw) => {
    expect(appKeyRefusalForSiwe(siwe(raw), undefined, admitted)?.reason).toMatch(/^apps_key/);
  });

  test('an admitted resource plus one that was not', () => {
    const message = siwe({ [PREFIX]: [`${E}decrypt`], [urn('/apps/xyz.tinycloud.listen/k')]: [`${E}decrypt`] });
    expect(appKeyRefusalForSiwe(message, undefined, admitted)).toEqual({ reason: 'apps_key' });
  });

  test('a wasm entry that the text scan did not show is refused', () => {
    const entries = [{ service: 'encryption', space: 'encryption', path: urn('/apps/xyz.tinycloud.notes/'), actions: [`${E}decrypt`] }];
    expect(appKeyRefusalForSiwe(siwe({ [PREFIX]: [`${E}decrypt`] }), entries, admitted)).toEqual({ reason: 'apps_key' });
  });

  test('key.delete is refused even on an admitted resource', () => {
    const wide: AdmittedAppKey[] = [{ resource: PREFIX, abilities: [`${E}key.delete`] }];
    expect(appKeyRefusalForSiwe(siwe({ [PREFIX]: [`${E}key.delete`] }), undefined, wide)).toEqual({ reason: 'key_delete' });
  });

  test('without an admission the same message is refused', () => {
    expect(appKeyRefusalForSiwe(siwe({ [PREFIX]: [`${E}decrypt`] }))).toEqual({ reason: 'apps_key' });
  });
});

describe('appKeyResourcesOf', () => {
  test('lists the apps/ resources as written and nothing else', () => {
    const message = siwe({ [PREFIX]: [`${E}decrypt`], [urn('')]: [`${E}network.create`], [urn('/secrets/x')]: [`${E}decrypt`] });
    expect(appKeyResourcesOf(message)).toEqual([[PREFIX, [`${E}decrypt`]]]);
  });

  test('null when a ReCap cannot be read', () => {
    expect(appKeyResourcesOf(siwe({ [PREFIX]: [`${E}decrypt`] }).replace(/(- urn:recap:)\S*/, '$1%%%'))).toBeNull();
  });
});

describe('appKeyGroupPartial', () => {
  const ids = (...values: string[]) => new Set(values);
  const all = ids('a1', 'a2', 'k1', 'k2');
  const group = ids('a1', 'a2');

  test.each([
    ['everything selected', ids('a1', 'a2', 'k1', 'k2'), false],
    ['only the group removed', ids('k1', 'k2'), false],
    ['nothing selected', ids(), false],
    ['only the siblings dropped', ids('a1', 'a2'), true],
    ['one group action dropped', ids('a1', 'k1', 'k2'), true],
    ['one sibling action dropped', ids('a1', 'a2', 'k1'), true],
    ['one group action alone', ids('a1'), true],
  ])('%s', (_name, selected, partial) => {
    expect(appKeyGroupPartial(group, all, selected)).toBe(partial);
  });

  test('a request with no admitted rows is never partial', () => {
    expect(appKeyGroupPartial(ids(), all, ids('k1'))).toBe(false);
  });
});

describe('admittedAppKeyActionIds', () => {
  const entries = [
    { path: PREFIX, actions: [`${E}key.create`, `${E}decrypt`] },
    { path: SPACE, actions: ['tinycloud.kv/get'] },
  ];
  const id = (entry: { path: string }, action: string) => `${entry.path}|${action}`;

  test('is the actions of the admitted resources only', () => {
    expect(admittedAppKeyActionIds(entries, admitted, id)).toEqual(new Set([`${PREFIX}|${E}key.create`, `${PREFIX}|${E}decrypt`]));
  });

  test('is empty without an admission', () => {
    expect(admittedAppKeyActionIds(entries, undefined, id).size).toBe(0);
  });
});
